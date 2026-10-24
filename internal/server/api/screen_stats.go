package api

import (
	"bytes"
	"sync/atomic"
	"time"

	"toshell/internal/server/logging"
)

// 屏幕帧广播的投递可观测性（v1.4.1）。
//
// 背景：屏幕帧是「一把广播」——一条帧同时写给所有 WS 订阅者，但整条链路上此前
// 既没有「投递成功数」也没有「慢消费者丢弃数」。出问题时前端只表现为黑屏，运维
// 无法区分下面几种完全不同的根因：
//
//	① 植入端根本没出帧        → frames_in 不涨、last_frame_at 不更新
//	② 出了帧但被服务端限速合并 → frames_in/last_frame_at 涨、limits_hit 涨
//	③ 没有前端订阅者          → frames_in 涨、subscribers=0、frames_delivered 不涨
//	④ 订阅者太慢、发送缓冲满   → frames_dropped 涨（客户端随即被断开）
//
// 计数口径（全部是进程内聚合值，**不按帧存明细**，避免高基数图像帧把内存吃光）：
//   - frames_in:        收到的帧数（进入广播入口、限速判断之前）
//   - frames_delivered: 成功写入某个订阅者发送缓冲的次数（单位：帧 × 订阅者）
//   - frames_dropped:   因订阅者发送缓冲满（慢消费者）被丢弃的次数（帧 × 订阅者）
//   - limits_hit:       被服务端限速器合并丢弃的帧数
//   - subscribers:      当前 WS 订阅者数（瞬时值，读快照时取）
//   - last_frame_at:    最后一帧到达的 unix 毫秒时间戳（0 = 尚未收到帧）
//
// 并发：写路径全部走 atomic（植入端读取 goroutine / 限速器 / WS Hub 事件循环
// 三处并发），读路径（/system/stats、/channels/health）无锁快照。
type screenStreamCounters struct {
	framesIn        atomic.Uint64
	framesDelivered atomic.Uint64
	framesDropped   atomic.Uint64
	limitsHit       atomic.Uint64
	lastFrameAt     atomic.Int64 // unix ms；0 = 尚未收到帧
}

// screenStreamStats 是 /system/stats 与 /channels/health 里的 screen_stream 字段。
// 只追加字段、不修改已有字段的语义；字段名与前端/脚本约定一致。
type screenStreamStats struct {
	FramesIn        uint64 `json:"frames_in"`
	FramesDelivered uint64 `json:"frames_delivered"`
	FramesDropped   uint64 `json:"frames_dropped"`
	LimitsHit       uint64 `json:"limits_hit"`
	Subscribers     int    `json:"subscribers"`
	LastFrameAt     int64  `json:"last_frame_at"`
}

// screenFrameEventPrefix 是屏幕帧 WS 事件序列化后的稳定前缀。
// WSEvent 的字段顺序是 Type、Payload、Time，encoding/json 按结构体字段顺序输出，
// 因此前缀固定；观测回调用它把屏幕帧与任务/会话上下线等其他广播区分开。
var screenFrameEventPrefix = []byte(`{"type":"screen_frame"`)

// recordFrameIn 记录一帧到达（由 screenFrameLimiter.Allow 调用，每帧一次）。
func (c *screenStreamCounters) recordFrameIn(now time.Time) {
	c.framesIn.Add(1)
	c.lastFrameAt.Store(now.UnixMilli())
}

// recordLimitDrop 记录一帧被限速器合并丢弃。
func (c *screenStreamCounters) recordLimitDrop() {
	c.limitsHit.Add(1)
}

// recordFanout 记录一次广播扇出的投递结果。
// delivered/dropped 是该条广播对各个订阅者发送尝试的成功/失败次数。
func (c *screenStreamCounters) recordFanout(delivered, dropped int) {
	if delivered > 0 {
		c.framesDelivered.Add(uint64(delivered))
	}
	if dropped > 0 {
		c.framesDropped.Add(uint64(dropped))
	}
}

// snapshot 返回聚合计数快照（不含 subscribers，后者由 Server 从 Hub 现取）。
func (c *screenStreamCounters) snapshot() screenStreamStats {
	return screenStreamStats{
		FramesIn:        c.framesIn.Load(),
		FramesDelivered: c.framesDelivered.Load(),
		FramesDropped:   c.framesDropped.Load(),
		LimitsHit:       c.limitsHit.Load(),
		LastFrameAt:     c.lastFrameAt.Load(),
	}
}

// screenStreamStatsSnapshot 返回屏幕流统计快照（聚合计数 + 瞬时订阅者数）。
//
// 读路径不持任何锁；各字段分别读 atomic，不保证跨字段严格同一时刻一致——
// 对可观测性足够，也避免在读接口里阻塞帧处理。
func (s *Server) screenStreamStatsSnapshot() screenStreamStats {
	out := s.frameLimiter().stats.snapshot()
	if s.wsHub != nil {
		out.Subscribers = s.wsHub.ClientCount()
	}
	return out
}

// attachScreenFrameObserver 把 WS Hub 的扇出结果接到屏幕帧计数上。
//
// 由 frameLimiter() 在 sync.Once 内调用，保证每个 Server 只注册一次。
// 回调只在 Hub 事件循环里做前缀判断 + atomic 累加，绝不写日志、不加锁、不阻塞扇出。
func (s *Server) attachScreenFrameObserver() {
	if s.wsHub == nil || s.screenLimiter == nil {
		return
	}
	limiter := s.screenLimiter
	s.wsHub.SetFanoutObserver(func(message []byte, delivered, dropped int) {
		if !bytes.HasPrefix(message, screenFrameEventPrefix) {
			return
		}
		limiter.recordFanout(delivered, dropped)
	})
	go limiter.watchFanoutDropWarnings()
}

// watchFanoutDropWarnings 每秒检查一次慢消费者丢弃计数，有新增才记一条 warning。
//
// 为什么不在扇出回调里直接打日志：回调运行在 WS Hub 的单一事件循环上，日志 I/O
// （文件 + 数据库）会把所有 WS 推送一起卡住，慢消费者反而会拖垮整条流。
// 这里按秒聚合，最多每秒一条，内容带本次新增与累计丢弃数（单位：帧 × 订阅者）。
func (l *screenFrameLimiter) watchFanoutDropWarnings() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var logged uint64
	for range ticker.C {
		cur := l.stats.framesDropped.Load()
		if cur <= logged {
			continue
		}
		delta := cur - logged
		logged = cur
		logging.Warn("screen-stream", "屏幕帧投递失败（慢消费者/发送缓冲满）：本秒新增 %d 次，累计 frames_dropped=%d（单位：帧×订阅者，对应 WS 客户端已被断开）", delta, cur)
	}
}
