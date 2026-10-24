package api

import (
	"sync"
	"time"

	"toshell/internal/server/logging"
)

// 屏幕流服务端限速与帧合并（ROADMAP P0.2）。
//
// 植入端按 fps 出帧，但网络抖动、参数被改、或同一会话被多个页面观看时，帧仍可能
// 超发；前端只需要「最新一帧」——旧帧堆积只会浪费 WS 带宽并拖慢渲染。
// 这里按会话记录最小出帧间隔，超出的帧直接丢弃（合并到下一帧），
// 并统计丢弃数用于诊断（warning 日志按会话 1 秒限频，见 warnDropLocked）。
const screenFrameMinInterval = 100 * time.Millisecond // 硬上限：10fps

// screenDropWarnInterval 丢弃 warning 日志的单会话限频窗口。
// 取 1s：10fps 的会话也最多每秒一条，既能看见"一直在丢"，又不会把日志刷爆。
const screenDropWarnInterval = time.Second

type screenFrameLimiter struct {
	mu      sync.Mutex
	min     map[string]time.Duration
	last    map[string]time.Time
	dropped map[string]uint64
	warned  map[string]time.Time // 每会话最近一条丢弃 warning 的时间（限频用）

	// 屏幕帧广播的进程内聚合计数（v1.4.1 可观测性）：写路径全部 atomic，
	// 读路径无锁快照。只存聚合值、不按帧存明细，避免高基数图像帧吃内存。
	stats screenStreamCounters
}

func newScreenFrameLimiter() *screenFrameLimiter {
	return &screenFrameLimiter{
		min:     make(map[string]time.Duration),
		last:    make(map[string]time.Time),
		dropped: make(map[string]uint64),
		warned:  make(map[string]time.Time),
	}
}

// SetFPS 记录会话期望帧率（由 screen-stream 启动参数决定）。
func (l *screenFrameLimiter) SetFPS(sessionID string, fps int) {
	if sessionID == "" {
		return
	}
	if fps <= 0 {
		fps = 2
	}
	interval := time.Second / time.Duration(fps)
	if interval < screenFrameMinInterval {
		interval = screenFrameMinInterval
	}
	l.mu.Lock()
	l.min[sessionID] = interval
	l.mu.Unlock()
}

// Allow 判断该帧是否应当下发；false 表示丢弃（合并）。
//
// frames_in / last_frame_at 在这里记：Allow 是每一帧进入广播前必经的唯一入口，
// 即使随后被限速丢弃，也仍然算"收到过帧"（黑屏时据此区分"没出帧"与"全被丢"）。
func (l *screenFrameLimiter) Allow(sessionID string) bool {
	now := time.Now()
	l.stats.recordFrameIn(now)

	if sessionID == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	interval, ok := l.min[sessionID]
	if !ok {
		interval = time.Second / 2 // 未声明帧率时按 2fps 兜底
	}
	if last, ok := l.last[sessionID]; ok && now.Sub(last) < interval {
		l.dropped[sessionID]++
		l.stats.recordLimitDrop()
		l.warnDropLocked(sessionID, now, interval)
		return false
	}
	l.last[sessionID] = now
	return true
}

// warnDropLocked 记一条限速丢弃 warning（调用方必须持有 l.mu）。
//
// 限频：每个会话最多每秒一条；内容带会话 id 与累计丢弃数，保证"丢弃"本身
// 也留在日志里可查。日志 I/O 走独立 goroutine，不能压回帧处理路径。
func (l *screenFrameLimiter) warnDropLocked(sessionID string, now time.Time, interval time.Duration) {
	if last, ok := l.warned[sessionID]; ok && now.Sub(last) < screenDropWarnInterval {
		return
	}
	l.warned[sessionID] = now
	dropped := l.dropped[sessionID]
	go logging.Warn("screen-stream", "屏幕帧被限速丢弃：session=%s 累计丢弃=%d（该会话最小间隔 %v，服务端硬上限 10fps）", sessionID, dropped, interval)
}

// recordFanout 记录 WS Hub 一次扇出的投递结果（帧 × 订阅者的成功/失败次数）。
// 由 screen_frame 观测回调调用；回调运行在 Hub 事件循环，这里只做 atomic 累加。
func (l *screenFrameLimiter) recordFanout(delivered, dropped int) {
	l.stats.recordFanout(delivered, dropped)
}

// Reset 清理会话的限速状态（流停止/会话删除时调用）。
func (l *screenFrameLimiter) Reset(sessionID string) {
	l.mu.Lock()
	delete(l.min, sessionID)
	delete(l.last, sessionID)
	delete(l.dropped, sessionID)
	delete(l.warned, sessionID)
	l.mu.Unlock()
}

// Dropped 返回已丢弃帧数（测试/诊断用）。
func (l *screenFrameLimiter) Dropped(sessionID string) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped[sessionID]
}

func (s *Server) frameLimiter() *screenFrameLimiter {
	s.screenLimiterOnce.Do(func() {
		if s.screenLimiter == nil {
			s.screenLimiter = newScreenFrameLimiter()
		}
		// 把 Hub 的扇出结果接到计数器上（v1.4.1；见 screen_stats.go）。
		s.attachScreenFrameObserver()
	})
	return s.screenLimiter
}
