package api

import (
	"sync"
	"testing"
	"time"
)

func TestScreenFrameLimiterThrottlesByFPS(t *testing.T) {
	l := newScreenFrameLimiter()
	l.SetFPS("sess", 2) // 500ms/帧

	if !l.Allow("sess") {
		t.Fatal("首帧应放行")
	}
	if l.Allow("sess") {
		t.Fatal("同一间隔内的第二帧应被丢弃（帧合并）")
	}
	if got := l.Dropped("sess"); got != 1 {
		t.Fatalf("丢弃计数 = %d, want 1", got)
	}

	time.Sleep(520 * time.Millisecond)
	if !l.Allow("sess") {
		t.Fatal("超过间隔后应放行")
	}
	if l.Dropped("sess") != 1 {
		t.Fatalf("放行不应增加丢弃计数: %d", l.Dropped("sess"))
	}
}

// 硬上限 10fps：即使请求 30fps 也不会把 WS 打爆。
func TestScreenFrameLimiterHardFloor(t *testing.T) {
	l := newScreenFrameLimiter()
	l.SetFPS("fast", 30)

	if !l.Allow("fast") {
		t.Fatal("首帧应放行")
	}
	time.Sleep(40 * time.Millisecond)
	if l.Allow("fast") {
		t.Fatal("40ms < 100ms 硬下限，应丢弃")
	}
	time.Sleep(80 * time.Millisecond)
	if !l.Allow("fast") {
		t.Fatal("累计 >100ms 后应放行")
	}
}

// 未声明帧率的会话按 2fps 兜底。
func TestScreenFrameLimiterDefaultFPS(t *testing.T) {
	l := newScreenFrameLimiter()
	if !l.Allow("unknown") {
		t.Fatal("首帧应放行")
	}
	if l.Allow("unknown") {
		t.Fatal("兜底 2fps 下应立即丢弃第二帧")
	}
}

func TestScreenFrameLimiterReset(t *testing.T) {
	l := newScreenFrameLimiter()
	l.SetFPS("s", 1)
	l.Allow("s")
	l.Allow("s")
	if l.Dropped("s") == 0 {
		t.Fatal("应有丢弃计数")
	}
	l.Reset("s")
	if l.Dropped("s") != 0 {
		t.Fatal("Reset 应清空计数")
	}
	if !l.Allow("s") {
		t.Fatal("Reset 后首帧应放行")
	}
}

func TestIntParamClamping(t *testing.T) {
	five, zero, huge, neg := 5, 0, 99999, -3
	cases := []struct {
		name string
		v    *int
		def  int
		min  int
		max  int
		want int
	}{
		{"nil用默认", nil, 2, 1, 10, 2},
		{"正常值", &five, 2, 1, 10, 5},
		{"低于下限", &neg, 0, 0, 16, 0},
		{"高于上限", &huge, 0, 0, 16, 16},
		{"零值合法", &zero, 70, 0, 100, 0},
	}
	for _, c := range cases {
		if got := intParam(c.v, c.def, c.min, c.max); got != c.want {
			t.Errorf("%s: intParam = %d, want %d", c.name, got, c.want)
		}
	}
}

// ─── v1.4.1 屏幕帧投递计数 ─────────────────────────────────────────────

// frames_in 记录每一帧（含随后被限速丢弃的帧），limits_hit 只记限速丢弃。
func TestScreenFrameLimiterCountsFramesAndLimitDrops(t *testing.T) {
	l := newScreenFrameLimiter()
	l.SetFPS("sess", 2) // 500ms/帧

	before := time.Now().UnixMilli()
	if !l.Allow("sess") {
		t.Fatal("首帧应放行")
	}
	if l.Allow("sess") {
		t.Fatal("同一间隔内的第二帧应被丢弃（帧合并）")
	}
	got := l.stats.snapshot()
	if got.FramesIn != 2 {
		t.Fatalf("frames_in = %d, want 2（收到但被限速丢弃的帧也要计数）", got.FramesIn)
	}
	if got.LimitsHit != 1 {
		t.Fatalf("limits_hit = %d, want 1", got.LimitsHit)
	}
	if got.FramesDelivered != 0 || got.FramesDropped != 0 {
		t.Fatalf("限速器不应改动投递计数: delivered=%d dropped=%d", got.FramesDelivered, got.FramesDropped)
	}
	if got.LastFrameAt < before || got.LastFrameAt > time.Now().UnixMilli() {
		t.Fatalf("last_frame_at = %d, want 在 [%d, %d] 内", got.LastFrameAt, before, time.Now().UnixMilli())
	}
	if l.Dropped("sess") != 1 {
		t.Fatalf("按会话丢弃计数 = %d, want 1", l.Dropped("sess"))
	}
}

// 空会话 id（未归属会话的帧）不参与限速，但仍应计入 frames_in。
func TestScreenFrameLimiterCountsEmptySessionFrames(t *testing.T) {
	l := newScreenFrameLimiter()
	if !l.Allow("") || !l.Allow("") {
		t.Fatal("空会话 id 不应被限速")
	}
	got := l.stats.snapshot()
	if got.FramesIn != 2 || got.LimitsHit != 0 {
		t.Fatalf("frames_in=%d limits_hit=%d, want 2/0", got.FramesIn, got.LimitsHit)
	}
}

// Hub 扇出回调只做 atomic 累加：delivered/dropped 分别累计。
func TestScreenFrameLimiterRecordsFanoutCounters(t *testing.T) {
	l := newScreenFrameLimiter()
	l.recordFanout(3, 1)
	l.recordFanout(0, 2)
	l.recordFanout(0, 0)
	got := l.stats.snapshot()
	if got.FramesDelivered != 3 {
		t.Fatalf("frames_delivered = %d, want 3", got.FramesDelivered)
	}
	if got.FramesDropped != 3 {
		t.Fatalf("frames_dropped = %d, want 3", got.FramesDropped)
	}
}

// 丢弃 warning 按会话 1 秒限频：连续丢弃只登记一条（不刷屏），Reset 清掉限频状态。
func TestScreenFrameLimiterDropWarningIsRateLimited(t *testing.T) {
	l := newScreenFrameLimiter()
	l.SetFPS("s", 1) // 1s/帧：下面的连续调用都会命中限速分支
	l.Allow("s")
	for i := 0; i < 5; i++ {
		l.Allow("s")
	}

	l.mu.Lock()
	warnedCount := len(l.warned)
	lastWarn := l.warned["s"]
	l.mu.Unlock()
	if warnedCount != 1 || lastWarn.IsZero() {
		t.Fatalf("warning 限频状态 = %d 条 / %v, want 1 条非零时间", warnedCount, lastWarn)
	}

	l.Reset("s")
	l.mu.Lock()
	_, stillWarned := l.warned["s"]
	l.mu.Unlock()
	if stillWarned {
		t.Fatal("Reset 应清掉会话的 warning 限频状态")
	}
	if l.Dropped("s") != 0 {
		t.Fatal("Reset 应清掉按会话丢弃计数")
	}
}

// 并发安全（-race 在 windows/386 + CGO_ENABLED=0 下不可用，用 goroutine + 最终值断言）：
// 多 goroutine 同时记 frames_in / 扇出结果，最终值必须精确等于调用次数。
func TestScreenFrameLimiterConcurrentAtomicCounters(t *testing.T) {
	l := newScreenFrameLimiter()
	const goroutines = 8
	const perGoroutine = 200

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				l.Allow("") // 空会话：只验证 frames_in/last_frame_at 的并发递增
				l.recordFanout(2, 1)
			}
		}()
	}
	wg.Wait()

	wantFrames := uint64(goroutines * perGoroutine)
	got := l.stats.snapshot()
	if got.FramesIn != wantFrames {
		t.Fatalf("frames_in = %d, want %d", got.FramesIn, wantFrames)
	}
	if got.FramesDelivered != wantFrames*2 {
		t.Fatalf("frames_delivered = %d, want %d", got.FramesDelivered, wantFrames*2)
	}
	if got.FramesDropped != wantFrames {
		t.Fatalf("frames_dropped = %d, want %d", got.FramesDropped, wantFrames)
	}
	if got.LimitsHit != 0 {
		t.Fatalf("空会话不应触发限速: limits_hit=%d", got.LimitsHit)
	}
	if got.LastFrameAt <= 0 {
		t.Fatalf("last_frame_at = %d, want > 0", got.LastFrameAt)
	}
}
