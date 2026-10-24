package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"toshell/internal/server/session"
)

// ─── 屏幕帧投递观测：字段形状 / 扇出计数 / Hub 行为不变 ──────────────────

// 观测依赖「屏幕帧事件的序列化前缀」识别事件类型；这里把该假设钉死：
// 一旦 WSEvent 字段顺序或类型名变化，计数会静默归零，必须让测试先失败。
func TestScreenFrameEventPrefixMatchesBroadcastJSON(t *testing.T) {
	frame, err := json.Marshal(WSEvent{Type: "screen_frame", Payload: map[string]interface{}{"x": 1}})
	if err != nil {
		t.Fatalf("marshal screen_frame: %v", err)
	}
	if !bytes.HasPrefix(frame, screenFrameEventPrefix) {
		t.Fatalf("屏幕帧广播 JSON 不再以约定前缀开头: %s", frame)
	}

	other, err := json.Marshal(WSEvent{Type: "session_online", Payload: map[string]interface{}{"x": 1}})
	if err != nil {
		t.Fatalf("marshal session_online: %v", err)
	}
	if bytes.HasPrefix(other, screenFrameEventPrefix) {
		t.Fatalf("非屏幕帧事件不应命中屏幕帧前缀: %s", other)
	}
}

func decodeStatsBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是 JSON 对象: %v; body=%s", err, rec.Body.String())
	}
	return body
}

// /system/stats：旧字段一个不少、语义不变；screen_stream 在「从未收到帧」时
// 也必须存在且全为 0（否则前端/脚本没法区分"字段缺失"与"真的没有帧"）。
func TestSystemStatsAddsScreenStreamWithoutChangingExistingFields(t *testing.T) {
	s := &Server{sessionMgr: session.New(), startTime: time.Now()}
	rec := httptest.NewRecorder()
	s.systemStatsHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/system/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}
	body := decodeStatsBody(t, rec)

	for _, key := range []string{"hostname", "goroutines", "go_version", "cpu_count", "memory", "sessions", "uptime", "timestamp"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("已有字段 %q 丢失（只允许追加字段）", key)
		}
	}

	mem, ok := body["memory"].(map[string]interface{})
	if !ok {
		t.Fatalf("memory 字段类型变了: %T", body["memory"])
	}
	for _, key := range []string{"alloc", "total_alloc", "sys", "heap_inuse"} {
		if _, ok := mem[key]; !ok {
			t.Fatalf("memory.%s 字段丢失", key)
		}
	}

	sess, ok := body["sessions"].(map[string]interface{})
	if !ok {
		t.Fatalf("sessions 字段类型变了: %T", body["sessions"])
	}
	for _, key := range []string{"total", "active"} {
		if _, ok := sess[key]; !ok {
			t.Fatalf("sessions.%s 字段丢失", key)
		}
	}

	raw, ok := body["screen_stream"].(map[string]interface{})
	if !ok {
		t.Fatalf("screen_stream 缺失或不是对象: %T", body["screen_stream"])
	}
	for _, key := range []string{"frames_in", "frames_delivered", "frames_dropped", "limits_hit", "subscribers", "last_frame_at"} {
		v, ok := raw[key]
		if !ok {
			t.Fatalf("screen_stream.%s 字段缺失", key)
		}
		n, ok := v.(float64)
		if !ok {
			t.Fatalf("screen_stream.%s 不是数字: %T", key, v)
		}
		if n != 0 {
			t.Fatalf("未收到任何帧时 screen_stream.%s = %v, want 0", key, n)
		}
	}
}

// /system/stats：计数变化要能反映到响应里（frames_in / delivered / dropped / limits_hit）。
func TestSystemStatsScreenStreamReflectsCounters(t *testing.T) {
	s := &Server{sessionMgr: session.New(), startTime: time.Now()}
	l := s.frameLimiter()
	l.SetFPS("s1", 2)
	l.Allow("s1")        // frames_in=1，放行
	l.Allow("s1")        // frames_in=2，限速丢弃
	l.recordFanout(2, 1) // 两条订阅者投递成功 + 一条慢消费者丢弃

	rec := httptest.NewRecorder()
	s.systemStatsHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/system/stats", nil))
	raw, ok := decodeStatsBody(t, rec)["screen_stream"].(map[string]interface{})
	if !ok {
		t.Fatal("screen_stream 缺失")
	}
	want := map[string]float64{
		"frames_in":        2,
		"frames_delivered": 2,
		"frames_dropped":   1,
		"limits_hit":       1,
		"subscribers":      0, // 没有 wsHub（未装配 WS 订阅面）
	}
	for key, w := range want {
		got, ok := raw[key].(float64)
		if !ok || got != w {
			t.Fatalf("screen_stream.%s = %v, want %v", key, raw[key], w)
		}
	}
	if ts, ok := raw["last_frame_at"].(float64); !ok || ts <= 0 {
		t.Fatalf("screen_stream.last_frame_at = %v, want > 0", raw["last_frame_at"])
	}
}

// /channels/health：只追加 screen_stream，四通道字段与语义不变。
func TestChannelsHealthAddsScreenStreamWithoutChangingExistingFields(t *testing.T) {
	s := &Server{sessionMgr: session.New()}
	rec := httptest.NewRecorder()
	s.channelsHealthHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/channels/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}
	body := decodeStatsBody(t, rec)

	for _, key := range []string{"channels", "total_online", "total_session", "timestamp"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("已有字段 %q 丢失（只允许追加字段）", key)
		}
	}
	channels, ok := body["channels"].([]interface{})
	if !ok || len(channels) != 4 {
		t.Fatalf("channels = %T(len=%d), want 四通道数组", body["channels"], len(channels))
	}
	for _, item := range channels {
		ch, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("通道项不是对象: %T", item)
		}
		for _, key := range []string{"type", "online", "total_session", "listeners", "running"} {
			if _, ok := ch[key]; !ok {
				t.Fatalf("通道项字段 %q 丢失", key)
			}
		}
	}
	if _, ok := body["screen_stream"].(map[string]interface{}); !ok {
		t.Fatalf("screen_stream 缺失或不是对象: %T", body["screen_stream"])
	}
}

// ─── WSHub 扇出观测：未注册回调行为不变、注册后每次尝试都被记账 ──────────

// 不注册观测回调时，扇出行为必须与改动前一致：健康订阅者收到全部消息，
// 慢订阅者（缓冲满）被关闭并移除。
func TestWSHubFanoutUnchangedWithoutObserver(t *testing.T) {
	h := NewWSHub()
	go h.Run()

	fast := &WSClient{send: make(chan []byte, 8), hub: h}
	slow := &WSClient{send: make(chan []byte, 0), hub: h} // 无缓冲且无人读 → 必然缓冲满
	h.register <- fast
	h.register <- slow
	waitFor(t, 2*time.Second, "两个客户端注册", func() bool { return h.ClientCount() == 2 })

	const messages = 5
	for i := 0; i < messages; i++ {
		h.Broadcast(WSEvent{Type: "session_online", Payload: map[string]interface{}{"i": i}})
	}
	for i := 0; i < messages; i++ {
		select {
		case <-fast.send:
		case <-time.After(2 * time.Second):
			t.Fatalf("健康客户端未收到第 %d 条广播（未注册回调时行为必须不变）", i+1)
		}
	}
	waitFor(t, 2*time.Second, "慢客户端被断开", func() bool { return h.ClientCount() == 1 })
	if _, ok := <-slow.send; ok {
		t.Fatal("慢客户端应被 close（与改动前一致）")
	}
}

// 注册观测回调后：一条广播的 delivered + dropped 必须等于该时刻的订阅者数
// （即扇出尝试次数），不能有分支漏记。第 1 条 3 个订阅者（2 成功 / 1 慢消费者），
// 之后慢消费者被移除，剩下 4 条各 2 次成功 → 尝试总次数 = 3 + 4*2 = 11。
func TestWSHubFanoutObserverCountsEveryAttempt(t *testing.T) {
	h := NewWSHub()
	type sample struct{ delivered, dropped int }
	samples := make(chan sample, 16)
	h.SetFanoutObserver(func(_ []byte, delivered, dropped int) {
		samples <- sample{delivered: delivered, dropped: dropped}
	})
	go h.Run()

	healthy := []*WSClient{
		{send: make(chan []byte, 16), hub: h},
		{send: make(chan []byte, 16), hub: h},
	}
	slow := &WSClient{send: make(chan []byte, 0), hub: h}
	for _, c := range healthy {
		h.register <- c
	}
	h.register <- slow
	waitFor(t, 2*time.Second, "三个客户端注册", func() bool { return h.ClientCount() == 3 })

	const messages = 5
	for i := 0; i < messages; i++ {
		h.Broadcast(WSEvent{Type: "session_online"})
	}

	totalDelivered, totalDropped := 0, 0
	for i := 0; i < messages; i++ {
		select {
		case s := <-samples:
			totalDelivered += s.delivered
			totalDropped += s.dropped
		case <-time.After(2 * time.Second):
			t.Fatalf("第 %d 条广播未被观测到", i+1)
		}
	}

	wantDelivered, wantDropped, wantAttempts := 2+4*2, 1, 3+4*2
	if totalDelivered != wantDelivered || totalDropped != wantDropped {
		t.Fatalf("观测计数 = delivered %d / dropped %d, want %d / %d",
			totalDelivered, totalDropped, wantDelivered, wantDropped)
	}
	if totalDelivered+totalDropped != wantAttempts {
		t.Fatalf("delivered+dropped = %d, 扇出尝试次数 = %d（有分支漏记）",
			totalDelivered+totalDropped, wantAttempts)
	}
}

// 端到端（不走真实植入端）：真实 WS 订阅者 + BroadcastScreenFrame 的真实广播路径。
// 验证 frames_in / frames_delivered / subscribers / last_frame_at 都随真实帧变化。
func TestBroadcastScreenFrameEndToEndCounts(t *testing.T) {
	s := &Server{wsHub: NewWSHub()}
	go s.wsHub.Run()

	sub1 := &WSClient{send: make(chan []byte, 8), hub: s.wsHub}
	sub2 := &WSClient{send: make(chan []byte, 8), hub: s.wsHub}
	s.wsHub.register <- sub1
	s.wsHub.register <- sub2
	waitFor(t, 2*time.Second, "订阅者注册", func() bool { return s.wsHub.ClientCount() == 2 })

	s.frameLimiter().SetFPS("sess-e2e", 1) // 1s/帧，保证第二次调用落在限速窗口内
	payload := []byte(`{"image":"aGVsbG8=","format":"jpeg","width":1,"height":1}`)
	s.BroadcastScreenFrame("sess-e2e", payload)

	waitFor(t, 2*time.Second, "两个订阅者各收到一次投递", func() bool {
		return s.screenStreamStatsSnapshot().FramesDelivered == 2
	})
	// 同一会话 1s 内的第二帧应被限速合并：只涨 limits_hit，不涨 delivered。
	s.BroadcastScreenFrame("sess-e2e", payload)
	waitFor(t, 2*time.Second, "限速丢弃计数", func() bool {
		return s.screenStreamStatsSnapshot().LimitsHit == 1
	})

	snap := s.screenStreamStatsSnapshot()
	if snap.FramesIn != 2 {
		t.Fatalf("frames_in = %d, want 2", snap.FramesIn)
	}
	if snap.FramesDelivered != 2 {
		t.Fatalf("frames_delivered = %d, want 2（帧 × 2 个订阅者）", snap.FramesDelivered)
	}
	if snap.FramesDropped != 0 {
		t.Fatalf("frames_dropped = %d, want 0", snap.FramesDropped)
	}
	if snap.Subscribers != 2 {
		t.Fatalf("subscribers = %d, want 2", snap.Subscribers)
	}
	if snap.LastFrameAt <= 0 {
		t.Fatalf("last_frame_at = %d, want > 0", snap.LastFrameAt)
	}

	// 帧确实通过 WS 广播出去了（不是只加了计数）。
	for i, sub := range []*WSClient{sub1, sub2} {
		select {
		case msg := <-sub.send:
			if !bytes.HasPrefix(msg, screenFrameEventPrefix) {
				t.Fatalf("订阅者 %d 收到的不是 screen_frame 事件: %s", i, msg)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("订阅者 %d 未收到 screen_frame", i)
		}
	}
}

// 慢消费者在真实屏幕帧广播里被丢弃时，帧级计数（frames_dropped）也要动，
// 且订阅者数随即下降（Hub 会断开缓冲满的客户端）。
func TestBroadcastScreenFrameCountsSlowSubscriberDrop(t *testing.T) {
	s := &Server{wsHub: NewWSHub()}
	go s.wsHub.Run()

	healthy := &WSClient{send: make(chan []byte, 8), hub: s.wsHub}
	slow := &WSClient{send: make(chan []byte, 0), hub: s.wsHub}
	s.wsHub.register <- healthy
	s.wsHub.register <- slow
	waitFor(t, 2*time.Second, "订阅者注册", func() bool { return s.wsHub.ClientCount() == 2 })

	s.BroadcastScreenFrame("sess-slow", []byte(`{"image":"aGVsbG8=","format":"jpeg","width":1,"height":1}`))
	waitFor(t, 2*time.Second, "投递成功与慢消费者丢弃各记一次", func() bool {
		snap := s.screenStreamStatsSnapshot()
		return snap.FramesDelivered == 1 && snap.FramesDropped == 1
	})
	waitFor(t, 2*time.Second, "慢客户端被断开", func() bool {
		return s.screenStreamStatsSnapshot().Subscribers == 1
	})
	if _, ok := <-slow.send; ok {
		t.Fatal("慢客户端应被 close")
	}
}
