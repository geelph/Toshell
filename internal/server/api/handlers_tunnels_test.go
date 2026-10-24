package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"toshell/internal/common/tunnel"
	"toshell/internal/server/config"
	"toshell/internal/server/database"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
	"toshell/internal/server/tunnelstore"
)

// ─── 隧道持久化 + 重启恢复的用例 ─────────────────────────────────────────────
//
// 全部用真实 sqlite 临时库 + 真实监听器（随机端口），但**不需要真实植入端**：
//   - "端口真的在监听"用 TCP 拨号验证；
//   - "代理认证真的生效"用 SOCKS5 方法协商/子协商字节验证（不建立 CONNECT）；
//   - "服务端重启"用同一份库 + 全新的内存态 Server 模拟。
//
// 用完必须停监听、关库：否则 Windows 上 t.TempDir 清理会失败（用例全绿却整体 FAIL）。

const tunnelTestKey = "0123456789abcdef0123456789abcdef" // 32 字节 = AES-256

type tunnelTestEnv struct {
	s     *Server
	db    *database.Database
	store *tunnelstore.Store
}

func newTunnelTestEnv(t *testing.T) *tunnelTestEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "tunnels-api.db")
	d, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	store, err := tunnelstore.New(d.SQL(), []byte(tunnelTestKey))
	if err != nil {
		t.Fatalf("tunnelstore.New: %v", err)
	}
	env := &tunnelTestEnv{s: newTunnelTestServer(store), db: d, store: store}
	t.Cleanup(func() {
		env.s.stopAllTunnels()
		_ = d.Close()
	})
	return env
}

// newTunnelTestServer 构造最小可用 Server：会话/任务管理器 + 假推送 + 隧道存储，不起 HTTP 服务。
func newTunnelTestServer(store *tunnelstore.Store) *Server {
	sessMgr := session.New()
	return &Server{
		cfg:           &config.Config{},
		sessionMgr:    sessMgr,
		taskMgr:       task.NewIsolated(sessMgr),
		listener:      &fakePusher{},
		socks5Servers: make(map[string]*tunnel.SOCKS5Server),
		tunnelStore:   store,
	}
}

// restartServer 模拟"服务端进程重启"：同一份库，全新的内存态（代理 map 为空）。
func (e *tunnelTestEnv) restartServer(t *testing.T) *Server {
	t.Helper()
	s := newTunnelTestServer(e.store)
	t.Cleanup(s.stopAllTunnels)
	return s
}

func (s *Server) stopAllTunnels() {
	for id := range s.runtimeSnapshot() {
		s.stopSOCKS5(id)
	}
}

// freePort 先占再放，拿一个大概率空闲的端口。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func dialPort(port int) bool {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// waitPortState 等端口进入期望状态（监听从 accept 到可拨号有极短延迟）。
func waitPortState(t *testing.T, port int, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if dialPort(port) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("端口 %d 期望 listening=%v，超时未达成", port, want)
}

// postTunnel 调 createTunnelHandler，返回解析后的响应与原始响应体（用于断言不回显口令）。
func postTunnel(t *testing.T, s *Server, body string) (map[string]interface{}, string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/tunnels", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.createTunnelHandler(w, req)
	if w.Code != 200 {
		t.Fatalf("create 状态码=%d body=%s", w.Code, w.Body.String())
	}
	raw := w.Body.String()
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("create 响应不是 JSON：%v body=%s", err, raw)
	}
	return out, raw
}

// getTunnels 调 listTunnelsHandler，返回解析后的响应与原始响应体。
func getTunnels(t *testing.T, s *Server, query string) (map[string]interface{}, string) {
	t.Helper()
	target := "/api/v1/tunnels"
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest("GET", target, nil)
	w := httptest.NewRecorder()
	s.listTunnelsHandler(w, req)
	if w.Code != 200 {
		t.Fatalf("list 状态码=%d body=%s", w.Code, w.Body.String())
	}
	raw := w.Body.String()
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("list 响应不是 JSON：%v body=%s", err, raw)
	}
	return out, raw
}

func deleteTunnel(t *testing.T, s *Server, id string) (map[string]interface{}, string) {
	t.Helper()
	req := httptest.NewRequest("DELETE", "/api/v1/tunnels/"+id, nil)
	req = mux.SetURLVars(req, map[string]string{"id": id})
	w := httptest.NewRecorder()
	s.closeTunnelHandler(w, req)
	if w.Code != 200 {
		t.Fatalf("delete 状态码=%d body=%s", w.Code, w.Body.String())
	}
	raw := w.Body.String()
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("delete 响应不是 JSON：%v body=%s", err, raw)
	}
	return out, raw
}

// serverEntries 取出列表响应里的 servers 数组。
func serverEntries(t *testing.T, resp map[string]interface{}) []map[string]interface{} {
	t.Helper()
	raw, ok := resp["servers"].([]interface{})
	if !ok {
		t.Fatalf("列表响应缺少 servers 数组：%+v", resp)
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("servers 元素不是对象：%T", item)
		}
		out = append(out, m)
	}
	return out
}

// socks5Probe 做一次真实的 SOCKS5 方法协商（可选再做用户名/口令子协商），
// 返回（服务端选中的方法字节, 认证是否通过）：
//
//	0x00 无认证 / 0x02 用户名口令 / 0xFF 无可用方法
//
// 不发 CONNECT：没有植入端也能验证"端口在监听"与"认证真的生效"。
func socks5Probe(t *testing.T, port int, offerUserPass bool, user, pass string) (byte, bool) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("socks5 dial %d: %v", port, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	methods := []byte{0x00}
	if offerUserPass {
		methods = append(methods, 0x02)
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		t.Fatalf("socks5 write methods: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("socks5 read method reply: %v", err)
	}
	if reply[0] != 0x05 {
		t.Fatalf("socks5 版本字节异常：%v", reply)
	}
	if reply[1] != 0x02 {
		return reply[1], false
	}
	sub := []byte{0x01, byte(len(user))}
	sub = append(sub, user...)
	sub = append(sub, byte(len(pass)))
	sub = append(sub, pass...)
	if _, err := conn.Write(sub); err != nil {
		t.Fatalf("socks5 write subnegotiation: %v", err)
	}
	res := make([]byte, 2)
	if _, err := io.ReadFull(conn, res); err != nil {
		t.Fatalf("socks5 read subnegotiation reply: %v", err)
	}
	return reply[1], res[1] == 0x00
}

// TestTunnelCreatePersistsListAndCloseDeletes 覆盖：创建→落库→列表可见→关闭→列表消失，
// 并顺带验证"口令不回显"与"认证真的生效"。
func TestTunnelCreatePersistsListAndCloseDeletes(t *testing.T) {
	env := newTunnelTestEnv(t)
	port := freePort(t)
	const (
		user = "operator-x"
		pass = "s3cret-pass-9"
	)
	body := fmt.Sprintf(`{"session_id":"sess-create","local_port":%d,"auth_user":%q,"auth_pass":%q,"remark":"prod"}`,
		port, user, pass)

	resp, rawCreate := postTunnel(t, env.s, body)
	if resp["success"] != true {
		t.Fatalf("创建应成功：%+v", resp)
	}
	if resp["auth_enabled"] != true {
		t.Errorf("应回显 auth_enabled=true：%+v", resp)
	}
	if resp["persisted"] != true {
		t.Errorf("有库时 persisted 应为 true：%+v", resp)
	}
	if resp["restored"] != false {
		t.Errorf("新建的代理不应标 restored：%+v", resp)
	}
	if got, _ := resp["local_port"].(float64); int(got) != port {
		t.Errorf("local_port 不符：got=%v want=%d", resp["local_port"], port)
	}
	// 安全：口令与用户名都不许出现在响应里（只回 auth_enabled）。
	if strings.Contains(rawCreate, pass) || strings.Contains(rawCreate, user) {
		t.Errorf("创建响应回显了口令/用户名：%s", rawCreate)
	}

	// ① 落库
	row, err := env.store.Get("sess-create")
	if err != nil {
		t.Fatalf("创建后应在 tunnels 表里：%v", err)
	}
	if row.LocalPort != port || !row.AuthEnabled || row.Status != tunnelstore.StatusRunning || row.Remark != "prod" {
		t.Fatalf("落库内容不符：%+v", row)
	}
	// ② 端口真的在监听 + 认证生效
	waitPortState(t, port, true)
	if m, ok := socks5Probe(t, port, false, "", ""); m != 0xFF || ok {
		t.Errorf("启用认证时只提供无认证方法应回 0xFF，实际 method=%#x ok=%v", m, ok)
	}
	if m, ok := socks5Probe(t, port, true, user, pass); m != 0x02 || !ok {
		t.Errorf("正确口令应认证通过，实际 method=%#x ok=%v", m, ok)
	}
	if _, ok := socks5Probe(t, port, true, user, "wrong-pass"); ok {
		t.Error("错误口令不应认证通过")
	}

	// ③ 列表以库为准
	list, rawList := getTunnels(t, env.s, "")
	entries := serverEntries(t, list)
	if len(entries) != 1 {
		t.Fatalf("列表应有 1 条，实际 %d：%s", len(entries), rawList)
	}
	entry := entries[0]
	if entry["id"] != "sess-create" || entry["session_id"] != "sess-create" {
		t.Errorf("id/session_id 不符：%+v", entry)
	}
	if entry["listening"] != true || entry["status"] != "running" || entry["restored"] != false || entry["persisted"] != true {
		t.Errorf("运行态/库态对账不符：%+v", entry)
	}
	if entry["auth_enabled"] != true || entry["remark"] != "prod" {
		t.Errorf("auth_enabled/remark 不符：%+v", entry)
	}
	if _, ok := entry["created_at"].(string); !ok {
		t.Errorf("列表应带 created_at：%+v", entry)
	}
	if strings.Contains(rawList, pass) || strings.Contains(rawList, user) {
		t.Errorf("列表响应回显了口令/用户名：%s", rawList)
	}

	// ④ 关闭 → 库删、列表消失、端口释放
	del, _ := deleteTunnel(t, env.s, "sess-create")
	if del["success"] != true {
		t.Fatalf("关闭应成功：%+v", del)
	}
	if _, err := env.store.Get("sess-create"); !errors.Is(err, tunnelstore.ErrNotFound) {
		t.Fatalf("关闭后库里应没有该记录，实际：%v", err)
	}
	list2, _ := getTunnels(t, env.s, "")
	if n := len(serverEntries(t, list2)); n != 0 {
		t.Fatalf("关闭后列表应为空，实际 %d 条", n)
	}
	waitPortState(t, port, false)
}

// TestTunnelRestoreAfterRestart 覆盖核心目标：服务端重启后按库自动重建监听，
// 列表里能看出"已恢复"，且认证口令也一起恢复（解密正确）。
func TestTunnelRestoreAfterRestart(t *testing.T) {
	env := newTunnelTestEnv(t)
	port := freePort(t)
	const (
		user = "operator-x"
		pass = "s3cret-pass-9"
	)
	postTunnel(t, env.s, fmt.Sprintf(
		`{"session_id":"sess-restore","local_port":%d,"auth_user":%q,"auth_pass":%q}`, port, user, pass))
	waitPortState(t, port, true)

	// 模拟进程退出：内存态消失（代理 map 清空），库保留。
	env.s.stopAllTunnels()
	waitPortState(t, port, false)

	s2 := env.restartServer(t)
	restored, failed := s2.RestoreTunnels()
	if restored != 1 || failed != 0 {
		t.Fatalf("应恢复 1 条、失败 0 条，实际 restored=%d failed=%d", restored, failed)
	}

	// ① 库里那条还在，且被标记为已恢复
	row, err := env.store.Get("sess-restore")
	if err != nil {
		t.Fatalf("重启后记录应还在：%v", err)
	}
	if !row.Restored || row.Status != tunnelstore.StatusRunning || row.LastError != "" {
		t.Fatalf("恢复后状态不符：%+v", row)
	}
	// ② 端口重新在监听
	waitPortState(t, port, true)
	// ③ 列表能看出"已恢复"，运行态一致
	list, raw := getTunnels(t, s2, "")
	entries := serverEntries(t, list)
	if len(entries) != 1 {
		t.Fatalf("恢复后列表应有 1 条：%s", raw)
	}
	if entries[0]["restored"] != true || entries[0]["listening"] != true || entries[0]["status"] != "running" {
		t.Errorf("恢复后的列表状态不符：%+v", entries[0])
	}
	// ④ 认证口令也恢复了（能通过子协商 = 解密正确、没有降级成无认证）
	if m, ok := socks5Probe(t, port, false, "", ""); m != 0xFF || ok {
		t.Errorf("恢复后仍应要求认证，实际 method=%#x ok=%v", m, ok)
	}
	if m, ok := socks5Probe(t, port, true, user, pass); m != 0x02 || !ok {
		t.Errorf("恢复后的口令应可用，实际 method=%#x ok=%v", m, ok)
	}
	// ⑤ 幂等：再恢复一次不会起第二份监听，也不会把状态弄坏
	if r2, f2 := s2.RestoreTunnels(); r2 != 1 || f2 != 0 {
		t.Errorf("重复恢复应幂等（1/0），实际 restored=%d failed=%d", r2, f2)
	}
}

// TestTunnelRestorePortInUseMarksErrorAndKeepsOthers 覆盖降级行为：
// 端口被占用 → 该条标 error + 记录原因，其余照常恢复，进程不崩，并打出汇总日志。
func TestTunnelRestorePortInUseMarksErrorAndKeepsOthers(t *testing.T) {
	env := newTunnelTestEnv(t)
	goodPort := freePort(t)
	badPort := freePort(t)

	// 手工占住 badPort（模拟"别的进程占着端口"），测试结束释放。
	occupier, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", badPort))
	if err != nil {
		t.Fatalf("占用 %d 失败：%v", badPort, err)
	}
	t.Cleanup(func() { _ = occupier.Close() })

	// 直接写库（模拟上一次进程留下的两条"应该存在"的记录）
	if err := env.store.Upsert(&tunnelstore.Tunnel{
		ID: "sess-bad", SessionID: "sess-bad", LocalPort: badPort, Status: tunnelstore.StatusRunning,
	}, ""); err != nil {
		t.Fatalf("seed bad: %v", err)
	}
	if err := env.store.Upsert(&tunnelstore.Tunnel{
		ID: "sess-good", SessionID: "sess-good", LocalPort: goodPort, Status: tunnelstore.StatusRunning,
	}, ""); err != nil {
		t.Fatalf("seed good: %v", err)
	}

	// 捕获汇总日志（logging 包在未初始化文件日志时走标准库 log）。
	var logBuf bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prevOut)

	s := env.restartServer(t)
	restored, failed := s.RestoreTunnels()
	if restored != 1 || failed != 1 {
		t.Fatalf("应 1 成功 1 失败，实际 restored=%d failed=%d", restored, failed)
	}

	// 失败那条：标 error + 有原因；成功那条：running + restored
	bad, err := env.store.Get("sess-bad")
	if err != nil {
		t.Fatalf("Get(bad): %v", err)
	}
	if bad.Status != tunnelstore.StatusError || bad.LastError == "" {
		t.Fatalf("端口占用那条应被标 error 且有原因：%+v", bad)
	}
	good, err := env.store.Get("sess-good")
	if err != nil {
		t.Fatalf("Get(good): %v", err)
	}
	if good.Status != tunnelstore.StatusRunning || !good.Restored {
		t.Fatalf("正常那条应恢复成功：%+v", good)
	}
	waitPortState(t, goodPort, true)

	// 列表里失败条目 listening=false / status=error / last_error 可见（其余字段照常）。
	list, _ := getTunnels(t, s, "")
	entries := serverEntries(t, list)
	if len(entries) != 2 {
		t.Fatalf("列表应有 2 条，实际 %d", len(entries))
	}
	var badEntry map[string]interface{}
	for _, e := range entries {
		if e["id"] == "sess-bad" {
			badEntry = e
		}
	}
	if badEntry == nil {
		t.Fatal("列表里应能看到失败的那条（不能因为失败就藏起来）")
	}
	if badEntry["listening"] != false || badEntry["status"] != "error" || badEntry["restored"] != false {
		t.Errorf("失败条目状态不符：%+v", badEntry)
	}
	if s, _ := badEntry["last_error"].(string); s == "" {
		t.Errorf("失败条目应带 last_error：%+v", badEntry)
	}

	// 汇总日志格式： [tunnel] restored 1/2 (1 failed: port NNN in use)
	got := logBuf.String()
	if !strings.Contains(got, "[INFO] [tunnel] restored 1/2") {
		t.Errorf("缺少恢复汇总日志行，实际日志：\n%s", got)
	}
	if !strings.Contains(got, fmt.Sprintf("port %d in use", badPort)) {
		t.Errorf("汇总日志应指出被占用的端口 %d，实际日志：\n%s", badPort, got)
	}
}

// TestTunnelWithoutStoreDegradesToMemory 覆盖无库降级：行为等同 v1.4.0（只在内存），
// API 用 persisted=false 明示，创建/列表/关闭仍然可用。
func TestTunnelWithoutStoreDegradesToMemory(t *testing.T) {
	env := newTunnelTestEnv(t)
	env.s.tunnelStore = nil
	port := freePort(t)

	resp, _ := postTunnel(t, env.s, fmt.Sprintf(`{"session_id":"sess-mem","local_port":%d}`, port))
	if resp["success"] != true || resp["persisted"] != false {
		t.Fatalf("无库时应成功但 persisted=false：%+v", resp)
	}
	waitPortState(t, port, true)

	list, _ := getTunnels(t, env.s, "")
	entries := serverEntries(t, list)
	if len(entries) != 1 || entries[0]["persisted"] != false || entries[0]["listening"] != true {
		t.Fatalf("无库降级列表不符：%+v", entries)
	}
	// 未启用认证时代理应接受 0x00 方法。
	if m, _ := socks5Probe(t, port, false, "", ""); m != 0x00 {
		t.Errorf("无认证代理应选中 0x00 方法，实际 %#x", m)
	}

	if del, _ := deleteTunnel(t, env.s, "sess-mem"); del["success"] != true {
		t.Fatalf("无库时关闭也应成功：%+v", del)
	}
	waitPortState(t, port, false)
}

// TestRebindTunnelHandlerIsSafe 覆盖会话上线补绑逻辑的健壮性（幂等、无代理时不 panic）。
func TestRebindTunnelHandlerIsSafe(t *testing.T) {
	env := newTunnelTestEnv(t)
	// 没有代理时调用：直接返回，不应 panic。
	env.s.RebindTunnelHandler("nope")
	env.s.RebindTunnelHandler("")

	port := freePort(t)
	postTunnel(t, env.s, fmt.Sprintf(`{"session_id":"sess-bind","local_port":%d}`, port))
	// 会话不存在时调用：同样安全。
	env.s.RebindTunnelHandler("sess-bind")
	waitPortState(t, port, true)
}
