package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── 批量任务下发用例（v1.4.1）──────────────────────────────────────────────
//
// 全部不联网、不需要真实植入端：会话是进程内注册的假会话，任务是隔离的任务管理器，
// 推送用假 TaskPusher（记录实际下发次数）。因此可以精确断言"逐项独立"语义：
// 某一项失败既不会让请求整体 500，也不会阻止其它项被创建/推送。
//
// 覆盖任务书要求的五种情形：
//   - 全成功；
//   - 部分失败（会话不存在），且失败项不影响成功项；
//   - 空列表 / 超上限（201 个）→ 400；
//   - 破坏性任务被拒，且拒绝按逐项失败传播（不创建任何任务）；
//   - "一次批量 = 一条审计"（带目标数与成功/失败计数）。

type bulkTestEnv struct {
	s      *Server
	sess   *session.Manager
	tm     *task.Manager
	pusher *fakePusher
	ids    []string

	mu     sync.Mutex
	audits []bulkTasksAuditEvent
}

// newBulkTestEnv 构造最小可用的 Server + nSessions 个在线会话。
//
// ⚠️ session.New() 是进程级单例：用例必须用唯一 id 并在结束时移除，否则 -count=N
// 重跑会撞 "session already exists"（与 handlers_session_guard_test.go 同一约定）。
func newBulkTestEnv(t *testing.T, nSessions int) *bulkTestEnv {
	t.Helper()

	sessMgr := session.New()
	tm := task.NewIsolated(sessMgr)
	pusher := &fakePusher{}
	s := &Server{sessionMgr: sessMgr, taskMgr: tm, listener: pusher}

	env := &bulkTestEnv{s: s, sess: sessMgr, tm: tm, pusher: pusher}
	prefix := fmt.Sprintf("bulk-%d", time.Now().UnixNano())
	for i := 0; i < nSessions; i++ {
		id := fmt.Sprintf("%s-%d", prefix, i)
		if err := sessMgr.Add(&types.SessionInfo{ID: id, Hostname: "host", Status: "active"}); err != nil {
			t.Fatalf("session Add: %v", err)
		}
		env.ids = append(env.ids, id)
	}
	t.Cleanup(func() {
		for _, id := range env.ids {
			_ = sessMgr.Remove(id)
		}
	})

	prevHook := bulkTasksAuditHook
	bulkTasksAuditHook = func(ev bulkTasksAuditEvent) {
		env.mu.Lock()
		env.audits = append(env.audits, ev)
		env.mu.Unlock()
	}
	t.Cleanup(func() { bulkTasksAuditHook = prevHook })

	return env
}

// bulkBody 把请求对象序列化成 JSON。
func bulkBody(t *testing.T, v map[string]interface{}) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(raw)
}

// post 调用 handler 并解出 JSON 响应。
func (e *bulkTestEnv) post(t *testing.T, body string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/bulk", strings.NewReader(body))
	rec := httptest.NewRecorder()
	e.s.bulkTasksHandler(rec, req)
	return rec.Code, decodeJSON(t, rec)
}

// auditSnapshot 取当前已记录的审计事件（拷贝，避免与 hook 竞争）。
func (e *bulkTestEnv) auditSnapshot() []bulkTasksAuditEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]bulkTasksAuditEvent, len(e.audits))
	copy(out, e.audits)
	return out
}

// itemsOf 把响应里的 items 数组转成 map 切片（null 安全）。
func itemsOf(t *testing.T, body map[string]interface{}) []map[string]interface{} {
	t.Helper()
	raw, ok := body["items"].([]interface{})
	if !ok {
		t.Fatalf("响应缺少 items 数组：%v", body)
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, v := range raw {
		m, ok := v.(map[string]interface{})
		if !ok {
			t.Fatalf("items 元素不是对象：%v", v)
		}
		out = append(out, m)
	}
	return out
}

// itemError 取 items[i].error（字符串，空则返回 ""）。
func itemError(items []map[string]interface{}, i int) string {
	if i < 0 || i >= len(items) {
		return ""
	}
	s, _ := items[i]["error"].(string)
	return s
}

// itemOK 取 items[i].ok。
func itemOK(items []map[string]interface{}, i int) bool {
	if i < 0 || i >= len(items) {
		return false
	}
	b, _ := items[i]["ok"].(bool)
	return b
}

func TestBulkTasksAllSucceed(t *testing.T) {
	env := newBulkTestEnv(t, 2)

	code, body := env.post(t, bulkBody(t, map[string]interface{}{
		"session_ids": env.ids,
		"task_type":   "command",
		"command":     "whoami",
		"timeout":     30,
	}))
	if code != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200（body=%v）", code, body)
	}
	if got := int(body["total"].(float64)); got != 2 {
		t.Fatalf("total = %d, want 2", got)
	}
	if got := int(body["succeeded"].(float64)); got != 2 {
		t.Fatalf("succeeded = %d, want 2", got)
	}
	if got := int(body["failed"].(float64)); got != 0 {
		t.Fatalf("failed = %d, want 0", got)
	}

	items := itemsOf(t, body)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	for i, it := range items {
		if !itemOK(items, i) || itemError(items, i) != "" {
			t.Fatalf("items[%d] 应为成功：%v", i, it)
		}
		if _, ok := it["task_id"]; !ok {
			t.Fatalf("items[%d] 成功项缺少 task_id：%v", i, it)
		}
		if sid, _ := it["session_id"].(string); sid != env.ids[i] {
			t.Fatalf("items[%d].session_id = %q, want %q", i, sid, env.ids[i])
		}
	}

	// 每个会话都真的建了任务、真的推送了一次。
	if env.pusher.count() != 2 {
		t.Fatalf("推送次数 = %d, want 2", env.pusher.count())
	}
	for _, sid := range env.ids {
		tasks := env.tm.ListBySession(sid)
		if len(tasks) != 1 {
			t.Fatalf("会话 %s 任务数 = %d, want 1", sid, len(tasks))
		}
		if tasks[0].TaskType != task.TaskTypeCommand || tasks[0].Command != "whoami" {
			t.Fatalf("任务参数不符: type=%q command=%q", tasks[0].TaskType, tasks[0].Command)
		}
		if tasks[0].Timeout != 30 {
			t.Fatalf("任务 timeout = %d, want 30", tasks[0].Timeout)
		}
	}

	// 一次批量 = 一条审计，带 N 个目标与成功/失败计数。
	audits := env.auditSnapshot()
	if len(audits) != 1 {
		t.Fatalf("审计条数 = %d, want 1（批量不得展开成 N 条）", len(audits))
	}
	if audits[0].Event != "tasks_bulk" || audits[0].Targets != 2 ||
		audits[0].Succeeded != 2 || audits[0].Failed != 0 {
		t.Fatalf("审计字段不符：%+v", audits[0])
	}
	if len(audits[0].SessionIDs) != 2 {
		t.Fatalf("审计应带 2 个目标会话，实际 %v", audits[0].SessionIDs)
	}
}

func TestBulkTasksPartialFailureIsolated(t *testing.T) {
	env := newBulkTestEnv(t, 2)
	missing := fmt.Sprintf("bulk-missing-%d", time.Now().UnixNano())

	// 把"不存在的会话"夹在中间：若实现用整体事务/提前 return，后面那台就不会成功。
	ids := []string{env.ids[0], missing, env.ids[1]}
	code, body := env.post(t, bulkBody(t, map[string]interface{}{
		"session_ids": ids,
		"task_type":   "shell",
		"command":     "whoami",
	}))
	if code != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200（逐项失败不得整体 500，body=%v）", code, body)
	}
	if got := int(body["total"].(float64)); got != 3 {
		t.Fatalf("total = %d, want 3", got)
	}
	if got := int(body["succeeded"].(float64)); got != 2 {
		t.Fatalf("succeeded = %d, want 2", got)
	}
	if got := int(body["failed"].(float64)); got != 1 {
		t.Fatalf("failed = %d, want 1", got)
	}

	items := itemsOf(t, body)
	if !itemOK(items, 0) {
		t.Fatalf("失败项之前的成功项被影响：%v", items[0])
	}
	if itemOK(items, 1) {
		t.Fatalf("不存在的会话应为失败：%v", items[1])
	}
	if got := itemError(items, 1); got != "session_not_found" {
		t.Fatalf("失败原因 = %q, want session_not_found", got)
	}
	// 关键断言：失败项**之后**的项照常成功（逐项独立）。
	if !itemOK(items, 2) {
		t.Fatalf("失败项之后的目标被影响（逐项独立被破坏）：%v", items[2])
	}

	// 只有两台真实会话被建任务/推送。
	if n := env.pusher.count(); n != 2 {
		t.Fatalf("推送次数 = %d, want 2", n)
	}
	if n := env.tm.Count(); n != 2 {
		t.Fatalf("任务数 = %d, want 2", n)
	}

	audits := env.auditSnapshot()
	if len(audits) != 1 {
		t.Fatalf("审计条数 = %d, want 1", len(audits))
	}
	if audits[0].Succeeded != 2 || audits[0].Failed != 1 || audits[0].Targets != 3 {
		t.Fatalf("审计计数不符：%+v", audits[0])
	}
	if audits[0].FailureReasons["session_not_found"] != 1 {
		t.Fatalf("审计应记录失败原因分布，实际 %v", audits[0].FailureReasons)
	}
}

func TestBulkTasksEmptySessionIDs(t *testing.T) {
	env := newBulkTestEnv(t, 1)

	code, body := env.post(t, `{"session_ids":[],"command":"whoami"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("HTTP = %d, want 400（body=%v）", code, body)
	}
	if _, ok := body["error"]; !ok {
		t.Fatalf("400 响应应有 error 字段：%v", body)
	}
	// 缺字段（null）与空数组同义。
	code2, _ := env.post(t, `{"command":"whoami"}`)
	if code2 != http.StatusBadRequest {
		t.Fatalf("缺 session_ids：HTTP = %d, want 400", code2)
	}

	if n := env.tm.Count(); n != 0 {
		t.Fatalf("空列表不应创建任务，实际 %d 条", n)
	}
	if n := env.pusher.count(); n != 0 {
		t.Fatalf("空列表不应推送，实际 %d 次", n)
	}
	if n := len(env.auditSnapshot()); n != 0 {
		t.Fatalf("被 400 拒绝的请求不应写审计，实际 %d 条", n)
	}
}

func TestBulkTasksOverLimit(t *testing.T) {
	env := newBulkTestEnv(t, 1)

	ids := make([]string, 0, bulkTasksMaxSessions+1)
	for i := 0; i < bulkTasksMaxSessions+1; i++ {
		ids = append(ids, fmt.Sprintf("over-%d-%d", time.Now().UnixNano(), i))
	}
	code, body := env.post(t, bulkBody(t, map[string]interface{}{
		"session_ids": ids,
		"command":     "whoami",
	}))
	if code != http.StatusBadRequest {
		t.Fatalf("HTTP = %d, want 400（%d 个目标超过上限 %d，body=%v）",
			code, len(ids), bulkTasksMaxSessions, body)
	}

	// 边界：恰好上限不应被 400 拒绝（这里只验"上限判断是 > 而不是 >="）。
	bodyMax := bulkBody(t, map[string]interface{}{
		"session_ids": ids[:bulkTasksMaxSessions],
		"command":     "whoami",
	})
	codeMax, respMax := env.post(t, bodyMax)
	if codeMax != http.StatusOK {
		t.Fatalf("恰好 %d 个目标：HTTP = %d, want 200（body=%v）", bulkTasksMaxSessions, codeMax, respMax)
	}
	if got := int(respMax["total"].(float64)); got != bulkTasksMaxSessions {
		t.Fatalf("total = %d, want %d", got, bulkTasksMaxSessions)
	}
}

func TestBulkTasksDestructiveRejected(t *testing.T) {
	env := newBulkTestEnv(t, 2)

	code, body := env.post(t, bulkBody(t, map[string]interface{}{
		"session_ids": env.ids,
		"task_type":   "edr_blind", // avops.TaskNoRetry == true
	}))
	if code != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200（拒绝按逐项失败传播，不是整体 4xx/5xx，body=%v）", code, body)
	}
	if got := int(body["total"].(float64)); got != 2 {
		t.Fatalf("total = %d, want 2", got)
	}
	if got := int(body["succeeded"].(float64)); got != 0 {
		t.Fatalf("succeeded = %d, want 0", got)
	}
	if got := int(body["failed"].(float64)); got != 2 {
		t.Fatalf("failed = %d, want 2", got)
	}
	items := itemsOf(t, body)
	for i := range items {
		if itemOK(items, i) {
			t.Fatalf("破坏性任务 items[%d] 不应成功：%v", i, items[i])
		}
		if got := itemError(items, i); got != "destructive_task_forbidden" {
			t.Fatalf("items[%d].error = %q, want destructive_task_forbidden", i, got)
		}
		if _, ok := items[i]["task_id"]; ok {
			t.Fatalf("被拒项不应有 task_id：%v", items[i])
		}
	}

	// 守卫必须在下发**之前**生效：不建任务、不推送。
	if n := env.tm.Count(); n != 0 {
		t.Fatalf("破坏性任务被拒后不应创建任务，实际 %d 条", n)
	}
	if n := env.pusher.count(); n != 0 {
		t.Fatalf("破坏性任务被拒后不应推送，实际 %d 次", n)
	}

	audits := env.auditSnapshot()
	if len(audits) != 1 {
		t.Fatalf("审计条数 = %d, want 1", len(audits))
	}
	if audits[0].Failed != 2 || audits[0].FailureReasons["destructive_task_forbidden"] != 2 {
		t.Fatalf("审计应记录破坏性拒绝：%+v", audits[0])
	}
}

func TestBulkTasksUnknownTypeRejected(t *testing.T) {
	env := newBulkTestEnv(t, 1)

	code, body := env.post(t, bulkBody(t, map[string]interface{}{
		"session_ids": env.ids,
		"task_type":   "file_list", // 需要逐机 path，不在批量白名单
	}))
	if code != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200", code)
	}
	items := itemsOf(t, body)
	if got := itemError(items, 0); got != "task_type_not_allowed" {
		t.Fatalf("error = %q, want task_type_not_allowed", got)
	}
	if n := env.tm.Count(); n != 0 {
		t.Fatalf("白名单外类型不应创建任务，实际 %d 条", n)
	}
}

// TestBulkTasksCompatAliases 钉住任务书示例形状 { "type": "shell", "data": "whoami" }：
// 规范字段（task_type/command）为空时，别名必须能工作；规范字段非空时永远优先。
func TestBulkTasksCompatAliases(t *testing.T) {
	env := newBulkTestEnv(t, 1)

	code, body := env.post(t, bulkBody(t, map[string]interface{}{
		"session_ids": env.ids,
		"type":        "shell",
		"data":        "whoami",
		"timeout":     15,
	}))
	if code != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200（body=%v）", code, body)
	}
	items := itemsOf(t, body)
	if !itemOK(items, 0) {
		t.Fatalf("别名形状应成功：%v", items[0])
	}
	tasks := env.tm.ListBySession(env.ids[0])
	if len(tasks) != 1 || tasks[0].TaskType != task.TaskTypeShell || tasks[0].Command != "whoami" {
		t.Fatalf("别名应映射为 shell/whoami，实际 %+v", tasks)
	}
}
