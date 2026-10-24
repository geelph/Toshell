package api

// 展示层编码归一（GBK → UTF-8）的接线测试。
//
// 守护两件事：
//  1. 用户报的两条乱码回显（EDR 击杀 / 启动项）都经过同一个展示漏斗，漏斗真的生效；
//  2. **边界**：转换只发生在展示副本上，任务存储里的原始字节一字不改，
//     且 GET /tasks/{id}?raw=1 能无损回读原始字节（base64）。

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gorilla/mux"
	"toshell/internal/common/types"
	"toshell/internal/server/task"
)

// realTaskkillGBK 真实字节：中文 Windows 上 taskkill 的报错输出
// （见 .tmp-verify/gbk-repro/taskkill.raw，chcp 936 捕获）。
const realTaskkillGBKHex = "b4edcef33a20c3bbd3d0d5d2b5bdbdf8b3cc2022746f7368656c6c5f6e6f5f737563685f61762e65786522a1a30d0a"

// gbkEDRTaskkillOutput 模拟"杀软击杀"回执的真实形态：
// 植入端自己写的 UTF-8 表头 + 被调 taskkill 的 GBK 输出。
func gbkEDRTaskkillOutput(t *testing.T) string {
	t.Helper()
	raw, err := hex.DecodeString(realTaskkillGBKHex)
	if err != nil {
		t.Fatalf("fixture hex: %v", err)
	}
	return "== EDR Kill (击杀) ==\n[-] 360tray.exe: " + string(raw)
}

// completeTaskWithOutput 建一条已完成任务（不走数据库、不起监听器）。
func completeTaskWithOutput(t *testing.T, env *agentTaskTestEnv, taskType, output string) uint64 {
	t.Helper()
	info, err := env.tm.Create(env.sid, task.TaskParams{TaskType: taskType, Command: "probe"})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := env.tm.Complete(info.ID, 0, output, ""); err != nil {
		t.Fatalf("complete task: %v", err)
	}
	return info.ID
}

// 展示漏斗（GET /api/v1/tasks/{id}）必须把 GBK 部分解成中文，且不动 UTF-8 表头。
func TestGetTaskHandlerDecodesGBKForDisplay(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	raw := gbkEDRTaskkillOutput(t)
	id := completeTaskWithOutput(t, env, "edr_kill", raw)

	req := httptest.NewRequest("GET", "/api/v1/tasks/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": uintToString(id)})
	rec := httptest.NewRecorder()
	env.s.getTaskHandler(rec, req)

	var got struct {
		Status        string `json:"status"`
		Output        string `json:"output"`
		OutputDecoded bool   `json:"output_decoded"`
		OutputRaw     int    `json:"output_raw_bytes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是 JSON: %v (%s)", err, rec.Body.String())
	}
	const wantHead = "== EDR Kill (击杀) ==\n[-] 360tray.exe: 错误: 没有找到进程 \"toshell_no_such_av.exe\"。"
	if !strings.HasPrefix(got.Output, wantHead) {
		t.Fatalf("展示输出未正确解码:\n got %q\nwant 前缀 %q", got.Output, wantHead)
	}
	if strings.Contains(got.Output, "鍑绘潃") {
		t.Fatalf("UTF-8 中文被二次转换成了乱码: %q", got.Output)
	}
	if !got.OutputDecoded {
		t.Error("output_decoded 应为 true（发生了 GBK→UTF-8 转换）")
	}
	if got.OutputRaw != len(raw) {
		t.Errorf("output_raw_bytes = %d, want %d（原始字节数）", got.OutputRaw, len(raw))
	}

	// ── 边界：存储层必须还是原始字节 ──
	stored, err := env.tm.Get(id)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if stored.Output != raw {
		t.Fatalf("展示转换污染了任务原始结果！\n stored %q\n  want %q", stored.Output, raw)
	}
}

// raw=1 必须能无损回读原始字节（非法 UTF-8 用 base64 承载）。
func TestGetTaskHandlerRawBytes(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	raw := gbkEDRTaskkillOutput(t)
	id := completeTaskWithOutput(t, env, "persistence", raw)

	req := httptest.NewRequest("GET", "/api/v1/tasks/1?raw=1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": uintToString(id)})
	rec := httptest.NewRecorder()
	env.s.getTaskHandler(rec, req)

	var got struct {
		OutputB64      string `json:"output_b64"`
		OutputBytes    int    `json:"output_bytes"`
		OutputEncoding string `json:"output_encoding"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("raw 响应不是 JSON: %v", err)
	}
	if got.OutputEncoding != "raw" || got.OutputBytes != len(raw) {
		t.Fatalf("raw 元信息不对: %+v (want bytes=%d)", got, len(raw))
	}
	decoded, err := base64.StdEncoding.DecodeString(got.OutputB64)
	if err != nil {
		t.Fatalf("output_b64 不是合法 base64: %v", err)
	}
	if string(decoded) != raw {
		t.Fatalf("raw=1 回读的字节与原始结果不一致:\n got %q\nwant %q", decoded, raw)
	}
}

// 任务列表（GET /api/v1/tasks）同样只回展示副本，且字段是扁平化的（嵌入结构体不能变成嵌套）。
func TestListTasksHandlerDecodes(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	raw := gbkEDRTaskkillOutput(t)
	completeTaskWithOutput(t, env, "edr_kill", raw)

	req := httptest.NewRequest("GET", "/api/v1/tasks", nil)
	rec := httptest.NewRecorder()
	env.s.listTasksHandler(rec, req)

	var got struct {
		Tasks []struct {
			ID            uint64 `json:"id"`
			SessionID     string `json:"session_id"`
			TaskType      string `json:"task_type"`
			Status        string `json:"status"`
			Output        string `json:"output"`
			OutputDecoded bool   `json:"output_decoded"`
		} `json:"tasks"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("列表响应不是 JSON: %v", err)
	}
	if got.Count != 1 || len(got.Tasks) != 1 {
		t.Fatalf("列表条数不对: count=%d len=%d", got.Count, len(got.Tasks))
	}
	tk := got.Tasks[0]
	// 嵌入的 TaskInfo 字段必须被提升到顶层（不能出现 {"TaskInfo":{...}} 这种嵌套）。
	if tk.TaskType != "edr_kill" || tk.SessionID != env.sid || tk.Status != "completed" {
		t.Fatalf("TaskInfo 字段未扁平化: %+v", tk)
	}
	if !strings.Contains(tk.Output, "错误: 没有找到进程") || strings.Contains(tk.Output, "鍑绘潃") {
		t.Fatalf("列表输出未解码: %q", tk.Output)
	}
	if !tk.OutputDecoded {
		t.Error("列表里的 output_decoded 应为 true")
	}
}

// 工具/AI 结果信封（taskOutput）同样走展示解码；纯 UTF-8 结果保持原样。
func TestTaskOutputDisplayDecoding(t *testing.T) {
	if got := taskOutput(nil); got != "" {
		t.Errorf("taskOutput(nil) = %q, want empty", got)
	}
	g := &types.TaskInfo{Output: gbkEDRTaskkillOutput(t)}
	if out := taskOutput(g); !strings.Contains(out, "错误: 没有找到进程") || strings.Contains(out, "鍑绘潃") {
		t.Fatalf("taskOutput 未正确解码: %q", out)
	}
	// 启动项 list 这类纯 UTF-8 输出必须原样返回。
	const utf8Out = "== 持久化方法（启动项）列表 ==\nregistry_run | 是 | HKCU\\...\\Run 注册表启动项\n"
	u := &types.TaskInfo{Output: utf8Out}
	if got := taskOutput(u); got != utf8Out {
		t.Fatalf("合法 UTF-8 被改动了:\n got %q\nwant %q", got, utf8Out)
	}
}

// 摘要截断必须落在 rune 边界上（旧的 output[:200] 会切出半个汉字 → "�"）。
func TestSummarizeOutputRuneSafe(t *testing.T) {
	long := strings.Repeat("持久化成功", 80) // 300 字节 UTF-8
	got := summarizeOutput(long, 10)
	if !utf8.ValidString(got) {
		t.Fatalf("摘要不是合法 UTF-8（切坏了 rune）: %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("超长摘要应带省略号: %q", got)
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Fatalf("摘要里出现替换字符: %q", got)
	}
	// GBK 输入先解码再截断，不能截出半截 GBK 双字节。
	gbkLong := strings.Repeat(strings.Repeat("\xB4\xED\xCE\xF3", 1), 100) // "错误" × 100
	got = summarizeOutput(gbkLong, 9)
	if strings.ContainsRune(got, utf8.RuneError) || !utf8.ValidString(got) {
		t.Fatalf("GBK 摘要切坏了: %q", got)
	}
	if short := summarizeOutput("ok", 10); short != "ok" {
		t.Errorf("短输出不应被改动: %q", short)
	}
}

// WebSocket 任务事件里的 output/error 也必须是展示文本。
func TestBroadcastTaskEventDecodes(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	env.s.wsHub = NewWSHub()
	raw := gbkEDRTaskkillOutput(t)
	env.s.BroadcastTaskEvent("task_completed", 7, env.sid, "edr_kill", 0, raw, "")

	select {
	case data := <-env.s.wsHub.broadcast:
		var ev WSEvent
		if err := json.Unmarshal(data, &ev); err != nil {
			t.Fatalf("WS 事件不是 JSON: %v", err)
		}
		payload, _ := ev.Payload.(map[string]interface{})
		out, _ := payload["output"].(string)
		if !strings.Contains(out, "错误: 没有找到进程") || strings.Contains(out, "鍑绘潃") {
			t.Fatalf("WS 事件输出未解码: %q", out)
		}
	default:
		t.Fatal("没有收到 WS 广播")
	}
}

// uintToString 避免为一行转换引入 strconv 依赖噪音。
func uintToString(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
