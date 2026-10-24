package api

// 任务输出 → 展示文本的**唯一转换点**。
//
// 为什么要有这个文件（而不是每处各写一段）：
//   - 用户报的"杀软击杀回显全是乱码 / 启动项回显乱码"走的是两条不同的业务链
//     （sessions/{id}/edr/kill 与 sessions/{id}/persistence → 同一个任务结果通道），
//     但它们最终都从 task.Output 取文本展示。只在这个漏斗里做编码归一，
//     两条链就一起修好，而不是各打一个补丁。
//   - 展示漏斗共三个：工具/AI 结果信封（taskOutput）、Web 的 GET /tasks/{id} 与
//     任务列表（newTaskDisplay）、WebSocket 任务事件（BroadcastTaskEvent）。
//     三处都只对**副本**做转换。
//
// 边界（硬约束）：转换结果绝不写回 task.Output，也不进数据库。
//   - 原始字节仍可用 GET /api/v1/tasks/{id}?raw=1 回读（base64 无损）；
//   - 二进制/截图等结果本来就是合法 UTF-8（base64 JSON），转换对它们是恒等操作；
//   - 因此"大文件/二进制语义"不受影响。
//
// 具体解码规则见 internal/common/encoding/text.go（UTF-8 原样 / GBK 解码 / 十六进制兜底）。

import (
	"unicode/utf8"

	textenc "toshell/internal/common/encoding"
	"toshell/internal/common/types"
)

// displayOutput 把一段可能来自 GBK 控制台的输出归一成可展示文本。
// 合法 UTF-8 输入原样返回，调用它可以无条件幂等地加在任何展示路径上。
func displayOutput(s string) string {
	return textenc.DecodeOutputText(s)
}

// taskDisplay 是 TaskInfo 的展示视图：Output 已按展示需要归一，其余字段与存储层一致。
// 用匿名嵌入而不是复制结构体，避免 TaskInfo 新增字段后这里漏同步。
type taskDisplay struct {
	*types.TaskInfo
	// OutputDecoded 本次展示是否对 output/error 做过编码归一
	// （false = 原始结果本来就是合法 UTF-8 或为空）。
	OutputDecoded bool `json:"output_decoded,omitempty"`
	// OutputRawBytes 原始输出字节数（与展示文本的字符/字节数可能不同，
	// 前端要显示"原始大小"时用这个，不要用 output 的长度反推）。
	OutputRawBytes int `json:"output_raw_bytes,omitempty"`
}

// newTaskDisplay 构造任务的展示副本：只改副本里的 Output/Error，存储层的 task 不动。
func newTaskDisplay(t *types.TaskInfo) *taskDisplay {
	if t == nil {
		return nil
	}
	cp := *t
	output, convOut := textenc.DecodeOutputTextReport(t.Output)
	errText, convErr := textenc.DecodeOutputTextReport(t.Error)
	cp.Output = output
	cp.Error = errText
	return &taskDisplay{
		TaskInfo:       &cp,
		OutputDecoded:  convOut || convErr,
		OutputRawBytes: len(t.Output),
	}
}

// taskDisplays 批量构造展示副本（任务列表用）。
func taskDisplays(tasks []*types.TaskInfo) []*taskDisplay {
	out := make([]*taskDisplay, 0, len(tasks))
	for _, t := range tasks {
		if t == nil {
			continue
		}
		out = append(out, newTaskDisplay(t))
	}
	return out
}

// summarizeOutput 生成"任务完成"事件里的短摘要：先做展示解码，再按**字符边界**截断。
//
// 历史实现直接 output[:200] 按字节切：UTF-8/GBK 中文被切在半路时，JSON 序列化
// 会给出一个 U+FFFD，前端看到的末尾就是一个"�"。这里保证切点落在 rune 边界上。
func summarizeOutput(s string, maxBytes int) string {
	s = displayOutput(s)
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
