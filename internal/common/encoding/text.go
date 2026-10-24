package encoding

// 展示层文本编码归一（命令输出/任务结果 → 界面可读文本）。
//
// 背景：Windows 控制台工具（tasklist / net user / sc query / reg query / taskkill…）
// 在中文系统上按 CP936(GBK) 输出字节；这些字节若直接当 UTF-8 展示就是乱码。植入端会在
// 捕获侧做一次归一（builders/implant 的 decodeConsoleText），但服务端仍需要自己的
// 解释层，原因有三：
//  1. 已经在现场运行的旧版本载荷不会重编，它们回传的仍是原始 GBK 字节；
//  2. 载荷的输出可能是"植入端自己写的 UTF-8 + 被调工具的 GBK"混合串；
//  3. 展示层是唯一能保证"原始结果不被改写"的位置 —— 转换只作用于展示副本。
//
// 边界（必须守住）：这里的函数**只用于展示**。任务的原始 Output 字节必须原样留在
// 任务存储里（可回读/可下载），任何写回 task.Output 的调用都是错的。
//
// 判定顺序（每一行独立判定，避免把混合串里已经正确的部分打坏）：
//  1. 合法 UTF-8 → 原样保留（ASCII、植入端自写中文、base64 JSON 都走这条）；
//  2. 非法 UTF-8 → 按 GBK(CP936) 解码，解码结果里没有替换字符则采用；
//  3. GBK 也解不出来（二进制/其它编码）→ 显式标注 + 原始字节十六进制预览（不静默丢数据）。
//
// 为什么是"逐行"而不是"整串"：GBK 双字节的尾字节范围 0x40–0xFE，绝大多数组合都不是
// 合法 UTF-8 序列，因此"这一行是不是合法 UTF-8"是一个稳定、廉价的信号；而一整串里
// 同时存在 UTF-8 行与 GBK 行是常态（中文回执 + 中文工具输出）。

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

const (
	// maxBinaryPreviewBytes 十六进制兜底预览的字节上限（防止一个二进制结果把界面撑爆）。
	maxBinaryPreviewBytes = 512
	// binaryPreviewTag 兜底标注前缀：前端/操作员一眼能看出"这不是正常文本"。
	binaryPreviewTag = "[服务端提示] 该段输出不是合法 UTF-8，且无法按 GBK(CP936) 解码"
)

// DecodeOutputText 把一段"来自被控主机"的输出归一成可展示的 UTF-8 文本。
// 合法 UTF-8 原样返回（同一个字符串，零拷贝），因此对已经是 UTF-8 的结果完全无副作用。
func DecodeOutputText(s string) string {
	text, _ := DecodeOutputTextReport(s)
	return text
}

// DecodeOutputTextReport 与 DecodeOutputText 相同，额外返回"是否发生过转换"。
// 调用方可用它给前端标注"此结果由服务端按 GBK 解码展示"（转换前后字节数可能不同）。
func DecodeOutputTextReport(s string) (string, bool) {
	if s == "" || utf8.ValidString(s) {
		return s, false
	}
	lines := strings.Split(s, "\n")
	converted := false
	for i, line := range lines {
		if line == "" || utf8.ValidString(line) {
			continue
		}
		if decoded, ok := decodeGBKLine(line); ok {
			lines[i] = decoded
		} else {
			lines[i] = binaryPreview(line)
		}
		converted = true
	}
	if !converted {
		// 理论上到不了这里（整串非法必然至少有一行非法），保险起见原样返回。
		return s, false
	}
	return strings.Join(lines, "\n"), true
}

// decodeGBKLine 尝试把一行 GBK 字节解成 UTF-8。
// 失败（或解码结果含 U+FFFD 替换字符）返回 ok=false，交给十六进制兜底：
// x/text 的 GBK 解码器对非法字节**不会报错**，而是替换成 U+FFFD，所以必须显式检查。
func decodeGBKLine(line string) (string, bool) {
	decoded, err := simplifiedchinese.GBK.NewDecoder().String(line)
	if err != nil || !utf8.ValidString(decoded) {
		return "", false
	}
	if strings.ContainsRune(decoded, utf8.RuneError) {
		return "", false
	}
	return decoded, true
}

// binaryPreview 为"既不是 UTF-8 也不是 GBK"的字节生成显式标注 + 十六进制预览。
// 不静默丢字节：标注里给出总字节数，预览受 maxBinaryPreviewBytes 限制（超出会说明只取了前 N 字节）。
func binaryPreview(line string) string {
	total := len(line)
	shown := line
	truncated := false
	if total > maxBinaryPreviewBytes {
		shown = line[:maxBinaryPreviewBytes]
		truncated = true
	}
	var b strings.Builder
	b.WriteString(binaryPreviewTag)
	if truncated {
		b.WriteString(fmt.Sprintf("（共 %d 字节，下面只预览前 %d 字节）：", total, len(shown)))
	} else {
		b.WriteString(fmt.Sprintf("（共 %d 字节）：", total))
	}
	b.WriteString(hex.EncodeToString([]byte(shown)))
	return b.String()
}
