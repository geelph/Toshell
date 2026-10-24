package encoding

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// gbkBytes 把 UTF-8 文本编成 GBK 字节（仅测试用：构造"中文控制台工具会吐出的字节"）。
func gbkBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatalf("GBK encode %q: %v", s, err)
	}
	return b
}

// 真实字节证据：Windows 中文系统上 `taskkill /F /IM toshell_no_such_av.exe` 的重定向输出
// （.tmp-verify/gbk-repro/taskkill.raw，chcp 936 下捕获），原样抄成十六进制。
// 这段字节不是合法 UTF-8，旧的展示路径会把它显示成 "´íÎó: Ã»ÓÐÕÒµ½½ø³Ì…"。
const realTaskkillGBKHex = "b4edcef33a20c3bbd3d0d5d2b5bdbdf8b3cc2022746f7368656c6c5f6e6f5f737563685f61762e65786522a1a30d0a"

func TestDecodeOutputTextRealGBK(t *testing.T) {
	raw, err := hex.DecodeString(realTaskkillGBKHex)
	if err != nil {
		t.Fatalf("bad fixture hex: %v", err)
	}
	// 先证明这段字节确实不是合法 UTF-8（否则用例本身没有意义）。
	if got, _ := DecodeOutputTextReport(""); got != "" {
		t.Fatalf("empty input: got %q", got)
	}
	const want = "错误: 没有找到进程 \"toshell_no_such_av.exe\"。\r\n"
	text, converted := DecodeOutputTextReport(string(raw))
	if !converted {
		t.Fatal("真实 GBK 字节应被判定为需要转换")
	}
	if text != want {
		t.Fatalf("GBK 解码结果不对:\n got %q\nwant %q", text, want)
	}
	// 幂等：再解一次不再变化（服务端多次展示同一结果时不能越解越坏）。
	if again := DecodeOutputText(text); again != text {
		t.Fatalf("重复解码不应改变结果: %q -> %q", text, again)
	}
}

// 旧 bug 回归：EDR 击杀回执是植入端自己写的 UTF-8 中文，
// 曾被整串 GBK→UTF-8 打成 "鍑绘潃"。展示层必须原样保留。
func TestDecodeOutputTextKeepsUTF8(t *testing.T) {
	for _, s := range []string{
		"== EDR Kill (击杀) ==\n[+] MsMpEng.exe terminated\n",
		"[+] 持久化成功 (Registry Run): toshell -> C:\\Users\\a\\toshell.exe\n",
		`[{"name":"registry_run","description":"HKCU\\...\\Run 注册表启动项","reliable":true}]`,
		"PID      Session Name                   Name\n---      ------------                   ----\n",
		"",
	} {
		got, converted := DecodeOutputTextReport(s)
		if converted {
			t.Errorf("合法 UTF-8 不应被转换: %q", s)
		}
		if got != s {
			t.Errorf("合法 UTF-8 必须原样返回:\n got %q\nwant %q", got, s)
		}
	}
}

// 混合串（真实形态）：植入端 UTF-8 表头 + 中文工具的 GBK 输出，逐行判定后两部分都要对。
func TestDecodeOutputTextMixedLines(t *testing.T) {
	gbkErr := string(gbkBytes(t, "错误: 没有找到进程 \"360tray.exe\"。"))
	mixed := "== EDR Kill (击杀) ==\n[-] 360tray.exe: " + gbkErr + "\n"
	got, converted := DecodeOutputTextReport(mixed)
	if !converted {
		t.Fatal("混合串应被判定为需要转换")
	}
	const want = "== EDR Kill (击杀) ==\n[-] 360tray.exe: 错误: 没有找到进程 \"360tray.exe\"。\n"
	if got != want {
		t.Fatalf("混合串逐行解码结果不对:\n got %q\nwant %q", got, want)
	}
}

// 启动项/表格类输出：多行 GBK 中文全部正确，ASCII 列不受影响（别把 ASCII 也转坏）。
func TestDecodeOutputTextTable(t *testing.T) {
	var b strings.Builder
	b.WriteString("PID      Session Name                   Name\n")
	b.WriteString("---      ------------                   ----\n")
	for _, line := range []string{"  1234 Console                     notepad.exe", "  5678 Services                    火绒安全.exe"} {
		b.WriteString(line + "\n")
	}
	gbk := gbkBytes(t, b.String())
	// 上面这串整体含 GBK 中文，但每行的 ASCII 列必须保持一模一样的字符。
	got, converted := DecodeOutputTextReport(string(gbk))
	if !converted {
		t.Fatal("含 GBK 中文的表格应被判定为需要转换")
	}
	if !strings.HasPrefix(got, "PID      Session Name                   Name\n") {
		t.Fatalf("ASCII 表头被改动了: %q", got)
	}
	if !strings.Contains(got, "火绒安全.exe") {
		t.Fatalf("表格里的中文没有正确解码: %q", got)
	}
}

// 既非 UTF-8 也非 GBK 的字节：显式标注 + 十六进制预览，且不静默丢数据。
func TestDecodeOutputTextBinaryFallback(t *testing.T) {
	raw := string([]byte{0xff, 0xfe, 0x00, 0x01})
	got, converted := DecodeOutputTextReport(raw)
	if !converted {
		t.Fatal("非法字节应被判定为需要转换")
	}
	if !strings.Contains(got, binaryPreviewTag) {
		t.Fatalf("兜底文案缺失: %q", got)
	}
	if !strings.Contains(got, "fffe0001") {
		t.Fatalf("缺少原始字节十六进制预览: %q", got)
	}
	if !strings.Contains(got, "共 4 字节") {
		t.Fatalf("缺少原始字节数标注: %q", got)
	}
}

// 超长二进制：预览必须截断并明确说明只取了前 N 字节。
func TestDecodeOutputTextBinaryPreviewTruncated(t *testing.T) {
	raw := strings.Repeat(string([]byte{0xff}), maxBinaryPreviewBytes+64)
	got := DecodeOutputText(raw)
	if !strings.Contains(got, "只预览前") {
		t.Fatalf("超长二进制应说明预览被截断: %.120q", got)
	}
	// 预览部分长度应被限制（十六进制是字节数的两倍）。
	hexLen := 0
	for i := len(got) - 1; i >= 0; i-- {
		if !strings.ContainsRune("0123456789abcdef", rune(got[i])) {
			break
		}
		hexLen++
	}
	if hexLen == 0 || hexLen > maxBinaryPreviewBytes*2 {
		t.Fatalf("十六进制预览未被限制在 %d 字节内 (hexLen=%d)", maxBinaryPreviewBytes, hexLen)
	}
}

// DecodeOutputText 必须与 Report 版本一致（展示路径全部走 Report 的便捷包装）。
func TestDecodeOutputTextMatchesReport(t *testing.T) {
	raw := string(gbkBytes(t, "启动项: 注册表启动项"))
	if DecodeOutputText(raw) != "启动项: 注册表启动项" {
		t.Fatalf("DecodeOutputText 结果不对: %q", DecodeOutputText(raw))
	}
}
