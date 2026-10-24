// Package preview 定义"文件列表 → 预览"的统一判定清单（前后端共用同一套规则）。
//
// 设计目标：
//  1. 一处判定：服务端处理器用 Decide 做**二次校验**（前端限制可被绕过），
//     同时通过 /api/v1/files/preview-policy 把清单下发给前端，避免两边各写一份漂移。
//  2. 明确分类：文本/图片可内联预览；可执行/压缩包/数据库**只给下载**；
//     未识别后缀不静默失败，返回"需要二次确认"的决策，由前端弹窗让操作员选择。
//  3. 超大文件不伪造完整内容：文本超过 MaxInlineBytes 只返回前缀字节并在响应里
//     标 truncated=true（前端必须显示截断标注）。
//
// 本包只做纯逻辑（不读文件、不碰 HTTP），因此可以完整单测。
package preview

import (
	"encoding/hex"
	"math"
	"path/filepath"
	"sort"
	"strings"
)

// Category 文件预览分类。
type Category string

const (
	CategoryText       Category = "text"
	CategoryImage      Category = "image"
	CategoryExecutable Category = "executable"
	CategoryArchive    Category = "archive"
	CategoryDatabase   Category = "database"
	CategoryUnknown    Category = "unknown"
)

// 决策错误码（对外契约：只允许新增，不允许改名）。
const (
	CodeOK       = "ok"                  // 允许预览（可能带截断）
	CodeBlocked  = "preview_blocked"     // 黑名单类型：明确拒绝，只给下载
	CodeUnknown  = "preview_unknown_ext" // 未识别后缀：需要操作员确认后才允许强制预览
	CodeBinary   = "preview_binary"      // 内容二进制探测命中：拒绝内联预览
	CodeTooLarge = "preview_too_large"   // 文件过大（图片/超硬上限）：只给下载
	CodeForced   = "preview_forced"      // 未识别后缀 + 操作员确认：按前缀只读预览
	CodeBadImage = "preview_bad_image"   // 后缀是图片但内容签名不匹配
	CodeTimeout  = "preview_timeout"     // 等待植入端回传超时
	CodeFailed   = "preview_failed"      // 任务失败/会话掉线
	CodeBadPath  = "preview_bad_path"    // 路径非法
)

// 预览上限（字节）。前端通过 Policy 获取，不硬编码。
const (
	// MaxInlineBytes 文本类"完整预览"上限：超过即视为超大文件，只回传前缀。
	MaxInlineBytes = 1024 * 1024 // 1 MiB
	// OversizePreviewBytes 超大文本文件只回传的前缀长度。
	OversizePreviewBytes = 64 * 1024 // 64 KiB
	// MaxUnknownPreviewBytes 未识别后缀被操作员强制预览时的前缀长度（只读）。
	MaxUnknownPreviewBytes = 8 * 1024 // 8 KiB
	// MaxImagePreviewBytes 图片内联预览上限（超过只给下载）。
	MaxImagePreviewBytes = 2 * 1024 * 1024 // 2 MiB
	// MaxSourceBytes 预览允许从植入端回传的硬上限（防止一个点击拉几百 MB）。
	MaxSourceBytes = 64 * 1024 * 1024 // 64 MiB
)

// textExtensions 允许内联预览的文本类后缀（小写、不带点）。
var textExtensions = []string{
	"txt", "log", "ini", "conf", "cfg", "json", "xml", "csv", "tsv", "md",
	"yml", "yaml", "sh", "bash", "zsh", "py", "ps1", "psm1", "bat", "cmd",
	"go", "js", "mjs", "cjs", "ts", "tsx", "jsx", "java", "c", "h", "cpp",
	"cc", "cxx", "hpp", "rs", "rb", "php", "pl", "lua", "sql", "toml",
	"properties", "env", "gitignore", "dockerfile", "makefile", "gradle",
	"html", "htm", "css", "scss", "sass", "less", "vue", "svelte", "diff",
	"patch", "rtf", "tex", "asc", "pem", "crt", "cer", "csr", "key", "pub",
}

// imageExtensions 允许内联预览的图片后缀。刻意**不包含 svg**：
// SVG 可内联脚本，属于可执行内容，按"下载后本地查看"处理。
var imageExtensions = []string{
	"png", "jpg", "jpeg", "gif", "bmp", "webp",
}

// executableExtensions 可执行/二进制/可执行脚本类：只给下载。
var executableExtensions = []string{
	"exe", "dll", "sys", "so", "dylib", "elf", "bin", "msi", "scr", "com",
	"jar", "class", "apk", "deb", "rpm", "img", "iso", "vhd", "vhdx",
	"vmdk", "ps1exe", "cpl", "ocx", "drv", "ko", "wasm", "o", "obj", "lib",
	"a", "pyc", "pyo",
}

// archiveExtensions 压缩包：只给下载。
var archiveExtensions = []string{
	"zip", "rar", "7z", "gz", "tgz", "tar", "xz", "bz2", "cab", "lz",
	"lzma", "zst", "z", "arj", "ace", "iso9660",
}

// databaseExtensions 数据库/邮件库：只给下载。
var databaseExtensions = []string{
	"db", "sqlite", "sqlite3", "mdb", "accdb", "pst", "ost", "edb", "mdf",
	"ldf", "ndf", "dmp", "kdbx", "frm", "ibd", "myd", "myi",
}

var (
	textSet       = toSet(textExtensions)
	imageSet      = toSet(imageExtensions)
	executableSet = toSet(executableExtensions)
	archiveSet    = toSet(archiveExtensions)
	databaseSet   = toSet(databaseExtensions)
)

func toSet(list []string) map[string]struct{} {
	m := make(map[string]struct{}, len(list))
	for _, e := range list {
		m[e] = struct{}{}
	}
	return m
}

// ExtOf 归一化取扩展名：小写、不带点；无扩展名返回 ""。
// 复合后缀（.tar.gz）按最后一段（gz）分类，仍在压缩包白名单内。
func ExtOf(name string) string {
	// 先去掉末尾的点（如 "file.txt." 这种 Windows 允许的写法）再取后缀，
	// 否则 filepath.Ext("file.txt.") 会返回 "."。
	name = strings.TrimRight(name, ".")
	ext := strings.ToLower(filepath.Ext(name))
	return strings.TrimPrefix(ext, ".")
}

// Classify 按后缀归类；未识别后缀返回 CategoryUnknown。
func Classify(name string) Category {
	ext := ExtOf(name)
	switch {
	case ext == "":
		return CategoryUnknown
	case inSet(textSet, ext):
		return CategoryText
	case inSet(imageSet, ext):
		return CategoryImage
	case inSet(executableSet, ext):
		return CategoryExecutable
	case inSet(archiveSet, ext):
		return CategoryArchive
	case inSet(databaseSet, ext):
		return CategoryDatabase
	default:
		return CategoryUnknown
	}
}

// IsPreviewableExt 是否属于文本/图片白名单（不涉及大小与内容）。
func IsPreviewableExt(name string) bool {
	c := Classify(name)
	return c == CategoryText || c == CategoryImage
}

func inSet(set map[string]struct{}, ext string) bool {
	_, ok := set[ext]
	return ok
}

// Decision 一次预览请求的判定结果。
type Decision struct {
	// Allowed true = 可以做内容预览；false = 只给下载（或需先确认）。
	Allowed bool `json:"allowed"`
	// Category 分类结果。
	Category Category `json:"category"`
	// Ext 归一化后缀（不带点）。
	Ext string `json:"ext"`
	// Code 机器可读结论（见 Code* 常量）。
	Code string `json:"code"`
	// Message 中文说明（可直接展示给操作员，不含任何文件内容）。
	Message string `json:"message"`
	// RequiresConfirmation true = 未识别后缀，前端必须弹窗让操作员选择
	// "仍要预览（前 N KB，只读）" 或 "下载"。
	RequiresConfirmation bool `json:"requires_confirmation,omitempty"`
	// DownloadOnly true = 不提供任何内联预览，只能下载。
	DownloadOnly bool `json:"download_only"`
	// Truncated true = 只回传前缀，前端必须显示截断标注。
	Truncated bool `json:"truncated"`
	// PreviewBytes 允许回传给浏览器的最大字节数（0 = 不适用）。
	PreviewBytes int64 `json:"preview_bytes"`
}

// Decide 根据文件名、大小（来自目录列表，可为 0/未知）与操作员确认标记给出判定。
//
// 规则优先级：黑名单（可执行/压缩包/数据库）→ 图片 → 文本 → 未识别后缀。
// force 只对"未识别后缀"生效；黑名单类型即使 force 也不给内联预览（fail-closed）。
func Decide(name string, size int64, force bool) Decision {
	ext := ExtOf(name)
	cat := Classify(name)

	if size < 0 {
		size = 0
	}

	switch cat {
	case CategoryExecutable, CategoryArchive, CategoryDatabase:
		return Decision{
			Allowed:      false,
			Category:     cat,
			Ext:          ext,
			Code:         CodeBlocked,
			Message:      blockedMessage(ext, cat),
			DownloadOnly: true,
		}

	case CategoryImage:
		if size > MaxImagePreviewBytes {
			return Decision{
				Allowed:      false,
				Category:     cat,
				Ext:          ext,
				Code:         CodeTooLarge,
				Message:      "该图片超过 " + humanBytes(MaxImagePreviewBytes) + "，内联预览会占用大量传输；请下载后在本地查看。",
				DownloadOnly: true,
			}
		}
		return Decision{
			Allowed:      true,
			Category:     cat,
			Ext:          ext,
			Code:         CodeOK,
			Message:      "图片预览",
			PreviewBytes: size,
		}

	case CategoryText:
		if size > MaxSourceBytes {
			return Decision{
				Allowed:      false,
				Category:     cat,
				Ext:          ext,
				Code:         CodeTooLarge,
				Message:      "文件超过 " + humanBytes(MaxSourceBytes) + "，预览需要完整回传，请下载后在本地查看。",
				DownloadOnly: true,
			}
		}
		if size > MaxInlineBytes {
			return Decision{
				Allowed:      true,
				Category:     cat,
				Ext:          ext,
				Code:         CodeOK,
				Message:      "文件较大（超过 " + humanBytes(MaxInlineBytes) + "），仅显示前 " + humanBytes(OversizePreviewBytes) + "。",
				Truncated:    true,
				PreviewBytes: OversizePreviewBytes,
			}
		}
		return Decision{
			Allowed:      true,
			Category:     cat,
			Ext:          ext,
			Code:         CodeOK,
			Message:      "文本预览",
			PreviewBytes: size,
		}

	default: // CategoryUnknown
		if size > MaxSourceBytes {
			return Decision{
				Allowed:      false,
				Category:     cat,
				Ext:          ext,
				Code:         CodeTooLarge,
				Message:      "文件超过 " + humanBytes(MaxSourceBytes) + "，预览需要完整回传，请下载后在本地查看。",
				DownloadOnly: true,
			}
		}
		if !force {
			return Decision{
				Allowed:              false,
				Category:             cat,
				Ext:                  ext,
				Code:                 CodeUnknown,
				Message:              unknownMessage(ext),
				RequiresConfirmation: true,
				PreviewBytes:         MaxUnknownPreviewBytes,
			}
		}
		return Decision{
			Allowed:      true,
			Category:     cat,
			Ext:          ext,
			Code:         CodeForced,
			Message:      "未识别后缀，已按操作员确认强制只读预览前 " + humanBytes(MaxUnknownPreviewBytes) + "。",
			Truncated:    size > MaxUnknownPreviewBytes,
			PreviewBytes: MaxUnknownPreviewBytes,
		}
	}
}

// LimitFor 返回本次预览实际需要回传的字节数上限（<=0 表示不限制，调用方按内容长度）。
func LimitFor(d Decision) int64 {
	if d.PreviewBytes > 0 {
		return d.PreviewBytes
	}
	return math.MaxInt64
}

func blockedMessage(ext string, cat Category) string {
	kind := "可执行/二进制文件"
	switch cat {
	case CategoryArchive:
		kind = "压缩包"
	case CategoryDatabase:
		kind = "数据库/邮件库文件"
	}
	target := "该文件"
	if ext != "" {
		target = "该 " + strings.ToUpper(ext) + " 文件"
	}
	return target + "属于" + kind + "，不提供内联预览（避免浏览器渲染或脚本执行）；请下载后在本地查看。"
}

func unknownMessage(ext string) string {
	target := "该文件"
	if ext != "" {
		target = "该后缀（." + ext + "）"
	}
	return target + "不在预览白名单，可能是二进制文件；建议下载后在本地查看。可仍以只读方式预览前 " +
		humanBytes(MaxUnknownPreviewBytes) + "（内容不会执行）。"
}

// LooksBinary 内容二进制探测：前 sampleLimit 字节里 NUL 或异常控制字符
// 占比超过 10% 即视为二进制。用于**服务端二次校验**（未识别后缀强制预览、
// 文本后缀被改名成二进制等场景），避免把二进制原样吐给浏览器。
func LooksBinary(data []byte) bool {
	const sampleLimit = 2048
	n := len(data)
	if n > sampleLimit {
		n = sampleLimit
	}
	if n == 0 {
		return false
	}
	bad := 0
	for _, c := range data[:n] {
		// 允许 TAB/LF/CR/ESC（ESC 常见于 ANSI 彩色日志）
		if c == 0 || (c < 0x09) || (c > 0x0d && c < 0x20 && c != 0x1b) || c == 0x7f {
			bad++
		}
	}
	return bad*10 > n
}

// SniffImageMIME 校验图片内容签名并返回严格 MIME；不匹配返回 ok=false。
// 浏览器端必须用这里返回的 MIME 拼 data: URL，绝不能按后缀猜类型
// （否则 .png 里塞 HTML 会变成 XSS 通道）。
func SniffImageMIME(data []byte) (mime string, ok bool) {
	switch {
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n":
		return "image/png", true
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return "image/jpeg", true
	case len(data) >= 6 && (string(data[:6]) == "GIF87a" || string(data[:6]) == "GIF89a"):
		return "image/gif", true
	case len(data) >= 2 && string(data[:2]) == "BM":
		return "image/bmp", true
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return "image/webp", true
	}
	return "", false
}

// HexPrefix 返回前 n 字节的十六进制串（仅用于诊断/测试，不用于响应）。
func HexPrefix(data []byte, n int) string {
	if n <= 0 || n > len(data) {
		n = len(data)
	}
	return hex.EncodeToString(data[:n])
}

func humanBytes(n int64) string {
	switch {
	case n >= 1024*1024:
		return itoa(n/(1024*1024)) + " MB"
	case n >= 1024:
		return itoa(n/1024) + " KB"
	default:
		return itoa(n) + " B"
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Policy 下发给前端的清单（GET /api/v1/files/preview-policy）。
// 前端以本结构为权威；拿不到时用内置同款清单兜底（见 web/src/utils/previewPolicy.ts）。
type Policy struct {
	TextExtensions         []string `json:"text_extensions"`
	ImageExtensions        []string `json:"image_extensions"`
	ExecutableExtensions   []string `json:"executable_extensions"`
	ArchiveExtensions      []string `json:"archive_extensions"`
	DatabaseExtensions     []string `json:"database_extensions"`
	MaxInlineBytes         int64    `json:"max_inline_bytes"`
	OversizePreviewBytes   int64    `json:"oversize_preview_bytes"`
	MaxUnknownPreviewBytes int64    `json:"max_unknown_preview_bytes"`
	MaxImagePreviewBytes   int64    `json:"max_image_preview_bytes"`
	MaxSourceBytes         int64    `json:"max_source_bytes"`
	UnknownMessage         string   `json:"unknown_message"`
	BlockedMessage         string   `json:"blocked_message"`
	ForceReadOnlyNote      string   `json:"force_read_only_note"`
	Note                   string   `json:"note"`
}

// DefaultPolicy 返回排序后的稳定清单（便于前端 diff 与单测断言）。
func DefaultPolicy() Policy {
	cp := func(in []string) []string {
		out := append([]string(nil), in...)
		sort.Strings(out)
		return out
	}
	return Policy{
		TextExtensions:         cp(textExtensions),
		ImageExtensions:        cp(imageExtensions),
		ExecutableExtensions:   cp(executableExtensions),
		ArchiveExtensions:      cp(archiveExtensions),
		DatabaseExtensions:     cp(databaseExtensions),
		MaxInlineBytes:         MaxInlineBytes,
		OversizePreviewBytes:   OversizePreviewBytes,
		MaxUnknownPreviewBytes: MaxUnknownPreviewBytes,
		MaxImagePreviewBytes:   MaxImagePreviewBytes,
		MaxSourceBytes:         MaxSourceBytes,
		UnknownMessage:         unknownMessage(""),
		BlockedMessage:         blockedMessage("", CategoryExecutable),
		ForceReadOnlyNote:      "强制预览只读：内容按纯文本渲染，不执行、不内联为 HTML/SVG。",
		Note:                   "清单由服务端 /api/v1/files/preview-policy 下发；服务端会对预览请求二次校验，前端限制不是安全边界。",
	}
}
