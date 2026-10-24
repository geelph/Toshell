package preview

import (
	"sort"
	"testing"
)

func TestClassifyCategories(t *testing.T) {
	cases := []struct {
		name string
		want Category
	}{
		// 文本类（抽样覆盖每个子类）
		{"a.txt", CategoryText},
		{"server.LOG", CategoryText},
		{"app.ini", CategoryText},
		{"conf.yaml", CategoryText},
		{"data.json", CategoryText},
		{"readme.md", CategoryText},
		{"deploy.sh", CategoryText},
		{"scan.py", CategoryText},
		{"run.ps1", CategoryText},
		{"x.bat", CategoryText},
		{"main.go", CategoryText},
		{"index.ts", CategoryText},
		{"payload.rs", CategoryText},
		{"web.html", CategoryText}, // 文本白名单但前端按纯文本渲染，不执行
		// 图片
		{"a.png", CategoryImage},
		{"photo.JPG", CategoryImage},
		{"x.jpeg", CategoryImage},
		{"b.gif", CategoryImage},
		{"c.bmp", CategoryImage},
		{"d.webp", CategoryImage},
		// 可执行 / 二进制
		{"probe.exe", CategoryExecutable},
		{"lib.dll", CategoryExecutable},
		{"drv.sys", CategoryExecutable},
		{"x.so", CategoryExecutable},
		{"y.elf", CategoryExecutable},
		{"z.bin", CategoryExecutable},
		{"setup.msi", CategoryExecutable},
		{"app.jar", CategoryExecutable},
		{"pkg.apk", CategoryExecutable},
		{"fw.img", CategoryExecutable},
		{"win.iso", CategoryExecutable},
		{"disk.vhd", CategoryExecutable},
		// 压缩包
		{"a.zip", CategoryArchive},
		{"b.rar", CategoryArchive},
		{"c.7z", CategoryArchive},
		{"d.gz", CategoryArchive},
		{"e.tar", CategoryArchive},
		{"f.xz", CategoryArchive},
		{"g.cab", CategoryArchive},
		{"h.tar.gz", CategoryArchive},
		// 数据库 / 邮件库
		{"data.db", CategoryDatabase},
		{"x.sqlite", CategoryDatabase},
		{"y.mdb", CategoryDatabase},
		{"mail.pst", CategoryDatabase},
		{"mail.ost", CategoryDatabase},
		// 未识别 / 无后缀
		{"weird.xyz", CategoryUnknown},
		{"noext", CategoryUnknown},
		{"dot.", CategoryUnknown},
		// 刻意不算图片：SVG 可执行脚本
		{"logo.svg", CategoryUnknown},
	}
	for _, tc := range cases {
		if got := Classify(tc.name); got != tc.want {
			t.Errorf("Classify(%q) = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestExtOfNormalization(t *testing.T) {
	cases := map[string]string{
		"A.TXT":          "txt",
		"a.tar.GZ":       "gz",
		"file.txt.":      "txt",
		`C:\dir\x.Ps1`:   "ps1",
		"/tmp/a.json":    "json",
		"noext":          "",
		"weird.xyz":      "xyz",
		"archive.tar.gz": "gz",
	}
	for name, want := range cases {
		if got := ExtOf(name); got != want {
			t.Errorf("ExtOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestDecideAllowedTextAndImage(t *testing.T) {
	dec := Decide("notes.txt", 2*1024, false)
	if !dec.Allowed || dec.Code != CodeOK || dec.Category != CategoryText || dec.Truncated {
		t.Fatalf("text decision = %+v", dec)
	}
	if dec.PreviewBytes != 2*1024 {
		t.Fatalf("PreviewBytes = %d, want 2048", dec.PreviewBytes)
	}

	dec = Decide("pic.png", 512*1024, false)
	if !dec.Allowed || dec.Category != CategoryImage || dec.Code != CodeOK {
		t.Fatalf("image decision = %+v", dec)
	}
}

func TestDecideOversizeTextTruncates(t *testing.T) {
	dec := Decide("big.log", MaxInlineBytes+1, false)
	if !dec.Allowed || !dec.Truncated {
		t.Fatalf("oversize text must be allowed but truncated: %+v", dec)
	}
	if dec.PreviewBytes != OversizePreviewBytes {
		t.Fatalf("PreviewBytes = %d, want %d", dec.PreviewBytes, OversizePreviewBytes)
	}
	if LimitFor(dec) != OversizePreviewBytes {
		t.Fatalf("LimitFor = %d", LimitFor(dec))
	}
}

func TestDecideHardSourceLimit(t *testing.T) {
	dec := Decide("huge.log", MaxSourceBytes+1, false)
	if dec.Allowed || dec.Code != CodeTooLarge || !dec.DownloadOnly {
		t.Fatalf("huge text must be download-only: %+v", dec)
	}
}

func TestDecideImageTooLarge(t *testing.T) {
	dec := Decide("huge.png", MaxImagePreviewBytes+1, false)
	if dec.Allowed || dec.Code != CodeTooLarge || !dec.DownloadOnly {
		t.Fatalf("huge image must be download-only: %+v", dec)
	}
}

func TestDecideBlockedTypes(t *testing.T) {
	for _, name := range []string{"probe.exe", "a.zip", "data.db", "mail.pst"} {
		for _, force := range []bool{false, true} {
			dec := Decide(name, 1024, force)
			if dec.Allowed {
				t.Fatalf("Decide(%q, force=%v) must not be allowed: %+v", name, force, dec)
			}
			if dec.Code != CodeBlocked || !dec.DownloadOnly {
				t.Fatalf("Decide(%q) = %+v, want blocked/download-only", name, dec)
			}
			if dec.Message == "" {
				t.Fatalf("Decide(%q) must carry a Chinese message", name)
			}
		}
	}
}

func TestDecideUnknownRequiresConfirmation(t *testing.T) {
	dec := Decide("weird.xyz", 4096, false)
	if dec.Allowed || !dec.RequiresConfirmation || dec.Code != CodeUnknown || dec.DownloadOnly {
		t.Fatalf("unknown ext decision = %+v", dec)
	}
	if dec.PreviewBytes != MaxUnknownPreviewBytes {
		t.Fatalf("PreviewBytes = %d, want %d", dec.PreviewBytes, MaxUnknownPreviewBytes)
	}
	if dec.Message == "" {
		t.Fatal("unknown ext must carry an explicit popup message")
	}

	forced := Decide("weird.xyz", 20*1024, true)
	if !forced.Allowed || forced.Code != CodeForced || !forced.Truncated {
		t.Fatalf("forced decision = %+v", forced)
	}
	if forced.PreviewBytes != MaxUnknownPreviewBytes {
		t.Fatalf("forced PreviewBytes = %d", forced.PreviewBytes)
	}

	small := Decide("weird.xyz", 100, true)
	if small.Truncated {
		t.Fatalf("small forced preview should not be marked truncated: %+v", small)
	}
}

func TestDecideUnknownHugeStillDownloadOnly(t *testing.T) {
	// 未识别后缀也受硬上限保护，不能靠 force 拉一个超大文件
	dec := Decide("weird.xyz", MaxSourceBytes+1, true)
	if dec.Allowed || dec.Code != CodeTooLarge || !dec.DownloadOnly {
		t.Fatalf("huge unknown decision = %+v", dec)
	}
}

func TestLooksBinary(t *testing.T) {
	if LooksBinary([]byte("hello world\n\tplain text\r\n")) {
		t.Fatal("plain text misdetected as binary")
	}
	if LooksBinary([]byte("line1\x1b[31mred\x1b[0m\n")) {
		t.Fatal("ANSI log misdetected as binary")
	}
	if !LooksBinary([]byte{0x4d, 0x5a, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}) {
		t.Fatal("binary with NUL not detected")
	}
	if LooksBinary(nil) {
		t.Fatal("empty content should not be binary")
	}
}

func TestSniffImageMIME(t *testing.T) {
	if m, ok := SniffImageMIME([]byte("\x89PNG\r\n\x1a\nrest")); !ok || m != "image/png" {
		t.Fatalf("png sniff = %q/%v", m, ok)
	}
	if m, ok := SniffImageMIME([]byte("\xff\xd8\xff\xe0rest")); !ok || m != "image/jpeg" {
		t.Fatalf("jpeg sniff = %q/%v", m, ok)
	}
	if m, ok := SniffImageMIME([]byte("GIF89a....")); !ok || m != "image/gif" {
		t.Fatalf("gif sniff = %q/%v", m, ok)
	}
	if _, ok := SniffImageMIME([]byte("<html><script>alert(1)</script>")); ok {
		t.Fatal("HTML content must not be sniffed as an image")
	}
	if _, ok := SniffImageMIME([]byte("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")); ok {
		t.Fatal("SVG content must not be sniffed as an image")
	}
}

func TestDefaultPolicyStable(t *testing.T) {
	p := DefaultPolicy()
	if len(p.TextExtensions) == 0 || len(p.ImageExtensions) == 0 {
		t.Fatal("policy lists must not be empty")
	}
	if !sort.StringsAreSorted(p.TextExtensions) || !sort.StringsAreSorted(p.ExecutableExtensions) {
		t.Fatal("policy lists must be sorted for stable frontend diff")
	}
	// 关键黑名单必须真的在黑名单里（防止误改造成"可预览"）
	for _, ext := range []string{"exe", "dll", "zip", "7z", "db", "pst", "iso", "vhd"} {
		found := false
		for _, e := range p.ExecutableExtensions {
			if e == ext {
				found = true
				break
			}
		}
		for _, e := range p.ArchiveExtensions {
			if e == ext {
				found = true
				break
			}
		}
		for _, e := range p.DatabaseExtensions {
			if e == ext {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%q missing from blocked policy lists", ext)
		}
	}
	// 图片清单不能包含 svg（可执行脚本）
	for _, e := range p.ImageExtensions {
		if e == "svg" {
			t.Fatal("svg must not be in image allowlist (script execution risk)")
		}
	}
	if p.MaxInlineBytes != MaxInlineBytes || p.MaxSourceBytes != MaxSourceBytes {
		t.Fatalf("policy limits drifted: %+v", p)
	}
	if p.UnknownMessage == "" || p.BlockedMessage == "" {
		t.Fatal("policy must carry user-facing messages")
	}
}

func TestHumanBytesUsedInMessages(t *testing.T) {
	// Message 里的单位必须是可读的 KB/MB（而不是裸字节数）
	dec := Decide("big.log", MaxInlineBytes+1, false)
	if want := "1 MB"; !contains(dec.Message, want) {
		t.Fatalf("message %q should mention %s", dec.Message, want)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
