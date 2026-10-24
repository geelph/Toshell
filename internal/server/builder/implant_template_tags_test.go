package builder

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ─── 植入端模板「文件集 × 构建标签」矩阵自检 ────────────────────────────
//
// 为什么需要这个测试（两类真实事故都出在这里）：
//  1. **重复声明**：blob_unix.go 旧标签只有 `!windows`，而 features_stub_light.go
//     是 `light` —— 「linux/macOS + light」这一种组合下 runMappedImage 被定义两次，
//     `go build` 直接报 `runMappedImage redeclared in this block`，
//     **linux 精简档根本构建不出载荷**（Windows 同组合正常，所以很难被发现）。
//  2. **缺声明**：历史上出现过「生成 Linux/macOS 载荷报 undefined: handleXxx」，
//     即某个平台组合少了一份 stub（USAGE.md 的排错表里还留着这条）。
//
// 两类问题都只在「某个特定组合」出现，人工审代码几乎必漏；这里把组合枚举出来，
// 用与 builder 完全相同的标签口径算文件集，再查函数/方法级重复声明。
// 纯逻辑、不编译、不联网，Windows 上可跑。
//
// 说明：本测试只查「重复声明」（可由源码静态判定）。「缺声明」需要类型检查，
// 由真实构建（探针/CI 的 go build）兜底，这里不假装覆盖。

// funcDeclRe 匹配顶层函数与方法声明（含 receiver）。
var funcDeclRe = regexp.MustCompile(`(?m)^func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*[\(\[]`)

// templateTagMatrix 返回待检查的 (GOOS, 构建标签集) 组合。
// 标签集与 buildTagList 的口径一致（transport_* / light / bof / execmodule / evasionscan），
// GOOS 来自 builder 支持的三个目标平台。
func templateTagMatrix() []struct {
	osName string
	tags   []string
} {
	transports := []struct{ protocol, tag string }{
		{"tcp", ""},
		{"http", "transport_http"},
		{"websocket", "transport_ws"},
		{"mqtt", "transport_mqtt"},
	}
	var out []struct {
		osName string
		tags   []string
	}
	for _, osName := range []string{"windows", "linux", "darwin"} {
		for _, tr := range transports {
			for _, profile := range []string{"full", "light"} {
				var tags []string
				if tr.tag != "" {
					tags = append(tags, tr.tag)
				}
				if profile == "light" {
					tags = append(tags, "light")
				}
				out = append(out, struct {
					osName string
					tags   []string
				}{osName, tags})
				// 额外能力标签：都是「默认关闭、显式勾选才编译」的那几档
				for _, extra := range []string{"bof", "execmodule", "evasionscan"} {
					more := append(append([]string{}, tags...), extra)
					out = append(out, struct {
						osName string
						tags   []string
					}{osName, more})
				}
			}
		}
	}
	return out
}

// TestImplantTemplateNoDuplicateDeclsAcrossTags 枚举 (GOOS × 标签集) 组合，
// 断言任意组合下进入编译的文件集合里没有同名函数/方法。
func TestImplantTemplateNoDuplicateDeclsAcrossTags(t *testing.T) {
	dir := "implant" // go test 的 cwd 就是包目录，模板在包目录下的 implant/
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("找不到植入端模板目录 %q：%v", dir, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取模板目录失败：%v", err)
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		files = append(files, e.Name())
	}

	checked := 0
	for _, combo := range templateTagMatrix() {
		set := func(tag string) bool {
			if tag == combo.osName {
				return true
			}
			if tag == "unix" {
				return combo.osName != "windows"
			}
			switch tag {
			case "gc":
				return true // CGO_ENABLED=0 + 默认编译器
			case "cgo", "ignore", "tools":
				return false
			}
			for _, tg := range combo.tags {
				if tag == tg {
					return true
				}
			}
			return false
		}
		// 组合键 → 声明该符号的文件
		owner := map[string]string{}
		for _, name := range files {
			included, ok := templateFileIncluded(dir, name, combo.osName, set)
			if !ok {
				t.Fatalf("%s: 无法解析 build 约束", name)
			}
			if !included {
				continue
			}
			body, rerr := os.ReadFile(filepath.Join(dir, name))
			if rerr != nil {
				t.Fatalf("读取 %s 失败：%v", name, rerr)
			}
			for _, m := range funcDeclRe.FindAllStringSubmatch(string(body), -1) {
				key := m[2]
				if recv := strings.TrimSpace(m[1]); recv != "" {
					// 方法：以接收者类型名做前缀，避免不同类型的同名方法互相误报
					fields := strings.Fields(recv)
					if len(fields) > 0 {
						typ := strings.TrimLeft(fields[len(fields)-1], "*")
						key = typ + "." + key
					}
				}
				if prev, dup := owner[key]; dup && prev != name {
					t.Errorf("组合 os=%s tags=%v：声明 %s 在 %s 与 %s 里重复出现（会报 redeclared，该组合构建不出来）",
						combo.osName, combo.tags, key, prev, name)
					continue
				}
				owner[key] = name
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("没有检查任何组合")
	}
}

// templateFileIncluded 判断模板文件在该 (GOOS, 标签) 下是否参与编译。
//
// 与 builder.copyImplantSource 的口径保持一致的关键一点：platform_*.go 会被**改名**为
// platform.go 并只挑与目标 OS 匹配的那一份（另一份直接不拷贝）。
func templateFileIncluded(dir, name, goos string, set func(string) bool) (bool, bool) {
	if strings.HasPrefix(name, "platform_") {
		isWindows := strings.Contains(name, "windows")
		return (goos == "windows") == isWindows, true
	}
	body, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return false, false
	}
	expr := ""
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//go:build ") {
			expr = strings.TrimSpace(strings.TrimPrefix(line, "//go:build "))
			break
		}
		if strings.HasPrefix(line, "package ") {
			break // build 约束必须在 package 之前，越界即没有
		}
	}
	if expr == "" {
		return true, true
	}
	val, ok := evalBuildExpr(expr, set)
	return val, ok
}

// ─── 极简 //go:build 表达式求值器（只支持模板里实际用到的语法）─────────
// 语法：expr := or ; or := and ('||' and)* ; and := unary ('&&' unary)* ;
//
//	unary := '!' unary | '(' expr ')' | IDENT

type buildExprParser struct {
	src string
	pos int
	set func(string) bool
}

// evalBuildExpr 求值一个 //go:build 表达式；解析失败返回 ok=false。
func evalBuildExpr(expr string, set func(string) bool) (bool, bool) {
	p := &buildExprParser{src: expr, set: set}
	v, ok := p.parseOr()
	if !ok {
		return false, false
	}
	p.skipSpace()
	return v, p.pos >= len(p.src)
}

func (p *buildExprParser) skipSpace() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t' || p.src[p.pos] == '\r') {
		p.pos++
	}
}

func (p *buildExprParser) parseOr() (bool, bool) {
	v, ok := p.parseAnd()
	if !ok {
		return false, false
	}
	for {
		p.skipSpace()
		if !strings.HasPrefix(p.src[p.pos:], "||") {
			return v, true
		}
		p.pos += 2
		rhs, ok := p.parseAnd()
		if !ok {
			return false, false
		}
		v = v || rhs
	}
}

func (p *buildExprParser) parseAnd() (bool, bool) {
	v, ok := p.parseUnary()
	if !ok {
		return false, false
	}
	for {
		p.skipSpace()
		if !strings.HasPrefix(p.src[p.pos:], "&&") {
			return v, true
		}
		p.pos += 2
		rhs, ok := p.parseUnary()
		if !ok {
			return false, false
		}
		v = v && rhs
	}
}

func (p *buildExprParser) parseUnary() (bool, bool) {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return false, false
	}
	switch p.src[p.pos] {
	case '!':
		p.pos++
		v, ok := p.parseUnary()
		return !v, ok
	case '(':
		p.pos++
		v, ok := p.parseOr()
		if !ok {
			return false, false
		}
		p.skipSpace()
		if p.pos >= len(p.src) || p.src[p.pos] != ')' {
			return false, false
		}
		p.pos++
		return v, true
	}
	start := p.pos
	for p.pos < len(p.src) && (isIdentByte(p.src[p.pos]) || p.src[p.pos] == '.') {
		p.pos++
	}
	if start == p.pos {
		return false, false
	}
	return p.set(p.src[start:p.pos]), true
}

// TestBuildExprEvaluator 求值器自身的关键用例（避免它悄悄失效让上一个测试变成空转）。
func TestBuildExprEvaluator(t *testing.T) {
	tags := map[string]bool{"light": true, "transport_http": true}
	set := func(s string) bool { return tags[s] }
	cases := []struct {
		expr string
		want bool
	}{
		{"light", true},
		{"!light", false},
		{"windows", false},
		{"!windows && !light", false},
		{"!windows && light", true},
		{"transport_http && light", true},
		{"transport_http || mqtt", true},
		{"(light || bof) && !windows", true},
		{"bof", false},
	}
	names := make([]string, 0, len(cases))
	for _, c := range cases {
		names = append(names, c.expr)
		got, ok := evalBuildExpr(c.expr, set)
		if !ok {
			t.Errorf("%q: 解析失败", c.expr)
			continue
		}
		if got != c.want {
			t.Errorf("%q = %v, want %v", c.expr, got, c.want)
		}
	}
	sort.Strings(names) // 只是让输出稳定，无实际断言
}
