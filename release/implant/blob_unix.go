//go:build !windows && !light

package main

// non-Windows + full 档的反射加载/内存执行 stub。
//
// ⚠️ 标签里必须有 `!light`（原本只有 `!windows`，这是一个**会让 linux/macOS 的精简档
// 直接构建失败**的 bug）：
//   - runMappedImage 在 light 档由 features_stub_light.go（`//go:build light`）提供；
//     两边同时命中就是 `runMappedImage redeclared in this block`，`go build` 直接失败；
//   - Windows 侧对应文件（blob_windows.go / imgexec_windows.go）本来就是
//     `windows` / `windows && !light` 错开的，只有 unix 这一边漏了 `!light`，
//     于是「linux/amd64 + light」这一种组合构建不出来，而 windows 同组合正常。
//   - linux 精简档的 loadDLLMem 由 blob_unix_light.go 提供（两个文件互斥，不重复定义）。

// loadDLLMem 反射加载 DLL：非 Windows 平台不支持。
func loadDLLMem(dataB64, entryName string) (string, int32, string) {
	return "", -1, "DLL reflective loading is only supported on Windows"
}

// runMappedImage 反射式内存执行 EXE（含参数）：非 Windows 平台不支持
// （Linux/macOS 侧用 memfd + execve 的路径，见 ROADMAP P0.3）。
func runMappedImage(dataB64, args, imageName string, waitMs int) (string, int32, string) {
	return "", -1, "in-memory EXE execution is only supported on Windows (use exec with a temp file on Unix)"
}
