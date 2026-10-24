//go:build !windows && light

package main

// ─── 非 Windows 精简档（light）的反射加载 stub ─────────────────────────────
//
// 为什么需要这个独立文件（而不是塞进 features_stub_light.go）：
//   - features_stub_light.go 是 `//go:build light`，Windows 精简档也会编译它，
//     而 Windows 精简档的 loadDLLMem 已经由 blob_windows.go（`//go:build windows`）
//     提供 —— 在那儿再写一份就是重复定义。
//   - 所以「loadDLLMem 的 unix 精简档实现」只能放在 `!windows && light` 里，
//     与 blob_unix.go（`!windows && !light`）互补，保证任意组合下**恰好一份**。
//
// runMappedImage 不在这里定义：light 档统一由 features_stub_light.go 提供
// （历史上 blob_unix.go 只有 `!windows`，于是 linux+light 同时命中两处，
// 报 `runMappedImage redeclared in this block`，linux 精简档根本构建不出来）。

// loadDLLMem 反射加载 DLL：非 Windows 平台不支持。
func loadDLLMem(dataB64, entryName string) (string, int32, string) {
	return "", -1, "DLL reflective loading is only supported on Windows"
}
