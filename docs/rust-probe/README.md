# Rust 植入端体积探针

配套文档：[`../RUST-IMPLANT.md`](../RUST-IMPLANT.md)（可行性评估）。

这些文件是**探针**，用来量"如果植入端用 Rust 写，体积是多少"。它们不是我方产品代码：

- 没有 TLS / WS / MQTT 传输（`cargo-tls/` 里单独量 TLS 这一层）
- 没有注入 / BOF / 凭据 / 驱动 / 持久化
- `t3_full.rs` 的 SM4-GCM 通过标准向量，但整体未做安全性评审

**不要把这些当成可用载荷。**

## 本机实测结果

Windows 11，`rustc 1.97.0`，target `x86_64-pc-windows-gnu`，静态 CRT，
`opt-level=z, lto=fat, codegen-units=1, panic=abort, strip=symbols`：

| 探针 | 内容 | 体积 |
|---|---|---:|
| `t1_floor` | `fn main(){}` 运行期地板 | 228,864 |
| `t2_net` | TCP 帧协议 + 注册/心跳/任务循环 | 258,048 |
| `t3_full` | + shell / 文件 / 进程 / 用户名 / base64 / SM4-GCM | **350,720** |
| `cargo-tls/tcp_base` | 裸 TCP + 手写 HTTP/1.1 | 258,048 |
| `cargo-tls/tls_schannel` | + Windows SChannel（系统 TLS） | 275,456（Δ **17,408**） |
| `cargo-tls/tls_rustls` | + rustls/ring/webpki-roots | 1,146,368（Δ 888,320） |

对照：Go 版 `light/tcp` = 2,946,805，`light/http` = 5,455,613（`v1.4.0` 实测）。

## 一键复现

```powershell
# 需要：rustc + MinGW-w64 gcc（或 MSVC 工具链）
./build.ps1 -MingwDir 'C:\msys64\mingw64'      # 只量单文件三档
./build.ps1 -MingwDir 'C:\msys64\mingw64' -WithTls   # 额外量 TLS 三档（需 cargo + 网络）
```

脚本会打印每档体积，并跑 `t3_full --selftest`（SM4 标准向量 + GCM 往返/篡改拒绝 + base64）。

## 已知环境坑

1. MinGW 若缺 `x86_64-w64-mingw32/lib/default-manifest.o`，链接会报
   `cannot find default-manifest.o`；正式环境请装完整的 `mingw-w64-x86_64-gcc`。
2. **`PATH` 里 32 位 `mingw32\bin` 排在 `mingw64\bin` 前面时**，`cc1.exe` 会以
   `0xC000007B` 静默失败（导入的 DLL 被解析到 32 位版本）。构建脚本已把 mingw64 放最前。
3. `GetUserNameW` 在 `advapi32`，不在 `kernel32`。
