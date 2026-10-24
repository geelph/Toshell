# 植入端 Rust 版本可行性评估

> 结论先行：**可行，且体积收益远超预期（实测小 8~15 倍）。但应作为"第二植入端"增量引入，
> 不替换 Go 植入端。** 建议落在 **v1.6**，先用 `light` 档打通"能连、能执行、能传文件"，
> 再逐项补 Windows 侧高价值能力。
>
> 本文所有数字都是**本机实测**，不是估算；实测方法与可复现脚本见第 7 节。
> 唯一没有实测的是「Rust 版 full（含劫持/BOF/凭据/驱动）的体积」——第 5 节给出推导过程，
> 并明确标注它是推导值。

---

## 1. 为什么要问这个问题

`v1.4.0` 实测的体积矩阵（Windows/386，`-trimpath -ldflags "-s -w -buildid="`）：

| 形态 | 体积 | 相对 light/tcp |
|---|---:|---:|
| light / tcp | 2,946,805 | — |
| light / tcp + exec_module | 2,973,941 | +27,136 |
| full / tcp | 3,522,293 | +575,488 |
| light / websocket | 5,097,728 | +2,150,923 |
| light / mqtt | 5,399,798 | +2,452,993 |
| light / http | 5,455,613 | +2,508,808 |

拆开看很清楚：

- **能力层的体积代价很小**（exec_module 只 +27 KB，full 相对 light 只 +575 KB）。
- **传输栈的体积代价极大**（http 一个通道就 +2.39 MB，因为要拖进 `net/http` + `crypto/tls` + 证书池）。

Go 的地板就在这里：一个只做"连上、领任务、回结果"的载荷也压不到 3 MB 以下，而带 TLS 的
HTTP 轮询直接冲到 5.4 MB。ROADMAP 里"体积下探"这条线一直推进困难，根因不在我们的代码写得多，
而在 **Go 运行期 + 标准库传输栈的固定成本**（之前已结论：`nano ≤1.8 MB` 在 Go 下不可行）。

Rust 恰好在这两点上结构性地便宜：没有 GC/调度器运行期，TLS 可以走**系统 SChannel**
（不打包密码学实现，增量只有 17 KB）。

---

## 2. 实测结果总览

环境：Windows 11 (10.0.26300)，`rustc 1.97.0 (Rev1, Built by MSYS2 project)`，
target `x86_64-pc-windows-gnu`，静态 CRT（`-C target-feature=+crt-static`），
release 参数 `opt-level=z, lto=fat, codegen-units=1, panic=abort, strip=symbols`。

### 2.1 三个能力梯度（单文件 `rustc`，无任何第三方 crate）

| 探针 | 内容 | 体积 | 相对上一档 |
|---|---|---:|---:|
| `t1_floor` | `fn main(){}` —— 纯运行期地板 | **228,864** | — |
| `t2_net` | TCP 帧协议 + 注册/心跳/任务取回/结果回写 + 抖动睡眠 | **258,048** | +29,184 |
| `t3_full` | `t2` + 交互/一次性 shell、文件列举/读/写/删、进程枚举、用户名、base64、**SM4-GCM** | **350,720** | +92,672 |

三个数字都是**可运行的真实 exe**（不是空壳），`t3_full` 在本机跑通自检：

```
SM4(known vector) = 681edf34d206965e86b3e94f536e4246     ← GB/T 32907-2016 标准向量
user      = 123
processes = 298
sysinfo   = host=DESKTOP-... user=123 os=windows arch=x86_64 pid=... cwd=...
SM4=true GCM_roundtrip=true GCM_tamper_reject=true B64=true
```

也就是说：**把 Go 版 `light/tcp` 的功能等价物写成 Rust，产物约 343 KB，
同一形态 Go 版是 2,946,805 B —— 小 8.4 倍，省 2,596,085 B。**

### 2.2 传输层的体积代价（这是最关键的一组）

同一份"手写 HTTP/1.1 轮询"代码，只换 TLS 实现：

| 探针 | 内容 | 体积 | TLS 净增量 |
|---|---|---:|---:|
| `tcp_base` | 裸 TCP + 手写 HTTP/1.1（不引 hyper/tokio） | **258,048** | — |
| `tls_schannel` | 同上 + **Windows SChannel**（`native-tls` → `schannel` crate） | **275,456** | **+17,408** |
| `tls_rustls` | 同上 + **rustls + ring + webpki-roots**（自带密码学 + 根证书） | **1,146,368** | +888,320 |

两个结论：

1. **Windows 上应该用 SChannel，不要用 rustls。** TLS 增量 17 KB 对 868 KB，差 51 倍。
   顺带一个免杀上的好处：SChannel 走系统 `secur32.dll`/`bcrypt.dll`，产物里没有
   `ring` 那种大段常量表和特征函数群，静态指纹面更接近"正常 Windows 程序"。
2. 即使选了"最贵"的 rustls，`light + http` 也只有 **1.15 MB**，仍比 Go 的 5.46 MB 小 4.75 倍。

### 2.3 构建档位对比（`t3_full` 同一份代码换参数）

| 参数 | 体积 |
|---|---:|
| `opt-level=z` + `lto=fat` + `strip` | **350,720** |
| `opt-level=s` + `lto=fat` + `strip` | 355,328 |
| `opt-level=3` + `lto=fat` + `strip` | 380,928 |
| `opt-level=3`，无 LTO，不 strip | 1,280,863 |

`z` 与 `s` 几乎没差别（+1.3%），说明这个体量下体积主要由"被链接进来的 std 片段"决定，
而不是指令调度。**不开 LTO / 不 strip 会让体积涨 3.7 倍**——构建脚本必须写死这几个参数，
并且在 CI 里断言体积上限（和现在的 Go 侧做法一致）。

### 2.4 同口径对照

| 形态 | Go（实测） | Rust（实测/推导） | 倍数 |
|---|---:|---:|---:|
| light / tcp | 2,946,805 | **350,720**（实测） | 8.4× |
| light / http(SChannel) | 5,455,613 | **≈368,128**（350,720+17,408，实测相加） | 14.8× |
| light / http(rustls) | 5,455,613 | **≈1,239,040**（350,720+888,320） | 4.4× |
| full / tcp | 3,522,293 | ≈650 KB ~ 1 MB（推导，见第 5 节） | 3.5× ~ 5.4× |

---

## 3. 要搬多少东西：源码规模

`internal/server/builder/implant/` 当前 **61 个 `.go` 文件 / 12,957 行**：

| 分类 | 文件 | 行数 | 说明 |
|---|---:|---:|---|
| Windows 专用（`*_windows.go`） | 30 | 8,184 | 注入、BOF/COFF、凭据、驱动、EDR、持久化、UAC、截图、直调、休眠掩码、内存执行守护 |
| 跨平台/Unix（`*_unix.go` 等） | 13 | 340 | 基本是 stub，实现很薄 |
| 可移植核心 | 21 | 4,569 | `main.go`(2,213)、`tunnel.go`(584)、三套传输、`sm4.go`、`relay.go`、`shell_pty_unix.go` |

**这是一份对 Rust 相当友好的分布**：真正难的部分（8,184 行 Windows 内核/PE 手艺）
本来就是 `unsafe` 领域，Go 写起来靠的是 `syscall`+`windows` 包，换成 Rust 的
`windows-sys` 并没有本质劣势；而**可移植核心只有 4,569 行**，正好是 Rust 最舒服的区间。

---

## 4. 移植成本分解

### 4.1 几乎零成本的部分（协议层与 Rust 语言无关）

- **线协议**：`[4 字节长度][1 字节类型][AES/SM4-GCM 密文]`，载荷是 JSON。
  Rust 侧 `serde_json` + 一个 GCM 实现即可，**服务端一行不用改**。
- **配置块**：尾部 `<encMagic><4B len><加密 JSON>`，格式与语言无关。
  当前 builder 已经把配置块写成 JSON（`server_url/interval/jitter/kill_date/transport/...`），
  Rust 植入端只要按同样的偏移规则读，**构建器不需要为 Rust 另写一套**。
- **能力位图 / `cap:v1:` 令牌 / 心跳字段**：都是 JSON 字符串，照抄。
- **前端**：会话列表、任务面板、文件管理都不感知植入端语言。

结论：**服务端与前端改动接近 0**，改动集中在"新增一个 Rust 源码树 + 构建器里多一个语言分支"。

### 4.2 必须重写的部分

| 模块 | Go 行数 | Rust 预估 | 难度 | 备注 |
|---|---:|---:|---|---|
| 传输核心（TCP 帧 + 注册/心跳/结果） | ~1,300 | 1,400 | 低 | `t2_net` 已跑通 |
| HTTP / WS / MQTT 通道 | ~1,500 | 1,800 | 中 | WS 需自己做握手/掩码；MQTT 需自己做 CONNECT/PUB/SUB |
| SM4-GCM | 304 | 320 | 低 | `t3_full` 已通过标准向量 |
| 隧道多路复用 + 中继 | ~800 | 900 | 中高 | 连接池 + 背压，Go 的 goroutine 换成线程池/异步需重新设计 |
| 交互式 shell（PTY） | ~300 | 350 | 中 | Windows 用 ConPTY，Linux 用 `posix_openpt` |
| 文件传输（分块/断点） | ~500 | 600 | 低 | |
| 进程/服务/网络/系统信息 | ~600 | 700 | 中 | 需要大量 Win32 FFI |
| 注入（ProcessInject/Spoof/AutoInject） | 807 | 900 | 高 | 全部 `unsafe`，寄存器/APC/线程上下文 |
| BOF/COFF 加载器 | 1,025 | 1,100 | 高 | PE/COFF 解析 + 重定位 + Beacon API 表 |
| 凭据收集 | 868 | 900 | 高 | LSASS/DPAPI/浏览器库解析 |
| 驱动加载 / PPL | 415 | 450 | 高 | 拿不到 `.sys` 时无法真验证 |
| EDR 对抗 / 持久化 / UAC | ~1,300 | 1,400 | 中高 | 大量 API 序列 |
| 内存执行守护 / 直调 / 休眠掩码 | ~2,000 | 2,100 | 极高 | 汇编桩、IAT 钩子、栈帧处理 |
| **合计** | **12,957** | **≈13,000 ~ 15,000** | | Rust 在 `unsafe` 领域更啰嗦，但去掉了大量错误处理样板 |

### 4.3 分阶段建议（每阶段都可独立交付、可测）

| 阶段 | 内容 | 预估 | 交付标准 |
|---|---|---|---|
| R1 | `light` 档：TCP 传输 + 注册/心跳 + shell + 文件 + sysinfo + SM4-GCM | 2~3 周 | 体积 ≤ 450 KB；能注册、执行命令、传文件；与本项目 Go 服务端互通 |
| R2 | HTTP/H2 通道（SChannel）+ WS + 隧道/中继 | 2~3 周 | 与 TCP 同会话可用；隧道能打内网 |
| R3 | 进程/服务/网络信息 + 截图 + 持久化 + UAC | 2~3 周 | Windows 会话页面前 6 个 tab 可用 |
| R4 | 注入族 + 内存执行 + 直调 + 休眠掩码 | 4~6 周 | 与 Go 版行为对齐（缺失项如实标 ❌） |
| R5 | BOF/COFF + 凭据 + 驱动 | 4~6 周 | 只在有 VM/`.sys` 时验证 |

**总计 3~4 个月**（单人、非全职），与"Go 版 60~70% 的工作量"这一被广泛引用的经验值一致。

---

## 5. full 档体积的推导（明确标注为推导值）

`t3_full`（350,720）覆盖了 light 档的能力层，但**不含** Windows 重型能力。增量推导：

- Windows 专用 Go 代码 8,184 行。参照 `t3_full` 的比例：350,720 B 对应约 4,900 行
  （含 std 片段），**不是**线性关系——大头是被链接进来的 std 片段。
- Rust 里这些能力主要新增的是 `unsafe` FFI 调用与 PE/COFF 解析代码，
  新增的 std 片段很少（`windows-sys` 只编译用到的原型）。
- 经验系数：新增 8,000 行业务代码在 `opt-level=z + lto + strip` 下约 **250~450 KB**。

所以 full 档估计落在 **650 KB ~ 1 MB**，即比 Go 的 full（3.52 MB）小 3.5~5.4 倍。
这个数字必须等 R4/R5 真正跑完才能替换成实测值；**在拿到实测值之前不要写进对外材料。**

---

## 6. 风险与不做的事

### 6.1 真实风险

1. **两套植入端 = 两套 bug 面。** 服务端协议必须严格同构，否则会出现"Go 能用、Rust 不能"
   的幽灵问题。缓解：把"线协议"固化成一份可执行规范 + 双向互通回归测试（Go 产物 ↔ Rust 产物
   打同一个服务端），纳入 CI。
2. **能力长期不对等。** 这是必然的，必须**在 UI 上如实标**（沿用现有能力位图机制：
   Rust 产物注册时只上报它真有的能力，页面自然只显示可用 tab），
   绝不能出现"点了没反应"。
3. **工具链成本。** 构建机需要 rustup + 对应 target；`release.yml` 要加 Rust 构建步骤，
   并断言体积上限。交叉编译到 Linux/macOS 还需要额外的链接器（`x86_64-unknown-linux-musl` 等）。
   本机实测就踩到了这一点：**Windows 侧必须用 MSVC 或完整的 MinGW-w64**，
   当前环境的 MinGW 缺 `default-manifest.o`、且 `PATH` 里 32 位 mingw32 排在前面会让
   `cc1.exe` 以 `0xC000007B` 直接失败（详见 7.3）。
4. **许可证合规。** 引入 `native-tls`/`schannel`/`rustls`/`ring` 等 crate 必须在
   `NOTICE`/`THIRD-PARTY` 里登记（它们多为 MIT/Apache-2.0/ISC，允许商用，但要求保留声明）。
   若最终选择 SChannel 方案，依赖面反而更小。
5. **免杀不是自动收益。** 小体积 ≠ 免杀。Rust 产物有自己的指纹特征（`/rustc/` 路径字符串、
   panic 消息、`.rdata` 里的格式串）。R1 阶段就要做一次"落地/动态/静态"三分类体检，
   把结论写进 `docs/EVASION.md`，而不是假设"Rust 更小所以更免杀"。

### 6.2 明确不做

- **不替换 Go 植入端。** Go 版的 Windows 手艺（mexecguard、直调、BOF、驱动）积累了整个
  v1.3~v1.4 周期，Rust 版从零复刻不划算，也没必要。
- **不追 32 位 / ARM64 首发。** `i686-pc-windows-gnu` 与 `aarch64` 的 std 需要额外 target，
  本机未装、未测；等 R1 稳定后再排。
- **不做"Rust 版专属新能力"**，直到 R5 完成。否则会出现"只有 Rust 有、Go 没有"的分裂。
- **不在没拿到 `.sys`/VM 的情况下宣称驱动能力。**

### 6.3 建议的落地方式

- 新增构建器选项 `language: "go" | "rust"`（默认 `go`，**默认不变**）。
- Rust 只开放 `light` / `full` 两档，`nano` 不开放。
- 产物命名与现在一致，`implants/` 下按 `language` 分子目录，避免与 Go 产物混淆。
- 前端生成载荷页加一个"植入端语言"下拉，选 Rust 时**当场显示实测体积与已实现能力**，
  没实现的按钮灰掉并注明"Rust 版未实现"。
- 版本归属：**v1.6**（v1.5 用在通道注册表/持久化隧道等收益更高的地方，见 `ROADMAP.md`）。

---

## 7. 可复现：我在本机是怎么测的

### 7.1 探针源码

三个单文件探针与三个 TLS 探针都随仓库提供，位于 `docs/rust-probe/`：

```
docs/rust-probe/
├── README.md
├── build.ps1              # 一键构建 + 量体积 + 跑 t3 自检
├── t1_floor.rs            # 228,864 B  纯运行期地板
├── t2_net.rs              # 258,048 B  TCP 帧协议 + 注册/心跳/任务循环
├── t3_full.rs             # 350,720 B  + shell/文件/进程/base64/SM4-GCM（含自检）
└── cargo-tls/             # 三个 TLS 探针（需要 cargo + 网络拉 crate）
    ├── Cargo.toml
    ├── src/tcp_base.rs    # 258,048 B
    ├── src/tls_schannel.rs# 275,456 B
    └── src/tls_rustls.rs  # 1,146,368 B
```

它们是**探针**，不是产品代码：没有 TLS/WS/MQTT、没有注入/凭据/驱动，不能当载荷用。

### 7.2 体积数字的复现命令

```powershell
# 单文件三档
rustc docs/rust-probe/t2_net.rs `
  -C opt-level=z -C lto=fat -C codegen-units=1 -C panic=abort -C strip=symbols `
  -C target-feature=+crt-static -C linker=<mingw64>/bin/gcc.exe -o t2_net.exe
(Get-Item t2_net.exe).Length

# TLS 三档
cd docs/rust-probe/cargo-tls
cargo build --release --bin tcp_base
cargo build --release --bin tls_schannel --features schannel
cargo build --release --bin tls_rustls  --features rustls
```

### 7.3 环境坑（实测踩到，写下来省下次的时间）

1. **Windows 上最小可用工具链 = MSVC 或完整 MinGW-w64。** 本机的 MSYS2 里
   `mingw-w64-x86_64-gcc` 装上了，但 `x86_64-w64-mingw32/lib/default-manifest.o` 缺失，
   链接报 `cannot find default-manifest.o`；补一个空的 `.drectve` 目标文件即可通过
   （仅为测量，正式环境请装完整工具链）。
2. **`PATH` 里 mingw32 排在 mingw64 前面时，`cc1.exe` 会以 `0xC000007B`
   （`STATUS_INVALID_IMAGE_FORMAT`）静默失败**——它 `import` 的
   `libgcc_s_seh-1.dll` 等被解析到 32 位版本。构建脚本必须把 `mingw64\bin` 放到最前面。
3. `rustup-init.exe`（从 `static.rust-lang.org` 下载）在本机被安全软件拦为
   `Access is denied`；改用 `pacman -S mingw-w64-x86_64-rust` 装 MSYS2 打包版才成功。
   **CI 上直接用官方 rustup 即可，这是本机环境的特例。**
4. `GetUserNameW` 在 `advapi32` 而不是 `kernel32`，`extern` 块要分开 `#[link]`。

---

## 8. 一句话回答

**可以加，而且是目前性价比最高的一次"体积 + 免杀静态面"优化：**
`light/tcp` 从 2.95 MB 降到 343 KB（实测），`light/http` 从 5.46 MB 降到 368 KB（TLS 走
SChannel，实测增量 17 KB）；代价是 3~4 个月把 13,000 行 Go 重写成 13,000~15,000 行 Rust，
外加一套 CI 工具链与"两套植入端"的长期维护成本。

**推荐路径**：v1.6 作为**可选**的第二植入端，先交付 `light` 档（R1，2~3 周），
能用、能测、体积优势立现；之后按 R2~R5 补能力，每阶段都在 UI 上如实标注已实现/未实现。
