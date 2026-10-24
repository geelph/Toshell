# Rust 植入端体积探针构建脚本（仅用于测量，产物不是可用载荷）
#
#   ./build.ps1 -MingwDir 'C:\msys64\mingw64'
#   ./build.ps1 -MingwDir 'C:\msys64\mingw64' -WithTls
#
# 需要：rustc（+ cargo，若要量 TLS 三档）、MinGW-w64 的 gcc（或改用 MSVC 工具链）。

param(
    [string]$MingwDir = 'C:\msys64\mingw64',
    [switch]$WithTls,
    [string]$OutDir = ''
)

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutDir) { $OutDir = Join-Path $here 'out' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$rustc = Join-Path $MingwDir 'bin\rustc.exe'
$cargo = Join-Path $MingwDir 'bin\cargo.exe'
$gcc = Join-Path $MingwDir 'bin\gcc.exe'

if (-not (Test-Path $rustc)) { throw "找不到 rustc：$rustc（用 -MingwDir 指定工具链根目录）" }

# 坑：PATH 里 32 位 mingw32 排在前面会让 cc1.exe 以 0xC000007B 失败。
$env:PATH = (Join-Path $MingwDir 'bin') + ';' + $env:PATH

# 统一体积档位：不开 LTO / 不 strip 会让体积涨约 3.7 倍。
$flags = @(
    '-C', 'opt-level=z',
    '-C', 'lto=fat',
    '-C', 'codegen-units=1',
    '-C', 'panic=abort',
    '-C', 'strip=symbols',
    '-C', 'target-feature=+crt-static',
    '-C', "linker=$gcc",
    '--edition', '2021',
    '-A', 'warnings'
)

$results = @()
foreach ($name in @('t1_floor', 't2_net', 't3_full')) {
    $src = Join-Path $here "$name.rs"
    $exe = Join-Path $OutDir "$name.exe"
    & $rustc $src @flags -o $exe
    if (-not (Test-Path $exe)) { throw "$name 构建失败" }
    $size = (Get-Item $exe).Length
    $results += [pscustomobject]@{ 探针 = $name; 字节 = $size }
    '{0,-12} {1,10:N0} B' -f $name, $size
}

# t3_full 自检：SM4 标准向量 + GCM 往返/篡改拒绝 + base64 + Win32 探测
$exe = Join-Path $OutDir 't3_full.exe'
& $exe --selftest
if ($LASTEXITCODE -ne 0) { throw 't3_full 自检失败' }

if ($WithTls) {
    if (-not (Test-Path $cargo)) { throw "找不到 cargo：$cargo" }
    $tlsDir = Join-Path $here 'cargo-tls'
    Push-Location $tlsDir
    try {
        & $cargo build --release --bin tcp_base
        & $cargo build --release --bin tls_schannel --features schannel
        & $cargo build --release --bin tls_rustls --features rustls
        $rel = Join-Path $tlsDir 'target\x86_64-pc-windows-gnu\release'
        foreach ($n in @('tcp_base', 'tls_schannel', 'tls_rustls')) {
            $p = Join-Path $rel "$n.exe"
            if (Test-Path $p) {
                $size = (Get-Item $p).Length
                $results += [pscustomobject]@{ 探针 = $n; 字节 = $size }
                '{0,-12} {1,10:N0} B' -f $n, $size
            }
        }
    }
    finally {
        Pop-Location
    }
}

''
'=== 汇总（字节）==='
$results | Format-Table -AutoSize
