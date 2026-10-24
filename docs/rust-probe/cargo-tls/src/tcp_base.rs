// 体积基线：与 tls_schannel / tls_rustls 完全相同的 HTTP 轮询逻辑，但走裸 TCP（无 TLS）。
// 用它做差，得到 "TLS 这一层的净体积"。
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1".into());
    let port = std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8080);
    let _ = poll(&host, port);
}

fn http_post(w: &mut impl Write, host: &str, path: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        w,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        path, host, body.len()
    )?;
    w.write_all(body)?;
    w.flush()
}

fn http_read(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut hdr = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    while hdr.len() < 8192 {
        r.read_exact(&mut b)?;
        hdr.push(b[0]);
        if hdr.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&hdr).to_ascii_lowercase();
    let mut content_len = 0usize;
    for line in text.split("\r\n") {
        if let Some(v) = line.strip_prefix("content-length:") {
            content_len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_len];
    if content_len > 0 {
        r.read_exact(&mut body)?;
    }
    Ok(body)
}

fn poll(host: &str, port: u16) -> std::io::Result<()> {
    let mut sock = TcpStream::connect((host, port))?;
    sock.set_read_timeout(Some(Duration::from_secs(60)))?;
    http_post(&mut sock, host, "/api/v1/poll", b"register")?;
    let _ = http_read(&mut sock)?;
    for _ in 0..3 {
        http_post(&mut sock, host, "/api/v1/poll", b"hb")?;
        let _ = http_read(&mut sock)?;
        std::thread::sleep(Duration::from_secs(5));
    }
    Ok(())
}
