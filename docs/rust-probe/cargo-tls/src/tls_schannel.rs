// 体积探针：TLS(Windows SChannel 原生) + 手写 HTTP/1.1 轮询，模拟 ToShell 的 http 传输。
// 目的：量出"Rust 版 http 传输"相对"Rust 版 tcp 传输"的增量，与 Go 版（light+tcp 2.95MB → light+http 5.46MB）对比。
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1".into());
    let port = std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8443);
    let _ = poll(&host, port);
}

// 手写 HTTP/1.1 POST（不引 hyper/tokio）
fn http_post(
    w: &mut impl Write,
    host: &str,
    path: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write!(
        w,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        path,
        host,
        body.len()
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
    let mut content_len = 0usize;
    let text = String::from_utf8_lossy(&hdr).to_ascii_lowercase();
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
    let tcp = TcpStream::connect((host, port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(60)))?;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let mut tls = connector
        .connect(host, tcp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    http_post(&mut tls, host, "/api/v1/poll", b"register")?;
    let _ = http_read(&mut tls)?;
    for _ in 0..3 {
        http_post(&mut tls, host, "/api/v1/poll", b"hb")?;
        let _ = http_read(&mut tls)?;
        std::thread::sleep(Duration::from_secs(5));
    }
    Ok(())
}
