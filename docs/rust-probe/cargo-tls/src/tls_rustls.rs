// 体积探针：TLS(rustls + ring + webpki-roots) + 手写 HTTP/1.1 轮询。
// 与 tls_schannel 对照，量出"自带密码学实现"相对"用系统 TLS"的体积差。
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1".into());
    let port = std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8443);
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
    // 与 Go 版一致：不校验证书链（自签名 C2 常态），但要真做 TLS 握手
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut cfg = cfg;
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(skip_verify::NoVerify::new()));

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), server_name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let mut sock = TcpStream::connect((host, port))?;
    sock.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    http_post(&mut tls, host, "/api/v1/poll", b"register")?;
    let _ = http_read(&mut tls)?;
    for _ in 0..3 {
        http_post(&mut tls, host, "/api/v1/poll", b"hb")?;
        let _ = http_read(&mut tls)?;
        std::thread::sleep(Duration::from_secs(5));
    }
    Ok(())
}

mod skip_verify {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerify(rustls::crypto::CryptoProvider);

    impl NoVerify {
        pub fn new() -> Self {
            NoVerify(rustls::crypto::ring::default_provider())
        }
    }

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
