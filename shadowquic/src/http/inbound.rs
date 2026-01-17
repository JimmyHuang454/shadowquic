use crate::config::HttpServerCfg;
use crate::error::SError;
use crate::msgs::socks5::SocksAddr;
use crate::{ProxyRequest, TcpInner, TcpSession, handle_proxy_request, router::Router};
use bytes::{Buf, Bytes, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, error, info, trace_span};
use url::Url;

pub async fn start_http_inbound(
    tag: String,
    router: Arc<Router>,
    cfg: HttpServerCfg,
) -> Result<(), SError> {
    let dual_stack = cfg.bind_addr.is_ipv6();
    let socket = Socket::new(
        if dual_stack {
            Domain::IPV6
        } else {
            Domain::IPV4
        },
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if dual_stack {
        let _ = socket.set_only_v6(false);
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&cfg.bind_addr.into())?;
    socket.listen(256)?;
    let listener = TcpListener::from_std(socket.into())
        .map_err(|e| SError::SocksError(format!("failed to create TcpListener: {e}")))?;

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let span = trace_span!(
                        "http",
                        s = addr.to_string(),
                        d = tracing::field::Empty,
                        r = tracing::field::Empty,
                        o = tracing::field::Empty,
                        t = tracing::field::Empty
                    );
                    let router = router.clone();
                    let tag = tag.clone();
                    let handle_span = span.clone();
                    tokio::spawn(
                        async move {
                            info!("inbound connection accepted");
                            let res: Result<(), SError> = async {
                                let req = parse_http_request(stream).await?;
                                handle_proxy_request(router, tag, req, handle_span).await;
                                Ok(())
                            }
                            .await;
                            if let Err(e) = res {
                                error!("error during handling http inbound connection: {}", e);
                            }
                        }
                        .instrument(span),
                    );
                }
                Err(e) => {
                    error!("error during accepting http inbound connection: {}", e);
                }
            }
        }
    });

    Ok(())
}

pub struct PrefixedTcpStream {
    stream: TcpStream,
    prefix: Option<Bytes>,
}

impl AsyncRead for PrefixedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(prefix) = &mut self.prefix {
            if prefix.has_remaining() {
                let len = std::cmp::min(buf.remaining(), prefix.remaining());
                buf.put_slice(&prefix[..len]);
                prefix.advance(len);
                if !prefix.has_remaining() {
                    self.prefix = None;
                }
                return Poll::Ready(Ok(()));
            } else {
                self.prefix = None;
            }
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl crate::TcpTrait for PrefixedTcpStream {}

async fn parse_http_request(mut stream: TcpStream) -> Result<ProxyRequest, SError> {
    let start_time = std::time::Instant::now();

    let mut buf = BytesMut::with_capacity(1024);

    loop {
        let n = stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| SError::SocksError(e.to_string()))?;
        if n == 0 {
            return Err(SError::SocksError("Connection closed".to_string()));
        }

        let first_line_end = match buf.windows(2).position(|w| w == b"\r\n") {
            Some(i) => i,
            None => {
                if buf.len() >= 65536 {
                    return Err(SError::SocksError("Header too large".to_string()));
                }
                continue;
            }
        };

        let first_line_bytes = &buf[..first_line_end];
        let first_line = match std::str::from_utf8(first_line_bytes) {
            Ok(s) => s,
            Err(_) => {
                return Err(SError::SocksError(
                    "Invalid UTF-8 in request line".to_string(),
                ));
            }
        };

        let mut parts = first_line.split_whitespace();
        let method = parts
            .next()
            .ok_or(SError::SocksError("No method".to_string()))?;
        let path = parts
            .next()
            .ok_or(SError::SocksError("No path".to_string()))?;

        if method == "CONNECT" {
            if let Some(headers_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let dst = parse_host_port(path)?;
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .map_err(|e| SError::SocksError(e.to_string()))?;

                let offset = headers_end + 4;
                let remaining = buf.split_off(offset);
                let prefix = if remaining.is_empty() {
                    None
                } else {
                    Some(remaining.freeze())
                };

                let prefixed_stream = PrefixedTcpStream { stream, prefix };

                return Ok(ProxyRequest::Tcp(TcpSession {
                    inner: TcpInner {
                        stream: Box::new(prefixed_stream),
                    },
                    dst,
                    start_time,
                }));
            } else {
                if buf.len() >= 65536 {
                    return Err(SError::SocksError("Header too large".to_string()));
                }
                continue;
            }
        } else {
            if let Some(dst) = parse_url_simple(path) {
                let prefix = Some(buf.freeze());
                let prefixed_stream = PrefixedTcpStream { stream, prefix };
                return Ok(ProxyRequest::Tcp(TcpSession {
                    inner: TcpInner {
                        stream: Box::new(prefixed_stream),
                    },
                    dst,
                    start_time,
                }));
            }

            let headers_part = &buf[first_line_end + 2..];
            if let Some(dst) = find_host(headers_part) {
                let prefix = Some(buf.freeze());
                let prefixed_stream = PrefixedTcpStream { stream, prefix };
                return Ok(ProxyRequest::Tcp(TcpSession {
                    inner: TcpInner {
                        stream: Box::new(prefixed_stream),
                    },
                    dst,
                    start_time,
                }));
            }

            if buf.windows(4).position(|w| w == b"\r\n\r\n").is_some() {
                return Err(SError::SocksError("No Host header found".to_string()));
            }

            if buf.len() >= 65536 {
                return Err(SError::SocksError("Header too large".to_string()));
            }
            continue;
        }
    }
}

fn parse_host_port(path: &str) -> Result<SocksAddr, SError> {
    if let Ok(addr) = path.parse::<SocketAddr>() {
        return Ok(SocksAddr::from(addr));
    }
    if path.contains(':') {
        let parts: Vec<&str> = path.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(SError::SocksError(format!("Invalid host:port: {}", path)));
        }
        let port = parts[0]
            .parse::<u16>()
            .map_err(|_| SError::SocksError("Invalid port".to_string()))?;
        let host = parts[1];
        return Ok(SocksAddr::from_domain(host.to_string(), port));
    }
    // Default to HTTPS for CONNECT when port is omitted
    let url = Url::parse(&format!("https://{}/", path))
        .map_err(|_| SError::SocksError(format!("Invalid host: {}", path)))?;
    let host = url
        .host_str()
        .ok_or_else(|| SError::SocksError("Missing host".to_string()))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    Ok(SocksAddr::from_domain(host, port))
}

fn parse_url_simple(path: &str) -> Option<SocksAddr> {
    if path.starts_with("http://") || path.starts_with("https://") {
        if let Ok(url) = Url::parse(path) {
            if let Some(host) = url.host_str() {
                let port = url.port_or_known_default().unwrap_or(80);
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    let addr = SocketAddr::new(ip, port);
                    return Some(SocksAddr::from(addr));
                }
                return Some(SocksAddr::from_domain(host.to_string(), port));
            }
        }
    }
    None
}

fn find_host(buf: &[u8]) -> Option<SocksAddr> {
    let s = std::str::from_utf8(buf).ok()?;

    for line in s.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > 5 && line[..5].eq_ignore_ascii_case("host:") {
            let host_raw = line[5..].trim();
            let url = Url::parse(&format!("http://{}/", host_raw)).ok()?;
            let host = url.host_str()?.to_string();
            let port = url.port_or_known_default().unwrap_or(80);
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                let addr = SocketAddr::new(ip, port);
                return Some(SocksAddr::from(addr));
            }
            return Some(SocksAddr::from_domain(host, port));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::socks5::AddrOrDomain;

    #[test]
    fn parse_url_simple_ip_host_uses_ip_addr() {
        let dst = parse_url_simple("http://33.22.22.1").expect("expected dst");
        assert_eq!(dst.port, 80);
        match dst.addr {
            AddrOrDomain::V4(_) => {}
            _ => panic!("expected IPv4 address variant for IP host"),
        }
    }

    #[test]
    fn find_host_ip_uses_ip_addr() {
        let req = b"GET / HTTP/1.1\r\nHost: 33.22.22.1:8080\r\n\r\n";
        let dst = find_host(req).expect("expected dst");
        assert_eq!(dst.port, 8080);
        match dst.addr {
            AddrOrDomain::V4(_) => {}
            _ => panic!("expected IPv4 address variant for IP host header"),
        }
    }
}
