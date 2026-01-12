use crate::config::{AuthUser, HttpServerCfg};
use crate::error::SError;
use crate::msgs::socks5::SocksAddr;
use crate::{Inbound, ProxyRequest, TcpSession};
use anyhow::Result;
use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

pub struct HttpServer {
    #[allow(dead_code)]
    bind_addr: SocketAddr,
    #[allow(dead_code)]
    users: Vec<AuthUser>,
    listener: TcpListener,
}

impl HttpServer {
    pub async fn new(cfg: HttpServerCfg) -> Result<Self, SError> {
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
        Ok(Self {
            bind_addr: cfg.bind_addr,
            listener,
            users: cfg.users,
        })
    }
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

#[async_trait]
impl Inbound for HttpServer {
    async fn accept(&mut self) -> Result<ProxyRequest, SError> {
        let (mut stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|e| SError::SocksError(e.to_string()))?;

        let mut buf = BytesMut::with_capacity(4096);

        loop {
            let n = stream
                .read_buf(&mut buf)
                .await
                .map_err(|e| SError::SocksError(e.to_string()))?;
            if n == 0 {
                return Err(SError::SocksError("Connection closed".to_string()));
            }

            let mut headers = [httparse::EMPTY_HEADER; 64];
            let parse_result = {
                let mut req = httparse::Request::new(&mut headers);
                match req.parse(&buf) {
                    Ok(httparse::Status::Complete(offset)) => {
                        let method = req
                            .method
                            .ok_or(SError::SocksError("No method".to_string()))?;
                        let path = req.path.ok_or(SError::SocksError("No path".to_string()))?;

                        let is_connect = method == "CONNECT";
                        let dst = if is_connect {
                            parse_host_port(path)?
                        } else {
                            parse_url(path, req.headers)?
                        };
                        Ok(Some((offset, dst, is_connect)))
                    }
                    Ok(httparse::Status::Partial) => Ok(None),
                    Err(e) => Err(SError::SocksError(format!("Http parse error: {}", e))),
                }
            };

            match parse_result {
                Ok(Some((offset, dst, is_connect))) => {
                    if is_connect {
                        stream
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await
                            .map_err(|e| SError::SocksError(e.to_string()))?;
                    }

                    let remaining = buf.split_off(offset);

                    let prefix = if is_connect {
                        if remaining.is_empty() {
                            None
                        } else {
                            Some(remaining.freeze())
                        }
                    } else {
                        let mut full = buf;
                        full.unsplit(remaining);
                        Some(full.freeze())
                    };

                    let prefixed_stream = PrefixedTcpStream { stream, prefix };

                    return Ok(ProxyRequest::Tcp(TcpSession {
                        stream: Box::new(prefixed_stream),
                        dst,
                    }));
                }
                Ok(None) => {
                    if buf.len() >= 65536 {
                        return Err(SError::SocksError("Header too large".to_string()));
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
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
    let port = url
        .port_or_known_default()
        .unwrap_or(443);
    Ok(SocksAddr::from_domain(host, port))
}

fn parse_url(path: &str, headers: &[httparse::Header]) -> Result<SocksAddr, SError> {
    if path.starts_with("http://") || path.starts_with("https://") {
        let url = Url::parse(path)
            .map_err(|e| SError::SocksError(format!("Http parse error: {}", e)))?;
        let host = url
            .host_str()
            .ok_or_else(|| SError::SocksError("Missing host".to_string()))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| SError::SocksError("Missing port".to_string()))?;
        return Ok(SocksAddr::from_domain(host, port));
    }

    for header in headers {
        if header.name.eq_ignore_ascii_case("Host") {
            let host_raw = std::str::from_utf8(header.value)
                .map_err(|_| SError::SocksError("Invalid Host header".to_string()))?
                .trim();
            // Build an http URL to leverage known default port (80)
            let url = Url::parse(&format!("http://{}/", host_raw))
                .map_err(|_| SError::SocksError("Invalid Host header".to_string()))?;
            let host = url
                .host_str()
                .ok_or_else(|| SError::SocksError("Missing host".to_string()))?
                .to_string();
            let port = url
                .port_or_known_default()
                .unwrap_or(80);
            return Ok(SocksAddr::from_domain(host, port));
        }
    }

    Err(SError::SocksError(
        "Could not determine destination".to_string(),
    ))
}
