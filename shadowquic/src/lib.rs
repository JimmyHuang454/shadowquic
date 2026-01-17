use std::sync::Arc;

use bytes::Bytes;
use error::SError;
use msgs::socks5::SocksAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{Span, error, field, info, trace, Instrument};

pub mod config;
pub mod direct;
pub mod error;
pub mod http;
pub mod msgs;
pub mod quic;
pub mod router;
pub mod shadowquic;
pub mod socks;
pub mod tun;
pub mod utils;
pub enum ProxyRequest<T = AnyTcp, I = AnyUdpRecv, O = AnyUdpSend> {
    Tcp(TcpSession<T>),
    Udp(UdpSession<I, O>),
}
/// Udp socket only use immutable reference to self
/// So it can be safely wrapped by Arc and cloned to work in duplex way.
#[async_trait]
pub trait UdpSend: Send + Sync + Unpin {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError>; // addr is proxy addr
}
#[async_trait]
pub trait UdpRecv: Send + Sync + Unpin {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError>; // socksaddr is proxy addr
}
use std::time::Instant;

pub struct Session<T> {
    pub dst: SocksAddr,
    pub inner: T,
    pub start_time: Instant,
}

pub struct TcpInner<IO = AnyTcp> {
    pub stream: IO,
}

pub struct UdpInner<I = AnyUdpRecv, O = AnyUdpSend> {
    pub recv: I,
    pub send: O,
    /// Control stream, should be kept alive during session.
    pub stream: Option<AnyTcp>,
}

pub type TcpSession<IO = AnyTcp> = Session<TcpInner<IO>>;
pub type UdpSession<I = AnyUdpRecv, O = AnyUdpSend> = Session<UdpInner<I, O>>;

pub type AnyTcp = Box<dyn TcpTrait>;
pub type AnyUdpSend = Arc<dyn UdpSend>;
pub type AnyUdpRecv = Box<dyn UdpRecv>;
pub trait TcpTrait: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl TcpTrait for TcpStream {}

#[async_trait]
pub trait Inbound<T = AnyTcp, I = AnyUdpRecv, O = AnyUdpSend>: Send + Sync + Unpin {
    async fn accept(&mut self) -> Result<ProxyRequest<T, I, O>, SError>;
    async fn init(&self) -> Result<(), SError> {
        Ok(())
    }
}

#[async_trait]
pub trait Outbound<T = AnyTcp, I = AnyUdpRecv, O = AnyUdpSend>: Send + Sync + Unpin {
    async fn handle(
        &mut self,
        req: ProxyRequest<T, I, O>,
    ) -> Result<tokio::sync::oneshot::Receiver<(u64, u64)>, SError>;
    fn tag(&self) -> &str;
}

#[async_trait]
impl UdpSend for Sender<(Bytes, SocksAddr)> {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError> {
        let siz = buf.len();
        self.send((buf, addr))
            .await
            .map_err(|_| SError::InboundUnavailable)?;
        Ok(siz)
    }
}
#[async_trait]
impl UdpRecv for Receiver<(Bytes, SocksAddr)> {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError> {
        let r = self.recv().await.ok_or(SError::OutboundUnavailable)?;
        Ok(r)
    }
}
use crate::router::{OutboundStats, Router};
use crate::utils::{format_bytes, format_duration};

pub struct SessionObserver {
    stats: Option<Arc<OutboundStats>>,
    dst: SocksAddr,
    start_time: Instant,
}

impl SessionObserver {
    pub fn new(stats: Option<Arc<OutboundStats>>, dst: SocksAddr, start_time: Instant) -> Self {
        Self {
            stats,
            dst,
            start_time,
        }
    }

    pub fn on_start(&self) {
        if let Some(ref s) = self.stats {
            s.on_request_start();
        }
    }

    pub fn on_handle_error(&self) {
        if let Some(ref s) = self.stats {
            s.on_request_error();
            trace!(
                "outbound {} stats: current: {}, total: {}, upload: {}, download: {}",
                s.tag(),
                s.current_connections(),
                s.total_connections(),
                s.upload_bytes(),
                s.download_bytes()
            );
        }
    }

    pub async fn observe(self, rx: tokio::sync::oneshot::Receiver<(u64, u64)>) {
        let stats = self.stats;
        let result = rx.await;
        match (stats, result) {
            (Some(stats), Ok((upload, download))) => {
                stats.on_request_finish(upload, download);
                trace!(
                    "request to {} finished, upload: {}, download: {}, cost: {}",
                    self.dst,
                    format_bytes(upload),
                    format_bytes(download),
                    format_duration(self.start_time.elapsed())
                );
                trace!(
                    "outbound {} stats: current: {}, total: {}, upload: {}, download: {}",
                    stats.tag(),
                    stats.current_connections(),
                    stats.total_connections(),
                    format_bytes(stats.upload_bytes()),
                    format_bytes(stats.download_bytes())
                );
            }
            (Some(stats), Err(_)) => {
                stats.on_request_error();
                trace!(
                    "outbound {} stats: current: {}, total: {}, upload: {}, download: {}",
                    stats.tag(),
                    stats.current_connections(),
                    stats.total_connections(),
                    format_bytes(stats.upload_bytes()),
                    format_bytes(stats.download_bytes())
                );
            }
            (None, Ok((upload, download))) => {
                trace!(
                    "request to {} finished, upload: {}, download: {}, cost: {}",
                    self.dst,
                    format_bytes(upload),
                    format_bytes(download),
                    format_duration(self.start_time.elapsed())
                );
            }
            (None, Err(_)) => {}
        }
    }

    pub fn spawn_observe(self, rx: tokio::sync::oneshot::Receiver<(u64, u64)>, span: Span) {
        tokio::spawn(
            async move {
                self.observe(rx).await;
            }
            .instrument(span),
        );
    }
}

pub async fn handle_proxy_request(
    router: Arc<Router>,
    inbound_tag: String,
    req: ProxyRequest,
    span: Span,
) {
    let (outbound, stats, rule_index) = router.route(&inbound_tag, &req);
    let mut out = outbound.lock().await;
    let (dst, start_time) = match &req {
        ProxyRequest::Tcp(s) => (s.dst.clone(), s.start_time),
        ProxyRequest::Udp(s) => (s.dst.clone(), s.start_time),
    };
    span.record("d", &field::display(&dst));
    span.record(
        "r",
        &field::debug(&match rule_index {
            Some(idx) => idx.to_string(),
            None => "default".to_string(),
        }),
    );
    span.record("o", &field::debug(&out.tag()));
    span.record("t", &field::debug(&format_duration(start_time.elapsed())));
    let observer = SessionObserver::new(stats.clone(), dst.clone(), start_time);
    observer.on_start();

    match out.handle(req).await {
        Ok(rx) => {
            observer.spawn_observe(rx, span.clone());
        }
        Err(e) => {
            observer.on_handle_error();
            error!(parent: &span, "error during handling request: {}", e);
        }
    }
}
