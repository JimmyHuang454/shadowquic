use std::sync::Arc;

use bytes::Bytes;
use error::SError;
use msgs::socks5::SocksAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::error;

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
pub struct TcpSession<IO = AnyTcp> {
    pub stream: IO,
    pub dst: SocksAddr,
}

pub struct UdpSession<I = AnyUdpRecv, O = AnyUdpSend> {
    pub recv: I,
    pub send: O,
    /// Control stream, should be kept alive during session.
    pub stream: Option<AnyTcp>,
    pub dst: SocksAddr,
}

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
    async fn handle(&mut self, req: ProxyRequest<T, I, O>) -> Result<(), SError>;
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
use crate::router::Router;

pub struct Manager {
    pub inbounds: Vec<(String, Box<dyn Inbound>)>,
    pub router: Arc<Router>,
}

impl Manager {
    pub async fn run(self) -> Result<(), SError> {
        let mut tasks = Vec::new();
        for (tag, inbound) in self.inbounds {
            let router = self.router.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = inbound.init().await {
                    error!("error during init inbound {}: {}", tag, e);
                    return;
                }
                let mut inbound = inbound;
                loop {
                    match inbound.accept().await {
                        Ok(req) => {
                            let dst = match &req {
                                ProxyRequest::Tcp(s) => &s.dst,
                                ProxyRequest::Udp(s) => &s.dst,
                            };
                            let outbound = router.route(&tag, dst);
                            let mut out = outbound.lock().await;
                            match out.handle(req).await {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("error during handling request: {}", e)
                                }
                            }
                        }
                        Err(e) => {
                            error!("error during accepting request: {}", e)
                        }
                    }
                }
            }));
        }

        for task in tasks {
            let _ = task.await;
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}
