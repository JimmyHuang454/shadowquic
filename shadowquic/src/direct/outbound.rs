use std::{net::ToSocketAddrs, sync::Arc};

use bytes::BytesMut;
use tokio::net::TcpStream;
use tracing::{Instrument, error, trace, trace_span};

use crate::{
    Outbound, UdpSession,
    config::{DirectOutCfg, DnsCfg},
    error::SError,
    utils::{self, bidirectional_copy, dual_socket::DualSocket},
};
use async_trait::async_trait;

#[derive(Clone, Debug)]
pub struct DirectOut {
    pub tag: String,
    pub cfg: DirectOutCfg,
    pub dns_cfg: DnsCfg,
}

#[async_trait]
impl Outbound for DirectOut {
    fn tag(&self) -> &str {
        &self.tag
    }
    async fn handle(
        &mut self,
        req: crate::ProxyRequest,
    ) -> Result<tokio::sync::oneshot::Receiver<(u64, u64)>, crate::error::SError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let self_clone = self.clone();
        let fut = async move {
            let res = async {
                match req {
                    crate::ProxyRequest::Tcp(mut tcp_session) => {
                        let resolve_result =
                            utils::dns::resolve_socks_addr(&tcp_session.dst, &self_clone.dns_cfg)
                                .await?;
                        let dst = resolve_result.addr;
                        trace!(
                            "resolved {} to {} (cached: {}) cost: {:?}",
                            tcp_session.dst,
                            dst,
                            resolve_result.cached,
                            tcp_session.start_time.elapsed()
                        );
                        let mut upstream = TcpStream::connect(dst).await?;
                        let (upload, download) =
                            bidirectional_copy(&mut tcp_session.inner.stream, &mut upstream)
                                .await?;
                        Ok((upload, download))
                    }
                    crate::ProxyRequest::Udp(udp_session) => {
                        self_clone.handle_udp(udp_session).await?;
                        Ok((0, 0))
                    }
                }
            }
            .await;

            match res {
                Ok(stats) => {
                    let _ = tx.send(stats);
                    Ok(())
                }
                Err(e) => {
                    let _ = tx.send((0, 0)); // Send 0s on error? Or drop tx?
                    // If we drop tx, rx.await fails.
                    Err(e)
                }
            }
        };
        let span = trace_span!("direct");
        tokio::spawn(
            async {
                let _ = fut.await.map_err(|x: SError| error!("{}", x));
            }
            .instrument(span),
        );

        Ok(rx)
    }
}
impl DirectOut {
    pub async fn new(tag: String, cfg: DirectOutCfg, dns_cfg: DnsCfg) -> Self {
        crate::utils::dns::init_dns_from_direct_cfg(&dns_cfg).await;
        Self { tag, cfg, dns_cfg }
    }

    async fn handle_udp(&self, udp_session: UdpSession) -> Result<(), SError> {
        trace!("associating udp to {}", udp_session.dst);

        let socket = DualSocket::new_bind_any().await?;
        let upstream = Arc::new(socket);
        let upstream_clone = upstream.clone();
        let mut downstream = udp_session.inner.recv;

        let dns_cache = utils::dns::DnsResolve::default();
        let dns_cache_clone = dns_cache.clone();
        // let dns_strategy = self.dns_cfg.dns_strategy.clone();
        // let doh_cfg = self.dns_cfg.dns_over_https.clone();
        let dns_cfg = Arc::new(self.dns_cfg.clone());
        let sender = udp_session.inner.send;

        let fut1 = async move {
            let mut buf_send = BytesMut::new();
            buf_send.resize(2000, 0);
            loop {
                //trace!("recv upstream");
                let (len, dst) = upstream.recv_from_buf(&mut buf_send).await?;
                //trace!("udp request reply from:{}", dst);
                let dst = dns_cache_clone.inv_resolve(&dst).await;
                //trace!("udp source inverse resolved to:{}", dst);
                //trace!("udp recved:{} bytes", len);
                let _ = sender
                    .send_to(buf_send.clone().split_to(len).freeze(), dst)
                    .await?;
            }
            #[allow(unreachable_code)]
            (Ok(()) as Result<(), SError>)
        };
        let fut2 = async move {
            loop {
                let (buf, dst) = downstream.recv_from().await?;

                let resolve_result = dns_cache.resolve(dst, &dns_cfg).await?;
                let dst = resolve_result.addr;
                //trace!("udp resolve to:{} (cached: {})", dst, resolve_result.cached);
                let _siz = upstream_clone.send_to(&buf, &dst).await?;
                //trace!("udp request sent:{}bytes", siz);
            }
            #[allow(unreachable_code)]
            (Ok(()) as Result<(), SError>)
        };
        // We can use spawn, but it requirs communication to shutdown the other
        // Flatten spawn handle using try_join! doesn't work. Don't know why
        tokio::try_join!(fut1, fut2)?;
        Ok(())
    }
}
