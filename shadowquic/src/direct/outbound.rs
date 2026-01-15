use std::{net::ToSocketAddrs, sync::Arc};

use bytes::BytesMut;
use tokio::net::TcpStream;
use tracing::{Instrument, error, trace, trace_span};

use crate::{
    Outbound, UdpSession,
    config::DirectOutCfg,
    error::SError,
    utils::{self, bidirectional_copy, dual_socket::DualSocket},
};
use async_trait::async_trait;

#[derive(Clone, Debug, Default)]
pub struct DirectOut {
    pub cfg: DirectOutCfg,
}

#[async_trait]
impl Outbound for DirectOut {
    async fn handle(
        &mut self,
        req: crate::ProxyRequest,
    ) -> Result<tokio::sync::oneshot::Receiver<(u64, u64)>, crate::error::SError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let dns_strategy = self.cfg.dns_strategy.clone();
        let doh_cfg = self.cfg.dns_over_https.clone();
        let self_clone = self.clone();
        let fut = async move {
            let res = async {
                match req {
                    crate::ProxyRequest::Tcp(mut tcp_session) => {
                        trace!(
                            "direct tcp to {} cost: {:?}",
                            tcp_session.dst,
                            tcp_session.start_time.elapsed()
                        );

                        let dst = utils::dns::resolve_socks_addr(
                            &tcp_session.dst,
                            &dns_strategy,
                            doh_cfg.as_ref(),
                        )
                        .await?;
                        trace!(
                            "resolved {} to {} cost: {:?}",
                            tcp_session.dst,
                            dst,
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
    pub fn new(cfg: DirectOutCfg) -> Self {
        crate::utils::dns::init_dns_from_direct_cfg(&cfg);
        Self { cfg }
    }

    async fn handle_udp(&self, udp_session: UdpSession) -> Result<(), SError> {
        trace!("associating udp to {}", udp_session.dst);
        let dst = udp_session
            .dst
            .to_socket_addrs()?
            .next()
            .ok_or(SError::DomainResolveFailed(udp_session.dst.to_string()))?;
        trace!("resolved to {}", dst);
        let ipv4_only = dst.is_ipv4();

        let socket = DualSocket::new_bind(dst, !ipv4_only)?;

        let upstream = Arc::new(socket);
        let upstream_clone = upstream.clone();
        let mut downstream = udp_session.inner.recv;

        let dns_cache = utils::dns::DnsResolve::default();
        let dns_cache_clone = dns_cache.clone();
        let dns_strategy = self.cfg.dns_strategy.clone();
        let doh_cfg = self.cfg.dns_over_https.clone();
        let fut1 = async move {
            loop {
                let mut buf_send = BytesMut::new();
                buf_send.resize(2000, 0);
                //trace!("recv upstream");
                let (len, dst) = upstream.recv_from(&mut buf_send).await?;
                //trace!("udp request reply from:{}", dst);
                let dst = dns_cache_clone.inv_resolve(&dst).await;
                //trace!("udp source inverse resolved to:{}", dst);
                let buf = buf_send.freeze();
                //trace!("udp recved:{} bytes", len);
                let _ = udp_session
                    .inner
                    .send
                    .send_to(buf.slice(..len), dst)
                    .await?;
            }
            #[allow(unreachable_code)]
            (Ok(()) as Result<(), SError>)
        };
        let fut2 = async move {
            loop {
                let (buf, dst) = downstream.recv_from().await?;

                let dst = dns_cache
                    .resolve(dst, &dns_strategy, doh_cfg.as_ref())
                    .await?;
                //trace!("udp resolve to:{}", dst);
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
