use async_trait::async_trait;
use bytes::Bytes;
use std::{
    net::{ToSocketAddrs, UdpSocket},
    sync::Arc,
    time::SystemTime,
};
use tokio::{
    io::AsyncReadExt,
    sync::{
        OnceCell,
        mpsc::{Receiver, Sender, channel},
    },
};

use crate::quic::EndClient;
use tracing::{Instrument, Level, debug, error, info, span, trace};

use crate::{
    Outbound,
    config::ShadowQuicClientCfg,
    error::SError,
    msgs::{
        shadowquic::{SQCmd, SQReq},
        socks5::{SEncode, SocksAddr},
    },
    quic::{QuicClient, QuicConnection},
    shadowquic::{handle_udp_recv_ctrl, handle_udp_send},
};

use super::{IDStore, SQConn, handle_udp_packet_recv, inbound::Unsplit};

pub struct ShadowQuicClient<EndT: QuicClient = EndClient> {
    pub quic_conn: Option<SQConn<EndT::C>>,
    pub config: ShadowQuicClientCfg,
    pub quic_end: OnceCell<EndT>,
}
impl<End: QuicClient> ShadowQuicClient<End> {
    pub fn new(cfg: ShadowQuicClientCfg) -> Self {
        Self {
            quic_conn: None,
            quic_end: OnceCell::new(),
            config: cfg,
        }
    }
    pub async fn init_endpoint(&self, ipv6: bool) -> Result<End, SError> {
        End::new(&self.config, ipv6).await
    }
    pub fn new_with_socket(cfg: ShadowQuicClientCfg, socket: UdpSocket) -> Result<Self, SError> {
        Ok(Self {
            quic_end: OnceCell::from(End::new_with_socket(&cfg, socket)?),
            quic_conn: None,
            config: cfg,
        })
    }

    pub async fn get_conn(&self) -> Result<SQConn<End::C>, SError> {
        let mut addr = self
            .config
            .addr
            .to_socket_addrs()
            .unwrap_or_else(|_| panic!("resolve quic addr faile: {}", self.config.addr))
            .next()
            .unwrap_or_else(|| panic!("resolve quic addr faile: {}", self.config.addr));

        if let Some(ph) = &self.config.port_hopping {
            let ports = ph.get_ports();
            if !ports.is_empty() {
                let nanos = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos();
                let port = ports[nanos as usize % ports.len()];
                addr.set_port(port);
                info!("Port hopping selected port: {}", port);
            }
        }

        let conn = self
            .quic_end
            .get_or_init(|| async {
                self.init_endpoint(addr.is_ipv6())
                    .await
                    .expect("error during initialize quic endpoint")
            })
            .await
            .connect(addr, &self.config.server_name)
            .await?;

        let conn = SQConn {
            conn,
            send_id_store: Default::default(),
            recv_id_store: IDStore {
                id_counter: Default::default(),
                inner: Default::default(),
            },
        };
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            let _ = handle_udp_packet_recv(conn_clone)
                .await
                .map_err(|x| error!("handle udp packet recv error: {}", x));
        });
        Ok(conn)
    }
    async fn prepare_conn(&mut self) -> Result<(), SError> {
        // delete connection if closed.
        self.quic_conn.take_if(|x| {
            x.close_reason().is_some_and(|x| {
                info!("quic connection closed due to {}", x);
                true
            })
        });
        // Creating new connectin
        if self.quic_conn.is_none() {
            self.quic_conn = Some(self.get_conn().await?);
        }
        Ok(())
    }
}
#[async_trait]
impl Outbound for ShadowQuicClient {
    async fn handle(&mut self, req: crate::ProxyRequest) -> Result<tokio::sync::oneshot::Receiver<(u64, u64)>, crate::error::SError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.prepare_conn().await?;

        let conn = self.quic_conn.as_mut().unwrap().clone();

        let over_stream = self.config.over_stream;
        let (mut send, recv, id) = QuicConnection::open_bi(&conn.conn).await?;
        let _span = span!(Level::TRACE, "bistream", id = id);
        let fut = async move {
            let res = async {
                match req {
                    crate::ProxyRequest::Tcp(mut tcp_session) => {
                        debug!("bistream opened for tcp dst:{}", tcp_session.dst.clone());
                        //let _enter = _span.enter();
                        let req = SQReq {
                            cmd: SQCmd::Connect,
                            dst: tcp_session.dst.clone(),
                        };
                        req.encode(&mut send).await?;
                        trace!("tcp connect req header sent");

                        let u = tokio::io::copy_bidirectional(
                            &mut Unsplit { s: send, r: recv },
                            &mut tcp_session.inner.stream,
                        )
                        .await?;
                        Ok((u.1, u.0))
                    }
                    crate::ProxyRequest::Udp(udp_session) => {
                        info!("bistream opened for udp dst:{}", udp_session.dst.clone());
                        let req = SQReq {
                            cmd: if over_stream {
                                SQCmd::AssociatOverStream
                            } else {
                                SQCmd::AssociatOverDatagram
                            },
                            dst: udp_session.dst.clone(),
                        };
                        req.encode(&mut send).await?;
                        trace!("udp associate req header sent");
                        let fut2 = handle_udp_recv_ctrl(recv, udp_session.inner.send.clone(), conn.clone());
                        let fut1 = handle_udp_send(send, udp_session.inner.recv, conn, over_stream);
                        // control stream, in socks5 inbound, end of control stream
                        // means end of udp association.
                        let fut3 = async {
                            if udp_session.inner.stream.is_none() {
                                return Ok(());
                            }
                            let mut buf = [0u8];
                            udp_session
                                .inner
                                .stream
                                .unwrap()
                                .read_exact(&mut buf)
                                .await
                                .map_err(|x| SError::UDPSessionClosed(x.to_string()))?;
                            error!("unexpected data received from socks control stream");
                            Err(SError::UDPSessionClosed(
                                "unexpected data received from socks control stream".into(),
                            )) as Result<(), SError>
                        };

                        tokio::try_join!(fut1, fut2, fut3)?;
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
                    let _ = tx.send((0, 0));
                    Err(e)
                }
            }
        };
        tokio::spawn(async {
            let _ = fut.instrument(_span).await.map_err(|x: SError| error!("{}", x));
        });
        Ok(rx)
    }
}

/// Helper function to create new stream for proxy dstination
#[allow(dead_code)]
pub async fn connect_tcp<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    dst: SocksAddr,
) -> Result<Unsplit<C::SendStream, C::RecvStream>, crate::error::SError> {
    let conn = sq_conn;

    let (mut send, recv, _id) = conn.open_bi().await?;

    info!("bistream opened for tcp dst:{}", dst.clone());
    //let _enter = _span.enter();
    let req = SQReq {
        cmd: SQCmd::Connect,
        dst,
    };
    req.encode(&mut send).await?;
    trace!("req header sent");

    Ok(Unsplit { s: send, r: recv })
}

/// associate a udp socket in the remote server
/// return a socket-like send, recv handle.
#[allow(dead_code)]
pub async fn associate_udp<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    dst: SocksAddr,
    over_stream: bool,
) -> Result<(Sender<(Bytes, SocksAddr)>, Receiver<(Bytes, SocksAddr)>), SError> {
    let conn = sq_conn;

    let (mut send, recv, _id) = conn.open_bi().await?;

    info!("bistream opened for udp dst:{}", dst.clone());

    let req = SQReq {
        cmd: if over_stream {
            SQCmd::AssociatOverStream
        } else {
            SQCmd::AssociatOverDatagram
        },
        dst: dst.clone(),
    };
    req.encode(&mut send).await?;
    let (local_send, udp_recv) = channel::<(Bytes, SocksAddr)>(10);
    let (udp_send, local_recv) = channel::<(Bytes, SocksAddr)>(10);
    let local_send = Arc::new(local_send);
    let fut2 = handle_udp_recv_ctrl(recv, local_send, conn.clone());
    let fut1 = handle_udp_send(send, Box::new(local_recv), conn.clone(), over_stream);

    tokio::spawn(async {
        match tokio::try_join!(fut1, fut2) {
            Err(e) => error!("udp association ended due to {}", e),
            Ok(_) => trace!("udp association ended"),
        }
    });

    Ok((udp_send, udp_recv))
}
