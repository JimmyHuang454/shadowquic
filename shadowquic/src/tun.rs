use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc::{Sender, channel};
use tracing::{error, info, warn, trace_span};
use tun_rs::DeviceBuilder;

use crate::{
    AnyUdpRecv, AnyUdpSend, ProxyRequest, UdpInner, UdpSend, UdpSession,
    config::TunInboundCfg,
    error::SError,
    handle_proxy_request,
    msgs::socks5::{AddrOrDomain, SocksAddr},
    router::Router,
    utils::route::RouteManager,
};

#[derive(Clone, Debug)]
struct FlowKey {
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
}

impl std::hash::Hash for FlowKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.src.hash(state);
        self.src_port.hash(state);
        self.dst.hash(state);
        self.dst_port.hash(state);
    }
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.src == other.src
            && self.src_port == other.src_port
            && self.dst == other.dst
            && self.dst_port == other.dst_port
    }
}
impl Eq for FlowKey {}

struct FlowState {
    last_seen: Instant,
    downstream: Sender<(Bytes, SocksAddr)>,
}

#[derive(Clone)]
struct TunFlowSend {
    write_tx: Sender<Vec<u8>>,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
}

#[async_trait]
impl UdpSend for TunFlowSend {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError> {
        let port = addr.port;
        let src_ip = match addr.addr {
            AddrOrDomain::V4(v4) => IpAddr::V4(v4.into()),
            AddrOrDomain::V6(v6) => IpAddr::V6(v6.into()),
            AddrOrDomain::Domain(_) => self.remote_ip,
        };

        let packet = match (src_ip, self.local_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                build_ipv4_udp_packet(src, dst, port, self.local_port, &buf)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                build_ipv6_udp_packet(src, dst, port, self.local_port, &buf)
            }
            _ => return Err(SError::SocksError("ip version mismatch".into())),
        };

        self.write_tx
            .send(packet)
            .await
            .map_err(|_| SError::InboundUnavailable)?;

        Ok(buf.len())
    }
}

pub fn start_tun_inbound(
    tag: String,
    router: Arc<Router>,
    cfg: TunInboundCfg,
) -> Result<(), SError> {
    if cfg.ipv4_cidr.is_none() && cfg.ipv6_cidr.is_none() {
        return Err(SError::SocksError("tun inbound requires ipv4 or ipv6".into()));
    }

    tokio::spawn(async move {
        let mut builder = DeviceBuilder::new();
        if let Some(name) = &cfg.name {
            builder = builder.name(name);
        }
        if let Some(mtu) = cfg.mtu {
            builder = builder.mtu(mtu);
        }
        if let Some(ipv4) = cfg.ipv4_cidr.as_deref() {
            match ipv4.parse::<ipnet::IpNet>() {
                Ok(ipnet::IpNet::V4(v4)) => {
                    builder = builder.ipv4(v4.addr().to_string(), v4.prefix_len(), None);
                }
                Ok(_) => warn!("tun ipv4-cidr is not ipv4"),
                Err(e) => warn!("tun ipv4-cidr parse failed: {}", e),
            }
        }
        if let Some(ipv6) = cfg.ipv6_cidr.as_deref() {
            match ipv6.parse::<ipnet::IpNet>() {
                Ok(ipnet::IpNet::V6(v6)) => {
                    builder = builder.ipv6(v6.addr().to_string(), v6.prefix_len());
                }
                Ok(_) => warn!("tun ipv6-cidr is not ipv6"),
                Err(e) => warn!("tun ipv6-cidr parse failed: {}", e),
            }
        }

        let dev = match builder.build_async() {
            Ok(d) => d,
            Err(e) => {
                error!("tun build failed: {}", e);
                return;
            }
        };

        let mut _route_manager = None;
        if cfg.auto_route == Some(true) {
            if let Some(name) = &cfg.name {
                info!("enabling auto route for interface: {}", name);
                _route_manager = Some(RouteManager::new(
                    name.clone(),
                    cfg.ipv4_cidr.is_some(),
                    cfg.ipv6_cidr.is_some(),
                ));
            } else {
                error!("auto_route enabled but tun name is not set");
            }
        }

        let (write_tx, mut write_rx) = channel::<Vec<u8>>(1024);

        let flow_timeout = Duration::from_secs(cfg.flow_timeout_secs.unwrap_or(120));
        let mut flows: HashMap<FlowKey, FlowState> = HashMap::new();
        let mut buf = vec![0u8; 65536];
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(30));

        info!("tun inbound started");

        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    let now = Instant::now();
                    flows.retain(|_, st| now.duration_since(st.last_seen) < flow_timeout);
                }
                maybe_pkt = write_rx.recv() => {
                    let Some(pkt) = maybe_pkt else { break };
                    if let Err(e) = dev.send(&pkt).await {
                        error!("tun send failed: {}", e);
                    }
                }
                r = dev.recv(&mut buf) => {
                    let len = match r {
                        Ok(n) => n,
                        Err(e) => {
                            error!("tun recv failed: {}", e);
                            continue;
                        }
                    };
                    let pkt = &buf[..len];
                    let Some(parsed) = parse_udp_ip_packet(pkt) else {
                        continue;
                    };

                    let key = FlowKey {
                        src: parsed.src_ip,
                        src_port: parsed.src_port,
                        dst: parsed.dst_ip,
                        dst_port: parsed.dst_port,
                    };

                    let now = Instant::now();

                    let dst_sock: SocksAddr = SocketAddr::new(parsed.dst_ip, parsed.dst_port).into();

                    if !flows.contains_key(&key) {
                        let (down_tx, down_rx) = channel::<(Bytes, SocksAddr)>(1024);
                        let send = TunFlowSend {
                            write_tx: write_tx.clone(),
                            local_ip: parsed.src_ip,
                            local_port: parsed.src_port,
                            remote_ip: parsed.dst_ip,
                        };

                        let bind_dst: SocksAddr = match parsed.dst_ip {
                            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into(),
                            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into(),
                        };

                        let session = UdpSession {
                            inner: UdpInner {
                                recv: Box::new(down_rx) as AnyUdpRecv,
                                send: std::sync::Arc::new(send) as AnyUdpSend,
                                stream: None,
                            },
                            dst: bind_dst,
                            start_time: now,
                        };

                        let router = router.clone();
                        let tag = tag.clone();
                        tokio::spawn(async move {
                            let span = trace_span!("tun");
                            handle_proxy_request(router, tag, ProxyRequest::Udp(session), span).await;
                        });

                        flows.insert(key.clone(), FlowState { last_seen: now, downstream: down_tx });
                    }

                    if let Some(st) = flows.get_mut(&key) {
                        st.last_seen = now;
                        let _ = st.downstream.try_send((Bytes::copy_from_slice(parsed.payload), dst_sock));
                    }
                }
            }
        }
    });

    Ok(())
}

struct ParsedUdp<'a> {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

fn parse_udp_ip_packet(pkt: &[u8]) -> Option<ParsedUdp<'_>> {
    let v = pkt.first().copied()? >> 4;
    match v {
        4 => parse_ipv4_udp(pkt),
        6 => parse_ipv6_udp(pkt),
        _ => None,
    }
}

fn parse_ipv4_udp(pkt: &[u8]) -> Option<ParsedUdp<'_>> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    if pkt[9] != 17 {
        return None;
    }
    let src_ip = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
    let udp = &pkt[ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }
    let payload = &udp[8..udp_len];
    Some(ParsedUdp {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
    })
}

fn parse_ipv6_udp(pkt: &[u8]) -> Option<ParsedUdp<'_>> {
    if pkt.len() < 40 {
        return None;
    }
    if pkt[6] != 17 {
        return None;
    }
    let src_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?));
    let udp = &pkt[40..];
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }
    let payload = &udp[8..udp_len];
    Some(ParsedUdp {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
    })
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&b) = data.chunks_exact(2).remainder().first() {
        sum += (b as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_ipv4_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];

    pkt[0] = 0x45;
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[10..12].copy_from_slice(&0u16.to_be_bytes());
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());

    let csum = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());

    let udp_off = 20;
    pkt[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[udp_off + 4..udp_off + 6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&0u16.to_be_bytes());
    pkt[udp_off + 8..].copy_from_slice(payload);

    let udp_len = (8 + payload.len()) as u16;
    let mut pseudo = Vec::with_capacity(12 + 8 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(&pkt[udp_off..udp_off + 8]);
    pseudo.extend_from_slice(payload);
    let udp_csum = checksum(&pseudo);
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&udp_csum.to_be_bytes());

    pkt
}

fn build_ipv6_udp_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 40 + udp_len;
    let mut pkt = vec![0u8; total_len];

    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());

    let udp_off = 40;
    pkt[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[udp_off + 4..udp_off + 6].copy_from_slice(&((udp_len) as u16).to_be_bytes());
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&0u16.to_be_bytes());
    pkt[udp_off + 8..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(40 + 8 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&pkt[udp_off..udp_off + 8]);
    pseudo.extend_from_slice(payload);
    let udp_csum = checksum(&pseudo);
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&udp_csum.to_be_bytes());

    pkt
}
