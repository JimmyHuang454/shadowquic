use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use fast_socks5::client::{Config, Socks5Datagram};

use shadowquic::config::{
    AuthUser, CongestionControl, DirectOutCfg, DnsCfg, JlsUpstream, ShadowQuicClientCfg,
    ShadowQuicServerCfg, SocksServerCfg, default_initial_mtu,
};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Duration;

use shadowquic::{
    direct::outbound::DirectOut,
    router::Router,
    shadowquic::{inbound::start_shadowquic_inbound, outbound::ShadowQuicClient},
    socks::inbound::start_socks_inbound,
};

use tracing::{Level, level_filters::LevelFilter, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const CHUNK_LEN: usize = 1000;
const ROUND: usize = 100;
#[tokio::test]
async fn main() {
    let socks_server = "127.0.0.1:1030";
    let target_addr = ("127.0.0.1", 1446);
    let mut config = Config::default();
    config.set_skip_auth(false);
    test_shadowquic().await;
    tokio::spawn(echo_udp(1446));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let backing_socket = TcpStream::connect(socks_server).await.unwrap();
    let socks = Socks5Datagram::bind(
        backing_socket,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    )
    .await
    .unwrap();
    let sendbuf: Vec<u8> = (0..(CHUNK_LEN * ROUND)).map(|_| rand::random()).collect();
    let mut recvbuf = vec![0u8; CHUNK_LEN * ROUND];
    let mut ii = 0;
    let mut jj = 0;
    let fut = async {
        loop {
            tokio::select! {
                r = async {
                    if ii == ROUND {
                        tokio::time::sleep(Duration::from_millis(200000)).await;
                    }
                    socks.send_to(&sendbuf[ii*CHUNK_LEN..(ii+1)*CHUNK_LEN], target_addr).await
                 } => {
                    r.unwrap();
                    ii += 1;
                    #[warn(clippy::modulo_one)]
                    if ii % 1 == 0 {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
                r = socks.recv_from(&mut recvbuf[jj*CHUNK_LEN..(jj+1)*CHUNK_LEN]) => {
                    let (len, _addr) = r.unwrap();
                    assert!(len == CHUNK_LEN);
                    jj += 1;
                    if jj == ROUND {
                        break;
                    }
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(60), fut)
        .await
        .unwrap();

    assert!(sendbuf == recvbuf);
}

use tokio::sync::Mutex;

async fn test_shadowquic() {
    let filter = tracing_subscriber::filter::Targets::new()
        // Enable the `INFO` level for anything in `my_crate`
        .with_target("udp", Level::TRACE)
        .with_target("shadowquic", Level::INFO)
        .with_target("shadowquic::msgs::socks", LevelFilter::OFF);

    // Enable the `DEBUG` level for a specific module.

    // Build a new subscriber with the `fmt` layer using the `Targets`
    // filter we constructed above.
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .try_init();

    // env_logger::init();
    trace!("Running");

    let sq_client = ShadowQuicClient::new("sq".to_string(), ShadowQuicClientCfg {
        password: "123".into(),
        username: "123".into(),
        addr: "[::1]:4448".to_string(),
        server_name: "localhost".into(),
        alpn: vec!["h3".into()],
        initial_mtu: 1200,
        congestion_control: CongestionControl::Bbr,
        zero_rtt: true,
        over_stream: true,
        ..Default::default()
    });

    let mut client_outbounds = HashMap::new();
    client_outbounds.insert(
        "sq".to_string(),
        Arc::new(Mutex::new(
            Box::new(sq_client) as Box<dyn shadowquic::Outbound>
        )),
    );
    let client_router =
        Router::new(vec![], client_outbounds, Some("sq".to_string()), true, None).unwrap();

    let client_router = Arc::new(client_router);

    start_socks_inbound(
        "socks".to_string(),
        client_router,
        SocksServerCfg {
            bind_addr: "127.0.0.1:1030".parse().unwrap(),
            users: vec![],
        },
    )
    .await
    .unwrap();

    let sq_server_cfg = ShadowQuicServerCfg {
        bind_addr: "[::1]:4448".parse().unwrap(),
        users: vec![AuthUser {
            username: "123".into(),
            password: "123".into(),
        }],
        jls_upstream: JlsUpstream {
            addr: "localhost:443".into(),
            ..Default::default()
        },
        alpn: vec!["h3".into()],
        zero_rtt: true,
        initial_mtu: default_initial_mtu(),
        congestion_control: CongestionControl::Bbr,
        ..Default::default()
    };
    let dns_cfg = DnsCfg {
        tag: "default".to_string(),
        dns_strategy: Default::default(),
        dns_over_https: None,
        dns_server: None,
        dns_cache_size: None,
        dns_memory_cache_capacity: None,
        dns_disk_cache_capacity: None,
        dns_disk_cache_path: None,
        dns_positive_min_ttl: None,
        dns_positive_max_ttl: None,
        dns_negative_min_ttl: None,
        dns_negative_max_ttl: None,
    };
    let direct_client =
        DirectOut::new("direct".to_string(), DirectOutCfg::default(), dns_cfg).await;

    let mut server_outbounds = HashMap::new();
    server_outbounds.insert(
        "direct".to_string(),
        Arc::new(Mutex::new(
            Box::new(direct_client) as Box<dyn shadowquic::Outbound>
        )),
    );
    let server_router =
        Router::new(vec![], server_outbounds, Some("direct".to_string()), true, None).unwrap();

    let server_router = Arc::new(server_router);

    start_shadowquic_inbound("sq".to_string(), server_router, sq_server_cfg)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
}
async fn echo_udp(port: u16) {
    let socks = Arc::new(UdpSocket::bind(("0.0.0.0", port)).await.unwrap());

    let mut recvbuf = vec![0u8; CHUNK_LEN];
    // let mut s1:TcpStream = s.get_socket();

    let socks1 = socks.clone();
    loop {
        let (_len, addr) = socks1.recv_from(&mut recvbuf).await.unwrap();

        socks.send_to(&recvbuf, addr).await.unwrap();
    }
}
