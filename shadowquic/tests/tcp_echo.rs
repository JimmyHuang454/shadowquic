use fast_socks5::client::{Config, Socks5Stream};
use shadowquic::config::{
    AuthUser, CongestionControl, DirectOutCfg, DnsCfg, JlsUpstream, ShadowQuicClientCfg,
    ShadowQuicServerCfg, SocksServerCfg, default_initial_mtu,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::{net::TcpListener, time::Duration};

use shadowquic::router::Router;
use std::collections::HashMap;

use shadowquic::{
    direct::outbound::DirectOut,
    shadowquic::{inbound::start_shadowquic_inbound, outbound::ShadowQuicClient},
    socks::inbound::start_socks_inbound,
};

use tracing::info;
use tracing::{Level, level_filters::LevelFilter, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::sync::Arc;
use tokio::sync::Mutex;

const CHUNK_LEN: usize = 1024;
const ROUND: usize = 100;
#[tokio::test]
async fn main() {
    let socks_server = "127.0.0.1:1092";
    let target_addr = "127.0.0.1";
    let target_port = 1445;
    let mut config = Config::default();
    config.set_skip_auth(false);
    test_shadowquic().await;
    tokio::spawn(tcp_peer(1445));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut s = Socks5Stream::connect(socks_server, target_addr.into(), target_port, config)
        .await
        .unwrap();

    let sendbuf: Vec<u8> = (0..(CHUNK_LEN * ROUND)).map(|_| rand::random()).collect();
    let mut recvbuf = vec![0u8; CHUNK_LEN * ROUND];
    // let mut s1:TcpStream = s.get_socket();
    let (mut r, mut w) = s.get_socket_mut().split();
    let fut_1 = async {
        let now = tokio::time::Instant::now();
        for ii in 0..ROUND {
            r.read_exact(&mut recvbuf[ii * CHUNK_LEN..(ii + 1) * CHUNK_LEN])
                .await
                .unwrap();
        }
        let after = tokio::time::Instant::now();
        let dura = after - now;
        info!("read finished at:{:?}", after);
        eprintln!(
            "average download speed:{} MB/s",
            (CHUNK_LEN * ROUND) as f64 / dura.as_secs_f64() / 1024.0 / 1024.0
        );
    };
    let fut_2 = async {
        let now = tokio::time::Instant::now();
        info!("start write at:{:?}", now);
        for ii in 0..ROUND {
            w.write_all(&sendbuf[ii * CHUNK_LEN..(ii + 1) * CHUNK_LEN])
                .await
                .unwrap();
        }
        w.flush().await.unwrap();
        let after = tokio::time::Instant::now();
        let dura = after - now;
        eprintln!(
            "average upload speed:{} MB/s",
            (CHUNK_LEN * ROUND) as f64 / dura.as_secs_f64() / 1024.0 / 1024.0
        );
    };

    tokio::join!(fut_1, fut_2);
    assert!(sendbuf == recvbuf);
}

async fn test_shadowquic() {
    let filter = tracing_subscriber::filter::Targets::new()
        // Enable the `INFO` level for anything in `my_crate`
        .with_target("tcp", Level::TRACE)
        .with_target("shadowquic", LevelFilter::TRACE);

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
        addr: "127.0.0.1:4445".to_string(),
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
            bind_addr: "127.0.0.1:1092".parse().unwrap(),
            users: vec![],
        },
    )
    .await
    .unwrap();

    let sq_server_cfg = ShadowQuicServerCfg {
        bind_addr: "127.0.0.1:4445".parse().unwrap(),
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
async fn tcp_peer(port: u16) {
    let lis = TcpListener::bind(("0.0.0.0", port)).await.unwrap();
    let (mut s, _addr) = lis.accept().await.unwrap();
    info!("accepted");
    let (mut r, mut w) = s.split();

    tokio::io::copy(&mut r, &mut w).await.unwrap();
}
