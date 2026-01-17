use std::collections::HashMap;
use std::sync::Arc;
use std::{time::Duration, vec};
use tokio::sync::Mutex;

use shadowquic::{
    config::{
        AuthUser, CongestionControl, JlsUpstream, ShadowQuicClientCfg, ShadowQuicServerCfg,
        SocksServerCfg, default_initial_mtu,
    },
    direct::outbound::DirectOut,
    router::Router,
    shadowquic::{inbound::start_shadowquic_inbound, outbound::ShadowQuicClient},
    socks::inbound::start_socks_inbound,
};
use tracing::{Level, level_filters::LevelFilter, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    test_shadowquic().await
}

async fn test_shadowquic() {
    let filter = tracing_subscriber::filter::Targets::new()
        // Enable the `INFO` level for anything in `my_crate`
        .with_target("shadowquic", Level::TRACE)
        .with_target("shadowquic::msgs::socks", LevelFilter::OFF);

    // Enable the `DEBUG` level for a specific module.

    // Build a new subscriber with the `fmt` layer using the `Targets`
    // filter we constructed above.
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    // env_logger::init();
    trace!("Running");

    let sq_client = ShadowQuicClient::new("sq".to_string(), ShadowQuicClientCfg {
        password: "123".into(),
        username: "123".into(),
        addr: "127.0.0.1:4444".to_string(),
        server_name: "localhost".into(),
        alpn: vec!["h3".into()],
        initial_mtu: 1200,
        congestion_control: CongestionControl::Bbr,
        zero_rtt: true,
        over_stream: false,
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
            bind_addr: "127.0.0.1:1089".parse().unwrap(),
            users: vec![],
        },
    )
    .await
    .unwrap();

    let sq_server_cfg = ShadowQuicServerCfg {
        bind_addr: "127.0.0.1:4444".parse().unwrap(),
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

    let dns_cfg = shadowquic::config::DnsCfg {
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
        DirectOut::new("direct".to_string(), shadowquic::config::DirectOutCfg::default(), dns_cfg)
            .await;

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

    tokio::time::sleep(Duration::from_millis(500)).await;
}
