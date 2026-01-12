use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use fast_socks5::client::{Config, Socks5Datagram, Socks5Stream};
use shadowquic::config::{AuthUser, SocksClientCfg, SocksServerCfg};
use shadowquic::router::Router;
use shadowquic::socks::outbound::SocksClient;
use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::net::TcpStream;
use tokio::time::Duration;

use shadowquic::{Manager, direct::outbound::DirectOut, socks::inbound::SocksServer};

use tracing::{Level, level_filters::LevelFilter, trace};
use tracing::{debug, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::test]
async fn test_tcp() {
    let socks_server = "127.0.0.1:1093";
    let target_addr = "127.0.0.1";
    let target_port = 1454;
    let mut config = Config::default();
    config.set_skip_auth(false);
    spawn_echo(target_port).await;
    spawn_socks().await;

    let fut = async {
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut s = Socks5Stream::connect(socks_server, target_addr.into(), target_port, config)
            .await
            .unwrap();

        let query = dns_request("www.baidu.com".into());
        let len_byte = (query.len() as u16).to_be_bytes();
        s.write_all(&len_byte).await.unwrap();
        s.write_all(&query).await.unwrap();

        let mut len_buffer = [0u8; 2];
        s.read_exact(&mut len_buffer).await.unwrap();
        let response_len = u16::from_be_bytes(len_buffer) as usize;

        let mut response = vec![0u8; response_len];
        s.read_exact(&mut response).await.unwrap();
        info!(
            "from tcp {target_addr}:{target_port}: {:?}",
            &response[0..response_len]
        );
        assert_eq!(response[0], 0x13);
        assert_eq!(response[1], 0x37);

        let backing_socket = TcpStream::connect(socks_server).await.unwrap();
        let client_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        let socks = Socks5Datagram::bind(backing_socket, client_bind_addr)
            .await
            .unwrap();

        let mut recv = [0u8; 200];
        socks
            .send_to(&query, (target_addr, target_port))
            .await
            .unwrap();
        let (len, _) = socks.recv_from(&mut recv).await.unwrap();
        info!("from udp {target_addr}:{target_port}: {:?}", &recv[0..len]);
        assert_eq!(recv[0], 0x13);
        assert_eq!(recv[1], 0x37);
    };

    tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .unwrap();
}

fn dns_request(domain: String) -> Vec<u8> {
    debug!("Requesting results...");

    let mut query: Vec<u8> = vec![
        0x13, 0x37, // txid
        0x01, 0x00, // flags
        0x00, 0x01, // questions
        0x00, 0x00, // answer RRs
        0x00, 0x00, // authority RRs
        0x00, 0x00, // additional RRs
    ];
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend(part.chars().map(|c| c as u8));
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    debug!("query: {:?}", query);

    query
    // assert_eq!(msg[0], 0x13);
    // assert_eq!(msg[1], 0x37);
}

use std::sync::Arc;
use tokio::sync::Mutex;

async fn spawn_socks() {
    let filter = tracing_subscriber::filter::Targets::new()
        // Enable the `INFO` level for anything in `my_crate`
        .with_target("socks_out", Level::TRACE)
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

    let socks_server = SocksServer::new(SocksServerCfg {
        bind_addr: "127.0.0.1:1093".parse().unwrap(),
        users: vec![],
    })
    .await
    .unwrap();
    let sq_client = SocksClient::new(SocksClientCfg {
        addr: "127.0.0.1:1070".into(),
        username: Some("test".into()),
        password: Some("test".into()),
        bind_interface: None,
    });

    let mut client_outbounds = HashMap::new();
    client_outbounds.insert(
        "sq".to_string(),
        Arc::new(Mutex::new(
            Box::new(sq_client) as Box<dyn shadowquic::Outbound>
        )),
    );
    let client_router = Router::new(vec![], client_outbounds, Some("sq".to_string())).unwrap();

    let client = Manager {
        inbounds: vec![("socks".to_string(), Box::new(socks_server))],
        router: Arc::new(client_router),
    };

    let sq_server = SocksServer::new(SocksServerCfg {
        bind_addr: "127.0.0.1:1070".parse().unwrap(),
        users: vec![AuthUser {
            username: "test".into(),
            password: "test".into(),
        }],
    })
    .await
    .unwrap();
    let direct_client = DirectOut::default();

    let mut server_outbounds = HashMap::new();
    server_outbounds.insert(
        "direct".to_string(),
        Arc::new(Mutex::new(
            Box::new(direct_client) as Box<dyn shadowquic::Outbound>
        )),
    );
    let server_router = Router::new(vec![], server_outbounds, Some("direct".to_string())).unwrap();

    let server = Manager {
        inbounds: vec![("sq".to_string(), Box::new(sq_server))],
        router: Arc::new(server_router),
    };

    tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::spawn(client.run());
    tokio::time::sleep(Duration::from_millis(100)).await;
}

async fn spawn_echo(port: u16) {
    let udp = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
            let _ = udp.send_to(&buf[..len], peer).await;
        }
    });

    let lis = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = lis.accept().await.unwrap();
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if s.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                let mut payload = vec![0u8; n];
                if s.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let _ = s.write_all(&len_buf).await;
                let _ = s.write_all(&payload).await;
                let _ = s.flush().await;
            });
        }
    });
}
