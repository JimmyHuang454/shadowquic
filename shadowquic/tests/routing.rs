use shadowquic::config::{
    InboundCfg, InboundType, OutboundCfg, Rule, SocksClientCfg, SocksServerCfg,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use shadowquic::router::Router;
use tokio::sync::Mutex;

async fn start_mock_server(addr: &str) -> (String, Arc<Notify>) {
    let listener = TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap().to_string();
    let notify = Arc::new(Notify::new());
    let notify_clone = notify.clone();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                notify_clone.notify_one();
                // Perform a dummy SOCKS5 handshake so the client thinks it succeeded
                // 1. Client sends: [VERSION, NMETHODS, METHODS...]
                let mut buf = [0u8; 256];
                if stream.read(&mut buf).await.is_err() {
                    continue;
                }
                // 2. Server sends: [VERSION, METHOD] (0x05, 0x00 for NO AUTH)
                if stream.write_all(&[0x05, 0x00]).await.is_err() {
                    continue;
                }
                // 3. Client sends: [VERSION, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
                if stream.read(&mut buf).await.is_err() {
                    continue;
                }
                // 4. Server sends: [VERSION, REP, RSV, ATYP, BND.ADDR, BND.PORT] (0x05, 0x00, 0x00, 0x01, ...)
                let response = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0];
                let _ = stream.write_all(&response).await;
            }
        }
    });

    (local_addr, notify)
}

#[tokio::test]
async fn test_routing_rules() {
    // 1. Start two mock servers (representing outbounds)
    let (addr_a, notify_a) = start_mock_server("127.0.0.1:0").await;
    let (addr_b, notify_b) = start_mock_server("127.0.0.1:0").await;

    // 2. Configure Manager
    // Outbounds: "out_a" -> addr_a, "out_b" -> addr_b
    // Inbounds: "in_1" (default), "in_2" (tagged)
    // Rules:
    //   1. inbound: ["in_2"] -> out_b
    //   2. domain: ["google.com"] -> out_a
    //   3. ip: ["1.1.1.1/32"] -> out_a
    //   4. default -> out_b

    let mut outbounds = HashMap::new();
    outbounds.insert(
        "out_a".to_string(),
        OutboundCfg::Socks(SocksClientCfg {
            addr: addr_a.clone(),
            username: None,
            password: None,
            bind_interface: None,
        }),
    );
    outbounds.insert(
        "out_b".to_string(),
        OutboundCfg::Socks(SocksClientCfg {
            addr: addr_b.clone(),
            username: None,
            password: None,
            bind_interface: None,
        }),
    );

    let mut inbounds = Vec::new();
    // in_1
    inbounds.push(InboundCfg {
        tag: "in_1".to_string(),
        inner: InboundType::Socks(SocksServerCfg {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            users: vec![],
        }),
    });
    // in_2
    inbounds.push(InboundCfg {
        tag: "in_2".to_string(),
        inner: InboundType::Socks(SocksServerCfg {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            users: vec![],
        }),
    });

    let rules = vec![
        Rule {
            inbound: Some(vec!["in_2".to_string()]),
            domain: Some(vec!["google.com".to_string()]),
            ip: None,
            geoip: None,
            private_ip: false,
            outbound: "out_b".to_string(),
        },
        Rule {
            inbound: None,
            domain: Some(vec!["google.com".to_string()]),
            ip: None,
            geoip: None,
            private_ip: false,
            outbound: "out_a".to_string(),
        },
        Rule {
            inbound: None,
            domain: None,
            ip: Some(vec!["1.1.1.1/32".to_string()]),
            geoip: None,
            private_ip: false,
            outbound: "out_a".to_string(),
        },
    ];

    // NOTE: We need to use Config::build_manager to properly process Rules (parse CIDRs, etc.)
    // But Config::build_manager is not public or accessible easily for tests without constructing full Config.
    // Wait, Config is just a struct. Manager is built from it.
    // The `Manager::new` or similar logic is likely in `src/bin/main.rs` or `src/lib.rs`.
    // Let's check `src/lib.rs` for `Manager` creation or `Config` methods.

    // Assuming we can't easily access the internal parsing logic of Rule -> ParsedRule if it's private.
    // But `Router::new` takes `Vec<Rule>`. `Router::new` does the parsing!
    // So we can manually construct the Manager using `Router::new`.

    // We need to construct `Manager` manually.
    // Manager needs `inbounds: Vec<(String, Box<dyn Inbound>)>` and `router: Arc<Router>`.

    // First, let's create the Inbound instances.
    // We need to know their bound addresses to connect to them.
    // Since we bind to port 0, we need to get the assigned port.

    use shadowquic::socks::inbound::SocksServer;

    let server1 = SocksServer::new(SocksServerCfg {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        users: vec![],
    })
    .await
    .unwrap();
    let addr_in_1 = server1.local_addr().unwrap();

    let server2 = SocksServer::new(SocksServerCfg {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        users: vec![],
    })
    .await
    .unwrap();
    let addr_in_2 = server2.local_addr().unwrap();

    // Create Outbounds
    use shadowquic::socks::outbound::SocksClient;

    let mut outbounds_map: HashMap<String, Arc<Mutex<Box<dyn shadowquic::Outbound>>>> =
        HashMap::new();

    let client_a = SocksClient::new("out_a".to_string(), SocksClientCfg {
        addr: addr_a.clone(),
        username: None,
        password: None,
        bind_interface: None,
    });
    outbounds_map.insert(
        "out_a".to_string(),
        Arc::new(Mutex::new(Box::new(client_a))),
    );

    let client_b = SocksClient::new("out_b".to_string(), SocksClientCfg {
        addr: addr_b.clone(),
        username: None,
        password: None,
        bind_interface: None,
    });
    outbounds_map.insert(
        "out_b".to_string(),
        Arc::new(Mutex::new(Box::new(client_b))),
    );

    // Create Router

    let router = Router::new(rules, outbounds_map, Some("out_b".to_string()), true, None).unwrap();
    let router = Arc::new(router);

    let r1 = router.clone();
    server1.run("in_1".to_string(), r1);

    let r2 = router.clone();
    server2.run("in_2".to_string(), r2);

    // Helper to connect and request
    async fn request(proxy_addr: SocketAddr, target: &str, port: u16) {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        // SOCKS5 Handshake
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x00]);

        // Request
        // CMD=1 (CONNECT), ATYP=3 (DOMAIN) or 1 (IPv4)
        // Simple logic for domain vs ip
        let mut req = vec![0x05, 0x01, 0x00];
        if let Ok(ip) = target.parse::<std::net::Ipv4Addr>() {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        } else {
            req.push(0x03);
            req.push(target.len() as u8);
            req.extend_from_slice(target.as_bytes());
        }
        req.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&req).await.unwrap();

        // Read response (we don't care about content, just that it connected and router forwarded it)
        // The mock outbound server will accept and complete handshake.
        // We wait a bit to ensure the notification happens.
        let mut buf = [0u8; 10];
        let _ = stream.read(&mut buf).await;
    }

    let timeout = std::time::Duration::from_secs(10);

    // Case 1: in_1 -> google.com -> should match domain rule -> out_a
    tokio::time::timeout(timeout, async {
        request(addr_in_1, "google.com", 80).await;
        notify_a.notified().await;
    })
    .await
    .expect("case 1 timeout");
    println!("Case 1 passed: google.com -> out_a");

    // Case 2: in_1 -> 1.1.1.1 -> should match ip rule -> out_a
    tokio::time::timeout(timeout, async {
        request(addr_in_1, "1.1.1.1", 80).await;
        notify_a.notified().await;
    })
    .await
    .expect("case 2 timeout");
    println!("Case 2 passed: 1.1.1.1 -> out_a");

    // Case 3: in_1 -> example.com -> no match -> default -> out_b
    tokio::time::timeout(timeout, async {
        request(addr_in_1, "example.com", 80).await;
        notify_b.notified().await;
    })
    .await
    .expect("case 3 timeout");
    println!("Case 3 passed: example.com -> out_b (default)");

    // Case 4: in_2 -> google.com -> should match inbound rule (priority?) -> out_b
    // Config:
    //   1. inbound: ["in_2"] -> out_b
    //   2. domain: ["google.com"] -> out_a
    // The router iterates rules in order. First match wins.
    // So if "in_2" rule is first, it should go to out_b.
    tokio::time::timeout(timeout, async {
        request(addr_in_2, "google.com", 80).await;
        notify_b.notified().await;
    })
    .await
    .expect("case 4 timeout");
    println!("Case 4 passed: in_2 -> google.com -> out_b (inbound rule priority)");
}

#[tokio::test]
async fn test_geoip_validation() {
    let rules = vec![Rule {
        inbound: None,
        domain: None,
        ip: None,
        geoip: Some(vec!["cn".to_string()]),
        private_ip: false,
        outbound: "out_a".to_string(),
    }];
    let outbounds_map: HashMap<String, Arc<Mutex<Box<dyn shadowquic::Outbound>>>> = HashMap::new();
    let result = Router::new(rules, outbounds_map, Some("out_b".to_string()), true, None);
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "GeoIP rule present but mmdb not configured"
    );
}
