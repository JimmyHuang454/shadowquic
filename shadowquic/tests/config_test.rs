use shadowquic::config::{Config, OutboundCfg};
use std::fs;

#[test]
fn test_parse_client_yaml() {
    let content = fs::read_to_string("config_examples/client.yaml").unwrap();
    let config: Config = serde_yaml::from_str(&content).unwrap();
    assert_eq!(config.inbounds.len(), 1);
    assert_eq!(config.inbounds[0].tag, "socks-in");
    assert_eq!(config.outbounds.len(), 2);
    assert!(config.outbounds.contains_key("shadowquic-out"));
    assert!(config.outbounds.contains_key("direct-out"));
    assert_eq!(config.rules.len(), 3);
}

#[test]
fn test_parse_http_in_out_yaml() {
    let content = fs::read_to_string("config_examples/http_in_out.yaml").unwrap();
    let config: Config = serde_yaml::from_str(&content).unwrap();
    assert_eq!(config.inbounds.len(), 2);
    let mut tags: Vec<_> = config.inbounds.iter().map(|i| i.tag.as_str()).collect();
    tags.sort();
    assert_eq!(tags, vec!["http-in", "sq-in"]);
    assert_eq!(config.outbounds.len(), 3);
    assert!(config.outbounds.contains_key("sq-out"));
    assert!(config.outbounds.contains_key("direct-out"));
    assert_eq!(config.rules.len(), 2);
}

#[test]
fn test_dns_top_level_and_direct_tag() {
    let yaml = r#"
inbounds:
  socks-in:
    type: socks
    bind-addr: "127.0.0.1:1089"
outbounds:
  direct-out:
    type: direct
    dns-tag: google
dns:
  google:
    dns-strategy: prefer-ipv4
    dns-server: "udp://8.8.8.8:53"
final: direct-out
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.dns.len(), 1);
    assert_eq!(config.dns[0].tag, "google");
    let direct = config.outbounds.get("direct-out").unwrap();
    match direct {
        OutboundCfg::Direct(d) => {
            assert_eq!(d.dns_tag.as_deref(), Some("google"));
        }
        _ => panic!("direct-out outbound is not direct"),
    }
}
