use shadowquic::config::Config;
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
    assert_eq!(config.inbounds[0].tag, "http-in");
    assert_eq!(config.inbounds[1].tag, "sq-in");
    assert_eq!(config.outbounds.len(), 2);
    assert!(config.outbounds.contains_key("sq-out"));
    assert!(config.outbounds.contains_key("direct-out"));
    assert_eq!(config.rules.len(), 2);
}
