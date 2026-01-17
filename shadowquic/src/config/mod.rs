use serde::{Deserialize, Serialize, de::Deserializer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::Level;

use crate::{
    Outbound,
    direct::outbound::DirectOut,
    error::SError,
    http::inbound::start_http_inbound,
    router::Router,
    shadowquic::{inbound::start_shadowquic_inbound, outbound::ShadowQuicClient},
    socks::{inbound::start_socks_inbound, outbound::SocksClient},
    tun::start_tun_inbound,
};

#[cfg(target_os = "android")]
use std::path::PathBuf;

/// Overall configuration of shadowquic.
///
/// Example:
/// ```yaml
/// inbound:
///   type: xxx
///   xxx: xxx
/// outbounds:
///   out1:
///     type: xxx
///     xxx: xxx
/// final: out1
/// log-level: trace # or debug, info, warn, error
/// ```
/// Supported inbound types are listed in [`InboundCfg`]
///
/// Supported outbound types are listed in [`OutboundCfg`]
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_inbounds")]
    pub inbounds: Vec<InboundCfg>,
    pub inbound: Option<InboundCfg>,
    pub outbounds: HashMap<String, OutboundCfg>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_dns")]
    pub dns: Vec<DnsCfg>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(rename = "final-outbound", alias = "final")]
    pub final_out: Option<String>,
    #[serde(rename = "select")]
    pub select_legacy: Option<String>,
    #[serde(default)]
    pub log_level: LogLevel,
    #[serde(default)]
    pub stream_buffer_size: Option<usize>,
    #[serde(default = "default_log_outbound_stats")]
    pub log_outbound_stats: bool,
    pub mmdb: Option<String>,
}
impl Config {
    pub async fn run(self) -> Result<(), SError> {
        if let Some(size) = self.stream_buffer_size {
            crate::utils::set_bidirectional_copy_buffer_size(size);
        }
        let dns_map: HashMap<String, DnsCfg> = self
            .dns
            .into_iter()
            .map(|cfg| (cfg.tag.clone(), cfg))
            .collect();
        let mut outbounds = HashMap::new();
        for (tag, cfg) in self.outbounds {
            let out = cfg.build_outbound(tag.clone(), &dns_map).await?;
            outbounds.insert(tag, Arc::new(Mutex::new(out)));
        }

        let default_out = self
            .final_out
            .or(self.select_legacy);

        let router = Router::new(
            self.rules,
            outbounds,
            default_out,
            self.log_outbound_stats,
            self.mmdb,
        )
        .map_err(|e| SError::SocksError(e.to_string()))?;

        let router = Arc::new(router);

        let mut has_inbound = false;
        if let Some(inbound) = self.inbound {
            has_inbound = true;
            inbound.start(router.clone()).await?;
        }
        for inbound in self.inbounds {
            has_inbound = true;
            inbound.start(router.clone()).await?;
        }

        if !has_inbound {
            return Err(SError::SocksError("No inbound configured".to_string()));
        }

        Ok(())
    }
}

fn default_log_outbound_stats() -> bool {
    true
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Rule {
    pub inbound: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
    pub ip: Option<Vec<String>>,
    pub geoip: Option<Vec<String>>,
    #[serde(default)]
    pub private_ip: bool,
    pub outbound: String,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InboundCfg {
    #[serde(default = "default_inbound_tag")]
    pub tag: String,
    #[serde(flatten)]
    pub inner: InboundType,
}

impl InboundCfg {
    async fn start(self, router: Arc<Router>) -> Result<(), SError> {
        self.inner.start(self.tag, router).await
    }
}

fn deserialize_inbounds<'de, D>(deserializer: D) -> Result<Vec<InboundCfg>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum InboundsHelper {
        List(Vec<InboundCfg>),
        Map(HashMap<String, InboundType>),
    }

    let helper = InboundsHelper::deserialize(deserializer)?;
    let inbounds = match helper {
        InboundsHelper::List(v) => v,
        InboundsHelper::Map(m) => m
            .into_iter()
            .map(|(tag, inner)| InboundCfg { tag, inner })
            .collect(),
    };
    Ok(inbounds)
}

fn default_inbound_tag() -> String {
    "default".to_string()
}

/// Inbound configuration
/// example:
/// ```yaml
/// type: socks # or shadowquic
/// bind-addr: "0.0.0.0:443" # "[::]:443"
/// xxx: xxx # other field depending on type
/// ```
/// See [`SocksServerCfg`] and [`ShadowQuicServerCfg`] for configuration field of corresponding type
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type")]
pub enum InboundType {
    Socks(SocksServerCfg),
    Http(HttpServerCfg),
    Tun(TunInboundCfg),
    #[serde(rename = "shadowquic")]
    ShadowQuic(ShadowQuicServerCfg),
}
impl InboundType {
    async fn start(self, tag: String, router: Arc<Router>) -> Result<(), SError> {
        match self {
            InboundType::Socks(cfg) => start_socks_inbound(tag, router, cfg).await,
            InboundType::Http(cfg) => start_http_inbound(tag, router, cfg).await,
            InboundType::Tun(cfg) => start_tun_inbound(tag, router, cfg),
            InboundType::ShadowQuic(cfg) => start_shadowquic_inbound(tag, router, cfg).await,
        }
    }
}

/// Outbound configuration
/// example:
/// ```yaml
/// type: socks # or shadowquic or direct
/// addr: "127.0.0.1:443" # "[::1]:443"
/// xxx: xxx # other field depending on type
/// ```
/// See [`SocksClientCfg`] and [`ShadowQuicClientCfg`] for configuration field of corresponding type
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type")]
pub enum OutboundCfg {
    Socks(SocksClientCfg),
    #[serde(rename = "shadowquic")]
    ShadowQuic(ShadowQuicClientCfg),
    Direct(DirectOutCfg),
}

impl OutboundCfg {
    async fn build_outbound(
        self,
        tag: String,
        dns_map: &HashMap<String, DnsCfg>,
    ) -> Result<Box<dyn Outbound>, SError> {
        let r: Box<dyn Outbound> = match self {
            OutboundCfg::Socks(cfg) => Box::new(SocksClient::new(tag, cfg)),
            OutboundCfg::ShadowQuic(cfg) => Box::new(ShadowQuicClient::new(tag, cfg)),
            OutboundCfg::Direct(cfg) => {
                let dns_cfg = if let Some(tag) = &cfg.dns_tag {
                     dns_map.get(tag).cloned().unwrap_or(
                        DnsCfg {
                            tag: "default".to_string(),
                            dns_strategy: DnsStrategy::default(),
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
                        }
                     )
                } else {
                     dns_map.get("default").cloned().unwrap_or(
                         DnsCfg {
                            tag: "default".to_string(),
                            dns_strategy: DnsStrategy::default(),
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
                        }
                     )
                };
                Box::new(DirectOut::new(tag, cfg, dns_cfg).await)
            }
        };
        Ok(r)
    }
}

/// Socks inbound configuration
///
/// Example:
/// ```yaml
/// bind-addr: "0.0.0.0:1089" # or "[::]:1089" for dualstack
/// users:
///  - username: "username"
///    password: "password"
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct SocksServerCfg {
    /// Server binding address. e.g. `0.0.0.0:1089`, `[::1]:1089`
    pub bind_addr: SocketAddr,
    /// Socks5 username, optional
    /// Left empty to disable authentication
    #[serde(default = "Vec::new")]
    pub users: Vec<AuthUser>,
}

/// Http inbound configuration
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct HttpServerCfg {
    /// Server binding address.
    pub bind_addr: SocketAddr,
    /// Http username, optional
    /// Left empty to disable authentication
    #[serde(default = "Vec::new")]
    pub users: Vec<AuthUser>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct TunInboundCfg {
    pub name: Option<String>,
    pub ipv4_cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
    pub mtu: Option<u16>,
    pub flow_timeout_secs: Option<u64>,
    pub auto_route: Option<bool>,
}

/// user authentication
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct AuthUser {
    pub username: String,
    pub password: String,
}

/// Socks outbound configuration
/// Example:
/// ```yaml
/// addr: "12.34.56.7:1089" # or "[12:ff::ff]:1089" for dualstack
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct SocksClientCfg {
    pub addr: String,
    /// SOCKS5 username, optional
    pub username: Option<String>,
    /// SOCKS5 password, optional
    pub password: Option<String>,
    pub bind_interface: Option<String>,
}

/// Shadowquic outbound configuration
///   
/// example:
/// ```yaml
/// addr: "12.34.56.7:1089" # or "[12:ff::ff]:1089" for dualstack
/// password: "12345678"
/// username: "87654321"
/// server-name: "echo.free.beeceptor.com" # must be the same as jls_upstream in server
/// alpn: ["h3"]
/// initial-mtu: 1400
/// congestion-control: bbr
/// zero-rtt: true
/// over-stream: false  # true for udp over stream, false for udp over datagram
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", default)]
pub struct ShadowQuicClientCfg {
    /// username, must be the same as the server
    pub username: String,
    /// password, must be the same as the server
    pub password: String,
    /// Shadowquic server address. example: `127.0.0.0.1:443`, `www.server.com:443`, `[ff::f1]:4443`
    pub addr: String,
    /// Server name, must be the same as the server jls_upstream
    /// domain name
    pub server_name: String,
    /// Alpn of tls, default is \["h3"\], must have common element with server
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Initial mtu, must be larger than min mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1300
    #[serde(default = "default_initial_mtu")]
    pub initial_mtu: u16,
    /// Congestion control, default to "bbr", supported: "bbr", "new-reno", "cubic"
    #[serde(default = "default_congestion_control")]
    pub congestion_control: CongestionControl,
    /// Set to true to enable zero rtt, default to true
    #[serde(default = "default_zero_rtt")]
    pub zero_rtt: bool,
    /// Transfer udp over stream or over datagram.
    /// If true, use quic stream to send UDP, otherwise use quic datagram
    /// extension, similar to native UDP in TUIC
    #[serde(default = "default_over_stream")]
    pub over_stream: bool,
    #[serde(default = "default_min_mtu")]
    pub min_mtu: u16,
    /// Idle timeout in milliseconds
    /// The connection will be closed if no packet is received within this time.
    /// Default is 30_000 (30s).
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u32,
    /// Keep alive interval in milliseconds
    /// 0 means disable keep alive, should be smaller than 30_000(idle time).
    /// Disabled by default.
    #[serde(default = "default_keep_alive_interval")]
    pub keep_alive_interval: u32,

    /// Port hopping configuration
    /// Randomly select a port from the list or range to connect to.
    /// Range format: "start-end" e.g. "1000-2000"
    pub port_hopping: Option<PortHopping>,

    /// Android Only. the unix socket path for protecting android socket
    #[cfg(target_os = "android")]
    pub protect_path: Option<PathBuf>,
    pub bind_interface: Option<String>,
}

impl Default for ShadowQuicClientCfg {
    fn default() -> Self {
        Self {
            password: Default::default(),
            username: Default::default(),
            addr: Default::default(),
            server_name: Default::default(),
            alpn: Default::default(),
            initial_mtu: default_initial_mtu(),
            congestion_control: Default::default(),
            zero_rtt: Default::default(),
            over_stream: Default::default(),
            min_mtu: default_min_mtu(),
            idle_timeout: default_idle_timeout(),
            keep_alive_interval: default_keep_alive_interval(),
            port_hopping: None,
            #[cfg(target_os = "android")]
            protect_path: Default::default(),
            bind_interface: None,
        }
    }
}

pub fn default_initial_mtu() -> u16 {
    1300
}
pub fn default_min_mtu() -> u16 {
    1290
}
pub fn default_zero_rtt() -> bool {
    true
}
pub fn default_congestion_control() -> CongestionControl {
    CongestionControl::Bbr
}
pub fn default_over_stream() -> bool {
    false
}
pub fn default_alpn() -> Vec<String> {
    vec!["h3".into()]
}
pub fn default_keep_alive_interval() -> u32 {
    0
}
pub fn default_rate_limit() -> u64 {
    u64::MAX
}
pub fn default_idle_timeout() -> u32 {
    30_000
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum CongestionControl {
    #[default]
    Bbr,
    Cubic,
    NewReno,
}
/// Configuration of direct outbound
/// Example:
/// ```yaml
/// dns-strategy: prefer-ipv4 # or prefer-ipv6, ipv4-only, ipv6-only
/// ```
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct DirectOutCfg {
    pub dns_tag: Option<String>,
}
/// DNS resolution strategy
/// Default is `prefer-ipv4``
/// - `prefer-ipv4`: try to use ipv4 first, if no ipv4 address, use ipv6
/// - `prefer-ipv6`: try to use ipv6 first, if no ipv6 address, use ipv4
/// - `ipv4-only`: only use ipv4 address
/// - `ipv6-only`: only use ipv6 address
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DnsStrategy {
    #[default]
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct DnsOverHttpsCfg {
    pub url: String,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct DnsCfg {
    #[serde(default = "default_dns_tag")]
    pub tag: String,
    #[serde(default, rename = "strategy", alias = "dns-strategy")]
    pub dns_strategy: DnsStrategy,
    pub dns_over_https: Option<DnsOverHttpsCfg>,
    #[serde(rename = "server", alias = "dns-server")]
    pub dns_server: Option<String>,
    #[serde(default, deserialize_with = "deserialize_byte_size")]
    pub dns_cache_size: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_byte_size")]
    pub dns_memory_cache_capacity: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_byte_size")]
    pub dns_disk_cache_capacity: Option<usize>,
    pub dns_disk_cache_path: Option<String>,
    pub dns_positive_min_ttl: Option<u64>,
    pub dns_positive_max_ttl: Option<u64>,
    pub dns_negative_min_ttl: Option<u64>,
    pub dns_negative_max_ttl: Option<u64>,
}

fn default_dns_tag() -> String {
    "default".to_string()
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct DnsCfgInner {
    #[serde(default, rename = "strategy", alias = "dns-strategy")]
    pub dns_strategy: DnsStrategy,
    pub dns_over_https: Option<DnsOverHttpsCfg>,
    #[serde(rename = "server", alias = "dns-server")]
    pub dns_server: Option<String>,
    #[serde(default, deserialize_with = "deserialize_byte_size")]
    pub dns_cache_size: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_byte_size")]
    pub dns_memory_cache_capacity: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_byte_size")]
    pub dns_disk_cache_capacity: Option<usize>,
    pub dns_disk_cache_path: Option<String>,
    pub dns_positive_min_ttl: Option<u64>,
    pub dns_positive_max_ttl: Option<u64>,
    pub dns_negative_min_ttl: Option<u64>,
    pub dns_negative_max_ttl: Option<u64>,
}

fn deserialize_byte_size<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SizeOrStr {
        Size(usize),
        Str(String),
    }

    match Option::<SizeOrStr>::deserialize(deserializer)? {
        Some(SizeOrStr::Size(s)) => Ok(Some(s)),
        Some(SizeOrStr::Str(s)) => {
            // Treat KB, MB, GB as KiB, MiB, GiB (binary units) to match common expectations in computing
            let s_upper = s.to_uppercase();
            let s_corrected = if !s_upper.contains("I") {
                s_upper
                    .replace("KB", "KIB")
                    .replace("MB", "MIB")
                    .replace("GB", "GIB")
                    .replace("TB", "TIB")
            } else {
                s
            };
            let b = s_corrected.parse::<bytesize::ByteSize>().map_err(serde::de::Error::custom)?;
            Ok(Some(b.as_u64() as usize))
        }
        None => Ok(None),
    }
}

fn deserialize_dns<'de, D>(deserializer: D) -> Result<Vec<DnsCfg>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DnsHelper {
        List(Vec<DnsCfg>),
        Map(HashMap<String, DnsCfgInner>),
    }

    let helper = DnsHelper::deserialize(deserializer)?;
    let dns = match helper {
        DnsHelper::List(v) => v,
        DnsHelper::Map(m) => m
            .into_iter()
            .map(|(tag, inner)| DnsCfg {
                tag,
                dns_strategy: inner.dns_strategy,
                dns_over_https: inner.dns_over_https,
                dns_server: inner.dns_server,
                dns_cache_size: inner.dns_cache_size,
                dns_memory_cache_capacity: inner.dns_memory_cache_capacity,
                dns_disk_cache_capacity: inner.dns_disk_cache_capacity,
                dns_disk_cache_path: inner.dns_disk_cache_path,
                dns_positive_min_ttl: inner.dns_positive_min_ttl,
                dns_positive_max_ttl: inner.dns_positive_max_ttl,
                dns_negative_min_ttl: inner.dns_negative_min_ttl,
                dns_negative_max_ttl: inner.dns_negative_max_ttl,
            })
            .collect(),
    };
    Ok(dns)
}



#[derive(Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum PortHopping {
    Range(String),
    List(Vec<u16>),
}

impl PortHopping {
    pub fn get_ports(&self) -> Vec<u16> {
        match self {
            PortHopping::List(v) => v.clone(),
            PortHopping::Range(s) => {
                let parts: Vec<&str> = s.split('-').collect();
                if parts.len() != 2 {
                    return vec![];
                }
                let start = parts[0].parse::<u16>().unwrap_or(0);
                let end = parts[1].parse::<u16>().unwrap_or(0);
                (start..=end).collect()
            }
        }
    }
}

/// Configuration of shadowquic inbound
///
/// Example:
/// ```yaml
/// bind-addr: "0.0.0.0:1443"
/// users:
///   - username: "zhangsan"
///     password: "12345678"
/// jls-upstream:
///   addr: "echo.free.beeceptor.com:443" # domain/ip + port, domain must be the same as client.
///   rate-limit: 1000000 # Limiting forwarding rate in unit of bps. optional, default is disabled
/// server-name: "echo.free.beeceptor.com" # must be the same as client
/// alpn: ["h3"]
/// congestion-control: bbr
/// zero-rtt: true
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ShadowQuicServerCfg {
    /// Binding address. e.g. `0.0.0.0:443`, `[::1]:443`
    pub bind_addr: SocketAddr,
    /// Users for client authentication
    pub users: Vec<AuthUser>,
    /// Server name used to check client. Must be the same as client
    /// If empty, server name will be parsed from jls_upstream
    /// If not available, server name check will be skipped
    pub server_name: Option<String>,
    /// Jls upstream, camouflage server, must be address with port. e.g.: `codepn.io:443`,`google.com:443`,`127.0.0.1:443`
    pub jls_upstream: JlsUpstream,
    /// Alpn of tls. Default is `["h3"]`, must have common element with client
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// 0-RTT handshake.
    /// Set to true to enable zero rtt.
    /// Enabled by default
    #[serde(default = "default_zero_rtt")]
    pub zero_rtt: bool,
    /// Congestion control, default to "bbr", supported: "bbr", "new-reno", "cubic"
    #[serde(default = "default_congestion_control")]
    pub congestion_control: CongestionControl,
    /// Initial mtu, must be larger than min mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1300
    #[serde(default = "default_initial_mtu")]
    pub initial_mtu: u16,
    /// Minimum mtu, must be smaller than initial mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1290
    #[serde(default = "default_min_mtu")]
    pub min_mtu: u16,
    /// Idle timeout in milliseconds
    /// The connection will be closed if no packet is received within this time.
    /// Default is 30_000 (30s).
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u32,
    /// Port hopping configuration
    /// Listen on multiple ports.
    /// Range format: "start-end" e.g. "1000-2000"
    pub port_hopping: Option<PortHopping>,
}

/// Jls upstream configuration
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct JlsUpstream {
    /// Jls upstream address, e.g. `codepn.io:443`, `google.com:443`, `127.0.0.1:443`
    pub addr: String,
    /// Maximum rate for JLS forwarding in unit of bps, default is disabled.
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u64,
}

impl Default for JlsUpstream {
    fn default() -> Self {
        Self {
            addr: String::new(),
            rate_limit: u64::MAX,
        }
    }
}
impl Default for ShadowQuicServerCfg {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:443".parse().unwrap(),
            users: Default::default(),
            jls_upstream: Default::default(),
            alpn: Default::default(),
            zero_rtt: Default::default(),
            congestion_control: Default::default(),
            initial_mtu: default_initial_mtu(),
            min_mtu: default_min_mtu(),
            idle_timeout: default_idle_timeout(),
            server_name: None,
            port_hopping: None,
        }
    }
}
/// Log level of shadowquic
/// Default level is info.
#[derive(Deserialize, Clone, Default, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}
impl LogLevel {
    pub fn as_tracing_level(&self) -> Level {
        match self {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Config, PortHopping};
    #[test]
    fn test() {
        let cfgstr = r###"
inbound:
    type: socks
    bind-addr: 127.0.0.1:1089
outbounds:
    direct:
        type: direct
        dns-strategy: prefer-ipv4
select: direct
"###;
        let _cfg: Config = serde_yaml::from_str(cfgstr).expect("yaml parsed failed");
    }

    #[test]
    fn test_port_hopping() {
        let ph = PortHopping::Range("1000-1002".to_string());
        assert_eq!(ph.get_ports(), vec![1000, 1001, 1002]);

        let ph = PortHopping::List(vec![80, 443]);
        assert_eq!(ph.get_ports(), vec![80, 443]);
    }

    #[test]
    fn test_port_hopping_yaml() {
        let cfgstr = r###"
inbound:
    type: shadowquic
    bind-addr: 127.0.0.1:443
    port-hopping: "1000-1002"
    users: []
    jls-upstream:
        addr: "google.com:443"
outbounds:
    sq:
        type: shadowquic
        addr: "127.0.0.1:443"
        port-hopping: [1000, 1001]
        username: "u"
        password: "p"
        server-name: "s"
select: sq
"###;
        let cfg: Config = serde_yaml::from_str(cfgstr).expect("yaml parsed failed");

        if let super::InboundType::ShadowQuic(sq) = cfg.inbound.unwrap().inner {
            assert!(sq.port_hopping.is_some());
            match sq.port_hopping.unwrap() {
                PortHopping::Range(s) => assert_eq!(s, "1000-1002"),
                _ => panic!("Expected Range"),
            }
        } else {
            panic!("Expected ShadowQuic inbound");
        }

        if let super::OutboundCfg::ShadowQuic(sq) = cfg.outbounds.get("sq").unwrap() {
            assert!(sq.port_hopping.is_some());
            match sq.port_hopping.as_ref().unwrap() {
                PortHopping::List(l) => assert_eq!(l, &vec![1000, 1001]),
                _ => panic!("Expected List"),
            }
        } else {
            panic!("Expected ShadowQuic outbound");
        }
    }
}
