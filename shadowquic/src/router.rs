use crate::Outbound;
use crate::config::Rule;
use crate::msgs::socks5::{AddrOrDomain, SocksAddr};
use anyhow::{Context, Result};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use tracing::{debug, warn};

#[derive(Debug)]
pub struct OutboundStats {
    tag: String,
    current_connections: AtomicU64,
    total_connections: AtomicU64,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
}

impl OutboundStats {
    pub fn new(tag: String) -> Self {
        Self {
            tag,
            current_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
        }
    }

    pub fn on_request_start(&self) {
        self.current_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_request_finish(&self, upload: u64, download: u64) {
        self.current_connections.fetch_sub(1, Ordering::Relaxed);
        self.upload_bytes.fetch_add(upload, Ordering::Relaxed);
        self.download_bytes.fetch_add(download, Ordering::Relaxed);
    }

    pub fn on_request_error(&self) {
        self.current_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn current_connections(&self) -> u64 {
        self.current_connections.load(Ordering::Relaxed)
    }

    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    pub fn upload_bytes(&self) -> u64 {
        self.upload_bytes.load(Ordering::Relaxed)
    }

    pub fn download_bytes(&self) -> u64 {
        self.download_bytes.load(Ordering::Relaxed)
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }
}

#[derive(Clone)]
pub struct Router {
    rules: Vec<ParsedRule>,
    outbounds: HashMap<String, Arc<Mutex<Box<dyn Outbound>>>>,
    default_outbound: Arc<Mutex<Box<dyn Outbound>>>,
    default_stats: Option<Arc<OutboundStats>>,
    stats: Option<HashMap<String, Arc<OutboundStats>>>,
    mmdb: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

#[derive(Clone)]
struct ParsedRule {
    inbound: Option<Vec<String>>,
    domain_suffix: Option<Vec<String>>,
    ip_cidr: Option<Vec<IpNet>>,
    geoip: Option<Vec<String>>,
    private_ip: bool,
    outbound: Arc<Mutex<Box<dyn Outbound>>>,
    stats: Option<Arc<OutboundStats>>,
}

impl Router {
    pub fn new(
        config_rules: Vec<Rule>,
        outbounds: HashMap<String, Arc<Mutex<Box<dyn Outbound>>>>,
        default_outbound_tag: Option<String>,
        enable_stats: bool,
        mmdb_path: Option<String>,
    ) -> Result<Self> {
        let mmdb = if let Some(path) = mmdb_path {
            let reader = maxminddb::Reader::open_readfile(path).context("Failed to open mmdb")?;
            Some(Arc::new(reader))
        } else {
            None
        };

        if mmdb.is_none() {
            for rule in &config_rules {
                if rule.geoip.is_some() {
                    return Err(anyhow::anyhow!(
                        "GeoIP rule present but mmdb not configured"
                    ));
                }
            }
        }

        let mut stats: Option<HashMap<String, Arc<OutboundStats>>> = None;
        if enable_stats {
            let mut s = HashMap::new();
            for tag in outbounds.keys() {
                s.insert(tag.clone(), Arc::new(OutboundStats::new(tag.clone())));
            }
            stats = Some(s);
        }

        let (default_outbound, default_stats) = if let Some(tag) = &default_outbound_tag {
            let outbound = outbounds
                .get(tag)
                .cloned()
                .with_context(|| format!("Default outbound {} not found", tag))?;
            let s = stats.as_ref().and_then(|m| m.get(tag).cloned());
            (outbound, s)
        } else {
            if outbounds.is_empty() {
                return Err(anyhow::anyhow!("No outbounds configured"));
            }
            let (tag, outbound) = outbounds.iter().next().unwrap();
            let s = stats.as_ref().and_then(|m| m.get(tag).cloned());
            (outbound.clone(), s)
        };

        let mut parsed_rules = Vec::new();
        for rule in config_rules {
            let outbound = outbounds
                .get(&rule.outbound)
                .cloned()
                .with_context(|| format!("Outbound {} in rule not found", rule.outbound))?;

            let mut ip_cidrs = Vec::new();
            if let Some(ips) = rule.ip {
                for ip_str in ips {
                    match ip_str.parse::<IpNet>() {
                        Ok(net) => ip_cidrs.push(net),
                        Err(_) => {
                            // Try parsing as IpAddr and convert to /32 or /128
                            match ip_str.parse::<IpAddr>() {
                                Ok(addr) => ip_cidrs.push(IpNet::from(addr)),
                                Err(e) => warn!("Invalid IP/CIDR in rule: {} ({})", ip_str, e),
                            }
                        }
                    }
                }
            }
            let ip_cidr = if ip_cidrs.is_empty() {
                None
            } else {
                Some(ip_cidrs)
            };

            let rule_stats = stats.as_ref().and_then(|m| m.get(&rule.outbound).cloned());

            parsed_rules.push(ParsedRule {
                inbound: rule.inbound,
                domain_suffix: rule.domain,
                ip_cidr,
                geoip: rule.geoip,
                private_ip: rule.private_ip,
                outbound,
                stats: rule_stats,
            });
        }

        Ok(Self {
            rules: parsed_rules,
            outbounds,
            default_outbound,
            default_stats,
            stats,
            mmdb,
        })
    }

    fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        }
    }

    fn match_ip_and_geo(&self, rule: &ParsedRule, ip: IpAddr) -> bool {
        if let Some(cidrs) = &rule.ip_cidr {
            if cidrs.iter().any(|cidr| cidr.contains(&ip)) {
                return true;
            }
        }
        if rule.private_ip && Self::is_private_ip(ip) {
            return true;
        }
        if let Some(codes) = &rule.geoip
            && let Some(mmdb) = &self.mmdb
        {
            let iso_code = match mmdb.lookup::<maxminddb::geoip2::Country>(ip) {
                Ok(country) => country
                    .country
                    .and_then(|c| c.iso_code)
                    .map(|s| s.to_string().to_lowercase()),
                Err(_) => None,
            };
            if let Some(iso) = iso_code {
                if codes.iter().any(|code| code.to_lowercase() == iso) {
                    return true;
                }
            }
        }
        return false;
    }

    pub fn route(
        &self,
        inbound_tag: &str,
        req: &crate::ProxyRequest,
    ) -> (
        Arc<Mutex<Box<dyn Outbound>>>,
        Option<Arc<OutboundStats>>,
        Option<usize>,
    ) {
        let dst = match req {
            crate::ProxyRequest::Tcp(s) => &s.dst,
            crate::ProxyRequest::Udp(s) => &s.dst,
        };
        for (idx, rule) in self.rules.iter().enumerate() {
            if let Some(inbounds) = &rule.inbound {
                if !inbounds.iter().any(|t| t == inbound_tag) {
                    continue;
                }
            }

            match &dst.addr {
                AddrOrDomain::Domain(d) => {
                    let domain = String::from_utf8_lossy(&d.contents);
                    if let Some(suffixes) = &rule.domain_suffix {
                        if !suffixes.iter().any(|s| domain.ends_with(s)) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                AddrOrDomain::V4(x) => {
                    let ip = IpAddr::from(*x);
                    if !self.match_ip_and_geo(rule, ip) {
                        continue;
                    }
                }
                AddrOrDomain::V6(x) => {
                    let ip = IpAddr::from(*x);
                    if !self.match_ip_and_geo(rule, ip) {
                        continue;
                    }
                }
            }

            return (rule.outbound.clone(), rule.stats.clone(), Some(idx));
        }
        return (
            self.default_outbound.clone(),
            self.default_stats.clone(),
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_private_ip_detection_common_ranges() {
        let private_ips = [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fc00::1".parse().unwrap()),
            IpAddr::V6("fe80::1".parse().unwrap()),
        ];

        for ip in private_ips {
            assert!(Router::is_private_ip(ip), "expected {ip} to be private");
        }

        let public_ips = [
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
        ];

        for ip in public_ips {
            assert!(!Router::is_private_ip(ip), "expected {ip} to be public");
        }
    }
}
