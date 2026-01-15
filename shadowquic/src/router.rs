use crate::config::Rule;
use crate::msgs::socks5::{AddrOrDomain, SocksAddr};
use crate::Outbound;
use anyhow::{Context, Result};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

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
    default_outbound_tag: String,
    stats: HashMap<String, Arc<OutboundStats>>,
}

#[derive(Clone)]
struct ParsedRule {
    inbound: Option<Vec<String>>,
    domain_suffix: Option<Vec<String>>,
    ip_cidr: Option<Vec<IpNet>>,
    outbound: Arc<Mutex<Box<dyn Outbound>>>,
    outbound_tag: String,
}

impl Router {
    pub fn new(
        config_rules: Vec<Rule>,
        outbounds: HashMap<String, Arc<Mutex<Box<dyn Outbound>>>>,
        default_outbound_tag: Option<String>,
        enable_stats: bool,
    ) -> Result<Self> {
        let (default_outbound_tag_value, default_outbound) =
            if let Some(tag) = &default_outbound_tag {
                let outbound = outbounds
                    .get(tag)
                    .cloned()
                    .with_context(|| format!("Default outbound {} not found", tag))?;
                (tag.clone(), outbound)
            } else {
                if outbounds.is_empty() {
                    return Err(anyhow::anyhow!("No outbounds configured"));
                }
                let (tag, outbound) = outbounds.iter().next().unwrap();
                (tag.clone(), outbound.clone())
            };

        let mut stats = HashMap::new();
        if enable_stats {
            for tag in outbounds.keys() {
                stats.insert(tag.clone(), Arc::new(OutboundStats::new(tag.clone())));
            }
        }

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

            parsed_rules.push(ParsedRule {
                inbound: rule.inbound,
                domain_suffix: rule.domain,
                ip_cidr,
                outbound,
                outbound_tag: rule.outbound,
            });
        }

        Ok(Self {
            rules: parsed_rules,
            outbounds,
            default_outbound,
            default_outbound_tag: default_outbound_tag_value,
            stats,
        })
    }

    pub fn route(
        &self,
        inbound_tag: &str,
        req: &crate::ProxyRequest,
    ) -> (Arc<Mutex<Box<dyn Outbound>>>, Option<Arc<OutboundStats>>) {
        let dst = match req {
            crate::ProxyRequest::Tcp(s) => &s.dst,
            crate::ProxyRequest::Udp(s) => &s.dst,
        };
        for rule in &self.rules {
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
                    }
                    if rule.ip_cidr.is_some() {
                        continue;
                    }
                }
                AddrOrDomain::V4(x) => {
                    if rule.domain_suffix.is_some() {
                        continue;
                    }
                    if let Some(cidrs) = &rule.ip_cidr {
                        let ip = IpAddr::from(*x);
                        if !cidrs.iter().any(|cidr| cidr.contains(&ip)) {
                            continue;
                        }
                    }
                }
                AddrOrDomain::V6(x) => {
                    if rule.domain_suffix.is_some() {
                        continue;
                    }
                    if let Some(cidrs) = &rule.ip_cidr {
                        let ip = IpAddr::from(*x);
                        if !cidrs.iter().any(|cidr| cidr.contains(&ip)) {
                            continue;
                        }
                    }
                }
            }

            let stats = self.stats.get(&rule.outbound_tag).cloned();
            return (rule.outbound.clone(), stats);
        }
        let stats = self.stats.get(&self.default_outbound_tag).cloned();
        (self.default_outbound.clone(), stats)
    }
}
