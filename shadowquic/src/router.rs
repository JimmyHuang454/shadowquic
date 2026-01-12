use crate::Outbound;
use crate::config::Rule;
use crate::msgs::socks5::{AddrOrDomain, SocksAddr};
use anyhow::{Context, Result};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

#[derive(Clone)]
pub struct Router {
    rules: Vec<ParsedRule>,
    outbounds: HashMap<String, Arc<Mutex<Box<dyn Outbound>>>>,
    default_outbound: Arc<Mutex<Box<dyn Outbound>>>,
}

#[derive(Clone)]
struct ParsedRule {
    inbound: Option<Vec<String>>,
    domain_suffix: Option<Vec<String>>,
    ip_cidr: Option<Vec<IpNet>>,
    outbound: Arc<Mutex<Box<dyn Outbound>>>,
}

impl Router {
    pub fn new(
        config_rules: Vec<Rule>,
        outbounds: HashMap<String, Arc<Mutex<Box<dyn Outbound>>>>,
        default_outbound_tag: Option<String>,
    ) -> Result<Self> {
        let default_outbound = if let Some(tag) = &default_outbound_tag {
            outbounds
                .get(tag)
                .cloned()
                .with_context(|| format!("Default outbound {} not found", tag))?
        } else {
            // Pick any outbound or fail? Ideally we need a default.
            // If outbounds is not empty, pick one?
            // For now, let's require default_outbound_tag if provided, or pick first if not?
            // User config `select` is fallback.
            // If `select` is missing, maybe we just error if no rules match?
            // But for safety, let's just pick one or use a dummy error outbound.
            // Let's assume `select` is mandatory if rules don't cover everything.
            // If outbounds is empty, we can't do anything.
            if outbounds.is_empty() {
                return Err(anyhow::anyhow!("No outbounds configured"));
            }
            // Pick first one
            outbounds.values().next().unwrap().clone()
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

            parsed_rules.push(ParsedRule {
                inbound: rule.inbound,
                domain_suffix: rule.domain,
                ip_cidr,
                outbound,
            });
        }

        Ok(Self {
            rules: parsed_rules,
            outbounds,
            default_outbound,
        })
    }

    pub fn route(&self, inbound_tag: &str, dst: &SocksAddr) -> Arc<Mutex<Box<dyn Outbound>>> {
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

            return rule.outbound.clone();
        }

        self.default_outbound.clone()
    }
}
