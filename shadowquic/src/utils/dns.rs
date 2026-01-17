use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    Resolver,
};
use tokio::net::lookup_host;
use url::Url;

use crate::{
    config::{DirectOutCfg, DnsCfg, DnsOverHttpsCfg, DnsStrategy},
    error::SError,
    msgs::socks5::{AddrOrDomain, SocksAddr, VarVec},
    utils::dns_cache::{DnsFoyerCache, DnsCacheValue, create_dns_cache, DnsCacheExt},
};

#[derive(Default, Clone)]
pub struct DnsResolve;

#[derive(Clone, Debug, Default)]
pub struct DnsRuntimeConfig {
    pub cache_size: Option<usize>,
    pub positive_min_ttl: Option<std::time::Duration>,
    pub positive_max_ttl: Option<std::time::Duration>,
    pub negative_min_ttl: Option<std::time::Duration>,
    pub negative_max_ttl: Option<std::time::Duration>,
    pub udp_server: Option<SocketAddr>,
    pub foyer_cache: Option<DnsFoyerCache>,
}

static DNS_RUNTIME_CONFIG: std::sync::OnceLock<DnsRuntimeConfig> = std::sync::OnceLock::new();
static DEFAULT_RESOLVER: std::sync::OnceLock<Resolver<TokioConnectionProvider>> =
    std::sync::OnceLock::new();

pub async fn init_dns_from_direct_cfg(cfg: &DnsCfg) {
    let udp_server = cfg.dns_server.as_ref().and_then(|s| {
        // Expect format like udp://8.8.8.8:53
        if let Ok(url) = Url::parse(s) {
            if url.scheme() != "udp" {
                return None;
            }
            let host = url.host_str()?;
            let ip: IpAddr = host.parse().ok()?;
            let port = url.port().unwrap_or(53);
            Some(SocketAddr::new(ip, port))
        } else {
            None
        }
    });

    let foyer_cache = create_dns_cache(
        cfg.dns_memory_cache_capacity,
        cfg.dns_disk_cache_capacity,
        cfg.dns_disk_cache_path.clone(),
    ).await;

    let runtime_cfg = DnsRuntimeConfig {
        cache_size: cfg.dns_cache_size,
        positive_min_ttl: cfg.dns_positive_min_ttl.map(std::time::Duration::from_secs),
        positive_max_ttl: cfg.dns_positive_max_ttl.map(std::time::Duration::from_secs),
        negative_min_ttl: cfg.dns_negative_min_ttl.map(std::time::Duration::from_secs),
        negative_max_ttl: cfg.dns_negative_max_ttl.map(std::time::Duration::from_secs),
        udp_server,
        foyer_cache,
    };
    let _ = DNS_RUNTIME_CONFIG.set(runtime_cfg);
}

impl DnsResolve {
    pub async fn resolve(
        &self,
        socks: SocksAddr,
        cfg: &DnsCfg,
    ) -> Result<DnsResolveResult, SError> {
        resolve_socks_addr(&socks, cfg).await
    }

    pub async fn inv_resolve(&self, addr: &SocketAddr) -> SocksAddr {
        (*addr).into()
    }
}

pub struct DnsResolveResult {
    pub addr: SocketAddr,
    pub cached: bool,
}

pub async fn resolve_socks_addr(
    socks: &SocksAddr,
    cfg: &DnsCfg,
) -> Result<DnsResolveResult, SError> {
    let mut s = match socks.addr.clone() {
        AddrOrDomain::V4(x) => DnsResolveResult {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(x)), 0),
            cached: false,
        },
        AddrOrDomain::V6(x) => DnsResolveResult {
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(x)), 0),
            cached: false,
        },
        AddrOrDomain::Domain(var_vec) => {
            let host = String::from_utf8(var_vec.contents)
                .map_err(|_| SError::DomainResolveFailed(socks.to_string()))?;

            if let Some(runtime_cfg) = DNS_RUNTIME_CONFIG.get() {
                if let Some(cache) = &runtime_cfg.foyer_cache {
                    if let Some(val) = cache.get_ip(&host).await {
                        let addrs = val.0
                            .iter()
                            .map(|&ip| SocketAddr::new(ip, socks.port))
                            .collect::<Vec<_>>();
                        if let Some(addr) = apply_dns_strategy(addrs.into_iter(), &cfg.dns_strategy) {
                            return Ok(DnsResolveResult { addr, cached: true });
                        }
                    }
                }
            }

            let result_addr = match &cfg.dns_over_https {
                Some(doh_cfg) => match resolve_via_doh(&host, socks.port, &cfg.dns_strategy, doh_cfg).await {
                    Ok(addr) => addr,
                    Err(_) => resolve_via_default_resolver(&host, socks.port, &cfg.dns_strategy).await?,
                },
                None => resolve_via_default_resolver(&host, socks.port, &cfg.dns_strategy).await?,
            };

            if let Some(runtime_cfg) = DNS_RUNTIME_CONFIG.get() {
                if let Some(cache) = &runtime_cfg.foyer_cache {
                    cache.insert_ip(host, DnsCacheValue(vec![result_addr.ip()]));
                }
            }
            DnsResolveResult { addr: result_addr, cached: false }
        }
    };
    s.addr.set_port(socks.port);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ip_socks_addr_resolve_does_not_mark_cached() {
        let addr: SocketAddr = "33.22.22.1:80".parse().unwrap();
        let socks = SocksAddr::from(addr);
        let cfg = DnsCfg {
            tag: "test".to_string(),
            dns_strategy: DnsStrategy::PreferIpv4,
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

        let res = resolve_socks_addr(&socks, &cfg).await.unwrap();
        assert_eq!(res.addr, addr);
        assert!(!res.cached);
    }
}

fn make_resolver_opts() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    if let Some(cfg) = DNS_RUNTIME_CONFIG.get() {
        if let Some(cache_size) = cfg.cache_size {
            opts.cache_size = cache_size;
        }
        opts.positive_min_ttl = cfg.positive_min_ttl;
        opts.positive_max_ttl = cfg.positive_max_ttl;
        opts.negative_min_ttl = cfg.negative_min_ttl;
        opts.negative_max_ttl = cfg.negative_max_ttl;
    }
    opts
}

fn default_resolver() -> &'static Resolver<TokioConnectionProvider> {
    DEFAULT_RESOLVER.get_or_init(|| {
        let opts = make_resolver_opts();
        let resolver_cfg = if let Some(cfg) = DNS_RUNTIME_CONFIG.get() {
            if let Some(server) = cfg.udp_server {
                let ips = [server.ip()];
                let ns_group =
                    NameServerConfigGroup::from_ips_clear(&ips, server.port(), true);
                ResolverConfig::from_parts(None, vec![], ns_group)
            } else {
                ResolverConfig::default()
            }
        } else {
            ResolverConfig::default()
        };
        Resolver::builder_with_config(resolver_cfg, TokioConnectionProvider::default())
            .with_options(opts)
            .build()
    })
}

async fn resolve_via_default_resolver(
    name: &str,
    port: u16,
    strategy: &DnsStrategy,
) -> Result<SocketAddr, SError> {
    let resolver = default_resolver();
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    };
    let lookup = resolver
        .lookup_ip(fqdn)
        .await
        .map_err(|e| SError::SocksError(e.to_string()))?;
    let addrs = lookup
        .iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>();
    apply_dns_strategy(addrs.into_iter(), strategy)
        .ok_or_else(|| SError::DomainResolveFailed(name.to_string()))
}

pub fn apply_dns_strategy<It>(mut ip_list: It, strategy: &DnsStrategy) -> Option<SocketAddr>
where
    It: Iterator<Item = SocketAddr>,
{
    match strategy {
        DnsStrategy::Ipv4Only => ip_list.find(|addr| addr.is_ipv4()),
        DnsStrategy::Ipv6Only => ip_list.find(|addr| addr.is_ipv6()),
        DnsStrategy::PreferIpv4 => {
            let mut first = None;
            for ip in ip_list {
                if ip.is_ipv4() {
                    return Some(ip);
                }
                if first.is_none() {
                    first = Some(ip);
                }
            }
            first
        }
        DnsStrategy::PreferIpv6 => {
            let mut first = None;
            for ip in ip_list {
                if ip.is_ipv6() {
                    return Some(ip);
                }
                if first.is_none() {
                    first = Some(ip);
                }
            }
            first
        }
    }
}

fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut query: Vec<u8> = vec![
        0x13, 0x37,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    ];
    for part in name.split('.') {
        query.push(part.len() as u8);
        query.extend(part.as_bytes());
    }
    query.push(0);
    query.push((qtype >> 8) as u8);
    query.push((qtype & 0xff) as u8);
    query.push(0x00);
    query.push(0x01);
    query
}

fn skip_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    if offset >= buf.len() {
        return None;
    }
    loop {
        if offset >= buf.len() {
            return None;
        }
        let len = buf[offset];
        offset += 1;
        if len & 0xC0 == 0xC0 {
            if offset >= buf.len() {
                return None;
            }
            offset += 1;
            break;
        }
        if len == 0 {
            break;
        }
        let next = offset.checked_add(len as usize)?;
        if next > buf.len() {
            return None;
        }
        offset = next;
    }
    Some(offset)
}

fn parse_dns_response_ips(buf: &[u8], qtype: u16) -> Vec<IpAddr> {
    if buf.len() < 12 {
        return Vec::new();
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut offset = 12;

    for _ in 0..qdcount {
        if let Some(o) = skip_name(buf, offset) {
            offset = o;
        } else {
            return Vec::new();
        }
        if offset + 4 > buf.len() {
            return Vec::new();
        }
        offset += 4;
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        if let Some(o) = skip_name(buf, offset) {
            offset = o;
        } else {
            break;
        }
        if offset + 10 > buf.len() {
            break;
        }
        let typ = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > buf.len() {
            break;
        }
        if typ == qtype {
            if qtype == 1 && rdlen == 4 {
                let addr = IpAddr::from([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
                ips.push(addr);
            } else if qtype == 28 && rdlen == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[offset..offset + 16]);
                let addr = IpAddr::from(octets);
                ips.push(addr);
            }
        }
        offset += rdlen;
    }
    ips
}

async fn doh_query(
    cfg: &DnsOverHttpsCfg,
    name: &str,
    qtype: u16,
) -> Result<Vec<IpAddr>, SError> {
    let url = Url::parse(&cfg.url).map_err(|e| SError::SocksError(e.to_string()))?;

    let host = url
        .host_str()
        .ok_or_else(|| SError::SocksError("invalid doh url host".to_string()))?;
    let port = url.port().unwrap_or(443);

    let mut addrs = lookup_host((host, port)).await?;
    let mut ips = Vec::new();
    while let Some(addr) = addrs.next() {
        ips.push(addr.ip());
    }
    if ips.is_empty() {
        return Err(SError::DomainResolveFailed(name.to_string()));
    }

    let ns_group =
        NameServerConfigGroup::from_ips_https(&ips, port, host.to_string().into(), true);
    let resolver_cfg = ResolverConfig::from_parts(None, vec![], ns_group);
    let opts = make_resolver_opts();
    let resolver = Resolver::builder_with_config(resolver_cfg, TokioConnectionProvider::default())
        .with_options(opts)
        .build();

    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    };

    let lookup = resolver
        .lookup_ip(fqdn)
        .await
        .map_err(|e| SError::SocksError(e.to_string()))?;

    let res_ips: Vec<IpAddr> = lookup
        .iter()
        .filter(|ip| match qtype {
            1 => ip.is_ipv4(),
            28 => ip.is_ipv6(),
            _ => true,
        })
        .collect();
    Ok(res_ips)
}

async fn resolve_via_doh(
    name: &str,
    port: u16,
    strategy: &DnsStrategy,
    cfg: &DnsOverHttpsCfg,
) -> Result<SocketAddr, SError> {
    let ips = match strategy {
        DnsStrategy::Ipv4Only => doh_query(cfg, name, 1).await?,
        DnsStrategy::Ipv6Only => doh_query(cfg, name, 28).await?,
        DnsStrategy::PreferIpv4 => {
            let v4 = doh_query(cfg, name, 1).await?;
            if v4.is_empty() {
                doh_query(cfg, name, 28).await?
            } else {
                v4
            }
        }
        DnsStrategy::PreferIpv6 => {
            let v6 = doh_query(cfg, name, 28).await?;
            if v6.is_empty() {
                doh_query(cfg, name, 1).await?
            } else {
                v6
            }
        }
    };
    let ip = ips
        .into_iter()
        .next()
        .ok_or_else(|| SError::DomainResolveFailed(name.to_string()))?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod test {
    use super::*;

    fn make_addrs() -> Vec<SocketAddr> {
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
        ]
    }

    #[test]
    fn test_apply_dns_strategy_ipv4_only() {
        let addrs = make_addrs();
        let result = apply_dns_strategy(addrs.clone().into_iter(), &DnsStrategy::Ipv4Only);
        assert_eq!(result, Some(addrs[0]));
    }

    #[test]
    fn test_apply_dns_strategy_ipv6_only() {
        let addrs = make_addrs();
        let result = apply_dns_strategy(addrs.clone().into_iter(), &DnsStrategy::Ipv6Only);
        assert_eq!(result, Some(addrs[1]));
    }

    #[test]
    fn test_apply_dns_strategy_prefer_ipv4() {
        let addrs = make_addrs();
        let result = apply_dns_strategy(addrs.clone().into_iter(), &DnsStrategy::PreferIpv4);
        assert_eq!(result, Some(addrs[0]));
    }

    #[test]
    fn test_apply_dns_strategy_prefer_ipv6() {
        let addrs = make_addrs();
        let result = apply_dns_strategy(addrs.clone().into_iter(), &DnsStrategy::PreferIpv6);
        assert_eq!(result, Some(addrs[1]));
    }

    #[test]
    fn test_apply_dns_strategy_empty() {
        let addrs: Vec<SocketAddr> = vec![];
        let result = apply_dns_strategy(addrs.into_iter(), &DnsStrategy::PreferIpv4);
        assert_eq!(result, None);
    }
}
