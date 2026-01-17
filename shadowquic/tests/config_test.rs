use shadowquic::config::{Config, OutboundCfg};
use std::fs;

#[test]
fn test_dns_size_parsing() {
    let yaml = r#"
inbounds: []
outbounds: {}
dns:
  test1:
    strategy: prefer-ipv4
    dns-memory-cache-capacity: 1MB
    dns-disk-cache-capacity: 1KB
  test2:
    strategy: prefer-ipv4
    dns-memory-cache-capacity: 1048576
    dns-disk-cache-capacity: 1024
  test3:
    strategy: prefer-ipv4
    dns-memory-cache-capacity: 0
    dns-disk-cache-capacity: 0
  test4:
    strategy: prefer-ipv4
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.dns.len(), 4);
    
    // Sort by tag or find by tag
    let find_cfg = |tag: &str| config.dns.iter().find(|c| c.tag == tag).unwrap();

    let t1 = find_cfg("test1");
    // "1MB" now treated as 1MiB (binary units)
    assert_eq!(t1.dns_memory_cache_capacity, Some(1024 * 1024)); // 1MB = 1024^2
    assert_eq!(t1.dns_disk_cache_capacity, Some(1024)); // 1KB = 1024

    let t2 = find_cfg("test2");
    assert_eq!(t2.dns_memory_cache_capacity, Some(1048576));
    assert_eq!(t2.dns_disk_cache_capacity, Some(1024));

    let t3 = find_cfg("test3");
    assert_eq!(t3.dns_memory_cache_capacity, Some(0));
    assert_eq!(t3.dns_disk_cache_capacity, Some(0));

    let t4 = find_cfg("test4");
    assert_eq!(t4.dns_memory_cache_capacity, None);
    assert_eq!(t4.dns_disk_cache_capacity, None);
}

#[test]
fn test_dns_size_case_insensitivity_and_spacing() {
    let yaml = r#"
inbounds: []
outbounds: {}
dns:
  case_lower:
    strategy: prefer-ipv4
    dns-memory-cache-capacity: 1mb
  case_mixed:
    strategy: prefer-ipv4
    dns-memory-cache-capacity: 1 Mb
  case_space:
    strategy: prefer-ipv4
    dns-memory-cache-capacity: 1 mb
  case_kib:
    strategy: prefer-ipv4
    dns-memory-cache-capacity: 1 kib
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let find_cfg = |tag: &str| config.dns.iter().find(|c| c.tag == tag).unwrap();

    // 1mb -> 1MB -> 1MiB = 1048576
    assert_eq!(find_cfg("case_lower").dns_memory_cache_capacity, Some(1048576));
    
    // 1 Mb -> 1 MB -> 1MiB = 1048576
    assert_eq!(find_cfg("case_mixed").dns_memory_cache_capacity, Some(1048576));
    
    // 1 mb -> 1 MB -> 1MiB = 1048576
    assert_eq!(find_cfg("case_space").dns_memory_cache_capacity, Some(1048576));
    
    // 1 kib -> 1 KiB = 1024
    assert_eq!(find_cfg("case_kib").dns_memory_cache_capacity, Some(1024));
}
