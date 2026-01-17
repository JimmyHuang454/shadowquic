use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use foyer::{HybridCache, HybridCacheBuilder, BlockEngineConfig, FsDeviceBuilder, DeviceBuilder, RecoverMode};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]pub struct DnsCacheValue(pub Vec<IpAddr>);

pub type DnsFoyerCache = HybridCache<String, Vec<u8>>;

pub async fn create_dns_cache(
    memory_capacity: Option<usize>,
    disk_capacity: Option<usize>,
    disk_path: Option<String>,
) -> Option<DnsFoyerCache> {
    if memory_capacity.is_none() && disk_capacity.is_none() {
        return None;
    }

    let memory_cap = memory_capacity.unwrap_or(1024 * 1024);

    let builder = HybridCacheBuilder::new()
        .memory(memory_cap);

    let cache = if let (Some(disk_cap), Some(path)) = (disk_capacity, disk_path) {
        let device = match FsDeviceBuilder::new(path)
            .with_capacity(disk_cap)
            .build() {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!("Failed to build device: {}", e);
                    return None;
                }
            };
        
        builder
            .storage()
            .with_recover_mode(RecoverMode::Quiet)
            .with_engine_config(BlockEngineConfig::new(device))
            .build()
            .await
    } else {
        // If no disk cache configured, we must not call .storage().
        // However, builder.build() is not available on memory phase directly?
        // Let's try to verify if we can skip storage.
        // The error said `build` not found on `HybridCacheBuilderPhaseMemory`.
        // This implies we MUST configure storage or use a different way to finish.
        // Wait, the user said "Use Hybrid Cache ... can set memory size, don't use a separate Memory".
        // Maybe I should configure a dummy storage? Or maybe there's a way to build memory-only.
        // If Foyer 0.22 forces storage for HybridCache, then I might need to use `foyer::Cache` for memory-only?
        // But user explicitly said "Use Hybrid Cache".
        
        // Let's look at the docs or example again.
        // If I can't find a way to build memory-only HybridCache, I'll use a temp dir for now?
        // No, that's bad.
        
        // Maybe `builder.storage().build()` works if I don't provide engine config?
        // Previous error: `build` not found on storage phase too? No, I didn't check that properly.
        // I checked `storage().build()` and it failed because `build` wasn't found?
        // Wait, if `storage()` returns a builder that expects engine config...
        
        // Let's try `builder.storage().build().await` again, but first fix the DeviceBuilder import.
        // And if `build` is missing on storage phase without config, then I need config.
        
        // For memory only, if HybridCache requires storage, maybe I can use `foyer::Engine::NoOp`? 
        // Or `with_engine(NoOp)`?
        
        // If I cannot resolve this, I will assume for now that if only memory is requested,
        // I might need to create a temporary directory for disk cache, 
        // OR (better) I can just use `CacheBuilder` if I wasn't forced to use HybridCache.
        // But I AM forced.
        
        // Let's try to use `CacheBuilder` for memory-only case if `HybridCache` fails?
        // But the type is `HybridCache`. `Cache` is a different type.
        
        // What if I use `foyer::Cache` type alias? 
        // No, `DnsFoyerCache` is `HybridCache`.
        
        // Let's try to use a dummy device?
        // Or maybe `storage()` has a default?
        // The user example shows `.storage().with_engine_config(...)`.
        
        // Let's try to build with `storage().build()` again. 
        // If it fails, I'll try to find if there is a `None` engine.
        
        builder.storage().build().await
    };

    match cache {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::error!("Failed to build DNS cache: {}", e);
            None
        }
    }
}

impl DnsCacheExt for DnsFoyerCache {
    async fn get_ip(&self, key: &str) -> Option<DnsCacheValue> {
        match self.get(key).await {
            Ok(Some(entry)) => {
                match bincode::deserialize(entry.value()) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::error!("Failed to deserialize DNS cache value: {}", e);
                        None
                    }
                }
            }
            Ok(None) => None,
            Err(e) => {
                tracing::error!("Foyer cache get error: {}", e);
                None
            }
        }
    }

    fn insert_ip(&self, key: String, value: DnsCacheValue) {
        if let Ok(bytes) = bincode::serialize(&value) {
            self.insert(key, bytes);
        }
    }
}

pub trait DnsCacheExt {
    async fn get_ip(&self, key: &str) -> Option<DnsCacheValue>;
    fn insert_ip(&self, key: String, value: DnsCacheValue);
}
