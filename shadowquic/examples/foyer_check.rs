
use foyer::{HybridCache, HybridCacheBuilder, BlockEngineConfig, FsDeviceBuilder, DeviceBuilder};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("debug,foyer=trace")
        .init();

    let tmp_dir = std::env::temp_dir().join("shadowquic_foyer_check");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let path = tmp_dir.join("store").to_string_lossy().to_string();
    
    tracing::info!("Creating device at {}", path);
    
    let device = FsDeviceBuilder::new(&path)
        .with_capacity(1024 * 1024 * 10) // 10MB
        .build()
        .unwrap();
        
    tracing::info!("Device built");

    let cache: HybridCache<String, Vec<u8>> = HybridCacheBuilder::new()
        .memory(1024 * 100) // 100KB
        .storage()
        .with_engine_config(BlockEngineConfig::new(device))
        .build()
        .await
        .unwrap();
        
    tracing::info!("Cache built");
    
    for i in 0..10000 {
        let key = format!("key-{}", i);
        let val = vec![0u8; 100];
        cache.insert(key, val);
        if i % 1000 == 0 {
            tokio::task::yield_now().await;
        }
    }
    
    tracing::info!("Inserted 10000 items. Waiting...");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    
    match tokio::time::timeout(std::time::Duration::from_secs(10), cache.close()).await {
        Ok(_) => tracing::info!("Closed"),
        Err(e) => tracing::error!("Close timeout: {}", e),
    }
    
    // Check files
    let entries = std::fs::read_dir(&tmp_dir).unwrap();
    let mut count = 0;
    for e in entries {
        let e = e.unwrap();
        tracing::info!("Found file: {:?}", e.file_name());
        count += 1;
    }
    tracing::info!("Total files: {}", count);
}
