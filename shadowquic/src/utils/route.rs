use std::process::Command;
use tracing::{info, warn};

pub struct RouteManager {
    interface: String,
    ipv4: bool,
    ipv6: bool,
}

impl RouteManager {
    pub fn new(interface: String, ipv4: bool, ipv6: bool) -> Self {
        let manager = Self {
            interface,
            ipv4,
            ipv6,
        };
        manager.add_routes();
        manager
    }

    fn add_routes(&self) {
        if self.ipv4 {
            self.add_route_v4("0.0.0.0/1");
            self.add_route_v4("128.0.0.0/1");
        }
        if self.ipv6 {
            self.add_route_v6("::/1");
            self.add_route_v6("8000::/1");
        }
    }

    fn remove_routes(&self) {
        if self.ipv4 {
            self.delete_route_v4("0.0.0.0/1");
            self.delete_route_v4("128.0.0.0/1");
        }
        if self.ipv6 {
            self.delete_route_v6("::/1");
            self.delete_route_v6("8000::/1");
        }
    }

    #[cfg(target_os = "macos")]
    fn add_route_v4(&self, cidr: &str) {
        let output = Command::new("route")
            .args(&["-n", "add", "-net", cidr, "-interface", &self.interface])
            .output();
        match output {
            Ok(o) if o.status.success() => info!("added route {} dev {}", cidr, self.interface),
            Ok(o) => warn!(
                "failed to add route {} dev {}: {}",
                cidr,
                self.interface,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to execute route command: {}", e),
        }
    }

    #[cfg(target_os = "macos")]
    fn delete_route_v4(&self, cidr: &str) {
        let output = Command::new("route")
            .args(&["-n", "delete", "-net", cidr, "-interface", &self.interface])
            .output();
        match output {
            Ok(o) if o.status.success() => info!("deleted route {} dev {}", cidr, self.interface),
            Ok(o) => warn!(
                "failed to delete route {} dev {}: {}",
                cidr,
                self.interface,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to execute route command: {}", e),
        }
    }

    #[cfg(target_os = "macos")]
    fn add_route_v6(&self, cidr: &str) {
        let output = Command::new("route")
            .args(&["-n", "add", "-inet6", cidr, "-interface", &self.interface])
            .output();
        match output {
            Ok(o) if o.status.success() => info!("added route {} dev {}", cidr, self.interface),
            Ok(o) => warn!(
                "failed to add route {} dev {}: {}",
                cidr,
                self.interface,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to execute route command: {}", e),
        }
    }

    #[cfg(target_os = "macos")]
    fn delete_route_v6(&self, cidr: &str) {
        let output = Command::new("route")
            .args(&[
                "-n",
                "delete",
                "-inet6",
                cidr,
                "-interface",
                &self.interface,
            ])
            .output();
        match output {
            Ok(o) if o.status.success() => info!("deleted route {} dev {}", cidr, self.interface),
            Ok(o) => warn!(
                "failed to delete route {} dev {}: {}",
                cidr,
                self.interface,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to execute route command: {}", e),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn add_route_v4(&self, cidr: &str) {
        let output = Command::new("ip")
            .args(&["route", "add", cidr, "dev", &self.interface])
            .output();
        match output {
            Ok(o) if o.status.success() => info!("added route {} dev {}", cidr, self.interface),
            Ok(o) => warn!(
                "failed to add route {} dev {}: {}",
                cidr,
                self.interface,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to execute ip command: {}", e),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn delete_route_v4(&self, cidr: &str) {
        let output = Command::new("ip")
            .args(&["route", "del", cidr, "dev", &self.interface])
            .output();
        match output {
            Ok(o) if o.status.success() => info!("deleted route {} dev {}", cidr, self.interface),
            Ok(o) => warn!(
                "failed to delete route {} dev {}: {}",
                cidr,
                self.interface,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to execute ip command: {}", e),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn add_route_v6(&self, cidr: &str) {
        let output = Command::new("ip")
            .args(&["-6", "route", "add", cidr, "dev", &self.interface])
            .output();
        match output {
            Ok(o) if o.status.success() => info!("added route {} dev {}", cidr, self.interface),
            Ok(o) => warn!(
                "failed to add route {} dev {}: {}",
                cidr,
                self.interface,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to execute ip command: {}", e),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn delete_route_v6(&self, cidr: &str) {
        let output = Command::new("ip")
            .args(&["-6", "route", "del", cidr, "dev", &self.interface])
            .output();
        match output {
            Ok(o) if o.status.success() => info!("deleted route {} dev {}", cidr, self.interface),
            Ok(o) => warn!(
                "failed to delete route {} dev {}: {}",
                cidr,
                self.interface,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to execute ip command: {}", e),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    fn add_route_v4(&self, _cidr: &str) {
        warn!("auto_route not supported on this platform");
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    fn delete_route_v4(&self, _cidr: &str) {
        warn!("auto_route not supported on this platform");
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    fn add_route_v6(&self, _cidr: &str) {
        warn!("auto_route not supported on this platform");
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    fn delete_route_v6(&self, _cidr: &str) {
        warn!("auto_route not supported on this platform");
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        info!("cleaning up routes for {}", self.interface);
        self.remove_routes();
    }
}
