use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub tun: TunConfig,
    /// Destination networks that must be handled by the VM.
    #[serde(default)]
    pub routes: Vec<IpNet>,
    /// Networks that must never be captured, even if covered by `routes`.
    #[serde(default)]
    pub exclude: Vec<IpNet>,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// `ip:port` of the VM agent, reachable over the host <-> VM network.
    pub address: SocketAddr,
    #[serde(default)]
    pub token: String,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    /// Delay before retrying a failed connection to the VM agent.
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval_ms: u64,
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_address")]
    pub address: Ipv4Addr,
    #[serde(default = "default_tun_netmask")]
    pub netmask: Ipv4Addr,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Install `ip route` entries for `routes` / `exclude` on startup.
    #[serde(default = "default_true")]
    pub auto_route: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// Local address the forwarder listens on, e.g. `127.0.0.1:15353`.
    pub listen: SocketAddr,
    /// VPN-side resolvers, queried through the tunnel.
    pub upstream: Vec<SocketAddr>,
    #[serde(default = "default_dns_timeout")]
    pub timeout_ms: u64,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            name: default_tun_name(),
            address: default_tun_address(),
            netmask: default_tun_netmask(),
            mtu: default_mtu(),
            auto_route: true,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_connect_timeout() -> u64 {
    5_000
}
fn default_reconnect_interval() -> u64 {
    10_000
}
fn default_tun_name() -> String {
    "vpnbr0".to_string()
}
fn default_tun_address() -> Ipv4Addr {
    Ipv4Addr::new(10, 211, 0, 1)
}
fn default_tun_netmask() -> Ipv4Addr {
    Ipv4Addr::new(255, 255, 255, 0)
}
fn default_mtu() -> u16 {
    1500
}
fn default_dns_timeout() -> u64 {
    5_000
}

impl HostConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: HostConfig =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.routes.is_empty() {
            bail!("`routes` is empty: there is nothing to forward to the VM");
        }
        if self.tun.mtu < 1280 {
            bail!("tun.mtu must be at least 1280 (ipstack minimum)");
        }
        if self.server.reconnect_interval_ms == 0 {
            bail!("server.reconnect_interval_ms must be greater than zero");
        }

        let server_ip = self.server.address.ip();
        if self.captures(server_ip) && !self.excludes(server_ip) {
            // Not fatal: main() pins a host route for the VM before the TUN
            // routes go in, but the operator should know it is happening.
            tracing::warn!(
                %server_ip,
                "VM agent address falls inside a routed network; a direct host route will be pinned for it"
            );
        }
        if self.tun.address.is_broadcast() || self.tun.address.is_unspecified() {
            bail!(
                "tun.address {} is not a usable interface address",
                self.tun.address
            );
        }
        Ok(())
    }

    /// True when `ip` is covered by one of the forwarded networks.
    pub fn captures(&self, ip: IpAddr) -> bool {
        self.routes.iter().any(|net| net.contains(&ip))
    }

    pub fn excludes(&self, ip: IpAddr) -> bool {
        self.exclude.iter().any(|net| net.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CONFIG: &str = r#"
routes = ["10.0.0.0/8"]

[server]
address = "127.0.0.1:17321"
"#;

    #[test]
    fn reconnect_interval_defaults_to_ten_seconds() {
        let cfg: HostConfig = toml::from_str(MINIMAL_CONFIG).unwrap();
        assert_eq!(cfg.server.reconnect_interval_ms, 10_000);
        cfg.validate().unwrap();
    }

    #[test]
    fn reconnect_interval_can_be_configured() {
        let text = format!("{MINIMAL_CONFIG}\nreconnect_interval_ms = 2500\n");
        let cfg: HostConfig = toml::from_str(&text).unwrap();
        assert_eq!(cfg.server.reconnect_interval_ms, 2_500);
        cfg.validate().unwrap();
    }

    #[test]
    fn reconnect_interval_must_not_be_zero() {
        let text = format!("{MINIMAL_CONFIG}\nreconnect_interval_ms = 0\n");
        let cfg: HostConfig = toml::from_str(&text).unwrap();
        assert!(cfg.validate().is_err());
    }
}
