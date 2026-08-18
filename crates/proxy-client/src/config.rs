use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub server: SocketAddr,
    #[serde(default = "default_true")]
    pub quic_enabled: bool,
    #[serde(default = "default_true")]
    pub grpc_enabled: bool,
    #[serde(default)]
    pub quic_server: Option<SocketAddr>,
    #[serde(default)]
    pub grpc_server: Option<SocketAddr>,
    pub token: String,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    pub certificate: PathBuf,
    pub routes: Vec<IpNet>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval_ms: u64,
    #[serde(default)]
    pub tun: TunConfig,
}

#[derive(Debug, Clone, Deserialize)]
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
    #[serde(default = "default_true")]
    pub auto_route: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: default_tun_name(),
            address: default_tun_address(),
            netmask: default_tun_netmask(),
            mtu: default_mtu(),
            auto_route: true,
        }
    }
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Self =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        if !cfg.certificate.is_absolute() {
            cfg.certificate = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&cfg.certificate);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if !self.quic_enabled && !self.grpc_enabled {
            bail!("at least one of quic_enabled or grpc_enabled must be true");
        }
        if self.token.is_empty() {
            bail!("token must not be empty");
        }
        if self.token.len() > 255 {
            bail!("token must be at most 255 bytes");
        }
        if self.server_name.trim().is_empty() {
            bail!("server_name must not be empty");
        }
        if self.routes.is_empty() {
            bail!("routes must not be empty");
        }
        if self.routes.iter().any(|network| network.addr().is_ipv6()) {
            bail!("IPv6 routes are not supported until the TUN has an IPv6 address");
        }
        for server in self.enabled_servers() {
            if self
                .routes
                .iter()
                .any(|network| network.contains(&server.ip()))
            {
                bail!(
                    "proxy server {} is inside a proxy route; this would capture the tunnel itself",
                    server.ip()
                );
            }
        }
        if self.tun.mtu < 1280 {
            bail!("tun.mtu must be at least 1280");
        }
        if self.reconnect_interval_ms == 0 {
            bail!("reconnect_interval_ms must be greater than zero");
        }
        Ok(())
    }

    pub fn quic_server(&self) -> SocketAddr {
        self.quic_server.unwrap_or(self.server)
    }

    pub fn grpc_server(&self) -> SocketAddr {
        self.grpc_server.unwrap_or(self.server)
    }

    fn enabled_servers(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.quic_enabled
            .then(|| self.quic_server())
            .into_iter()
            .chain(self.grpc_enabled.then(|| self.grpc_server()))
    }
}

fn default_server_name() -> String {
    "vpnbridge.local".into()
}

fn default_connect_timeout() -> u64 {
    5_000
}

fn default_reconnect_interval() -> u64 {
    3_000
}

fn default_tun_name() -> String {
    "vpnquic0".into()
}

fn default_tun_address() -> Ipv4Addr {
    Ipv4Addr::new(10, 212, 0, 1)
}

fn default_tun_netmask() -> Ipv4Addr {
    Ipv4Addr::new(255, 255, 255, 0)
}

fn default_mtu() -> u16 {
    1_400
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_server_address_enables_both_transports() {
        let cfg: ClientConfig = toml::from_str(
            r#"
server = "192.0.2.1:4433"
token = "secret"
certificate = "cert.pem"
routes = ["10.0.0.0/8"]
"#,
        )
        .unwrap();
        assert!(cfg.quic_enabled);
        assert!(cfg.grpc_enabled);
        assert_eq!(cfg.quic_server(), cfg.server);
        assert_eq!(cfg.grpc_server(), cfg.server);
    }

    #[test]
    fn transport_addresses_override_the_legacy_server() {
        let cfg: ClientConfig = toml::from_str(
            r#"
server = "192.0.2.1:4433"
quic_server = "192.0.2.1:4443"
grpc_server = "192.0.2.1:4444"
token = "secret"
certificate = "cert.pem"
routes = ["10.0.0.0/8"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.quic_server(), "192.0.2.1:4443".parse().unwrap());
        assert_eq!(cfg.grpc_server(), "192.0.2.1:4444".parse().unwrap());
    }

    #[test]
    fn rejects_a_route_that_captures_the_server() {
        let cfg = ClientConfig {
            server: "10.1.2.3:4433".parse().unwrap(),
            quic_enabled: true,
            grpc_enabled: true,
            quic_server: None,
            grpc_server: None,
            token: "secret".into(),
            server_name: "vpnbridge.local".into(),
            certificate: "cert.pem".into(),
            routes: vec!["10.0.0.0/8".parse().unwrap()],
            connect_timeout_ms: 1_000,
            reconnect_interval_ms: 1_000,
            tun: TunConfig::default(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_disabling_all_transports() {
        let cfg = ClientConfig {
            server: "192.0.2.1:4433".parse().unwrap(),
            quic_enabled: false,
            grpc_enabled: false,
            quic_server: None,
            grpc_server: None,
            token: "secret".into(),
            server_name: "vpnbridge.local".into(),
            certificate: "cert.pem".into(),
            routes: vec!["10.0.0.0/8".parse().unwrap()],
            connect_timeout_ms: 1_000,
            reconnect_interval_ms: 1_000,
            tun: TunConfig::default(),
        };
        assert!(cfg.validate().is_err());
    }
}
