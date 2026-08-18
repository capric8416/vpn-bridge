use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    #[serde(default = "default_true")]
    pub quic_enabled: bool,
    #[serde(default = "default_true")]
    pub grpc_enabled: bool,
    #[serde(default)]
    pub quic_listen: Option<SocketAddr>,
    #[serde(default)]
    pub grpc_listen: Option<SocketAddr>,
    pub token: String,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    #[serde(default = "default_certificate")]
    pub certificate: PathBuf,
    #[serde(default = "default_private_key")]
    pub private_key: PathBuf,
    #[serde(default)]
    pub allow: Vec<IpNet>,
    #[serde(default)]
    pub deny: Vec<IpNet>,
    #[serde(default)]
    pub bind_ip: Option<IpAddr>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_dns_timeout")]
    pub dns_timeout_ms: u64,
    #[serde(default = "default_tcp_idle_timeout")]
    pub tcp_idle_timeout_secs: u64,
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout_secs: u64,
    #[serde(default = "default_max_streams")]
    pub max_concurrent_streams: u32,
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Self =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        cfg.certificate = resolve(base, cfg.certificate);
        cfg.private_key = resolve(base, cfg.private_key);
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
        if self.max_concurrent_streams == 0 {
            bail!("max_concurrent_streams must be greater than zero");
        }
        if self.connect_timeout_ms == 0 {
            bail!("connect_timeout_ms must be greater than zero");
        }
        if self.dns_timeout_ms == 0 {
            bail!("dns_timeout_ms must be greater than zero");
        }
        if self.tcp_idle_timeout_secs == 0 {
            bail!("tcp_idle_timeout_secs must be greater than zero");
        }
        if self.udp_timeout_secs == 0 {
            bail!("udp_timeout_secs must be greater than zero");
        }
        Ok(())
    }

    pub fn quic_listen(&self) -> SocketAddr {
        self.quic_listen.unwrap_or(self.listen)
    }

    pub fn grpc_listen(&self) -> SocketAddr {
        self.grpc_listen.unwrap_or(self.listen)
    }

    pub fn permits(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|network| network.contains(&ip)) {
            return false;
        }
        self.allow.is_empty() || self.allow.iter().any(|network| network.contains(&ip))
    }
}

fn resolve(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn default_server_name() -> String {
    "vpnbridge.local".into()
}

fn default_certificate() -> PathBuf {
    "proxy-server-cert.pem".into()
}

fn default_private_key() -> PathBuf {
    "proxy-server-key.pem".into()
}

fn default_connect_timeout() -> u64 {
    8_000
}

fn default_dns_timeout() -> u64 {
    5_000
}

fn default_tcp_idle_timeout() -> u64 {
    300
}

fn default_udp_timeout() -> u64 {
    60
}

fn default_max_streams() -> u32 {
    4_096
}

fn default_true() -> bool {
    true
}

pub fn token_matches(expected: &str, got: &str) -> bool {
    let (expected, got) = (expected.as_bytes(), got.as_bytes());
    let mut difference = (expected.len() ^ got.len()) as u8;
    for index in 0..expected.len().max(got.len()) {
        difference |=
            expected.get(index).copied().unwrap_or(0) ^ got.get(index).copied().unwrap_or(0);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_listen_address_enables_both_transports() {
        let cfg: ServerConfig = toml::from_str(
            r#"
listen = "0.0.0.0:4433"
token = "secret"
"#,
        )
        .unwrap();
        assert!(cfg.quic_enabled);
        assert!(cfg.grpc_enabled);
        assert_eq!(cfg.quic_listen(), cfg.listen);
        assert_eq!(cfg.grpc_listen(), cfg.listen);
        assert_eq!(cfg.dns_timeout_ms, 5_000);
        assert_eq!(cfg.tcp_idle_timeout_secs, 300);
    }

    #[test]
    fn rejects_disabling_all_transports() {
        let cfg: ServerConfig = toml::from_str(
            r#"
listen = "0.0.0.0:4433"
quic_enabled = false
grpc_enabled = false
token = "secret"
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn token_comparison_is_length_independent() {
        assert!(token_matches("secret", "secret"));
        assert!(!token_matches("secret", "secre"));
        assert!(!token_matches("secret", "Secret"));
    }

    #[test]
    fn rejects_zero_timeouts() {
        for field in [
            "connect_timeout_ms",
            "dns_timeout_ms",
            "tcp_idle_timeout_secs",
            "udp_timeout_secs",
        ] {
            let text = format!("listen = \"0.0.0.0:4433\"\ntoken = \"secret\"\n{field} = 0\n");
            let cfg: ServerConfig = toml::from_str(&text).unwrap();
            assert!(cfg.validate().is_err(), "{field} accepted zero");
        }
    }
}
