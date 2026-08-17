use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
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
        Ok(())
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

fn default_udp_timeout() -> u64 {
    60
}

fn default_max_streams() -> u32 {
    4_096
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
    fn token_comparison_is_length_independent() {
        assert!(token_matches("secret", "secret"));
        assert!(!token_matches("secret", "secre"));
        assert!(!token_matches("secret", "Secret"));
    }
}
