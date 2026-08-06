use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfig {
    /// Address the agent listens on for the host, e.g. `0.0.0.0:17321`.
    pub listen: SocketAddr,
    /// Shared secret; must match the host side. Empty disables authentication.
    #[serde(default)]
    pub token: String,
    /// Destinations the agent is willing to dial. Empty means "anything".
    #[serde(default)]
    pub allow: Vec<IpNet>,
    /// Destinations that are always refused, checked before `allow`.
    #[serde(default)]
    pub deny: Vec<IpNet>,
    /// Source address for outgoing connections — set it to the VPN adapter's
    /// address when Windows would otherwise pick the wrong interface.
    #[serde(default)]
    pub bind_ip: Option<IpAddr>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    /// Tear down a UDP session after this long without traffic either way.
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,
}

fn default_true() -> bool {
    true
}
fn default_connect_timeout() -> u64 {
    8_000
}
fn default_udp_timeout() -> u64 {
    60
}

impl VmConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: VmConfig =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.token.is_empty() && !self.listen.ip().is_loopback() {
            tracing::warn!(
                "no token configured: anyone able to reach {} can use this agent",
                self.listen
            );
        }
        if self.token.len() > 255 {
            bail!("token must be at most 255 bytes");
        }
        if let Some(bind) = self.bind_ip {
            if bind.is_ipv4() != self.listen.is_ipv4() {
                tracing::warn!(%bind, "bind_ip family differs from listen family");
            }
        }
        Ok(())
    }

    /// Policy check for a resolved destination address.
    pub fn permits(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        self.allow.is_empty() || self.allow.iter().any(|n| n.contains(&ip))
    }
}

/// Length-independent comparison so a wrong token cannot be guessed byte by
/// byte from timing.
pub fn token_matches(expected: &str, got: &str) -> bool {
    let (a, b) = (expected.as_bytes(), got.as_bytes());
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison() {
        assert!(token_matches("secret", "secret"));
        assert!(token_matches("", ""));
        assert!(!token_matches("secret", "secre"));
        assert!(!token_matches("secret", "Secret"));
        assert!(!token_matches("", "x"));
    }

    #[test]
    fn allow_list_semantics() {
        let cfg = VmConfig {
            listen: "0.0.0.0:1".parse().unwrap(),
            token: String::new(),
            allow: vec!["10.0.0.0/8".parse().unwrap()],
            deny: vec!["10.9.0.0/16".parse().unwrap()],
            bind_ip: None,
            connect_timeout_ms: 1000,
            udp_timeout_secs: 10,
            tcp_nodelay: true,
        };
        assert!(cfg.permits("10.1.2.3".parse().unwrap()));
        assert!(!cfg.permits("10.9.1.1".parse().unwrap()));
        assert!(!cfg.permits("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn empty_allow_list_permits_everything() {
        let cfg = VmConfig {
            listen: "0.0.0.0:1".parse().unwrap(),
            token: String::new(),
            allow: vec![],
            deny: vec![],
            bind_ip: None,
            connect_timeout_ms: 1000,
            udp_timeout_secs: 10,
            tcp_nodelay: true,
        };
        assert!(cfg.permits("8.8.8.8".parse().unwrap()));
    }
}
