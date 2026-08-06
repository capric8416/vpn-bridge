//! Thin wrapper around iproute2. Everything the host agent needs from the
//! kernel routing table goes through here so the logic stays in one place and
//! can be undone on shutdown.

use std::net::IpAddr;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;

/// Where the kernel would currently send traffic for a given address.
#[derive(Debug, Clone)]
pub struct NextHop {
    pub dev: String,
    pub gateway: Option<IpAddr>,
    pub src: Option<IpAddr>,
}

fn run(args: &[&str]) -> Result<String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("running `ip {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`ip {}` failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn family(net: &IpNet) -> &'static str {
    match net {
        IpNet::V4(_) => "-4",
        IpNet::V6(_) => "-6",
    }
}

fn family_ip(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "-4",
        IpAddr::V6(_) => "-6",
    }
}

/// `ip route get <ip>` — must be called *before* the TUN routes are installed,
/// otherwise it reports the tunnel itself.
pub fn lookup(ip: IpAddr) -> Result<NextHop> {
    let target = ip.to_string();
    let out = run(&[family_ip(ip), "route", "get", &target])?;
    let first = out
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty output from `ip route get {target}`"))?;

    let tokens: Vec<&str> = first.split_whitespace().collect();
    let mut hop = NextHop {
        dev: String::new(),
        gateway: None,
        src: None,
    };
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "via" => {
                hop.gateway = tokens.get(i + 1).and_then(|v| v.parse().ok());
                i += 2;
            }
            "dev" => {
                hop.dev = tokens.get(i + 1).unwrap_or(&"").to_string();
                i += 2;
            }
            "src" => {
                hop.src = tokens.get(i + 1).and_then(|v| v.parse().ok());
                i += 2;
            }
            _ => i += 1,
        }
    }
    if hop.dev.is_empty() {
        bail!("could not determine outgoing device for {target}: {first}");
    }
    Ok(hop)
}

/// True when a route for exactly this prefix already exists.
pub fn exists(net: &IpNet) -> bool {
    let spec = net.to_string();
    match run(&[family(net), "route", "show", "exact", &spec]) {
        Ok(out) => !out.trim().is_empty(),
        Err(_) => false,
    }
}

/// Installs routes and remembers which ones it created so they can be removed
/// again on shutdown.
#[derive(Default)]
pub struct RouteManager {
    added: Vec<IpNet>,
}

impl RouteManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Send `net` into the tunnel device.
    pub fn add_to_dev(&mut self, net: IpNet, dev: &str) -> Result<()> {
        let spec = net.to_string();
        run(&[family(&net), "route", "replace", &spec, "dev", dev])?;
        self.added.push(net);
        tracing::info!(%net, dev, "route installed");
        Ok(())
    }

    /// Pin `net` to its current next hop so the tunnel cannot swallow it.
    /// Pre-existing routes are left untouched (and not removed on shutdown).
    pub fn pin_direct(&mut self, net: IpNet, hop: &NextHop) -> Result<()> {
        if exists(&net) {
            tracing::debug!(%net, "exact route already present, leaving it alone");
            return Ok(());
        }
        let spec = net.to_string();
        let gw;
        let mut args: Vec<&str> = vec![family(&net), "route", "add", &spec];
        if let Some(g) = hop.gateway {
            gw = g.to_string();
            args.extend_from_slice(&["via", &gw]);
        }
        args.extend_from_slice(&["dev", &hop.dev]);
        run(&args)?;
        self.added.push(net);
        tracing::info!(%net, dev = %hop.dev, gateway = ?hop.gateway, "direct route pinned");
        Ok(())
    }

    /// Best-effort removal of everything this manager added.
    pub fn cleanup(&mut self) {
        for net in self.added.drain(..).rev() {
            let spec = net.to_string();
            match run(&[family(&net), "route", "del", &spec]) {
                Ok(_) => tracing::info!(%net, "route removed"),
                // The route usually disappears together with the TUN device,
                // so a failure here is expected during a normal shutdown.
                Err(err) => tracing::debug!(%net, %err, "route removal skipped"),
            }
        }
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// `/32` or `/128` prefix for a single address.
pub fn host_net(ip: IpAddr) -> IpNet {
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    IpNet::new(ip, prefix).expect("host prefix length is always valid")
}
