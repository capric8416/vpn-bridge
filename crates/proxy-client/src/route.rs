use std::process::Command;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;

pub struct RouteManager {
    device: String,
    added: Vec<IpNet>,
}

impl RouteManager {
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            added: Vec::new(),
        }
    }

    pub fn add(&mut self, network: IpNet) -> Result<()> {
        add_route(network, &self.device)?;
        self.added.push(network);
        tracing::info!(%network, device = %self.device, "proxy route installed");
        Ok(())
    }

    pub fn cleanup(&mut self) {
        for network in self.added.drain(..).rev() {
            match delete_route(network, &self.device) {
                Ok(()) => tracing::info!(%network, "proxy route removed"),
                Err(err) => tracing::warn!(%network, %err, "could not remove proxy route"),
            }
        }
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(target_os = "linux")]
fn add_route(network: IpNet, device: &str) -> Result<()> {
    run("ip", &["route", "add", &network.to_string(), "dev", device])
}

#[cfg(target_os = "linux")]
fn delete_route(network: IpNet, device: &str) -> Result<()> {
    run("ip", &["route", "del", &network.to_string(), "dev", device])
}

#[cfg(target_os = "macos")]
fn add_route(network: IpNet, device: &str) -> Result<()> {
    run(
        "route",
        &[
            "-n",
            "add",
            "-net",
            &network.to_string(),
            "-interface",
            device,
        ],
    )
}

#[cfg(target_os = "macos")]
fn delete_route(network: IpNet, device: &str) -> Result<()> {
    run(
        "route",
        &[
            "-n",
            "delete",
            "-net",
            &network.to_string(),
            "-interface",
            device,
        ],
    )
}

#[cfg(target_os = "windows")]
fn add_route(network: IpNet, device: &str) -> Result<()> {
    let prefix = format!("prefix={network}");
    let interface = format!("interface={device}");
    run(
        "netsh",
        &[
            "interface",
            "ipv4",
            "add",
            "route",
            &prefix,
            &interface,
            "store=active",
        ],
    )
}

#[cfg(target_os = "windows")]
fn delete_route(network: IpNet, device: &str) -> Result<()> {
    let prefix = format!("prefix={network}");
    let interface = format!("interface={device}");
    run(
        "netsh",
        &[
            "interface",
            "ipv4",
            "delete",
            "route",
            &prefix,
            &interface,
            "store=active",
        ],
    )
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running `{program} {}`", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "`{program} {}` failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
