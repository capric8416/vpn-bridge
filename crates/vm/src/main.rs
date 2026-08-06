//! vpnbridge-vm — runs inside the Windows VM that holds the VPN sessions.
//!
//! It accepts flows from the host agent over the host <-> VM network and
//! re-issues them locally, so every packet leaves through whichever VPN client
//! owns that network.

mod config;
mod server;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use crate::config::VmConfig;

#[derive(Parser, Debug)]
#[command(
    name = "vpnbridge-vm",
    version,
    about = "Dial VPN-only networks on behalf of the host"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "vm.toml")]
    config: PathBuf,
    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,
    /// Log level (trace, debug, info, warn, error). RUST_LOG overrides it.
    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    let cfg = Arc::new(VmConfig::load(&cli.config)?);
    if cli.check {
        println!("configuration OK: {}", cli.config.display());
        println!("  listen  : {}", cfg.listen);
        println!(
            "  auth    : {}",
            if cfg.token.is_empty() {
                "disabled"
            } else {
                "token"
            }
        );
        println!("  allow   : {}", join(&cfg.allow));
        println!("  deny    : {}", join(&cfg.deny));
        println!("  bind_ip : {:?}", cfg.bind_ip);
        return Ok(());
    }

    tokio::select! {
        result = server::run(cfg) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("vpnbridge_vm={level},warn")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn join(nets: &[ipnet::IpNet]) -> String {
    if nets.is_empty() {
        return "(any)".to_string();
    }
    nets.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
