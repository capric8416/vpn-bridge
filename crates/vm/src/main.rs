//! vpnbridge-vm — runs inside the Windows VM that holds the VPN sessions.
//!
//! It accepts flows from the host agent over the host <-> VM network and
//! re-issues them locally, so every packet leaves through whichever VPN client
//! owns that network.

mod config;
mod server;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::config::VmConfig;

#[derive(Parser, Debug)]
#[command(
    name = "vpnbridge-vm",
    version,
    about = "Dial VPN-only networks on behalf of the host"
)]
struct Cli {
    /// Path to the TOML configuration file. If omitted, searches the current
    /// directory and then the executable's directory for vm.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,
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

    let config_path = resolve_config_path(cli.config, "vm.toml")?;
    let cfg = Arc::new(VmConfig::load(&config_path)?);
    if cli.check {
        println!("configuration OK: {}", config_path.display());
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

fn resolve_config_path(explicit: Option<PathBuf>, file_name: &str) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }

    let current_dir = std::env::current_dir().context("getting current working directory")?;
    let executable = std::env::current_exe().context("getting executable path")?;
    choose_config_path(file_name, &current_dir, &executable, Path::is_file)
}

fn choose_config_path(
    file_name: &str,
    current_dir: &Path,
    executable: &Path,
    is_file: impl Fn(&Path) -> bool,
) -> Result<PathBuf> {
    let current = current_dir.join(file_name);
    if is_file(&current) {
        return Ok(current);
    }

    let executable_dir = executable
        .parent()
        .context("executable path has no parent directory")?;
    let adjacent = executable_dir.join(file_name);
    if is_file(&adjacent) {
        return Ok(adjacent);
    }

    bail!(
        "configuration file `{file_name}` not found; checked {} and {}",
        current.display(),
        adjacent.display()
    )
}

#[cfg(test)]
mod config_path_tests {
    use super::*;

    #[test]
    fn current_directory_takes_precedence() {
        let result = choose_config_path(
            "vm.toml",
            Path::new("work"),
            Path::new("bin/vpnbridge-vm"),
            |_| true,
        )
        .unwrap();
        assert_eq!(result, Path::new("work/vm.toml"));
    }

    #[test]
    fn falls_back_to_executable_directory() {
        let result = choose_config_path(
            "vm.toml",
            Path::new("work"),
            Path::new("bin/vpnbridge-vm"),
            |path| path == Path::new("bin/vm.toml"),
        )
        .unwrap();
        assert_eq!(result, Path::new("bin/vm.toml"));
    }

    #[test]
    fn reports_all_implicit_locations_when_missing() {
        let err = choose_config_path(
            "vm.toml",
            Path::new("work"),
            Path::new("bin/vpnbridge-vm"),
            |_| false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(&Path::new("work/vm.toml").display().to_string()));
        assert!(err.contains(&Path::new("bin/vm.toml").display().to_string()));
    }

    #[test]
    fn command_line_config_is_optional_and_preserved() {
        let implicit = Cli::try_parse_from(["vpnbridge-vm"]).unwrap();
        assert_eq!(implicit.config, None);

        let explicit =
            Cli::try_parse_from(["vpnbridge-vm", "--config", "custom/config.toml"]).unwrap();
        assert_eq!(explicit.config, Some(PathBuf::from("custom/config.toml")));
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
