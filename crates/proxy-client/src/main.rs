mod config;
mod device;
mod quic;
mod relay;
mod route;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use ipstack::{IpStack, IpStackConfig};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, Layer};

use crate::config::ClientConfig;
use crate::device::TunDevice;
use crate::quic::QuicClient;
use crate::route::RouteManager;

#[derive(Debug, Parser)]
#[command(
    name = "proxy-client",
    version,
    about = "Cross-platform QUIC TUN proxy"
)]
struct Cli {
    /// Path to the TOML configuration file. If omitted, searches the current
    /// directory and then the executable's directory for proxy-client.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(long)]
    check: bool,
    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log);
    let config_path = resolve_config_path(cli.config, "proxy-client.toml")?;
    let cfg = Arc::new(ClientConfig::load(&config_path)?);
    if cli.check {
        let _ = std::fs::File::open(&cfg.certificate).with_context(|| {
            format!("opening trusted certificate {}", cfg.certificate.display())
        })?;
        println!("configuration OK: {}", config_path.display());
        println!("  server      : {} (UDP/QUIC)", cfg.server);
        println!("  server name : {}", cfg.server_name);
        println!("  certificate : {}", cfg.certificate.display());
        println!("  routes      : {}", join(&cfg.routes));
        return Ok(());
    }

    let client = Arc::new(QuicClient::new(cfg.clone())?);
    let (device, device_name) = create_tun(&cfg)?;
    let mut routes = RouteManager::new(&device_name);
    if cfg.tun.auto_route {
        for network in &cfg.routes {
            routes
                .add(*network)
                .with_context(|| format!("installing proxy route {network}"))?;
        }
    } else {
        tracing::warn!("tun.auto_route is false; install proxy routes manually");
    }

    let mut stack_config = IpStackConfig::default();
    stack_config
        .mtu(cfg.tun.mtu)
        .map_err(|err| anyhow!("invalid TUN MTU {}: {err}", cfg.tun.mtu))?
        .packet_information(false)
        .udp_timeout(Duration::from_secs(60));
    let mut stack = IpStack::new(stack_config, device);

    tracing::info!(
        server = %cfg.server,
        tun = %device_name,
        routes = %join(&cfg.routes),
        "proxy-client running"
    );
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
            accepted = stack.accept() => {
                let stream = accepted.map_err(|err| anyhow!("IP stack stopped: {err}"))?;
                relay::dispatch(stream, client.clone());
            }
        }
    }
    routes.cleanup();
    Ok(())
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

fn create_tun(cfg: &ClientConfig) -> Result<(TunDevice, String)> {
    let device = DeviceBuilder::new()
        .name(&cfg.tun.name)
        .layer(Layer::L3)
        .ipv4(cfg.tun.address, cfg.tun.netmask, None)
        .mtu(cfg.tun.mtu)
        .enable(true)
        .build_async()
        .context("creating TUN device (administrator/root privileges required)")?;
    let name = device.name().context("reading created TUN device name")?;
    Ok((TunDevice(device), name))
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("proxy_client={level},warn")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn join(networks: &[ipnet::IpNet]) -> String {
    networks
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod config_path_tests {
    use super::*;

    #[test]
    fn current_directory_takes_precedence() {
        let result = choose_config_path(
            "proxy-client.toml",
            Path::new("work"),
            Path::new("bin/proxy-client"),
            |_| true,
        )
        .unwrap();
        assert_eq!(result, Path::new("work/proxy-client.toml"));
    }

    #[test]
    fn falls_back_to_executable_directory() {
        let result = choose_config_path(
            "proxy-client.toml",
            Path::new("work"),
            Path::new("bin/proxy-client"),
            |path| path == Path::new("bin/proxy-client.toml"),
        )
        .unwrap();
        assert_eq!(result, Path::new("bin/proxy-client.toml"));
    }

    #[test]
    fn reports_all_implicit_locations_when_missing() {
        let error = choose_config_path(
            "proxy-client.toml",
            Path::new("work"),
            Path::new("bin/proxy-client"),
            |_| false,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("work/proxy-client.toml"));
        assert!(error.contains("bin/proxy-client.toml"));
    }

    #[test]
    fn command_line_config_is_optional_and_preserved() {
        let implicit = Cli::try_parse_from(["proxy-client"]).unwrap();
        assert_eq!(implicit.config, None);

        let explicit =
            Cli::try_parse_from(["proxy-client", "--config", "custom/client.toml"]).unwrap();
        assert_eq!(explicit.config, Some(PathBuf::from("custom/client.toml")));
    }
}
