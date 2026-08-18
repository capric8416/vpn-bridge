mod certificate;
mod config;
mod grpc;
mod server;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::{Endpoint, IdleTimeout, ServerConfig as QuinnServerConfig, TransportConfig, VarInt};
use tracing_subscriber::EnvFilter;

use crate::config::ServerConfig;

#[derive(Debug, Parser)]
#[command(
    name = "proxy-server",
    version,
    about = "QUIC proxy server with gRPC TCP fallback"
)]
struct Cli {
    /// Path to the TOML configuration file. If omitted, searches the current
    /// directory and then the executable's directory for proxy-server.toml.
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
    let config_path = resolve_config_path(cli.config, "proxy-server.toml")?;
    let cfg = Arc::new(ServerConfig::load(&config_path)?);
    certificate::ensure_exists(&cfg.certificate, &cfg.private_key, &cfg.server_name)?;
    if cli.check {
        println!("configuration OK: {}", config_path.display());
        if cfg.quic_enabled {
            println!("  QUIC/UDP    : {}", cfg.quic_listen());
        } else {
            println!("  QUIC/UDP    : disabled");
        }
        if cfg.grpc_enabled {
            println!("  gRPC/TCP    : {}", cfg.grpc_listen());
        } else {
            println!("  gRPC/TCP    : disabled");
        }
        println!("  server name : {}", cfg.server_name);
        println!("  certificate : {}", cfg.certificate.display());
        return Ok(());
    }

    let endpoint = cfg.quic_enabled.then(|| make_endpoint(&cfg)).transpose()?;
    tracing::info!(
        quic_enabled = cfg.quic_enabled,
        quic_listen = %cfg.quic_listen(),
        grpc_enabled = cfg.grpc_enabled,
        grpc_listen = %cfg.grpc_listen(),
        "proxy-server running"
    );
    let result = match (endpoint.as_ref(), cfg.grpc_enabled) {
        (Some(endpoint), true) => tokio::select! {
            result = server::run(endpoint.clone(), cfg.clone()) => result,
            result = grpc::run(cfg.clone()) => result,
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                Ok(())
            }
        },
        (Some(endpoint), false) => tokio::select! {
            result = server::run(endpoint.clone(), cfg.clone()) => result,
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                Ok(())
            }
        },
        (None, true) => tokio::select! {
            result = grpc::run(cfg.clone()) => result,
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                Ok(())
            }
        },
        (None, false) => {
            bail!("all proxy transports are disabled")
        }
    };
    if let Some(endpoint) = endpoint {
        endpoint.close(VarInt::from_u32(0), b"shutdown");
        endpoint.wait_idle().await;
    }
    result
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

fn make_endpoint(cfg: &ServerConfig) -> Result<Endpoint> {
    let (certificates, private_key) = certificate::load(&cfg.certificate, &cfg.private_key)?;
    let mut server_config = QuinnServerConfig::with_single_cert(certificates, private_key)
        .context("creating QUIC TLS configuration")?;
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(cfg.max_concurrent_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(90)).context("invalid QUIC idle timeout")?,
        ));
    server_config.transport = Arc::new(transport);
    Endpoint::server(server_config, cfg.quic_listen()).context("binding QUIC UDP endpoint")
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("proxy_server={level},warn")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

#[cfg(test)]
mod config_path_tests {
    use super::*;

    #[test]
    fn current_directory_takes_precedence() {
        let result = choose_config_path(
            "proxy-server.toml",
            Path::new("work"),
            Path::new("bin/proxy-server"),
            |_| true,
        )
        .unwrap();
        assert_eq!(result, Path::new("work/proxy-server.toml"));
    }

    #[test]
    fn falls_back_to_executable_directory() {
        let result = choose_config_path(
            "proxy-server.toml",
            Path::new("work"),
            Path::new("bin/proxy-server"),
            |path| path == Path::new("bin/proxy-server.toml"),
        )
        .unwrap();
        assert_eq!(result, Path::new("bin/proxy-server.toml"));
    }

    #[test]
    fn reports_all_implicit_locations_when_missing() {
        let error = choose_config_path(
            "proxy-server.toml",
            Path::new("work"),
            Path::new("bin/proxy-server"),
            |_| false,
        )
        .unwrap_err()
        .to_string();
        let current_path = Path::new("work").join("proxy-server.toml");
        let executable_path = Path::new("bin").join("proxy-server.toml");
        assert!(error.contains(&current_path.display().to_string()));
        assert!(error.contains(&executable_path.display().to_string()));
    }

    #[test]
    fn command_line_config_is_optional_and_preserved() {
        let implicit = Cli::try_parse_from(["proxy-server"]).unwrap();
        assert_eq!(implicit.config, None);

        let explicit =
            Cli::try_parse_from(["proxy-server", "--config", "custom/server.toml"]).unwrap();
        assert_eq!(explicit.config, Some(PathBuf::from("custom/server.toml")));
    }
}
