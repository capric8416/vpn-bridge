//! vpnbridge-host — Linux side of the proxy chain.
//!
//! Creates a TUN device, steers the configured networks into it, terminates
//! TCP/UDP in userspace and hands every flow to the agent running inside the
//! Windows VM, which is the only machine that can see the VPN networks.

mod config;
mod dns;
mod route;
mod tunnel;

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

use vpnbridge_proto::{Address, Cmd};

use crate::config::HostConfig;
use crate::route::RouteManager;
use crate::tunnel::Client;

#[derive(Parser, Debug)]
#[command(
    name = "vpnbridge-host",
    version,
    about = "Forward selected networks to a VPN-connected VM"
)]
struct Cli {
    /// Path to the TOML configuration file. If omitted, searches the current
    /// directory and then the executable's directory for host.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Validate the configuration and exit without touching the network.
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

    let config_path = resolve_config_path(cli.config, "host.toml")?;
    let cfg = Arc::new(HostConfig::load(&config_path)?);
    if cli.check {
        println!("configuration OK: {}", config_path.display());
        println!("  VM agent   : {}", cfg.server.address);
        println!(
            "  tun device : {} {}/{}",
            cfg.tun.name, cfg.tun.address, cfg.tun.netmask
        );
        println!("  forwarding : {}", join(&cfg.routes));
        println!("  excluding  : {}", join(&cfg.exclude));
        if let Some(dns) = &cfg.dns {
            println!("  dns        : {} -> {:?}", dns.listen, dns.upstream);
        }
        return Ok(());
    }

    // Resolve every next hop *before* the tunnel routes exist, otherwise the
    // kernel would answer with the TUN device we are about to install.
    let server_ip = cfg.server.address.ip();
    let server_hop = if cfg.captures(server_ip) && !cfg.excludes(server_ip) {
        Some(route::lookup(server_ip).with_context(|| {
            format!("looking up the current route to the VM agent at {server_ip}")
        })?)
    } else {
        None
    };
    let mut exclude_hops = Vec::new();
    for net in &cfg.exclude {
        match route::lookup(net.network()) {
            Ok(hop) => exclude_hops.push((*net, hop)),
            Err(err) => {
                tracing::warn!(%net, %err, "no current route for excluded network, skipping")
            }
        }
    }

    let device = create_tun(&cfg)?;
    let mut routes = RouteManager::new();
    if cfg.tun.auto_route {
        // Exclusions first: they must be in place before the broad tunnel
        // routes can start attracting traffic.
        if let Some(hop) = &server_hop {
            routes
                .pin_direct(route::host_net(server_ip), hop)
                .context("pinning a direct route to the VM agent")?;
        }
        for (net, hop) in &exclude_hops {
            if let Err(err) = routes.pin_direct(*net, hop) {
                tracing::warn!(%net, %err, "could not pin excluded network");
            }
        }
        for net in &cfg.routes {
            routes
                .add_to_dev(*net, &cfg.tun.name)
                .with_context(|| format!("installing route {net} via {}", cfg.tun.name))?;
        }
    } else {
        tracing::warn!("tun.auto_route is false — install the routes yourself");
    }

    let client = Client::new(Arc::new(cfg.server.clone()));

    if let Some(dns_cfg) = &cfg.dns {
        let dns_cfg = Arc::new(dns_cfg.clone());
        let dns_client = client.clone();
        tokio::spawn(async move {
            if let Err(err) = dns::serve(dns_cfg, dns_client).await {
                tracing::error!(%err, "DNS forwarder stopped");
            }
        });
    }

    let mut ip_cfg = IpStackConfig::default();
    ip_cfg
        .mtu(cfg.tun.mtu)
        .map_err(|err| anyhow!("invalid tun.mtu {}: {err}", cfg.tun.mtu))?
        .packet_information(false)
        .udp_timeout(Duration::from_secs(60));
    let mut stack = IpStack::new(ip_cfg, device);

    tracing::info!(
        agent = %cfg.server.address,
        tun = %cfg.tun.name,
        routes = %join(&cfg.routes),
        "vpnbridge-host running"
    );

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                tracing::info!("shutting down");
                break;
            }
            accepted = stack.accept() => {
                let stream = accepted.map_err(|err| anyhow!("ip stack stopped: {err}"))?;
                dispatch(stream, &client);
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

#[cfg(test)]
mod config_path_tests {
    use super::*;

    #[test]
    fn current_directory_takes_precedence() {
        let result = choose_config_path(
            "host.toml",
            Path::new("work"),
            Path::new("bin/vpnbridge-host"),
            |_| true,
        )
        .unwrap();
        assert_eq!(result, Path::new("work/host.toml"));
    }

    #[test]
    fn falls_back_to_executable_directory() {
        let result = choose_config_path(
            "host.toml",
            Path::new("work"),
            Path::new("bin/vpnbridge-host"),
            |path| path == Path::new("bin/host.toml"),
        )
        .unwrap();
        assert_eq!(result, Path::new("bin/host.toml"));
    }

    #[test]
    fn reports_all_implicit_locations_when_missing() {
        let err = choose_config_path(
            "host.toml",
            Path::new("work"),
            Path::new("bin/vpnbridge-host"),
            |_| false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(&Path::new("work/host.toml").display().to_string()));
        assert!(err.contains(&Path::new("bin/host.toml").display().to_string()));
    }

    #[test]
    fn command_line_config_is_optional_and_preserved() {
        let implicit = Cli::try_parse_from(["vpnbridge-host"]).unwrap();
        assert_eq!(implicit.config, None);

        let explicit =
            Cli::try_parse_from(["vpnbridge-host", "--config", "custom/config.toml"]).unwrap();
        assert_eq!(explicit.config, Some(PathBuf::from("custom/config.toml")));
    }
}

fn dispatch(stream: IpStackStream, client: &Client) {
    match stream {
        IpStackStream::Tcp(mut tcp) => {
            let src = tcp.local_addr();
            let dst = tcp.peer_addr();
            let client = client.clone();
            tokio::spawn(async move {
                tracing::debug!(%src, %dst, "tcp flow");
                let tunnel = match client.open(Cmd::ConnectTcp, Address::Ip(dst)).await {
                    Ok(t) => t,
                    Err(err) => {
                        tracing::warn!(%dst, %err, "tcp: tunnel setup failed");
                        // The userspace stack already completed the handshake
                        // with the local app, so send a FIN instead of just
                        // dropping the stream — otherwise the app hangs until
                        // its own timeout.
                        let _ = tcp.shutdown().await;
                        return;
                    }
                };
                match tunnel::relay_tcp(tcp, tunnel).await {
                    Ok((up, down)) => tracing::debug!(%dst, up, down, "tcp flow closed"),
                    Err(err) => tracing::debug!(%dst, %err, "tcp flow ended"),
                }
            });
        }
        IpStackStream::Udp(udp) => {
            let src = udp.local_addr();
            let dst = udp.peer_addr();
            let client = client.clone();
            tokio::spawn(async move {
                tracing::debug!(%src, %dst, "udp flow");
                let tunnel = match client.open(Cmd::BindUdp, Address::Ip(dst)).await {
                    Ok(t) => t,
                    Err(err) => {
                        tracing::warn!(%dst, %err, "udp: tunnel setup failed");
                        return;
                    }
                };
                if let Err(err) = tunnel::relay_udp(udp, tunnel).await {
                    tracing::debug!(%dst, %err, "udp flow ended");
                }
            });
        }
        IpStackStream::UnknownTransport(u) => {
            // ICMP and friends are not proxied: replying locally would only
            // fake reachability. Test with TCP instead of ping.
            tracing::debug!(
                src = %u.src_addr(),
                dst = %u.dst_addr(),
                protocol = ?u.ip_protocol(),
                "dropping non TCP/UDP packet"
            );
        }
        IpStackStream::UnknownNetwork(packet) => {
            tracing::trace!(len = packet.len(), "dropping unknown network layer packet");
        }
    }
}

struct TunDevice(AsyncDevice);

impl AsyncRead for TunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.0.poll_recv(cx, buf.initialize_unfilled()) {
            Poll::Ready(Ok(read)) => {
                buf.advance(read);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn create_tun(cfg: &HostConfig) -> Result<TunDevice> {
    DeviceBuilder::new()
        .name(&cfg.tun.name)
        .layer(Layer::L3)
        .ipv4(cfg.tun.address, cfg.tun.netmask, None)
        .mtu(cfg.tun.mtu)
        .enable(true)
        .build_async()
        .map(TunDevice)
        .with_context(|| {
            format!(
                "creating TUN device {} (needs root or CAP_NET_ADMIN)",
                cfg.tun.name
            )
        })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("vpnbridge_host={level},warn")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn join(nets: &[ipnet::IpNet]) -> String {
    if nets.is_empty() {
        return "(none)".to_string();
    }
    nets.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
