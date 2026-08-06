//! vpnbridge-host — Linux side of the proxy chain.
//!
//! Creates a TUN device, steers the configured networks into it, terminates
//! TCP/UDP in userspace and hands every flow to the agent running inside the
//! Windows VM, which is the only machine that can see the VPN networks.

mod config;
mod dns;
mod route;
mod tunnel;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::AsyncWriteExt;

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
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/vpnbridge/host.toml")]
    config: PathBuf,
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

    let cfg = Arc::new(HostConfig::load(&cli.config)?);
    if cli.check {
        println!("configuration OK: {}", cli.config.display());
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

fn create_tun(cfg: &HostConfig) -> Result<tun::AsyncDevice> {
    let mut tun_cfg = tun::Configuration::default();
    tun_cfg
        .tun_name(&cfg.tun.name)
        .address(cfg.tun.address)
        .netmask(cfg.tun.netmask)
        .mtu(cfg.tun.mtu)
        .up();
    tun::create_as_async(&tun_cfg).with_context(|| {
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
