//! Server side of the bridge protocol. Runs inside the VM, where the VPN
//! clients have already installed their routes, so an ordinary `connect()` is
//! all it takes to reach the internal networks.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;

use vpnbridge_proto::{read_datagram, write_datagram, Address, Cmd, Request, Response, Status};

use crate::config::{token_matches, VmConfig};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run(cfg: Arc<VmConfig>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    tracing::info!(listen = %cfg.listen, "vpnbridge-vm running");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(%err, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(cfg, stream, peer).await {
                tracing::debug!(%peer, %err, "session ended");
            }
        });
    }
}

async fn handle(cfg: Arc<VmConfig>, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
    let _ = stream.set_nodelay(cfg.tcp_nodelay);

    let req = timeout(HANDSHAKE_TIMEOUT, Request::read_from(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))??;

    if !token_matches(&cfg.token, &req.token) {
        tracing::warn!(%peer, "rejected: bad token");
        Response::err(Status::AuthFailed, "bad token")
            .write_to(&mut stream)
            .await?;
        return Ok(());
    }

    let candidates = match resolve(&req.target).await {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => {
            reject(&mut stream, Status::Unreachable, "name resolved to nothing").await?;
            return Ok(());
        }
        Err(err) => {
            reject(
                &mut stream,
                Status::Unreachable,
                format!("resolve failed: {err}"),
            )
            .await?;
            return Ok(());
        }
    };

    let allowed: Vec<SocketAddr> = candidates
        .iter()
        .copied()
        .filter(|sa| cfg.permits(sa.ip()))
        .collect();
    if allowed.is_empty() {
        tracing::warn!(%peer, target = %req.target, "rejected by policy");
        reject(&mut stream, Status::Forbidden, "destination not allowed").await?;
        return Ok(());
    }

    match req.cmd {
        Cmd::ConnectTcp => serve_tcp(cfg, stream, peer, &req.target, &allowed).await,
        Cmd::BindUdp => serve_udp(cfg, stream, peer, &req.target, allowed[0]).await,
    }
}

async fn serve_tcp(
    cfg: Arc<VmConfig>,
    mut stream: TcpStream,
    peer: SocketAddr,
    target: &Address,
    candidates: &[SocketAddr],
) -> Result<()> {
    let dial = Duration::from_millis(cfg.connect_timeout_ms);
    let mut last_err = None;
    let mut upstream = None;
    for addr in candidates {
        match timeout(dial, dial_tcp(&cfg, *addr)).await {
            Ok(Ok(s)) => {
                upstream = Some(s);
                break;
            }
            Ok(Err(err)) => last_err = Some(err.to_string()),
            Err(_) => last_err = Some(format!("connect to {addr} timed out")),
        }
    }
    let mut upstream = match upstream {
        Some(s) => s,
        None => {
            let msg = last_err.unwrap_or_else(|| "connect failed".into());
            tracing::info!(%peer, %target, %msg, "tcp connect failed");
            reject(&mut stream, Status::Unreachable, msg).await?;
            return Ok(());
        }
    };
    let _ = upstream.set_nodelay(cfg.tcp_nodelay);
    Response::ok().write_to(&mut stream).await?;

    let local = upstream.local_addr().ok();
    tracing::debug!(%peer, %target, ?local, "tcp session open");
    let (up, down) = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
    let _ = upstream.shutdown().await;
    tracing::debug!(%peer, %target, up, down, "tcp session closed");
    Ok(())
}

async fn serve_udp(
    cfg: Arc<VmConfig>,
    mut stream: TcpStream,
    peer: SocketAddr,
    target: &Address,
    addr: SocketAddr,
) -> Result<()> {
    let bind = match cfg.bind_ip {
        Some(ip) if ip.is_ipv4() == addr.is_ipv4() => SocketAddr::new(ip, 0),
        _ if addr.is_ipv4() => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let sock = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(err) => {
            reject(
                &mut stream,
                Status::ServerError,
                format!("bind failed: {err}"),
            )
            .await?;
            return Ok(());
        }
    };
    if let Err(err) = sock.connect(addr).await {
        reject(
            &mut stream,
            Status::Unreachable,
            format!("connect failed: {err}"),
        )
        .await?;
        return Ok(());
    }
    Response::ok().write_to(&mut stream).await?;
    tracing::debug!(%peer, %target, "udp session open");

    relay_udp(stream, sock, Duration::from_secs(cfg.udp_timeout_secs)).await?;
    tracing::debug!(%peer, %target, "udp session closed");
    Ok(())
}

async fn relay_udp(stream: TcpStream, sock: UdpSocket, idle: Duration) -> Result<()> {
    let sock = Arc::new(sock);
    let (tunnel_rx, tunnel_tx) = stream.into_split();
    // Bumped by the uplink so the downlink's idle timer does not tear down a
    // session that is only ever sending.
    let activity = Arc::new(AtomicU64::new(0));

    let result = tokio::select! {
        r = udp_uplink(tunnel_rx, sock.clone(), activity.clone()) => r,
        r = udp_downlink(tunnel_tx, sock, activity, idle) => r,
    };
    match result {
        Ok(()) => Ok(()),
        Err(err) if is_benign_eof(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Tunnel frame -> UDP datagram towards the VPN.
async fn udp_uplink(
    mut tunnel_rx: OwnedReadHalf,
    sock: Arc<UdpSocket>,
    activity: Arc<AtomicU64>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    loop {
        let n = read_datagram(&mut tunnel_rx, &mut buf).await?;
        sock.send(&buf[..n]).await?;
        activity.fetch_add(1, Ordering::Relaxed);
    }
}

/// UDP datagram from the VPN -> tunnel frame, ending the session once nothing
/// has moved in either direction for `idle`.
async fn udp_downlink(
    mut tunnel_tx: OwnedWriteHalf,
    sock: Arc<UdpSocket>,
    activity: Arc<AtomicU64>,
    idle: Duration,
) -> io::Result<()> {
    let mut buf = vec![0u8; 65_535];
    let mut seen = activity.load(Ordering::Relaxed);
    loop {
        match timeout(idle, sock.recv(&mut buf)).await {
            Ok(res) => {
                let n = res?;
                write_datagram(&mut tunnel_tx, &buf[..n]).await?;
            }
            Err(_) => {
                let now = activity.load(Ordering::Relaxed);
                if now == seen {
                    let _ = tunnel_tx.shutdown().await;
                    return Ok(());
                }
                seen = now;
            }
        }
    }
}

async fn dial_tcp(cfg: &VmConfig, addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(bind) = cfg.bind_ip {
        if bind.is_ipv4() == addr.is_ipv4() {
            socket.bind(SocketAddr::new(bind, 0))?;
        }
    }
    socket.connect(addr).await
}

async fn resolve(target: &Address) -> io::Result<Vec<SocketAddr>> {
    match target {
        Address::Ip(sa) => Ok(vec![*sa]),
        // Resolved inside the VM on purpose: internal names usually only exist
        // in the VPN's DNS.
        Address::Domain(host, port) => Ok(tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .collect()),
    }
}

async fn reject(
    stream: &mut TcpStream,
    status: Status,
    message: impl Into<String>,
) -> io::Result<()> {
    Response::err(status, message).write_to(stream).await
}

fn is_benign_eof(err: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        err.kind(),
        UnexpectedEof | BrokenPipe | ConnectionReset | ConnectionAborted | NotConnected | TimedOut
    )
}
