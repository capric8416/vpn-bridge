//! Optional local DNS forwarder.
//!
//! Names that only the VPN's resolvers know about cannot be looked up on the
//! host, so this listens on a local UDP port and tunnels every query to a
//! VPN-side resolver. Point systemd-resolved (or /etc/resolv.conf) at it for
//! the internal domains.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use vpnbridge_proto::{read_datagram, write_datagram, Address, Cmd};

use crate::config::DnsConfig;
use crate::tunnel::Client;

/// Enough for any UDP DNS response; larger answers set TC and fall back to TCP,
/// which is routed through the TUN like any other traffic.
const DNS_BUF: usize = 4096;

pub async fn serve(cfg: Arc<DnsConfig>, client: Client) -> Result<()> {
    if cfg.upstream.is_empty() {
        return Err(anyhow!("dns.upstream is empty"));
    }
    let sock = Arc::new(
        UdpSocket::bind(cfg.listen)
            .await
            .with_context(|| format!("binding DNS forwarder on {}", cfg.listen))?,
    );
    tracing::info!(listen = %cfg.listen, upstream = ?cfg.upstream, "DNS forwarder ready");

    let mut buf = vec![0u8; DNS_BUF];
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(%err, "DNS recv failed");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        let sock = sock.clone();
        let client = client.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            match resolve(&cfg, &client, &query).await {
                Ok(answer) => {
                    if let Err(err) = sock.send_to(&answer, from).await {
                        tracing::warn!(%err, %from, "sending DNS answer failed");
                    }
                }
                Err(err) => tracing::warn!(%err, %from, "DNS query failed"),
            }
        });
    }
}

async fn resolve(cfg: &DnsConfig, client: &Client, query: &[u8]) -> Result<Vec<u8>> {
    let deadline = Duration::from_millis(cfg.timeout_ms);
    let mut last_err = None;
    for upstream in &cfg.upstream {
        match query_one(client, *upstream, query, deadline).await {
            Ok(answer) => return Ok(answer),
            Err(err) => {
                tracing::debug!(%upstream, %err, "upstream resolver failed, trying next");
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no upstream resolver configured")))
}

async fn query_one(
    client: &Client,
    upstream: std::net::SocketAddr,
    query: &[u8],
    deadline: Duration,
) -> Result<Vec<u8>> {
    let mut tunnel = client.open(Cmd::BindUdp, Address::Ip(upstream)).await?;
    write_datagram(&mut tunnel, query).await?;

    let mut buf = Vec::new();
    let n = timeout(deadline, read_datagram(&mut tunnel, &mut buf))
        .await
        .with_context(|| format!("timed out waiting for {upstream}"))??;
    buf.truncate(n);
    Ok(buf)
}
