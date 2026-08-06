//! Client side of the bridge protocol: opens one connection to the VM agent
//! per proxied flow and splices it onto the local (TUN) stream.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use vpnbridge_proto::{read_datagram, write_datagram, Address, Cmd, Request, Response, Status};

use crate::config::ServerConfig;

#[derive(Clone)]
pub struct Client {
    cfg: Arc<ServerConfig>,
}

impl Client {
    pub fn new(cfg: Arc<ServerConfig>) -> Self {
        Client { cfg }
    }

    /// Connect to the VM agent and complete the handshake for `target`.
    pub async fn open(&self, cmd: Cmd, target: Address) -> Result<TcpStream> {
        let dial = Duration::from_millis(self.cfg.connect_timeout_ms);
        let mut stream = timeout(dial, TcpStream::connect(self.cfg.address))
            .await
            .with_context(|| format!("timed out connecting to VM agent {}", self.cfg.address))?
            .with_context(|| format!("connecting to VM agent {}", self.cfg.address))?;
        if self.cfg.tcp_nodelay {
            stream.set_nodelay(true).ok();
        }

        let req = Request {
            cmd,
            token: self.cfg.token.clone(),
            target: target.clone(),
        };
        let resp = timeout(dial, handshake(&mut stream, &req))
            .await
            .with_context(|| format!("timed out during handshake for {target}"))?
            .with_context(|| format!("handshake for {target}"))?;

        if resp.status != Status::Ok {
            let detail = if resp.message.is_empty() {
                resp.status.to_string()
            } else {
                format!("{}: {}", resp.status, resp.message)
            };
            bail!("VM agent refused {target}: {detail}");
        }
        Ok(stream)
    }
}

async fn handshake(stream: &mut TcpStream, req: &Request) -> std::io::Result<Response> {
    req.write_to(stream).await?;
    Response::read_from(stream).await
}

/// Splice a local TCP stream onto a tunnel connection.
pub async fn relay_tcp<S>(mut local: S, mut tunnel: TcpStream) -> Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (up, down) = tokio::io::copy_bidirectional(&mut local, &mut tunnel).await?;
    let _ = tunnel.shutdown().await;
    Ok((up, down))
}

/// Relay datagrams between a local UDP flow and a `BindUdp` tunnel session.
///
/// `local` is expected to yield exactly one datagram per successful read, which
/// is what `ipstack`'s UDP streams do.
pub async fn relay_udp<S>(local: S, tunnel: TcpStream) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (local_rx, local_tx) = tokio::io::split(local);
    let (tunnel_rx, tunnel_tx) = tunnel.into_split();

    let result = tokio::select! {
        r = uplink(local_rx, tunnel_tx) => r,
        r = downlink(tunnel_rx, local_tx) => r,
    };
    match result {
        Ok(()) => Ok(()),
        // A closed tunnel or an idled-out UDP flow is the normal way these end.
        Err(err) if is_benign_eof(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Local datagram -> tunnel frame.
async fn uplink<R>(mut local_rx: R, mut tunnel_tx: OwnedWriteHalf) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 65_535];
    loop {
        let n = local_rx.read(&mut buf).await?;
        if n == 0 {
            let _ = tunnel_tx.shutdown().await;
            return Ok(());
        }
        write_datagram(&mut tunnel_tx, &buf[..n]).await?;
    }
}

/// Tunnel frame -> local datagram. Ends when the tunnel closes.
async fn downlink<W>(mut tunnel_rx: OwnedReadHalf, mut local_tx: W) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    loop {
        let n = read_datagram(&mut tunnel_rx, &mut buf).await?;
        local_tx.write_all(&buf[..n]).await?;
    }
}

pub fn is_benign_eof(err: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        err.kind(),
        UnexpectedEof | BrokenPipe | ConnectionReset | ConnectionAborted | NotConnected | TimedOut
    )
}
