//! Client side of the bridge protocol: opens one connection to the VM agent
//! per proxied flow and splices it onto the local (TUN) stream.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

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
        let retry = Duration::from_millis(self.cfg.reconnect_interval_ms);
        let mut stream = loop {
            let result = timeout(dial, TcpStream::connect(self.cfg.address)).await;
            match result {
                Ok(Ok(stream)) => break stream,
                Ok(Err(err)) => tracing::warn!(
                    agent = %self.cfg.address,
                    %err,
                    retry_ms = self.cfg.reconnect_interval_ms,
                    "connecting to VM agent failed; retrying"
                ),
                Err(_) => tracing::warn!(
                    agent = %self.cfg.address,
                    timeout_ms = self.cfg.connect_timeout_ms,
                    retry_ms = self.cfg.reconnect_interval_ms,
                    "connecting to VM agent timed out; retrying"
                ),
            }
            sleep(retry).await;
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::{TcpListener, TcpSocket};

    #[tokio::test]
    async fn retries_until_vm_agent_accepts_connections() {
        let reservation = TcpSocket::new_v4().unwrap();
        reservation
            .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap();
        let agent = reservation.local_addr().unwrap();
        let client = Client::new(Arc::new(ServerConfig {
            address: agent,
            token: "test-token".into(),
            connect_timeout_ms: 50,
            reconnect_interval_ms: 20,
            tcp_nodelay: true,
        }));
        let target = Address::Ip("10.0.0.1:443".parse().unwrap());

        let open = tokio::spawn(async move { client.open(Cmd::ConnectTcp, target).await });

        // Keep the port bound but not listening long enough for at least one
        // connection attempt to fail, then bring up a minimal VM agent.
        sleep(Duration::from_millis(30)).await;
        drop(reservation);
        let listener = TcpListener::bind(agent).await.unwrap();
        let (mut stream, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let request = Request::read_from(&mut stream).await.unwrap();
        assert_eq!(request.token, "test-token");
        Response::ok().write_to(&mut stream).await.unwrap();

        timeout(Duration::from_secs(1), open)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
