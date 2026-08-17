use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;

use vpnbridge_proto::{read_datagram, write_datagram, Address, Cmd, Request, Response, Status};

use crate::config::{token_matches, ServerConfig};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run(endpoint: Endpoint, cfg: Arc<ServerConfig>) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let cfg = cfg.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let peer = connection.remote_address();
                    tracing::info!(%peer, "QUIC connection established");
                    if let Err(err) = serve_connection(connection, cfg).await {
                        tracing::debug!(%peer, %err, "QUIC connection ended");
                    }
                }
                Err(err) => tracing::debug!(%err, "QUIC handshake failed"),
            }
        });
    }
    Ok(())
}

async fn serve_connection(connection: Connection, cfg: Arc<ServerConfig>) -> Result<()> {
    loop {
        let (send, recv) = connection.accept_bi().await?;
        let cfg = cfg.clone();
        let peer = connection.remote_address();
        tokio::spawn(async move {
            if let Err(err) = handle_stream(cfg, send, recv, peer).await {
                tracing::debug!(%peer, %err, "proxy stream ended");
            }
        });
    }
}

async fn handle_stream(
    cfg: Arc<ServerConfig>,
    mut send: SendStream,
    mut recv: RecvStream,
    peer: SocketAddr,
) -> Result<()> {
    let request = timeout(REQUEST_TIMEOUT, Request::read_from(&mut recv))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))??;

    if !token_matches(&cfg.token, &request.token) {
        tracing::warn!(%peer, "rejected stream with invalid token");
        Response::err(Status::AuthFailed, "invalid token")
            .write_to(&mut send)
            .await?;
        send.finish()?;
        return Ok(());
    }

    let candidates = match resolve(&request.target).await {
        Ok(candidates) if !candidates.is_empty() => candidates,
        Ok(_) => {
            reject(&mut send, Status::Unreachable, "name resolved to nothing").await?;
            return Ok(());
        }
        Err(err) => {
            reject(
                &mut send,
                Status::Unreachable,
                format!("resolve failed: {err}"),
            )
            .await?;
            return Ok(());
        }
    };
    let allowed: Vec<_> = candidates
        .into_iter()
        .filter(|address| cfg.permits(address.ip()))
        .collect();
    if allowed.is_empty() {
        reject(&mut send, Status::Forbidden, "destination not allowed").await?;
        return Ok(());
    }

    match request.cmd {
        Cmd::ConnectTcp => serve_tcp(&cfg, send, recv, peer, &request.target, &allowed).await,
        Cmd::BindUdp => serve_udp(&cfg, send, recv, peer, &request.target, allowed[0]).await,
    }
}

async fn serve_tcp(
    cfg: &ServerConfig,
    mut send: SendStream,
    recv: RecvStream,
    peer: SocketAddr,
    target: &Address,
    candidates: &[SocketAddr],
) -> Result<()> {
    let dial_timeout = Duration::from_millis(cfg.connect_timeout_ms);
    let mut last_error = None;
    let mut upstream = None;
    for candidate in candidates {
        match timeout(dial_timeout, dial_tcp(cfg, *candidate)).await {
            Ok(Ok(stream)) => {
                upstream = Some(stream);
                break;
            }
            Ok(Err(err)) => last_error = Some(err.to_string()),
            Err(_) => last_error = Some(format!("connect to {candidate} timed out")),
        }
    }
    let upstream = match upstream {
        Some(stream) => stream,
        None => {
            reject(
                &mut send,
                Status::Unreachable,
                last_error.unwrap_or_else(|| "connect failed".into()),
            )
            .await?;
            return Ok(());
        }
    };

    Response::ok().write_to(&mut send).await?;
    tracing::debug!(%peer, %target, "TCP proxy stream open");
    relay_tcp(upstream, send, recv).await?;
    tracing::debug!(%peer, %target, "TCP proxy stream closed");
    Ok(())
}

async fn serve_udp(
    cfg: &ServerConfig,
    mut send: SendStream,
    recv: RecvStream,
    peer: SocketAddr,
    target: &Address,
    destination: SocketAddr,
) -> Result<()> {
    let bind = match cfg.bind_ip {
        Some(ip) if ip.is_ipv4() == destination.is_ipv4() => SocketAddr::new(ip, 0),
        _ if destination.is_ipv4() => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(err) => {
            reject(
                &mut send,
                Status::ServerError,
                format!("bind failed: {err}"),
            )
            .await?;
            return Ok(());
        }
    };
    if let Err(err) = socket.connect(destination).await {
        reject(
            &mut send,
            Status::Unreachable,
            format!("connect failed: {err}"),
        )
        .await?;
        return Ok(());
    }

    Response::ok().write_to(&mut send).await?;
    tracing::debug!(%peer, %target, "UDP proxy stream open");
    relay_udp(
        socket,
        send,
        recv,
        Duration::from_secs(cfg.udp_timeout_secs),
    )
    .await?;
    tracing::debug!(%peer, %target, "UDP proxy stream closed");
    Ok(())
}

async fn relay_tcp(
    upstream: TcpStream,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
) -> Result<()> {
    let (mut upstream_recv, mut upstream_send) = upstream.into_split();
    let upload = async {
        tokio::io::copy(&mut quic_recv, &mut upstream_send).await?;
        upstream_send.shutdown().await
    };
    let download = async {
        tokio::io::copy(&mut upstream_recv, &mut quic_send).await?;
        quic_send.finish().map_err(io::Error::other)
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn relay_udp(
    socket: UdpSocket,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    idle: Duration,
) -> Result<()> {
    let socket = Arc::new(socket);
    let upload_socket = socket.clone();
    let activity = Arc::new(AtomicU64::new(0));
    let upload_activity = activity.clone();
    let upload = async move {
        let mut buffer = Vec::new();
        loop {
            let length = read_datagram(&mut quic_recv, &mut buffer).await?;
            upload_socket.send(&buffer[..length]).await?;
            upload_activity.fetch_add(1, Ordering::Relaxed);
        }
        #[allow(unreachable_code)]
        Ok::<_, io::Error>(())
    };
    let download = async move {
        let mut buffer = vec![0u8; 65_535];
        let mut seen = activity.load(Ordering::Relaxed);
        loop {
            match timeout(idle, socket.recv(&mut buffer)).await {
                Ok(result) => {
                    let length = result?;
                    write_datagram(&mut quic_send, &buffer[..length]).await?;
                }
                Err(_) => {
                    let now = activity.load(Ordering::Relaxed);
                    if now == seen {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "UDP flow idle"));
                    }
                    seen = now;
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, io::Error>(())
    };
    tokio::select! {
        result = upload => result?,
        result = download => result?,
    }
    Ok(())
}

async fn dial_tcp(cfg: &ServerConfig, address: SocketAddr) -> io::Result<TcpStream> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(bind_ip) = cfg.bind_ip {
        if bind_ip.is_ipv4() == address.is_ipv4() {
            socket.bind(SocketAddr::new(bind_ip, 0))?;
        }
    }
    socket.connect(address).await
}

async fn resolve(target: &Address) -> io::Result<Vec<SocketAddr>> {
    match target {
        Address::Ip(address) => Ok(vec![*address]),
        Address::Domain(host, port) => Ok(tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .collect()),
    }
}

async fn reject(send: &mut SendStream, status: Status, message: impl Into<String>) -> Result<()> {
    Response::err(status, message).write_to(send).await?;
    send.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use quinn::{ClientConfig as QuinnClientConfig, ServerConfig as QuinnServerConfig, VarInt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn proxies_tcp_and_udp_over_authenticated_quic_streams() {
        let identity = rcgen::generate_simple_self_signed(vec!["vpnbridge.local".into()]).unwrap();
        let certificate = CertificateDer::from(identity.cert);
        let private_key = PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der());
        let server_config =
            QuinnServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())
                .unwrap();
        let server_endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_address = server_endpoint.local_addr().unwrap();
        let cfg = Arc::new(ServerConfig {
            listen: server_address,
            token: "test-token".into(),
            server_name: "vpnbridge.local".into(),
            certificate: PathBuf::new(),
            private_key: PathBuf::new(),
            allow: Vec::new(),
            deny: Vec::new(),
            bind_ip: None,
            connect_timeout_ms: 1_000,
            udp_timeout_secs: 10,
            max_concurrent_streams: 16,
        });
        let server_task = tokio::spawn(run(server_endpoint.clone(), cfg));

        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&request).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut roots = quinn::rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client_config = QuinnClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let connection = client_endpoint
            .connect(server_address, "vpnbridge.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        Request {
            cmd: Cmd::ConnectTcp,
            token: "test-token".into(),
            target: Address::Ip(echo_address),
        }
        .write_to(&mut send)
        .await
        .unwrap();
        let response = Response::read_from(&mut recv).await.unwrap();
        assert_eq!(response.status, Status::Ok);
        send.write_all(b"hello").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(16).await.unwrap(), b"hello");

        echo_task.await.unwrap();

        let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_echo_address = udp_echo.local_addr().unwrap();
        let udp_echo_task = tokio::spawn(async move {
            let mut request = [0u8; 5];
            let (length, peer) = udp_echo.recv_from(&mut request).await.unwrap();
            udp_echo.send_to(&request[..length], peer).await.unwrap();
        });
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        Request {
            cmd: Cmd::BindUdp,
            token: "test-token".into(),
            target: Address::Ip(udp_echo_address),
        }
        .write_to(&mut send)
        .await
        .unwrap();
        let response = Response::read_from(&mut recv).await.unwrap();
        assert_eq!(response.status, Status::Ok);
        write_datagram(&mut send, b"hello").await.unwrap();
        let mut response = Vec::new();
        let length = read_datagram(&mut recv, &mut response).await.unwrap();
        assert_eq!(&response[..length], b"hello");
        send.finish().unwrap();

        udp_echo_task.await.unwrap();
        client_endpoint.close(VarInt::from_u32(0), b"test complete");
        server_endpoint.close(VarInt::from_u32(0), b"test complete");
        server_task.abort();
    }
}
