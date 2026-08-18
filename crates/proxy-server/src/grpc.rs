use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request as GrpcRequest, Response as GrpcResponse, Status};

use vpnbridge_proto::grpc::proxy_service_server::{ProxyService, ProxyServiceServer};
use vpnbridge_proto::grpc::TunnelFrame;
use vpnbridge_proto::Request;

use crate::config::ServerConfig;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const PIPE_CAPACITY: usize = 64 * 1024;
const FRAME_SIZE: usize = 16 * 1024;

pub async fn run(cfg: Arc<ServerConfig>) -> Result<()> {
    let certificate = std::fs::read(&cfg.certificate)
        .with_context(|| format!("reading certificate {}", cfg.certificate.display()))?;
    let private_key = std::fs::read(&cfg.private_key)
        .with_context(|| format!("reading private key {}", cfg.private_key.display()))?;
    let tls = ServerTlsConfig::new().identity(Identity::from_pem(certificate, private_key));
    let service = GrpcProxy { cfg: cfg.clone() };

    Server::builder()
        .tls_config(tls)
        .context("configuring gRPC TLS")?
        .add_service(ProxyServiceServer::new(service))
        .serve(cfg.grpc_listen())
        .await
        .context("serving gRPC TCP fallback")
}

struct GrpcProxy {
    cfg: Arc<ServerConfig>,
}

#[tonic::async_trait]
impl ProxyService for GrpcProxy {
    type OpenStream = ReceiverStream<Result<TunnelFrame, Status>>;

    async fn open(
        &self,
        request: GrpcRequest<tonic::Streaming<TunnelFrame>>,
    ) -> Result<GrpcResponse<Self::OpenStream>, Status> {
        let peer = request
            .remote_addr()
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let mut inbound = request.into_inner();
        let first = timeout(REQUEST_TIMEOUT, inbound.message())
            .await
            .map_err(|_| Status::deadline_exceeded("proxy request timed out"))?
            .map_err(|err| Status::invalid_argument(format!("reading proxy request: {err}")))?
            .ok_or_else(|| Status::invalid_argument("missing proxy request"))?;
        let request = Request::read_from(&mut std::io::Cursor::new(first.payload))
            .await
            .map_err(|err| Status::invalid_argument(format!("invalid proxy request: {err}")))?;

        let (handler_io, bridge_io) = tokio::io::duplex(PIPE_CAPACITY);
        let (handler_recv, handler_send) = tokio::io::split(handler_io);
        let (mut outbound, mut incoming) = tokio::io::split(bridge_io);
        let (response_tx, response_rx) = mpsc::channel(32);

        tokio::spawn(async move {
            let mut buffer = vec![0u8; FRAME_SIZE];
            loop {
                match outbound.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(length) => {
                        let frame = TunnelFrame {
                            payload: buffer[..length].to_vec(),
                        };
                        if response_tx.send(Ok(frame)).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = response_tx
                            .send(Err(Status::internal(format!(
                                "reading proxy response: {err}"
                            ))))
                            .await;
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(Some(frame)) => {
                        if incoming.write_all(&frame.payload).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = incoming.shutdown().await;
                        break;
                    }
                    Err(err) => {
                        tracing::debug!(%peer, %err, "gRPC request stream ended");
                        break;
                    }
                }
            }
        });

        let cfg = self.cfg.clone();
        tokio::spawn(async move {
            if let Err(err) =
                crate::server::handle_request(cfg, request, handler_send, handler_recv, peer).await
            {
                tracing::debug!(%peer, %err, "gRPC proxy stream ended");
            }
        });

        Ok(GrpcResponse::new(ReceiverStream::new(response_rx)))
    }
}
