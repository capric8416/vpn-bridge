use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use vpnbridge_proto::grpc::proxy_service_client::ProxyServiceClient;
use vpnbridge_proto::grpc::TunnelFrame;
use vpnbridge_proto::{Address, Cmd, Request, Response, Status};

use crate::config::ClientConfig;
use crate::transport::{Flow, FlowTransport};

const PIPE_CAPACITY: usize = 64 * 1024;
const FRAME_SIZE: usize = 16 * 1024;

pub struct GrpcClient {
    client: ProxyServiceClient<Channel>,
    cfg: Arc<ClientConfig>,
}

impl GrpcClient {
    pub fn new(cfg: Arc<ClientConfig>) -> Result<Self> {
        let certificate = std::fs::read(&cfg.certificate)
            .with_context(|| format!("reading certificate {}", cfg.certificate.display()))?;
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(certificate))
            .domain_name(cfg.server_name.clone());
        let endpoint = Endpoint::from_shared(format!("https://{}", cfg.grpc_server()))?
            .tls_config(tls)
            .context("configuring gRPC TLS")?
            .connect_timeout(std::time::Duration::from_millis(cfg.connect_timeout_ms));
        Ok(Self {
            client: ProxyServiceClient::new(endpoint.connect_lazy()),
            cfg,
        })
    }

    pub async fn open(&self, cmd: Cmd, target: Address) -> Result<Flow> {
        let mut request_bytes = Vec::new();
        Request {
            cmd,
            token: self.cfg.token.clone(),
            target: target.clone(),
        }
        .write_to(&mut request_bytes)
        .await
        .context("encoding gRPC proxy request")?;

        let (request_tx, request_rx) = mpsc::channel(32);
        request_tx
            .send(TunnelFrame {
                payload: request_bytes,
            })
            .await
            .map_err(|_| anyhow::anyhow!("gRPC request stream closed before opening"))?;
        let mut client = self.client.clone();
        let request_timeout = std::time::Duration::from_millis(self.cfg.connect_timeout_ms);
        let mut inbound = timeout(
            request_timeout,
            client.open(ReceiverStream::new(request_rx)),
        )
        .await
        .with_context(|| format!("gRPC fallback connection timed out for {target}"))?
        .with_context(|| format!("opening gRPC fallback stream for {target}"))?
        .into_inner();

        let (application_io, bridge_io) = tokio::io::duplex(PIPE_CAPACITY);
        let (application_recv, application_send) = tokio::io::split(application_io);
        let (mut outbound, mut incoming) = tokio::io::split(bridge_io);

        tokio::spawn(async move {
            let mut buffer = vec![0u8; FRAME_SIZE];
            loop {
                match outbound.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(length) => {
                        if request_tx
                            .send(TunnelFrame {
                                payload: buffer[..length].to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
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
                    Ok(None) | Err(_) => {
                        let _ = incoming.shutdown().await;
                        break;
                    }
                }
            }
        });

        let mut recv: crate::transport::FlowRecv = Box::new(application_recv);
        let response = timeout(request_timeout, Response::read_from(&mut recv))
            .await
            .with_context(|| format!("gRPC proxy response timed out for {target}"))?
            .with_context(|| format!("reading gRPC proxy response for {target}"))?;
        if response.status != Status::Ok {
            let message = if response.message.is_empty() {
                response.status.to_string()
            } else {
                format!("{}: {}", response.status, response.message)
            };
            bail!("proxy refused {target}: {message}");
        }

        Ok(Flow {
            send: Box::new(application_send),
            recv,
            transport: FlowTransport::Grpc,
        })
    }
}
