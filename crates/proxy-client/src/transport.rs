use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use vpnbridge_proto::{Address, Cmd};

use crate::config::ClientConfig;
use crate::grpc::GrpcClient;
use crate::quic::{QuicClient, QuicOpenError};

pub type FlowSend = Box<dyn AsyncWrite + Send + Unpin>;
pub type FlowRecv = Box<dyn AsyncRead + Send + Unpin>;

pub struct Flow {
    pub send: FlowSend,
    pub recv: FlowRecv,
    pub transport: FlowTransport,
}

#[derive(Clone, Copy, Debug)]
pub enum FlowTransport {
    Quic,
    Grpc,
}

pub struct TransportClient {
    quic: Option<QuicClient>,
    grpc: Option<GrpcClient>,
    fallback_until: Mutex<Option<Instant>>,
    retry_interval: Duration,
}

impl TransportClient {
    pub fn new(cfg: Arc<ClientConfig>) -> Result<Self> {
        Ok(Self {
            quic: cfg
                .quic_enabled
                .then(|| QuicClient::new(cfg.clone()))
                .transpose()?,
            grpc: cfg
                .grpc_enabled
                .then(|| GrpcClient::new(cfg.clone()))
                .transpose()?,
            fallback_until: Mutex::new(None),
            retry_interval: Duration::from_millis(cfg.reconnect_interval_ms),
        })
    }

    pub async fn open(&self, cmd: Cmd, target: Address) -> Result<Flow> {
        let Some(quic) = self.quic.as_ref() else {
            return self
                .grpc
                .as_ref()
                .context("gRPC transport is disabled")?
                .open(cmd, target)
                .await;
        };
        let Some(grpc) = self.grpc.as_ref() else {
            return match quic.open(cmd, target).await {
                Ok((send, recv)) => Ok(Flow {
                    send: Box::new(send),
                    recv: Box::new(recv),
                    transport: FlowTransport::Quic,
                }),
                Err(QuicOpenError::Rejected(err) | QuicOpenError::Unavailable(err)) => Err(err),
            };
        };

        let quic_suppressed = self
            .fallback_until
            .lock()
            .await
            .is_some_and(|until| Instant::now() < until);
        if quic_suppressed {
            match grpc.open(cmd, target.clone()).await {
                Ok(flow) => return Ok(flow),
                Err(grpc_error) => {
                    *self.fallback_until.lock().await = None;
                    tracing::warn!(%grpc_error, "gRPC fallback unavailable; retrying QUIC");
                }
            }
        }

        match quic.open(cmd, target.clone()).await {
            Ok((send, recv)) => {
                *self.fallback_until.lock().await = None;
                Ok(Flow {
                    send: Box::new(send),
                    recv: Box::new(recv),
                    transport: FlowTransport::Quic,
                })
            }
            Err(QuicOpenError::Rejected(err)) => Err(err),
            Err(QuicOpenError::Unavailable(quic_error)) => {
                *self.fallback_until.lock().await = Some(Instant::now() + self.retry_interval);
                tracing::warn!(%quic_error, "QUIC unavailable; using gRPC over TCP fallback");
                grpc.open(cmd, target)
                    .await
                    .context("QUIC and gRPC proxy transports are unavailable")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ipnet::IpNet;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::transport::{Identity, Server, ServerTlsConfig};
    use tonic::{Request as GrpcRequest, Response as GrpcResponse, Status};

    use vpnbridge_proto::grpc::proxy_service_server::{ProxyService, ProxyServiceServer};
    use vpnbridge_proto::grpc::TunnelFrame;
    use vpnbridge_proto::Response;

    use crate::config::{ClientConfig, TunConfig};

    struct EchoProxy;

    #[tonic::async_trait]
    impl ProxyService for EchoProxy {
        type OpenStream = ReceiverStream<Result<TunnelFrame, Status>>;

        async fn open(
            &self,
            request: GrpcRequest<tonic::Streaming<TunnelFrame>>,
        ) -> Result<GrpcResponse<Self::OpenStream>, Status> {
            let mut inbound = request.into_inner();
            inbound
                .message()
                .await?
                .ok_or_else(|| Status::invalid_argument("missing request"))?;
            let (tx, rx) = mpsc::channel(8);
            let mut response = Vec::new();
            Response::ok()
                .write_to(&mut response)
                .await
                .map_err(|err| Status::internal(err.to_string()))?;
            tx.send(Ok(TunnelFrame { payload: response }))
                .await
                .unwrap();
            tokio::spawn(async move {
                while let Ok(Some(frame)) = inbound.message().await {
                    if tx.send(Ok(frame)).await.is_err() {
                        break;
                    }
                }
            });
            Ok(GrpcResponse::new(ReceiverStream::new(rx)))
        }
    }

    #[tokio::test]
    async fn falls_back_to_grpc_when_quic_is_unavailable() {
        let identity = rcgen::generate_simple_self_signed(vec!["vpnbridge.local".into()]).unwrap();
        let certificate_pem = identity.cert.pem();
        let private_key_pem = identity.signing_key.serialize_pem();
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("server.pem");
        std::fs::write(&certificate_path, &certificate_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = listener.local_addr().unwrap();
        let tls =
            ServerTlsConfig::new().identity(Identity::from_pem(certificate_pem, private_key_pem));
        let server = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(ProxyServiceServer::new(EchoProxy))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let cfg = Arc::new(ClientConfig {
            server: server_address,
            quic_enabled: true,
            grpc_enabled: true,
            quic_server: None,
            grpc_server: None,
            token: "test-token".into(),
            server_name: "vpnbridge.local".into(),
            certificate: certificate_path,
            routes: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
            connect_timeout_ms: 1_000,
            reconnect_interval_ms: 1_000,
            tun: TunConfig::default(),
        });
        let client = TransportClient::new(cfg).unwrap();
        let mut flow = client
            .open(
                Cmd::ConnectTcp,
                Address::Ip("10.1.2.3:443".parse().unwrap()),
            )
            .await
            .unwrap();
        assert!(matches!(flow.transport, FlowTransport::Grpc));
        flow.send.write_all(b"hello").await.unwrap();
        let mut response = [0u8; 5];
        flow.recv.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"hello");

        server.abort();
    }
}
