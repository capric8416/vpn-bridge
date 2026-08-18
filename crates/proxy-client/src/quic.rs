use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::rustls::pki_types::CertificateDer;
use quinn::rustls::RootCertStore;
use quinn::{ClientConfig as QuinnClientConfig, Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::Mutex;
use tokio::time::timeout;

use vpnbridge_proto::{Address, Cmd, Request, Response, Status};

use crate::config::ClientConfig;

pub struct QuicClient {
    endpoint: Endpoint,
    cfg: Arc<ClientConfig>,
    connection: Mutex<Option<Connection>>,
}

impl QuicClient {
    pub fn new(cfg: Arc<ClientConfig>) -> Result<Self> {
        let roots = load_roots(&cfg.certificate)?;
        let client_config = QuinnClientConfig::with_root_certificates(Arc::new(roots))
            .context("creating QUIC TLS configuration")?;
        let server = cfg.quic_server();
        let bind = match server {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let mut endpoint = Endpoint::client(bind).context("creating QUIC client endpoint")?;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            cfg,
            connection: Mutex::new(None),
        })
    }

    pub async fn open(
        &self,
        cmd: Cmd,
        target: Address,
    ) -> std::result::Result<(SendStream, RecvStream), QuicOpenError> {
        let connection = self
            .connection()
            .await
            .map_err(QuicOpenError::Unavailable)?;
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(err) => {
                self.invalidate().await;
                return Err(QuicOpenError::Unavailable(
                    anyhow::Error::new(err).context("opening QUIC stream"),
                ));
            }
        };
        let request = Request {
            cmd,
            token: self.cfg.token.clone(),
            target: target.clone(),
        };
        if let Err(err) = request.write_to(&mut send).await {
            self.invalidate().await;
            return Err(QuicOpenError::Unavailable(
                anyhow::Error::new(err).context(format!("sending QUIC proxy request for {target}")),
            ));
        }
        let response = match timeout(
            Duration::from_millis(self.cfg.connect_timeout_ms),
            Response::read_from(&mut recv),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                self.invalidate().await;
                return Err(QuicOpenError::Unavailable(
                    anyhow::Error::new(err)
                        .context(format!("reading QUIC proxy response for {target}")),
                ));
            }
            Err(err) => {
                self.invalidate().await;
                return Err(QuicOpenError::Unavailable(
                    anyhow::Error::new(err)
                        .context(format!("QUIC proxy response timed out for {target}")),
                ));
            }
        };
        if response.status != Status::Ok {
            let message = if response.message.is_empty() {
                response.status.to_string()
            } else {
                format!("{}: {}", response.status, response.message)
            };
            return Err(QuicOpenError::Rejected(anyhow::anyhow!(
                "proxy refused {target}: {message}"
            )));
        }
        Ok((send, recv))
    }

    async fn connection(&self) -> Result<Connection> {
        let mut slot = self.connection.lock().await;
        if let Some(connection) = slot.as_ref() {
            if connection.close_reason().is_none() {
                return Ok(connection.clone());
            }
        }
        let connecting = self
            .endpoint
            .connect(self.cfg.quic_server(), &self.cfg.server_name)
            .context("starting QUIC connection")?;
        let connection = timeout(
            Duration::from_millis(self.cfg.connect_timeout_ms),
            connecting,
        )
        .await
        .context("QUIC connection timed out")??;
        tracing::info!(server = %self.cfg.quic_server(), "QUIC connection established");
        *slot = Some(connection.clone());
        Ok(connection)
    }

    async fn invalidate(&self) {
        self.connection.lock().await.take();
    }
}

pub enum QuicOpenError {
    Unavailable(anyhow::Error),
    Rejected(anyhow::Error),
}

fn load_roots(path: &Path) -> Result<RootCertStore> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("opening certificate {}", path.display()))?,
    );
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<CertificateDer<'static>>>>()
        .context("reading certificate PEM")?;
    if certificates.is_empty() {
        bail!("certificate file contains no certificates");
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .context("adding trusted certificate")?;
    }
    Ok(roots)
}
