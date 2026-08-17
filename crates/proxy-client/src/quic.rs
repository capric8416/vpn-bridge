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
use tokio::time::{sleep, timeout};

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
        let bind = match cfg.server {
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

    pub async fn open(&self, cmd: Cmd, target: Address) -> Result<(SendStream, RecvStream)> {
        loop {
            let connection = self.connection().await;
            let connection = match connection {
                Ok(connection) => connection,
                Err(err) => {
                    tracing::warn!(%err, "connecting to QUIC proxy failed; retrying");
                    sleep(Duration::from_millis(self.cfg.reconnect_interval_ms)).await;
                    continue;
                }
            };
            let (mut send, mut recv) = match connection.open_bi().await {
                Ok(streams) => streams,
                Err(err) => {
                    tracing::warn!(%err, "opening QUIC stream failed; reconnecting");
                    self.invalidate().await;
                    continue;
                }
            };
            let request = Request {
                cmd,
                token: self.cfg.token.clone(),
                target: target.clone(),
            };
            request
                .write_to(&mut send)
                .await
                .with_context(|| format!("sending proxy request for {target}"))?;
            let response = timeout(
                Duration::from_millis(self.cfg.connect_timeout_ms),
                Response::read_from(&mut recv),
            )
            .await
            .with_context(|| format!("proxy response timed out for {target}"))??;
            if response.status != Status::Ok {
                let message = if response.message.is_empty() {
                    response.status.to_string()
                } else {
                    format!("{}: {}", response.status, response.message)
                };
                bail!("proxy refused {target}: {message}");
            }
            return Ok((send, recv));
        }
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
            .connect(self.cfg.server, &self.cfg.server_name)
            .context("starting QUIC connection")?;
        let connection = timeout(
            Duration::from_millis(self.cfg.connect_timeout_ms),
            connecting,
        )
        .await
        .context("QUIC connection timed out")??;
        tracing::info!(server = %self.cfg.server, "QUIC connection established");
        *slot = Some(connection.clone());
        Ok(connection)
    }

    async fn invalidate(&self) {
        self.connection.lock().await.take();
    }
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
