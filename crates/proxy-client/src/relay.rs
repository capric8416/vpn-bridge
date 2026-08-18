use std::io;
use std::sync::Arc;

use anyhow::{Context, Result};
use ipstack::IpStackStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use vpnbridge_proto::{read_datagram, write_datagram, Address, Cmd};

use crate::transport::{FlowRecv, FlowSend, TransportClient};

pub fn dispatch(stream: IpStackStream, client: Arc<TransportClient>) {
    match stream {
        IpStackStream::Tcp(tcp) => {
            let source = tcp.local_addr();
            let destination = tcp.peer_addr();
            tokio::spawn(async move {
                tracing::debug!(%source, %destination, "TCP flow");
                let flow = match client.open(Cmd::ConnectTcp, Address::Ip(destination)).await {
                    Ok(flow) => flow,
                    Err(err) => {
                        tracing::warn!(%destination, %err, "TCP proxy setup failed");
                        return;
                    }
                };
                tracing::debug!(%destination, transport = ?flow.transport, "TCP proxy transport selected");
                if let Err(err) = relay_tcp(tcp, flow.send, flow.recv).await {
                    tracing::debug!(%destination, %err, "TCP flow ended");
                }
            });
        }
        IpStackStream::Udp(udp) => {
            let source = udp.local_addr();
            let destination = udp.peer_addr();
            tokio::spawn(async move {
                tracing::debug!(%source, %destination, "UDP flow");
                let flow = match client.open(Cmd::BindUdp, Address::Ip(destination)).await {
                    Ok(flow) => flow,
                    Err(err) => {
                        tracing::warn!(%destination, %err, "UDP proxy setup failed");
                        return;
                    }
                };
                tracing::debug!(%destination, transport = ?flow.transport, "UDP proxy transport selected");
                if let Err(err) = relay_udp(udp, flow.send, flow.recv).await {
                    tracing::debug!(%destination, %err, "UDP flow ended");
                }
            });
        }
        IpStackStream::UnknownTransport(unknown) => tracing::debug!(
            src = %unknown.src_addr(),
            dst = %unknown.dst_addr(),
            protocol = ?unknown.ip_protocol(),
            "dropping unsupported non-TCP/UDP packet"
        ),
        IpStackStream::UnknownNetwork(packet) => {
            tracing::trace!(length = packet.len(), "dropping unknown network packet")
        }
    }
}

async fn relay_tcp<S>(local: S, mut send: FlowSend, mut recv: FlowRecv) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut local_recv, mut local_send) = tokio::io::split(local);
    let upload = async {
        tokio::io::copy(&mut local_recv, &mut send).await?;
        send.shutdown().await
    };
    let download = async {
        tokio::io::copy(&mut recv, &mut local_send).await?;
        local_send.shutdown().await
    };
    tokio::try_join!(upload, download).context("relaying TCP over proxy transport")?;
    Ok(())
}

async fn relay_udp<S>(local: S, mut send: FlowSend, mut recv: FlowRecv) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut local_recv, mut local_send) = tokio::io::split(local);
    let upload = async {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let length = local_recv.read(&mut buffer).await?;
            if length == 0 {
                send.shutdown().await?;
                return Ok::<_, io::Error>(());
            }
            write_datagram(&mut send, &buffer[..length]).await?;
        }
    };
    let download = async {
        let mut buffer = Vec::new();
        loop {
            let length = read_datagram(&mut recv, &mut buffer).await?;
            local_send.write_all(&buffer[..length]).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, io::Error>(())
    };
    tokio::select! {
        result = upload => result.context("uploading UDP over proxy transport")?,
        result = download => result.context("downloading UDP over proxy transport")?,
    }
    Ok(())
}
