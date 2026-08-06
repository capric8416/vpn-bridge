//! Wire protocol spoken between the host agent (Linux, TUN side) and the VM
//! agent (Windows, VPN side).
//!
//! One TCP connection carries exactly one proxied flow. There is no
//! multiplexing on purpose: the host <-> VM link is a virtual NIC, so extra
//! connections are cheap, and per-flow connections avoid head-of-line blocking
//! and keep failure handling trivial.
//!
//! ```text
//! request   MAGIC(4) VER(1) CMD(1) TOKEN_LEN(1) TOKEN(n) ADDR
//! response  MAGIC(4) VER(1) STATUS(1) MSG_LEN(1) MSG(n)
//!
//! ADDR      ATYP(1) ADDR(4|1+n|16) PORT(2, big endian)
//!           ATYP: 1 = IPv4, 3 = domain name, 4 = IPv6
//! ```
//!
//! After a successful `ConnectTcp` handshake the connection turns into a raw
//! bidirectional byte stream. After a successful `BindUdp` handshake both sides
//! exchange length-prefixed datagrams: `LEN(2, big endian) PAYLOAD(LEN)`.

use std::fmt;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAGIC: [u8; 4] = *b"VBRG";
pub const VERSION: u8 = 1;

/// Largest datagram that can be carried by a `BindUdp` session.
pub const MAX_DATAGRAM: usize = u16::MAX as usize;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Cmd {
    /// Open a TCP connection to the target and splice both directions.
    ConnectTcp = 1,
    /// Open a UDP socket connected to the target and relay datagrams.
    BindUdp = 2,
}

impl Cmd {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Cmd::ConnectTcp),
            2 => Some(Cmd::BindUdp),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    AuthFailed = 1,
    /// Target is not covered by the server side allow list.
    Forbidden = 2,
    /// The server could not reach the target.
    Unreachable = 3,
    BadRequest = 4,
    Unsupported = 5,
    ServerError = 6,
}

impl Status {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Status::Ok),
            1 => Some(Status::AuthFailed),
            2 => Some(Status::Forbidden),
            3 => Some(Status::Unreachable),
            4 => Some(Status::BadRequest),
            5 => Some(Status::Unsupported),
            6 => Some(Status::ServerError),
            _ => None,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Status::Ok => "ok",
            Status::AuthFailed => "authentication failed",
            Status::Forbidden => "target not allowed by server policy",
            Status::Unreachable => "target unreachable from the VM",
            Status::BadRequest => "malformed request",
            Status::Unsupported => "unsupported command",
            Status::ServerError => "server error",
        };
        f.write_str(s)
    }
}

/// Target endpoint of a proxied flow.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Ip(sa) => sa.port(),
            Address::Domain(_, port) => *port,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ip(sa) => Some(sa.ip()),
            Address::Domain(..) => None,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Address::Ip(SocketAddr::V4(v4)) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            Address::Ip(SocketAddr::V6(v6)) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
            Address::Domain(host, port) => {
                // Callers build domains from configuration only, but truncate
                // defensively so the length prefix can never overflow.
                let bytes = host.as_bytes();
                let len = bytes.len().min(255);
                out.push(ATYP_DOMAIN);
                out.push(len as u8);
                out.extend_from_slice(&bytes[..len]);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self> {
        let atyp = r.read_u8().await?;
        match atyp {
            ATYP_IPV4 => {
                let mut octets = [0u8; 4];
                r.read_exact(&mut octets).await?;
                let port = r.read_u16().await?;
                Ok(Address::Ip(SocketAddr::from((
                    Ipv4Addr::from(octets),
                    port,
                ))))
            }
            ATYP_IPV6 => {
                let mut octets = [0u8; 16];
                r.read_exact(&mut octets).await?;
                let port = r.read_u16().await?;
                Ok(Address::Ip(SocketAddr::from((
                    Ipv6Addr::from(octets),
                    port,
                ))))
            }
            ATYP_DOMAIN => {
                let len = r.read_u8().await? as usize;
                let mut buf = vec![0u8; len];
                r.read_exact(&mut buf).await?;
                let port = r.read_u16().await?;
                let host = String::from_utf8(buf)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "domain is not valid utf-8"))?;
                Ok(Address::Domain(host, port))
            }
            other => Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown address type {other}"),
            )),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(sa: SocketAddr) -> Self {
        Address::Ip(sa)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(sa) => write!(f, "{sa}"),
            Address::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub cmd: Cmd,
    pub token: String,
    pub target: Address,
}

impl Request {
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        let token = self.token.as_bytes();
        if token.len() > 255 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "token longer than 255 bytes",
            ));
        }
        let mut buf = Vec::with_capacity(32 + token.len());
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION);
        buf.push(self.cmd as u8);
        buf.push(token.len() as u8);
        buf.extend_from_slice(token);
        self.target.encode(&mut buf);
        w.write_all(&buf).await?;
        w.flush().await
    }

    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic).await?;
        if magic != MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "bad magic"));
        }
        let version = r.read_u8().await?;
        if version != VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unsupported protocol version {version}"),
            ));
        }
        let cmd = Cmd::from_u8(r.read_u8().await?)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "unknown command"))?;
        let token_len = r.read_u8().await? as usize;
        let mut token = vec![0u8; token_len];
        r.read_exact(&mut token).await?;
        let token = String::from_utf8(token)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "token is not valid utf-8"))?;
        let target = Address::read_from(r).await?;
        Ok(Request { cmd, token, target })
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: Status,
    pub message: String,
}

impl Response {
    pub fn ok() -> Self {
        Response {
            status: Status::Ok,
            message: String::new(),
        }
    }

    pub fn err(status: Status, message: impl Into<String>) -> Self {
        Response {
            status,
            message: message.into(),
        }
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        let msg = self.message.as_bytes();
        let len = msg.len().min(255);
        let mut buf = Vec::with_capacity(7 + len);
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION);
        buf.push(self.status as u8);
        buf.push(len as u8);
        buf.extend_from_slice(&msg[..len]);
        w.write_all(&buf).await?;
        w.flush().await
    }

    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic).await?;
        if magic != MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "bad magic in response"));
        }
        let version = r.read_u8().await?;
        if version != VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unsupported protocol version {version} in response"),
            ));
        }
        let status = Status::from_u8(r.read_u8().await?)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "unknown status code"))?;
        let len = r.read_u8().await? as usize;
        let mut msg = vec![0u8; len];
        r.read_exact(&mut msg).await?;
        Ok(Response {
            status,
            message: String::from_utf8_lossy(&msg).into_owned(),
        })
    }
}

/// Write one length-prefixed datagram.
pub async fn write_datagram<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_DATAGRAM {
        return Err(Error::new(ErrorKind::InvalidInput, "datagram too large"));
    }
    let mut buf = Vec::with_capacity(2 + payload.len());
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf).await
}

/// Read one length-prefixed datagram into `buf`, returning its length.
pub async fn read_datagram<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> Result<usize> {
    let len = r.read_u16().await? as usize;
    buf.resize(len, 0);
    r.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn request_roundtrip_ipv4() {
        let req = Request {
            cmd: Cmd::ConnectTcp,
            token: "secret".into(),
            target: Address::Ip("10.1.2.3:443".parse().unwrap()),
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).await.unwrap();
        let decoded = Request::read_from(&mut Cursor::new(buf)).await.unwrap();
        assert_eq!(decoded.cmd, Cmd::ConnectTcp);
        assert_eq!(decoded.token, "secret");
        assert_eq!(decoded.target, req.target);
    }

    #[tokio::test]
    async fn request_roundtrip_domain() {
        let req = Request {
            cmd: Cmd::BindUdp,
            token: String::new(),
            target: Address::Domain("intranet.example.com".into(), 53),
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).await.unwrap();
        let decoded = Request::read_from(&mut Cursor::new(buf)).await.unwrap();
        assert_eq!(decoded.target, req.target);
    }

    #[tokio::test]
    async fn response_roundtrip() {
        let resp = Response::err(Status::Unreachable, "connection refused");
        let mut buf = Vec::new();
        resp.write_to(&mut buf).await.unwrap();
        let decoded = Response::read_from(&mut Cursor::new(buf)).await.unwrap();
        assert_eq!(decoded.status, Status::Unreachable);
        assert_eq!(decoded.message, "connection refused");
    }

    #[tokio::test]
    async fn datagram_roundtrip() {
        let mut wire = Vec::new();
        write_datagram(&mut wire, b"hello").await.unwrap();
        write_datagram(&mut wire, b"").await.unwrap();
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        assert_eq!(read_datagram(&mut cursor, &mut buf).await.unwrap(), 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(read_datagram(&mut cursor, &mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn rejects_bad_magic() {
        let mut wire = b"XXXX\x01".to_vec();
        wire.extend_from_slice(&[1, 0, ATYP_IPV4, 10, 0, 0, 1, 0, 80]);
        assert!(Request::read_from(&mut Cursor::new(wire)).await.is_err());
    }
}
