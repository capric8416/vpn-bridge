use std::fs::{File, OpenOptions};
use std::io::BufReader;
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub fn ensure_exists(certificate: &Path, private_key: &Path, server_name: &str) -> Result<()> {
    match (certificate.exists(), private_key.exists()) {
        (true, true) => return Ok(()),
        (true, false) | (false, true) => {
            bail!(
                "certificate and private key must either both exist or both be absent: {}, {}",
                certificate.display(),
                private_key.display()
            );
        }
        (false, false) => {}
    }

    let generated = rcgen::generate_simple_self_signed(vec![server_name.to_owned()])
        .context("generating self-signed certificate")?;
    if let Some(parent) = certificate.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating certificate directory {}", parent.display()))?;
    }
    if let Some(parent) = private_key.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating private-key directory {}", parent.display()))?;
    }
    std::fs::write(certificate, generated.cert.pem())
        .with_context(|| format!("writing certificate {}", certificate.display()))?;
    write_private_key(
        private_key,
        generated.signing_key.serialize_pem().as_bytes(),
    )?;
    tracing::info!(
        certificate = %certificate.display(),
        private_key = %private_key.display(),
        "generated self-signed QUIC identity"
    );
    Ok(())
}

fn write_private_key(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating private key {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing private key {}", path.display()))
}

pub fn load(
    certificate: &Path,
    private_key: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_reader = BufReader::new(
        File::open(certificate)
            .with_context(|| format!("opening certificate {}", certificate.display()))?,
    );
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("reading certificate PEM")?;
    if certificates.is_empty() {
        bail!("certificate file contains no certificates");
    }

    let mut key_reader = BufReader::new(
        File::open(private_key)
            .with_context(|| format!("opening private key {}", private_key.display()))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("reading private-key PEM")?
        .context("private-key file contains no supported key")?;
    Ok((certificates, key))
}
