//! Static-cert downstream TLS: the reverse-proxy listener behind
//! `start --target https://host --tls-cert P --tls-key K`.
//!
//! Thin accept loop wrapping the same hyper-util auto connection builder
//! the plaintext listeners use, with ALPN `[h2, http/1.1]`. No client-certificate
//! authentication.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;

use super::intercept::{serve_http_over_tls, InterceptHandler};
use crate::error::{Error, Result};
use crate::tls::{init_crypto_provider, TlsError};

/// Load a certificate/key PEM pair into a server config (no client auth).
pub fn load_identity(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    init_crypto_provider();

    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| Error::io(format!("read TLS certificate {}", cert_path.display()), e))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| Error::io(format!("read TLS key {}", key_path.display()), e))?;

    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| TlsError::key_material(format!("parse {}: {e}", cert_path.display())))?;
    if certs.is_empty() {
        return Err(TlsError::key_material(format!(
            "no CERTIFICATE block in {}\n  help: pass a PEM chain via --tls-cert",
            cert_path.display()
        ))
        .into());
    }

    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| TlsError::key_material(format!("parse {}: {e}", key_path.display())))?
        .ok_or_else(|| {
            TlsError::key_material(format!(
                "no private-key block in {}\n  help: pass a PEM key via --tls-key",
                key_path.display()
            ))
        })?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            TlsError::key_material(format!(
                "certificate/key mismatch across {} and {}: {e}",
                cert_path.display(),
                key_path.display()
            ))
        })?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Serve `listener` over TLS until the listener fails, handing each
/// decrypted HTTP session to `handler`.
pub async fn serve_tls(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    handler: InterceptHandler,
) -> std::io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            // Handshake failures never kill the accept loop.
            if let Ok(tls) = acceptor.accept(stream).await {
                let _ = serve_http_over_tls(tls, handler, peer).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    fn self_signed_pair(cn: &str) -> (String, String) {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec![cn.to_string()]).expect("self-signed");
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn loads_identity_and_sets_alpn() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let (cert_pem, key_pem) = self_signed_pair("localhost");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();

        let config = load_identity(&cert_path, &key_path).expect("identity");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn rejects_mismatched_pair_with_cause() {
        let dir = tempfile::tempdir().unwrap();
        let (a_cert, _) = self_signed_pair("a.test");
        let (_, b_key) = self_signed_pair("b.test");
        let cert_path = dir.path().join("a.pem");
        let key_path = dir.path().join("b.pem");
        std::fs::write(&cert_path, a_cert).unwrap();
        std::fs::write(&key_path, b_key).unwrap();

        let err = load_identity(&cert_path, &key_path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("mismatch"), "{err}");
    }
}
