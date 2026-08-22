//! rustls [`ServerConfig`] assembly for TLS interception plus the
//! tokio-rustls acceptor helpers.
//!
//! Every listener advertises ALPN `[h2, http/1.1]`; hyper-util's auto
//! connection builder picks the negotiated protocol on the decrypted leg.
//! Leaf certificates resolve through the shared [`LeafCache`] keyed by SNI,
//! with a per-config fallback host for clients that skip SNI (raw-IP or
//! no-SNI connections mint/reuse a leaf under the fallback name).

use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use super::ca::CaHandle;
use super::leaf::LeafCache;
use crate::error::Result;
use crate::tls::{init_crypto_provider, TlsError};

/// ALPN advertised by every arbiter TLS listener.
pub const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Fallback host when the client sends no SNI.
const FALLBACK_HOST: &str = "localhost";

/// `ResolvesServerCert` backed by the leaf cache. Sync by API contract —
/// see the `leaf` module docs for why inline cold mints are acceptable here.
struct CacheResolver {
    ca: Arc<CaHandle>,
    cache: Arc<LeafCache>,
    fallback_host: String,
}

impl std::fmt::Debug for CacheResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheResolver")
            .field("fallback_host", &self.fallback_host)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CacheResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name().unwrap_or(self.fallback_host.as_str());
        self.cache.get_or_mint_sync(&self.ca, host).ok()
    }
}

/// Build an interception [`ServerConfig`] resolving leaves through `cache`,
/// falling back to `fallback_host` when no SNI is presented.
pub fn build_server_config_with_fallback(
    ca: &CaHandle,
    cache: Arc<LeafCache>,
    fallback_host: &str,
) -> Result<Arc<ServerConfig>> {
    init_crypto_provider();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(CacheResolver {
            ca: Arc::new(ca.clone()),
            cache,
            fallback_host: fallback_host.to_string(),
        }));
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Build an interception [`ServerConfig`] with the default no-SNI fallback.
pub fn build_server_config(ca: &CaHandle, cache: Arc<LeafCache>) -> Result<Arc<ServerConfig>> {
    build_server_config_with_fallback(ca, cache, FALLBACK_HOST)
}

/// Wrap a server config in a reusable tokio-rustls acceptor.
pub fn tls_acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

/// Run the TLS handshake for `stream`, mapping failures to
/// [`TlsError::Handshake`] tagged with `host`.
pub async fn accept<S>(
    acceptor: &TlsAcceptor,
    stream: S,
    host: impl Into<String>,
) -> Result<tokio_rustls::server::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    acceptor.accept(stream).await.map_err(|e| {
        crate::error::Error::from(TlsError::Handshake {
            host: host.into(),
            source: Box::new(e),
        })
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca::{ensure_ca, CaAlg};
    use rustls::pki_types::{CertificateDer, ServerName};
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, TcpStream};

    async fn test_ca(dir: &std::path::Path) -> CaHandle {
        ensure_ca(
            dir,
            CaAlg::EcdsaP256,
            &dir.join("ca.pem"),
            &dir.join("key.pem"),
        )
        .await
        .expect("test CA")
    }

    fn trusted_client(root: &CertificateDer<'static>, alpn_h2: bool) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.clone()).expect("add root");
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        if alpn_h2 {
            config.alpn_protocols = vec![b"h2".to_vec()];
        }
        Arc::new(config)
    }

    /// One-shot interception endpoint: accepts TCP connections until
    /// `connections` handshakes completed through our resolver.
    async fn serve_n(config: Arc<ServerConfig>, listener: TcpListener, connections: usize) {
        let acceptor = tls_acceptor(config);
        for _ in 0..connections {
            let (socket, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            match accept(&acceptor, socket, "server-side").await {
                Ok(_tls) => { /* handshake done; stream drops */ }
                Err(_) => return,
            }
        }
    }

    async fn bind_local() -> (TcpListener, SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = l.local_addr().expect("addr");
        (l, addr)
    }

    #[tokio::test]
    async fn real_handshake_negotiates_alpn_h2_and_validates_dns_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = test_ca(tmp.path()).await;
        let root = ca.cert_chain_der[0].clone();
        let cache = Arc::new(LeafCache::new(8));
        let config = build_server_config_with_fallback(&ca, cache.clone(), "example.com").unwrap();
        let (listener, addr) = bind_local().await;
        tokio::spawn(serve_n(config, listener, 2));

        // DNS-SNI client offered h2 → h2 must be negotiated and the leaf's
        // DNS SAN must validate against the trusted root.
        let connector = tokio_rustls::TlsConnector::from(trusted_client(&root, true));
        let sni = ServerName::try_from("example.com".to_string()).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = connector.connect(sni, tcp).await.expect("dns handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        assert!(
            cache.contains("example.com"),
            "resolver must have cached the leaf"
        );
        drop(tls);

        // A raw-IP target never sends SNI (RFC 6066), so the server falls
        // back to the configured DNS-named leaf; a client verifying that cert
        // against an IP address must fail — pins down SAN semantics.
        let client_no_sni = trusted_client(&root, false);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let sni = ServerName::try_from(addr.ip().to_string()).expect("ip server name");
        let outcome = tokio_rustls::TlsConnector::from(client_no_sni)
            .connect(sni, tcp)
            .await;
        assert!(
            outcome.is_err(),
            "no-SNI fallback DNS leaf must not validate for an IP"
        );
    }

    #[tokio::test]
    async fn ip_san_leaf_enables_ip_sni_handshake() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = test_ca(tmp.path()).await;
        // Mint an IP leaf up front; the resolver serves it for the literal.
        let cache = Arc::new(LeafCache::new(8));
        cache
            .cert_for(&ca, "127.0.0.1")
            .await
            .expect("ip leaf mint");
        let config = build_server_config_with_fallback(&ca, cache.clone(), "127.0.0.1").unwrap();

        let (listener, addr) = bind_local().await;
        tokio::spawn(serve_n(config, listener, 1));

        let root = ca.cert_chain_der[0].clone();
        let client = trusted_client(&root, false);
        let sni = ServerName::try_from("127.0.0.1").expect("ip server name");
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(client)
            .connect(sni, tcp)
            .await
            .expect("ip-san handshake");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            None,
            "client offered no ALPN; none negotiated"
        );
    }
}
