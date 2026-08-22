//! TLS interception of CONNECT tunnels: accept the decrypted leg, extract
//! tunnel/TLS metadata, and serve plaintext HTTP through the caller's
//! handler via hyper-util's auto (h1+h2) connection builder.
//!
//! This is the per-connection core M3 wires into `server/proxy.rs`'s
//! CONNECT fallback: after the proxy replies `200 Connection Established`,
//! the upgraded socket lands here with its authority and either gets pumped
//! through untouched ([`ConnectAction::Passthrough`]) or terminated locally.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::response::Response;
use futures::future::BoxFuture;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::server::ServerConnection;
use tokio::io::{AsyncRead, AsyncWrite};

use super::connect::{decide, parse_authority, pump_passthrough, ConnectAction, PassthroughRules};
use crate::error::{Error, Result};
use crate::tls::acceptor::{accept as tls_accept, build_server_config_with_fallback, tls_acceptor};
use crate::tls::ca::CaHandle;
use crate::tls::init_crypto_provider;
use crate::tls::leaf::LeafCache;
use crate::types::{TlsExchangeInfo, TunnelInfo};

/// Handler for decrypted requests: receives the client's request exactly as
/// presented on the intercepted TLS leg and returns the response to send
/// back (the M3 pipeline — forward upstream + record — plugs in here).
pub type InterceptHandler =
    Arc<dyn Fn(http::Request<Incoming>) -> BoxFuture<'static, Response> + Send + Sync>;

/// Per-connection interception configuration.
#[derive(Clone)]
pub struct InterceptTlsConfig {
    /// Resolved root CA (leaf signing material).
    pub ca: Arc<CaHandle>,
    /// Shared dynamic leaf cache.
    pub cache: Arc<LeafCache>,
    /// Compiled passthrough rules.
    pub rules: PassthroughRules,
}

/// Metadata seam for the M3 wiring: what happened to this tunnel.
#[derive(Debug, Clone)]
pub struct InterceptOutcome {
    pub tunnel: TunnelInfo,
    pub tls: Option<TlsExchangeInfo>,
}

/// Construct [`TunnelInfo`] (M3 attach point).
pub fn tunnel_info(
    host: impl Into<String>,
    port: u16,
    intercepted: bool,
    alpn: Option<&[u8]>,
) -> TunnelInfo {
    TunnelInfo {
        host: host.into(),
        port,
        intercepted,
        alpn: alpn.map(|p| String::from_utf8_lossy(p).into_owned()),
    }
}

/// Construct [`TlsExchangeInfo`] from explicit values.
pub fn tls_exchange_info(
    version: Option<&str>,
    cipher_suite: Option<&str>,
    sni: Option<&str>,
) -> TlsExchangeInfo {
    TlsExchangeInfo {
        version: version.map(str::to_owned),
        cipher_suite: cipher_suite.map(str::to_owned),
        sni: sni.map(str::to_owned),
    }
}

/// Extract [`TlsExchangeInfo`] from an established server-side connection.
pub fn exchange_info_from_connection(conn: &ServerConnection) -> TlsExchangeInfo {
    TlsExchangeInfo {
        version: conn.protocol_version().map(|v| format!("{v:?}")),
        cipher_suite: conn.negotiated_cipher_suite().map(|s| format!("{s:?}")),
        sni: conn.server_name().map(str::to_owned),
    }
}

/// Handle one CONNECT-established stream end to end and report what became
/// of it. `peer` is the client address, carried into error context only.
pub async fn serve_intercepted<S>(
    io: S,
    peer: SocketAddr,
    authority: &str,
    cfg: InterceptTlsConfig,
    handler: InterceptHandler,
) -> Result<InterceptOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let target = parse_authority(authority)?;

    match decide(&cfg.rules, authority) {
        ConnectAction::Passthrough => {
            let mut upstream = tokio::net::TcpStream::connect((target.host.as_str(), target.port))
                .await
                .map_err(|e| {
                    Error::io(
                        format!("dial passthrough target {authority} for peer {peer}"),
                        e,
                    )
                })?;
            let mut client = io;
            pump_passthrough(&mut client, &mut upstream).await?;
            Ok(InterceptOutcome {
                tunnel: tunnel_info(target.host, target.port, false, None),
                tls: None,
            })
        }
        ConnectAction::Intercept => {
            init_crypto_provider();
            // The CONNECT authority is the no-SNI fallback: raw-IP clients
            // never send SNI (RFC 6066), so they must still get a usable leaf.
            let config =
                build_server_config_with_fallback(&cfg.ca, cfg.cache.clone(), &target.host)?;
            let acceptor = tls_acceptor(config);
            let tls_stream = tls_accept(&acceptor, io, authority).await?;

            let (_, conn) = tls_stream.get_ref();
            let info = exchange_info_from_connection(conn);
            let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);

            serve_http_over_tls(tls_stream, handler, peer).await?;

            Ok(InterceptOutcome {
                tunnel: tunnel_info(target.host, target.port, true, alpn.as_deref()),
                tls: Some(info),
            })
        }
    }
}

/// Serve HTTP/1.1 + h2 over an established TLS stream. Shared with
/// `tls_downstream` (static-cert reverse-proxy TLS terminates here too).
pub(crate) async fn serve_http_over_tls<S>(
    stream: tokio_rustls::server::TlsStream<S>,
    handler: InterceptHandler,
    peer: SocketAddr,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req: http::Request<Incoming>| {
        let handler = handler.clone();
        Box::pin(async move {
            let response = handler(req).await;
            Ok::<_, std::convert::Infallible>(response)
        })
    });
    Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await
        .map_err(|e| Error::other(format!("intercepted HTTP session for {peer} failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca::{ensure_ca, CaAlg};
    use crate::tls::leaf::DEFAULT_LEAF_CACHE_SIZE;
    use rustls::pki_types::ServerName;
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const CANNED_ORIGIN_RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

    /// Tiny origin server: reads one request head, replies canned bytes.
    async fn spawn_origin() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                // One read is plenty for the tiny test request head.
                if sock.read(&mut buf).await.unwrap_or(0) > 0 {
                    let _ = sock.write_all(CANNED_ORIGIN_RESPONSE).await;
                }
                let _ = sock.shutdown().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn intercepted_loopback_end_to_end() {
        let origin_addr = spawn_origin().await;

        let tmp = tempfile::tempdir().unwrap();
        let ca_dir = tmp.path().join("ca");
        let ca = ensure_ca(
            &ca_dir,
            CaAlg::EcdsaP256,
            &ca_dir.join("ca.pem"),
            &ca_dir.join("key.pem"),
        )
        .await
        .expect("test CA");

        let seen_host: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let seen_for_handler = seen_host.clone();

        // The pipeline stand-in: record the Host header, relay the GET to
        // the real origin over plain TCP, return its body to the client.
        let handler: InterceptHandler = Arc::new(move |req| {
            let host = req
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            *seen_for_handler.lock().unwrap() = host;
            let origin_addr = origin_addr;
            Box::pin(async move {
                let mut sock = TcpStream::connect(origin_addr).await.expect("dial origin");
                sock.write_all(
                    b"GET /ping HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("send origin request");
                let mut raw = Vec::new();
                sock.read_to_end(&mut raw)
                    .await
                    .expect("read origin response");
                let text = String::from_utf8_lossy(&raw).into_owned();
                let body = text.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned();
                axum::http::Response::builder()
                    .status(axum::http::StatusCode::OK)
                    .header(http::header::CONTENT_LENGTH, body.len())
                    .body(axum::body::Body::from(body))
                    .expect("build response")
            })
        });

        let cfg = InterceptTlsConfig {
            ca: Arc::new(ca.clone()),
            cache: Arc::new(LeafCache::new(DEFAULT_LEAF_CACHE_SIZE)),
            rules: PassthroughRules::default(),
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("interceptor bind");
        let interceptor_addr = listener.local_addr().unwrap();

        // Wrap serve_intercepted around accepted connections (the shape the
        // CONNECT fallback in proxy.rs will use).
        tokio::spawn(async move {
            while let Ok((sock, peer)) = listener.accept().await {
                let cfg = cfg.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let _ = serve_intercepted(sock, peer, "origin.test:443", cfg, handler).await;
                });
            }
        });

        // Trusted client: trusts ONLY our root CA.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_chain_der[0].clone()).expect("trust root");
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(client_config);

        let tcp = TcpStream::connect(interceptor_addr)
            .await
            .expect("dial interceptor");
        let sni = ServerName::try_from("origin.test".to_string()).expect("sni");
        let mut tls = connector.connect(sni, tcp).await.expect("handshake");

        tls.write_all(b"GET /ping HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("send request");
        let mut raw = Vec::new();
        tls.read_to_end(&mut raw).await.expect("read response");

        let text = String::from_utf8(raw).expect("utf8 response");
        assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
        assert!(
            text.ends_with("hello"),
            "origin body must round-trip: {text}"
        );

        let host = seen_host
            .lock()
            .unwrap()
            .clone()
            .expect("handler must see Host");
        assert_eq!(host, "origin.test", "handler saw the authority host");
    }

    #[tokio::test]
    async fn passthrough_pumps_to_real_upstream() {
        // Origin speaks plain bytes; a passthrough tunnel must carry them
        // through untouched.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
        let origin_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                if sock.read(&mut buf).await.unwrap_or(0) > 0 {
                    let _ = sock.write_all(b"PONG").await;
                }
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let ca_dir = tmp.path().join("ca");
        let ca = ensure_ca(
            &ca_dir,
            CaAlg::EcdsaP256,
            &ca_dir.join("ca.pem"),
            &ca_dir.join("key.pem"),
        )
        .await
        .expect("test CA");
        let cfg = InterceptTlsConfig {
            ca: Arc::new(ca),
            cache: Arc::new(LeafCache::new(4)),
            rules: PassthroughRules::compile(&["127.0.0.1:*".to_string()]).expect("rules"),
        };
        // Authority is a live loopback endpoint so the passthrough dial lands.
        let authority = format!("127.0.0.1:{}", origin_addr.port());

        let (client_side, mut server_side) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            serve_intercepted(
                client_side,
                "127.0.0.1:12345".parse().unwrap(),
                authority.as_str(),
                cfg,
                Arc::new(
                    |_req: http::Request<Incoming>| -> BoxFuture<'static, Response> {
                        Box::pin(async { unreachable!("passthrough never invokes the handler") })
                    },
                ),
            )
            .await
        });

        // Byte-transparency check while the tunnel is live.
        server_side.write_all(b"PING").await.unwrap();
        let mut buf = vec![0u8; 4];
        server_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PONG", "tunnel must be byte-transparent");

        // Closing the client half lets the pump finish; only then can the
        // outcome (tunnel metadata) be observed.
        drop(server_side);
        let outcome = task.await.expect("task join").expect("passthrough outcome");
        assert!(!outcome.tunnel.intercepted);
        assert!(outcome.tls.is_none());
    }
}

impl std::fmt::Debug for InterceptTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptTlsConfig")
            .field("ca", &"<CaHandle>")
            .field("cache_len", &self.cache.len())
            .field("passthrough_rules", &self.rules)
            .finish()
    }
}
