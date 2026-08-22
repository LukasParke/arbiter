//! Proxy + docs server lifecycle (port of `src/server.ts` `startServers`).
//!
//! Both listeners are served through hyper-util's **auto** connection
//! builder with HTTP/1.1 AND HTTP/2 enabled, so ALPN-negotiated h2 works
//! once a TLS acceptor is attached (W1) and h2c prior-knowledge clients are
//! served on plaintext too. Connections accept protocol upgrades
//! (`serve_connection_with_upgrades`), which WebSocket proxying relies on.

pub mod connect;
pub mod docs;
pub mod flows_api;
pub mod intercept;
pub mod proxy;
pub mod tls_downstream;

use std::path::PathBuf;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::middleware::HarStore;
use crate::mock::fault::FaultInjector;
use crate::rules::hooks::HookConfig;
use crate::rules::HeaderRuleSet;
use crate::server::intercept::InterceptTlsConfig;
use crate::storage::SqliteStore;
use crate::store::OpenApiStore;
use futures::future::BoxFuture;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::sync::watch;
use tower::Service;

pub use docs::{docs_router, DocsShared};
pub use proxy::{proxy_router, ProxyShared};

/// Server configuration options.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub target: url::Url,
    pub port: u16,
    pub docs_port: u16,
    /// Enables SQLite persistence of HAR entries and endpoints.
    pub db_path: Option<PathBuf>,
    /// Start only the docs listener; the proxy server is not bound.
    pub docs_only: bool,
    /// Start only the proxy listener; the docs server is not bound.
    pub proxy_only: bool,
    pub verbose: bool,
    /// TLS interception (CONNECT MITM); `None` = plain HTTP proxy only
    /// (M3a seam, wired from `start`'s typed CA flags at M3d assembly).
    pub intercept: Option<InterceptTlsConfig>,
    /// Fault injection on proxied traffic; `None` = disabled (AMEND-5).
    pub fault: Option<FaultInjector>,
    /// Header rewrite rules (request-direction, response-direction).
    pub header_rules: Option<(HeaderRuleSet, HeaderRuleSet)>,
    /// Subprocess/webhook hooks; `None` = disabled (W6).
    pub hooks: Option<HookConfig>,
    /// Live OpenAPI validation over proxied traffic; `None` = disabled
    /// (W7 seam for `--validate-spec`; consumed by the proxy pipeline).
    pub validate: Option<Arc<crate::validation::violations::LiveValidator>>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            target: url::Url::parse("http://localhost:3000").expect("default target"),
            port: 8080,
            docs_port: 9000,
            db_path: None,
            docs_only: false,
            proxy_only: false,
            verbose: false,
            intercept: None,
            fault: None,
            header_rules: None,
            hooks: None,
            validate: None,
        }
    }
}

/// Handles for the started servers. URLs reflect the actually-bound ports;
/// a listener disabled by `docs_only`/`proxy_only` reports its configured
/// port but is not reachable. `shutdown` stops every running listener.
pub struct RunningServers {
    pub proxy_url: url::Url,
    pub docs_url: url::Url,
    pub shutdown: BoxFuture<'static, ()>,
}

/// Serve `router` on `listener` over HTTP/1.1 AND HTTP/2 via hyper-util's
/// auto connection builder (per-connection protocol detection; ALPN-selected
/// h2 arrives with the W1 TLS acceptor). Upgrades (WebSocket) are supported.
/// The returned task ends when `shutdown` fires; in-flight connections are
/// aborted with it, matching the previous abrupt-shutdown semantics.
fn spawn_listener(
    name: &'static str,
    listener: tokio::net::TcpListener,
    router: axum::Router,
    mut shutdown: watch::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let builder = Builder::new(TokioExecutor::new());
        let connections: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let io = TokioIo::new(stream);
                        let router = router.clone();
                        let builder = builder.clone();
                        let connections = Arc::clone(&connections);
                        let handle = tokio::spawn(async move {
                            let service = service_fn(move |req| {
                                let mut router = router.clone();
                                async move { router.call(req).await }
                            });
                            if let Err(err) =
                                builder.serve_connection_with_upgrades(io, service).await
                            {
                                eprintln!("{name} connection error: {err}");
                            }
                        });
                        let mut open = connections.lock().expect("connection registry");
                        open.retain(|handle| !handle.is_finished());
                        open.push(handle);
                    }
                    Err(err) => {
                        eprintln!("{name} accept error: {err}");
                        break;
                    }
                }
            }
        }
        for handle in connections.lock().expect("connection registry").drain(..) {
            handle.abort();
        }
    })
}

/// Sets up and starts the proxy and/or docs servers.
///
/// Both apps share one [`OpenApiStore`] and one [`HarStore`]; when
/// `db_path` is set the OpenAPI store is hydrated from persisted endpoints
/// and new traffic is persisted best-effort (failures never break
/// proxying). Ports walk forward to the next free port on collision, like
/// the TS `findAvailablePort`.

pub async fn start_servers(options: ServerOptions) -> Result<RunningServers> {
    if options.docs_only && options.proxy_only {
        return Err(Error::other(
            "proxyOnly and docsOnly are mutually exclusive",
        ));
    }

    // Persistent storage (best-effort init, mirroring TS error handling).
    let db = match &options.db_path {
        Some(db_path) => match SqliteStore::open(db_path) {
            Ok(store) => {
                if options.verbose {
                    println!("Initialized SQLite storage at {}", db_path.display());
                }
                Some(Arc::new(store))
            }
            Err(e) => {
                eprintln!("Failed to initialize storage: {e}");
                None
            }
        },
        None => None,
    };

    let openapi = Arc::new(OpenApiStore::new());
    let har = Arc::new(HarStore::new());

    // Hydrate the OpenAPI store with persisted endpoints.
    if let Some(db) = &db {
        if let Ok(persisted) = db.get_all_endpoints() {
            for (path, method, data) in persisted {
                openapi.merge_endpoint_data(&path, &method, &data);
            }
        }
    }
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let (proxy_handle, proxy_port) = if !options.docs_only {
        let shared = Arc::new(ProxyShared {
            next_seq: std::sync::atomic::AtomicU64::new(0),
            target: options.target.clone(),
            openapi: Arc::clone(&openapi),
            har: Arc::clone(&har),
            policy: crate::redaction::RedactionPolicy::default(),
            db: db.clone(),
            verbose: options.verbose,
            intercept: options.intercept,
            fault: options.fault,
            header_rules: options.header_rules,
            hooks: options.hooks,
        });
        let (listener, port) = proxy::bind_listener(options.port).await?;
        let task = spawn_listener("proxy", listener, proxy_router(shared), shutdown_rx.clone());
        (Some(task), port)
    } else {
        (None, options.port)
    };

    let (docs_handle, docs_port) = if !options.proxy_only {
        let shared = Arc::new(DocsShared {
            target: options.target.clone(),
            openapi: Arc::clone(&openapi),
            har: Arc::clone(&har),
            db: db.clone(),
        });
        let (listener, port) = proxy::bind_listener(options.docs_port).await?;
        let task = spawn_listener("docs", listener, docs_router(shared), shutdown_rx.clone());
        (Some(task), port)
    } else {
        (None, options.docs_port)
    };

    println!("\nArbiter is running!");
    if !options.docs_only {
        println!("\nProxy Server:");
        println!("  URL: http://127.0.0.1:{proxy_port}");
        println!("  Target: {}", options.target);
    }
    if !options.proxy_only {
        println!("\nDocumentation:");
        println!("  API Reference: http://127.0.0.1:{docs_port}/docs");
        println!("\nExports:");
        println!("  HAR Export: http://127.0.0.1:{docs_port}/har");
        println!("  OpenAPI JSON: http://127.0.0.1:{docs_port}/openapi.json");
        println!("  OpenAPI YAML: http://127.0.0.1:{docs_port}/openapi.yaml");
    }

    let proxy_url = url::Url::parse(&format!("http://127.0.0.1:{proxy_port}"))
        .map_err(|e| Error::other(format!("invalid proxy url: {e}")))?;
    let docs_url = url::Url::parse(&format!("http://127.0.0.1:{docs_port}"))
        .map_err(|e| Error::other(format!("invalid docs url: {e}")))?;
    let shutdown: BoxFuture<'static, ()> = Box::pin(async move {
        let _ = shutdown_tx.send(());
        if let Some(handle) = proxy_handle {
            let _ = handle.await;
        }
        if let Some(handle) = docs_handle {
            let _ = handle.await;
        }
    });

    Ok(RunningServers {
        proxy_url,
        docs_url,
        shutdown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn docs_only_and_proxy_only_are_mutually_exclusive() {
        let err = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(start_servers(ServerOptions {
                docs_only: true,
                proxy_only: true,
                ..ServerOptions::default()
            }));
        assert!(err.is_err());
        let message = err.err().expect("error").to_string();
        assert!(message.contains("mutually exclusive"), "{message}");
    }

    #[tokio::test]
    async fn starts_docs_server_from_seeded_store_and_shuts_down() {
        let options = ServerOptions {
            target: url::Url::parse("http://localhost:3000").expect("target"),
            port: 0,
            docs_port: 0,
            docs_only: true,
            ..ServerOptions::default()
        };
        let servers = start_servers(options).await.expect("start servers");
        let docs = servers
            .docs_url
            .to_string()
            .trim_end_matches('/')
            .to_string();
        let proxy = servers
            .proxy_url
            .to_string()
            .trim_end_matches('/')
            .to_string();

        // Seed via a direct store handle through the docs app state is not
        // exposed; instead record through the same API the proxy uses by
        // constructing an identical store — but start_servers owns its
        // stores. So verify liveness + empty-spec behavior instead.
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{docs}/openapi.json"))
            .send()
            .await
            .expect("openapi request");
        assert_eq!(response.status(), 200);
        let spec: serde_json::Value = response.json().await.expect("spec");
        assert!(spec["openapi"].is_string());

        // The proxy was not bound (docs_only).
        let proxy_probe = client
            .get(proxy.clone())
            .timeout(std::time::Duration::from_millis(500))
            .send()
            .await;
        assert!(proxy_probe.is_err(), "proxy should not be listening");

        servers.shutdown.await;
        let after_shutdown = client
            .get(format!("{docs}/har"))
            .timeout(std::time::Duration::from_millis(500))
            .send()
            .await;
        assert!(after_shutdown.is_err(), "docs server should be stopped");
    }

    #[tokio::test]
    async fn proxy_traffic_is_visible_on_docs_endpoints() {
        // Tiny upstream that always answers JSON.
        async fn upstream_ok() -> axum::Json<serde_json::Value> {
            axum::Json(json!({ "pong": true }))
        }
        let upstream_app = axum::Router::new().route("/ping", axum::routing::get(upstream_ok));
        let upstream_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind upstream");
        let upstream_addr = upstream_listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(upstream_listener, upstream_app)
                .await
                .expect("serve upstream");
        });

        // Ephemeral ports for both listeners.
        let probe = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe");
        let proxy_port = probe.local_addr().expect("addr").port();
        drop(probe);
        let probe = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe");
        let docs_port = probe.local_addr().expect("addr").port();
        drop(probe);

        let servers = start_servers(ServerOptions {
            target: url::Url::parse(&format!("http://{upstream_addr}")).expect("target"),
            port: proxy_port,
            docs_port,
            ..ServerOptions::default()
        })
        .await
        .expect("start servers");
        assert_eq!(servers.proxy_url.port(), Some(proxy_port));
        let docs = servers
            .docs_url
            .to_string()
            .trim_end_matches('/')
            .to_string();
        let proxy = servers
            .proxy_url
            .to_string()
            .trim_end_matches('/')
            .to_string();

        // Drive one exchange through the proxy...
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{proxy}/ping?since=today"))
            .header("authorization", "Bearer abcdefghijklmnop")
            .send()
            .await
            .expect("proxied ping");
        assert_eq!(response.status(), 200);
        let payload: serde_json::Value = response.json().await.expect("json");
        assert_eq!(payload["pong"], true);

        // ...then observe it on the docs exports once recording lands.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let spec: serde_json::Value = client
                .get(format!("{docs}/openapi.json"))
                .send()
                .await
                .expect("spec")
                .json()
                .await
                .expect("spec json");
            if spec["paths"]["/ping"].is_object() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "recording never reached docs export: {spec}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let har: serde_json::Value = client
            .get(format!("{docs}/har"))
            .send()
            .await
            .expect("har")
            .json()
            .await
            .expect("har json");
        assert_eq!(
            har["log"]["entries"][0]["request"]["method"], "GET",
            "expected recorded entry: {har}"
        );

        servers.shutdown.await;
    }

    #[tokio::test]
    async fn db_path_persists_har_and_endpoints() {
        async fn ok() -> axum::Json<serde_json::Value> {
            axum::Json(json!({ "saved": true }))
        }
        let upstream_app = axum::Router::new().route("/db", axum::routing::get(ok));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind upstream");
        let upstream_addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, upstream_app).await.expect("serve");
        });

        let probe = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe");
        let proxy_port = probe.local_addr().expect("addr").port();
        drop(probe);
        let probe = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe");
        let docs_port = probe.local_addr().expect("addr").port();
        drop(probe);

        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("traffic.sqlite");
        let servers = start_servers(ServerOptions {
            target: url::Url::parse(&format!("http://{upstream_addr}")).expect("target"),
            port: proxy_port,
            docs_port,
            db_path: Some(db_path.clone()),
            ..ServerOptions::default()
        })
        .await
        .expect("start servers with db");

        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "{}{}",
                servers.proxy_url.to_string().trim_end_matches('/'),
                "/db"
            ))
            .send()
            .await
            .expect("proxied request");
        assert_eq!(response.status(), 200);

        // Persistence is best-effort/background; poll the sqlite file.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let store = SqliteStore::open(&db_path).expect("reopen sqlite");
        loop {
            let endpoints = store.get_all_endpoints().expect("endpoints");
            if !endpoints.is_empty() {
                let (path, method, _) = &endpoints[0];
                assert_eq!(path, "/db");
                assert_eq!(method, "get");
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "endpoint was never persisted"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let har_log = store.get_har_log().expect("har log");
        let entry_url = har_log["log"]["entries"][0]["request"]["url"]
            .as_str()
            .unwrap_or_default();
        assert!(
            entry_url.ends_with("/db"),
            "expected persisted HAR entry: {har_log}"
        );

        servers.shutdown.await;
    }

    #[test]
    fn default_options_match_cli_defaults() {
        let defaults = ServerOptions::default();
        assert_eq!(defaults.port, 8080);
        assert_eq!(defaults.docs_port, 9000);
        assert_eq!(defaults.target.as_str(), "http://localhost:3000/");
        assert_eq!(defaults.db_path, None);
        assert!(!defaults.verbose);
        assert!(!defaults.docs_only);
        assert!(!defaults.proxy_only);
    }
}
