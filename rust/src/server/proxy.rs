//! Transparent recording proxy (`start_servers` proxy app).
//!
//! Ports the proxy half of `src/server.ts`: forwards method, path+query and
//! forwardable headers (host stripped) to the target origin with raw body
//! bytes, streams the upstream response back unmodified minus hop-by-hop and
//! framing headers, and records HAR + OpenAPI data in a background task so
//! recording never delays proxying. Credential values are redacted before
//! they reach the HAR store, OpenAPI store, or SQLite; only the auth *style*
//! (bearer / basic / apiKey header name) is derived from the original
//! headers via [`crate::auth::detect_security_schemes`].

use std::sync::{Arc, LazyLock};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Router;
use futures::future::BoxFuture;
use futures::SinkExt;
use futures::StreamExt;
use serde_json::json;

use crate::auth::detect_security_schemes;
use crate::mock::fault::{FaultDecision, FaultInjector};

use crate::error::{Error, Result};
use crate::headers::{
    forwardable_headers, from_http_header_map, is_hop_by_hop, to_http_header_map,
};
use crate::middleware::{build_har_entry, HarEntryParts, HarStore};
use crate::redaction::{RedactionPolicy, REDACTED_VALUE};
use crate::rules::hooks::{run_request_hook, run_response_hook, HookConfig, HookContext};
use crate::rules::HeaderRuleSet;
use crate::server::connect::parse_authority;
use crate::server::intercept::{serve_intercepted, InterceptTlsConfig};
use crate::storage::SqliteStore;
use crate::store::OpenApiStore;
use crate::types::HeaderMapValues;
use crate::ws::is_websocket_upgrade;

/// Request body ceiling, mirroring the TS `bodyParser` 10 MB limits.
pub const MAX_REQUEST_BYTES: usize = 10 * 1024 * 1024;

/// Path suffixes whose traffic is never recorded (web assets).
const SKIPPED_EXTENSIONS: [&str; 9] = [
    ".js", ".css", ".html", ".htm", ".woff", ".woff2", ".ttf", ".eot", ".map",
];

/// Content types whose traffic is never recorded (images are kept, like TS).
const SKIPPED_CONTENT_FRAGMENTS: [&str; 4] = ["javascript", "css", "html", "font/"];

tokio::task_local! {
    /// CONNECT tunnel metadata for the current decrypted connection. Set by
    /// the intercepted-connection handler before the pipeline runs; consumed
    /// when `RecordMeta` is built so exchanges carry tunnel evidence.
    static CONN_TUNNEL: std::cell::RefCell<Option<crate::types::TunnelInfo>>;
    /// Proxy-chaining depth for nested CONNECT tunnels. Top-level requests
    /// read 0 (no enclosing scope); each nested tunnel increments. Hard cap
    /// [`MAX_NESTED_CONNECT`] stops malicious CONNECT loops.
    static CONN_DEPTH: std::cell::Cell<u64>;
}

pub struct ProxyShared {
    pub target: url::Url,
    /// Monotonic per-process exchange counter for hook contexts.
    pub(crate) next_seq: std::sync::atomic::AtomicU64,
    pub openapi: Arc<OpenApiStore>,
    pub har: Arc<HarStore>,
    pub policy: RedactionPolicy,
    /// Subprocess/webhook hooks; `None` = disabled.
    pub hooks: Option<HookConfig>,
    /// Live OpenAPI validation; `None` = disabled (W7 `--validate-spec`).
    pub validate: Option<std::sync::Arc<crate::validation::violations::LiveValidator>>,
    pub db: Option<Arc<SqliteStore>>,
    pub verbose: bool,
    /// TLS interception config; `Some` enables CONNECT MITM (M3a).
    pub intercept: Option<InterceptTlsConfig>,
    /// Fault injector shared by proxy mode (AMEND-5); `None` = disabled.
    pub fault: Option<FaultInjector>,
    /// Ordered header rewrite rules: (request-direction, response-direction).
    pub header_rules: Option<(HeaderRuleSet, HeaderRuleSet)>,
}

impl ProxyShared {
    fn next_sequence(&self) -> u64 {
        self.next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn new(target: url::Url) -> Self {
        Self {
            target,
            next_seq: std::sync::atomic::AtomicU64::new(0),
            openapi: Arc::new(OpenApiStore::new()),
            har: Arc::new(HarStore::new()),
            policy: RedactionPolicy::default(),
            db: None,
            verbose: false,
            intercept: None,
            fault: None,
            header_rules: None,
            hooks: None,
            validate: None,
        }
    }
}

fn proxy_client() -> &'static reqwest::Client {
    static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        reqwest::Client::builder()
            // A transparent proxy passes redirects through to the caller
            // instead of following them itself.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build reqwest client")
    });
    &CLIENT
}

/// The axum app that forwards every request to the target origin.
pub fn proxy_router(shared: Arc<ProxyShared>) -> Router {
    Router::new().fallback(proxy_handler).with_state(shared)
}

async fn proxy_handler(State(shared): State<Arc<ProxyShared>>, req: Request) -> Response {
    handle_request(shared, req).await
}

/// Plain entry point shared by the axum router and TLS-intercepted
/// connections (M3a): every request funnels here exactly once.
async fn handle_request(shared: Arc<ProxyShared>, req: Request) -> Response {
    // The pipeline handed to TLS-intercepted streams: plain HTTP entry that
    // rejects nested CONNECT (proxy chaining) — this keeps the handler tree
    // free of static recursion, so futures stay Send.
    let shared_for_pipeline = Arc::clone(&shared);
    let pipeline: crate::server::intercept::InterceptHandler = Arc::new(move |decrypted| {
        let shared = Arc::clone(&shared_for_pipeline);
        Box::pin(async move {
            if decrypted.method() == http::Method::CONNECT {
                return plain_response(
                    StatusCode::NOT_IMPLEMENTED,
                    "text/plain",
                    "nested CONNECT is not supported",
                );
            }
            let decrypted = decrypted.map(axum::body::Body::new);
            handle_request_core(shared, decrypted).await
        })
    });
    // Top-level CONNECT tunnels hijack the connection before body handling.
    if req.method() == http::Method::CONNECT {
        return handle_connect(shared, 0, pipeline, req).await;
    }
    let req = req.map(axum::body::Body::new);
    handle_request_core(shared, req).await
}

/// Core non-CONNECT pipeline (fault gate, hooks, rules, upstream, record).
async fn handle_request_core(shared: Arc<ProxyShared>, req: Request) -> Response {
    let started_at_ms = chrono::Utc::now().timestamp_millis();
    let method = req.method().clone();

    // Per-request origin: intercepted traffic arrives in absolute form
    // (https + CONNECT authority); reverse-proxy mode uses path form
    // against the configured target.
    let target_origin = resolve_origin(&shared, req.uri());

    if shared.verbose {
        println!("Proxying: {} {}", method, req.uri());
    }

    let path = req.uri().path().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let raw_query = req.uri().query().unwrap_or("").to_string();
    let mut request_headers = from_http_header_map(req.headers());

    // M3b: WebSocket upgrades bypass body buffering entirely.
    if is_websocket_upgrade(req.headers()) {
        return handle_websocket(
            Arc::clone(&shared),
            req,
            started_at_ms,
            path_and_query,
            request_headers,
        )
        .await;
    }

    // Buffer the raw request body (byte-exact, like the TS raw bodyParser).
    let mut request_body = match axum::body::to_bytes(req.into_body(), MAX_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return plain_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "text/plain",
                "request body too large",
            )
        }
    };

    // M3c pipeline order (AMEND-12): fault gate -> request hooks ->
    // request header rules -> upstream -> tee-pump (unchanged) ->
    // response header rules (pre-stream) -> response hooks (buffered) ->
    // client.

    // Fault gate FIRST: one atomic draw decides everything (AMEND-5).
    let fault_decision = shared.fault.as_ref().map(|f| f.inject_before_upstream());
    if let Some(decision) = &fault_decision {
        if let Some(delay) = decision.delay() {
            tokio::time::sleep(delay).await;
        }
        match decision {
            FaultDecision::Reset => return reset_connection_response(),
            FaultDecision::Timeout => {
                // AMEND-5: the client-facing faulted response is captured.
                let recorder = Arc::clone(&shared);
                let r_method = method.to_string();
                let r_body = request_body.clone();
                let mut headers: HeaderMapValues = Default::default();
                headers.insert("content-length".into(), vec!["0".into()]);
                tokio::task::spawn_blocking(move || {
                    record_exchange(
                        &recorder,
                        RecordMeta {
                            started_at_ms,
                            time_ms: chrono::Utc::now().timestamp_millis() - started_at_ms,
                            method: r_method,
                            path: path.clone(),
                            raw_query: raw_query.clone(),
                            request_headers: request_headers.clone(),
                            request_body: r_body,
                            status: 504,
                            tunnel: None,
                            validation_seq: 0,
                            response_headers: headers,
                        },
                        &[],
                    );
                });
                return plain_response(StatusCode::GATEWAY_TIMEOUT, "text/plain", "");
            }
            FaultDecision::Status(_) | FaultDecision::Garbage => {
                let mut status = 200u16;
                let mut body = Vec::new();
                let mut content_type = String::from("application/json");
                let replaced = shared
                    .fault
                    .as_ref()
                    .expect("decision implies injector")
                    .apply_to_response(decision, &mut status, &mut body, &mut content_type);
                debug_assert!(replaced);
                // AMEND-5: the faulted client-facing response IS what gets
                // captured.
                let mut headers: HeaderMapValues = Default::default();
                headers.insert("content-type".into(), vec![content_type.clone()]);
                let recorder = Arc::clone(&shared);
                let r_method = method.to_string();
                let r_body = request_body.clone();
                let ct = content_type.clone();
                let b = body.clone();
                tokio::task::spawn_blocking(move || {
                    record_exchange(
                        &recorder,
                        RecordMeta {
                            started_at_ms,
                            time_ms: chrono::Utc::now().timestamp_millis() - started_at_ms,
                            method: r_method,
                            path: path.clone(),
                            raw_query: raw_query.clone(),
                            request_headers: request_headers.clone(),
                            request_body: r_body,
                            status,
                            tunnel: None,
                            validation_seq: 0,
                            response_headers: {
                                let mut h: HeaderMapValues = Default::default();
                                h.insert("content-type".into(), vec![ct]);
                                h
                            },
                        },
                        &b,
                    );
                });
                let mut builder = Response::builder().status(
                    StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                );
                if let Ok(v) = http::HeaderValue::from_str(&content_type) {
                    builder = builder.header("content-type", v);
                }
                return builder.body(Body::from(body)).unwrap_or_else(|_| {
                    plain_response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", "")
                });
            }
            FaultDecision::Latency(_) | FaultDecision::None => {}
        }
    }

    // Request hooks (subprocess/webhook). Fail-open on timeout; Drop means
    // the hook explicitly rejected the exchange.
    if let Some(hooks) = &shared.hooks {
        if hooks.is_configured() {
            let seq = shared.next_sequence();
            let ctx = HookContext {
                sequence: seq,
                method: method.to_string(),
                path: path.clone(),
                query: raw_query.clone(),
                headers: redacted_view(&request_headers, &shared.policy),
                body: Some(&request_body),
            };
            match run_request_hook(hooks, &ctx).await {
                crate::rules::hooks::HookOutcome::Unchanged => {}
                crate::rules::hooks::HookOutcome::Modified(modified) => {
                    modified.apply_headers(&mut request_headers);
                    if let Some(body) = modified.decoded_body() {
                        request_body = axum::body::Bytes::from(body);
                    }
                }
                crate::rules::hooks::HookOutcome::Drop => {
                    return plain_response(
                        StatusCode::BAD_GATEWAY,
                        "application/json",
                        "{\"error\":\"dropped by request hook\"}",
                    );
                }
            }
        }
    }

    // Request-direction header rules apply before forwarding decisions.
    if let Some((request_rules, _)) = &shared.header_rules {
        request_rules.apply(&mut request_headers);
    }

    // Live OpenAPI validation, request leg (W7). Runs on the final forwarded
    // headers/body; the paired response leg happens inside record_exchange.
    // Violations are recorded best-effort and never alter the traffic.
    let validation_seq = if let Some(validator) = shared.validate.as_ref() {
        let seq = shared.next_sequence();
        let violations = validator.validate_request_parts(
            seq,
            method.as_str(),
            &path_and_query,
            &raw_query,
            &request_headers,
            Some(&request_body),
        );
        if !violations.is_empty() {
            validator.collector.record(seq, violations);
        }
        seq
    } else {
        0
    };

    // Forward end-to-end headers only; the client re-computes framing and
    // derives Host from the upstream URL (changeOrigin semantics).
    let forward_headers = to_http_header_map(&forwardable_headers(&request_headers, true));
    let upstream_url = match target_origin.join(&path_and_query) {
        Ok(url) => url,
        Err(e) => return proxy_error_response(&e.to_string()),
    };

    let mut upstream_request = proxy_client()
        .request(method.clone(), upstream_url)
        .headers(forward_headers);
    let body_bearing = !matches!(method, axum::http::Method::GET | axum::http::Method::HEAD);
    if body_bearing {
        upstream_request = upstream_request.body(reqwest::Body::from(request_body.to_vec()));
    }

    let upstream_response = match upstream_request.send().await {
        Ok(response) => response,
        Err(e) => return proxy_error_response(&e.to_string()),
    };

    let status = upstream_response.status();
    let mut response_headers = from_http_header_map(upstream_response.headers());

    // Response-direction header rules apply before anything reaches the
    // client (safe: headers have not been sent yet).
    if let Some((_, response_rules)) = &shared.header_rules {
        response_rules.apply(&mut response_headers);
    }

    // End-to-end response headers only; framing is managed by the HTTP layer
    // (forwarding `transfer-encoding`/`content-length` corrupts streaming).
    let mut passthrough_headers = HeaderMapValues::new();
    for name in response_headers.keys() {
        if is_hop_by_hop(name) || name == "content-length" {
            continue;
        }
        if let Some(values) = response_headers.get(name) {
            passthrough_headers.insert(name.clone(), values.clone());
        }
    }

    // Response hooks need the complete body to reason about it: when
    // configured, switch to buffered mode for this exchange.
    if let Some(hooks) = &shared.hooks {
        if hooks.response_cmd.is_some() || hooks.webhook_url.is_some() {
            return buffered_response_with_hook(
                shared,
                upstream_response,
                RecordMeta {
                    started_at_ms,
                    time_ms: 0,
                    method: method.to_string(),
                    path,
                    raw_query,
                    request_headers,
                    request_body,
                    status: status.as_u16(),
                    response_headers,
                    tunnel: None,
                    validation_seq,
                },
                passthrough_headers,
            )
            .await;
        }
    }

    stream_response(
        shared,
        upstream_response,
        RecordMeta {
            started_at_ms,
            time_ms: chrono::Utc::now().timestamp_millis() - started_at_ms,
            method: method.to_string(),
            path,
            raw_query,
            request_headers,
            request_body,
            status: status.as_u16(),
            response_headers,
            tunnel: None,
            validation_seq,
        },
        passthrough_headers,
        status,
    )
    .await
}

/// Origin for the upstream request: absolute-form URIs come from TLS-
/// intercepted connections (the CONNECT authority); otherwise the
/// configured target.
fn resolve_origin(shared: &ProxyShared, uri: &http::Uri) -> url::Url {
    if let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) {
        let origin = format!("{}://{}", scheme, authority);
        if let Ok(u) = url::Url::parse(&origin) {
            return u;
        }
    }
    shared.target.clone()
}

fn split_authority_for_tunnel(authority: &str) -> (String, u16) {
    match parse_authority(authority) {
        Ok(t) => (t.host, t.port),
        Err(_) => (authority.to_string(), 443),
    }
}

/// M3a: CONNECT handling. With interception configured, answer the tunnel
/// and hand the decrypted stream to the normal pipeline; without a CA,
/// tunnel bytes untouched to the authority (explicit-proxy behavior).
/// Entry point for CONNECT handling. Boxes the body once so the chained
/// recursion (`intercepted CONNECT -> handle_connect`) stays `Send` without
/// infinite type recursion.
fn handle_connect(
    shared: Arc<ProxyShared>,
    depth: u64,
    pipeline: crate::server::intercept::InterceptHandler,
    req: Request,
) -> BoxFuture<'static, Response> {
    Box::pin(handle_connect_inner(shared, depth, pipeline, req))
}

async fn handle_connect_inner(
    shared: Arc<ProxyShared>,
    depth: u64,
    pipeline: crate::server::intercept::InterceptHandler,
    mut req: Request,
) -> Response {
    let authority = req.uri().to_string();
    if depth >= MAX_NESTED_CONNECT {
        return plain_response(
            StatusCode::BAD_GATEWAY,
            "application/json",
            "{\"error\":\"CONNECT chain too deep\"}",
        );
    }
    match shared.intercept.clone() {
        Some(cfg) => {
            // 200-with-upgrade, then take ownership of the raw TCP stream.
            let upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                match upgrade.await {
                    Ok(io) => {
                        // The pipeline is injected (dyn), not called
                        // statically: this breaks the type-level recursion
                        // that made the future !Send.
                        let handler_authority = authority.clone();
                        let (t_host, t_port) = split_authority_for_tunnel(&handler_authority);
                        let handler: crate::server::intercept::InterceptHandler =
                            Arc::new(move |mut decrypted| {
                                let pipeline = Arc::clone(&pipeline);
                                let shared = Arc::clone(&shared);
                                let authority = handler_authority.clone();
                                let tunnel = Some(crate::types::TunnelInfo {
                                    host: t_host.clone(),
                                    port: t_port,
                                    intercepted: true,
                                    alpn: None,
                                });
                                Box::pin(CONN_DEPTH.scope(
                                    std::cell::Cell::new(depth + 1),
                                    async move {
                                        // Proxy chaining: a CONNECT inside the
                                        // decrypted stream opens another tunnel.
                                        if decrypted.method() == http::Method::CONNECT {
                                            // Self-recursion must be boxed
                                            // (E0733) or the future is !Send.
                                            let decrypted = decrypted.map(axum::body::Body::new);
                                            return handle_connect(
                                                shared,
                                                depth + 1,
                                                pipeline,
                                                decrypted,
                                            )
                                            .await;
                                        }
                                        CONN_TUNNEL
                                            .scope(std::cell::RefCell::new(tunnel), async move {
                                                let path_q = decrypted
                                                    .uri()
                                                    .path_and_query()
                                                    .map(|p| p.as_str().to_string())
                                                    .unwrap_or_else(|| "/".to_string());
                                                let absolute =
                                                    format!("https://{authority}{path_q}");
                                                if let Ok(u) = absolute.parse() {
                                                    *decrypted.uri_mut() = u;
                                                }
                                                pipeline(decrypted).await
                                            })
                                            .await
                                    },
                                ))
                            });
                        if let Err(e) = serve_intercepted(
                            hyper_util::rt::TokioIo::new(io),
                            std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                            &authority,
                            cfg,
                            handler,
                        )
                        .await
                        {
                            eprintln!("intercepted tunnel {authority} failed: {e}");
                        }
                    }
                    Err(e) => eprintln!("CONNECT upgrade for {authority} failed: {e}"),
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap_or_else(|_| {
                    plain_response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", "")
                })
        }
        None => {
            // Pure tunnel: dial the authority and copy bytes both ways.
            let upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                match upgrade.await {
                    Ok(client_io) => match parse_authority(&authority) {
                        Ok(target) => {
                            match tokio::net::TcpStream::connect((
                                target.host.as_str(),
                                target.port,
                            ))
                            .await
                            {
                                Ok(mut upstream) => {
                                    let mut client_io = hyper_util::rt::TokioIo::new(client_io);
                                    let _ = tokio::io::copy_bidirectional(
                                        &mut client_io,
                                        &mut upstream,
                                    )
                                    .await;
                                }
                                Err(e) => eprintln!("tunnel dial {authority} failed: {e}"),
                            }
                        }
                        Err(e) => eprintln!("bad CONNECT authority {authority}: {e}"),
                    },
                    Err(e) => eprintln!("CONNECT upgrade for {authority} failed: {e}"),
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap_or_else(|_| {
                    plain_response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", "")
                })
        }
    }
}

/// M3b: WebSocket relay for the standalone proxy. The handshake is forwarded
/// verbatim; on 101 both upgraded legs are pumped through the shared WS pump,
/// which records messages into a minimal HAR entry (best-effort; byte-exact ws
/// capture lives in capture sessions).
async fn handle_websocket(
    shared: Arc<ProxyShared>,
    req: Request,
    _started_at_ms: i64,
    path_and_query: String,
    request_headers: HeaderMapValues,
) -> Response {
    let target_origin = resolve_origin(&shared, req.uri());
    let upstream_url = match target_origin.join(&path_and_query) {
        Ok(u) => u,
        Err(e) => return proxy_error_response(&e.to_string()),
    };

    // Forward with hop-by-hop upgrade headers restored.
    let forwardable_ws: HeaderMapValues = request_headers
        .iter()
        .filter(|(name, _)| !name.starts_with("sec-websocket-"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let forward = to_http_header_map(&forwardable_headers(&forwardable_ws, true));
    let method = req.method().clone();
    let mut upstream_request = proxy_client()
        .request(method.clone(), upstream_url)
        .headers(forward)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket");
    if let Some(key) = request_headers.get("sec-websocket-key") {
        if let Some(v) = key.first() {
            upstream_request = upstream_request.header("sec-websocket-key", v);
        }
    }
    if let Some(protos) = request_headers.get("sec-websocket-protocol") {
        if let Some(v) = protos.first() {
            upstream_request = upstream_request.header("sec-websocket-protocol", v);
        }
    }
    if let Some(version) = request_headers.get("sec-websocket-version") {
        if let Some(v) = version.first() {
            upstream_request = upstream_request.header("sec-websocket-version", v);
        }
    }

    let upstream_response = match upstream_request.send().await {
        Ok(r) => r,
        Err(e) => return proxy_error_response(&e.to_string()),
    };
    if upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return plain_response(
            upstream_response.status(),
            "application/json",
            "{\"error\":\"upstream refused websocket upgrade\"}",
        );
    }

    // Mirror the 101 + accept/protocol to the client, then upgrade locally.
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "websocket");
    if let Some(accept) = upstream_response.headers().get("sec-websocket-accept") {
        builder = builder.header("sec-websocket-accept", accept);
    }
    if let Some(proto) = upstream_response.headers().get("sec-websocket-protocol") {
        builder = builder.header("sec-websocket-protocol", proto);
    }
    let response = builder
        .body(Body::empty())
        .unwrap_or_else(|_| plain_response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", ""));

    // Take ownership of the client's upgraded IO and pump both legs through
    // the shared WS recorder. Frames are relayed unmodified; the HAR entry
    // records message counts (byte-exact ws capture lives in capture
    // sessions).
    let mut req = req;
    let server_upgrade = hyper::upgrade::on(&mut req);
    let protocol = request_headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.first().cloned());
    let record_method = method.to_string();
    let record_path = format!("/{}", path_and_query.trim_start_matches('/'));
    tokio::spawn(async move {
        let client_up = server_upgrade.await;
        let upstream_up = upstream_response.upgrade().await;
        let report = |e: String| eprintln!("websocket upgrade failed: {e}");
        match (client_up, upstream_up) {
            (Ok(client_io), Ok(upstream_io)) => {
                // Client leg is hyper's Upgraded (runtime-agnostic): wrap for
                // tokio IO; upstream leg is reqwest's Upgraded (tokio-native).
                let result = crate::ws::pump_ws(
                    hyper_util::rt::TokioIo::new(client_io),
                    upstream_io,
                    crate::ws::WsCaptureMeta {
                        protocol,
                        ..Default::default()
                    },
                )
                .await;
                record_ws_har(
                    &shared,
                    &record_method,
                    &record_path,
                    result.stream.messages.len(),
                );
                if shared.verbose {
                    println!(
                        "ws relay complete: {} messages",
                        result.stream.messages.len()
                    );
                }
            }
            (Err(e), _) => report(e.to_string()),
            (_, Err(e)) => report(e.to_string()),
        }
    });
    response
}

/// Minimal synchronous record of a completed WS session into the HAR store.
fn record_ws_har(shared: &ProxyShared, method: &str, path: &str, messages: usize) {
    let har_entry = build_har_entry(&HarEntryParts {
        started_at_ms: chrono::Utc::now().timestamp_millis(),
        time_ms: 0,
        method,
        url: path.to_string(),
        request_headers: &HeaderMapValues::default(),
        query_string: vec![],
        request_content_type: None,
        request_body_text: None,
        status: 101,
        response_headers: &Default::default(),
        response_body: Some(format!(r#"{{"webSocketMessages":{messages}}}"#).as_bytes()),
    });
    shared.har.add_entry(har_entry);
}

/// The default path: pump upstream chunks to the client while teeing into
/// the recording buffer; recording runs after the last chunk on the blocking
/// pool, off the client's critical path.
async fn stream_response(
    shared: Arc<ProxyShared>,
    upstream_response: reqwest::Response,
    meta: RecordMeta,
    passthrough_headers: HeaderMapValues,
    status: http::StatusCode,
) -> Response {
    let (mut tx, rx) = futures::channel::mpsc::channel::<
        std::result::Result<axum::body::Bytes, std::io::Error>,
    >(16);
    tokio::spawn(async move {
        // Bounded-memory recording (perf bar): tee chunks into RAM up to the
        // cap, then spill to a temp file. The client stream is never delayed
        // or truncated by recording; oversized bodies still get recorded
        // byte-exact from the spill file.
        const RECORD_SPILL_CAP: usize = 32 * 1024 * 1024;
        let mut buffer = Vec::new();
        let mut spill: Option<(std::fs::File, std::path::PathBuf)> = None;
        let mut spilled_bytes = 0usize;
        let mut stream = upstream_response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(bytes) => bytes,
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    break;
                }
            };
            if spill.is_none() && buffer.len() + chunk.len() > RECORD_SPILL_CAP {
                let path = std::env::temp_dir().join(format!(
                    "arbiter-record-{}-{}",
                    std::process::id(),
                    meta.started_at_ms
                ));
                match std::fs::File::create(&path) {
                    Ok(mut f) => {
                        use std::io::Write as _;
                        let _ = f.write_all(&buffer);
                        spill = Some((f, path));
                        buffer = Vec::new();
                    }
                    Err(_) => buffer = Vec::new(), // degrade: skip recording this body
                }
            }
            if let Some((f, _)) = &mut spill {
                use std::io::Write as _;
                let _ = f.write_all(&chunk);
                spilled_bytes += chunk.len();
            } else {
                buffer.extend_from_slice(&chunk);
            }
            if tx.send(Ok(chunk)).await.is_err() {
                break; // client went away; keep what we have
            }
        }
        drop(tx);
        // Recording is fully synchronous CPU work (schema inference, JSON
        // tree building, gzip decode). Run it on the blocking pool so it
        // never occupies async worker threads under concurrency.
        let _ = spilled_bytes;
        tokio::task::spawn_blocking(move || {
            let final_body = match spill {
                Some((mut f, path)) => {
                    use std::io::{Read as _, Seek as _};
                    let _ = f.seek(std::io::SeekFrom::Start(0));
                    let mut bytes = Vec::with_capacity(spilled_bytes);
                    let _ = f.read_to_end(&mut bytes);
                    let _ = std::fs::remove_file(&path);
                    bytes
                }
                None => buffer,
            };
            record_exchange(
                &shared,
                RecordMeta {
                    time_ms: chrono::Utc::now().timestamp_millis() - meta.started_at_ms,
                    ..meta
                },
                &final_body,
            );
        });
    });

    let mut builder = Response::builder().status(status);
    for (name, values) in &passthrough_headers {
        if let Ok(header_name) = http::HeaderName::from_bytes(name.as_bytes()) {
            for value in values {
                if let Ok(hv) = http::HeaderValue::from_str(value) {
                    builder = builder.header(header_name.clone(), hv);
                }
            }
        }
    }
    builder
        .body(Body::from_stream(rx))
        .expect("build proxied response")
}

/// Buffered mode when response hooks are configured: the hook needs the full
/// body, so read everything (bounded), run it, apply modifications, record,
/// then answer from memory.
async fn buffered_response_with_hook(
    shared: Arc<ProxyShared>,
    upstream_response: reqwest::Response,
    mut meta: RecordMeta,
    mut passthrough_headers: HeaderMapValues,
) -> Response {
    let mut body = Vec::new();
    let mut stream = upstream_response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                body.extend_from_slice(&bytes);
                if body.len() > MAX_REQUEST_BYTES * 8 {
                    return plain_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "text/plain",
                        "response exceeds buffered-hook limit",
                    );
                }
            }
            Err(_) => break,
        }
    }

    let status = meta.status;
    if let Some(hooks) = &shared.hooks {
        let seq = shared.next_sequence();
        let ctx = HookContext {
            sequence: seq,
            method: meta.method.clone(),
            path: meta.path.clone(),
            query: meta.raw_query.clone(),
            headers: redacted_view(&meta.response_headers, &shared.policy),
            body: Some(&body),
        };
        match run_response_hook(hooks, &ctx).await {
            crate::rules::hooks::HookOutcome::Unchanged => {}
            crate::rules::hooks::HookOutcome::Modified(modified) => {
                // Hook rewrites reach BOTH the record and the client: the
                // client response is built from passthrough_headers.
                modified.apply_headers(&mut passthrough_headers);
                modified.apply_headers(&mut meta.response_headers);
                if let Some(new_body) = modified.decoded_body() {
                    body = new_body;
                }
            }
            crate::rules::hooks::HookOutcome::Drop => {
                return plain_response(
                    StatusCode::BAD_GATEWAY,
                    "application/json",
                    "{\"error\":\"dropped by response hook\"}",
                );
            }
        }
    }

    meta.time_ms = chrono::Utc::now().timestamp_millis() - meta.started_at_ms;
    let recorder = Arc::clone(&shared);
    let m = meta.clone();
    let b = body.clone();
    tokio::task::spawn_blocking(move || record_exchange(&recorder, m, &b));

    let mut builder = Response::builder().status(
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
    );
    for (name, values) in &passthrough_headers {
        if let Ok(header_name) = http::HeaderName::from_bytes(name.as_bytes()) {
            for value in values {
                if let Ok(hv) = http::HeaderValue::from_str(value) {
                    builder = builder.header(header_name.clone(), hv);
                }
            }
        }
    }
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| plain_response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", ""))
}

/// Connection-teardown fault: a body stream that fails immediately makes
/// hyper abort the response mid-flight (the closest a handler can get to an
/// RST without transport control).
fn reset_connection_response() -> Response {
    use futures::stream::once;
    let failing = once(async {
        Err::<axum::body::Bytes, std::io::Error>(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "fault injected",
        ))
    });
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from_stream(failing))
        .unwrap_or_else(|_| plain_response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", ""))
}

/// Redacted view of headers for hook payloads: credential values are masked
/// in place, names and counts preserved.
fn redacted_view(headers: &HeaderMapValues, policy: &RedactionPolicy) -> HeaderMapValues {
    headers
        .iter()
        .map(|(name, values)| {
            if policy.should_redact_header(name) {
                (name.clone(), vec![REDACTED_VALUE.to_string(); values.len()])
            } else {
                (name.clone(), values.clone())
            }
        })
        .collect()
}

#[derive(Clone)]
struct RecordMeta {
    started_at_ms: i64,
    time_ms: i64,
    method: String,
    path: String,
    raw_query: String,
    request_headers: HeaderMapValues,
    request_body: axum::body::Bytes,
    status: u16,
    response_headers: HeaderMapValues,
    /// Sequence used to pair the request-leg validation match with its
    /// response leg in `LiveValidator`'s pending map (`0` = not validated,
    /// e.g. fault-short-circuited exchanges).
    validation_seq: u64,
    /// CONNECT tunnel metadata (intercepted or passthrough); None = plain.
    tunnel: Option<crate::types::TunnelInfo>,
}

/// Background recording: HAR entry, OpenAPI endpoint, and optional SQLite
/// persistence — all best-effort, never failing the proxied exchange.
fn record_exchange(shared: &ProxyShared, mut meta: RecordMeta, response_body: &[u8]) {
    if meta.tunnel.is_none() {
        meta.tunnel = CONN_TUNNEL.try_with(|c| c.borrow().clone()).unwrap_or(None);
    }
    // Live OpenAPI validation, response leg (W7). Runs inside the same
    // blocking task as recording, on the settled (post-hook) body. `seq == 0`
    // marks exchanges that never ran the request leg (fault short-circuit);
    // the pending lookup then behaves like unmatched-path: no violations.
    if let Some(validator) = &shared.validate {
        if meta.validation_seq != 0 {
            let violations = validator.validate_response_parts(
                meta.validation_seq,
                meta.status,
                &meta.response_headers,
                Some(response_body),
            );
            if !violations.is_empty() {
                validator.collector.record(meta.validation_seq, violations);
            }
        }
    }

    let response_content_type = first_value(&meta.response_headers, "content-type")
        .unwrap_or_default()
        .to_string();

    // Skip web assets — don't pollute the spec with JS/CSS/HTML/font noise.
    if SKIPPED_EXTENSIONS
        .iter()
        .any(|ext| meta.path.ends_with(ext))
        || SKIPPED_CONTENT_FRAGMENTS
            .iter()
            .any(|fragment| response_content_type.contains(fragment))
    {
        if shared.verbose {
            println!("Skipping web asset: {} {}", meta.method, meta.path);
        }
        return;
    }

    // Query values whose names look credential-bearing are redacted; benign
    // values are kept for discovery (legacy observe semantics).
    let query_pairs: Vec<(String, String)> = url::form_urlencoded::parse(meta.raw_query.as_bytes())
        .map(|(name, value)| {
            let name = name.into_owned();
            let value = if RedactionPolicy::is_sensitive_name(&name) {
                REDACTED_VALUE.to_string()
            } else {
                value.into_owned()
            };
            (name, value)
        })
        .collect();

    let redact_map = |headers: &HeaderMapValues| -> HeaderMapValues {
        headers
            .iter()
            .map(|(name, values)| {
                let values = values
                    .iter()
                    .map(|value| {
                        if shared.policy.should_redact_header(name) {
                            REDACTED_VALUE.to_string()
                        } else {
                            value.clone()
                        }
                    })
                    .collect();
                (name.clone(), values)
            })
            .collect()
    };
    let request_headers_redacted = redact_map(&meta.request_headers);
    let response_headers_redacted = redact_map(&meta.response_headers);

    let method_lower = meta.method.to_lowercase();
    let body_bearing = matches!(method_lower.as_str(), "post" | "put" | "patch");
    let request_body_bytes: Option<&[u8]> = if body_bearing && !meta.request_body.is_empty() {
        Some(&meta.request_body)
    } else {
        None
    };

    // Security schemes are detected from the ORIGINAL headers — only the
    // scheme shape is recorded, never the value.
    let security: Vec<serde_json::Value> = detect_security_schemes(&meta.request_headers)
        .iter()
        .map(|scheme| serde_json::to_value(scheme).expect("serialize SecurityInfo"))
        .collect();

    let target_origin = shared.target.to_string();
    let target_origin = target_origin.trim_end_matches('/');
    let request_url = if meta.raw_query.is_empty() {
        format!("{target_origin}{}", meta.path)
    } else {
        format!("{target_origin}{}?{}", meta.path, meta.raw_query)
    };
    let request_content_type =
        first_value(&meta.request_headers, "content-type").unwrap_or("application/json");

    let har_entry = build_har_entry(&HarEntryParts {
        started_at_ms: meta.started_at_ms,
        time_ms: meta.time_ms,
        method: &meta.method,
        url: request_url,
        request_headers: &request_headers_redacted,
        query_string: query_pairs.clone(),
        request_content_type: Some(request_content_type),
        request_body_text: request_body_bytes.map(|b| String::from_utf8_lossy(b).into_owned()),
        status: meta.status,
        response_headers: &response_headers_redacted,
        response_body: Some(response_body),
    });
    shared.har.add_entry(har_entry.clone());

    if let Some(db) = &shared.db {
        let _ = db.save_har_entry(&har_entry);
    }

    shared.openapi.record_exchange_with_security(
        &method_lower,
        &meta.path,
        meta.status,
        &request_headers_redacted,
        request_body_bytes,
        &response_headers_redacted,
        Some(response_body),
        &security,
    );

    if let Some(db) = &shared.db {
        let request_body_value: serde_json::Value = match request_body_bytes {
            Some(bytes) => match serde_json::from_slice::<serde_json::Value>(bytes) {
                Ok(value) => value,
                Err(_) => serde_json::Value::String(String::from_utf8_lossy(bytes).into_owned()),
            },
            None => serde_json::Value::Null,
        };
        let mut query_object = serde_json::Map::new();
        for (name, value) in &query_pairs {
            query_object.insert(name.clone(), json!(value));
        }
        let mut response_headers_object = serde_json::Map::new();
        for (name, values) in &response_headers_redacted {
            response_headers_object.insert(
                name.clone(),
                json!(values.first().cloned().unwrap_or_default()),
            );
        }
        let row = json!({
            "path": meta.path,
            "method": method_lower,
            "request": {
                "query": serde_json::Value::Object(query_object),
                "headers": header_map_json(&request_headers_redacted),
                "contentType": request_content_type,
                "body": request_body_value,
                "security": security,
            },
            "response": {
                "status": meta.status,
                "headers": serde_json::Value::Object(response_headers_object),
                "contentType": if response_content_type.is_empty() {
                    "application/json".to_string()
                } else {
                    response_content_type
                },
            },
        });
        let _ = db.upsert_endpoint(&meta.path, &method_lower, &row);
    }

    if shared.verbose {
        println!("{} {} -> {}", meta.method, meta.path, meta.status);
    }
}

fn header_map_json(headers: &HeaderMapValues) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    for (name, values) in headers {
        object.insert(
            name.clone(),
            json!(values.first().cloned().unwrap_or_default()),
        );
    }
    serde_json::Value::Object(object)
}

fn first_value<'a>(headers: &'a HeaderMapValues, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|values| values.first().map(|v| v.as_str()))
}

fn proxy_error_response(message: &str) -> Response {
    let body = json!({ "error": "Proxy error", "message": message }).to_string();
    plain_response(StatusCode::INTERNAL_SERVER_ERROR, "application/json", &body)
}

fn plain_response(status: StatusCode, content_type: &str, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Body::from(body.to_string()))
        .expect("build static response")
}

/// Binds `127.0.0.1:port`, walking forward to the next free port on
/// `AddrInUse` (the TS `findAvailablePort` behavior). Port 0 binds once and
/// yields the OS-assigned port.
pub(crate) async fn bind_listener(port: u16) -> Result<(tokio::net::TcpListener, u16)> {
    let mut port = port;
    loop {
        match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await {
            Ok(listener) => {
                let bound = listener
                    .local_addr()
                    .map_err(|e| Error::io("read bound address", e))?;
                return Ok((listener, bound.port()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && port != 0 => {
                if port == u16::MAX {
                    return Err(Error::other("no available port"));
                }
                println!("Port {port} is in use, using port {} instead", port + 1);
                port += 1;
            }
            Err(e) => return Err(Error::io("bind server", e)),
        }
    }
}

#[allow(dead_code)]
fn _sync_probe() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<ProxyShared>();
}

/// Maximum proxy-chaining depth for nested CONNECT tunnels.
pub const MAX_NESTED_CONNECT: u64 = 8;

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn_upstream() -> url::Url {
        async fn echo(headers: axum::http::HeaderMap, body: String) -> Response {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let host = headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            Response::builder()
                .status(StatusCode::CREATED)
                .header("content-type", "application/json")
                .header("x-echo-auth", auth)
                .header("x-echo-host", host.clone())
                .header("te", "trailers")
                .body(Body::from(
                    json!({ "ok": true, "seen": body, "host": host }).to_string(),
                ))
                .expect("upstream response")
        }

        let app = Router::new().route("/echo", axum::routing::post(echo));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind upstream");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve upstream");
        });
        url::Url::parse(&format!("http://{addr}")).expect("upstream url")
    }

    async fn wait_until(predicate: impl Fn() -> bool, label: &str) {
        for _ in 0..100 {
            if predicate() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {label}");
    }

    #[tokio::test]
    async fn forwards_records_and_redacts() {
        let upstream = spawn_upstream().await;

        let mut shared = ProxyShared::new(upstream);
        shared.verbose = false;
        let shared = Arc::new(shared);
        let router = proxy_router(Arc::clone(&shared));

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind proxy");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve proxy");
        });

        let client = reqwest::Client::new();
        let response = client
            .post(format!("http://{addr}/echo?api_key=leaky&q=ok"))
            .header("authorization", "Bearer super-secret-token")
            .header("x-api-key", "key-123")
            .header("host", "should-not-be-forwarded")
            .body(r#"{"a":1}"#)
            .send()
            .await
            .expect("proxy request");

        // Status and body stream back unmodified; the upstream never saw the
        // client's overridden Host header (changeOrigin semantics).
        assert_eq!(response.status(), StatusCode::CREATED);
        // Hop-by-hop headers (te) never reach the client; end-to-end ones do.
        assert!(response.headers().get("te").is_none());
        assert!(response.headers().get("x-echo-host").is_some());
        let payload: serde_json::Value = response.json().await.expect("json");
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["seen"], r#"{"a":1}"#);
        assert_ne!(payload["host"], "should-not-be-forwarded");

        wait_until(
            || !shared.openapi.all_endpoints().is_empty(),
            "openapi recording",
        )
        .await;
        wait_until(|| shared.har.entry_count() > 0, "har recording").await;

        let har = shared.har.get_har();
        let entry = &har["log"]["entries"][0];
        assert_eq!(entry["request"]["method"], "POST");
        assert_eq!(entry["response"]["status"], 201);

        // Recorded headers are redacted even though the upstream saw them.
        let endpoints = shared.openapi.all_endpoints();
        let (_, method, _) = &endpoints[0];
        assert_eq!(method, "post");

        // Security schemes were detected from the original headers and land
        // in the generated spec.
        let spec = shared.openapi.generate_openapi();
        let rendered = spec.to_string();
        assert!(
            rendered.contains("apiKey") || rendered.contains("bearer"),
            "expected security schemes in spec: {rendered}"
        );

        // Credential query values are redacted in queryString and headers;
        // the raw URL text is preserved verbatim (matching TS). Benign
        // values survive for discovery.
        let har_text = har.to_string();
        assert!(
            !har_text.contains("super-secret-token"),
            "leaked bearer token: {har_text}"
        );
        assert!(
            !har_text.contains("\"value\":\"key-123\""),
            "leaked api key"
        );
        let query_string = entry["request"]["queryString"]
            .as_array()
            .expect("queryString");
        assert_eq!(query_string[0]["name"], "api_key");
        assert_eq!(query_string[0]["value"], "__redacted__");
        assert_eq!(query_string[1], json!({ "name": "q", "value": "ok" }));
    }

    #[tokio::test]
    async fn upstream_failure_yields_proxy_error_json() {
        let mut shared = ProxyShared::new(
            url::Url::parse("http://127.0.0.1:1").expect("target"), // nothing listens here
        );
        shared.verbose = false;
        let router = proxy_router(Arc::new(shared));

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind proxy");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve proxy");
        });

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{addr}/anything"))
            .send()
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let payload: serde_json::Value = response.json().await.expect("json");
        assert_eq!(payload["error"], "Proxy error");
        assert!(payload["message"].is_string());
    }

    #[tokio::test]
    async fn web_assets_are_not_recorded() {
        async fn asset() -> &'static str {
            "console.log(1)"
        }
        let app = Router::new().route("/app.js", axum::routing::get(asset));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind upstream");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve upstream");
        });

        let shared = Arc::new(ProxyShared::new(
            url::Url::parse(&format!("http://{addr}")).expect("target"),
        ));
        let router = proxy_router(Arc::clone(&shared));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind proxy");
        let proxy_addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve proxy");
        });

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{proxy_addr}/app.js"))
            .send()
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::OK);

        // Give the background recorder time to (not) record.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(shared.openapi.all_endpoints().is_empty());
        assert_eq!(shared.har.entry_count(), 0);
    }
    /// Proxy chaining end-to-end: client -> arbiter(intercept) -> inner
    /// CONNECT -> chained dial to a second hop. The inner CONNECT arrives on
    /// the DECRYPTED stream, exercising CONN_DEPTH recursion; the outer
    /// response is byte-checked and a depth-capped chain is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn nested_connect_chains_and_caps_depth() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        // Origin the inner GET will reach through the tunneled chain.
        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = origin_listener.accept().await.unwrap();
            let mut sock = sock;
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await;
            let _ = n;
        });

        let shared = Arc::new(ProxyShared::new(
            format!("http://{}", origin_addr).parse().unwrap(),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, proxy_router(shared)).await;
        });

        // Raw explicit-proxy client: CONNECT <origin> then GET inside.
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                    origin_addr.ip(),
                    origin_addr.port(),
                    origin_addr.ip(),
                    origin_addr.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut head = vec![0u8; 1024];
        let n = stream.read(&mut head).await.unwrap();
        let head_str = String::from_utf8_lossy(&head[..n]).to_string();
        assert!(
            head_str.starts_with("HTTP/1.1 200"),
            "expected established tunnel, got: {head_str}"
        );

        stream
            .write_all(b"GET /inner HTTP/1.1\r\nHost: chain.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("200 OK")
                && String::from_utf8_lossy(&body).ends_with("ok"),
            "inner GET should be answered over the tunnel: {}",
            String::from_utf8_lossy(&body)
        );
    }
}
