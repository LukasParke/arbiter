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
use futures::SinkExt;
use futures::StreamExt;
use serde_json::json;

use crate::auth::detect_security_schemes;
use crate::error::{Error, Result};
use crate::headers::{
    forwardable_headers, from_http_header_map, is_hop_by_hop, to_http_header_map,
};
use crate::middleware::{build_har_entry, HarEntryParts, HarStore};
use crate::redaction::{RedactionPolicy, REDACTED_VALUE};
use crate::storage::SqliteStore;
use crate::store::OpenApiStore;
use crate::types::HeaderMapValues;

/// Request body ceiling, mirroring the TS `bodyParser` 10 MB limits.
pub const MAX_REQUEST_BYTES: usize = 10 * 1024 * 1024;

/// Path suffixes whose traffic is never recorded (web assets).
const SKIPPED_EXTENSIONS: [&str; 9] = [
    ".js", ".css", ".html", ".htm", ".woff", ".woff2", ".ttf", ".eot", ".map",
];

/// Content types whose traffic is never recorded (images are kept, like TS).
const SKIPPED_CONTENT_FRAGMENTS: [&str; 4] = ["javascript", "css", "html", "font/"];

/// State shared by the proxy app and the background recorder.
pub struct ProxyShared {
    pub target: url::Url,
    pub openapi: Arc<OpenApiStore>,
    pub har: Arc<HarStore>,
    pub policy: RedactionPolicy,
    pub db: Option<Arc<SqliteStore>>,
    pub verbose: bool,
}

impl ProxyShared {
    pub fn new(target: url::Url) -> Self {
        Self {
            target,
            openapi: Arc::new(OpenApiStore::new()),
            har: Arc::new(HarStore::new()),
            policy: RedactionPolicy::default(),
            db: None,
            verbose: false,
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
    let started_at_ms = chrono::Utc::now().timestamp_millis();
    let method = req.method().clone();
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
    let request_headers = from_http_header_map(req.headers());

    // Buffer the raw request body (byte-exact, like the TS raw bodyParser).
    let request_body = match axum::body::to_bytes(req.into_body(), MAX_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return plain_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "text/plain",
                "request body too large",
            )
        }
    };

    // Forward end-to-end headers only; the client re-computes framing and
    // derives Host from the upstream URL (changeOrigin semantics).
    let forward_headers = to_http_header_map(&forwardable_headers(&request_headers, true));
    let upstream_url = match shared.target.join(&path_and_query) {
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
    let response_headers = from_http_header_map(upstream_response.headers());

    // End-to-end response headers only; framing is managed by the HTTP layer
    // (forwarding `transfer-encoding`/`content-length` corrupts streaming).
    let mut passthrough_headers = axum::http::HeaderMap::new();
    for (name, value) in upstream_response.headers() {
        if is_hop_by_hop(name.as_str()) || name == axum::http::header::CONTENT_LENGTH {
            continue;
        }
        passthrough_headers.append(name, value.clone());
    }

    // Pump upstream chunks to the client while teeing them into the
    // recording buffer; recording runs after the last chunk, off the client's
    // critical path.
    let (mut tx, rx) = futures::channel::mpsc::channel::<
        std::result::Result<axum::body::Bytes, std::io::Error>,
    >(16);
    let recorder = Arc::clone(&shared);
    let record_method = method.to_string();
    let record_body = request_body.clone();
    tokio::spawn(async move {
        let mut buffer = Vec::new();
        let mut stream = upstream_response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    buffer.extend_from_slice(&bytes);
                    if tx.send(Ok(bytes)).await.is_err() {
                        break; // client went away; keep what we have
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    break;
                }
            }
        }
        drop(tx);
        record_exchange(
            &recorder,
            RecordMeta {
                started_at_ms,
                time_ms: chrono::Utc::now().timestamp_millis() - started_at_ms,
                method: record_method,
                path,
                raw_query,
                request_headers,
                request_body: record_body,
                status: status.as_u16(),
                response_headers,
            },
            &buffer,
        )
        .await;
    });

    let mut builder = Response::builder().status(status);
    for (name, value) in &passthrough_headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from_stream(rx))
        .expect("build proxied response")
}

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
}

/// Background recording: HAR entry, OpenAPI endpoint, and optional SQLite
/// persistence — all best-effort, never failing the proxied exchange.
async fn record_exchange(shared: &ProxyShared, meta: RecordMeta, response_body: &[u8]) {
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
}
