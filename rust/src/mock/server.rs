//! Mock HTTP server (W3): axum app serving spec-generated or recorded
//! responses. Startup compiles every pattern/template BEFORE the socket
//! binds (fail-fast, <100 ms bar); `--watch` swaps engines via a 500 ms
//! mtime poll (AMEND-6, no notify crate); the fault gate runs BEFORE
//! generation/serving (AMEND-5).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::types::HeaderMapValues;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::Router;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use super::capture_mock::parse_query_string;
use super::example::cors_headers;
use super::fault::{FaultConfig, FaultDecision, FaultInjector};
use super::MatchStrategy;
use super::{compile_engine, IncomingRequest, MockEngine};

use crate::error::{Error, Result};

/// Incoming request bodies above this are rejected with 413.
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;

/// mtime poll cadence for `--watch` (AMEND-6).
pub const WATCH_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Where the engine content comes from — kept so the watch loop can rebuild.
#[derive(Debug, Clone)]
pub struct MockSourcePaths {
    pub spec_path: Option<PathBuf>,
    pub capture_dir: Option<PathBuf>,
}

/// Shared server state: hot-path engine reads go through `RwLock` clone of
/// an `Arc`, so a watch reload swaps one pointer and never blocks requests.
pub struct MockAppState {
    pub engine: Arc<RwLock<Arc<MockEngine>>>,
    pub fault: FaultInjector,
    pub strategy: MatchStrategy,
    pub vars: Arc<BTreeMap<String, String>>,
    pub source_paths: MockSourcePaths,
    pub watch_targets: Vec<PathBuf>,
    reload_warned: AtomicBool,
    matched: AtomicU64,
    unmatched: AtomicU64,
    faults_applied: AtomicU64,
    started: Instant,
}

impl MockAppState {
    pub fn new(
        engine: MockEngine,
        fault: FaultConfig,
        strategy: MatchStrategy,
        vars: Arc<BTreeMap<String, String>>,
        source_paths: MockSourcePaths,
    ) -> Self {
        Self::with_seed(
            engine,
            fault,
            strategy,
            vars,
            source_paths,
            fault_seed_entropy(),
        )
    }

    /// Deterministic constructor for tests.
    pub fn with_seed(
        engine: MockEngine,
        fault: FaultConfig,
        strategy: MatchStrategy,
        vars: Arc<BTreeMap<String, String>>,
        source_paths: MockSourcePaths,
        seed: u64,
    ) -> Self {
        let watch_targets = match (&source_paths.spec_path, &source_paths.capture_dir) {
            (Some(spec), _) => vec![spec.clone()],
            (None, Some(dir)) => vec![dir.join("manifest.json"), dir.join("exchanges.ndjson")],
            (None, None) => Vec::new(),
        };
        MockAppState {
            engine: Arc::new(RwLock::new(Arc::new(engine))),
            fault: FaultInjector::with_seed(fault, seed),
            strategy,
            vars,
            source_paths,
            watch_targets,
            reload_warned: AtomicBool::new(false),
            matched: AtomicU64::new(0),
            unmatched: AtomicU64::new(0),
            faults_applied: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    /// Machine-readable health payload served at `GET /__mock/health`.
    /// The caller reads the engine snapshot (async) and passes mode/rules.
    pub fn stats_json(&self, mode: &str, rules: usize) -> serde_json::Value {
        serde_json::json!({
            "status": "ok",
            "mode": mode,
            "rules": rules,
            "matched": self.matched.load(Ordering::Relaxed),
            "unmatched": self.unmatched.load(Ordering::Relaxed),
            "faultsApplied": self.faults_applied.load(Ordering::Relaxed),
            "uptimeSeconds": self.started.elapsed().as_secs(),
        })
    }
}

fn fault_seed_entropy() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    nanos | 1
}

// ---------------------------------------------------------------------------
// Router + handlers
// ---------------------------------------------------------------------------

/// Build the mock router: health endpoint plus a catch-all that routes
/// through the fault gate and the matching engine.
pub fn mock_router(state: Arc<MockAppState>) -> Router {
    Router::new()
        .route("/__mock/health", get(health))
        .fallback(mock_catch_all)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

async fn health(State(st): State<Arc<MockAppState>>) -> Response {
    let engine = st.engine.read().await;
    let payload = st.stats_json(engine.mode(), engine.rule_count());
    axum::Json(payload).into_response()
}

async fn mock_catch_all(
    State(st): State<Arc<MockAppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // CORS preflight never reaches the engine.
    if method == Method::OPTIONS {
        return cors_response(StatusCode::NO_CONTENT, Vec::new())
            .body(Body::empty())
            .unwrap_or_else(|_| empty_status_response(StatusCode::NO_CONTENT));
    }

    // Fault gate FIRST (AMEND-5): one atomic draw decides everything.
    let decision = st.fault.roll();
    if decision != FaultDecision::None {
        st.faults_applied.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(delay) = decision.delay() {
        tokio::time::sleep(delay).await;
    }
    match decision {
        FaultDecision::Reset => return reset_response(),
        FaultDecision::Timeout => {
            return empty_status_response(StatusCode::GATEWAY_TIMEOUT);
        }
        FaultDecision::Status(_) | FaultDecision::Garbage => {
            let mut status = 200u16;
            let mut resp_body = Vec::new();
            let mut content_type = String::from("application/json");
            st.fault
                .apply_to_response(&decision, &mut status, &mut resp_body, &mut content_type);
            return cors_response(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                vec![("content-type".to_string(), content_type)],
            )
            .body(Body::from(resp_body))
            .unwrap_or_else(|_| empty_status_response(StatusCode::INTERNAL_SERVER_ERROR));
        }
        FaultDecision::Latency(_) | FaultDecision::None => {}
    }

    // Decompose the request once for matching + templating.
    let mut header_values: HeaderMapValues = BTreeMap::new();
    for (name, value) in headers.iter() {
        header_values
            .entry(name.as_str().to_ascii_lowercase())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    let query = uri.query().map(parse_query_string).unwrap_or_default();
    let input = IncomingRequest {
        method: method.as_str().to_string(),
        path: uri.path().to_string(),
        query,
        headers: header_values,
        body: body.to_vec(),
    };

    let engine = st.engine.read().await.clone();
    let Some(resp) = engine.respond(&input) else {
        st.unmatched.fetch_add(1, Ordering::Relaxed);
        let payload = serde_json::json!({
            "error": "no matching stub",
            "method": input.method,
            "path": input.path,
        });
        return cors_response(
            StatusCode::GATEWAY_TIMEOUT,
            vec![("content-type".to_string(), "application/json".to_string())],
        )
        .body(Body::from(payload.to_string()))
        .unwrap_or_else(|_| empty_status_response(StatusCode::GATEWAY_TIMEOUT));
    };
    st.matched.fetch_add(1, Ordering::Relaxed);

    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut out_headers: Vec<(String, String)> = resp.headers;
    if let Some(ct) = resp.content_type {
        out_headers.push(("content-type".to_string(), ct));
    }
    cors_response(status, out_headers)
        .body(Body::from(resp.body))
        .unwrap_or_else(|_| empty_status_response(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Attach CORS headers (W3: mock responses are CORS-enabled by default).
fn cors_response(
    status: StatusCode,
    headers: Vec<(String, String)>,
) -> axum::http::response::Builder {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    for (name, value) in cors_headers() {
        builder = builder.header(name, value);
    }
    builder
}

fn empty_status_response(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static empty response")
}

/// Connection-reset fault: an immediately-failing body stream makes hyper
/// tear down the connection without a complete response.
fn reset_response() -> Response {
    use futures::stream::once;
    let stream = once(async {
        Err::<Vec<u8>, std::io::Error>(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "mock: fault injection reset",
        ))
    });
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from_stream(stream))
        .expect("static reset response")
}

// ---------------------------------------------------------------------------
// Bind + serve
// ---------------------------------------------------------------------------

/// Bind `host:port` and spawn the server. Returns the bound address (use
/// port 0 for an ephemeral port in tests) and the server task handle.
/// The engine is fully compiled by the caller BEFORE this binds.
pub async fn serve(
    host: &str,
    port: u16,
    state: Arc<MockAppState>,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    let app = mock_router(state);
    let listener = tokio::net::TcpListener::bind((host, port))
        .await
        .map_err(|e| Error::io(format!("mock: bind {host}:{port}"), e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::io("mock: resolve bound address", e))?;
    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("mock: server error: {e}");
        }
    });
    Ok((addr, handle))
}

// ---------------------------------------------------------------------------
// Watch (AMEND-6): 500 ms mtime poll, RwLock<Arc<MockEngine>> swap
// ---------------------------------------------------------------------------

/// Spawn the mtime watch loop. On change: rebuild the engine OFF the hot
/// path, swap the `RwLock` pointer. A failed parse keeps the previous
/// engine and warns exactly once per failure streak.
pub fn spawn_watch(state: Arc<MockAppState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut last = fingerprint(&state.watch_targets).await;
        let mut tick = tokio::time::interval(WATCH_POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let current = fingerprint(&state.watch_targets).await;
            if current == last {
                continue;
            }
            last = current;
            match compile_engine(
                state.source_paths.spec_path.as_deref(),
                state.source_paths.capture_dir.as_deref(),
                state.strategy,
                (*state.vars).clone(),
            ) {
                Ok(engine) => {
                    *state.engine.write().await = Arc::new(engine);
                    state.reload_warned.store(false, Ordering::Relaxed);
                }
                Err(e) => {
                    if !state.reload_warned.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "mock: reload failed, keeping previous engine: {e}\n  help: fix the spec/bundle file and save again"
                        );
                    }
                }
            }
        }
    })
}

/// mtime+size fingerprint of the watched files; missing files fingerprint
/// as `None` so first appearance still triggers a reload.
async fn fingerprint(targets: &[PathBuf]) -> Vec<Option<(u64, u64, u64)>> {
    let mut out = Vec::with_capacity(targets.len());
    for target in targets {
        out.push(match tokio::fs::metadata(target).await {
            Ok(meta) => {
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
                Some((
                    mtime.as_ref().map(|d| d.as_secs()).unwrap_or(0),
                    mtime.as_ref().map(|d| d.subsec_nanos() as u64).unwrap_or(0),
                    meta.len(),
                ))
            }
            Err(_) => None,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::capture_mock::test_support as mock_support;
    use crate::mock::fault::FaultKind;

    const SPEC_V1: &str = r#"
openapi: 3.0.3
info: { title: t, version: "1" }
paths:
  /pets/{id}:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              examples:
                one:
                  value: { id: "pet-1", name: Rex }
"#;

    const SPEC_V2: &str = r#"
openapi: 3.0.3
info: { title: t, version: "1" }
paths:
  /pets/{id}:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              examples:
                one:
                  value: { id: "pet-1", name: Rex }
  /dogs:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              example: { good: true }
"#;

    fn write_spec(dir: &std::path::Path, contents: &str) -> PathBuf {
        let path = dir.join("spec.yaml");
        std::fs::write(&path, contents).expect("write spec");
        path
    }

    fn spec_state(spec: &std::path::Path) -> Arc<MockAppState> {
        let engine = compile_engine(Some(spec), None, MatchStrategy::Strongest, BTreeMap::new())
            .expect("compile engine");
        Arc::new(MockAppState::with_seed(
            engine,
            FaultConfig::default(),
            MatchStrategy::Strongest,
            Arc::new(BTreeMap::new()),
            MockSourcePaths {
                spec_path: Some(spec.to_path_buf()),
                capture_dir: None,
            },
            7,
        ))
    }

    async fn get(st: &Arc<MockAppState>, path: &str) -> reqwest::Response {
        let (addr, handle) = serve("127.0.0.1", 0, st.clone()).await.expect("serve");
        let url = format!("http://{addr}{path}");
        let resp = reqwest::get(&url).await.expect("request");
        handle.abort();
        resp
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spec_mode_serves_examples_with_cors_and_health() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let spec = write_spec(dir.path(), SPEC_V1);
        let st = spec_state(&spec);

        let resp = get(&st, "/pets/pet-9").await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
        let body = resp.text().await.expect("body");
        assert!(body.contains("Rex"), "example body: {body}");

        let health = get(&st, "/__mock/health").await;
        assert_eq!(health.status(), 200);
        let stats: serde_json::Value = health.json().await.expect("health json");
        assert_eq!(stats["status"], "ok");
        assert_eq!(stats["mode"], "spec");
        assert_eq!(stats["rules"], 1);

        // Unknown route: deterministic 504 miss JSON.
        let miss = get(&st, "/nowhere").await;
        assert_eq!(miss.status(), 504);
        let miss_body: serde_json::Value = miss.json().await.expect("miss json");
        assert_eq!(miss_body["error"], "no matching stub");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn capture_mode_serves_recorded_bytes_exactly() {
        let bundle_dir = tempfile::tempdir().expect("tmpdir");
        mock_support::write_test_bundle(
            bundle_dir.path(),
            vec![mock_support::recorded_exchange(1)],
        );

        let engine = compile_engine(
            None,
            Some(bundle_dir.path()),
            MatchStrategy::Strongest,
            BTreeMap::new(),
        )
        .expect("compile engine");
        let st = Arc::new(MockAppState::with_seed(
            engine,
            FaultConfig::default(),
            MatchStrategy::Strongest,
            Arc::new(BTreeMap::new()),
            MockSourcePaths {
                spec_path: None,
                capture_dir: Some(bundle_dir.path().to_path_buf()),
            },
            7,
        ));

        let (addr, handle) = serve("127.0.0.1", 0, st).await.expect("serve");
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/messages?key=abc&id=7"))
            .header("content-type", "application/json")
            .body(br#"{"model":"claude","prompt":"hi"}"#.to_vec())
            .send()
            .await
            .expect("request");
        assert_eq!(resp.status(), 201);
        assert_eq!(
            resp.headers()
                .get("x-recorded")
                .and_then(|v| v.to_str().ok()),
            Some("yes")
        );
        let bytes = resp.bytes().await.expect("body");
        assert_eq!(
            bytes.as_ref(),
            mock_support::MARKER_BODY,
            "served bytes must be byte-identical to the recording"
        );
        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fault_gate_replaces_response_before_generation() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let spec = write_spec(dir.path(), SPEC_V1);
        let engine = compile_engine(Some(&spec), None, MatchStrategy::Strongest, BTreeMap::new())
            .expect("compile engine");
        let fault = FaultConfig::from_cli(None, Some(418), None, 100).expect("fault cfg");
        let st = Arc::new(MockAppState::with_seed(
            engine,
            fault,
            MatchStrategy::Strongest,
            Arc::new(BTreeMap::new()),
            MockSourcePaths {
                spec_path: Some(spec.clone()),
                capture_dir: None,
            },
            7,
        ));

        let resp = get(&st, "/pets/pet-1").await;
        assert_eq!(resp.status(), 418, "fault status replaces the example");
        let body = resp.text().await.expect("body");
        assert!(body.is_empty(), "status fault serves an empty body");

        let health = get(&st, "/__mock/health").await;
        let stats: serde_json::Value = health.json().await.expect("health");
        assert_eq!(stats["faultsApplied"], 1, "only the faulted request counts");
        assert_eq!(stats["matched"], 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn watch_reloads_engine_within_poll_window_and_survives_bad_parse() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let spec = write_spec(dir.path(), SPEC_V1);
        let st = spec_state(&spec);
        assert_eq!(st.engine.read().await.rule_count(), 1);

        spawn_watch(st.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Edit the spec: new route appears within ~500ms poll + rebuild.
        std::fs::write(&spec, SPEC_V2).expect("rewrite spec");
        let deadline = Instant::now() + Duration::from_millis(1200);
        loop {
            if st.engine.read().await.rule_count() == 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "watch did not swap the engine in time"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // A broken spec keeps the previous engine and warns once.
        std::fs::write(&spec, "{{{ not yaml").expect("break spec");
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(
            st.engine.read().await.rule_count(),
            2,
            "failed parse must keep the old engine"
        );
        assert!(st.reload_warned.load(Ordering::Relaxed));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reset_fault_tears_down_connection() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let spec = write_spec(dir.path(), SPEC_V1);
        let engine = compile_engine(Some(&spec), None, MatchStrategy::Strongest, BTreeMap::new())
            .expect("compile engine");
        let fault =
            FaultConfig::from_cli(None, None, Some(FaultKind::Reset), 100).expect("fault cfg");
        let st = Arc::new(MockAppState::with_seed(
            engine,
            fault,
            MatchStrategy::Strongest,
            Arc::new(BTreeMap::new()),
            MockSourcePaths {
                spec_path: Some(spec),
                capture_dir: None,
            },
            7,
        ));

        let (addr, handle) = serve("127.0.0.1", 0, st).await.expect("serve");
        let client = reqwest::Client::new();
        let result = client.get(format!("http://{addr}/pets/1")).send().await;
        assert!(
            result.is_err(),
            "reset fault must not yield a complete response"
        );
        handle.abort();
    }
}
