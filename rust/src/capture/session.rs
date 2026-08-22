//! Capture session: an HTTP reverse proxy that records canonical
//! [`CapturedExchange`]s of everything flowing through it and can export a
//! deterministic capture bundle. Port of `src/capture/session.ts`.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::Router;
use base64::Engine;
use futures::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use url::{Host, Url};

use crate::bundle::{load_bundle, sha256_hex, write_bundle, WriteBundleOptions, INLINE_BODY_LIMIT};
use crate::error::{Error, Result};
use crate::headers::{
    capture_headers, forwardable_headers, from_http_header_map, to_http_header_map,
    to_http_header_map_with,
};
use std::result::Result as StdResult;

/// Optional contract-validator hook invoked after each exchange settles.
pub type ValidationHook = Arc<dyn Fn(&CapturedExchange) -> Vec<Value> + Send + Sync>;

use crate::redaction::RedactionPolicy;
use crate::secret_scan::{ensure_clean, scan_exchanges, SecretScanOptions};
use crate::sse::SseParser;
use crate::types::{
    BodyStorage, CaptureFailure, CaptureManifest, CaptureMode, CapturedBody, CapturedExchange,
    CapturedRequest, CapturedResponse, HeaderMapValues, StreamState, ValidationSummary, WsStream,
    BUNDLE_SCHEMA_VERSION, EXCHANGE_SCHEMA_VERSION,
};
use crate::version::ARBITER_VERSION;
use crate::ws::{pump_ws, WsCaptureMeta};

use super::body_sink::{BodyLimitPolicy, BodySink, DEFAULT_MAX_BODY_BYTES, MAX_SPILLED_BODY_BYTES};

pub struct CaptureSessionOptions {
    pub target: Url,
    /// Listen address; default 127.0.0.1.
    pub listen_host: IpAddr,
    /// 0 = ephemeral port.
    pub listen_port: u16,
    pub mode: CaptureMode,
    pub redaction: RedactionPolicy,
    /// If set, `close()` in exact mode exports the bundle here.
    pub output: Option<PathBuf>,
    /// Optional contract validator hook, called after each exchange settles.
    pub validation: Option<ValidationHook>,
    /// Max in-memory body bytes before spill/fail. Default 32 MiB.
    pub max_body_bytes: Option<u64>,
    /// Auto-close after this many ms without traffic; the timer resets on
    /// every settled exchange.
    pub idle_timeout_ms: Option<u64>,
}

impl Default for CaptureSessionOptions {
    fn default() -> Self {
        Self {
            target: Url::parse("http://127.0.0.1").expect("static URL parses"),
            listen_host: IpAddr::from([127, 0, 0, 1]),
            listen_port: 0,
            mode: CaptureMode::Observe,
            redaction: RedactionPolicy::default(),
            output: None,
            validation: None,
            max_body_bytes: None,
            idle_timeout_ms: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    pub output: PathBuf,
    /// Exact secret values to reject anywhere in the bundle.
    pub reject_secrets: Vec<String>,
    /// Media types allowed to remain un-scanned binary in exact mode.
    pub allow_binary_media_types: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExportResult {
    pub manifest: CaptureManifest,
    pub output_dir: PathBuf,
}

struct SessionInner {
    target: Url,
    mode: CaptureMode,
    redaction: RedactionPolicy,
    output: Option<PathBuf>,
    validation: Option<ValidationHook>,
    started_at: String,
    sequence: AtomicU64,
    exchanges: Mutex<Vec<CapturedExchange>>,
    bodies: Mutex<HashMap<String, Vec<u8>>>,
    failures: Mutex<Vec<CaptureFailure>>,
    validations: Mutex<Vec<Value>>,
    in_flight: AtomicUsize,
    idle: Notify,
    /// Exchange-count signal the idle-timeout watchdog resets its timer on.
    activity: watch::Sender<u64>,
    /// Ticks the latest settled exchange sequence (AMEND-9 flow feed).
    flow_seq: watch::Sender<u64>,
    client: reqwest::Client,
    inline_body_limit: u64,
}

impl SessionInner {
    fn record_failure(&self, failure: CaptureFailure) {
        self.failures.lock().expect("failures lock").push(failure);
    }

    fn mark_activity(&self) {
        let count = self.exchanges.lock().map(|e| e.len()).unwrap_or(0) as u64;
        let _ = self.activity.send(count);
    }

    async fn wait_for_idle(&self) {
        loop {
            if self.in_flight.load(Ordering::Acquire) == 0 {
                return;
            }
            let notified = self.idle.notified();
            if self.in_flight.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    fn exchange_snapshot(&self) -> Vec<CapturedExchange> {
        self.exchanges.lock().expect("exchanges lock").clone()
    }

    fn failures_snapshot(&self) -> Vec<CaptureFailure> {
        self.failures.lock().expect("failures lock").clone()
    }

    fn bodies_snapshot(&self) -> HashMap<String, Vec<u8>> {
        self.bodies.lock().expect("bodies lock").clone()
    }

    fn new_sink(&self) -> BodySink {
        BodySink::with_options(
            BodyLimitPolicy::Spill,
            self.inline_body_limit,
            MAX_SPILLED_BODY_BYTES,
            &std::env::temp_dir(),
        )
    }
}

struct SessionCore {
    inner: Arc<SessionInner>,
    url: Url,
    shutdown_tx: watch::Sender<u8>,
    server_task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
}

/// A running capture proxy. Cloneable handle onto the shared server state.
#[derive(Clone)]
pub struct CaptureSession {
    core: Arc<SessionCore>,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn origin_of(url: &Url) -> String {
    let scheme = url.scheme();
    let host = match url.host() {
        Some(Host::Ipv6(h)) => format!("[{h}]"),
        _ => url.host_str().unwrap_or("").to_string(),
    };
    let known_default = |port: u16| matches!((scheme, port), ("http", 80) | ("https", 443));
    match url.port() {
        Some(port) if !known_default(port) => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    }
}

fn first_header<'a>(headers: &'a HeaderMapValues, name: &str) -> Option<&'a str> {
    headers
        .get(&name.to_lowercase())
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn version_string(version: axum::http::Version) -> String {
    match version {
        axum::http::Version::HTTP_09 => "0.9",
        axum::http::Version::HTTP_10 => "1.0",
        axum::http::Version::HTTP_11 => "1.1",
        axum::http::Version::HTTP_2 => "2",
        axum::http::Version::HTTP_3 => "3",
        _ => "1.1",
    }
    .to_string()
}

fn limit_message(err: &Error) -> Option<String> {
    match err {
        Error::BodyLimitExceeded(message) => Some(message.clone()),
        _ => None,
    }
}

/// Build a `CapturedBody` with `makeCapturedBody` semantics against the
/// in-memory body map: payloads up to [`INLINE_BODY_LIMIT`] inline as
/// base64, larger ones become content-addressed blob references whose bytes
/// live in `bodies` until export hands them to [`write_bundle`].
fn captured_body_from(
    bytes: &[u8],
    media_type: Option<&str>,
    content_encoding: Option<&str>,
    bodies: &mut HashMap<String, Vec<u8>>,
) -> CapturedBody {
    let digest = sha256_hex(bytes);
    let storage = if bytes.len() <= INLINE_BODY_LIMIT {
        BodyStorage::InlineBase64 {
            value: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    } else {
        bodies.insert(digest.clone(), bytes.to_vec());
        BodyStorage::Blob {
            path: format!("bodies/{digest}.bin"),
        }
    };
    CapturedBody {
        sha256: digest,
        size: bytes.len() as u64,
        media_type: media_type.map(str::to_string),
        content_encoding: content_encoding.map(str::to_string),
        storage,
    }
}

pub async fn start_capture_session(options: CaptureSessionOptions) -> Result<CaptureSession> {
    if options.target.scheme() != "http" && options.target.scheme() != "https" {
        return Err(Error::other(format!(
            "Unsupported target protocol: {}",
            options.target.scheme()
        )));
    }
    let (activity, _activity_rx) = watch::channel(0u64);
    let (flow_seq, _flow_seq_rx) = watch::channel(0u64);
    let inner = Arc::new(SessionInner {
        target: options.target.clone(),
        mode: options.mode,
        redaction: options.redaction,
        output: options.output.clone(),
        validation: options.validation,
        started_at: now_iso(),
        sequence: AtomicU64::new(0),
        exchanges: Mutex::new(Vec::new()),
        bodies: Mutex::new(HashMap::new()),
        failures: Mutex::new(Vec::new()),
        validations: Mutex::new(Vec::new()),
        in_flight: AtomicUsize::new(0),
        idle: Notify::new(),
        activity,
        flow_seq,
        client: reqwest::Client::builder()
            // Node's http.request never auto-follows redirects; mirror that.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::other(format!("build upstream client: {e}")))?,
        inline_body_limit: options.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
    });

    let listener = TcpListener::bind(SocketAddr::new(options.listen_host, options.listen_port))
        .await
        .map_err(|e| Error::io("bind capture listener", e))?;
    let address = listener
        .local_addr()
        .map_err(|e| Error::io("capture listener address", e))?;

    let app = Router::new().fallback(proxy).with_state(inner.clone());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(0u8);
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await;
    });

    let core = Arc::new(SessionCore {
        inner: inner.clone(),
        url: Url::parse(&format!(
            "http://{}:{}",
            format_host(address.ip()),
            address.port()
        ))
        .map_err(|e| Error::other(format!("capture URL: {e}")))?,
        shutdown_tx,
        server_task: tokio::sync::Mutex::new(Some(server_task)),
        closed: AtomicBool::new(false),
    });

    if let Some(idle_ms) = options.idle_timeout_ms {
        spawn_idle_watchdog(core.clone(), Duration::from_millis(idle_ms));
    }

    Ok(CaptureSession { core })
}

fn format_host(address: IpAddr) -> String {
    match address {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// Auto-close watchdog: shuts the session down after `idle` without traffic.
fn spawn_idle_watchdog(core: Arc<SessionCore>, idle: Duration) {
    let mut activity = core.inner.activity.subscribe();
    let mut shutdown_rx = core.shutdown_tx.subscribe();
    tokio::spawn(async move {
        loop {
            let timer = tokio::time::sleep(idle);
            tokio::pin!(timer);
            tokio::select! {
                _ = &mut timer => break,
                result = activity.changed() => {
                    if result.is_err() {
                        return; // session dropped
                    }
                    // The timer restarts on every new settled exchange.
                }
                _ = shutdown_rx.changed() => return, // explicit close wins
            }
        }
        let _ = core.shutdown_tx.send(2);
        let _ = shutdown_and_export(&core, None).await;
    });
}

async fn shutdown_and_export(core: &SessionCore, options: Option<ExportOptions>) -> Result<()> {
    if core.closed.swap(true, Ordering::AcqRel) {
        return Ok(()); // already shut down (e.g. by the idle watchdog)
    }
    let _ = core.shutdown_tx.send(1);
    if let Some(handle) = core.server_task.lock().await.take() {
        let _ = handle.await;
    }
    core.inner.wait_for_idle().await;
    // Exact mode exports on close when an output is configured.
    if core.inner.mode == CaptureMode::Exact {
        if let Some(output) = options
            .as_ref()
            .map(|options| options.output.clone())
            .or_else(|| core.inner.output.clone())
        {
            export_core(
                core,
                Some(ExportOptions {
                    output,
                    ..ExportOptions::default()
                }),
            )
            .await
            .map(|_| ())?;
        }
    }
    Ok(())
}

impl CaptureSession {
    pub fn url(&self) -> Url {
        self.core.url.clone()
    }

    pub async fn exchanges(&self) -> Vec<CapturedExchange> {
        self.core.inner.exchange_snapshot()
    }

    pub async fn failures(&self) -> Vec<CaptureFailure> {
        self.core.inner.failures_snapshot()
    }

    /// Resolves once no exchange is in flight.
    pub async fn wait_for_idle(&self) {
        self.core.inner.wait_for_idle().await;
    }

    /// Listener metadata for `--ready-file`: `{url, target, mode, pid}`.
    pub async fn ready_info(&self) -> Result<Value> {
        Ok(json!({
            "url": self.core.url.as_str(),
            "target": self.core.inner.target.as_str(),
            "mode": self.core.inner.mode.as_str(),
            "pid": std::process::id(),
        }))
    }

    pub async fn export(&self, options: Option<ExportOptions>) -> Result<ExportResult> {
        self.wait_for_idle().await;
        export_core(&self.core, options).await
    }

    /// Stops the server; exact mode exports when `output` is configured.
    pub async fn close(self) -> Result<()> {
        shutdown_and_export(&self.core, None).await
    }

    /// Subscribes to the latest settled exchange sequence (AMEND-9). The
    /// receiver ticks once per settled flow; initial value 0.
    pub(crate) fn subscribe_flows(&self) -> watch::Receiver<u64> {
        self.core.inner.flow_seq.subscribe()
    }

    /// Settled flows with sequence > `after_seq`, ascending, at most
    /// `limit` entries. Cheap projection for live feeds (TUI, /__flows).
    pub async fn flow_summaries(&self, after_seq: u64, limit: usize) -> Vec<FlowSummary> {
        let exchanges = self.core.inner.exchanges.lock().expect("exchanges lock");
        exchanges
            .iter()
            .filter(|exchange| exchange.sequence > after_seq)
            .take(limit)
            .map(|exchange| FlowSummary {
                sequence: exchange.sequence,
                method: exchange.request.method.clone(),
                path: exchange.request.path.clone(),
                status: exchange.response.status,
                started_at: exchange.started_at.clone(),
                duration_ms: exchange.duration_ms,
                provider: exchange.llm.as_ref().map(|llm| llm.provider.clone()),
                model: exchange.llm.as_ref().and_then(|llm| llm.model.clone()),
            })
            .collect()
    }

    /// Body bytes keyed by sha256 (blob payloads held in memory). Callers
    /// resolve `CapturedBody.storage` references against this map.
    pub async fn bodies_snapshot(&self) -> HashMap<String, Vec<u8>> {
        self.core.inner.bodies_snapshot()
    }

    /// Removes a settled exchange from the live store so it never reaches a
    /// bundle flush; also drops body bytes now referenced by nothing. Returns
    /// false when `seq` was not found.
    pub async fn remove_exchange(&self, seq: u64) -> bool {
        let inner = &self.core.inner;
        let removed = {
            let mut exchanges = inner.exchanges.lock().expect("exchanges lock");
            let before = exchanges.len();
            exchanges.retain(|exchange| exchange.sequence != seq);
            before != exchanges.len()
        };
        if !removed {
            return false;
        }
        let mut bodies = inner.bodies.lock().expect("bodies lock");
        let exchanges = inner.exchanges.lock().expect("exchanges lock");
        bodies.retain(|digest, _| {
            exchanges.iter().any(|exchange| {
                exchange.request.body.sha256 == *digest || exchange.response.body.sha256 == *digest
            })
        });
        let _ = inner.flow_seq.send(seq);
        true
    }
}

/// One settled flow projected for live consumers (TUI feed, /__flows).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSummary {
    pub sequence: u64,
    pub method: String,
    /// Redacted request path as stored.
    pub path: String,
    pub status: u16,
    pub started_at: String,
    pub duration_ms: f64,
    pub provider: Option<String>,
    pub model: Option<String>,
}

async fn export_core(core: &SessionCore, options: Option<ExportOptions>) -> Result<ExportResult> {
    let inner = &core.inner;
    let options = match options {
        Some(options) => options,
        None => ExportOptions {
            output: inner
                .output
                .clone()
                .ok_or_else(|| Error::other("No export output configured for capture session"))?,
            reject_secrets: Vec::new(),
            allow_binary_media_types: Vec::new(),
        },
    };

    let exchanges = inner.exchange_snapshot();
    let failures = inner.failures_snapshot();

    if inner.mode == CaptureMode::Exact && !failures.is_empty() {
        return Err(Error::other(format!(
            "Exact capture failed closed: {} capture failure(s). First: {}",
            failures.len(),
            failures[0].message
        )));
    }

    let bodies = inner.bodies_snapshot();

    if inner.mode == CaptureMode::Exact {
        let findings = scan_exchanges(
            &exchanges,
            &bodies,
            None,
            &SecretScanOptions {
                reject_secrets: options.reject_secrets.clone(),
                allow_binary_media_types: options.allow_binary_media_types.clone(),
            },
        );
        ensure_clean(findings)?;
    }

    let manifest = CaptureManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        arbiter_version: ARBITER_VERSION.to_string(),
        mode: inner.mode,
        target_origin: origin_of(&inner.target),
        started_at: inner.started_at.clone(),
        completed_at: now_iso(),
        exchange_count: 0,            // derived by write_bundle
        bundle_digest: String::new(), // derived by write_bundle
        redaction: inner.redaction.summary(),
        metadata: None,
    };
    let validation = inner.validations.lock().expect("validations lock").clone();
    let manifest = write_bundle(
        &options.output,
        WriteBundleOptions {
            manifest,
            exchanges,
            bodies,
            validation: (!validation.is_empty()).then_some(validation),
        },
    )?;
    // Round-trip verification mirrors the TS export, which returns loadBundle().
    let _bundle = load_bundle(&options.output)?;
    Ok(ExportResult {
        manifest,
        output_dir: options.output,
    })
}

/// Generic client-facing error; details stay in the capture failure.
async fn bad_gateway() -> Response {
    (
        axum::http::StatusCode::BAD_GATEWAY,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        json!({ "error": "Bad gateway" }).to_string(),
    )
        .into_response()
}

/// Everything needed to record one settled exchange.
struct ExchangeOutcome {
    seq: u64,
    started_at_iso: String,
    duration_ms: f64,
    method: String,
    raw_path: String,
    http_version: String,
    request_headers: HeaderMapValues,
    request_bytes: Vec<u8>,
    status: u16,
    status_text: String,
    response_http_version: String,
    response_headers: HeaderMapValues,
    stream: StreamState,
    failure: Option<CaptureFailure>,
    response_bytes: Vec<u8>,
    /// Captured websocket stream for upgrade exchanges (None otherwise).
    ws: Option<WsStream>,
}

fn finalize_exchange(inner: &Arc<SessionInner>, outcome: ExchangeOutcome) {
    let build = || -> Result<()> {
        let mut bodies = inner.bodies.lock().expect("bodies lock");
        let request_body = captured_body_from(
            &outcome.request_bytes,
            first_header(&outcome.request_headers, "content-type"),
            first_header(&outcome.request_headers, "content-encoding"),
            &mut bodies,
        );
        let response_body = captured_body_from(
            &outcome.response_bytes,
            first_header(&outcome.response_headers, "content-type"),
            first_header(&outcome.response_headers, "content-encoding"),
            &mut bodies,
        );
        drop(bodies);

        let mut exchange = CapturedExchange {
            schema_version: EXCHANGE_SCHEMA_VERSION,
            sequence: outcome.seq,
            started_at: outcome.started_at_iso,
            duration_ms: outcome.duration_ms,
            request: CapturedRequest {
                method: outcome.method,
                path: inner.redaction.redact_path(&outcome.raw_path),
                http_version: outcome.http_version,
                headers: capture_headers(&outcome.request_headers, &inner.redaction),
                body: request_body,
            },
            response: CapturedResponse {
                status: outcome.status,
                status_text: outcome.status_text,
                http_version: outcome.response_http_version,
                headers: capture_headers(&outcome.response_headers, &inner.redaction),
                body: response_body,
                stream: outcome.stream,
            },
            failure: outcome.failure.clone(),
            ws: outcome.ws,
            validation: None,
            tunnel: None,
            tls: None,
            llm: None,
        };
        if let Some(hook) = &inner.validation {
            let violations = hook(&exchange);
            exchange.validation = Some(ValidationSummary {
                valid: violations.is_empty(),
                violation_count: violations.len() as u64,
            });
            inner
                .validations
                .lock()
                .expect("validations lock")
                .extend(violations);
        }
        inner
            .exchanges
            .lock()
            .expect("exchanges lock")
            .push(exchange);
        let _ = inner.flow_seq.send(outcome.seq);
        if let Some(failure) = &outcome.failure {
            inner.record_failure(failure.clone());
        }
        Ok(())
    };
    if let Err(err) = build() {
        inner.record_failure(CaptureFailure {
            stage: "persistence".to_string(),
            message: err.to_string(),
        });
    }
}

/// Finish an exchange whose upstream connection failed: record it and answer
/// the client with a generic 502 (details stay in the capture failure).
async fn finish_upstream_failed(inner: &Arc<SessionInner>, outcome: ExchangeOutcome) -> Response {
    finalize_exchange(inner, outcome);
    inner.in_flight.fetch_sub(1, Ordering::AcqRel);
    inner.idle.notify_waiters();
    inner.mark_activity();
    bad_gateway().await
}

#[allow(clippy::too_many_arguments)]
fn upstream_failed_outcome(
    seq: u64,
    started_at_iso: String,
    started: &Instant,
    method: String,
    raw_path: String,
    http_version: String,
    request_headers: HeaderMapValues,
    request_bytes: Vec<u8>,
    message: String,
    client_aborted: bool,
) -> ExchangeOutcome {
    ExchangeOutcome {
        seq,
        started_at_iso,
        duration_ms: started.elapsed().as_secs_f64() * 1000.0,
        method,
        raw_path,
        http_version,
        request_headers,
        request_bytes,
        status: 502,
        status_text: "Bad Gateway".to_string(),
        response_http_version: "1.1".to_string(),
        response_headers: BTreeMap::new(),
        stream: StreamState {
            kind: "buffered".to_string(),
            completed: false,
            client_aborted,
            upstream_aborted: true,
            terminal_marker: None,
            error: Some(message.clone()),
        },
        failure: Some(CaptureFailure {
            stage: "upstream-connect".to_string(),
            message,
        }),
        response_bytes: Vec::new(),
        ws: None,
    }
}

async fn proxy(State(inner): State<Arc<SessionInner>>, req: Request) -> Response {
    let started = Instant::now();
    let started_at_iso = now_iso();
    let seq = inner.sequence.fetch_add(1, Ordering::Relaxed);
    let method = req.method().as_str().to_string();
    let raw_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let http_version = version_string(req.version());

    inner.in_flight.fetch_add(1, Ordering::AcqRel);

    // WebSocket upgrades bypass the body tee entirely: the handshake is
    // forwarded upstream and the pump records the message stream instead.
    if crate::ws::is_websocket_upgrade(req.headers()) {
        return proxy_ws_upgrade(inner, req, seq, started_at_iso, started).await;
    }

    let request_headers = from_http_header_map(req.headers());
    let mut upstream_headers = forwardable_headers(&request_headers, true);
    if inner.mode == CaptureMode::Exact {
        // Ask for undecoded bytes so canonical capture equals the application
        // body. Upstreams may still compress; that is recorded as-is.
        upstream_headers.insert("accept-encoding".to_string(), vec!["identity".to_string()]);
    }

    // Read the request body, teeing every chunk into the sink.
    let mut request_sink = inner.new_sink();
    let mut request_chunks: Vec<Bytes> = Vec::new();
    let mut capture_failure: Option<CaptureFailure> = None;
    let mut client_aborted = false;
    let mut body = req.into_body();
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    if let Err(err) = request_sink.write(data) {
                        // Never propagate raw error strings that could embed
                        // body bytes.
                        capture_failure = Some(CaptureFailure {
                            stage: "request-capture".to_string(),
                            message: limit_message(&err)
                                .unwrap_or_else(|| "Request capture sink failed".to_string()),
                        });
                        break;
                    }
                    request_chunks.push(data.clone());
                }
            }
            Some(Err(_)) => {
                client_aborted = true;
                break;
            }
            None => break,
        }
    }

    // Sink failure mirrors the TS behavior of destroying both connections and
    // recording the exchange with a 502 plus the capture failure.
    if let Some(failure) = capture_failure.clone() {
        request_sink.abort();
        let outcome = ExchangeOutcome {
            seq,
            started_at_iso,
            duration_ms: started.elapsed().as_secs_f64() * 1000.0,
            method,
            raw_path,
            http_version,
            request_headers,
            request_bytes: Vec::new(),
            status: 502,
            status_text: "Bad Gateway".to_string(),
            response_http_version: "1.1".to_string(),
            response_headers: BTreeMap::new(),
            stream: StreamState {
                kind: "buffered".to_string(),
                completed: false,
                client_aborted,
                upstream_aborted: true,
                terminal_marker: None,
                error: None,
            },
            failure: Some(failure),
            response_bytes: Vec::new(),
            ws: None,
        };
        return finish_upstream_failed(&inner, outcome).await;
    }

    let request_done = match request_sink.finish() {
        Ok(done) => done,
        Err(err) => {
            inner.record_failure(CaptureFailure {
                stage: "persistence".to_string(),
                message: err.to_string(),
            });
            inner.in_flight.fetch_sub(1, Ordering::AcqRel);
            inner.idle.notify_waiters();
            return bad_gateway().await;
        }
    };
    let request_bytes = request_done.bytes;

    // Forward upstream. Collapse any run of leading slashes to exactly one:
    // "//x" would parse as scheme-relative in Url::join, and empty means "/".
    let path_for_join = format!("/{}", raw_path.trim_start_matches('/'));
    let upstream_url = match inner.target.join(&path_for_join) {
        Ok(url) => url,
        Err(err) => {
            let outcome = upstream_failed_outcome(
                seq,
                started_at_iso,
                &started,
                method,
                raw_path,
                http_version,
                request_headers,
                request_bytes,
                format!("invalid request path: {err}"),
                client_aborted,
            );
            return finish_upstream_failed(&inner, outcome).await;
        }
    };
    let upstream_method = match reqwest::Method::from_bytes(method.as_bytes()) {
        Ok(method) => method,
        Err(_) => {
            inner.in_flight.fetch_sub(1, Ordering::AcqRel);
            inner.idle.notify_waiters();
            return axum::http::StatusCode::BAD_REQUEST.into_response();
        }
    };

    let mut request_builder =
        inner
            .client
            .request(upstream_method, upstream_url)
            .headers(to_http_header_map_with(&upstream_headers, |name| {
                name == "host"
            }));
    // The body is fully buffered by this point, so forward it with an
    // explicit content-length (recomputed by reqwest) instead of re-chunking
    // — matching Node's http.request behavior for buffered bodies. Chunk
    // framing is transport detail outside the capture exactness contract.
    if !request_bytes.is_empty() {
        request_builder = request_builder.body(reqwest::Body::from(request_bytes.clone()));
    }

    let upstream_response = match request_builder.send().await {
        Ok(response) => response,
        Err(err) => {
            let message = if client_aborted {
                "client aborted before upstream connected".to_string()
            } else {
                err.to_string()
            };
            let outcome = upstream_failed_outcome(
                seq,
                started_at_iso,
                &started,
                method,
                raw_path,
                http_version,
                request_headers,
                request_bytes,
                message,
                client_aborted,
            );
            return finish_upstream_failed(&inner, outcome).await;
        }
    };

    let status = upstream_response.status().as_u16();
    let status_text = upstream_response
        .status()
        .canonical_reason()
        .unwrap_or("")
        .to_string();
    let response_headers = from_http_header_map(upstream_response.headers());
    let media_type = first_header(&response_headers, "content-type").map(str::to_string);
    let is_sse = media_type
        .as_deref()
        .map(|m| m.to_lowercase().contains("text/event-stream"))
        .unwrap_or(false);
    let mut sse_parser = is_sse.then(SseParser::new);

    let client_headers = forwardable_headers(&response_headers, false);

    // Tee upstream bytes to the client and the response sink. The exchange
    // settles when the pump task finishes, keeping wait_for_idle accurate.
    let (mut tx, rx) = futures::channel::mpsc::channel::<StdResult<Bytes, std::io::Error>>(16);
    let mut builder = Response::builder().status(status);
    for (name, value) in to_http_header_map(&client_headers) {
        if let Some(name) = name {
            builder = builder.header(name, value);
        }
    }
    let response = builder
        .body(Body::from_stream(rx))
        .unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response());

    let pump_inner = inner.clone();
    let mut response_sink = inner.new_sink();
    let pump_started_at_iso = started_at_iso;
    let pump_response_http_version = version_string(upstream_response.version());
    tokio::spawn(async move {
        let mut upstream_aborted = false;
        let mut client_gone = false;
        let mut stream_error: Option<String> = None;
        let mut response_failure: Option<CaptureFailure> = None;

        let mut stream = upstream_response.bytes_stream();
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => {
                    if let Err(err) = response_sink.write(&chunk) {
                        response_failure = Some(CaptureFailure {
                            stage: "response-capture".to_string(),
                            message: limit_message(&err)
                                .unwrap_or_else(|| "Response capture sink failed".to_string()),
                        });
                        // Destroying the upstream (TS) truncates the stream.
                        upstream_aborted = true;
                        stream_error =
                            Some("upstream connection closed before completion".to_string());
                        break;
                    }
                    if let Some(parser) = sse_parser.as_mut() {
                        parser.feed(&chunk);
                    }
                    if tx.send(Ok(chunk)).await.is_err() {
                        // Client hung up mid-stream.
                        client_gone = true;
                        break;
                    }
                }
                Err(err) => {
                    upstream_aborted = true;
                    stream_error = Some(err.to_string());
                    break;
                }
            }
        }
        if let Some(parser) = sse_parser.as_mut() {
            parser.end();
        }
        drop(tx);

        let terminal_marker = sse_parser
            .as_ref()
            .and_then(|parser| parser.terminal_marker().map(str::to_string));
        let completed = !upstream_aborted && !client_gone && response_failure.is_none();
        let response_bytes = match response_sink.finish() {
            Ok(done) => done.bytes,
            Err(err) => {
                pump_inner.record_failure(CaptureFailure {
                    stage: "persistence".to_string(),
                    message: err.to_string(),
                });
                Vec::new()
            }
        };
        let outcome = ExchangeOutcome {
            seq,
            started_at_iso: pump_started_at_iso,
            duration_ms: started.elapsed().as_secs_f64() * 1000.0,
            method,
            raw_path,
            http_version,
            request_headers,
            request_bytes,
            status,
            status_text,
            response_http_version: pump_response_http_version,
            response_headers,
            stream: StreamState {
                kind: if is_sse { "sse" } else { "buffered" }.to_string(),
                completed,
                client_aborted: client_gone,
                upstream_aborted,
                terminal_marker,
                error: stream_error,
            },
            failure: response_failure,
            response_bytes,
            ws: None,
        };
        finalize_exchange(&pump_inner, outcome);
        pump_inner.in_flight.fetch_sub(1, Ordering::AcqRel);
        pump_inner.idle.notify_waiters();
        pump_inner.mark_activity();
    });

    response
}

/// Proxy an RFC 6455 websocket upgrade: forward the handshake verbatim,
/// mirror the upstream 101 to the client, then run the transparent capture
/// pump until both legs end. Non-101 upstream answers fall back to a plain
/// buffered exchange (no `ws` member). The exchange settles when the pump
/// finishes.
async fn proxy_ws_upgrade(
    inner: Arc<SessionInner>,
    mut req: Request,
    seq: u64,
    started_at_iso: String,
    started: Instant,
) -> Response {
    let method = req.method().as_str().to_string();
    let raw_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let http_version = version_string(req.version());
    let request_headers = from_http_header_map(req.headers());

    // The pending client upgrade must be registered before the request body
    // is consumed; hyper ties the upgraded IO to this request instance.
    let on_upgrade = hyper::upgrade::on(&mut req);
    drop(req.into_body()); // upgrades carry no body

    let mut upstream_headers = forwardable_headers(&request_headers, true);
    // Hop-by-hop upgrade headers were stripped for plain HTTP; restore them
    // so the upstream sees a real upgrade request.
    upstream_headers.insert("connection".to_string(), vec!["Upgrade".to_string()]);
    upstream_headers.insert("upgrade".to_string(), vec!["websocket".to_string()]);

    let path_for_join = format!("/{}", raw_path.trim_start_matches('/'));
    let upstream_url = match inner.target.join(&path_for_join) {
        Ok(url) => url,
        Err(err) => {
            let outcome = ws_failure_outcome(
                seq,
                started_at_iso,
                &started,
                method,
                raw_path,
                http_version,
                request_headers,
                format!("invalid request path: {err}"),
            );
            return finish_upstream_failed(&inner, outcome).await;
        }
    };
    let Ok(upstream_method) = reqwest::Method::from_bytes(method.as_bytes()) else {
        inner.in_flight.fetch_sub(1, Ordering::AcqRel);
        inner.idle.notify_waiters();
        return axum::http::StatusCode::BAD_REQUEST.into_response();
    };

    let request_builder =
        inner
            .client
            .request(upstream_method, upstream_url)
            .headers(to_http_header_map_with(&upstream_headers, |name| {
                name == "host"
            }));
    let upstream_response = match request_builder.send().await {
        Ok(response) => response,
        Err(err) => {
            let outcome = ws_failure_outcome(
                seq,
                started_at_iso,
                &started,
                method,
                raw_path,
                http_version,
                request_headers,
                err.to_string(),
            );
            return finish_upstream_failed(&inner, outcome).await;
        }
    };

    let status = upstream_response.status().as_u16();
    let status_text = upstream_response
        .status()
        .canonical_reason()
        .unwrap_or("")
        .to_string();
    let response_headers = from_http_header_map(upstream_response.headers());

    if status != 101 {
        // Not an upgrade: relay as a plain buffered exchange with no ws
        // member, exactly like an ordinary proxied response.
        let (response_bytes, upstream_aborted) = match upstream_response.bytes().await {
            Ok(bytes) => (bytes.to_vec(), false),
            Err(_) => (Vec::new(), true),
        };
        let client_headers = forwardable_headers(&response_headers, false);
        let mut builder = Response::builder().status(status);
        for (name, value) in to_http_header_map(&client_headers) {
            if let Some(name) = name {
                builder = builder.header(name, value);
            }
        }
        let response = builder
            .body(Body::from(response_bytes.clone()))
            .unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response());
        let outcome = ExchangeOutcome {
            seq,
            started_at_iso,
            duration_ms: started.elapsed().as_secs_f64() * 1000.0,
            method,
            raw_path,
            http_version,
            request_headers,
            request_bytes: Vec::new(),
            status,
            status_text,
            response_http_version: "1.1".to_string(),
            response_headers,
            stream: StreamState {
                kind: "buffered".to_string(),
                completed: !upstream_aborted,
                client_aborted: false,
                upstream_aborted,
                terminal_marker: None,
                error: None,
            },
            failure: None,
            response_bytes,
            ws: None,
        };
        finalize_exchange(&inner, outcome);
        inner.in_flight.fetch_sub(1, Ordering::AcqRel);
        inner.idle.notify_waiters();
        inner.mark_activity();
        return response;
    }

    // 101: mirror the handshake to the client. The accept value forwarded by
    // the upstream matches the client key we passed through verbatim.
    let mut client_headers = forwardable_headers(&response_headers, false);
    client_headers.insert("connection".to_string(), vec!["Upgrade".to_string()]);
    client_headers.insert("upgrade".to_string(), vec!["websocket".to_string()]);
    let meta = WsCaptureMeta {
        protocol: first_header(&response_headers, "sec-websocket-protocol").map(str::to_string),
        ..WsCaptureMeta::default()
    };

    let pump_inner = inner.clone();
    tokio::spawn(async move {
        let failure_stage = |message: String| -> ExchangeOutcome {
            ws_failure_outcome(
                seq,
                started_at_iso.clone(),
                &started,
                method.clone(),
                raw_path.clone(),
                http_version.clone(),
                request_headers.clone(),
                message,
            )
        };

        // Hold the upstream response until its upgraded IO resolves —
        // dropping it early loses the connection (documented race).
        let upstream_io = match upstream_response.upgrade().await {
            Ok(io) => io,
            Err(err) => {
                let outcome = failure_stage(format!("upstream upgrade failed: {err}"));
                finalize_exchange(&pump_inner, outcome);
                pump_inner.in_flight.fetch_sub(1, Ordering::AcqRel);
                pump_inner.idle.notify_waiters();
                pump_inner.mark_activity();
                return;
            }
        };
        let client_io = match tokio::time::timeout(Duration::from_secs(10), on_upgrade).await {
            Ok(Ok(io)) => io,
            _ => {
                let outcome =
                    failure_stage("client never completed the websocket upgrade".to_string());
                finalize_exchange(&pump_inner, outcome);
                pump_inner.in_flight.fetch_sub(1, Ordering::AcqRel);
                pump_inner.idle.notify_waiters();
                pump_inner.mark_activity();
                return;
            }
        };

        // hyper's Upgraded speaks the futures IO traits; TokioIo adapts it
        // for the tokio-trait pump. reqwest's upgraded side already does.
        let result = pump_ws(hyper_util::rt::TokioIo::new(client_io), upstream_io, meta).await;
        let outcome = ExchangeOutcome {
            seq,
            started_at_iso,
            duration_ms: started.elapsed().as_secs_f64() * 1000.0,
            method,
            raw_path,
            http_version,
            request_headers,
            request_bytes: Vec::new(),
            status: 101,
            status_text: "Switching Protocols".to_string(),
            response_http_version: "1.1".to_string(),
            response_headers,
            stream: StreamState {
                kind: "websocket".to_string(),
                completed: result.stream.completed,
                client_aborted: result.client_aborted,
                upstream_aborted: result.upstream_aborted,
                terminal_marker: None,
                error: result.error,
            },
            failure: None,
            response_bytes: Vec::new(),
            ws: Some(result.stream),
        };
        finalize_exchange(&pump_inner, outcome);
        pump_inner.in_flight.fetch_sub(1, Ordering::AcqRel);
        pump_inner.idle.notify_waiters();
        pump_inner.mark_activity();
    });

    let mut builder = Response::builder().status(101);
    for (name, value) in to_http_header_map(&client_headers) {
        if let Some(name) = name {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(Body::empty())
        .unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Failure variant for the websocket path: records the failed handshake as a
/// 502 exchange with no ws member.
#[allow(clippy::too_many_arguments)]
fn ws_failure_outcome(
    seq: u64,
    started_at_iso: String,
    started: &Instant,
    method: String,
    raw_path: String,
    http_version: String,
    request_headers: HeaderMapValues,
    message: String,
) -> ExchangeOutcome {
    ExchangeOutcome {
        seq,
        started_at_iso,
        duration_ms: started.elapsed().as_secs_f64() * 1000.0,
        method,
        raw_path,
        http_version,
        request_headers,
        request_bytes: Vec::new(),
        status: 502,
        status_text: "Bad Gateway".to_string(),
        response_http_version: "1.1".to_string(),
        response_headers: BTreeMap::new(),
        stream: StreamState {
            kind: "buffered".to_string(),
            completed: false,
            client_aborted: false,
            upstream_aborted: true,
            terminal_marker: None,
            error: Some(message.clone()),
        },
        failure: Some(CaptureFailure {
            stage: "upstream-connect".to_string(),
            message,
        }),
        response_bytes: Vec::new(),
        ws: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body as AxumBody;
    use axum::routing::{get, post};
    use std::io::Read;

    const SECRET_MARKER: &str = "sneaky-value-123";

    /// Fixture upstream: JSON echo, an SSE endpoint ending in `[DONE]`, and
    /// a bulk upload endpoint. Returns its base URL.
    async fn spawn_upstream() -> Url {
        let app = Router::new()
            .route(
                "/echo",
                post(|body: Bytes| async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                }),
            )
            .route(
                "/events",
                get(|| async {
                    let chunks: Vec<StdResult<Bytes, std::io::Error>> = vec![
                        Ok(Bytes::from_static(b"data: hello\n\n")),
                        Ok(Bytes::from_static(b"data: [DONE]\n\n")),
                    ];
                    axum::http::Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(AxumBody::from_stream(futures::stream::iter(chunks)))
                        .expect("static response builds")
                }),
            )
            .route("/upload", post(|body: String| async move { body }));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind fixture");
        let address = listener.local_addr().expect("fixture address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Url::parse(&format!("http://{address}")).expect("fixture URL")
    }

    async fn http_client() -> reqwest::Client {
        reqwest::Client::new()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn loopback_proxy_captures_and_exports() {
        let target = spawn_upstream().await;
        let output = tempfile::tempdir().expect("tempdir");
        let session = start_capture_session(CaptureSessionOptions {
            target: target.clone(),
            mode: CaptureMode::Exact,
            output: Some(output.path().to_path_buf()),
            ..CaptureSessionOptions::default()
        })
        .await
        .expect("session starts");

        assert_eq!(session.url().scheme(), "http");
        let ready = session.ready_info().await.expect("ready info");
        assert_eq!(ready["mode"], "exact");
        assert!(ready["url"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:"));

        let client = http_client().await;

        // JSON POST with a credential header and a secret query parameter.
        // The marker also rides inside the body so the export-time
        // reject_secrets scan has a textual body to reject.
        let echo_url = format!("{}echo?api_key={}", session.url(), SECRET_MARKER);
        let echo_payload = json!({ "hello": "world", "note": SECRET_MARKER }).to_string();
        let response = client
            .post(&echo_url)
            .header("authorization", "Bearer test-token-abcdefghij")
            .header("x-api-key", "remove-me-please-1")
            .header("content-type", "application/json")
            .body(echo_payload.clone())
            .send()
            .await
            .expect("proxy reaches upstream");
        assert_eq!(response.status(), 200);
        let echoed: Value =
            serde_json::from_str(&response.text().await.expect("echo body")).expect("echo json");
        assert_eq!(echoed["hello"], "world");

        // SSE passthrough with a terminal marker.
        let sse_url = format!("{}events", session.url());
        let sse_response = client.get(&sse_url).send().await.expect("sse via proxy");
        assert_eq!(
            sse_response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_lowercase().contains("text/event-stream")),
            Some(true)
        );
        let sse_text = sse_response.text().await.expect("sse body");
        assert_eq!(sse_text, "data: hello\n\ndata: [DONE]\n\n");

        // Bulk upload whose request body exceeds the 8 KiB inline limit.
        let big_payload = "x".repeat(9000);
        let upload_response = client
            .post(format!("{}upload", session.url()))
            .body(big_payload.clone())
            .send()
            .await
            .expect("upload via proxy");
        assert_eq!(upload_response.status(), 200);

        session.wait_for_idle().await;

        // Exact-mode export must reject a caller-declared secret value that
        // appears inside the captured bodies (fail closed).
        let rejected = session
            .export(Some(ExportOptions {
                output: tempfile::tempdir()
                    .expect("scan tempdir")
                    .path()
                    .to_path_buf(),
                reject_secrets: vec![SECRET_MARKER.to_string()],
                ..ExportOptions::default()
            }))
            .await;
        assert!(
            matches!(&rejected, Err(Error::SecretFindings(_))),
            "expected fail-closed secret scan, got {rejected:?}"
        );

        let result = session
            .export(None)
            .await
            .expect("export succeeds without rejection list");
        assert_eq!(result.manifest.exchange_count, 3);
        assert_eq!(result.manifest.mode, CaptureMode::Exact);
        assert_eq!(result.output_dir, output.path());

        // Round-trip through load_bundle and inspect the captured exchanges.
        let mut bundle = load_bundle(&result.output_dir).expect("bundle reloads");
        assert_eq!(bundle.exchanges.len(), 3);
        assert_eq!(bundle.manifest.target_origin, origin_of(&target));

        let echo_exchange = bundle
            .exchanges
            .iter()
            .find(|e| e.request.method == "POST" && !e.request.path.contains("upload"))
            .expect("echo exchange captured")
            .clone();
        // Query redaction evidence: name kept, value replaced.
        assert_eq!(
            echo_exchange.request.path.split('?').nth(1),
            Some("api_key=__redacted__")
        );
        // Header redaction evidence: values removed, names retained sorted.
        let redacted = &echo_exchange.request.headers.redacted;
        assert!(
            redacted.contains(&"authorization".to_string()),
            "{redacted:?}"
        );
        assert!(redacted.contains(&"x-api-key".to_string()));
        assert!(
            !echo_exchange
                .request
                .headers
                .values
                .contains_key("authorization"),
            "credential header value must not persist"
        );

        let sse_exchange = bundle
            .exchanges
            .iter()
            .find(|e| e.request.path.starts_with("/events"))
            .expect("sse exchange captured")
            .clone();
        assert_eq!(sse_exchange.response.stream.kind, "sse");
        assert_eq!(
            sse_exchange.response.stream.terminal_marker.as_deref(),
            Some("[DONE]")
        );
        assert!(sse_exchange.response.stream.completed);
        assert!(sse_exchange.failure.is_none());

        let upload_exchange = bundle
            .exchanges
            .iter()
            .find(|e| e.request.path.starts_with("/upload"))
            .expect("upload exchange captured")
            .clone();
        match &upload_exchange.request.body.storage {
            BodyStorage::Blob { path } => {
                assert!(path.starts_with("bodies/"), "{path}");
                let bytes = bundle
                    .read_body(&upload_exchange.request.body)
                    .expect("blob reads back");
                assert_eq!(bytes.len(), big_payload.len());
                assert_eq!(bytes, big_payload.into_bytes());
            }
            other => panic!("expected blob storage for large body, got {other:?}"),
        }

        // Inline round trip for the small echo body.
        let echo_bytes = bundle
            .read_body(&echo_exchange.request.body)
            .expect("inline reads back");
        assert!(serde_json::from_slice::<Value>(&echo_bytes).is_ok());

        session.close().await.expect("close");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exact_mode_fails_closed_on_upstream_failure_but_observe_exports() {
        // Upstream connect fails deterministically.
        // The discard port (9) is not listening; connecting is refused
        // immediately and deterministically (no port-reuse races with the
        // ephemeral fixture servers other tests spawn).
        let target = Url::parse("http://127.0.0.1:9").expect("target URL");

        for (mode, should_fail) in [(CaptureMode::Exact, true), (CaptureMode::Observe, false)] {
            let output = tempfile::tempdir().expect("tempdir");
            let session = start_capture_session(CaptureSessionOptions {
                target: target.clone(),
                mode,
                ..CaptureSessionOptions::default()
            })
            .await
            .expect("session starts");
            let client = http_client().await;
            let response = client
                .get(format!("{}anything", session.url()))
                .send()
                .await
                .expect("proxy answers even when upstream is down");
            assert_eq!(response.status(), 502);
            let text = response.text().await.expect("502 body consumed");
            assert_eq!(text, "{\"error\":\"Bad gateway\"}");
            session.wait_for_idle().await;

            let failures = session.failures().await;
            assert_eq!(failures.len(), 1, "{mode:?} records one failure");
            assert_eq!(failures[0].stage, "upstream-connect");

            let result = session
                .export(Some(ExportOptions {
                    output: output.path().to_path_buf(),
                    ..ExportOptions::default()
                }))
                .await;
            if should_fail {
                let message = result.expect_err("exact export fails closed").to_string();
                assert!(message.contains("failed closed"), "{message}");
            } else {
                let result = result.expect("observe export succeeds despite failure");
                assert_eq!(result.manifest.exchange_count, 1);
            }
            let _ = session.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn idle_timeout_auto_closes_and_exports() {
        let target = spawn_upstream().await;
        let output = tempfile::tempdir().expect("tempdir");
        let session = start_capture_session(CaptureSessionOptions {
            target,
            mode: CaptureMode::Exact,
            output: Some(output.path().to_path_buf()),
            idle_timeout_ms: Some(150),
            ..CaptureSessionOptions::default()
        })
        .await
        .expect("session starts");

        let client = http_client().await;
        client
            .post(format!("{}echo", session.url()))
            .header("content-type", "application/json")
            .body(json!({ "ping": true }).to_string())
            .send()
            .await
            .expect("request through proxy");
        session.wait_for_idle().await;

        tokio::time::sleep(Duration::from_millis(600)).await;
        let manifest_path = output.path().join("manifest.json");
        let mut manifest = String::new();
        std::fs::File::open(&manifest_path)
            .expect("watchdog exported the bundle on idle timeout")
            .read_to_string(&mut manifest)
            .expect("manifest readable");
        assert!(manifest.contains("\"exchangeCount\":1"), "{manifest}");
    }

    /// Raw websocket echo fixture: echoes Text/Binary frames, answers Ping
    /// with an explicit Pong, and completes close handshakes.
    async fn spawn_ws_echo_upstream() -> Url {
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind ws fixture");
        let address = listener.local_addr().expect("ws fixture address");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut ws = match accept_async(stream).await {
                        Ok(ws) => ws,
                        Err(_) => return,
                    };
                    while let Some(Ok(message)) = ws.next().await {
                        match message {
                            Message::Ping(payload) => {
                                if ws.send(Message::Pong(payload)).await.is_err() {
                                    break;
                                }
                            }
                            Message::Close(_) => {
                                let _ = ws.close(None).await;
                                break;
                            }
                            Message::Text(_) | Message::Binary(_) => {
                                if ws.send(message).await.is_err() {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                });
            }
        });
        // The capture session proxies plain HTTP; the websocket upgrade is
        // just a GET on this origin.
        Url::parse(&format!("http://{address}")).expect("fixture URL")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn websocket_upgrade_captures_stream_and_relays() {
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::Message;

        let target = spawn_ws_echo_upstream().await;
        let session = start_capture_session(CaptureSessionOptions {
            target,
            mode: CaptureMode::Observe,
            ..CaptureSessionOptions::default()
        })
        .await
        .expect("session starts");

        // tungstenite requires the ws:// scheme on the client side.
        let ws_url = session
            .url()
            .as_str()
            .trim_end_matches('/')
            .replacen("http://", "ws://", 1);
        let (mut ws, response) = connect_async(format!("{ws_url}/socket"))
            .await
            .expect("upgrade succeeds");
        assert_eq!(response.status(), 101);

        ws.send(Message::text("hello")).await.expect("send text");
        ws.send(Message::binary(b"\x00\x01binary!".to_vec()))
            .await
            .expect("send binary");
        ws.send(Message::Ping(b"pingme".to_vec()))
            .await
            .expect("send ping");

        // Drain echoed traffic until the terminal pong arrives.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut saw_text = false;
        let mut saw_binary = false;
        let mut saw_pong = false;
        while !(saw_text && saw_binary && saw_pong) {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let frame = tokio::time::timeout(remaining, ws.next())
                .await
                .expect("echo within deadline")
                .expect("stream open")
                .expect("frame ok");
            match frame {
                Message::Text(text) if text.as_str() == "hello" => saw_text = true,
                Message::Binary(data) if data.as_slice() == b"\x00\x01binary!" => {
                    saw_binary = true;
                }
                Message::Pong(payload) if payload.as_slice() == b"pingme" => saw_pong = true,
                _ => {}
            }
        }

        // Clean client-initiated close; the pump must observe it as such.
        let close_frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
            code: 1000u16.into(),
            reason: std::borrow::Cow::Borrowed("bye"),
        };
        ws.send(Message::Close(Some(close_frame)))
            .await
            .expect("send close");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match tokio::time::timeout(remaining, ws.next()).await {
                Ok(Some(_)) => continue,
                _ => break,
            }
        }

        session.wait_for_idle().await;
        let exchanges = session.exchanges().await;
        let exchange = exchanges
            .iter()
            .find(|exchange| exchange.ws.is_some())
            .expect("websocket exchange captured");
        assert_eq!(exchange.response.status, 101);
        assert_eq!(exchange.request.method, "GET");
        assert_eq!(exchange.request.path, "/socket");
        assert_eq!(exchange.response.stream.kind, "websocket");
        // Tunnel/TLS metadata belongs to the tls wave, never this capture.
        assert!(exchange.tunnel.is_none());
        assert!(exchange.tls.is_none());

        let stream = exchange.ws.as_ref().expect("ws present");
        assert!(stream.completed);
        assert_eq!(stream.close_code, Some(1000));
        assert_eq!(stream.close_reason.as_deref(), Some("bye"));

        let messages = &stream.messages;
        // First observed frame is the client's text hello, relayed upstream.
        assert_eq!(
            messages[0].direction,
            crate::types::WsDirection::ClientToServer
        );
        assert_eq!(messages[0].opcode, crate::types::WsOpcode::Text);
        assert_eq!(messages[0].text.as_deref(), Some("hello"));
        // Offsets are non-decreasing in arrival order.
        for pair in messages.windows(2) {
            assert!(pair[1].offset_ms >= pair[0].offset_ms);
        }
        // The binary round trip is recorded both directions with base64 data.
        let binary_out = messages
            .iter()
            .find(|m| m.opcode == crate::types::WsOpcode::Binary)
            .expect("client binary recorded");
        assert_eq!(
            binary_out.direction,
            crate::types::WsDirection::ClientToServer
        );
        assert_eq!(
            crate::secret_scan::base64_decode(binary_out.data_base64.as_deref().expect("base64"))
                .expect("decodes"),
            b"\x00\x01binary!".to_vec()
        );
        assert!(messages.iter().any(|m| {
            m.direction == crate::types::WsDirection::ServerToClient
                && m.opcode == crate::types::WsOpcode::Binary
                && m.size == binary_out.size
        }));
        // Ping passthrough: exactly one client ping recorded, at least one
        // pong observed from upstream.
        assert_eq!(
            messages
                .iter()
                .filter(|m| m.opcode == crate::types::WsOpcode::Ping)
                .count(),
            1
        );
        assert!(messages
            .iter()
            .any(|m| m.direction == crate::types::WsDirection::ServerToClient
                && m.opcode == crate::types::WsOpcode::Pong));
        // Close frame is recorded last with its direction preserved.
        let close = messages.last().expect("non-empty stream").clone();
        assert_eq!(close.opcode, crate::types::WsOpcode::Close);
        assert_eq!(close.text.as_deref(), Some("bye"));
        assert_eq!(close.direction, crate::types::WsDirection::ClientToServer);

        session.close().await.expect("close");
    }
}
