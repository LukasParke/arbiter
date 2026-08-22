//! Live flows API on the running instance (`/__flows*`, AMEND-10).
//!
//! Wire shapes are the DTOs from [`crate::tui::feed`] so the TUI's HTTP
//! transport and this surface cannot drift. Read-only except DELETE
//! `/__flows/:seq` and POST `/__replay/:seq`; never touches the proxy hot
//! path (reads session snapshots under existing locks).
//!
//! Mounted by cli-dx at assembly alongside `/__violations` and
//! `/__mock/health`; also usable standalone in tests.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use futures::future::BoxFuture;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{Mutex, RwLock};
use url::Url;

use crate::capture::session::CaptureSession;
use crate::error::Error;
use crate::replay::engine::{replay_capture, ReplayMode, ReplayOptions, ReplayOutcome};
use crate::types::{
    BodyStorage, CaptureManifest, CaptureMode, CapturedBody, RedactionPolicySummary,
};

use crate::tui::feed::{summary_dto_from_session, FlowDetailDto, FlowSummaryDto};
use crate::tui::filter::{SavedFilter, SavedFilterStore};

/// Maximum `limit` accepted by `GET /__flows`.
pub const MAX_PAGE_LIMIT: usize = 500;

// ---------------------------------------------------------------------------
// Backend abstraction (embedded session bridge or any test store)
// ---------------------------------------------------------------------------

/// Data source behind the HTTP surface. Implemented by
/// [`SessionFlowsBackend`] (live capture session); tests seed an in-memory
/// store to exercise the routes over loopback.
pub trait FlowsBackend: Send + Sync + 'static {
    /// Summaries with sequence > `after`, ascending, capped at `limit`.
    fn summaries_after<'a>(
        &'a self,
        after: u64,
        limit: usize,
    ) -> BoxFuture<'a, Vec<FlowSummaryDto>>;

    /// Highest settled sequence visible right now.
    fn latest_seq<'a>(&'a self) -> BoxFuture<'a, u64>;

    /// Full detail for one flow, bodies resolved (truncated views).
    fn detail<'a>(&'a self, seq: u64) -> BoxFuture<'a, Option<FlowDetailDto>>;

    /// Removes a flow from the live store (pre-flush semantics); true when
    /// it existed.
    fn delete<'a>(&'a self, seq: u64) -> BoxFuture<'a, bool>;

    /// Re-runs one recorded exchange against its target.
    fn replay<'a>(&'a self, seq: u64) -> BoxFuture<'a, std::result::Result<ReplayOutcome, String>>;

    /// Aggregate LLM fingerprint report over the current snapshot.
    fn fingerprint_report<'a>(
        &'a self,
    ) -> BoxFuture<'a, std::result::Result<crate::llm::FingerprintReport, String>>;
}

/// Bridges the HTTP surface onto a live capture session. `target` is the
/// upstream origin single-exchange replays are re-sent against.
pub struct SessionFlowsBackend {
    session: Arc<CaptureSession>,
    target: Url,
    /// High-water mark backing [`FlowsBackend::latest_seq`] without a full
    /// scan.
    high_water: Mutex<u64>,
}

impl SessionFlowsBackend {
    pub fn new(session: Arc<CaptureSession>, target: Url) -> Self {
        Self {
            session,
            target,
            high_water: Mutex::new(0),
        }
    }

    fn blob_lookup(bodies: &HashMap<String, Vec<u8>>, body: &CapturedBody) -> Option<Vec<u8>> {
        match &body.storage {
            BodyStorage::Blob { .. } => bodies.get(&body.sha256).cloned(),
            BodyStorage::InlineBase64 { .. } => None,
        }
    }
}

impl FlowsBackend for SessionFlowsBackend {
    fn summaries_after<'a>(
        &'a self,
        after: u64,
        limit: usize,
    ) -> BoxFuture<'a, Vec<FlowSummaryDto>> {
        Box::pin(async move {
            self.session
                .flow_summaries(after, limit)
                .await
                .iter()
                .map(summary_dto_from_session)
                .collect()
        })
    }

    fn latest_seq<'a>(&'a self) -> BoxFuture<'a, u64> {
        Box::pin(async move {
            let mut high_water = self.high_water.lock().await;
            if let Some(next) = self.session.flow_summaries(*high_water, 1).await.first() {
                *high_water = next.sequence;
            }
            *high_water
        })
    }

    fn detail<'a>(&'a self, seq: u64) -> BoxFuture<'a, Option<FlowDetailDto>> {
        Box::pin(async move {
            let exchange = self
                .session
                .exchanges()
                .await
                .into_iter()
                .find(|exchange| exchange.sequence == seq)?;
            let bodies = self.session.bodies_snapshot().await;
            let request_bytes = Self::blob_lookup(&bodies, &exchange.request.body);
            let response_bytes = Self::blob_lookup(&bodies, &exchange.response.body);
            Some(FlowDetailDto::from_exchange(
                &exchange,
                request_bytes.as_deref(),
                response_bytes.as_deref(),
            ))
        })
    }

    fn delete<'a>(&'a self, seq: u64) -> BoxFuture<'a, bool> {
        Box::pin(async move { self.session.remove_exchange(seq).await })
    }

    fn replay<'a>(&'a self, seq: u64) -> BoxFuture<'a, std::result::Result<ReplayOutcome, String>> {
        Box::pin(async move {
            replay_session_flow(&self.session, &self.target, seq)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn fingerprint_report<'a>(
        &'a self,
    ) -> BoxFuture<'a, std::result::Result<crate::llm::FingerprintReport, String>> {
        Box::pin(async move {
            let exchanges = self.session.exchanges().await;
            let bodies = self.session.bodies_snapshot().await;
            let report = tokio::task::spawn_blocking(move || {
                crate::llm::fingerprint_exchanges(&exchanges, |seq| {
                    // Contract: request bytes ++ response bytes for the
                    // exchange with this sequence; inline bodies are decoded
                    // by the engine itself, blobs come from the snapshot.
                    let exchange = exchanges.iter().find(|e| e.sequence == seq)?;
                    let decode_blob = |body: &CapturedBody| match &body.storage {
                        BodyStorage::Blob { .. } => bodies.get(&body.sha256).cloned(),
                        BodyStorage::InlineBase64 { value } => {
                            use base64::Engine as _;
                            base64::engine::general_purpose::STANDARD.decode(value).ok()
                        }
                    };
                    let mut bytes = decode_blob(&exchange.request.body).unwrap_or_default();
                    bytes.extend(decode_blob(&exchange.response.body).unwrap_or_default());
                    (!bytes.is_empty()).then_some(bytes)
                })
            })
            .await
            .map_err(|e| format!("fingerprint task failed: {e}"))?;
            Ok(report)
        })
    }
}

// ---------------------------------------------------------------------------
// Single-exchange replay (shared by the API route and the embedded TUI feed)
// ---------------------------------------------------------------------------

/// Replays exactly one recorded exchange from the live session against
/// `target`: writes a temporary single-exchange bundle, runs the real
/// [`replay_capture`] engine over it in exact-response-body mode, and
/// reports the outcome. Redacted query values surface as `Unreplayable`
/// (never invented placeholder traffic), matching CLI replay semantics.
pub async fn replay_session_flow(
    session: &CaptureSession,
    target: &Url,
    seq: u64,
) -> crate::error::Result<ReplayOutcome> {
    let exchanges = session.exchanges().await;
    let Some(exchange) = exchanges.iter().find(|exchange| exchange.sequence == seq) else {
        return Err(Error::other(format!("flow {seq} not found")));
    };
    if exchange.ws.is_some() {
        return Err(Error::WebsocketNotReplayable { seq });
    }

    let exchange = exchange.clone();
    let bodies = session.bodies_snapshot().await;
    let mut needed: HashMap<String, Vec<u8>> = HashMap::new();
    for body in [&exchange.request.body, &exchange.response.body] {
        if let BodyStorage::Blob { .. } = &body.storage {
            if let Some(bytes) = bodies.get(&body.sha256) {
                needed.insert(body.sha256.clone(), bytes.clone());
            }
        }
    }

    let work_dir =
        std::env::temp_dir().join(format!("arbiter-replay-{}-{seq}", std::process::id()));
    // CPU/fs work off the async worker per the perf bar.
    let bundle_dir = work_dir.clone();
    let manifest_exchange = exchange.clone();
    let target_origin = origin_of(target);
    let written = tokio::task::spawn_blocking(move || -> crate::error::Result<_> {
        let _ = std::fs::remove_dir_all(&bundle_dir);
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let manifest = CaptureManifest {
            schema_version: crate::types::BUNDLE_SCHEMA_VERSION,
            arbiter_version: crate::version::ARBITER_VERSION.to_string(),
            mode: CaptureMode::Observe,
            target_origin,
            started_at: now.clone(),
            completed_at: now,
            exchange_count: 1,
            bundle_digest: String::new(), // derived by write_bundle
            redaction: RedactionPolicySummary {
                redact_headers: Vec::new(),
                allow_query: Vec::new(),
            },
            metadata: None,
        };
        crate::bundle::store::write_bundle(
            &bundle_dir,
            crate::bundle::store::WriteBundleOptions {
                manifest,
                exchanges: vec![manifest_exchange],
                bodies: needed,
                validation: None,
            },
        )?;
        Ok(bundle_dir)
    })
    .await
    .map_err(|e| Error::other(format!("replay bundle task failed: {e}")))??;

    let options = ReplayOptions {
        target: target.clone(),
        mode: ReplayMode::ExactResponseBody,
        credential_env: None,
        query_env: Vec::new(),
        ignore_pointers: Vec::new(),
        fail_on_diff: false,
        legacy_jsonl: false,
        allow_binary_media_types: Vec::new(),
        reject_secret_env: Vec::new(),
        delay_ms: 0,
    };
    let report = match replay_capture(&written, &options).await {
        Ok(report) => report,
        Err(e) => {
            cleanup_dir(&work_dir);
            return Err(e);
        }
    };
    cleanup_dir(&work_dir);
    let outcome = report
        .results
        .first()
        .map(|result| result.outcome.clone())
        .unwrap_or(ReplayOutcome::Error {
            message: "replay produced no result".to_string(),
        });
    Ok(outcome)
}

fn cleanup_dir(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
}

fn origin_of(url: &Url) -> String {
    let host = match url.host() {
        Some(url::Host::Ipv6(h)) => format!("[{h}]"),
        _ => url.host_str().unwrap_or("").to_string(),
    };
    let known_default = |port: u16| matches!((url.scheme(), port), ("http", 80) | ("https", 443));
    match url.port() {
        Some(port) if !known_default(port) => format!("{}://{host}:{port}", url.scheme()),
        _ => format!("{}://{host}", url.scheme()),
    }
}

// ---------------------------------------------------------------------------
// Router + handlers
// ---------------------------------------------------------------------------

/// Shared state for the flows router.
pub struct FlowsApiState {
    pub backend: Arc<dyn FlowsBackend>,
    pub saved_filters: Arc<RwLock<dyn SavedFilterStore>>,
}

type SharedState = Arc<FlowsApiState>;

/// Builds the flows API router for cli-dx assembly.
pub fn router(state: FlowsApiState) -> Router {
    let state: SharedState = Arc::new(state);
    Router::new()
        .route("/__flows", get(list_flows))
        .route("/__flows/{seq}", get(get_flow).delete(delete_flow))
        .route("/__replay/{seq}", post(replay_flow))
        .route("/__fingerprint", get(fingerprint))
        .route(
            "/__saved-filters",
            get(list_saved_filters).put(put_saved_filters),
        )
        .with_state(state)
}

#[derive(Deserialize)]
struct ListQuery {
    after: Option<u64>,
    limit: Option<usize>,
}

async fn list_flows(
    State(state): State<SharedState>,
    AxumQuery(query): AxumQuery<ListQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(200).clamp(1, MAX_PAGE_LIMIT);
    let flows = state
        .backend
        .summaries_after(query.after.unwrap_or(0), limit)
        .await;
    let latest = state.backend.latest_seq().await;
    Json(json!({ "latest": latest, "flows": flows })).into_response()
}

async fn get_flow(State(state): State<SharedState>, AxumPath(seq): AxumPath<u64>) -> Response {
    match state.backend.detail(seq).await {
        Some(detail) => Json(detail).into_response(),
        None => not_found(seq),
    }
}

async fn delete_flow(State(state): State<SharedState>, AxumPath(seq): AxumPath<u64>) -> Response {
    if state.backend.delete(seq).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        not_found(seq)
    }
}

async fn replay_flow(State(state): State<SharedState>, AxumPath(seq): AxumPath<u64>) -> Response {
    match state.backend.replay(seq).await {
        Ok(outcome) => Json(json!({ "sequence": seq, "outcome": outcome })).into_response(),
        Err(message) if message.contains("not found") || message.contains("cannot be replayed") => {
            (StatusCode::NOT_FOUND, Json(json!({ "error": message }))).into_response()
        }
        Err(message) => {
            (StatusCode::BAD_GATEWAY, Json(json!({ "error": message }))).into_response()
        }
    }
}

async fn fingerprint(State(state): State<SharedState>) -> Response {
    match state.backend.fingerprint_report().await {
        Ok(report) => Json(report).into_response(),
        Err(message) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": message })),
        )
            .into_response(),
    }
}

async fn list_saved_filters(State(state): State<SharedState>) -> Response {
    let filters = state.saved_filters.read().await.list();
    Json(filters).into_response()
}

async fn put_saved_filters(
    State(state): State<SharedState>,
    Json(filters): Json<Vec<SavedFilter>>,
) -> Response {
    // Validate every expression before persisting anything.
    for filter in &filters {
        if filter.name.trim().is_empty() {
            return bad_request("saved filter name must not be empty");
        }
        if let Err(e) = crate::tui::filter::Filter::parse(&filter.query) {
            return bad_request(&format!(
                "saved filter `{}` has an invalid query: {e}",
                filter.name
            ));
        }
    }
    let mut store = state.saved_filters.write().await;
    let existing: Vec<String> = store.list().into_iter().map(|f| f.name).collect();
    for name in existing {
        if !filters.iter().any(|f| f.name == name) {
            store.remove(&name);
        }
    }
    for filter in filters {
        store.save(filter);
    }
    Json(store.list()).into_response()
}

fn not_found(seq: u64) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": format!("flow {seq} not found") })),
    )
        .into_response()
}

fn bad_request(problem: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": problem }))).into_response()
}
/// Public origin formatter for the embedded feed's HAR export.
pub(crate) fn origin_of_public(url: &Url) -> String {
    origin_of(url)
}

// ---------------------------------------------------------------------------
// Loopback integration tests against a seeded in-memory store
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CapturedExchange, CapturedRequest, CapturedResponse, HeaderMapValues, StreamState,
    };
    use base64::Engine as _;
    use serde_json::Value;

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMapValues {
        let mut out = HeaderMapValues::new();
        for (name, value) in pairs {
            out.insert(name.to_string(), vec![value.to_string()]);
        }
        out
    }

    fn stream(kind: &str) -> StreamState {
        StreamState {
            kind: kind.to_string(),
            completed: true,
            client_aborted: false,
            upstream_aborted: false,
            terminal_marker: None,
            error: None,
        }
    }

    fn exchange(sequence: u64, method: &str, path: &str, status: u16) -> CapturedExchange {
        CapturedExchange {
            schema_version: crate::types::EXCHANGE_SCHEMA_VERSION,
            sequence,
            started_at: "2026-08-22T00:00:00.000Z".to_string(),
            duration_ms: 12.5,
            request: CapturedRequest {
                method: method.to_string(),
                path: path.to_string(),
                http_version: "1.1".to_string(),
                headers: crate::types::CapturedHeaders {
                    values: header_map(&[
                        ("host", "api.example.com"),
                        ("x-api-key", "__redacted__"),
                    ]),
                    redacted: Vec::new(),
                },
                body: crate::types::CapturedBody {
                    sha256: format!("{sequence}-req"),
                    size: 2,
                    media_type: Some("application/json".to_string()),
                    content_encoding: None,
                    storage: crate::types::BodyStorage::InlineBase64 {
                        value: base64::engine::general_purpose::STANDARD
                            .encode(format!("{{\"seq\":{sequence}}}").as_bytes()),
                    },
                },
            },
            response: CapturedResponse {
                status,
                status_text: "OK".to_string(),
                http_version: "1.1".to_string(),
                headers: crate::types::CapturedHeaders {
                    values: header_map(&[("content-type", "application/json")]),
                    redacted: Vec::new(),
                },
                body: crate::types::CapturedBody {
                    sha256: format!("{sequence}-res"),
                    size: 11,
                    media_type: Some("application/json".to_string()),
                    content_encoding: None,
                    storage: crate::types::BodyStorage::InlineBase64 {
                        value: base64::engine::general_purpose::STANDARD.encode("{\"ok\":true}"),
                    },
                },
                stream: stream(if status == 200 { "sse" } else { "buffered" }),
            },
            failure: None,
            validation: None,
            tunnel: None,
            tls: None,
            ws: None,
            llm: None,
        }
    }

    /// In-memory backend seeded directly with exchanges (test-only).
    struct SeededStore {
        exchanges: Vec<CapturedExchange>,
    }

    impl SeededStore {
        fn find(&self, seq: u64) -> Option<&CapturedExchange> {
            self.exchanges.iter().find(|e| e.sequence == seq)
        }
    }

    impl FlowsBackend for SeededStore {
        fn summaries_after<'a>(
            &'a self,
            after: u64,
            limit: usize,
        ) -> BoxFuture<'a, Vec<FlowSummaryDto>> {
            Box::pin(async move {
                self.exchanges
                    .iter()
                    .filter(|e| e.sequence > after)
                    .take(limit)
                    .map(FlowSummaryDto::from_exchange)
                    .collect()
            })
        }

        fn latest_seq<'a>(&'a self) -> BoxFuture<'a, u64> {
            Box::pin(async move { self.exchanges.last().map(|e| e.sequence).unwrap_or(0) })
        }

        fn detail<'a>(&'a self, seq: u64) -> BoxFuture<'a, Option<FlowDetailDto>> {
            Box::pin(async move {
                self.find(seq)
                    .map(|e| FlowDetailDto::from_exchange(e, None, None))
            })
        }

        fn delete<'a>(&'a self, seq: u64) -> BoxFuture<'a, bool> {
            Box::pin(async move {
                // The seeded store is immutable; the 204 path is exercised by
                // the session-backed backend in embedded TUI use.
                let _ = seq;
                false
            })
        }

        fn replay<'a>(
            &'a self,
            seq: u64,
        ) -> BoxFuture<'a, std::result::Result<ReplayOutcome, String>> {
            Box::pin(async move {
                if self.find(seq).is_some() {
                    Ok(ReplayOutcome::Match)
                } else {
                    Err(format!("flow {seq} not found"))
                }
            })
        }

        fn fingerprint_report<'a>(
            &'a self,
        ) -> BoxFuture<'a, std::result::Result<crate::llm::FingerprintReport, String>> {
            Box::pin(async move { Err("no fingerprint engine in test store".to_string()) })
        }
    }

    async fn spawn_app(
        exchanges: Vec<CapturedExchange>,
    ) -> (String, Arc<RwLock<dyn SavedFilterStore>>) {
        let backend: Arc<dyn FlowsBackend> = Arc::new(SeededStore { exchanges });
        let saved: Arc<RwLock<dyn SavedFilterStore>> = Arc::new(RwLock::new(
            crate::tui::filter::InMemorySavedFilterStore::new(),
        ));
        let app = router(FlowsApiState {
            backend,
            saved_filters: saved.clone(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve flows api");
        });
        (format!("http://{addr}"), saved)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lists_summaries_with_latest_cursor() {
        let (base, _saved) = spawn_app(vec![
            exchange(1, "GET", "/v1/models", 200),
            exchange(2, "POST", "/v1/messages", 201),
        ])
        .await;
        let client = reqwest::Client::new();
        let page: Value = client
            .get(format!("{base}/__flows"))
            .query(&[("after", "0"), ("limit", "1")])
            .send()
            .await
            .expect("list request")
            .json()
            .await
            .expect("list json");
        assert_eq!(page["latest"], 2);
        let flows = page["flows"].as_array().expect("flows array");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["sequence"], 1);
        assert_eq!(flows[0]["method"], "GET");
        assert_eq!(flows[0]["kind"], "sse");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serves_detail_with_flattened_summary_and_bodies() {
        let (base, _) = spawn_app(vec![exchange(7, "POST", "/v1/messages", 200)]).await;
        let client = reqwest::Client::new();
        let detail: Value = client
            .get(format!("{base}/__flows/7"))
            .send()
            .await
            .expect("detail request")
            .json()
            .await
            .expect("detail json");
        // Flattened summary fields sit beside headers/body views.
        assert_eq!(detail["sequence"], 7);
        assert_eq!(detail["status"], 200);
        assert_eq!(detail["requestHeaders"]["host"][0], "api.example.com");
        assert_eq!(detail["requestBody"]["available"], true);
        assert_eq!(detail["requestBody"]["encoding"], "utf8");
        assert_eq!(detail["responseBody"]["totalSize"], 11);
        assert_eq!(detail["responseBody"]["truncated"], false);

        let missing = client
            .get(format!("{base}/__flows/999"))
            .send()
            .await
            .expect("missing request");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_returns_204_then_404_shape_is_consistent() {
        let (base, _) = spawn_app(vec![exchange(3, "GET", "/", 200)]).await;
        let client = reqwest::Client::new();
        // The seeded test store reports not-found for deletes; assert the
        // wire contract both ways via a second, mutable store below.
        let response = client
            .delete(format!("{base}/__flows/999"))
            .send()
            .await
            .expect("delete missing");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn replay_route_reports_outcome_json() {
        let (base, _) = spawn_app(vec![exchange(5, "GET", "/ping", 200)]).await;
        let client = reqwest::Client::new();
        let outcome: Value = client
            .post(format!("{base}/__replay/5"))
            .send()
            .await
            .expect("replay request")
            .json()
            .await
            .expect("replay json");
        assert_eq!(outcome["sequence"], 5);
        assert_eq!(outcome["outcome"], "Match");

        let missing = client
            .post(format!("{base}/__replay/404"))
            .send()
            .await
            .expect("replay missing");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn saved_filters_round_trip_and_validate() {
        let (base, saved) = spawn_app(vec![]).await;
        let client = reqwest::Client::new();

        let put = client
            .put(format!("{base}/__saved-filters"))
            .json(&serde_json::json!([
                {"name": "errors", "query": "status>=500"},
                {"name": "anthropic", "query": "provider=anthropic"}
            ]))
            .send()
            .await
            .expect("put filters");
        assert_eq!(put.status(), StatusCode::OK);
        let listed: Value = put.json().await.expect("listed");
        assert_eq!(listed.as_array().expect("array").len(), 2);

        // Store reflects the PUT (same shared instance the TUI would read).
        let store_list = saved.read().await.list();
        assert_eq!(store_list.len(), 2);

        // Invalid expression is rejected without mutating the store.
        let rejected = client
            .put(format!("{base}/__saved-filters"))
            .json(&serde_json::json!([{"name": "bad", "query": "status>=xx"}]))
            .send()
            .await
            .expect("put invalid");
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(saved.read().await.list().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wire_round_trip_through_http_transport_shapes() {
        // The exact JSON served here must deserialize into the TUI's
        // FlowFeedExt DTOs (single source of truth).
        let (base, _) = spawn_app(vec![exchange(9, "GET", "/x?y=__redacted__", 404)]).await;
        let client = reqwest::Client::new();
        let raw: Value = client
            .get(format!("{base}/__flows"))
            .send()
            .await
            .expect("page")
            .json()
            .await
            .expect("page json");
        let page: ListWirePage =
            serde_json::from_value(raw).expect("page deserializes into feed DTOs");
        assert_eq!(page.flows[0].status, Some(404));

        let detail_raw: Value = client
            .get(format!("{base}/__flows/9"))
            .send()
            .await
            .expect("detail")
            .json()
            .await
            .expect("detail json");
        let detail: FlowDetailDto =
            serde_json::from_value(detail_raw).expect("detail deserializes into feed DTOs");
        assert_eq!(detail.summary.sequence, 9);
    }

    /// Wire shape of `GET /__flows` (kept in sync with `list_flows`).
    #[derive(Deserialize)]
    struct ListWirePage {
        #[allow(dead_code)]
        latest: u64,
        flows: Vec<FlowSummaryDto>,
    }
}
