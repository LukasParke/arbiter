//! Flow feed transports for the TUI plus the `/__flows*` wire DTOs.
//!
//! The DTOs in this module are the single source of truth for both
//! transports: [`EmbeddedFlowFeed`] reads the live capture session through a
//! watch channel, and [`HttpFlowFeed`] polls `GET /__flows` on a running
//! instance. Both yield exactly the same shapes (serde camelCase), which the
//! HTTP surface in `server/flows_api.rs` also serves.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use url::Url;

use crate::capture::session::CaptureSession;
use crate::types::{BodyStorage, CapturedBody, CapturedExchange, HeaderMapValues, LlmMeta};

/// Detail bodies are truncated at this byte count; `totalSize` carries the
/// full size and `truncated` marks the cut so the viewer can say so.
pub const DETAIL_BODY_TRUNCATE_BYTES: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Wire DTOs (shared by tui/feed + server/flows_api)
// ---------------------------------------------------------------------------

/// Compact LLM columns for the flow list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmSummaryDto {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
}

impl LlmSummaryDto {
    pub fn from_meta(meta: &LlmMeta) -> Self {
        Self {
            provider: meta.provider.clone(),
            model: meta.model.clone(),
            input_tokens: meta.prompt_tokens,
            output_tokens: meta.completion_tokens,
            total_tokens: meta.total_tokens,
        }
    }
}

/// One flow row in the list view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSummaryDto {
    pub sequence: u64,
    /// ISO-8601 timestamp of when the exchange started.
    pub started_at: String,
    pub method: String,
    /// Redacted stored path including query.
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    /// One of `http`, `sse`, `ws`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmSummaryDto>,
}

impl FlowSummaryDto {
    /// Projects an exchange into its list-row shape.
    pub fn from_exchange(exchange: &CapturedExchange) -> Self {
        let kind = if exchange.ws.is_some() {
            "ws"
        } else if exchange.response.stream.kind == "sse" {
            "sse"
        } else {
            "http"
        };
        let host = exchange
            .request
            .headers
            .values
            .get("host")
            .and_then(|values| values.first())
            .map(|host| host.trim().to_string());
        Self {
            sequence: exchange.sequence,
            started_at: exchange.started_at.clone(),
            method: exchange.request.method.clone(),
            path: exchange.request.path.clone(),
            host,
            status: Some(exchange.response.status),
            duration_ms: Some(exchange.duration_ms),
            kind: kind.to_string(),
            llm: exchange.llm.as_ref().map(LlmSummaryDto::from_meta),
        }
    }
}

/// Lazy, possibly-truncated body view served with flow detail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyViewDto {
    /// False when the bytes were not resolvable (e.g. spilled blob evicted).
    pub available: bool,
    /// `utf8` when `text` is decoded text; `base64` when only binary data is
    /// offered; absent when unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Decoded text (`encoding == "utf8"`), truncated per the lazy flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Full body size in bytes, regardless of truncation.
    pub total_size: u64,
    /// True when `text`/data was cut at [`DETAIL_BODY_TRUNCATE_BYTES`].
    pub truncated: bool,
}

impl BodyViewDto {
    pub fn unavailable() -> Self {
        Self {
            available: false,
            encoding: None,
            text: None,
            total_size: 0,
            truncated: false,
        }
    }

    /// Builds a view from raw body bytes. Text-safe bytes render as UTF-8
    /// (invalid sequences replaced, never a panic); everything else is
    /// base64-flagged binary.
    pub fn from_bytes(bytes: &[u8], media_type: Option<&str>) -> Self {
        if bytes.is_empty() {
            return Self {
                available: true,
                encoding: Some("utf8".to_string()),
                text: Some(String::new()),
                total_size: 0,
                truncated: false,
            };
        }
        let textual = media_type
            .map(|mt| mt.starts_with("text/") || mt.contains("json") || mt.contains("xml"))
            .unwrap_or(false);
        let truncated = bytes.len() > DETAIL_BODY_TRUNCATE_BYTES;
        let slice = if truncated {
            &bytes[..DETAIL_BODY_TRUNCATE_BYTES]
        } else {
            bytes
        };
        // Prefer UTF-8 whenever the slice decodes cleanly; fall back to
        // lossy text for textual media types and base64 for binary.
        match std::str::from_utf8(slice) {
            Ok(text) => Self {
                available: true,
                encoding: Some("utf8".to_string()),
                text: Some(text.to_string()),
                total_size: bytes.len() as u64,
                truncated,
            },
            Err(_) if textual => Self {
                available: true,
                encoding: Some("utf8".to_string()),
                text: Some(String::from_utf8_lossy(slice).into_owned()),
                total_size: bytes.len() as u64,
                truncated,
            },
            Err(_) => {
                use base64::Engine as _;
                Self {
                    available: true,
                    encoding: Some("base64".to_string()),
                    text: Some(base64::engine::general_purpose::STANDARD.encode(slice)),
                    total_size: bytes.len() as u64,
                    truncated,
                }
            }
        }
    }
}

/// Full flow detail: summary fields flattened plus headers and body views.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowDetailDto {
    #[serde(flatten)]
    pub summary: FlowSummaryDto,
    pub request_headers: HeaderMapValues,
    pub response_headers: HeaderMapValues,
    pub request_body: BodyViewDto,
    pub response_body: BodyViewDto,
}

impl FlowDetailDto {
    /// Builds detail from an exchange and resolved body bytes (request,
    /// response). Unresolvable legs become unavailable views.
    pub fn from_exchange(
        exchange: &CapturedExchange,
        request_bytes: Option<&[u8]>,
        response_bytes: Option<&[u8]>,
    ) -> Self {
        let resolve = |body: &CapturedBody, bytes: Option<&[u8]>| match (&body.storage, bytes) {
            (_, Some(bytes)) => BodyViewDto::from_bytes(bytes, body.media_type.as_deref()),
            (BodyStorage::InlineBase64 { value }, None) => {
                use base64::Engine as _;
                match base64::engine::general_purpose::STANDARD.decode(value) {
                    Ok(bytes) => BodyViewDto::from_bytes(&bytes, body.media_type.as_deref()),
                    Err(_) => BodyViewDto {
                        available: false,
                        encoding: None,
                        text: None,
                        total_size: body.size,
                        truncated: false,
                    },
                }
            }
            (BodyStorage::Blob { .. }, None) => BodyViewDto {
                available: false,
                encoding: None,
                text: None,
                total_size: body.size,
                truncated: false,
            },
        };
        Self {
            summary: FlowSummaryDto::from_exchange(exchange),
            request_headers: exchange.request.headers.values.clone(),
            response_headers: exchange.response.headers.values.clone(),
            request_body: resolve(&exchange.request.body, request_bytes),
            response_body: resolve(&exchange.response.body, response_bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// Feed transports
// ---------------------------------------------------------------------------

/// Embedded transport attached to a live capture session. New-flow ticks
/// arrive on the session's watch channel; batches pull summaries past the
/// cursor via `flow_summaries(after, limit)`.
#[allow(dead_code)] // reserved for watch-driven refresh
pub struct EmbeddedFlowFeed {
    /// Upstream origin replays are re-sent against (the capture target).
    target: Url,
    session: Arc<CaptureSession>,
    tick: watch::Receiver<u64>,
    cursor: u64,
    bodies: HashMap<String, Vec<u8>>,
    status: FeedStatus,
}

impl EmbeddedFlowFeed {
    pub fn new(session: Arc<CaptureSession>, target: Url, tick: watch::Receiver<u64>) -> Self {
        Self {
            session,
            target,
            tick,
            cursor: 0,
            bodies: HashMap::new(),
            status: FeedStatus::default(),
        }
    }
}

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const BATCH_LIMIT: usize = 500;

/// Last action status (replay outcome, delete result, transport error) for
/// the TUI status bar. Shared behind a mutex because action methods take
/// `&self`.
#[derive(Default)]
struct FeedStatus(Arc<Mutex<Option<String>>>);

impl FeedStatus {
    fn set(&self, message: impl Into<String>) {
        *self.0.lock().expect("feed status lock") = Some(message.into());
    }
    fn get(&self) -> Option<String> {
        self.0.lock().expect("feed status lock").clone()
    }
}

/// Consecutive poll failures before [`HttpFlowFeed`] reports the attached
/// instance as unreachable.
const DISCONNECT_AFTER_FAILURES: u32 = 2;

/// HTTP polling transport against a running instance's flows API
/// (`GET /__flows?after=N&limit=500`). Failures are tolerated transparently,
/// but two consecutive poll failures flip the feed into a `Disconnected`
/// state (see [`FlowFeedExt::disconnected_since`]) so the UI can banner the
/// staleness. Polling continues automatically; the first successful poll
/// clears the state and resets the cursor to 0 so the full snapshot is
/// refetched (callers dedupe by sequence).
pub struct HttpFlowFeed {
    base: Url,
    client: reqwest::Client,
    cursor: u64,
    status: FeedStatus,
    consecutive_failures: u32,
    /// Wall-clock `HH:MM:SS` when the current disconnection began.
    disconnected_since: Option<String>,
    poll_interval: Duration,
}

impl HttpFlowFeed {
    pub fn new(base: Url) -> Self {
        Self::with_poll_interval(base, DEFAULT_POLL_INTERVAL)
    }

    /// Registers a failed poll: after [`DISCONNECT_AFTER_FAILURES`]
    /// consecutive failures the feed reports disconnected and resets its
    /// cursor so the first successful poll refetches everything.
    async fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= DISCONNECT_AFTER_FAILURES {
            if self.disconnected_since.is_none() {
                self.disconnected_since = Some(now_hhmmss());
            }
            self.cursor = 0;
        }
    }

    /// Overrides the tick interval (tests use fast polls).
    pub fn with_poll_interval(base: Url, poll_interval: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            base,
            client,
            cursor: 0,
            status: FeedStatus::default(),
            consecutive_failures: 0,
            disconnected_since: None,
            poll_interval,
        }
    }

    async fn fetch_json<T: serde::de::DeserializeOwned>(&self, url: Url) -> Option<T> {
        match self.client.get(url).send().await {
            Ok(response) => match response.json::<T>().await {
                Ok(parsed) => Some(parsed),
                Err(e) => {
                    self.status.set(format!("flows api decode failed: {e}"));
                    None
                }
            },
            Err(e) => {
                self.status.set(format!("flows api unreachable: {e}"));
                None
            }
        }
    }

    async fn send_action(&self, method: reqwest::Method, path: String) {
        let url = self.base.join(&path).unwrap_or_else(|_| self.base.clone());
        match self.client.request(method, url).send().await {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                self.status.set(format!(
                    "action rejected: HTTP {}",
                    response.status().as_u16()
                ));
            }
            Err(e) => self.status.set(format!("action failed: {e}")),
        }
    }
}

/// `HH:MM:SS` stamp used by the disconnect banner.
fn now_hhmmss() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}
/// Transport-agnostic feed operations used by the TUI event loop. Native
/// async-fn-in-trait: the app always holds a concrete [`FlowFeed`], so no
/// dyn dispatch is required.
#[allow(async_fn_in_trait)]
pub trait FlowFeedExt {
    /// Pulls the next batch of new summaries (empty when nothing changed).
    async fn next_batch(&mut self) -> Vec<FlowSummaryDto>;
    /// Lazily resolves full detail (headers + body views) for one flow.
    async fn flow_detail(&self, seq: u64) -> Option<FlowDetailDto>;
    /// Deletes a flow from the live store.
    async fn delete(&self, seq: u64);
    /// Re-runs a recorded exchange against its target.
    async fn replay(&self, seq: u64);
    /// How long the caller should idle between ticks.
    fn poll_interval(&self) -> Duration {
        DEFAULT_POLL_INTERVAL
    }
    /// Latest status line for display (transport errors, action outcomes).
    fn status_line(&self) -> Option<String>;
    /// Wall-clock time (`HH:MM:SS`) the attached instance became
    /// unreachable: set after two consecutive failed polls, cleared on the
    /// first success. `None` while healthy.
    fn disconnected_since(&self) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FlowFeedKind {
    Embedded,
    Http,
}
pub enum FlowFeed {
    Embedded(EmbeddedFlowFeed),
    Http(HttpFlowFeed),
}

impl FlowFeed {
    pub fn kind(&self) -> FlowFeedKind {
        match self {
            FlowFeed::Embedded(_) => FlowFeedKind::Embedded,
            FlowFeed::Http(_) => FlowFeedKind::Http,
        }
    }
}

impl FlowFeedExt for FlowFeed {
    async fn next_batch(&mut self) -> Vec<FlowSummaryDto> {
        match self {
            FlowFeed::Embedded(feed) => feed.next_batch().await,
            FlowFeed::Http(feed) => feed.next_batch().await,
        }
    }

    async fn flow_detail(&self, seq: u64) -> Option<FlowDetailDto> {
        match self {
            FlowFeed::Embedded(feed) => feed.flow_detail(seq).await,
            FlowFeed::Http(feed) => feed.flow_detail(seq).await,
        }
    }

    async fn delete(&self, seq: u64) {
        match self {
            FlowFeed::Embedded(feed) => feed.delete(seq).await,
            FlowFeed::Http(feed) => feed.delete(seq).await,
        }
    }

    async fn replay(&self, seq: u64) {
        match self {
            FlowFeed::Embedded(feed) => feed.replay(seq).await,
            FlowFeed::Http(feed) => feed.replay(seq).await,
        }
    }

    fn poll_interval(&self) -> Duration {
        match self {
            FlowFeed::Embedded(feed) => feed.poll_interval(),
            FlowFeed::Http(feed) => feed.poll_interval(),
        }
    }

    fn status_line(&self) -> Option<String> {
        match self {
            FlowFeed::Embedded(feed) => feed.status_line(),
            FlowFeed::Http(feed) => feed.status_line(),
        }
    }

    fn disconnected_since(&self) -> Option<String> {
        match self {
            FlowFeed::Embedded(feed) => feed.disconnected_since(),
            FlowFeed::Http(feed) => feed.disconnected_since(),
        }
    }
}

impl FlowFeedExt for EmbeddedFlowFeed {
    async fn next_batch(&mut self) -> Vec<FlowSummaryDto> {
        let summaries = self.session.flow_summaries(self.cursor, BATCH_LIMIT).await;
        if summaries.is_empty() {
            return Vec::new();
        }
        self.cursor = summaries.last().map(|s| s.sequence).unwrap_or(self.cursor);
        // Refresh the body cache so detail views see newly settled blobs.
        self.bodies = self.session.bodies_snapshot().await;
        summaries.iter().map(summary_dto_from_session).collect()
    }

    async fn flow_detail(&self, seq: u64) -> Option<FlowDetailDto> {
        let exchange = self
            .session
            .exchanges()
            .await
            .into_iter()
            .find(|exchange| exchange.sequence == seq)?;
        let lookup = |body: &CapturedBody| match &body.storage {
            BodyStorage::InlineBase64 { .. } => None,
            BodyStorage::Blob { .. } => self.bodies.get(&body.sha256).cloned(),
        };
        let request_bytes = lookup(&exchange.request.body)
            .or_else(|| blob_bytes(&self.bodies, &exchange.request.body));
        let response_bytes = lookup(&exchange.response.body)
            .or_else(|| blob_bytes(&self.bodies, &exchange.response.body));
        Some(FlowDetailDto::from_exchange(
            &exchange,
            request_bytes.as_deref(),
            response_bytes.as_deref(),
        ))
    }

    async fn delete(&self, seq: u64) {
        let removed = self.session.remove_exchange(seq).await;
        if removed {
            self.status.set(format!("deleted flow {seq}"));
        } else {
            self.status
                .set(format!("delete failed: flow {seq} not found"));
        }
    }

    async fn replay(&self, seq: u64) {
        match crate::server::flows_api::replay_session_flow(&self.session, &self.target, seq).await
        {
            Ok(outcome) => self
                .status
                .set(format!("replay {seq}: {}", outcome_label(&outcome))),
            Err(e) => self.status.set(format!("replay {seq} failed: {e}")),
        }
    }

    fn status_line(&self) -> Option<String> {
        self.status.get()
    }
}

fn blob_bytes(bodies: &HashMap<String, Vec<u8>>, body: &CapturedBody) -> Option<Vec<u8>> {
    match &body.storage {
        BodyStorage::Blob { .. } => bodies.get(&body.sha256).cloned(),
        BodyStorage::InlineBase64 { .. } => None,
    }
}

/// Projects a session `FlowSummary` into the shared wire DTO. Isolates every
/// dependency on the session-owned summary shape to this one function.
pub(crate) fn summary_dto_from_session(
    summary: &crate::capture::session::FlowSummary,
) -> FlowSummaryDto {
    FlowSummaryDto {
        sequence: summary.sequence,
        started_at: summary.started_at.clone(),
        method: summary.method.clone(),
        path: summary.path.clone(),
        // The delta-summary projection does not carry the host header.
        host: None,
        status: Some(summary.status),
        duration_ms: Some(summary.duration_ms),
        // Kind is not carried in the delta projection; detail views show it.
        kind: "http".to_string(),
        llm: summary.provider.as_ref().map(|provider| LlmSummaryDto {
            provider: provider.clone(),
            model: summary.model.clone(),
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
        }),
    }
}

/// Short human label for a replay outcome (status-bar friendly).
pub fn outcome_label(outcome: &crate::replay::engine::ReplayOutcome) -> String {
    use crate::replay::engine::ReplayOutcome as O;
    match outcome {
        O::Match => "match".to_string(),
        O::Diff { .. } => "diff".to_string(),
        O::Unreplayable { reason } => format!("unreplayable ({reason})"),
        O::Error { message } => format!("error ({message})"),
    }
}
impl FlowFeed {
    /// Writes the current snapshot as a HAR 1.2 document. Embedded mode
    /// projects the live session via `exchanges_to_har`; HTTP mode downloads
    /// the running instance's `/har` surface.
    pub async fn export_har(&self, path: &std::path::Path) -> crate::error::Result<usize> {
        match self {
            FlowFeed::Embedded(feed) => feed.export_har(path).await,
            FlowFeed::Http(feed) => feed.download_har(path).await,
        }
    }
}

impl EmbeddedFlowFeed {
    async fn export_har(&self, path: &std::path::Path) -> crate::error::Result<usize> {
        let exchanges = self.session.exchanges().await;
        let bodies = self.session.bodies_snapshot().await;
        let count = exchanges.len();
        let origin = crate::server::flows_api::origin_of_public(&self.target);
        let har = tokio::task::spawn_blocking(move || {
            crate::bundle::derive::exchanges_to_har(&exchanges, &origin, &bodies)
        })
        .await
        .map_err(|e| crate::error::Error::other(format!("har task failed: {e}")))?;
        let bytes = serde_json::to_vec_pretty(&har.log).map_err(|e| crate::error::Error::Json {
            context: "serialize HAR".to_string(),
            source: e,
        })?;
        write_bytes_atomic(path, &bytes).await?;
        Ok(count)
    }
}

/// Small atomic file write (temp file + rename) used for exports.
async fn write_bytes_atomic(path: &std::path::Path, bytes: &[u8]) -> crate::error::Result<()> {
    let target = path.to_path_buf();
    let payload = bytes.to_vec();
    tokio::task::spawn_blocking(move || -> crate::error::Result<()> {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| crate::error::Error::io("create export dir", e))?;
        }
        let tmp = target.with_extension("har.tmp");
        std::fs::write(&tmp, &payload)
            .map_err(|e| crate::error::Error::io("write export file", e))?;
        std::fs::rename(&tmp, &target)
            .map_err(|e| crate::error::Error::io("finalize export file", e))?;
        Ok(())
    })
    .await
    .map_err(|e| crate::error::Error::other(format!("export task failed: {e}")))?
}
impl HttpFlowFeed {
    async fn download_har(&self, path: &std::path::Path) -> crate::error::Result<usize> {
        let url = self
            .base
            .join("/har")
            .map_err(|e| crate::error::Error::other(format!("invalid base URL: {e}")))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| crate::error::Error::Http(format!("HAR download failed: {e}")))?;
        if !response.status().is_success() {
            return Err(crate::error::Error::Http(format!(
                "HAR download failed: HTTP {}",
                response.status().as_u16()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| crate::error::Error::Http(format!("HAR body read failed: {e}")))?;
        let count = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/log/entries")
                    .and_then(|entries| entries.as_array())
                    .map(|entries| entries.len())
            })
            .unwrap_or(0);
        write_bytes_atomic(path, &bytes).await?;
        Ok(count)
    }
}
impl FlowFeedExt for HttpFlowFeed {
    async fn next_batch(&mut self) -> Vec<FlowSummaryDto> {
        let mut url = self
            .base
            .join("/__flows")
            .unwrap_or_else(|_| self.base.clone());
        url.query_pairs_mut()
            .append_pair("after", &self.cursor.to_string())
            .append_pair("limit", &BATCH_LIMIT.to_string());
        #[derive(Deserialize)]
        struct FlowsPage {
            latest: u64,
            flows: Vec<FlowSummaryDto>,
        }
        match self.fetch_json::<FlowsPage>(url).await {
            Some(page) => {
                // Clear any disconnect state before advancing the cursor:
                // record_failure reset it to 0, so this poll refetched the
                // full snapshot and callers dedupe by sequence.
                let _recovered = self.disconnected_since.take().is_some();
                self.consecutive_failures = 0;
                if let Some(last) = page.flows.last() {
                    self.cursor = last.sequence.max(self.cursor);
                } else {
                    self.cursor = page.latest;
                }
                page.flows
            }
            None => {
                self.record_failure().await;
                Vec::new()
            }
        }
    }

    async fn flow_detail(&self, seq: u64) -> Option<FlowDetailDto> {
        let url = self.base.join(&format!("/__flows/{seq}")).ok()?;
        self.fetch_json::<FlowDetailDto>(url).await
    }

    async fn delete(&self, seq: u64) {
        self.send_action(reqwest::Method::DELETE, format!("/__flows/{seq}"))
            .await;
    }

    async fn replay(&self, seq: u64) {
        self.send_action(reqwest::Method::POST, format!("/__replay/{seq}"))
            .await;
    }

    fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    fn status_line(&self) -> Option<String> {
        self.status.get()
    }

    fn disconnected_since(&self) -> Option<String> {
        self.disconnected_since.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flows_page_router() -> axum::Router {
        axum::Router::new().route(
            "/__flows",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "latest": 2,
                    "flows": [
                        {
                            "sequence": 1, "startedAt": "2026-08-22T00:00:00.000Z",
                            "method": "GET", "path": "/one", "kind": "http"
                        },
                        {
                            "sequence": 2, "startedAt": "2026-08-22T00:00:01.000Z",
                            "method": "GET", "path": "/two", "kind": "http"
                        }
                    ]
                }))
            }),
        )
    }

    /// Binds a listener with SO_REUSEADDR so the test can kill and revive
    /// the server on the same address.
    fn bind_reusable(addr: std::net::SocketAddr) -> tokio::net::TcpListener {
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket.set_reuseaddr(true).expect("reuseaddr");
        socket.bind(addr).expect("bind");
        let listener = socket.listen(1024).expect("listen");
        listener.local_addr().expect("local addr");
        listener
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_failed_polls_disconnect_then_success_refetches_all() {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let listener = bind_reusable(addr);
        let addr = listener.local_addr().expect("local addr");
        let router = flows_page_router();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve flows page");
        });
        let base = Url::parse(&format!("http://{addr}")).expect("base");
        let mut feed = HttpFlowFeed::with_poll_interval(base, Duration::from_millis(10));

        // Healthy: first poll delivers the full page and advances the cursor
        // past both sequences.
        assert!(feed.disconnected_since().is_none());
        let batch = feed.next_batch().await;
        assert_eq!(
            batch.iter().map(|f| f.sequence).collect::<Vec<_>>(),
            vec![1, 2]
        );

        // Kill the server mid-test and poll until the transport actually
        // starts failing (an already-accepted connection can serve one last
        // request). A single failure is tolerated without flagging
        // disconnection.
        server.abort();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while feed.consecutive_failures == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "poll never failed after server death"
            );
            feed.next_batch().await;
        }
        assert!(
            feed.disconnected_since().is_none(),
            "one failure must not banner the instance dead"
        );

        // Second consecutive failure flips to Disconnected{since}.
        while feed.consecutive_failures < DISCONNECT_AFTER_FAILURES {
            assert!(
                std::time::Instant::now() < deadline,
                "polls never reached the disconnect threshold"
            );
            feed.next_batch().await;
        }
        let since = feed
            .disconnected_since()
            .expect("disconnected after 2 failures");
        assert_eq!(since.len(), 8, "HH:MM:SS stamp");

        // Keep failing while down: the stamp must not move.
        tokio::time::sleep(Duration::from_millis(20)).await;
        feed.next_batch().await;
        assert_eq!(feed.disconnected_since().as_deref(), Some(since.as_str()));

        // Revive on the same port: success clears the banner and resets the
        // cursor to 0 so the previously-consumed sequences are refetched
        // (the app dedupes them by sequence).
        let listener = bind_reusable(addr);
        assert_eq!(listener.local_addr().expect("addr"), addr);
        let router = flows_page_router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve revived");
        });
        let mut recovered = Vec::new();
        for _ in 0..50 {
            recovered = feed.next_batch().await;
            if !recovered.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            recovered.iter().map(|f| f.sequence).collect::<Vec<_>>(),
            vec![1, 2],
            "full refetch includes already-seen sequences"
        );
        assert!(feed.disconnected_since().is_none(), "banner cleared");
    }
}
