//! Replay of canonical capture bundles (port of src/replay/index.ts).
//!
//! Recorded requests are resent verbatim — method, path (with redacted query
//! values replaced from `query_env`), forwardable headers, and exact body
//! bytes — to `options.target`, and responses are compared per `mode`.
//! Credentials are injected only from the environment; the stored capture is
//! never updated with secrets. A redacted query value with no replacement
//! makes the exchange unreplayable: Arbiter never invents query values.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use url::Url;

use crate::bundle::{load_bundle, CaptureBundle};
use crate::error::{Error, Result};
use crate::headers::{to_http_header_map_with, HOP_BY_HOP_HEADERS};
use crate::redaction::{redacted_query_names, REDACTED_VALUE};
use crate::replay::compare::{compare_exact, compare_semantic_json, compare_semantic_sse};
use crate::secret_scan::{ensure_clean, scan_exchanges, SecretScanOptions};
use crate::types::{CapturedBody, CapturedExchange};

/// Max buffered replay response bytes (matches the TS default).
const MAX_RESPONSE_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplayMode {
    StatusOnly,
    ExactResponseBody,
    SemanticJsonResponse,
    SemanticSseResponse,
}

impl ReplayMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReplayMode::StatusOnly => "status-only",
            ReplayMode::ExactResponseBody => "exact-response-body",
            ReplayMode::SemanticJsonResponse => "semantic-json-response",
            ReplayMode::SemanticSseResponse => "semantic-sse-response",
        }
    }
}

/// Environment-to-header credential mapping (`env_var`, `header`, optional
/// scheme such as `Bearer`), resolved at replay time. The stored capture is
/// never updated with secrets.
#[derive(Debug, Clone)]
pub struct ReplayCredentialEnv {
    pub env_var: String,
    pub header: String,
    pub scheme: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReplayOptions {
    pub target: Url,
    pub mode: ReplayMode,
    pub credential_env: Option<ReplayCredentialEnv>,
    /// `NAME:ENV_VAR` replacements for redacted query values.
    pub query_env: Vec<(String, String)>,
    /// Volatile JSON pointers excluded from semantic comparisons.
    pub ignore_pointers: Vec<String>,
    pub fail_on_diff: bool,
    /// Treat `bundle_dir` as a legacy traffic JSONL file instead of a bundle.
    pub legacy_jsonl: bool,
    /// Media types the secret scan may treat as unscannable binary.
    pub allow_binary_media_types: Vec<String>,
    /// Environment variables holding secret values the bundle must not
    /// contain; the bundle is secret-scanned before any replay when set.
    pub reject_secret_env: Vec<String>,
    /// Delay between replayed exchanges in milliseconds.
    pub delay_ms: u64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplayExchangeResult {
    pub sequence: u64,
    pub outcome: ReplayOutcome,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ReplayOutcome {
    Match,
    Diff { detail: String },
    Unreplayable { reason: String },
    Error { message: String },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ReplayReport {
    pub mode: ReplayMode,
    pub results: Vec<ReplayExchangeResult>,
    pub matched: usize,
    pub diffed: usize,
}

/// Replay every exchange of a capture bundle (or legacy traffic JSONL) against
/// `options.target` and compare per `options.mode`.
///
/// Fails closed before any request when the bundle contains caller-rejected
/// secrets. With `fail_on_diff`, returns `Err` only after the full report has
/// been produced; the error message carries the matched/diffed counts so the
/// CLI can surface it directly.
pub async fn replay_capture(bundle_dir: &Path, options: &ReplayOptions) -> Result<ReplayReport> {
    if options.target.scheme() != "http" && options.target.scheme() != "https" {
        return Err(Error::other(format!(
            "Unsupported replay target protocol: {}",
            options.target.scheme()
        )));
    }
    let origin = match options.target.origin() {
        url::Origin::Tuple(scheme, host, port) => format!("{scheme}://{host}:{port}"),
        url::Origin::Opaque(_) => {
            return Err(Error::other(format!(
                "Unsupported replay target protocol: {}",
                options.target.scheme()
            )))
        }
    };

    // Resolve every environment mapping up front: a missing variable is a
    // configuration error, never a silent partial replay.
    let mut query_replacements: HashMap<String, String> = HashMap::new();
    for (name, env_var) in &options.query_env {
        let value = resolve_env_value(env_var, &format!("query-env {name}:{env_var}"))?;
        query_replacements.insert(name.clone(), value);
    }
    let credential = match &options.credential_env {
        Some(credential) => Some(resolve_credential_env(credential)?),
        None => None,
    };
    let reject_secrets = options
        .reject_secret_env
        .iter()
        .map(|env_var| resolve_env_value(env_var, "reject-secret-env"))
        .collect::<Result<Vec<_>>>()?;

    let mut source = load_source(bundle_dir, options.legacy_jsonl)?;

    if !reject_secrets.is_empty() {
        let scan_options = SecretScanOptions {
            reject_secrets,
            allow_binary_media_types: options.allow_binary_media_types.clone(),
        };
        let bodies = source.read_all_bodies()?;
        let findings = scan_exchanges(
            source.exchanges(),
            &bodies,
            source.metadata(),
            &scan_options,
        );
        ensure_clean(findings)?;
    }

    let client = reqwest::Client::builder()
        // Recorded requests are replayed verbatim; redirect following would
        // compare a different exchange than the one captured.
        .redirect(Policy::none())
        .build()
        .map_err(|e| Error::Http(format!("build replay client: {e}")))?;

    let exchanges: Vec<CapturedExchange> = source.exchanges().to_vec();
    let mut results = Vec::with_capacity(exchanges.len());
    for (index, exchange) in exchanges.iter().enumerate() {
        let outcome = try_replay_exchange(
            &mut source,
            exchange,
            options,
            &origin,
            &query_replacements,
            &credential,
            &client,
        )
        .await;
        results.push(ReplayExchangeResult {
            sequence: exchange.sequence,
            outcome,
        });
        if options.delay_ms > 0 && index + 1 < exchanges.len() {
            tokio::time::sleep(Duration::from_millis(options.delay_ms)).await;
        }
    }

    let matched = results
        .iter()
        .filter(|r| r.outcome == ReplayOutcome::Match)
        .count();
    let diffed = results.len() - matched;
    let report = ReplayReport {
        mode: options.mode,
        results,
        matched,
        diffed,
    };
    if options.fail_on_diff && diffed > 0 {
        return Err(Error::other(format!(
            "Replay found {diffed} differing exchange(s) out of {} (matched {matched}) against {}",
            report.results.len(),
            options.target.origin().ascii_serialization(),
        )));
    }
    Ok(report)
}

/// Canonical bundle or legacy traffic JSONL, behind one read interface.
enum SourceBundle {
    Canonical(Box<CaptureBundle>),
    Legacy(Vec<CapturedExchange>),
}

impl SourceBundle {
    fn exchanges(&self) -> &[CapturedExchange] {
        match self {
            SourceBundle::Canonical(bundle) => &bundle.exchanges,
            SourceBundle::Legacy(exchanges) => exchanges,
        }
    }

    fn metadata(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            SourceBundle::Canonical(bundle) => bundle.manifest.metadata.as_ref(),
            SourceBundle::Legacy(_) => None,
        }
    }

    fn read_body(&mut self, body: &CapturedBody) -> Result<Vec<u8>> {
        match self {
            SourceBundle::Canonical(bundle) => bundle.read_body(body),
            SourceBundle::Legacy(_) => match &body.storage {
                crate::types::BodyStorage::InlineBase64 { value } => {
                    crate::secret_scan::base64_decode(value)
                        .map_err(|e| Error::other(format!("malformed base64 in inline body: {e}")))
                }
                crate::types::BodyStorage::Blob { path } => Err(Error::other(format!(
                    "legacy traffic line references blob body {path}; not replayable"
                ))),
            },
        }
    }

    fn read_all_bodies(&mut self) -> Result<HashMap<String, Vec<u8>>> {
        match self {
            SourceBundle::Canonical(bundle) => bundle.read_all_bodies(),
            SourceBundle::Legacy(_) => Ok(HashMap::new()),
        }
    }
}

fn load_source(bundle_dir: &Path, legacy_jsonl: bool) -> Result<SourceBundle> {
    if legacy_jsonl {
        Ok(SourceBundle::Legacy(super::legacy::load_legacy_jsonl(
            bundle_dir,
        )?))
    } else {
        Ok(SourceBundle::Canonical(Box::new(load_bundle(bundle_dir)?)))
    }
}

struct ResolvedCredential {
    header: HeaderName,
    value: String,
}

fn resolve_credential_env(credential: &ReplayCredentialEnv) -> Result<ResolvedCredential> {
    let secret = resolve_env_value(&credential.env_var, "credential-env")?;
    let value = match &credential.scheme {
        Some(scheme) => format!("{scheme} {secret}"),
        None => secret,
    };
    let header = HeaderName::from_bytes(credential.header.as_bytes())
        .map_err(|e| Error::other(format!("invalid credential header name: {e}")))?;
    Ok(ResolvedCredential { header, value })
}

fn resolve_env_value(env_var: &str, flag: &str) -> Result<String> {
    match std::env::var(env_var) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(Error::other(format!(
            "{flag}: environment variable {env_var} is not set"
        ))),
    }
}

async fn try_replay_exchange(
    source: &mut SourceBundle,
    exchange: &CapturedExchange,
    options: &ReplayOptions,
    origin: &str,
    query_replacements: &HashMap<String, String>,
    credential: &Option<ResolvedCredential>,
    client: &reqwest::Client,
) -> ReplayOutcome {
    match try_replay_exchange_inner(
        source,
        exchange,
        options,
        origin,
        query_replacements,
        credential,
        client,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => ReplayOutcome::Error {
            message: err.to_string(),
        },
    }
}

async fn try_replay_exchange_inner(
    source: &mut SourceBundle,
    exchange: &CapturedExchange,
    options: &ReplayOptions,
    origin: &str,
    query_replacements: &HashMap<String, String>,
    credential: &Option<ResolvedCredential>,
    client: &reqwest::Client,
) -> Result<ReplayOutcome> {
    let request_bytes = source.read_body(&exchange.request.body)?;

    // A redacted query value is not replayable: sending the placeholder
    // upstream would call the target with invented data. Either the
    // environment supplies every replacement or the exchange fails as
    // unreplayable.
    let mut replay_path = exchange.request.path.clone();
    if !redacted_query_names(&replay_path).is_empty() {
        let query_start = replay_path
            .find('?')
            .ok_or_else(|| Error::other("redacted query names but no query separator"))?;
        let mut missing: Vec<String> = Vec::new();
        let mut rebuilt_pairs: Vec<String> = Vec::new();
        for pair in replay_path[query_start + 1..].split('&') {
            let Some(eq) = pair.find('=') else {
                rebuilt_pairs.push(pair.to_string());
                continue;
            };
            if &pair[eq + 1..] != REDACTED_VALUE {
                // Allowed (non-redacted) pairs keep their original text.
                rebuilt_pairs.push(pair.to_string());
                continue;
            }
            let raw_name = &pair[..eq];
            let name = decode_query_name(raw_name);
            match query_replacements.get(&name) {
                Some(replacement) => {
                    rebuilt_pairs.push(format!(
                        "{raw_name}={}",
                        encode_query_component(replacement)
                    ));
                }
                None => {
                    if !missing.contains(&name) {
                        missing.push(name);
                    }
                    rebuilt_pairs.push(pair.to_string());
                }
            }
        }
        if !missing.is_empty() {
            return Ok(ReplayOutcome::Unreplayable {
                reason: format!(
                    "Unreplayable: query value(s) redacted at capture with no replacement provided: {}",
                    missing.join(", ")
                ),
            });
        }
        replay_path = format!(
            "{}?{}",
            &replay_path[..query_start],
            rebuilt_pairs.join("&")
        );
    }

    let url = if replay_path.starts_with('/') {
        format!("{origin}{replay_path}")
    } else {
        format!("{origin}/{replay_path}")
    };

    // Recorded request headers, minus hop-by-hop and framing headers the
    // client recomputes (host comes from the target URL).
    let skipped = |name: &str| {
        HOP_BY_HOP_HEADERS.contains(&name)
            || matches!(name, "content-length" | "host" | "accept-encoding")
    };
    let mut headers: HeaderMap = to_http_header_map_with(&exchange.request.headers.values, skipped);
    if let Some(credential) = credential {
        headers.insert(
            credential.header.clone(),
            HeaderValue::from_str(&credential.value)
                .map_err(|e| Error::other(format!("invalid credential header value: {e}")))?,
        );
    }
    headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );

    let method = reqwest::Method::from_bytes(exchange.request.method.as_bytes())
        .map_err(|e| Error::other(format!("invalid recorded method: {e}")))?;
    let mut request = client.request(method, &url).headers(headers);
    if !request_bytes.is_empty() {
        request = request.body(request_bytes);
    }

    let response = request
        .send()
        .await
        .map_err(|e| Error::Http(format!("replay request to {url} failed: {e}")))?;
    let replayed_status = response.status().as_u16();
    let response_bytes = read_response_body(response).await?;

    let status_match = replayed_status == exchange.response.status;

    let mut problems: Vec<String> = Vec::new();
    if !status_match {
        problems.push(format!(
            "status mismatch: recorded {}, replayed {replayed_status}",
            exchange.response.status
        ));
    }
    if options.mode != ReplayMode::StatusOnly {
        if options.mode == ReplayMode::SemanticSseResponse && exchange.response.stream.kind != "sse"
        {
            // Applying SSE comparison to a non-SSE exchange must be a visible
            // failure, never a vacuous pass.
            problems.push(format!(
                "Recorded exchange is not SSE (stream kind: {}); semantic-sse-response does not apply",
                exchange.response.stream.kind
            ));
        } else {
            let expected = source.read_body(&exchange.response.body)?;
            let diff = match options.mode {
                ReplayMode::ExactResponseBody => compare_exact(&response_bytes, &expected),
                ReplayMode::SemanticJsonResponse => {
                    compare_semantic_json(&response_bytes, &expected, &options.ignore_pointers)
                }
                ReplayMode::SemanticSseResponse => {
                    compare_semantic_sse(&response_bytes, &expected, &options.ignore_pointers)
                }
                ReplayMode::StatusOnly => None,
            };
            if let Some(detail) = diff {
                problems.push(detail);
            }
        }
    }

    Ok(if problems.is_empty() {
        ReplayOutcome::Match
    } else {
        ReplayOutcome::Diff {
            detail: problems.join("; "),
        }
    })
}

async fn read_response_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::Http(format!("read replay response: {e}")))?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Http(format!(
                "Replay response exceeded {MAX_RESPONSE_BYTES} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Percent-decode a query name with `+` treated as space; returns the input
/// on invalid escapes (mirrors the TS decodeQueryName).
fn decode_query_name(text: &str) -> String {
    let plus_fixed = text.replace('+', " ");
    percent_encoding::percent_decode_str(&plus_fixed)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| text.to_string())
}

/// Percent-encode a query value with `encodeURIComponent` semantics.
fn encode_query_component(value: &str) -> String {
    const COMPONENT_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'!')
        .remove(b'~')
        .remove(b'*')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')');
    percent_encoding::percent_encode(value.as_bytes(), COMPONENT_SET).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{make_captured_body, write_bundle, WriteBundleOptions};
    use crate::redaction::RedactionPolicy;
    use crate::types::{
        CaptureMode, CapturedHeaders, CapturedRequest, CapturedResponse, StreamState,
        BUNDLE_SCHEMA_VERSION,
    };
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use std::sync::{Arc, Mutex, PoisonError};

    /// Poison-tolerant lock: a panicked handler in one test must not cascade
    /// into unrelated assertion failures.
    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // ---- fixtures ----

    fn empty_headers() -> CapturedHeaders {
        CapturedHeaders {
            values: BTreeMap::new(),
            redacted: vec![],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recorded_exchange(
        seq: u64,
        path: &str,
        method: &str,
        req_body: &[u8],
        status: u16,
        resp_body: &[u8],
        stream_kind: &str,
    ) -> CapturedExchange {
        let request_body = make_captured_body(req_body, None, None, None).unwrap();
        let response_body = make_captured_body(resp_body, None, None, None).unwrap();
        CapturedExchange {
            schema_version: 1,
            sequence: seq,
            started_at: "2026-08-21T00:00:00.000Z".into(),
            duration_ms: 1.0,
            request: CapturedRequest {
                method: method.into(),
                path: path.into(),
                http_version: "1.1".into(),
                headers: empty_headers(),
                body: request_body,
            },
            response: CapturedResponse {
                status,
                status_text: String::new(),
                http_version: "1.1".into(),
                headers: empty_headers(),
                body: response_body,
                stream: StreamState {
                    kind: stream_kind.into(),
                    completed: true,
                    client_aborted: false,
                    upstream_aborted: false,
                    terminal_marker: None,
                    error: None,
                },
            },
            failure: None,
            validation: None,
            tunnel: None,
            tls: None,
            ws: None,
            llm: None,
        }
    }

    fn write_test_bundle(dir: &Path, exchanges: Vec<CapturedExchange>) -> std::path::PathBuf {
        let out = dir.join("capture");
        let manifest = crate::types::CaptureManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            arbiter_version: "1.1.0".into(),
            mode: CaptureMode::Exact,
            target_origin: "https://api.example.com".into(),
            started_at: "2026-08-21T00:00:00.000Z".into(),
            completed_at: "2026-08-21T00:00:01.000Z".into(),
            exchange_count: 0,
            bundle_digest: "0".repeat(64),
            redaction: RedactionPolicy::default().summary(),
            metadata: None,
        };
        write_bundle(
            &out,
            WriteBundleOptions {
                manifest,
                exchanges,
                bodies: HashMap::new(),
                validation: None,
            },
        )
        .unwrap();
        out
    }

    fn options_for(target: Url, mode: ReplayMode) -> ReplayOptions {
        ReplayOptions {
            target,
            mode,
            credential_env: None,
            query_env: vec![],
            ignore_pointers: vec![],
            fail_on_diff: false,
            legacy_jsonl: false,
            allow_binary_media_types: vec![],
            reject_secret_env: vec![],
            delay_ms: 0,
        }
    }

    type SharedLog = Arc<Mutex<Vec<String>>>;

    async fn seen_requests(log: &SharedLog) -> Vec<String> {
        lock(log).clone()
    }

    // ---- exact mode ----

    #[tokio::test]
    async fn exact_mode_matches_identical_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router =
            axum::Router::new().route("/x", get(|| async { (StatusCode::OK, "hello") }));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1, "/x", "GET", b"", 200, b"hello", "buffered",
            )],
        );
        let report = replay_capture(&bundle, &options_for(target, ReplayMode::ExactResponseBody))
            .await
            .unwrap();
        assert_eq!(report.matched, 1);
        assert_eq!(report.diffed, 0);
        assert_eq!(report.results[0].outcome, ReplayOutcome::Match);
    }

    #[tokio::test]
    async fn exact_mode_reports_diff_with_offset_and_fails_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router =
            axum::Router::new().route("/x", get(|| async { (StatusCode::OK, "hellX") }));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1, "/x", "GET", b"", 200, b"hello", "buffered",
            )],
        );
        let mut options = options_for(target, ReplayMode::ExactResponseBody);
        let report = replay_capture(&bundle, &options).await.unwrap();
        assert_eq!(report.matched, 0);
        assert_eq!(report.diffed, 1);
        match &report.results[0].outcome {
            ReplayOutcome::Diff { detail } => {
                assert!(detail.contains("offset 4"), "detail: {detail}");
            }
            other => panic!("expected Diff, got {other:?}"),
        }

        // fail_on_diff: full report produced first, then Err with counts.
        options.fail_on_diff = true;
        let err = replay_capture(&bundle, &options).await.unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("1 differing exchange(s) out of 1"),
            "err: {message}"
        );
    }

    #[tokio::test]
    async fn status_mismatch_is_a_diff() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router =
            axum::Router::new().route("/x", get(|| async { StatusCode::NOT_FOUND }));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1, "/x", "GET", b"", 200, b"hello", "buffered",
            )],
        );
        let report = replay_capture(&bundle, &options_for(target, ReplayMode::ExactResponseBody))
            .await
            .unwrap();
        match &report.results[0].outcome {
            ReplayOutcome::Diff { detail } => {
                assert!(detail.contains("status mismatch: recorded 200, replayed 404"));
            }
            other => panic!("expected Diff, got {other:?}"),
        }
    }

    // ---- semantic JSON mode ----

    #[tokio::test]
    async fn semantic_json_honors_ignore_pointers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router = axum::Router::new().route(
            "/data",
            get(|| async { (StatusCode::OK, "{\"id\":\"b\",\"v\":1}") }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1,
                "/data",
                "GET",
                b"",
                200,
                br#"{"id":"a","v":1}"#,
                "buffered",
            )],
        );
        let mut options = options_for(target, ReplayMode::SemanticJsonResponse);
        options.ignore_pointers = vec!["/id".into()];
        let report = replay_capture(&bundle, &options).await.unwrap();
        assert_eq!(report.matched, 1);

        // Without the ignore pointer the volatile field is a diff at /id.
        options.ignore_pointers = vec![];
        let report = replay_capture(&bundle, &options).await.unwrap();
        match &report.results[0].outcome {
            ReplayOutcome::Diff { detail } => {
                assert!(detail.contains("/id"), "detail: {detail}");
            }
            other => panic!("expected Diff, got {other:?}"),
        }
    }

    // ---- semantic SSE mode ----

    #[tokio::test]
    async fn semantic_sse_matches_streams_and_fails_loudly_on_non_sse() {
        let recorded_body = b"event: delta\ndata: {\"t\":\"x\",\"id\":\"a\"}\n\ndata: [DONE]\n\n";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router = axum::Router::new().route(
            "/stream",
            get(|| async {
                (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    "event: delta\ndata: {\"t\":\"x\",\"id\":\"b\"}\n\ndata: [DONE]\n\n",
                )
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1,
                "/stream",
                "GET",
                b"",
                200,
                recorded_body,
                "sse",
            )],
        );
        let mut options = options_for(target, ReplayMode::SemanticSseResponse);
        options.ignore_pointers = vec!["/id".into()];
        let report = replay_capture(&bundle, &options).await.unwrap();
        assert_eq!(report.matched, 1, "results: {:?}", report.results);

        // A buffered (non-SSE) recorded exchange under SSE mode must be a
        // visible diff, never a vacuous match.
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1, "/stream", "GET", b"", 200, b"plain", "buffered",
            )],
        );
        let report = replay_capture(&bundle, &options).await.unwrap();
        match &report.results[0].outcome {
            ReplayOutcome::Diff { detail } => {
                assert!(detail.contains("not SSE"), "detail: {detail}");
            }
            other => panic!("expected Diff, got {other:?}"),
        }
    }

    // ---- unreplayable redacted query values ----

    #[tokio::test]
    async fn redacted_query_without_replacement_is_unreplayable() {
        let log: SharedLog = Arc::new(Mutex::new(Vec::new()));
        let seen = log.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router = axum::Router::new()
            .route(
                "/x",
                get(
                    |axum::extract::RawQuery(query): axum::extract::RawQuery| async move {
                        lock(&seen).push(query.unwrap_or_default());
                        (StatusCode::OK, "token")
                    },
                ),
            )
            .with_state(log.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1,
                "/x?token=__redacted__&keep=1",
                "GET",
                b"",
                200,
                b"token",
                "buffered",
            )],
        );

        // No query_env: fail closed as unreplayable; nothing is sent upstream.
        let options = options_for(target.clone(), ReplayMode::ExactResponseBody);
        let report = replay_capture(&bundle, &options).await.unwrap();
        assert_eq!(
            report.results[0].outcome,
            ReplayOutcome::Unreplayable {
                reason: "Unreplayable: query value(s) redacted at capture with no replacement provided: token"
                    .into(),
            }
        );
        assert_eq!(report.diffed, 1);
        assert!(seen_requests(&log).await.is_empty());

        // With a replacement from the environment the request is replayed and
        // the substituted value reaches the target.
        let env_var = "ARBITER_REPLAY_TEST_TOKEN_A";
        std::env::set_var(env_var, "sk-secret-value");
        let mut options = options_for(target, ReplayMode::ExactResponseBody);
        options.query_env = vec![("token".into(), env_var.into())];
        let report = replay_capture(&bundle, &options).await.unwrap();
        assert_eq!(report.results[0].outcome, ReplayOutcome::Match);
        assert_eq!(
            seen_requests(&log).await,
            vec!["token=sk-secret-value&keep=1".to_string()]
        );
    }

    // ---- credential injection ----

    #[tokio::test]
    async fn credential_env_injects_header_upstream() {
        let seen: SharedLog = Arc::new(Mutex::new(Vec::new()));
        let auth_log = seen.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router = axum::Router::new()
            .route(
                "/x",
                get(|headers: axum::http::HeaderMap| async move {
                    lock(&auth_log).push(
                        headers
                            .get("authorization")
                            .map(|v| v.to_str().unwrap().to_string())
                            .unwrap_or_default(),
                    );
                    (StatusCode::OK, "ok")
                }),
            )
            .with_state(seen.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1, "/x", "GET", b"", 200, b"ok", "buffered",
            )],
        );
        let env_var = "ARBITER_REPLAY_TEST_TOKEN_B";
        std::env::set_var(env_var, "abc123");
        let mut options = options_for(target, ReplayMode::StatusOnly);
        options.credential_env = Some(ReplayCredentialEnv {
            env_var: env_var.into(),
            header: "authorization".into(),
            scheme: Some("Bearer".into()),
        });
        let report = replay_capture(&bundle, &options).await.unwrap();
        assert_eq!(report.matched, 1);
        assert_eq!(*lock(&seen), vec!["Bearer abc123".to_string()]);
    }

    #[tokio::test]
    async fn missing_credential_env_fails_before_any_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router =
            axum::Router::new().route("/x", get(|| async { (StatusCode::OK, "ok") }));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1, "/x", "GET", b"", 200, b"ok", "buffered",
            )],
        );
        let mut options = options_for(target, ReplayMode::StatusOnly);
        options.credential_env = Some(ReplayCredentialEnv {
            env_var: "ARBITER_DEFINITELY_UNSET_VAR_XYZ".into(),
            header: "authorization".into(),
            scheme: None,
        });
        let err = replay_capture(&bundle, &options).await.unwrap_err();
        assert!(
            err.to_string().contains("ARBITER_DEFINITELY_UNSET_VAR_XYZ"),
            "err: {err}"
        );
    }

    // ---- secret scan ----

    #[tokio::test]
    async fn reject_secret_env_scans_bundle_before_replay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router =
            axum::Router::new().route("/x", get(|| async { (StatusCode::OK, "hello") }));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let leaked = "sk-ant-abcdefghijklmnop";
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1,
                "/x",
                "GET",
                b"",
                200,
                format!("hello {leaked}").as_bytes(),
                "buffered",
            )],
        );
        let env_var = "ARBITER_REPLAY_TEST_SECRET_C";
        std::env::set_var(env_var, leaked);
        let mut options = options_for(target, ReplayMode::ExactResponseBody);
        options.reject_secret_env = vec![env_var.into()];
        let err = replay_capture(&bundle, &options).await.unwrap_err();
        assert!(err.to_string().contains("Secret scan failed"), "err: {err}");
    }

    // ---- request fidelity ----

    #[tokio::test]
    async fn replays_method_body_and_headers_verbatim() {
        let seen: SharedLog = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router = axum::Router::new()
            .route(
                "/submit",
                post(
                    |headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
                        let content_type = headers
                            .get("content-type")
                            .map(|v| v.to_str().unwrap().to_string())
                            .unwrap_or_default();
                        let accept_encoding = headers
                            .get("accept-encoding")
                            .map(|v| v.to_str().unwrap().to_string())
                            .unwrap_or_default();
                        lock(&log).push(format!(
                            "{content_type}|{accept_encoding}|{}",
                            String::from_utf8_lossy(&body)
                        ));
                        (StatusCode::CREATED, "created")
                    },
                ),
            )
            .with_state(seen.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let mut exchange = recorded_exchange(
            7,
            "/submit",
            "POST",
            b"payload=1",
            201,
            b"created",
            "buffered",
        );
        exchange.request.headers.values.insert(
            "content-type".into(),
            vec!["application/x-www-form-urlencoded".into()],
        );
        exchange
            .request
            .headers
            .values
            .insert("accept-encoding".into(), vec!["gzip".into()]);
        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(dir.path(), vec![exchange]);

        let options = options_for(target, ReplayMode::ExactResponseBody);
        let report = replay_capture(&bundle, &options).await.unwrap();
        assert_eq!(report.matched, 1);
        assert_eq!(
            *lock(&seen),
            vec!["application/x-www-form-urlencoded|identity|payload=1".to_string()]
        );
    }

    // ---- legacy JSONL replay ----

    #[tokio::test]
    async fn replays_legacy_jsonl_against_target() {
        let seen: SharedLog = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router = axum::Router::new()
            .route(
                "/legacy",
                get(|| async move {
                    lock(&log).push("hit".into());
                    (StatusCode::OK, "{\"ok\":true}")
                }),
            )
            .with_state(seen.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let traffic = dir.path().join("traffic.jsonl");
        std::fs::write(
            &traffic,
            serde_json::json!({
                "timestamp": "2026-08-21T00:00:00.000Z",
                "method": "GET",
                "path": "/legacy",
                "response_status": 200,
                "response_body": "{\"ok\":true}"
            })
            .to_string(),
        )
        .unwrap();

        let mut options = options_for(target, ReplayMode::ExactResponseBody);
        options.legacy_jsonl = true;
        let report = replay_capture(&traffic, &options).await.unwrap();
        assert_eq!(report.matched, 1);
        assert_eq!(*lock(&seen), vec!["hit".to_string()]);
    }

    // ---- transport errors ----

    #[tokio::test]
    async fn unreachable_target_is_an_error_outcome() {
        // Port 1 on loopback: nothing listens there.
        let target = Url::parse("http://127.0.0.1:1").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1, "/x", "GET", b"", 200, b"hello", "buffered",
            )],
        );
        let options = options_for(target, ReplayMode::StatusOnly);
        let report = replay_capture(&bundle, &options).await.unwrap();
        match &report.results[0].outcome {
            ReplayOutcome::Error { message } => {
                assert!(!message.is_empty());
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unsupported_target_protocol_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = write_test_bundle(
            dir.path(),
            vec![recorded_exchange(
                1, "/x", "GET", b"", 200, b"hello", "buffered",
            )],
        );
        let options = options_for(
            Url::parse("ftp://example.com").unwrap(),
            ReplayMode::StatusOnly,
        );
        let err = replay_capture(&bundle, &options).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("Unsupported replay target protocol"));
    }

    #[test]
    fn delay_ms_present_in_default_options_shape() {
        // Guards the contract field added by Main's amendment: delay sleeps
        // between exchanges (exercised implicitly by delay_ms: 0 elsewhere).
        let target = Url::parse("http://127.0.0.1:1").unwrap();
        let options = options_for(target, ReplayMode::StatusOnly);
        assert_eq!(options.delay_ms, 0);
    }
    #[test]
    fn report_serializes_to_ts_compatible_json() {
        let report = ReplayReport {
            mode: ReplayMode::SemanticJsonResponse,
            results: vec![
                ReplayExchangeResult {
                    sequence: 1,
                    outcome: ReplayOutcome::Match,
                },
                ReplayExchangeResult {
                    sequence: 2,
                    outcome: ReplayOutcome::Diff {
                        detail: "JSON values differ at /id".into(),
                    },
                },
                ReplayExchangeResult {
                    sequence: 3,
                    outcome: ReplayOutcome::Unreplayable {
                        reason: "no replacement".into(),
                    },
                },
            ],
            matched: 1,
            diffed: 2,
        };
        let json = serde_json::to_value(&report).unwrap();
        // Mode serializes as the TS CLI mode string.
        assert_eq!(json["mode"], "semantic-json-response");
        assert_eq!(json["matched"], 1);
        assert_eq!(json["diffed"], 2);
        assert_eq!(json["results"][0]["sequence"], 1);
        assert_eq!(json["results"][0]["outcome"], "Match");
        assert_eq!(
            json["results"][1]["outcome"]["Diff"]["detail"],
            "JSON values differ at /id"
        );
        assert_eq!(
            json["results"][2]["outcome"]["Unreplayable"]["reason"],
            "no replacement"
        );
        // And round-trips.
        let back: ReplayReport = serde_json::from_value(json).unwrap();
        assert_eq!(back.mode, ReplayMode::SemanticJsonResponse);
        assert_eq!(back.results[1].outcome, report.results[1].outcome);
        assert_eq!(back.diffed, 2);
    }
}
