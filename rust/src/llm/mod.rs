//! LLM request/response fingerprinting engine (W4).
//!
//! Pure, side-effect-free analysis of captured exchanges: ordered provider
//! detection ([`provider`]), per-dialect usage/stop-reason extraction
//! ([`usage`]), types-only schema fingerprints ([`shape`] + [`schema_fp`]).
//! No I/O happens here except through caller-supplied body bytes.
//!
//! ```text
//! CapturedExchange ──► fingerprint_exchange ──► types::LlmMeta
//!        │                     ▲
//!        └─ fingerprint_exchanges (AMEND-10 batch) ──► FingerprintReport
//!                ▲
//! fingerprint_bundle(dir) = bundle::load_bundle + read_all_bodies + above
//! ```
//!
//! `shape_drift` is never set by [`fingerprint_exchange`]; drift is a
//! property of a *set* and is decided by [`fingerprint_exchanges`], which
//! groups exchanges sharing `(provider, request path prefix, model)`.

pub mod provider;
pub mod schema_fp;
pub mod shape;
pub mod usage;

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::{BodyStorage, CapturedBody, CapturedExchange, HeaderMapValues, LlmMeta};

pub use provider::{detect_model, Detection, Provider, ProviderDetector, RequestContext};
pub use schema_fp::{fingerprints_differ, schema_fingerprint};
pub use shape::Shape;
pub use usage::Usage;

/// One classified exchange in a [`FingerprintReport`] (serde camelCase).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeFingerprint {
    pub sequence: u64,
    pub provider: String,
    pub model: Option<String>,
    pub streaming: bool,
    pub tool_count: Option<u32>,
    pub tool_names: Vec<String>,
    pub usage: Option<Usage>,
    pub stop_reason: Option<String>,
    pub request_fp: Option<String>,
    pub response_fp: Option<String>,
}

/// A group of exchanges sharing `(provider, path, model)` whose request
/// shapes disagree — the drift-detection payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriftGroup {
    pub provider: String,
    /// Shared request path prefix (path without query string).
    pub path: String,
    pub model: Option<String>,
    /// Member exchange sequences, ascending.
    pub sequences: Vec<u64>,
    /// Number of distinct request shape fingerprints inside the group.
    pub distinct_request_fps: usize,
}

/// Batch report over a set of exchanges (AMEND-10 wire shape for
/// `GET /__fingerprint` and `arbiter fingerprint --json`). Entries are
/// sequence-ascending; drift groups are ordered by their first sequence.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintReport {
    pub entries: Vec<ExchangeFingerprint>,
    pub drift_groups: Vec<DriftGroup>,
}

/// Classify one settled exchange into its wire-visible `llm` metadata block.
///
/// Returns `None` when no provider rule matches at all (non-LLM traffic stays
/// unclassified). `resolve_body` supplies blob-backed bytes; see
/// [`fingerprint_exchanges`] for the exact contract. `shape_drift` is always
/// `None` here — the batch pass decides drift.
pub fn fingerprint_exchange(
    exchange: &CapturedExchange,
    resolve_body: impl Fn(u64) -> Option<Vec<u8>>,
) -> Option<LlmMeta> {
    let (request_bytes, response_bytes) = resolve_legs(exchange, resolve_body);
    let request_json: Option<Value> = request_bytes
        .as_deref()
        .and_then(|b| serde_json::from_slice(b).ok());
    let headers = &exchange.request.headers.values;
    let host = host_of(headers);
    let detection = ProviderDetector::detect(&RequestContext {
        path: &exchange.request.path,
        host,
        headers,
        body: request_json.as_ref(),
    });
    if detection.provider == Provider::Unknown {
        return None;
    }

    let streaming = detect_streaming(exchange, request_json.as_ref());
    let (tools_present, tool_count, tool_names) =
        extract_tools(detection.provider, request_json.as_ref());

    // Usage + stop reason from the response half (JSON, SSE, or NDJSON).
    let extracted = response_bytes
        .as_deref()
        .map(|bytes| {
            usage::extract(
                detection.provider,
                exchange.response.body.media_type.as_deref(),
                bytes,
            )
        })
        .unwrap_or_default();

    let sse_media_type = matches!(exchange.response.body.media_type.as_deref(), Some(m) if m.to_ascii_lowercase().contains("event-stream"));
    let request_fp = request_json.as_ref().map(schema_fingerprint);
    let response_fp = response_shape_fp(streaming && sse_media_type, response_bytes.as_deref());
    let model = detect_model(
        detection.provider,
        &exchange.request.path,
        request_json.as_ref(),
    );

    Some(LlmMeta {
        provider: detection.provider.as_str().to_string(),
        model,
        streaming,
        tool_count: tools_present.then_some(tool_count),
        tool_names: tools_present.then_some(tool_names),
        prompt_tokens: extracted.usage.as_ref().and_then(|u| u.prompt_tokens),
        completion_tokens: extracted.usage.as_ref().and_then(|u| u.completion_tokens),
        total_tokens: extracted.usage.as_ref().and_then(|u| u.total_tokens),
        stop_reason: extracted.stop_reason,
        request_shape_fp: request_fp,
        response_shape_fp: response_fp,
        shape_drift: None,
    })
}

/// AMEND-10 binding batch entry point: classify every LLM-shaped exchange in
/// `exchanges` and compute drift groups.
///
/// Resolver contract: keyed by exchange **sequence**. Inline bodies are
/// decoded locally and never consult it. For blob-backed legs the resolver
/// returns that exchange's blob bytes — when both legs are blob-backed, the
/// request bytes followed by the response bytes concatenated (the engine
/// splits them via recorded sizes and verifies each sha256). Unresolvable or
/// digest-mismatched bytes degrade the affected field to `None`, never error.
pub fn fingerprint_exchanges(
    exchanges: &[CapturedExchange],
    resolve_body: impl Fn(u64) -> Option<Vec<u8>>,
) -> FingerprintReport {
    // (provider, path-prefix, model) -> member sequences + distinct fps.
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct GroupKey {
        provider: String,
        path: String,
        model: Option<String>,
    }
    let mut groups: BTreeMap<GroupKey, (Vec<u64>, Vec<String>)> = BTreeMap::new();
    let mut entries = Vec::with_capacity(exchanges.len());
    for exchange in exchanges {
        let Some(meta) = fingerprint_exchange(exchange, &resolve_body) else {
            continue;
        };
        if let Some(fp) = &meta.request_shape_fp {
            let key = GroupKey {
                provider: meta.provider.clone(),
                path: path_prefix(&exchange.request.path).to_string(),
                model: meta.model.clone(),
            };
            let members = groups.entry(key).or_default();
            members.0.push(exchange.sequence);
            members.1.push(fp.clone());
        }
        entries.push(ExchangeFingerprint {
            sequence: exchange.sequence,
            provider: meta.provider,
            model: meta.model,
            streaming: meta.streaming,
            tool_count: meta.tool_count,
            tool_names: meta.tool_names.unwrap_or_default(),
            usage: (meta.prompt_tokens.is_some()
                || meta.completion_tokens.is_some()
                || meta.total_tokens.is_some())
            .then_some(Usage {
                prompt_tokens: meta.prompt_tokens,
                completion_tokens: meta.completion_tokens,
                total_tokens: meta.total_tokens,
            }),
            stop_reason: meta.stop_reason,
            request_fp: meta.request_shape_fp,
            response_fp: meta.response_shape_fp,
        });
    }

    let mut drift_groups: Vec<DriftGroup> = groups
        .into_iter()
        .filter_map(|(key, (mut sequences, mut fps))| {
            fps.sort();
            fps.dedup();
            if fps.len() <= 1 {
                return None;
            }
            sequences.sort_unstable();
            Some(DriftGroup {
                provider: key.provider,
                path: key.path,
                model: key.model,
                sequences,
                distinct_request_fps: fps.len(),
            })
        })
        .collect();
    drift_groups.sort_by_key(|group| group.sequences.first().copied());
    entries.sort_by_key(|entry| entry.sequence);
    FingerprintReport {
        entries,
        drift_groups,
    }
}

/// Convenience wrapper: fingerprint a bundle directory on disk using
/// [`crate::bundle::load_bundle`] plus body resolution.
pub fn fingerprint_bundle(bundle_dir: &Path) -> crate::error::Result<FingerprintReport> {
    let mut bundle = crate::bundle::load_bundle(bundle_dir)?;
    let bodies = bundle.read_all_bodies()?;
    let resolve = |sequence: u64| -> Option<Vec<u8>> {
        let exchange = bundle.exchanges.iter().find(|e| e.sequence == sequence)?;
        concat_blobs(&exchange.request.body, &exchange.response.body, &bodies)
    };
    Ok(fingerprint_exchanges(&bundle.exchanges, resolve))
}

// -------------------------------------------------------------------------
// Internals
// -------------------------------------------------------------------------

/// Request path without its query string.
fn path_prefix(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

fn host_of(headers: &HeaderMapValues) -> Option<&str> {
    headers
        .get("host")
        .or_else(|| headers.get(":authority"))
        .and_then(|values| values.first())
        .map(|h| h.split(':').next().unwrap_or(h))
}

/// Streaming = request body `"stream": true`, or an SSE response content
/// type, or a captured WebSocket stream on the exchange.
fn detect_streaming(exchange: &CapturedExchange, request_json: Option<&Value>) -> bool {
    if request_json
        .and_then(|v| v.get("stream"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    if matches!(exchange.response.body.media_type.as_deref(), Some(m) if m.to_ascii_lowercase().contains("event-stream"))
    {
        return true;
    }
    exchange.ws.is_some()
}

/// Tool definitions per dialect: presence, count, names. An absent `tools`
/// array yields `(false, 0, [])`; an explicit empty array counts as present.
/// Anthropic/OpenAI-family name at `tools[].name` / `tools[].function.name`;
/// Google nests declarations under `tools[].functionDeclarations[]`.
fn extract_tools(provider: Provider, request_json: Option<&Value>) -> (bool, u32, Vec<String>) {
    let Some(request) = request_json else {
        return (false, 0, Vec::new());
    };
    let Some(tools) = request.get("tools").and_then(Value::as_array) else {
        return (false, 0, Vec::new());
    };
    if tools.is_empty() {
        return (true, 0, Vec::new());
    }
    let definitions: Vec<&Value> = match provider {
        Provider::Google => tools
            .iter()
            .filter_map(|t| t.get("functionDeclarations"))
            .filter_map(Value::as_array)
            .flatten()
            .collect(),
        _ => tools.iter().collect(),
    };
    let names: Vec<String> = definitions
        .iter()
        .filter_map(|tool| {
            tool.get("name")
                .or_else(|| tool.pointer("/function/name"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    (true, definitions.len() as u32, names)
}

/// Response shape fingerprint. Non-streaming: the parsed JSON body. SSE:
/// the union of all parsed event payloads (order-independent), so streams
/// with identical event shapes hash equal regardless of chunk boundaries.
fn response_shape_fp(is_sse: bool, bytes: Option<&[u8]>) -> Option<String> {
    let bytes = bytes?;
    if is_sse {
        let events = crate::sse::parse_sse_body(bytes);
        let values: Vec<Value> = events
            .iter()
            .filter_map(|event| serde_json::from_str(&event.data).ok())
            .collect();
        (!values.is_empty()).then(|| schema_fingerprint(&Value::Array(values)))
    } else {
        serde_json::from_slice::<Value>(bytes)
            .ok()
            .map(|v| schema_fingerprint(&v))
    }
}

// ----- body resolution -----------------------------------------------------

/// Decode inline base64 bodies locally; route blob legs through the caller's
/// resolver, splitting concatenated blobs by recorded size and verifying each
/// sha256. Never errors — undecodable bytes become `None`.
fn resolve_legs(
    exchange: &CapturedExchange,
    resolve_body: impl Fn(u64) -> Option<Vec<u8>>,
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let inline_request = decode_inline(&exchange.request.body);
    let inline_response = decode_inline(&exchange.response.body);
    let request_needs_blob = matches!(exchange.request.body.storage, BodyStorage::Blob { .. })
        && inline_request.is_none();
    let response_needs_blob = matches!(exchange.response.body.storage, BodyStorage::Blob { .. })
        && inline_response.is_none();

    if !request_needs_blob && !response_needs_blob {
        return (inline_request, inline_response);
    }
    let Some(all) = resolve_body(exchange.sequence) else {
        return (inline_request, inline_response);
    };
    let request = match (request_needs_blob, inline_request) {
        (true, _) => pick_leg(&all, &exchange.request.body),
        (false, inline) => inline,
    };
    let response = match (response_needs_blob, inline_response) {
        (true, _) => pick_leg(&all, &exchange.response.body),
        (false, inline) => inline,
    };
    (request, response)
}

fn decode_inline(body: &CapturedBody) -> Option<Vec<u8>> {
    match &body.storage {
        BodyStorage::InlineBase64 { value } => crate::secret_scan::base64_decode(value).ok(),
        BodyStorage::Blob { .. } => None,
    }
}

/// Match resolver bytes against one leg: either they are exactly that body,
/// or they are the request++response concatenation and this leg's slice
/// verifies by size + sha256.
fn pick_leg(all: &[u8], body: &CapturedBody) -> Option<Vec<u8>> {
    if all.len() as u64 == body.size {
        return verified(all, body);
    }
    // Concatenation case: try this body at the front, then at the back.
    let size = body.size as usize;
    if all.len() >= size {
        if verified(&all[..size], body).is_some() {
            return Some(all[..size].to_vec());
        }
        if verified(&all[all.len() - size..], body).is_some() {
            return Some(all[all.len() - size..].to_vec());
        }
    }
    None
}

fn verified(bytes: &[u8], body: &CapturedBody) -> Option<Vec<u8>> {
    (crate::bundle::sha256_hex(bytes) == body.sha256).then(|| bytes.to_vec())
}

/// Bundle adapter: concatenate this exchange's blob bodies (request first,
/// then response) from the preloaded body table.
fn concat_blobs(
    request: &CapturedBody,
    response: &CapturedBody,
    bodies: &HashMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if matches!(request.storage, BodyStorage::Blob { .. }) {
        out.extend_from_slice(bodies.get(&request.sha256)?);
    }
    if matches!(response.storage, BodyStorage::Blob { .. }) {
        out.extend_from_slice(bodies.get(&response.sha256)?);
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CapturedHeaders, CapturedRequest, CapturedResponse, StreamState, EXCHANGE_SCHEMA_VERSION,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    const ANTHROPIC_SSE: &str = concat!(
        "event: message_start\n",
        r#"data: {"type":"message_start","message":{"model":"claude-sonnet-4","usage":{"input_tokens":24,"output_tokens":1}}}"#,
        "\n\n",
        "event: message_delta\n",
        r#"data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":101}}"#,
        "\n\n",
        "event: message_stop\n",
        r#"data: {"type":"message_stop"}"#,
        "\n\n"
    );

    fn inline_body(bytes: &[u8], media_type: Option<&str>) -> CapturedBody {
        use base64::Engine;
        CapturedBody {
            sha256: crate::bundle::sha256_hex(bytes),
            size: bytes.len() as u64,
            media_type: media_type.map(str::to_string),
            content_encoding: None,
            storage: BodyStorage::InlineBase64 {
                value: base64::engine::general_purpose::STANDARD.encode(bytes),
            },
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> CapturedHeaders {
        CapturedHeaders {
            values: pairs.iter().fold(BTreeMap::new(), |mut map, (k, v)| {
                map.entry(k.to_string())
                    .or_insert_with(Vec::new)
                    .push(v.to_string());
                map
            }),
            redacted: vec![],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_exchange(
        sequence: u64,
        path: &str,
        request_headers: CapturedHeaders,
        request_bytes: &[u8],
        request_media: Option<&str>,
        response_headers: CapturedHeaders,
        response_bytes: &[u8],
        response_media: Option<&str>,
        stream_kind: &str,
    ) -> CapturedExchange {
        CapturedExchange {
            schema_version: EXCHANGE_SCHEMA_VERSION,
            sequence,
            started_at: "2026-08-21T00:00:00.000Z".into(),
            duration_ms: 10.0,
            request: CapturedRequest {
                method: "POST".into(),
                path: path.into(),
                http_version: "1.1".into(),
                headers: request_headers,
                body: inline_body(request_bytes, request_media),
            },
            response: CapturedResponse {
                status: 200,
                status_text: "OK".into(),
                http_version: "1.1".into(),
                headers: response_headers,
                body: inline_body(response_bytes, response_media),
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

    fn anthropic_exchange(sequence: u64, model_value: &str) -> CapturedExchange {
        let request = json!({"model": model_value, "max_tokens": 1024u32, "messages": [
            {"role": "user", "content": "hi"}
        ]});
        let response = json!({
            "id": "msg_01", "role": "assistant", "model": model_value,
            "content": [{"type": "text", "text": "Hello!"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 24, "output_tokens": 101}
        });
        make_exchange(
            sequence,
            "/v1/messages",
            headers(&[
                ("x-api-key", "sk-ant-01"),
                ("host", "api.anthropic.com:443"),
            ]),
            request.to_string().as_bytes(),
            Some("application/json"),
            headers(&[("content-type", "application/json")]),
            response.to_string().as_bytes(),
            Some("application/json"),
            "buffered",
        )
    }

    fn no_resolver(_: u64) -> Option<Vec<u8>> {
        None
    }

    #[test]
    fn anthropic_non_stream_exchange_classified() {
        let meta =
            fingerprint_exchange(&anthropic_exchange(1, "claude-sonnet-4"), no_resolver).unwrap();
        assert_eq!(meta.provider, "anthropic");
        assert_eq!(meta.model.as_deref(), Some("claude-sonnet-4"));
        assert!(!meta.streaming);
        assert_eq!(meta.prompt_tokens, Some(24));
        assert_eq!(meta.completion_tokens, Some(101));
        assert_eq!(meta.total_tokens, Some(125));
        assert_eq!(meta.stop_reason.as_deref(), Some("end_turn"));
        assert!(meta.request_shape_fp.is_some());
        assert!(meta.response_shape_fp.is_some());
        assert_eq!(meta.shape_drift, None);
        assert_ne!(meta.request_shape_fp, meta.response_shape_fp);
    }

    #[test]
    fn anthropic_sse_stream_exchange_folds_usage() {
        let exchange = make_exchange(
            2,
            "/v1/messages",
            headers(&[("x-api-key", "sk-ant-01"), ("anthropic-version", "2023-06-01")]),
            br#"{"model":"claude-sonnet-4","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}"#,
            Some("application/json"),
            headers(&[("content-type", "text/event-stream")]),
            ANTHROPIC_SSE.as_bytes(),
            Some("text/event-stream"),
            "sse",
        );
        let meta = fingerprint_exchange(&exchange, no_resolver).unwrap();
        assert!(meta.streaming);
        assert_eq!(meta.prompt_tokens, Some(24));
        assert_eq!(meta.completion_tokens, Some(101));
        assert_eq!(meta.stop_reason.as_deref(), Some("end_turn"));
        assert!(meta.response_shape_fp.is_some());
    }

    #[test]
    fn openai_tools_counted_with_names() {
        let request = json!({
            "model": "gpt-4o",
            "messages": [],
            "tools": [
                {"type": "function", "function": {"name": "get_weather"}},
                {"type": "function", "function": {"name": "get_time"}}
            ]
        });
        let response = json!({"choices": [{"finish_reason": null}], "usage": {}});
        let exchange = make_exchange(
            3,
            "/v1/chat/completions",
            headers(&[("authorization", "Bearer sk-proj-x")]),
            request.to_string().as_bytes(),
            Some("application/json"),
            headers(&[]),
            response.to_string().as_bytes(),
            Some("application/json"),
            "buffered",
        );
        let meta = fingerprint_exchange(&exchange, no_resolver).unwrap();
        assert_eq!(meta.provider, "openai");
        assert_eq!(meta.tool_count, Some(2));
        assert_eq!(
            meta.tool_names.unwrap(),
            vec!["get_weather".to_string(), "get_time".to_string()]
        );
    }

    #[test]
    fn non_llm_exchange_is_skipped() {
        let exchange = make_exchange(
            9,
            "/users/42",
            headers(&[("host", "example.com")]),
            b"{}",
            Some("application/json"),
            headers(&[]),
            b"{}",
            Some("application/json"),
            "buffered",
        );
        assert!(fingerprint_exchange(&exchange, no_resolver).is_none());
    }

    #[test]
    fn drift_grouping_across_three_exchanges() {
        // Exchanges 1 and 3 share a request shape; 2 differs (tools array).
        let mut exchanges = vec![
            anthropic_exchange(1, "claude-sonnet-4"),
            anthropic_exchange(2, "claude-sonnet-4"),
            anthropic_exchange(3, "claude-sonnet-4"),
        ];
        // Give exchange 2 an extra top-level field -> different shape fp.
        let drifted_request = json!({"model": "claude-sonnet-4", "max_tokens": 1024u32,
            "temperature": 0.7, "messages": [{"role": "user", "content": "hi"}]});
        let bytes = drifted_request.to_string();
        exchanges[1].request.body = inline_body(bytes.as_bytes(), Some("application/json"));

        let report = fingerprint_exchanges(&exchanges, no_resolver);
        assert_eq!(report.entries.len(), 3);
        assert_eq!(report.drift_groups.len(), 1);
        let group = &report.drift_groups[0];
        assert_eq!(group.provider, "anthropic");
        assert_eq!(group.path, "/v1/messages");
        assert_eq!(group.model.as_deref(), Some("claude-sonnet-4"));
        assert_eq!(group.sequences, vec![1, 2, 3]);
        assert_eq!(group.distinct_request_fps, 2);
        // Report JSON is camelCase wire-ready.
        let value = serde_json::to_value(&report).unwrap();
        assert!(value["driftGroups"][0]["distinctRequestFps"].is_u64());
    }

    #[test]
    fn no_drift_when_shapes_agree() {
        let report = fingerprint_exchanges(
            &[
                anthropic_exchange(1, "claude-sonnet-4"),
                anthropic_exchange(2, "claude-sonnet-4"),
            ],
            no_resolver,
        );
        assert_eq!(report.entries.len(), 2);
        assert!(report.drift_groups.is_empty());
    }

    #[test]
    fn bundle_round_trip_via_write_bundle_including_blob_body() {
        use crate::bundle::{write_bundle, WriteBundleOptions};
        use crate::types::{CaptureManifest, CaptureMode, RedactionPolicySummary};

        let dir = tempfile::tempdir().unwrap();
        let big_tail = "x".repeat(12_000); // pushes the response past inline limit
        let streaming_response_body = format!(
            concat!(
                "event: message_start\n",
                "data: {{\"type\":\"message_start\",\"message\":{{\"usage\":{{\"input_tokens\":24,\"output_tokens\":1}}}}}}\n\n",
                "event: message_delta\n",
                "data: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\"usage\":{{\"output_tokens\":101}}}}\n\n"
            ),
        ) + &format!("event: padding\ndata: \"{big_tail}\"\n\n");

        let small = anthropic_exchange(1, "claude-sonnet-4");
        let mut streamed = make_exchange(
            2,
            "/v1/messages",
            headers(&[("x-api-key", "sk-ant-01"), ("anthropic-version", "2023-06-01")]),
            br#"{"model":"claude-sonnet-4","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}"#,
            Some("application/json"),
            headers(&[("content-type", "text/event-stream")]),
            streaming_response_body.as_bytes(),
            Some("text/event-stream"),
            "sse",
        );
        // Force blob storage on the SSE response body.
        streamed.response.body = CapturedBody {
            sha256: crate::bundle::sha256_hex(streaming_response_body.as_bytes()),
            size: streaming_response_body.len() as u64,
            media_type: Some("text/event-stream".into()),
            content_encoding: None,
            storage: BodyStorage::Blob {
                path: format!(
                    "bodies/{}.bin",
                    crate::bundle::sha256_hex(streaming_response_body.as_bytes())
                ),
            },
        };
        let exchanges = vec![small, streamed];
        let mut bodies = HashMap::new();
        bodies.insert(
            exchanges[1].response.body.sha256.clone(),
            streaming_response_body.clone().into_bytes(),
        );
        let manifest = CaptureManifest {
            schema_version: 1,
            arbiter_version: env!("CARGO_PKG_VERSION").into(),
            mode: CaptureMode::Observe,
            target_origin: "https://api.anthropic.com".into(),
            started_at: "2026-08-21T00:00:00.000Z".into(),
            completed_at: "2026-08-21T00:00:01.000Z".into(),
            exchange_count: 2,
            bundle_digest: String::new(),
            redaction: RedactionPolicySummary {
                redact_headers: vec!["authorization".into()],
                allow_query: vec![],
            },
            metadata: None,
        };
        write_bundle(
            dir.path(),
            WriteBundleOptions {
                manifest,
                exchanges: exchanges.clone(),
                bodies,
                validation: None,
            },
        )
        .unwrap();

        // Direct path must resolve the blob leg with the raw bytes; the
        // bundle path resolves them from disk — results must agree.
        let blob_bytes = streaming_response_body.clone().into_bytes();
        let direct_resolver =
            move |sequence: u64| -> Option<Vec<u8>> { (sequence == 2).then(|| blob_bytes.clone()) };
        let direct = fingerprint_exchanges(&exchanges, direct_resolver);
        let from_bundle = fingerprint_bundle(dir.path()).expect("bundle round-trip");
        assert_eq!(from_bundle.entries.len(), 2);
        assert_eq!(
            from_bundle, direct,
            "blob resolution must match inline analysis"
        );
        let streamed_entry = from_bundle
            .entries
            .iter()
            .find(|e| e.sequence == 2)
            .unwrap();
        assert!(streamed_entry.streaming);
        assert_eq!(
            streamed_entry.usage.as_ref().unwrap().completion_tokens,
            Some(101)
        );
        assert_eq!(streamed_entry.stop_reason.as_deref(), Some("end_turn"));
    }
}
