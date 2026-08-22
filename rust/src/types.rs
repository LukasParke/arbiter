//! Canonical capture model.
//!
//! Arbiter guarantees exact application HTTP body bytes after transport
//! decoding: request bytes received from the client, response bytes delivered
//! to the client, ordered SSE bytes and terminal state, method/path/query,
//! response status, and selected end-to-end headers. Transport framing
//! (TLS records, HTTP/2 frames, TCP segmentation, chunk boundaries) is out of
//! scope. Field names and JSON shape match the TypeScript implementation
//! exactly (camelCase, `schemaVersion: 1`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const EXCHANGE_SCHEMA_VERSION: u64 = 1;
/// Bundle format version written by this build. Writers stamp 1 for
/// HTTP-only captures (byte-identical to TS output, frozen interchange) and
/// 2 only when v2 extension content (tunnel/tls/ws/llm) is present.
/// Loaders accept both (see bundle::validate::validate_manifest).
pub const BUNDLE_SCHEMA_VERSION: u64 = 2;
/// Exchange-line schema version; additive optional fields keep lines at 1.
pub const EXCHANGE_SCHEMA_VERSION_V2: u64 = 1;

/// Lowercased header names; duplicate values keep array order.
pub type HeaderMapValues = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedHeaders {
    pub values: HeaderMapValues,
    /// Names of headers whose values were removed before persistence.
    pub redacted: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BodyStorage {
    InlineBase64 { value: String },
    Blob { path: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedBody {
    pub sha256: String,
    pub size: u64,
    pub media_type: Option<String>,
    pub content_encoding: Option<String>,
    pub storage: BodyStorage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamState {
    /// One of `buffered`, `sse`, `other-stream`.
    pub kind: String,
    pub completed: bool,
    pub client_aborted: bool,
    pub upstream_aborted: bool,
    pub terminal_marker: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureFailure {
    /// One of `request-capture`, `upstream-connect`, `response-capture`,
    /// `persistence`.
    pub stage: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationSummary {
    pub valid: bool,
    pub violation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedRequest {
    pub method: String,
    /// Path plus query. Query values may be redacted per policy.
    pub path: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub headers: CapturedHeaders,
    pub body: CapturedBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedResponse {
    pub status: u16,
    #[serde(rename = "statusText")]
    pub status_text: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub headers: CapturedHeaders,
    pub body: CapturedBody,
    pub stream: StreamState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedExchange {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub sequence: u64,
    /// ISO-8601 timestamp.
    pub started_at: String,
    pub duration_ms: f64,
    pub request: CapturedRequest,
    pub response: CapturedResponse,
    pub failure: Option<CaptureFailure>,
    pub validation: Option<ValidationSummary>,
    /// CONNECT tunnel metadata when this exchange flowed through a tunneled
    /// HTTPS connection (v2, absent on plain HTTP captures).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelInfo>,
    /// TLS handshake details for intercepted or TLS-terminated exchanges.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsExchangeInfo>,
    /// Captured WebSocket message stream (v2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws: Option<WsStream>,
    /// LLM provider fingerprint extracted from this exchange (v2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmMeta>,
}

// ---------------------------------------------------------------------------
// Capture schema v2 — additive members. All are optional with
// `skip_serializing_if` so HTTP-only records serialize byte-identically to
// v1 (frozen TS interchange, AMEND-13).
// ---------------------------------------------------------------------------

/// Direction of a captured WebSocket message relative to the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WsDirection {
    ClientToServer,
    ServerToClient,
}

/// RFC 6455 opcodes captured by the recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WsOpcode {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

/// One captured WebSocket message. Text frames carry `text`; other frames
/// carry `dataBase64`. `offsetMs` is milliseconds since exchange start and is
/// stripped from the bundle digest (timing provenance).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsMessage {
    pub direction: WsDirection,
    pub opcode: WsOpcode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_base64: Option<String>,
    pub size: u64,
    pub offset_ms: f64,
}

/// Captured WebSocket session attached to a proxied exchange.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsStream {
    /// Negotiated subprotocol from Sec-WebSocket-Protocol, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    pub messages: Vec<WsMessage>,
    /// True when the stream ended with a Close frame or terminal error.
    pub completed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
}

/// CONNECT tunnel metadata for exchanges that flowed through an intercepted
/// or pass-through HTTPS tunnel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelInfo {
    /// Authority host from the CONNECT request line.
    pub host: String,
    pub port: u16,
    /// True when TLS was terminated locally (intercepted), false when the
    /// tunnel was passed through untouched.
    pub intercepted: bool,
    /// Negotiated ALPN protocol on the client side, e.g. "h2", "http/1.1".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

/// TLS handshake details for intercepted/TLS-terminated exchanges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsExchangeInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// Server name indication presented by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

/// LLM provider fingerprint extracted from request/response shapes (W4).
/// Populated by `arbiter::llm` at capture settle time or batch analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmMeta {
    /// Detected provider id, e.g. "anthropic", "openai", "ollama".
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub streaming: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    /// sha256 of the types-only normalized shape of the request body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_shape_fp: Option<String>,
    /// sha256 of the types-only normalized shape of the response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_shape_fp: Option<String>,
    /// True when this exchange's shape fingerprint differs from every other
    /// exchange sharing (provider, path, model) in the same analysis set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape_drift: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureMode {
    Observe,
    Exact,
}

impl CaptureMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaptureMode::Observe => "observe",
            CaptureMode::Exact => "exact",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionPolicySummary {
    #[serde(rename = "redactHeaders")]
    pub redact_headers: Vec<String>,
    #[serde(rename = "allowQuery")]
    pub allow_query: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "arbiterVersion")]
    pub arbiter_version: String,
    pub mode: CaptureMode,
    /// Target origin with any query/credentials removed.
    #[serde(rename = "targetOrigin")]
    pub target_origin: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "completedAt")]
    pub completed_at: String,
    #[serde(rename = "exchangeCount")]
    pub exchange_count: u64,
    /// Digest over normalized exchange content, excluding timing provenance.
    #[serde(rename = "bundleDigest")]
    pub bundle_digest: String,
    pub redaction: RedactionPolicySummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::stable_stringify;
    use serde_json::Value;

    fn sample_exchange() -> CapturedExchange {
        let headers = CapturedHeaders {
            values: BTreeMap::from([("content-type".into(), vec!["application/json".into()])]),
            redacted: vec!["authorization".into()],
        };
        let body = CapturedBody {
            sha256: "0".repeat(64),
            size: 0,
            media_type: None,
            content_encoding: None,
            storage: BodyStorage::InlineBase64 {
                value: String::new(),
            },
        };
        CapturedExchange {
            schema_version: EXCHANGE_SCHEMA_VERSION,
            sequence: 1,
            started_at: "2026-08-21T00:00:00.000Z".into(),
            duration_ms: 12.5,
            request: CapturedRequest {
                method: "GET".into(),
                path: "/x".into(),
                http_version: "1.1".into(),
                headers: headers.clone(),
                body: body.clone(),
            },
            response: CapturedResponse {
                status: 200,
                status_text: "OK".into(),
                http_version: "1.1".into(),
                headers,
                body,
                stream: StreamState {
                    kind: "buffered".into(),
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

    #[test]
    fn exchange_json_matches_ts_shape() {
        let json = serde_json::to_value(sample_exchange()).unwrap();
        assert_eq!(json["schemaVersion"], 1);
        assert_eq!(json["startedAt"], "2026-08-21T00:00:00.000Z");
        assert_eq!(json["request"]["httpVersion"], "1.1");
        assert_eq!(json["response"]["stream"]["clientAborted"], false);
        assert_eq!(json["response"]["stream"]["terminalMarker"], Value::Null);
        assert_eq!(json["request"]["body"]["storage"]["kind"], "inline-base64");
    }

    #[test]
    fn blob_storage_kebab_kind() {
        let body = CapturedBody {
            sha256: "a".repeat(64),
            size: 3,
            media_type: Some("text/plain".into()),
            content_encoding: None,
            storage: BodyStorage::Blob {
                path: format!("bodies/{}.bin", "a".repeat(64)),
            },
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["storage"]["kind"], "blob");
        assert_eq!(
            json["storage"]["path"],
            format!("bodies/{}.bin", "a".repeat(64))
        );
        assert_eq!(json["mediaType"], "text/plain");
        let round: CapturedBody = serde_json::from_value(json).unwrap();
        assert_eq!(round, body);
    }

    #[test]
    fn manifest_serializes_stably() {
        let manifest = CaptureManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            arbiter_version: "1.1.0".into(),
            mode: CaptureMode::Exact,
            target_origin: "https://api.example.com".into(),
            started_at: "2026-08-21T00:00:00.000Z".into(),
            completed_at: "2026-08-21T00:00:01.000Z".into(),
            exchange_count: 1,
            bundle_digest: "0".repeat(64),
            redaction: RedactionPolicySummary {
                redact_headers: vec!["authorization".into()],
                allow_query: vec![],
            },
            metadata: None,
        };
        let text = stable_stringify(&serde_json::to_value(&manifest).unwrap());
        assert!(text.starts_with(r#"{"arbiterVersion":"1.1.0","bundleDigest":"#));
    }
}
