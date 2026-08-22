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
pub const BUNDLE_SCHEMA_VERSION: u64 = 1;

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
