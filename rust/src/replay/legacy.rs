//! Legacy traffic JSONL ingestion (port of src/replay/legacy.ts).
//!
//! Legacy traffic lines are the `TrafficLine` projection written by
//! `exchanges_to_traffic_jsonl` (`timestamp`, `method`, `path`,
//! `request_headers`, `request_body` [+ `request_body_encoding`],
//! `response_status`, `response_headers`, `response_body`
//! [+ `response_body_encoding`]). Each line is mapped back into a canonical
//! [`CapturedExchange`] so the replay engine can treat legacy captures and
//! canonical bundles identically.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::bundle::make_captured_body;
use crate::error::{Error, Result};
use crate::types::{
    CapturedExchange, CapturedHeaders, CapturedRequest, CapturedResponse, HeaderMapValues,
    StreamState, EXCHANGE_SCHEMA_VERSION,
};

/// One legacy traffic JSONL line (snake_case projection of an exchange).
#[derive(Debug, Clone, Deserialize)]
pub struct LegacyTrafficLine {
    pub timestamp: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub request_body: Option<String>,
    /// Present (as `"base64"`) when `request_body` is not UTF-8 text.
    pub request_body_encoding: Option<String>,
    pub response_status: u16,
    #[serde(default)]
    pub response_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub response_body: Option<String>,
    /// Present (as `"base64"`) when `response_body` is not UTF-8 text.
    pub response_body_encoding: Option<String>,
}

/// Load a legacy traffic JSONL file into a replayable exchange list.
///
/// Blank lines are skipped; malformed lines fail with their line number
/// (fail closed — a partially loaded capture must never replay silently).
pub fn load_legacy_jsonl(path: &Path) -> Result<Vec<CapturedExchange>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::io(format!("read traffic jsonl {}", path.display()), e))?;
    let mut exchanges = Vec::new();
    for (index, line) in raw.split('\n').enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: LegacyTrafficLine = serde_json::from_str(line).map_err(|e| Error::Json {
            context: format!("traffic line {}", index + 1),
            source: e,
        })?;
        exchanges.push(line_to_exchange(&parsed, exchanges.len() as u64 + 1)?);
    }
    Ok(exchanges)
}

fn line_to_exchange(line: &LegacyTrafficLine, sequence: u64) -> Result<CapturedExchange> {
    let request_headers = single_value_headers(&line.request_headers);
    let response_headers = single_value_headers(&line.response_headers);
    let media_type_for = |headers: &HeaderMapValues| {
        headers
            .get("content-type")
            .and_then(|values| values.first())
            .map(|value| {
                // Strip parameters ("application/json; charset=utf-8").
                value
                    .split(';')
                    .next()
                    .unwrap_or(value)
                    .trim()
                    .to_lowercase()
            })
    };

    let request_bytes = decode_body_text(
        line.request_body.as_deref(),
        line.request_body_encoding.as_deref(),
        "request",
        sequence,
    )?;
    let response_bytes = decode_body_text(
        line.response_body.as_deref(),
        line.response_body_encoding.as_deref(),
        "response",
        sequence,
    )?;

    let request_body = make_captured_body(
        &request_bytes,
        media_type_for(&request_headers).as_deref(),
        None,
        None,
    )?;
    let response_body = make_captured_body(
        &response_bytes,
        media_type_for(&response_headers).as_deref(),
        None,
        None,
    )?;

    Ok(CapturedExchange {
        schema_version: EXCHANGE_SCHEMA_VERSION,
        sequence,
        started_at: line.timestamp.clone(),
        duration_ms: 0.0,
        request: CapturedRequest {
            method: line.method.to_uppercase(),
            path: line.path.clone(),
            http_version: "1.1".to_string(),
            headers: CapturedHeaders {
                values: request_headers,
                redacted: vec![],
            },
            body: request_body,
        },
        response: CapturedResponse {
            status: line.response_status,
            status_text: String::new(),
            http_version: "1.1".to_string(),
            headers: CapturedHeaders {
                values: response_headers,
                redacted: vec![],
            },
            body: response_body,
            stream: StreamState {
                kind: "buffered".to_string(),
                completed: true,
                client_aborted: false,
                upstream_aborted: false,
                terminal_marker: None,
                error: None,
            },
        },
        failure: None,
        validation: None,
    })
}

fn decode_body_text(
    text: Option<&str>,
    encoding: Option<&str>,
    role: &str,
    sequence: u64,
) -> Result<Vec<u8>> {
    let Some(text) = text else {
        return Ok(Vec::new());
    };
    match encoding {
        None => Ok(text.as_bytes().to_vec()),
        Some("base64") => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|e| {
                    Error::other(format!(
                        "traffic exchange {sequence}: malformed base64 in {role} body: {e}"
                    ))
                })
        }
        Some(other) => Err(Error::other(format!(
            "traffic exchange {sequence}: unsupported {role} body encoding {other:?}"
        ))),
    }
}

fn single_value_headers(headers: &BTreeMap<String, String>) -> HeaderMapValues {
    headers
        .iter()
        .map(|(name, value)| (name.to_lowercase(), vec![value.clone()]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::sha256_hex;

    fn write_traffic(dir: &Path, lines: &[String]) -> std::path::PathBuf {
        let path = dir.join("traffic.jsonl");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    fn simple_line() -> serde_json::Value {
        serde_json::json!({
            "timestamp": "2026-08-21T00:00:00.000Z",
            "method": "get",
            "path": "/v1/things?api_version=2023-06-01",
            "request_headers": {"Content-Type": "application/json", "X-Beta": "1"},
            "request_body": "{\"a\":1}",
            "response_status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": "{\"ok\":true}"
        })
    }

    #[test]
    fn loads_traffic_lines_into_exchanges() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_traffic(dir.path(), &[simple_line().to_string()]);
        let exchanges = load_legacy_jsonl(&path).unwrap();
        assert_eq!(exchanges.len(), 1);
        let exchange = &exchanges[0];
        assert_eq!(exchange.sequence, 1);
        assert_eq!(exchange.request.method, "GET");
        assert_eq!(exchange.request.path, "/v1/things?api_version=2023-06-01");
        assert_eq!(exchange.response.status, 200);
        assert_eq!(exchange.response.stream.kind, "buffered");
        assert!(exchange.response.stream.completed);
        // Headers normalized to lowercase multi-map form.
        assert_eq!(
            exchange.request.headers.values.get("content-type"),
            Some(&vec!["application/json".to_string()])
        );
        // Body bytes round-trip with verified digests.
        let body = &exchange.request.body;
        assert_eq!(body.sha256, sha256_hex(br#"{"a":1}"#));
        assert_eq!(body.size, 7);
        assert_eq!(body.media_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn skips_blank_lines_and_numbers_sequences() {
        let dir = tempfile::tempdir().unwrap();
        let line = serde_json::json!({
            "timestamp": "t", "method": "GET", "path": "/x", "response_status": 404
        })
        .to_string();
        let path = dir.path().join("traffic.jsonl");
        std::fs::write(&path, format!("{line}\n\n{line}\n")).unwrap();
        let exchanges = load_legacy_jsonl(&path).unwrap();
        assert_eq!(exchanges.len(), 2);
        assert_eq!(exchanges[0].sequence, 1);
        assert_eq!(exchanges[1].sequence, 2);
        assert_eq!(exchanges[1].response.status, 404);
    }

    #[test]
    fn decodes_base64_marked_bodies() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"\x00\x01\x02");
        let line = serde_json::json!({
            "timestamp": "t", "method": "POST", "path": "/bin",
            "request_body": encoded, "request_body_encoding": "base64",
            "response_status": 200
        })
        .to_string();
        let path = write_traffic(dir.path(), &[line]);
        let exchanges = load_legacy_jsonl(&path).unwrap();
        assert_eq!(exchanges[0].request.body.size, 3);
    }

    #[test]
    fn fails_closed_on_malformed_line() {
        let dir = tempfile::tempdir().unwrap();
        let good = serde_json::json!({
            "timestamp": "t", "method": "GET", "path": "/x", "response_status": 200
        })
        .to_string();
        let path = write_traffic(dir.path(), &[good, "{not json".to_string()]);
        let err = load_legacy_jsonl(&path).unwrap_err();
        assert!(err.to_string().contains("traffic line 2"), "err: {err}");
    }

    #[test]
    fn fails_on_unknown_body_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let line = serde_json::json!({
            "timestamp": "t", "method": "GET", "path": "/x",
            "response_status": 200, "response_body": "zz", "response_body_encoding": "rot13"
        })
        .to_string();
        let path = write_traffic(dir.path(), &[line]);
        let err = load_legacy_jsonl(&path).unwrap_err();
        assert!(err.to_string().contains("rot13"), "err: {err}");
    }
}
