//! Derived export views. HAR and traffic JSONL are projections of the
//! canonical exchange model, never independent storage formats.
//!
//! Port of `src/bundle/derive.ts`. Bodies are resolved from a digest-keyed
//! map (inline bodies decode from base64; blob digests must be present in
//! the map, as produced by `CaptureBundle::read_all_bodies`).

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use base64::Engine as _;
use regex::Regex;
use serde::Serialize;

use crate::types::{BodyStorage, CapturedBody, CapturedExchange, HeaderMapValues};
use crate::version::ARBITER_VERSION;

fn textual_media() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)json|text|xml|yaml|x-www-form-urlencoded|event-stream|javascript").unwrap()
    });
    &RE
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HarHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HarPostData {
    mime_type: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HarContent {
    size: u64,
    mime_type: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HarRequest {
    method: String,
    url: String,
    http_version: String,
    headers: Vec<HarHeader>,
    query_string: Vec<HarHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_data: Option<HarPostData>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HarResponse {
    status: u16,
    status_text: String,
    http_version: String,
    headers: Vec<HarHeader>,
    content: HarContent,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HarEntry {
    started_date_time: String,
    time: f64,
    request: HarRequest,
    response: HarResponse,
}

#[derive(Debug, Clone, Serialize)]
struct HarLogInner {
    version: &'static str,
    creator: Creator,
    entries: Vec<HarEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct Creator {
    name: &'static str,
    version: &'static str,
}

/// HAR 1.2 document: `{ "log": { version, creator, entries } }`.
#[derive(Debug, Clone)]
pub struct HarLog {
    pub log: serde_json::Value,
}

/// Resolve the stored bytes for a captured body. Inline bodies decode from
/// base64; blob bodies are looked up by digest. Unresolvable bodies degrade
/// to empty bytes (HAR is a best-effort projection, never an error surface).
fn body_bytes(body: &CapturedBody, bodies: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    match &body.storage {
        BodyStorage::InlineBase64 { value } => base64::engine::general_purpose::STANDARD
            .decode(value)
            .unwrap_or_default(),
        BodyStorage::Blob { .. } => bodies.get(&body.sha256).cloned().unwrap_or_default(),
    }
}

/// Resolve a request path+query against the target origin, mirroring the TS
/// `new URL(path, targetOrigin)`. Falls back to the raw path when either
/// side fails to parse.
fn absolute_url(target_origin: &str, path: &str) -> Option<url::Url> {
    let base = url::Url::parse(target_origin).ok()?;
    base.join(path).ok()
}

fn headers_to_har(values: &HeaderMapValues) -> Vec<HarHeader> {
    let mut out = Vec::new();
    for (name, header_values) in values {
        for value in header_values {
            out.push(HarHeader {
                name: name.clone(),
                value: value.clone(),
            });
        }
    }
    out
}

fn first_values(values: &HeaderMapValues) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, header_values) in values {
        if let Some(first) = header_values.first() {
            out.insert(name.clone(), first.clone());
        }
    }
    out
}

fn is_textual(body: &CapturedBody) -> bool {
    body.content_encoding.is_none()
        && body
            .media_type
            .as_deref()
            .map(|m| textual_media().is_match(m))
            .unwrap_or(false)
}

/// Textual bodies are inlined as UTF-8; everything else is base64 with an
/// explicit `base64` encoding marker.
fn encode_content(bytes: &[u8], body: &CapturedBody) -> (String, Option<&'static str>) {
    if is_textual(body) {
        (String::from_utf8_lossy(bytes).into_owned(), None)
    } else {
        (
            base64::engine::general_purpose::STANDARD.encode(bytes),
            Some("base64"),
        )
    }
}

/// Empty bodies become `null`; textual bodies UTF-8; others base64 with the
/// encoding marker so JSONL consumers never mistake binary for text.
fn body_to_text(bytes: &[u8], body: &CapturedBody) -> (Option<String>, Option<&'static str>) {
    if bytes.is_empty() {
        return (None, None);
    }
    if is_textual(body) {
        (Some(String::from_utf8_lossy(bytes).into_owned()), None)
    } else {
        (
            Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            Some("base64"),
        )
    }
}

/// Project captured exchanges into a HAR 1.2 log rooted at `target_origin`.
pub fn exchanges_to_har(
    exchanges: &[CapturedExchange],
    target_origin: &str,
    bodies: &HashMap<String, Vec<u8>>,
) -> HarLog {
    let entries: Vec<HarEntry> = exchanges
        .iter()
        .map(|exchange| {
            let parsed = absolute_url(target_origin, &exchange.request.path);
            let url_string = parsed
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_else(|| exchange.request.path.clone());
            let query_string: Vec<HarHeader> = parsed
                .as_ref()
                .map(|u| {
                    u.query_pairs()
                        .map(|(name, value)| HarHeader {
                            name: name.into_owned(),
                            value: value.into_owned(),
                        })
                        .collect()
                })
                .unwrap_or_default();

            let request_bytes = body_bytes(&exchange.request.body, bodies);
            let response_bytes = body_bytes(&exchange.response.body, bodies);
            let (request_text, request_encoding) =
                encode_content(&request_bytes, &exchange.request.body);
            let (response_text, response_encoding) =
                encode_content(&response_bytes, &exchange.response.body);

            let post_data = if request_bytes.is_empty() {
                None
            } else {
                Some(HarPostData {
                    mime_type: exchange
                        .request
                        .body
                        .media_type
                        .clone()
                        .unwrap_or_else(|| "application/octet-stream".to_string()),
                    text: request_text,
                    encoding: request_encoding.map(|e| e.to_string()),
                })
            };

            HarEntry {
                started_date_time: exchange.started_at.clone(),
                time: exchange.duration_ms,
                request: HarRequest {
                    method: exchange.request.method.clone(),
                    url: url_string,
                    http_version: format!("HTTP/{}", exchange.request.http_version),
                    headers: headers_to_har(&exchange.request.headers.values),
                    query_string,
                    post_data,
                },
                response: HarResponse {
                    status: exchange.response.status,
                    status_text: exchange.response.status_text.clone(),
                    http_version: format!("HTTP/{}", exchange.response.http_version),
                    headers: headers_to_har(&exchange.response.headers.values),
                    content: HarContent {
                        size: exchange.response.body.size,
                        mime_type: exchange
                            .response
                            .body
                            .media_type
                            .clone()
                            .unwrap_or_else(|| "application/octet-stream".to_string()),
                        text: response_text,
                        encoding: response_encoding.map(|e| e.to_string()),
                    },
                },
            }
        })
        .collect();

    let inner = HarLogInner {
        version: "1.2",
        creator: Creator {
            name: "Arbiter",
            version: ARBITER_VERSION,
        },
        entries,
    };
    HarLog {
        log: serde_json::to_value(&inner).expect("HAR log serializes"),
    }
}

/// One traffic line: a stable-JSON projection of a single exchange.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrafficLine {
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub request_headers: BTreeMap<String, String>,
    pub request_body: Option<String>,
    /// Present (as `"base64"`) when `request_body` is not UTF-8 text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_encoding: Option<String>,
    pub response_status: u16,
    pub response_headers: BTreeMap<String, String>,
    pub response_body: Option<String>,
    /// Present (as `"base64"`) when `response_body` is not UTF-8 text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_encoding: Option<String>,
}

impl TrafficLine {
    /// Canonical (key-sorted) JSON encoding of this line, matching the
    /// stable-JSON discipline used across the bundle format.
    pub fn to_stable_json(&self) -> String {
        let value = serde_json::to_value(self).expect("traffic line serializes");
        crate::json::stable_stringify(&value)
    }
}

/// Project captured exchanges into stable-JSON traffic lines, one per
/// exchange, in input order.
pub fn exchanges_to_traffic_jsonl(
    exchanges: &[CapturedExchange],
    bodies: &HashMap<String, Vec<u8>>,
) -> Vec<String> {
    exchanges
        .iter()
        .map(|exchange| {
            let request_bytes = body_bytes(&exchange.request.body, bodies);
            let response_bytes = body_bytes(&exchange.response.body, bodies);
            let (request_text, request_encoding) =
                body_to_text(&request_bytes, &exchange.request.body);
            let (response_text, response_encoding) =
                body_to_text(&response_bytes, &exchange.response.body);
            let line = TrafficLine {
                timestamp: exchange.started_at.clone(),
                method: exchange.request.method.clone(),
                path: exchange.request.path.clone(),
                request_headers: first_values(&exchange.request.headers.values),
                request_body: request_text,
                request_body_encoding: request_encoding.map(|e| e.to_string()),
                response_status: exchange.response.status,
                response_headers: first_values(&exchange.response.headers.values),
                response_body: response_text,
                response_body_encoding: response_encoding.map(|e| e.to_string()),
            };
            line.to_stable_json()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::make_captured_body;
    use crate::types::{
        CaptureFailure, CapturedHeaders, CapturedRequest, CapturedResponse, StreamState,
        ValidationSummary,
    };

    fn header_map(pairs: &[(&str, &[&str])]) -> HeaderMapValues {
        let mut map = HeaderMapValues::new();
        for (name, values) in pairs {
            map.insert(
                name.to_string(),
                values.iter().map(|v| v.to_string()).collect(),
            );
        }
        map
    }

    fn exchange_with(
        seq: u64,
        path: &str,
        request_body: &[u8],
        request_media: Option<&str>,
        response_body: &[u8],
        response_media: Option<&str>,
    ) -> CapturedExchange {
        let req = make_captured_body(request_body, request_media, None, None).unwrap();
        let resp = make_captured_body(response_body, response_media, None, None).unwrap();
        CapturedExchange {
            schema_version: 1,
            sequence: seq,
            started_at: "2025-01-01T00:00:00.000Z".into(),
            duration_ms: 12.5,
            request: CapturedRequest {
                method: "POST".into(),
                path: path.into(),
                http_version: "1.1".into(),
                headers: CapturedHeaders {
                    values: header_map(&[
                        ("content-type", ["application/json"].as_slice()),
                        ("x-multi", ["first", "second"].as_slice()),
                    ]),
                    redacted: vec![],
                },
                body: req,
            },
            response: CapturedResponse {
                status: 201,
                status_text: "Created".into(),
                http_version: "1.1".into(),
                headers: CapturedHeaders {
                    values: header_map(&[("server", ["test"].as_slice())]),
                    redacted: vec![],
                },
                body: resp,
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
    fn har_log_shape_and_entry_fields() {
        let exchange = exchange_with(
            0,
            "/v1/messages?api_key=abc&page=2",
            b"{\"q\":1}",
            Some("application/json"),
            b"{\"ok\":true}",
            Some("application/json"),
        );
        let bodies: HashMap<String, Vec<u8>> = HashMap::new();
        let har = exchanges_to_har(&[exchange], "https://api.example.com", &bodies);

        let inner = har.log.as_object().expect("log object");
        assert_eq!(
            inner.keys().collect::<Vec<_>>(),
            vec!["creator", "entries", "version"]
        );
        assert_eq!(inner.get("version").unwrap(), "1.2");
        let creator = inner.get("creator").unwrap();
        assert_eq!(creator.get("name").unwrap(), "Arbiter");
        assert_eq!(creator.get("version").unwrap(), ARBITER_VERSION);

        let entries = inner.get("entries").unwrap().as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = entries[0].as_object().unwrap();
        assert_eq!(
            entry.get("startedDateTime").unwrap(),
            "2025-01-01T00:00:00.000Z"
        );
        assert_eq!(entry.get("time").unwrap(), 12.5);

        let request = entry.get("request").unwrap().as_object().unwrap();
        assert_eq!(request.get("method").unwrap(), "POST");
        assert_eq!(
            request.get("url").unwrap(),
            "https://api.example.com/v1/messages?api_key=abc&page=2"
        );
        assert_eq!(request.get("httpVersion").unwrap(), "HTTP/1.1");
        let query = request.get("queryString").unwrap().as_array().unwrap();
        assert_eq!(query.len(), 2);
        assert_eq!(query[0].get("name").unwrap(), "api_key");
        assert_eq!(query[0].get("value").unwrap(), "abc");
        assert_eq!(query[1].get("name").unwrap(), "page");

        let headers = request.get("headers").unwrap().as_array().unwrap();
        assert_eq!(headers.len(), 3); // content-type + x-multi x2
        let post = request.get("postData").unwrap().as_object().unwrap();
        assert_eq!(post.get("mimeType").unwrap(), "application/json");
        assert_eq!(post.get("text").unwrap(), "{\"q\":1}");
        assert!(post.get("encoding").is_none()); // textual: no encoding marker

        let response = entry.get("response").unwrap().as_object().unwrap();
        assert_eq!(response.get("status").unwrap(), 201);
        assert_eq!(response.get("statusText").unwrap(), "Created");
        let content = response.get("content").unwrap().as_object().unwrap();
        assert_eq!(content.get("mimeType").unwrap(), "application/json");
        assert_eq!(content.get("size").unwrap(), 11);
        assert_eq!(content.get("text").unwrap(), "{\"ok\":true}");
        assert!(content.get("encoding").is_none());
    }

    #[test]
    fn har_empty_request_body_has_no_post_data_and_binary_is_base64() {
        let exchange = exchange_with(
            0,
            "/v1/binary",
            b"",
            None,
            b"\xff\xfe\x00binary",
            Some("image/png"),
        );
        let bodies: HashMap<String, Vec<u8>> = HashMap::new();
        let har = exchanges_to_har(&[exchange], "https://api.example.com", &bodies);

        let entry = har.log["entries"][0].as_object().unwrap();
        assert!(entry["request"].get("postData").is_none());
        let content = entry["response"]["content"].as_object().unwrap();
        assert_eq!(content["mimeType"], "image/png");
        assert_eq!(content["encoding"], "base64");
        assert_eq!(
            content["text"],
            base64::engine::general_purpose::STANDARD.encode(b"\xff\xfe\x00binary")
        );
    }

    #[test]
    fn har_blob_bodies_resolve_from_map() {
        let bytes = b"large payload".to_vec();
        let mut exchange = exchange_with(
            0,
            "/x",
            b"req",
            Some("text/plain"),
            &bytes,
            Some("text/plain"),
        );
        let digest = crate::bundle::sha256_hex(&bytes);
        // Force the response body to blob storage.
        exchange.response.body.storage = BodyStorage::Blob {
            path: format!("bodies/{digest}.bin"),
        };
        let mut bodies: HashMap<String, Vec<u8>> = HashMap::new();
        bodies.insert(digest, bytes);
        let har = exchanges_to_har(
            std::slice::from_ref(&exchange),
            "https://api.example.com",
            &bodies,
        );
        assert_eq!(
            har.log["entries"][0]["response"]["content"]["text"],
            "large payload"
        );
    }

    #[test]
    fn traffic_line_shape_and_encoding_markers() {
        let exchange = exchange_with(
            0,
            "/v1/messages?x=1",
            b"{\"q\":1}",
            Some("application/json"),
            b"",
            Some("application/json"),
        );
        let bodies: HashMap<String, Vec<u8>> = HashMap::new();
        let lines = exchanges_to_traffic_jsonl(std::slice::from_ref(&exchange), &bodies);
        assert_eq!(lines.len(), 1);

        let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        let obj = parsed.as_object().unwrap();
        // Stable JSON: keys sorted.
        let keys: Vec<&String> = obj.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);

        assert_eq!(parsed["timestamp"], "2025-01-01T00:00:00.000Z");
        assert_eq!(parsed["method"], "POST");
        assert_eq!(parsed["path"], "/v1/messages?x=1");
        // First value only for repeated headers.
        assert_eq!(parsed["request_headers"]["x-multi"], "first");
        assert_eq!(
            parsed["request_headers"]["content-type"],
            "application/json"
        );
        assert_eq!(parsed["request_body"], "{\"q\":1}");
        assert!(parsed.get("request_body_encoding").is_none());
        assert_eq!(parsed["response_status"], 201);
        assert_eq!(parsed["response_body"], serde_json::Value::Null);
        assert!(parsed.get("response_body_encoding").is_none());
    }

    #[test]
    fn traffic_line_marks_binary_bodies_base64() {
        let exchange = exchange_with(
            0,
            "/bin",
            b"\x00\x01\x02",
            Some("application/octet-stream"),
            b"\xff",
            Some("application/octet-stream"),
        );
        let bodies: HashMap<String, Vec<u8>> = HashMap::new();
        let lines = exchanges_to_traffic_jsonl(std::slice::from_ref(&exchange), &bodies);
        let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(parsed["request_body_encoding"], "base64");
        assert_eq!(
            parsed["request_body"],
            base64::engine::general_purpose::STANDARD.encode(b"\x00\x01\x02")
        );
        assert_eq!(parsed["response_body_encoding"], "base64");
    }

    #[test]
    fn traffic_lines_are_stable_and_ordered() {
        let a = exchange_with(0, "/a", b"1", Some("text/plain"), b"2", Some("text/plain"));
        let mut b = exchange_with(1, "/b", b"3", Some("text/plain"), b"4", Some("text/plain"));
        b.request
            .headers
            .values
            .insert("zz".into(), vec!["v".into()]);
        let bodies: HashMap<String, Vec<u8>> = HashMap::new();
        let lines = exchanges_to_traffic_jsonl(&[a, b], &bodies);
        assert_eq!(lines.len(), 2);
        // Deterministic across runs.
        let mut b2 = exchange_with(1, "/b", b"3", Some("text/plain"), b"4", Some("text/plain"));
        b2.request
            .headers
            .values
            .insert("zz".into(), vec!["v".into()]);
        let again = exchanges_to_traffic_jsonl(
            &[
                exchange_with(0, "/a", b"1", Some("text/plain"), b"2", Some("text/plain")),
                b2,
            ],
            &bodies,
        );
        assert_eq!(lines, again);
    }

    #[test]
    fn failure_and_validation_fields_do_not_break_projection() {
        let mut exchange = exchange_with(
            7,
            "/f",
            b"{}",
            Some("application/json"),
            b"{}",
            Some("application/json"),
        );
        exchange.failure = Some(CaptureFailure {
            stage: "response-capture".into(),
            message: "boom".into(),
        });
        exchange.validation = Some(ValidationSummary {
            valid: false,
            violation_count: 2,
        });
        let bodies: HashMap<String, Vec<u8>> = HashMap::new();
        let har = exchanges_to_har(&[exchange], "https://api.example.com", &bodies);
        assert_eq!(har.log["entries"].as_array().unwrap().len(), 1);
    }
}
