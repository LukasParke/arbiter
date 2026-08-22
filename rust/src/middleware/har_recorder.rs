//! HAR entry construction and the shared HAR store.
//!
//! Ports `src/server.ts` (`HARStore`, including its deferred raw-response
//! processing) and the HAR entry shape produced by the proxy recorder in
//! `src/server.ts` / `src/middleware/harRecorder.ts`. Entry shape satisfies
//! the HAR 1.2 consumers in `bundle::derive` (`exchanges_to_har`).

use serde_json::{json, Value};
use std::io::Read as _;
use std::sync::{LazyLock, Mutex};

use crate::types::HeaderMapValues;

/// Placeholder stored while a raw response buffer awaits processing.
pub const DEFERRED_TEXT: &str = "[Response content stored]";

/// Request/response parts for one HAR entry. Header maps must already be
/// redacted by the caller (the proxy applies the redaction policy before
/// recording); query pairs are ordered as they appeared on the wire.
#[derive(Debug, Clone)]
pub struct HarEntryParts<'a> {
    /// Request start, in milliseconds since the Unix epoch.
    pub started_at_ms: i64,
    /// Total request/response duration in milliseconds.
    pub time_ms: i64,
    pub method: &'a str,
    /// Full request URL (target origin + path + query).
    pub url: String,
    /// Redacted request headers; `content-length` is excluded from the entry.
    pub request_headers: &'a HeaderMapValues,
    pub query_string: Vec<(String, String)>,
    /// Request content type (defaults to `application/json` in the entry).
    pub request_content_type: Option<&'a str>,
    /// Decoded request body text, if any (drives `postData`).
    pub request_body_text: Option<String>,
    pub status: u16,
    /// Redacted response headers.
    pub response_headers: &'a HeaderMapValues,
    /// Raw response body bytes; `content-encoding` is honored when rendering
    /// `content.text`.
    pub response_body: Option<&'a [u8]>,
}

fn header_name_values(map: &HeaderMapValues, skip_content_length: bool) -> Value {
    let entries: Vec<Value> = map
        .iter()
        .filter(|(name, _)| !(skip_content_length && name.as_str() == "content-length"))
        .flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| json!({ "name": name, "value": value }))
        })
        .collect();
    Value::Array(entries)
}

fn first_header_value<'a>(map: &'a HeaderMapValues, name: &str) -> Option<&'a str> {
    map.get(name)
        .and_then(|values| values.first().map(|v| v.as_str()))
}

/// Renders `content.text` from raw response bytes, porting
/// `HARStore.processRawBuffers`: gzip is decompressed, other content
/// encodings are summarized, and JSON payloads are re-serialized compactly.
pub fn render_response_text(
    body: &[u8],
    content_type: &str,
    content_encoding: Option<&str>,
) -> String {
    let encoding = content_encoding.map(|e| e.to_lowercase());
    let text: String = match encoding.as_deref() {
        Some("gzip") => {
            let mut decoder = flate2::read::GzDecoder::new(body);
            let mut out = Vec::new();
            match decoder.read_to_end(&mut out) {
                Ok(_) => String::from_utf8_lossy(&out).into_owned(),
                Err(_) => "[Compressed content]".to_string(),
            }
        }
        Some(other) => return format!("[{other} compressed content]"),
        None => String::from_utf8_lossy(body).into_owned(),
    };

    if content_type.contains("json") {
        match serde_json::from_str::<Value>(&text) {
            Ok(parsed) => serde_json::to_string(&parsed).unwrap_or(text),
            Err(_) => text,
        }
    } else {
        text
    }
}

/// Builds one HAR 1.2 entry (`startedDateTime`, `time`, `request`,
/// `response`) with the exact field shape the TS proxy records. Unlike the
/// TS implementation the raw response buffer is processed eagerly — the
/// deferred `_rawResponseBuffer` was a JS event-loop optimization and never
/// appears in exported HAR output.
pub fn build_har_entry(parts: &HarEntryParts) -> Value {
    let started_date_time = chrono::DateTime::from_timestamp_millis(parts.started_at_ms)
        .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string());

    let request_content_type = parts.request_content_type.unwrap_or("application/json");
    let response_content_type = first_header_value(parts.response_headers, "content-type")
        .unwrap_or("application/octet-stream")
        .to_string();

    let content_text = parts
        .response_body
        .map(|body| {
            render_response_text(
                body,
                &response_content_type,
                first_header_value(parts.response_headers, "content-encoding"),
            )
        })
        .unwrap_or_else(|| DEFERRED_TEXT.to_string());

    let content_size = parts.response_body.map(|b| b.len()).unwrap_or(0);

    let query_string: Vec<Value> = parts
        .query_string
        .iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect();
    let mut request = json!({
        "method": parts.method,
        "url": parts.url,
        "httpVersion": "HTTP/1.1",
        "headers": header_name_values(parts.request_headers, true),
        "queryString": Value::Array(query_string),
    });
    if let Some(body_text) = &parts.request_body_text {
        request["postData"] = json!({
            "mimeType": request_content_type,
            "text": body_text,
        });
    }

    json!({
        "startedDateTime": started_date_time,
        "time": parts.time_ms,
        "request": request,
        "response": {
            "status": parts.status,
            "statusText": if parts.status == 200 { "OK" } else { "Error" },
            "httpVersion": "HTTP/1.1",
            "headers": header_name_values(parts.response_headers, false),
            "content": {
                "size": content_size,
                "mimeType": response_content_type,
                "text": content_text,
            },
        },
    })
}

/// Thread-safe in-memory HAR log (`HARStore` in `src/server.ts`).
#[derive(Debug, Default)]
pub struct HarStore {
    entries: Mutex<Vec<Value>>,
}

impl HarStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_entry(&self, entry: Value) {
        self.entries.lock().expect("har store poisoned").push(entry);
    }

    /// The full HAR document:
    /// `{ log: { version: "1.2", creator: { name: "Arbiter", version }, entries } }`.
    pub fn get_har(&self) -> Value {
        let entries = self.entries.lock().expect("har store poisoned").clone();
        json!({
            "log": {
                "version": "1.2",
                "creator": { "name": "Arbiter", "version": "1.0.0" },
                "entries": entries,
            }
        })
    }

    pub fn clear(&self) {
        self.entries.lock().expect("har store poisoned").clear();
    }

    pub fn entry_count(&self) -> usize {
        self.entries.lock().expect("har store poisoned").len()
    }
    /// Clones the entries at indices `[start, len)` paired with their
    /// index, so flows-API polling only pays for new entries (O(new)).
    pub fn entries_from(&self, start: usize) -> Vec<(usize, Value)> {
        self.entries
            .lock()
            .expect("har store poisoned")
            .iter()
            .enumerate()
            .skip(start)
            .map(|(index, entry)| (index, entry.clone()))
            .collect()
    }

    /// Clones one entry by index.
    pub fn entry(&self, index: usize) -> Option<Value> {
        self.entries
            .lock()
            .expect("har store poisoned")
            .get(index)
            .cloned()
    }

    /// Removes the entry at `index`; true when it existed. Later entries
    /// shift down one index, mirroring plain vector deletion.
    pub fn remove_entry(&self, index: usize) -> bool {
        let mut entries = self.entries.lock().expect("har store poisoned");
        if index >= entries.len() {
            return false;
        }
        entries.remove(index);
        true
    }
}

/// Process-wide HAR store, mirroring the TS module-level
/// `export const harStore = new HARStore()`.
pub fn har_store() -> &'static HarStore {
    static STORE: LazyLock<HarStore> = LazyLock::new(HarStore::new);
    &STORE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn headers(entries: &[(&str, &str)]) -> HeaderMapValues {
        let mut map = HeaderMapValues::new();
        for (name, value) in entries {
            map.entry(name.to_lowercase())
                .or_default()
                .push(value.to_string());
        }
        map
    }

    fn sample_parts<'a>(
        req_headers: &'a HeaderMapValues,
        resp_headers: &'a HeaderMapValues,
        body: Option<&'a [u8]>,
    ) -> HarEntryParts<'a> {
        HarEntryParts {
            started_at_ms: 1_700_000_000_123,
            time_ms: 42,
            method: "GET",
            url: "http://localhost:3000/test?foo=bar".to_string(),
            request_headers: req_headers,
            query_string: vec![("foo".to_string(), "bar".to_string())],
            request_content_type: Some("application/json"),
            request_body_text: None,
            status: 200,
            response_headers: resp_headers,
            response_body: body,
        }
    }

    #[test]
    fn entry_has_har_1_2_shape() {
        let req = headers(&[
            ("content-type", "application/json"),
            ("host", "localhost:8080"),
        ]);
        let resp = headers(&[("content-type", "application/json")]);
        let entry = build_har_entry(&sample_parts(&req, &resp, Some(br#"{"success":true}"#)));

        assert_eq!(entry["startedDateTime"], "2023-11-14T22:13:20.123Z");
        assert_eq!(entry["time"], 42);
        assert_eq!(entry["request"]["method"], "GET");
        assert_eq!(
            entry["request"]["url"],
            "http://localhost:3000/test?foo=bar"
        );
        assert_eq!(entry["request"]["httpVersion"], "HTTP/1.1");
        assert_eq!(
            entry["request"]["queryString"],
            json!([{ "name": "foo", "value": "bar" }])
        );
        assert_eq!(entry["response"]["status"], 200);
        assert_eq!(entry["response"]["statusText"], "OK");
        assert_eq!(entry["response"]["httpVersion"], "HTTP/1.1");
        assert_eq!(entry["response"]["content"]["size"], 16);
        assert_eq!(entry["response"]["content"]["mimeType"], "application/json");
        // JSON bodies are re-serialized compactly (JSON.stringify semantics).
        assert_eq!(entry["response"]["content"]["text"], r#"{"success":true}"#);
        // The internal raw-buffer property never leaks into entries.
        assert!(entry.get("_rawResponseBuffer").is_none());
    }

    #[test]
    fn content_length_is_dropped_from_request_headers_only() {
        let req = headers(&[
            ("content-type", "application/json"),
            ("content-length", "13"),
            ("x-custom", "v"),
        ]);
        let resp = headers(&[("content-length", "5"), ("x-resp", "w")]);
        let entry = build_har_entry(&sample_parts(&req, &resp, Some(b"hello")));

        let req_headers = entry["request"]["headers"].as_array().expect("headers");
        let names: Vec<&str> = req_headers
            .iter()
            .map(|h| h["name"].as_str().expect("name"))
            .collect();
        assert!(names.contains(&"x-custom"));
        assert!(!names.contains(&"content-length"));

        let resp_headers = entry["response"]["headers"].as_array().expect("headers");
        let resp_names: Vec<&str> = resp_headers
            .iter()
            .map(|h| h["name"].as_str().expect("name"))
            .collect();
        assert!(resp_names.contains(&"content-length"));
        assert!(resp_names.contains(&"x-resp"));
    }

    #[test]
    fn post_body_becomes_post_data_with_mime_type() {
        let req = headers(&[("content-type", "application/json")]);
        let resp = headers(&[("content-type", "application/json")]);
        let mut parts = sample_parts(&req, &resp, Some(br#"{"id":1}"#));
        parts.method = "POST";
        parts.request_body_text = Some(r#"{"name":"Test User"}"#.to_string());
        let entry = build_har_entry(&parts);

        assert_eq!(entry["request"]["postData"]["mimeType"], "application/json");
        assert_eq!(
            entry["request"]["postData"]["text"],
            r#"{"name":"Test User"}"#
        );
    }

    #[test]
    fn no_body_means_no_post_data_and_error_status_text() {
        let req = headers(&[]);
        let resp = headers(&[("content-type", "text/plain")]);
        let mut parts = sample_parts(&req, &resp, Some(b"boom"));
        parts.status = 500;
        let entry = build_har_entry(&parts);

        assert!(entry["request"].get("postData").is_none());
        assert_eq!(entry["response"]["status"], 500);
        assert_eq!(entry["response"]["statusText"], "Error");
        assert_eq!(entry["response"]["content"]["text"], "boom");
        assert_eq!(entry["response"]["content"]["mimeType"], "text/plain");
    }

    #[test]
    fn gzip_response_bodies_are_decompressed() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(br#"{"decompressed":true}"#)
            .expect("write gz");
        let gzipped = encoder.finish().expect("finish gz");

        let req = headers(&[]);
        let resp = headers(&[
            ("content-type", "application/json"),
            ("content-encoding", "gzip"),
        ]);
        let entry = build_har_entry(&sample_parts(&req, &resp, Some(&gzipped)));

        assert_eq!(
            entry["response"]["content"]["text"],
            r#"{"decompressed":true}"#
        );
        assert_eq!(entry["response"]["content"]["size"], gzipped.len() as i64);
    }

    #[test]
    fn non_gzip_encodings_are_summarized_and_failures_fall_back() {
        assert_eq!(
            render_response_text(b"x", "application/json", Some("deflate")),
            "[deflate compressed content]"
        );
        assert_eq!(
            render_response_text(b"not gzip", "text/plain", Some("gzip")),
            "[Compressed content]"
        );
    }

    #[test]
    fn malformed_json_is_kept_verbatim() {
        assert_eq!(
            render_response_text(b"{not json", "application/json", None),
            "{not json"
        );
    }

    #[test]
    fn har_store_round_trips_and_clears() {
        let store = HarStore::new();
        assert_eq!(store.entry_count(), 0);

        let req = headers(&[]);
        let resp = headers(&[]);
        store.add_entry(build_har_entry(&sample_parts(&req, &resp, None)));
        store.add_entry(build_har_entry(&sample_parts(&req, &resp, None)));
        assert_eq!(store.entry_count(), 2);

        let har = store.get_har();
        assert_eq!(har["log"]["version"], "1.2");
        assert_eq!(har["log"]["creator"]["name"], "Arbiter");
        assert_eq!(har["log"]["creator"]["version"], "1.0.0");
        assert_eq!(har["log"]["entries"].as_array().expect("entries").len(), 2);

        store.clear();
        assert_eq!(store.entry_count(), 0);
        assert_eq!(
            store.get_har()["log"]["entries"]
                .as_array()
                .expect("entries")
                .len(),
            0
        );
    }

    #[test]
    fn global_har_store_is_reachable_and_isolated_from_locals() {
        let global = har_store();
        global.clear();
        let req = headers(&[]);
        let resp = headers(&[]);
        global.add_entry(build_har_entry(&sample_parts(&req, &resp, None)));
        assert_eq!(global.entry_count(), 1);
        assert!(std::ptr::eq(har_store(), global));
        global.clear();
    }

    #[test]
    fn indexed_accessors_and_remove_entry() {
        let store = HarStore::new();
        let req = headers(&[]);
        let resp = headers(&[]);
        store.add_entry(build_har_entry(&sample_parts(&req, &resp, None)));
        store.add_entry(build_har_entry(&sample_parts(&req, &resp, None)));
        store.add_entry(build_har_entry(&sample_parts(&req, &resp, None)));

        // Tail reads are index-paired and skip earlier entries.
        let tail = store.entries_from(1);
        assert_eq!(tail.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![1, 2]);
        assert!(store.entry(2).is_some());
        assert!(store.entry(3).is_none());

        // Removal reports existence and shifts later indices down.
        assert!(store.remove_entry(1));
        assert_eq!(store.entry_count(), 2);
        assert!(store.entry(1).is_some(), "former index 2 shifted down");
        assert!(store.entry(2).is_none());
        let tail = store.entries_from(0);
        assert_eq!(tail.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 1]);
    }
}
