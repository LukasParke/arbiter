//! Header normalization, redaction capture, and forwarding policy.

use std::collections::BTreeMap;

use crate::redaction::RedactionPolicy;
use crate::types::{CapturedHeaders, HeaderMapValues};

/// RFC 9110 hop-by-hop headers, never forwarded or replayed.
pub const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP_HEADERS.contains(&name.to_lowercase().as_str())
}

/// Build lowercased name -> value[] headers from a raw header list of
/// interleaved name/value pairs, preserving duplicate header values as
/// separate array entries.
pub fn headers_from_raw(raw_headers: &[String]) -> HeaderMapValues {
    let mut out: HeaderMapValues = BTreeMap::new();
    let mut iter = raw_headers.iter();
    while let (Some(name), Some(value)) = (iter.next(), iter.next()) {
        out.entry(name.to_lowercase())
            .or_default()
            .push(value.clone());
    }
    out
}

/// Apply a redaction policy to normalized headers: matching header values are
/// removed entirely and the names recorded as evidence (sorted).
pub fn capture_headers(headers: &HeaderMapValues, policy: &RedactionPolicy) -> CapturedHeaders {
    let mut values: HeaderMapValues = BTreeMap::new();
    let mut redacted: Vec<String> = vec![];
    for (name, header_values) in headers {
        if policy.should_redact_header(name) {
            redacted.push(name.clone());
        } else {
            values.insert(name.clone(), header_values.clone());
        }
    }
    redacted.sort();
    CapturedHeaders { values, redacted }
}

/// Headers safe to forward upstream: hop-by-hop and framing headers are
/// stripped; the HTTP client recomputes framing itself.
pub fn forwardable_headers(headers: &HeaderMapValues, strip_host: bool) -> HeaderMapValues {
    let mut out: HeaderMapValues = BTreeMap::new();
    for (name, values) in headers {
        if is_hop_by_hop(name) {
            continue;
        }
        if name == "content-length" {
            continue; // recomputed from the streamed body
        }
        if strip_host && name == "host" {
            continue;
        }
        out.insert(name.clone(), values.clone());
    }
    out
}

/// Convert a header map into an HTTP `HeaderMap`, joining duplicates with
/// ", " only when a name cannot carry multiple entries. Invalid names or
/// values (visible ASCII requirement) are skipped rather than failing a
/// capture.
pub fn to_http_header_map(values: &HeaderMapValues) -> http::HeaderMap {
    to_http_header_map_with(values, |_| false)
}

/// Like [`to_http_header_map`] but skipping names for which `skip`
/// returns true (used to drop per-request framing like host).
pub fn to_http_header_map_with(
    values: &HeaderMapValues,
    skip: impl Fn(&str) -> bool,
) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for (name, header_values) in values {
        if skip(name) {
            continue;
        }
        let Ok(header_name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        // Reconstruct one entry per duplicate value to preserve multiplicity.
        for value in header_values {
            if let Ok(header_value) = http::HeaderValue::from_bytes(value.as_bytes()) {
                map.append(&header_name, header_value);
            }
        }
    }
    map
}

/// Convert an `http::HeaderMap` into normalized lowercased multi-map form.
pub fn from_http_header_map(map: &http::HeaderMap) -> HeaderMapValues {
    let mut out: HeaderMapValues = BTreeMap::new();
    for (name, value) in map {
        let key = name.as_str().to_lowercase();
        let val = String::from_utf8_lossy(value.as_bytes()).into_owned();
        out.entry(key).or_default().push(val);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_pairs_preserve_duplicates() {
        let raw = vec![
            "Set-Cookie".to_string(),
            "a=1".to_string(),
            "set-cookie".to_string(),
            "b=2".to_string(),
            "Host".to_string(),
            "example.com".to_string(),
        ];
        let out = headers_from_raw(&raw);
        assert_eq!(
            out.get("set-cookie"),
            Some(&vec!["a=1".to_string(), "b=2".to_string()])
        );
        assert_eq!(out.get("host"), Some(&vec!["example.com".to_string()]));
    }

    #[test]
    fn capture_headers_sorts_redacted_evidence() {
        let mut headers: HeaderMapValues = BTreeMap::new();
        headers.insert("z-auth".into(), vec!["v".into()]);
        headers.insert("authorization".into(), vec!["secret".into()]);
        headers.insert("content-type".into(), vec!["application/json".into()]);
        headers.insert("x-api-key".into(), vec!["k".into()]);
        let captured = capture_headers(&headers, &RedactionPolicy::default());
        assert_eq!(
            captured.redacted,
            vec!["authorization", "x-api-key", "z-auth"]
        );
        assert!(captured.values.contains_key("content-type"));
        assert!(!captured.values.contains_key("authorization"));
    }

    #[test]
    fn forwardable_strips_framing() {
        let mut headers: HeaderMapValues = BTreeMap::new();
        for name in [
            "connection",
            "transfer-encoding",
            "content-length",
            "host",
            "accept",
        ] {
            headers.insert(name.into(), vec!["1".into()]);
        }
        let stripped = forwardable_headers(&headers, true);
        assert_eq!(stripped.keys().collect::<Vec<_>>(), vec!["accept"]);
        let kept = forwardable_headers(&headers, false);
        assert_eq!(kept.keys().collect::<Vec<_>>(), vec!["accept", "host"]);
    }

    #[test]
    fn http_map_round_trip_keeps_duplicates() {
        use crate::types::HeaderMapValues as M;
        let mut m: M = BTreeMap::new();
        m.insert("x-multi".into(), vec!["a".into(), "b".into()]);
        let map = to_http_header_map(&m);
        assert_eq!(map.get_all("x-multi").iter().count(), 2);
        let back = from_http_header_map(&map);
        assert_eq!(back.get("x-multi"), Some(&vec!["a".into(), "b".into()]));
    }
}
