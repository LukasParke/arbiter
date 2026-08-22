//! Replay comparison primitives (port of src/replay/compare.ts).
//!
//! Byte-exact comparison reports the first differing offset; semantic JSON
//! comparison reports the first differing RFC 6901 pointer honoring declared
//! volatile pointers; semantic SSE comparison compares ordered events by name
//! with JSON payloads compared semantically. A body that yields no parseable
//! SSE events never matches vacuously under [`compare_semantic_sse`].

use std::collections::HashSet;

use serde_json::Value;

use crate::sse::parse_sse_body;

/// Byte-for-byte comparison reporting the first differing offset.
///
/// Returns `None` when the buffers are identical, otherwise a detail string
/// naming the first differing byte offset (or the length mismatch at the
/// shorter length).
pub fn compare_exact(actual: &[u8], expected: &[u8]) -> Option<String> {
    let limit = actual.len().min(expected.len());
    for i in 0..limit {
        if actual[i] != expected[i] {
            return Some(format!(
                "Byte mismatch at offset {i}: expected 0x{:02x}, got 0x{:02x}",
                expected[i], actual[i]
            ));
        }
    }
    if expected.len() != actual.len() {
        return Some(format!(
            "Length mismatch: expected {} bytes, got {}",
            expected.len(),
            actual.len()
        ));
    }
    None
}

/// Semantic JSON comparison after declared normalization.
///
/// Both bodies must parse as JSON (failure is a diff, never a skip); the
/// returned detail carries the first differing RFC 6901 pointer. Pointers in
/// `ignore` are treated as volatile and excluded from comparison.
pub fn compare_semantic_json(actual: &[u8], expected: &[u8], ignore: &[String]) -> Option<String> {
    let expected_value: Value = match serde_json::from_slice(expected) {
        Ok(value) => value,
        Err(err) => return Some(format!("Expected body is not valid JSON: {err}")),
    };
    let actual_value: Value = match serde_json::from_slice(actual) {
        Ok(value) => value,
        Err(err) => return Some(format!("Actual body is not valid JSON: {err}")),
    };
    let ignore = ignore.iter().cloned().collect::<HashSet<_>>();
    first_json_diff(&expected_value, &actual_value, "", &ignore).map(|pointer| {
        format!(
            "JSON values differ at {}",
            if pointer.is_empty() { "/" } else { &pointer }
        )
    })
}

/// Semantic SSE comparison: ordered events must match by name, and JSON data
/// payloads are compared semantically with declared volatile pointers.
/// Non-JSON data is compared as text.
///
/// A body yielding no parseable SSE events is not comparable in SSE mode;
/// matching it vacuously would be a false green.
pub fn compare_semantic_sse(actual: &[u8], expected: &[u8], ignore: &[String]) -> Option<String> {
    let all_expected = parse_sse_body(expected);
    if all_expected.is_empty() {
        return Some("Expected body contains no parseable SSE events".to_string());
    }
    let all_actual = parse_sse_body(actual);
    if all_actual.is_empty() {
        return Some("Actual body contains no parseable SSE events".to_string());
    }
    let ignore = ignore.iter().cloned().collect::<HashSet<_>>();

    let limit = all_expected.len().min(all_actual.len());
    for i in 0..limit {
        let exp = &all_expected[i];
        let act = &all_actual[i];
        if exp.event != act.event {
            return Some(format!(
                "event {i}: event name: expected {}, got {}",
                exp.event.as_deref().unwrap_or("(none)"),
                act.event.as_deref().unwrap_or("(none)")
            ));
        }
        let exp_json = try_parse_json(&exp.data);
        let act_json = try_parse_json(&act.data);
        match (exp_json, act_json) {
            (Some(exp_value), Some(act_value)) => {
                if let Some(pointer) = first_json_diff(&exp_value, &act_value, "", &ignore) {
                    return Some(format!(
                        "event {i}: data JSON differs at {}",
                        if pointer.is_empty() { "/" } else { &pointer }
                    ));
                }
            }
            _ => {
                if exp.data != act.data {
                    return Some(format!("event {i}: data text differs"));
                }
            }
        }
    }
    if all_expected.len() != all_actual.len() {
        return Some(format!(
            "event {limit}: event count: expected {}, got {}",
            all_expected.len(),
            all_actual.len()
        ));
    }
    None
}

fn try_parse_json(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

/// Returns the JSON pointer of the first difference, or `None` when equal.
/// An empty-string root difference is reported as `/` by callers via the
/// returned empty pointer convention (root pointer is `""`).
pub fn first_json_diff(
    expected: &Value,
    actual: &Value,
    pointer: &str,
    ignore: &HashSet<String>,
) -> Option<String> {
    if ignore.contains(pointer) {
        return None;
    }
    if let (Value::Array(expected_items), Value::Array(actual_items)) = (expected, actual) {
        let limit = expected_items.len().min(actual_items.len());
        for i in 0..limit {
            let child = format!("{pointer}/{i}");
            if let Some(diff) =
                first_json_diff(&expected_items[i], &actual_items[i], &child, ignore)
            {
                return Some(diff);
            }
        }
        if expected_items.len() != actual_items.len() {
            return Some(format!("{pointer}/{limit}"));
        }
        return None;
    }
    if let (Value::Object(expected_map), Value::Object(actual_map)) = (expected, actual) {
        let mut keys: Vec<&String> = expected_map
            .keys()
            .chain(actual_map.keys())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        keys.sort();
        for key in keys {
            let child = format!("{pointer}/{}", escape_pointer(key));
            if ignore.contains(&child) {
                continue;
            }
            match (expected_map.get(key), actual_map.get(key)) {
                (Some(exp_value), Some(act_value)) => {
                    if let Some(diff) = first_json_diff(exp_value, act_value, &child, ignore) {
                        return Some(diff);
                    }
                }
                // Present in exactly one object: missing key.
                _ => return Some(child),
            }
        }
        return None;
    }
    if expected == actual {
        None
    } else if pointer.is_empty() {
        Some("/".to_string())
    } else {
        Some(pointer.to_string())
    }
}

fn escape_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ignore_set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // ---- compare_exact ----

    #[test]
    fn exact_matches_identical_buffers() {
        assert_eq!(compare_exact(b"abc", b"abc"), None);
    }

    #[test]
    fn exact_reports_first_differing_byte_offset() {
        let diff = compare_exact(b"abcXef", b"abcdef");
        let detail = diff.expect("must differ");
        assert!(detail.contains("offset 3"), "detail: {detail}");
        assert!(detail.contains("0x64"), "detail: {detail}"); // expected 'd'
        assert!(detail.contains("0x58"), "detail: {detail}"); // got 'X'
    }

    #[test]
    fn exact_reports_length_mismatch_at_shorter_length() {
        let diff = compare_exact(b"abcd", b"abc");
        let detail = diff.expect("must differ");
        assert!(detail.contains("Length mismatch"), "detail: {detail}");
        assert!(detail.contains("expected 3"), "detail: {detail}");
        assert!(detail.contains("got 4"), "detail: {detail}");
    }

    // ---- compare_semantic_json ----

    #[test]
    fn json_ignores_whitespace_and_key_order() {
        let a = br#"{"b": 1, "a": [1, 2]}"#;
        let b = b"{ \"a\":[1,2],\n\"b\":1 }";
        assert_eq!(compare_semantic_json(a, b, &[]), None);
    }

    #[test]
    fn json_reports_first_differing_pointer() {
        let a = br#"{"x":{"y":[1,2,3]}}"#;
        let b = br#"{"x":{"y":[1,9,3]}}"#;
        let diff = compare_semantic_json(a, b, &[]).expect("must differ");
        assert!(diff.contains("/x/y/1"), "detail: {diff}");
    }

    #[test]
    fn json_honors_ignored_pointers() {
        let a = br#"{"id":"one","value":1}"#;
        let b = br#"{"id":"two","value":1}"#;
        assert_eq!(compare_semantic_json(a, b, &["/id".to_string()]), None,);
    }

    #[test]
    fn json_fails_on_invalid_json_rather_than_skipping() {
        let diff = compare_semantic_json(br#"{}"#, b"not json", &[]).expect("must differ");
        assert!(
            diff.contains("Expected body is not valid JSON"),
            "detail: {diff}"
        );

        let diff = compare_semantic_json(b"not json", br#"{}"#, &[]).expect("must differ");
        assert!(
            diff.contains("Actual body is not valid JSON"),
            "detail: {diff}"
        );
    }

    #[test]
    fn json_reports_missing_keys() {
        let diff = compare_semantic_json(br#"{}"#, br#"{"a":1}"#, &[]).expect("must differ");
        assert!(diff.contains("/a"), "detail: {diff}");
    }

    // ---- compare_semantic_sse ----

    fn stream(events: &[&str]) -> Vec<u8> {
        format!("{}\n\n", events.join("\n\n")).into_bytes()
    }

    #[test]
    fn sse_matches_identical_event_streams() {
        let a = stream(&["event: delta\ndata: {\"t\":\"x\"}", "data: [DONE]"]);
        assert_eq!(compare_semantic_sse(&a, &a, &[]), None);
    }

    #[test]
    fn sse_compares_json_payloads_semantically() {
        let a = stream(&["data: {\"a\":1, \"b\":2}"]);
        let b = stream(&["data: {\"b\":2,\"a\":1}"]);
        assert_eq!(compare_semantic_sse(&a, &b, &[]), None);
    }

    #[test]
    fn sse_reports_first_differing_event_with_pointer() {
        let a = stream(&["data: {\"n\":1}", "data: {\"n\":2}"]);
        let b = stream(&["data: {\"n\":1}", "data: {\"n\":3}"]);
        let diff = compare_semantic_sse(&a, &b, &[]).expect("must differ");
        assert!(diff.contains("event 1"), "detail: {diff}");
        assert!(diff.contains("/n"), "detail: {diff}");
    }

    #[test]
    fn sse_honors_volatile_pointers_in_event_data() {
        let a = stream(&["data: {\"id\":\"a\",\"text\":\"same\"}"]);
        let b = stream(&["data: {\"id\":\"b\",\"text\":\"same\"}"]);
        assert_eq!(compare_semantic_sse(&a, &b, &["/id".to_string()]), None,);
    }

    #[test]
    fn sse_reports_event_name_mismatches() {
        let a = stream(&["event: message_start\ndata: {}"]);
        let b = stream(&["event: message_stop\ndata: {}"]);
        let diff = compare_semantic_sse(&a, &b, &[]).expect("must differ");
        assert!(diff.contains("event name"), "detail: {diff}");
    }

    #[test]
    fn sse_reports_event_count_mismatches() {
        let a = stream(&["data: {\"n\":1}", "data: [DONE]"]);
        let b = stream(&["data: {\"n\":1}"]);
        let diff = compare_semantic_sse(&b, &a, &[]).expect("must differ");
        assert!(diff.contains("event count"), "detail: {diff}");
        assert!(diff.contains("expected 2, got 1"), "detail: {diff}");
    }

    #[test]
    fn sse_rejects_bodies_with_no_parseable_events_instead_of_matching_vacuously() {
        let empty: Vec<u8> = vec![];
        let json = br#"{"ok":true}"#;
        let diff = compare_semantic_sse(&empty, &empty, &[]).expect("must differ");
        assert!(diff.contains("no parseable SSE events"), "detail: {diff}");
        assert!(compare_semantic_sse(json, json, &[]).is_some());
    }

    #[test]
    fn sse_rejects_when_only_the_actual_body_is_non_sse() {
        let sse = stream(&["data: {\"n\":1}"]);
        let diff = compare_semantic_sse(b"", &sse, &[]).expect("must differ");
        assert!(diff.contains("Actual body"), "detail: {diff}");
    }

    // ---- first_json_diff ----

    #[test]
    fn first_json_diff_escapes_pointer_special_characters() {
        let diff = first_json_diff(&json!({"a/b": 1}), &json!({"a/b": 2}), "", &ignore_set(&[]))
            .expect("must differ");
        assert_eq!(diff, "/a~1b");
    }

    #[test]
    fn first_json_diff_returns_none_for_deep_equality() {
        assert_eq!(
            first_json_diff(
                &json!({"a": [{"b": null}]}),
                &json!({"a": [{"b": null}]}),
                "",
                &ignore_set(&[])
            ),
            None
        );
    }

    #[test]
    fn first_json_diff_root_difference_reported_as_root_pointer() {
        assert_eq!(
            first_json_diff(&json!(1), &json!(2), "", &ignore_set(&[])),
            Some("/".to_string())
        );
    }
}
