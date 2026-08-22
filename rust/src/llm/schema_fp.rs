//! Schema fingerprinting: sha256 over the canonical rendering of the
//! normalized shape tree ([`crate::llm::shape`]).
//!
//! The fingerprint is plain lowercase hex (the output of
//! [`crate::bundle::sha256_hex`]) so it can be compared as an opaque string.
//! Any two bodies whose JSON differs only in key order, whitespace, or number
//! formatting produce identical fingerprints; any type-level difference
//! (including array element-union changes) produces different ones.

use serde_json::Value;

use crate::llm::shape::shape_of;

/// Fingerprint the normalized shape of a JSON value as sha256 hex.
pub fn schema_fingerprint(value: &Value) -> String {
    crate::bundle::sha256_hex(shape_of(value).render().as_bytes())
}

/// Centralized drift comparison for tuple aggregation (trivial today, but
/// every drift decision must go through here).
pub fn fingerprints_differ(a: &str, b: &str) -> bool {
    a != b
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const GOLDEN_NESTED: &str = "44dd2606fb79936f919e0f114a12333be68696664d000797e065dfec75aa64ad";

    #[test]
    fn stable_across_key_order_and_whitespace() {
        let a = json!({"model": "claude", "messages": [{"role": "user", "content": "hi"}], "stream": false});
        let b: Value = serde_json::from_str(
            r#"{ "stream" : false ,
                 "messages" : [ { "content" : "hi" ,  "role" : "user" } ],
             "model":"claude" }"#,
        )
        .unwrap();
        assert_eq!(schema_fingerprint(&a), schema_fingerprint(&b));
        assert_eq!(schema_fingerprint(&a).len(), 64);
    }

    #[test]
    fn shape_change_changes_fingerprint() {
        let a = json!({"model": "claude"});
        let b = json!({"model": 42});
        assert!(fingerprints_differ(
            &schema_fingerprint(&a),
            &schema_fingerprint(&b)
        ));
    }

    #[test]
    fn golden_vector_is_locked() {
        // Cross-run golden vector: recomputing this hash pins the whole
        // normalization + rendering pipeline against silent format changes.
        let doc = json!({
            "model": "gemini",
            "generationConfig": {"temperature": 0.7, "topK": [1, 2]},
            "contents": [{"parts": [{"text": "hi"}], "role": "user"}],
            "tools": [],
            "flag": null
        });
        assert_eq!(schema_fingerprint(&doc), GOLDEN_NESTED);
    }

    #[test]
    fn empty_object_and_array_differ() {
        assert!(fingerprints_differ(
            &schema_fingerprint(&json!({})),
            &schema_fingerprint(&json!([]))
        ));
    }
}
