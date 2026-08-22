//! Deterministic JSON serialization and JSON Pointer (RFC 6901) helpers.
//!
//! `stable_stringify` sorts object keys lexicographically at every depth with
//! no whitespace variance — the canonical form used for manifest/exchange
//! serialization and bundle digests. It matches the TS `stableStringify`
//! byte-for-byte for the same value.

use serde_json::Value;

/// Canonical JSON encoding: object keys sorted at every depth, compact.
pub fn stable_stringify(value: &Value) -> String {
    let mut out = String::new();
    write_stable(value, &mut out);
    out
}

fn write_stable(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            escape_json_string(s, out);
            out.push('"');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_stable(item, out);
            }
            out.push(']');
        }
        // serde_json's Map is a BTreeMap by default: iteration is already
        // key-sorted, which is exactly the stable ordering.
        Value::Object(map) => {
            out.push('{');
            for (i, (key, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                escape_json_string(key, out);
                out.push_str("\":");
                write_stable(val, out);
            }
            out.push('}');
        }
    }
}

/// Escape per RFC 8259 with the same two-byte escapes serde_json emits
/// (`\b \t \n \f \r \" \\` and `\u00XX` for other control characters).
fn escape_json_string(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// Resolve an RFC 6901 JSON Pointer against a value. Empty pointer = whole
/// document; `~0`/`~1` escapes honored; `-` on arrays resolves to nothing.
pub fn json_pointer_get<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    if !pointer.starts_with('/') {
        return None;
    }
    let mut current = value;
    for raw_token in pointer.split('/').skip(1) {
        let token = raw_token.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(map) => map.get(&token)?,
            Value::Array(items) => {
                if token == "-" {
                    return None;
                }
                items.get(token.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stable_stringify_sorts_keys_at_depth() {
        let v = json!({ "b": 1, "a": { "z": [1, {"y": 2, "x": 3}], "a": null } });
        assert_eq!(
            stable_stringify(&v),
            r#"{"a":{"a":null,"z":[1,{"x":3,"y":2}]},"b":1}"#
        );
    }

    #[test]
    fn stable_stringify_escapes() {
        let v = json!("quote\" back\\slash\n\t\u{01}");
        assert_eq!(
            stable_stringify(&v),
            "\"quote\\\" back\\\\slash\\n\\t\\u0001\""
        );
    }

    #[test]
    fn pointer_resolution() {
        let v = json!({"a/b": 1, "m~n": 2, "arr": [{"x": 5}]});
        assert_eq!(json_pointer_get(&v, ""), Some(&v));
        assert_eq!(json_pointer_get(&v, "/a~1b"), Some(&json!(1)));
        assert_eq!(json_pointer_get(&v, "/m~0n"), Some(&json!(2)));
        assert_eq!(json_pointer_get(&v, "/arr/0/x"), Some(&json!(5)));
        assert_eq!(json_pointer_get(&v, "/arr/-"), None);
        assert_eq!(json_pointer_get(&v, "/missing"), None);
    }
}
