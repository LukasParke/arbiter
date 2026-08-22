//! OpenAPI spec loading and Prism-parity example-response generation (W3).
//!
//! AMEND-4: this module hosts THE single spec loader,
//! [`load_spec_document`]; validation and any other consumer delegate here.
//! One `serde_yaml` call-site, extension-dispatched.
use std::path::Path;

use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// Max $ref resolution depth (cyclic specs must not hang startup).
const REF_DEPTH_LIMIT: usize = 32;

// ---------------------------------------------------------------------------
// Spec loader (AMEND-4)
// ---------------------------------------------------------------------------

/// Load an OpenAPI document as JSON. `.yaml`/`.yml` parse as YAML; anything
/// else parses as JSON. This is the ONE spec call-site in the crate.
pub fn load_spec_document(path: &Path) -> Result<Value> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::io(format!("mock: read spec {}", path.display()), e))?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "yaml" | "yml" => {
            let yaml: serde_yaml::Value = serde_yaml::from_slice(&bytes).map_err(|e| {
                Error::other(format!("mock: invalid YAML in {}: {e}", path.display()))
            })?;
            serde_json::to_value(yaml).map_err(|e| Error::Json {
                context: format!("mock: convert YAML spec {} to JSON", path.display()),
                source: e,
            })
        }
        _ => serde_json::from_slice(&bytes).map_err(|e| Error::Json {
            context: format!("mock: parse spec {}", path.display()),
            source: e,
        }),
    }
}

// ---------------------------------------------------------------------------
// Example response generation
// ---------------------------------------------------------------------------

/// Resolve the example response for `(method, path)` against a parsed spec.
///
/// Resolution order (deterministic at every tier):
/// 1. matching operation's preferred status (`status_pref`) else lowest 2xx
/// 2. media-type `examples` entry, then media-type `example`
/// 3. schema-derived sample (recursive: `example`/`default` keyword, enum[0],
///    required object properties, arrays of one element)
/// 4. empty `{}` with status 200, `application/json`
///
/// Returns `(status, content_type, body_bytes)`.
pub fn example_response_for(
    spec: &Value,
    method: &str,
    path: &str,
    status_pref: Option<u16>,
) -> Option<(u16, String, Vec<u8>)> {
    let op = find_operation(spec, method, path)?;
    let responses = op.get("responses")?.as_object()?;

    let Some((status, response)) = select_response(responses, status_pref) else {
        return Some((200, "application/json".to_string(), b"{}".to_vec()));
    };

    if let Some(content) = response.get("content").and_then(Value::as_object) {
        if let Some((content_type, mt)) = pick_media_type(content) {
            // Tier 2a: named `examples`, deterministic key order.
            if let Some(examples) = mt.get("examples").and_then(Value::as_object) {
                for key in examples.keys() {
                    if let Some(value) = examples[key].get("value") {
                        return Some((status, content_type.clone(), json_body(value)));
                    }
                }
            }
            // Tier 2b: inline `example`.
            if let Some(example) = mt.get("example") {
                if !example.is_null() {
                    return Some((status, content_type.clone(), json_body(example)));
                }
            }
            // Tier 3: schema-derived sample.
            if let Some(schema) = mt.get("schema") {
                let sample = sample_from_schema(spec, schema, 0);
                return Some((status, content_type.clone(), json_body(&sample)));
            }
            // Declared content type but nothing to derive from: empty JSON.
            return Some((status, content_type.clone(), b"{}".to_vec()));
        }
    }

    // No content block: status-only response (204-style).
    Some((status, "application/json".to_string(), Vec::new()))
}

/// CORS headers attached to mock responses when enabled.
pub fn cors_headers() -> [(&'static str, &'static str); 3] {
    [
        ("access-control-allow-origin", "*"),
        (
            "access-control-allow-methods",
            "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
        ),
        ("access-control-allow-headers", "*"),
    ]
}

fn json_body(value: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec())
}

/// Find the operation node for `(method, path)`, matching OpenAPI path
/// templates (`/v1/messages/{id}`) segment-wise. Most-specific template wins:
/// fewest parameters, then most literal characters, then lexicographic.
fn find_operation<'a>(spec: &'a Value, method: &str, path: &str) -> Option<&'a Value> {
    let paths = spec.get("paths")?.as_object()?;
    let mut best: Option<(&String, (usize, usize, bool))> = None;
    for (tpl, item) in paths {
        let item = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        if !path_matches_template(tpl, path) {
            continue;
        }
        let params = tpl.matches('{').count();
        let rank = (params, tpl.len(), tpl == path);
        let better = match best {
            None => true,
            Some((_, cur)) => {
                rank.0 < cur.0
                    || (rank.0 == cur.0 && (rank.1 > cur.1 || (rank.1 == cur.1 && rank.2)))
            }
        };
        if better && item.get(method.to_ascii_lowercase().as_str()).is_some() {
            best = Some((tpl, rank));
        }
    }
    let (tpl, _) = best?;
    paths[tpl].get(method.to_ascii_lowercase().as_str())
}

/// Segment-wise template matching: `{param}` matches exactly one non-empty
/// segment; literal segments compare equal.
fn path_matches_template(tpl: &str, path: &str) -> bool {
    let t: Vec<&str> = tpl.split('/').filter(|s| !s.is_empty()).collect();
    let p: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    t.len() == p.len()
        && t.iter()
            .zip(&p)
            .all(|(ts, ps)| is_template_segment(ts) || ts == ps)
}

fn is_template_segment(seg: &str) -> bool {
    seg.len() >= 2 && seg.starts_with('{') && seg.ends_with('}')
}

/// Select the response entry: preferred status first, then lowest 2xx
/// (numeric codes and `2XX`-style ranges both handled). Deterministic.
fn select_response(
    responses: &Map<String, Value>,
    status_pref: Option<u16>,
) -> Option<(u16, &Value)> {
    if let Some(pref) = status_pref {
        if let Some(r) = responses.get(&pref.to_string()) {
            return Some((pref, r));
        }
    }
    let mut candidates: Vec<(u16, &Value)> = Vec::new();
    for (key, value) in responses {
        if let Some(code) = status_code_of(key) {
            if (200..300).contains(&code) {
                candidates.push((code, value));
            }
        }
    }
    candidates.sort_by_key(|(code, _)| *code);
    candidates.into_iter().next()
}

/// Parse `"200"` → 200, `"2XX"` → 200 (range base), anything else → None.
fn status_code_of(key: &str) -> Option<u16> {
    if let Ok(code) = key.parse::<u16>() {
        return (100..=599).contains(&code).then_some(code);
    }
    let bytes = key.as_bytes();
    if bytes.len() == 3 && bytes[1] == b'X' && bytes[2] == b'X' && bytes[0].is_ascii_digit() {
        return Some((bytes[0] - b'0') as u16 * 100);
    }
    None
}

/// Pick the served media type deterministically: JSON-flavored keys first,
/// then lexicographic order.
fn pick_media_type(content: &Map<String, Value>) -> Option<(&String, &Value)> {
    let mut keys: Vec<&String> = content.keys().collect();
    keys.sort();
    keys.iter()
        .find(|k| k.contains("json"))
        .or_else(|| keys.first())
        .and_then(|k| content.get(*k).map(|v| (*k, v)))
}

// ---------------------------------------------------------------------------
// Schema-derived samples
// ---------------------------------------------------------------------------

/// Deterministic recursive sample generation.
pub fn sample_from_schema(root: &Value, schema: &Value, depth: usize) -> Value {
    if depth > REF_DEPTH_LIMIT {
        return Value::Null;
    }
    let obj = match schema.as_object() {
        Some(o) => o,
        None => return Value::Null,
    };

    // Local $ref resolution first.
    if let Some(reference) = obj.get("$ref").and_then(Value::as_str) {
        if let Some(resolved) = resolve_local_ref(root, reference) {
            return sample_from_schema(root, resolved, depth + 1);
        }
        return Value::Null;
    }

    // Keyword overrides before structural walk.
    for keyword in ["example", "default"] {
        if let Some(v) = obj.get(keyword) {
            if !v.is_null() {
                return v.clone();
            }
        }
    }
    if let Some(enum_vals) = obj.get("enum").and_then(Value::as_array) {
        if let Some(first) = enum_vals.first() {
            return first.clone();
        }
    }

    // Composition keywords.
    for composite in ["allOf", "anyOf", "oneOf"] {
        if let Some(subs) = obj.get(composite).and_then(Value::as_array) {
            let mut merged = Map::new();
            let mut merged_any = false;
            for sub in subs {
                let sample = sample_from_schema(root, sub, depth + 1);
                merged_any = true;
                if let Value::Object(m) = sample {
                    for (k, v) in m {
                        merged.insert(k, v);
                    }
                } else if merged.len() == 1 {
                    let only = merged.values().next().cloned();
                    if let Some(v) = only {
                        return v;
                    }
                }
            }
            if merged_any {
                return Value::Object(merged);
            }
        }
    }

    let schema_type = obj
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| infer_type(obj));

    match schema_type.as_deref() {
        Some("object") => {
            let required: Vec<&str> = obj
                .get("required")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let props = obj.get("properties").and_then(Value::as_object);
            let mut out = Map::new();
            if let Some(props) = props {
                for name in &required {
                    if let Some(prop_schema) = props.get(*name) {
                        out.insert(
                            (*name).to_string(),
                            sample_from_schema(root, prop_schema, depth + 1),
                        );
                    }
                }
                // No `required` list: emit all declared properties so the
                // sample still documents the shape.
                if required.is_empty() {
                    for (name, prop_schema) in props {
                        out.insert(
                            name.clone(),
                            sample_from_schema(root, prop_schema, depth + 1),
                        );
                    }
                }
            }
            Value::Object(out)
        }
        Some("array") => {
            let items = obj.get("items").cloned().unwrap_or(Value::Null);
            Value::Array(vec![sample_from_schema(root, &items, depth + 1)])
        }
        Some("string") => Value::String(canonical_string(obj)),
        Some("integer") => Value::Number(serde_json::Number::from(0)),
        Some("number") => serde_json::Number::from_f64(0.0)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Some("boolean") => Value::Bool(false),
        _ => Value::Null,
    }
}

fn infer_type(obj: &Map<String, Value>) -> Option<String> {
    if obj.contains_key("properties") || obj.contains_key("required") {
        Some("object".into())
    } else if obj.contains_key("items") {
        Some("array".into())
    } else {
        None
    }
}

fn canonical_string(obj: &Map<String, Value>) -> String {
    match obj.get("format").and_then(Value::as_str) {
        Some("date") => "1970-01-01".to_string(),
        Some("date-time") => "1970-01-01T00:00:00Z".to_string(),
        Some("uuid") => "00000000-0000-4000-8000-000000000000".to_string(),
        Some("email") => "user@example.com".to_string(),
        Some("uri") | Some("url") => "https://example.com/".to_string(),
        Some("binary") => String::new(),
        _ => String::new(),
    }
}

/// Resolve a local RFC 6901 pointer like `#/components/schemas/Pet`.
fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    root.pointer(pointer)
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_YAML: &str = r##"
openapi: 3.0.3
info:
  title: Demo
  version: "1.0"
paths:
  /pets/{id}:
    get:
      operationId: getPet
      parameters:
        - name: id
          in: path
          required: true
          schema: { type: string }
      responses:
        "200":
          description: ok
          content:
            application/json:
              examples:
                dog:
                  value:
                    id: pet-42
                    name: Rex
              schema:
                $ref: "#/components/schemas/Pet"
  /pets:
    get:
      operationId: listPets
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: "#/components/schemas/Pet"
    post:
      operationId: createPet
      responses:
        "201":
          description: created
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Pet"
components:
  schemas:
    Pet:
      type: object
      required: [id, name, tags, kind, born]
      properties:
        id: { type: string }
        name: { type: string, example: Fido }
        tags:
          type: array
          items: { type: string }
        kind:
          type: string
          enum: [cat, dog]
        born:
          type: string
          format: date-time
"##;

    fn load_yaml_spec() -> Value {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("spec.yaml");
        std::fs::write(&path, SPEC_YAML).expect("write spec");
        load_spec_document(&path).expect("parse spec")
    }

    #[test]
    fn loader_dispatches_by_extension_and_errors_loudly() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let yaml_path = dir.path().join("spec.yml");
        std::fs::write(
            &yaml_path,
            "openapi: 3.0.3\ninfo:\n  title: t\n  version: \"1\"\npaths: {}",
        )
        .expect("write");
        assert!(load_spec_document(&yaml_path).is_ok());

        let json_path = dir.path().join("spec.json");
        std::fs::write(&json_path, "{\"openapi\":\"3.0.3\"}").expect("write");
        assert!(load_spec_document(&json_path).is_ok());

        let bad_path = dir.path().join("spec.json");
        std::fs::write(&bad_path, "{{{ not json").expect("write");
        assert!(load_spec_document(&bad_path).is_err());

        let missing = dir.path().join("nope.yaml");
        assert!(load_spec_document(&missing).is_err());
    }

    #[test]
    fn examples_preferred_over_schema_derived() {
        let spec = load_yaml_spec();
        let (status, ct, body) =
            example_response_for(&spec, "GET", "/pets/pet-7", None).expect("example found");
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        let text = String::from_utf8(body).expect("utf8");
        assert!(text.contains("\"Rex\""), "named example wins: {text}");
        assert!(!text.contains("Fido"));
    }

    #[test]
    fn schema_derived_fallback_is_recursive_and_deterministic() {
        let spec = load_yaml_spec();
        // POST has no example: falls through to the schema sample.
        let (status, _, body) =
            example_response_for(&spec, "POST", "/pets", None).expect("example found");
        assert_eq!(status, 201);
        let doc: Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(doc["id"], Value::String(String::new()));
        assert_eq!(
            doc["name"],
            Value::String("Fido".into()),
            "property example honored"
        );
        assert_eq!(
            doc["tags"],
            Value::Array(vec![Value::String(String::new())]),
            "array gets one element"
        );
        assert_eq!(doc["kind"], Value::String("cat".into()), "enum picks first");
        assert_eq!(doc["born"], Value::String("1970-01-01T00:00:00Z".into()));

        // Arrays of objects: one element, recursively sampled.
        let (s2, _, body2) =
            example_response_for(&spec, "GET", "/pets", None).expect("list example");
        assert_eq!(s2, 200);
        let list: Value = serde_json::from_slice(&body2).expect("json body");
        let items = list.as_array().expect("array body");
        assert_eq!(items.len(), 1);

        // Same input, byte-identical output across calls.
        assert_eq!(
            example_response_for(&spec, "POST", "/pets", None),
            example_response_for(&spec, "POST", "/pets", None)
        );
    }

    #[test]
    fn status_preference_and_unknown_routes() {
        let spec = load_yaml_spec();
        // Preferred status that exists wins over default selection.
        let (status, _, _) =
            example_response_for(&spec, "GET", "/pets/x", Some(200)).expect("found");
        assert_eq!(status, 200);
        // Unknown route/method: no crash, graceful miss.
        assert!(example_response_for(&spec, "DELETE", "/pets/x", None).is_none());
        assert!(example_response_for(&spec, "GET", "/nowhere", None).is_none());
        // Route without documented responses falls back to empty 200.
        let minimal = serde_json::json!({
            "paths": { "/x": { "get": { "responses": {} } } }
        });
        let (st, ct, body) = example_response_for(&minimal, "GET", "/x", None).expect("fallback");
        assert_eq!((st, ct), (200, "application/json".to_string()));
        assert_eq!(body, b"{}");
    }

    #[test]
    fn cors_headers_present() {
        let cors = cors_headers();
        assert!(cors
            .iter()
            .any(|(k, v)| *k == "access-control-allow-origin" && *v == "*"));
        assert!(cors
            .iter()
            .any(|(k, _)| *k == "access-control-allow-methods"));
        assert!(cors
            .iter()
            .any(|(k, _)| *k == "access-control-allow-headers"));
    }

    #[test]
    fn template_params_match_one_segment_only() {
        let spec = serde_json::json!({
            "paths": {
                "/a/{id}/b": { "get": { "responses": { "200": {
                    "description": "ok",
                    "content": { "application/json": { "example": { "ok": true } } }
                } } } }
            }
        });
        let (st, _, body) = example_response_for(&spec, "GET", "/a/123/b", None).expect("match");
        assert_eq!(st, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json")["ok"],
            Value::Bool(true)
        );
        // Two segments where the template expects one: no match.
        assert!(example_response_for(&spec, "GET", "/a/1/2/b", None).is_none());
    }
}
