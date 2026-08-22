//! Port of `src/infer.ts` — schema inference from JSON values and traffic
//! JSONL files.

use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use crate::error::{Error, Result};

/// A single inferred OpenAPI schema node. Field names on the wire match the
/// TypeScript `InferredSchema` interface exactly (camelCase, optional fields
/// omitted when absent).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct InferredSchema {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<SchemaType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<BTreeMap<String, InferredSchema>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<InferredSchema>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<serde_json::Value>,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_: Option<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullable: Option<bool>,
    #[serde(
        rename = "additionalProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub additional_properties: Option<bool>,
}

/// The `type` field of an [`InferredSchema`]: a single type or a union array,
/// mirroring TS `string | string[]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SchemaType {
    One(String),
    Many(Vec<String>),
}

/// An inferred schema for one endpoint/status/content-type group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSchema {
    pub path: String,
    pub method: String,
    pub status_code: u16,
    pub content_type: String,
    pub schema: InferredSchema,
    pub sample_count: usize,
}

fn date_time_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}").unwrap());
    &RE
}

fn date_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap());
    &RE
}

fn uri_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^https?://").unwrap());
    &RE
}

fn email_re() -> &'static Regex {
    // JS `\w` is ASCII-only; spell the class out for parity.
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$").unwrap()
    });
    &RE
}

fn ipv4_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$").unwrap());
    &RE
}

fn uuid_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            .unwrap()
    });
    &RE
}

/// Infer an OpenAPI schema from a JSON value.
///
/// Direct port of TS `inferSchema(value, path)`. The `path` argument only
/// feeds recursion labels in the original; it does not influence output.
pub fn infer_schema(value: &serde_json::Value, path: &str) -> InferredSchema {
    let _ = path;
    match value {
        serde_json::Value::Null => InferredSchema {
            type_: Some(SchemaType::One("null".into())),
            nullable: Some(true),
            ..Default::default()
        },
        serde_json::Value::Bool(b) => InferredSchema {
            type_: Some(SchemaType::One("boolean".into())),
            example: Some(serde_json::Value::Bool(*b)),
            ..Default::default()
        },
        serde_json::Value::Number(n) => InferredSchema {
            type_: Some(SchemaType::One(
                if is_integer_number(n) {
                    "integer"
                } else {
                    "number"
                }
                .into(),
            )),
            example: Some(value.clone()),
            ..Default::default()
        },
        serde_json::Value::String(s) => {
            let mut schema = InferredSchema {
                type_: Some(SchemaType::One("string".into())),
                example: Some(value.clone()),
                ..Default::default()
            };
            if date_time_re().is_match(s) {
                schema.format = Some("date-time".into());
            } else if date_re().is_match(s) {
                schema.format = Some("date".into());
            } else if uri_re().is_match(s) {
                schema.format = Some("uri".into());
            } else if email_re().is_match(s) {
                schema.format = Some("email".into());
            } else if ipv4_re().is_match(s) {
                schema.format = Some("ipv4".into());
            } else if uuid_re().is_match(s) {
                schema.format = Some("uuid".into());
            }
            schema
        }
        serde_json::Value::Array(items) => {
            if items.is_empty() {
                return InferredSchema {
                    type_: Some(SchemaType::One("array".into())),
                    items: Some(Box::new(InferredSchema {
                        type_: Some(SchemaType::One("object".into())),
                        ..Default::default()
                    })),
                    ..Default::default()
                };
            }
            let item_schemas: Vec<InferredSchema> = items
                .iter()
                .map(|item| infer_schema(item, &format!("{path}[]")))
                .collect();
            let merged_items = merge_schemas(&item_schemas);
            InferredSchema {
                type_: Some(SchemaType::One("array".into())),
                items: Some(Box::new(merged_items)),
                ..Default::default()
            }
        }
        serde_json::Value::Object(map) => {
            let mut properties = BTreeMap::new();
            let mut required: Vec<String> = Vec::new();
            for (key, val) in map {
                properties.insert(key.clone(), infer_schema(val, key));
                if !val.is_null() {
                    required.push(key.clone());
                }
            }
            InferredSchema {
                type_: Some(SchemaType::One("object".into())),
                properties: Some(properties),
                required: (!required.is_empty()).then_some(required),
                additional_properties: Some(false),
                ..Default::default()
            }
        }
    }
}

/// JSON numbers are integers when they have no fractional part (`1e6`
/// included), matching JS `Number.isInteger`.
fn is_integer_number(n: &serde_json::Number) -> bool {
    if n.is_i64() || n.is_u64() {
        return true;
    }
    match n.as_f64() {
        Some(f) => f.is_finite() && f.fract() == 0.0,
        None => false,
    }
}

/// Merge multiple schemas into one.
///
/// Port of TS `mergeSchemas`: unions types, merges object properties
/// recursively, intersects `required`, merges array items and keeps the first
/// example. A lone `null` alongside one concrete type becomes `nullable`.
pub fn merge_schemas(schemas: &[InferredSchema]) -> InferredSchema {
    if schemas.is_empty() {
        return InferredSchema {
            type_: Some(SchemaType::One("object".into())),
            ..Default::default()
        };
    }
    if schemas.len() == 1 {
        return schemas[0].clone();
    }

    // Collect all types, preserving first-seen order like a JS Set.
    let mut types: Vec<String> = Vec::new();
    let mut all_properties: BTreeMap<String, Vec<InferredSchema>> = BTreeMap::new();
    let mut all_items: Vec<InferredSchema> = Vec::new();
    let mut all_examples: Vec<serde_json::Value> = Vec::new();

    for s in schemas {
        if let Some(SchemaType::One(t)) = &s.type_ {
            if !types.contains(t) {
                types.push(t.clone());
            }
        }
        if let Some(props) = &s.properties {
            for (k, v) in props {
                all_properties.entry(k.clone()).or_default().push(v.clone());
            }
        }
        if let Some(items) = &s.items {
            all_items.push((**items).clone());
        }
        if let Some(example) = &s.example {
            all_examples.push(example.clone());
        }
    }

    let mut result = InferredSchema::default();

    // Handle type merging.
    if types.len() == 1 {
        result.type_ = Some(SchemaType::One(types[0].clone()));
    } else if types.len() > 1 {
        if types.contains(&"null".to_string()) && types.len() == 2 {
            let non_null = types
                .iter()
                .find(|t| t.as_str() != "null")
                .cloned()
                .unwrap_or_else(|| "string".to_string());
            result.type_ = Some(SchemaType::One(non_null));
            result.nullable = Some(true);
        } else {
            result.type_ = Some(SchemaType::Many(types.clone()));
        }
    }

    // Merge object properties.
    if !all_properties.is_empty() {
        let mut merged_props = BTreeMap::new();
        for (key, prop_schemas) in &all_properties {
            merged_props.insert(key.clone(), merge_schemas(prop_schemas));
        }
        result.properties = Some(merged_props);

        // Required if present in every schema that has properties.
        let required: Vec<String> = all_properties
            .keys()
            .filter(|key| {
                schemas
                    .iter()
                    .all(|s| s.properties.as_ref().is_some_and(|p| p.contains_key(*key)))
            })
            .cloned()
            .collect();
        result.required = (!required.is_empty()).then_some(required);
        result.additional_properties = Some(false);
    }

    // Merge array items.
    if !all_items.is_empty() {
        result.items = Some(Box::new(merge_schemas(&all_items)));
    }

    // Use first example.
    if let Some(first) = all_examples.first() {
        result.example = Some(first.clone());
    }

    result
}

/// One raw record of a legacy traffic JSONL file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrafficRecord {
    path: String,
    method: String,
    status: u16,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    body: Option<String>,
}

/// Infer schemas from a traffic JSONL file.
///
/// Each line is `{ path, method, status, contentType?, body? }`. Only lines
/// whose content type includes "json" and whose body parses as JSON are
/// grouped; responses are grouped by `method|path|status` and their bodies
/// merged into one schema per group.
pub fn infer_from_traffic(traffic_path: &std::path::Path) -> Result<Vec<EndpointSchema>> {
    let raw = std::fs::read_to_string(traffic_path)
        .map_err(|e| Error::io(format!("read traffic file {}", traffic_path.display()), e))?;
    let lines = raw.split('\n').filter(|l| !l.trim().is_empty());

    // Group responses by endpoint, preserving first-appearance order.
    struct Group {
        path: String,
        method: String,
        status_code: u16,
        content_type: String,
        bodies: Vec<serde_json::Value>,
    }
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();

    for line in lines {
        let entry: TrafficRecord = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let content_type = entry.content_type.clone().unwrap_or_default();
        if entry.body.is_none() || !content_type.contains("json") {
            continue;
        }
        let Ok(body) =
            serde_json::from_str::<serde_json::Value>(entry.body.as_deref().unwrap_or(""))
        else {
            continue;
        };

        let key = format!("{}|{}|{}", entry.method, entry.path, entry.status);
        let group = groups.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Group {
                path: entry.path.clone(),
                method: entry.method.clone(),
                status_code: entry.status,
                content_type: if content_type.is_empty() {
                    "application/json".to_string()
                } else {
                    content_type.clone()
                },
                bodies: Vec::new(),
            }
        });
        group.bodies.push(body);
    }

    let mut results = Vec::new();
    for key in order {
        let group = &groups[&key];
        if group.bodies.is_empty() {
            continue;
        }
        let schemas: Vec<InferredSchema> =
            group.bodies.iter().map(|b| infer_schema(b, "")).collect();
        let merged = merge_schemas(&schemas);
        results.push(EndpointSchema {
            path: group.path.clone(),
            method: group.method.clone(),
            status_code: group.status_code,
            content_type: group.content_type.clone(),
            sample_count: group.bodies.len(),
            schema: merged,
        });
    }

    Ok(results)
}

/// Format inferred schemas as an OpenAPI `components.schemas` YAML fragment.
pub fn format_as_components(endpoints: &[EndpointSchema]) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push("components:".to_string());
    lines.push("  schemas:".to_string());

    for ep in endpoints {
        let name = schema_name_from_endpoint(ep);
        lines.push(format!("    {name}:"));
        lines.extend(format_schema(&ep.schema, "      "));
    }

    lines.join("\n")
}

fn schema_name_from_endpoint(ep: &EndpointSchema) -> String {
    // Generate a schema name from path and status.
    let stripped = strip_origin(&ep.path);
    let parts: Vec<String> = stripped
        .split('/')
        .filter(|p| !p.is_empty() && !(p.starts_with('{') && p.ends_with('}')))
        .map(|p| {
            p.chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect()
        })
        .collect();

    let base = if parts.is_empty() {
        "root".to_string()
    } else {
        parts.join("_")
    };
    format!(
        "{}_{}_{}_response",
        ep.method.to_lowercase(),
        base,
        ep.status_code
    )
}

fn strip_origin(path: &str) -> &str {
    for prefix in ["https://", "http://"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            return match rest.find('/') {
                Some(idx) => &rest[idx..],
                None => "/",
            };
        }
    }
    path
}

fn format_schema(schema: &InferredSchema, indent: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();

    if let Some(t) = &schema.type_ {
        let rendered = match t {
            SchemaType::One(s) => s.clone(),
            SchemaType::Many(list) => list.join(", "),
        };
        lines.push(format!("{indent}type: {rendered}"));
    }

    if let Some(true) = schema.nullable {
        lines.push(format!("{indent}nullable: true"));
    }

    if let Some(f) = &schema.format {
        lines.push(format!("{indent}format: {f}"));
    }

    if let Some(ex) = &schema.example {
        let ex = serde_json::to_string(ex).unwrap_or_else(|_| "null".to_string());
        lines.push(format!("{indent}example: {ex}"));
    }

    if let Some(props) = &schema.properties {
        lines.push(format!("{indent}properties:"));
        for (key, prop) in props {
            lines.push(format!("{indent}  {key}:"));
            lines.extend(format_schema(prop, &format!("{indent}    ")));
        }
    }

    if let Some(required) = &schema.required {
        if !required.is_empty() {
            lines.push(format!("{indent}required:"));
            for req in required {
                lines.push(format!("{indent}  - {req}"));
            }
        }
    }

    if let Some(items) = &schema.items {
        lines.push(format!("{indent}items:"));
        lines.extend(format_schema(items, &format!("{indent}  ")));
    }

    if let Some(ap) = schema.additional_properties {
        lines.push(format!("{indent}additionalProperties: {ap}"));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn infers_scalars_with_examples() {
        assert_eq!(
            infer_schema(&json!(null), ""),
            InferredSchema {
                type_: Some(SchemaType::One("null".into())),
                nullable: Some(true),
                ..Default::default()
            }
        );
        let s = infer_schema(&json!(true), "");
        assert_eq!(s.type_, Some(SchemaType::One("boolean".into())));
        assert_eq!(s.example, Some(json!(true)));

        let i = infer_schema(&json!(42), "");
        assert_eq!(i.type_, Some(SchemaType::One("integer".into())));

        let f = infer_schema(&json!(9.876543), "");
        assert_eq!(f.type_, Some(SchemaType::One("number".into())));
    }

    #[test]
    fn detects_string_formats() {
        let cases = [
            ("2026-01-02T03:04:05Z", "date-time"),
            ("2026-01-02", "date"),
            ("https://example.com/x", "uri"),
            ("user@example.com", "email"),
            ("192.168.0.1", "ipv4"),
            ("123e4567-e89b-12d3-a456-426614174000", "uuid"),
        ];
        for (value, format) in cases {
            let s = infer_schema(&json!(value), "");
            assert_eq!(s.format.as_deref(), Some(format), "value {value}");
        }
    }

    #[test]
    fn infers_objects_and_arrays() {
        let s = infer_schema(&json!({"id": 1, "name": null, "tags": ["a", "b"]}), "");
        assert_eq!(s.type_, Some(SchemaType::One("object".into())));
        let props = s.properties.unwrap();
        assert_eq!(props["id"].type_, Some(SchemaType::One("integer".into())));
        assert_eq!(props["name"].type_, Some(SchemaType::One("null".into())));
        let tags = props["tags"].clone();
        assert_eq!(tags.type_, Some(SchemaType::One("array".into())));
        assert_eq!(
            tags.items.unwrap().type_,
            Some(SchemaType::One("string".into()))
        );
        // name is null so not required
        assert_eq!(s.required, Some(vec!["id".into(), "tags".into()]));
        assert_eq!(s.additional_properties, Some(false));

        let empty = infer_schema(&json!([]), "");
        assert_eq!(
            empty.items.unwrap().type_,
            Some(SchemaType::One("object".into()))
        );
    }

    #[test]
    fn merge_empty_yields_object() {
        let m = merge_schemas(&[]);
        assert_eq!(m.type_, Some(SchemaType::One("object".into())));
    }

    #[test]
    fn merge_single_is_passthrough() {
        let s = infer_schema(&json!("hello"), "");
        let m = merge_schemas(std::slice::from_ref(&s));
        assert_eq!(m, s);
    }

    #[test]
    fn merge_null_becomes_nullable() {
        let a = infer_schema(&json!(null), "");
        let b = infer_schema(&json!("x"), "");
        let m = merge_schemas(&[a, b]);
        assert_eq!(m.type_, Some(SchemaType::One("string".into())));
        assert_eq!(m.nullable, Some(true));
    }

    #[test]
    fn merge_unions_multiple_types() {
        let a = infer_schema(&json!("x"), "");
        let b = infer_schema(&json!(1), "");
        let c = infer_schema(&json!(true), "");
        let m = merge_schemas(&[a, b, c]);
        assert_eq!(
            m.type_,
            Some(SchemaType::Many(vec![
                "string".into(),
                "integer".into(),
                "boolean".into()
            ]))
        );
    }

    #[test]
    fn merge_intersects_required_and_merges_properties() {
        let a = infer_schema(&json!({"id": 1, "name": "a"}), "");
        let b = infer_schema(&json!({"id": 2}), "");
        let m = merge_schemas(&[a, b]);
        let props = m.properties.unwrap();
        assert!(props.contains_key("name"));
        assert_eq!(props["id"].type_, Some(SchemaType::One("integer".into())));
        assert_eq!(props["name"].nullable, None); // both non-null strings
        assert_eq!(m.required, Some(vec!["id".into()]));
    }

    #[test]
    fn merge_keeps_first_example() {
        let a = infer_schema(&json!("first"), "");
        let b = infer_schema(&json!("second"), "");
        let m = merge_schemas(&[a, b]);
        assert_eq!(m.example, Some(json!("first")));
    }

    fn write_temp_jsonl(lines: &[String]) -> std::path::PathBuf {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("traffic.jsonl");
        std::fs::write(&path, lines.join("\n")).expect("write");
        // Leak the dir so the path stays valid until process exit (tests only).
        std::mem::forget(dir);
        path
    }

    #[test]
    fn infer_from_traffic_groups_by_method_path_status() {
        let path = write_temp_jsonl(&[
            json!({"path":"/users","method":"get","status":200,"contentType":"application/json","body":"{\"id\":1}"}).to_string(),
            json!({"path":"/users","method":"get","status":200,"contentType":"application/json","body":"{\"id\":2,\"name\":\"j\"}"}).to_string(),
            json!({"path":"/users","method":"post","status":201,"contentType":"application/json","body":"{\"ok\":true}"}).to_string(),
        ]);
        let eps = infer_from_traffic(&path).expect("infer");
        assert_eq!(eps.len(), 2);
        let get = eps.iter().find(|e| e.method == "get").unwrap();
        assert_eq!(get.sample_count, 2);
        assert_eq!(
            get.schema.properties.as_ref().unwrap()["id"].type_,
            Some(SchemaType::One("integer".into()))
        );
        assert_eq!(
            get.schema.properties.as_ref().unwrap()["name"].type_,
            Some(SchemaType::One("string".into()))
        );
    }

    #[test]
    fn infer_from_traffic_skips_non_json() {
        let path = write_temp_jsonl(&[
            json!({"path":"/bin","method":"get","status":200,"contentType":"image/png","body":"AAAA"}).to_string(),
            json!({"path":"/broken","method":"get","status":200,"contentType":"application/json","body":"{not json"}).to_string(),
            json!({"path":"/empty","method":"get","status":204}).to_string(),
        ]);
        let eps = infer_from_traffic(&path).expect("infer");
        assert!(eps.is_empty());
    }

    #[test]
    fn format_as_components_renders_yaml_fragment() {
        let eps = vec![EndpointSchema {
            path: "/users/123".into(),
            method: "GET".into(),
            status_code: 200,
            content_type: "application/json".into(),
            sample_count: 1,
            schema: infer_schema(&json!({"id": 1}), ""),
        }];
        let out = format_as_components(&eps);
        assert!(out.starts_with("components:\n  schemas:\n    get_users_123_200_response:"));
        assert!(out.contains("type: object"));
        assert!(out.contains("properties:"));
        assert!(out.contains("required:"));
        assert!(out.contains("- id"));
        assert!(out.contains("additionalProperties: false"));
    }

    #[test]
    fn schema_name_strips_params_and_origin() {
        let ep = EndpointSchema {
            path: "https://api.example.com/v1/users/{id}".into(),
            method: "POST".into(),
            status_code: 201,
            content_type: String::new(),
            sample_count: 1,
            schema: InferredSchema::default(),
        };
        assert_eq!(schema_name_from_endpoint(&ep), "post_v1_users_201_response");
    }
}
