//! Port of `src/generate-spec.ts`: generate an OpenAPI 3.1 specification from
//! captured traffic JSONL.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::infer::{infer_schema, merge_schemas};

/// Generated OpenAPI document (shape per `generate-spec.ts`).
#[derive(Debug, Clone)]
pub struct GeneratedSpec {
    pub spec: Value,
}

#[derive(Debug, Deserialize)]
struct TrafficEntry {
    path: String,
    method: String,
    #[serde(default)]
    #[serde(rename = "queryParams")]
    query_params: Option<Vec<String>>,
    status: i64,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    #[serde(rename = "contentType")]
    content_type: Option<String>,
}

#[derive(Debug, Default)]
struct ResponseGroup {
    bodies: Vec<Value>,
    content_type: String,
}

#[derive(Debug, Default)]
struct EndpointGroup {
    path: String,
    method: String,
    query_params: BTreeSet<String>,
    responses: BTreeMap<i64, ResponseGroup>,
}

/// Generate an OpenAPI 3.1 spec from a traffic JSONL file.
///
/// Mirrors `generateSpecFromTraffic`: groups entries by `method|path`,
/// collects query parameter names, infers response schemas from JSON bodies
/// via `infer.ts`, and extracts the server URL from the first traffic entry.
pub fn generate_spec_from_traffic(
    traffic_path: &Path,
    title: &str,
    version: &str,
) -> Result<GeneratedSpec> {
    let raw = fs::read_to_string(traffic_path).map_err(|e| {
        Error::io(
            format!("failed to read traffic file {}", traffic_path.display()),
            e,
        )
    })?;
    let entries = parse_traffic_jsonl(&raw)?;

    // Group by method|path.
    let mut groups: BTreeMap<String, EndpointGroup> = BTreeMap::new();

    for entry in &entries {
        let key = format!("{}|{}", entry.method, entry.path);

        let group = groups.entry(key).or_insert_with(|| EndpointGroup {
            path: entry.path.clone(),
            method: entry.method.clone(),
            query_params: BTreeSet::new(),
            responses: BTreeMap::new(),
        });

        // Collect query params (names only, value part dropped).
        if let Some(qps) = &entry.query_params {
            for qp in qps {
                if let Some(name) = qp.split('=').next() {
                    if !name.is_empty() {
                        group.query_params.insert(name.to_string());
                    }
                }
            }
        }

        // Collect responses.
        group
            .responses
            .entry(entry.status)
            .or_insert_with(|| ResponseGroup {
                bodies: Vec::new(),
                content_type: entry
                    .content_type
                    .clone()
                    .unwrap_or_else(|| "application/json".to_string()),
            });

        if let Some(body) = &entry.body {
            if entry
                .content_type
                .as_deref()
                .map(|ct| ct.contains("json"))
                .unwrap_or(false)
            {
                if let Ok(parsed) = serde_json::from_str::<Value>(body) {
                    if let Some(resp) = group.responses.get_mut(&entry.status) {
                        resp.bodies.push(parsed);
                    }
                }
                // Non-JSON bodies are skipped, as in TS.
            }
        }
    }

    // Build paths.
    let mut paths: Map<String, Value> = Map::new();
    let mut schemas: Map<String, Value> = Map::new();

    for group in groups.values() {
        let path_item = paths
            .entry(group.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        // Internal invariant: path items are always objects we created.
        let path_item_obj = path_item.as_object_mut().expect("path item is an object");

        let mut parameters: Vec<Value> = Vec::new();
        for name in &group.query_params {
            parameters.push(json!({
                "name": name,
                "in": "query",
                "required": false,
                "schema": { "type": "string" },
            }));
        }

        let mut responses: Map<String, Value> = Map::new();
        for (status, resp) in &group.responses {
            let schema_name = format!(
                "{}_{}_{}",
                group.method.to_lowercase(),
                sanitize_path(&group.path),
                status
            );

            if !resp.bodies.is_empty() {
                let inferred: Vec<_> = resp.bodies.iter().map(|b| infer_schema(b, "")).collect();
                let merged = merge_schemas(&inferred);
                schemas.insert(
                    schema_name.clone(),
                    serde_json::to_value(&merged).map_err(|e| Error::Json {
                        context: "failed to serialize inferred schema".to_string(),
                        source: e,
                    })?,
                );

                responses.insert(
                    status.to_string(),
                    json!({
                        "description": format!("Response for {} {}", group.method, group.path),
                        "content": {
                            (resp.content_type.clone()): {
                                "schema": { "$ref": format!("#/components/schemas/{}", schema_name) }
                            }
                        }
                    }),
                );
            } else {
                responses.insert(
                    status.to_string(),
                    json!({
                        "description": format!("Response for {} {}", group.method, group.path),
                    }),
                );
            }
        }

        let mut operation = json!({
            "operationId": format!("{}_{}", group.method.to_lowercase(), sanitize_path(&group.path)),
            "summary": format!("{} {}", group.method, group.path),
            "responses": Value::Object(responses),
        });
        let operation_obj = operation.as_object_mut().expect("operation is an object");
        if !parameters.is_empty() {
            operation_obj.insert("parameters".to_string(), Value::Array(parameters));
        }

        path_item_obj.insert(group.method.to_lowercase(), operation);
    }

    // Extract server URL from traffic if not provided.
    let server_url = entries.first().map(|first| {
        let base = url::Url::parse("http://localhost").expect("constant base URL parses");
        match url::Url::options().base_url(Some(&base)).parse(&first.path) {
            Ok(parsed) => {
                let host = parsed.host_str().unwrap_or("localhost");
                let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
                format!("{}://{}{}", parsed.scheme(), host, port)
            }
            Err(_) => "http://localhost".to_string(),
        }
    });

    let servers = match server_url {
        Some(u) => json!([{ "url": u, "description": "Target server" }]),
        None => json!([]),
    };

    let title = if title.is_empty() {
        "Generated API Specification"
    } else {
        title
    };
    let version = if version.is_empty() { "1.0.0" } else { version };

    Ok(GeneratedSpec {
        spec: json!({
            "openapi": "3.1.0",
            "info": {
                "title": title,
                "description": "Auto-generated from captured traffic",
                "version": version,
            },
            "servers": servers,
            "paths": Value::Object(paths),
            "components": { "schemas": Value::Object(schemas) },
        }),
    })
}
/// Mirror of TS `sanitizePath`.
fn sanitize_path(path: &str) -> String {
    static REGEXES: LazyLock<(Regex, Regex, Regex, Regex)> = LazyLock::new(|| {
        (
            Regex::new(r"^https?://[^/]+").expect("valid regex"),
            Regex::new(r"[^a-zA-Z0-9]").expect("valid regex"),
            Regex::new(r"_+").expect("valid regex"),
            Regex::new(r"^_+|_+$").expect("valid regex"),
        )
    });
    let (re_scheme, re_non_alnum, re_underscores, re_trim) = &*REGEXES;
    let s = re_scheme.replace(path, "");
    let s = re_non_alnum.replace_all(&s, "_");
    let s = re_underscores.replace_all(&s, "_");
    re_trim.replace_all(&s, "").into_owned()
}

/// Parse newline-delimited JSON traffic entries; blank lines are ignored.
fn parse_traffic_jsonl(raw: &str) -> Result<Vec<TrafficEntry>> {
    let mut entries = Vec::new();
    for line in raw.split('\n').filter(|l| !l.trim().is_empty()) {
        let entry: TrafficEntry = serde_json::from_str(line).map_err(|e| Error::Json {
            context: format!("failed to parse traffic line: {line}"),
            source: e,
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Serialize the generated spec as YAML.
pub fn spec_to_yaml(spec: &GeneratedSpec) -> String {
    serde_yaml::to_string(&spec.spec).unwrap_or_default()
}

/// Serialize the generated spec as pretty JSON.
pub fn spec_to_json(spec: &GeneratedSpec) -> String {
    serde_json::to_string_pretty(&spec.spec).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_traffic(lines: &[String]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("traffic.jsonl");
        let mut f = fs::File::create(&path).expect("create");
        for line in lines {
            writeln!(f, "{line}").expect("write");
        }
        dir
    }

    #[test]
    fn generates_openapi_31_from_traffic() {
        let dir = write_traffic(&[
            r#"{"path":"/v1/users","method":"GET","status":200,"contentType":"application/json","body":"{\"users\":[],\"total\":0}"}"#.to_string(),
            r#"{"path":"/v1/users","method":"GET","status":200,"contentType":"application/json","body":"{\"users\":[{\"id\":\"a\"}],\"total\":1}"}"#.to_string(),
            r#"{"path":"/v1/users","method":"GET","status":200,"queryParams":["page"]}"#.to_string(),
            r#"{"path":"/v1/users","method":"POST","status":201,"contentType":"application/json","body":"{\"id\":\"x\"}"}"#.to_string(),
            r#"{"path":"/v1/users","method":"POST","status":400,"contentType":"text/plain","body":"bad request"}"#.to_string(),
            r#""#.to_string(),
        ]);

        let spec =
            generate_spec_from_traffic(&dir.path().join("traffic.jsonl"), "Test API", "0.2.0")
                .expect("generate");

        assert_eq!(spec.spec["openapi"], "3.1.0");
        assert_eq!(spec.spec["info"]["title"], "Test API");
        assert_eq!(spec.spec["info"]["version"], "0.2.0");
        assert_eq!(
            spec.spec["info"]["description"],
            "Auto-generated from captured traffic"
        );
        // Relative traffic -> localhost server (TS: new URL(path, 'http://localhost')).
        assert_eq!(spec.spec["servers"][0]["url"], "http://localhost");
        assert_eq!(spec.spec["servers"][0]["description"], "Target server");

        let paths = spec.spec["paths"].as_object().expect("paths object");
        assert_eq!(paths.len(), 1);
        assert!(paths.contains_key("/v1/users"));

        let get_op = &paths["/v1/users"]["get"];
        assert_eq!(get_op["operationId"], "get_v1_users");
        assert_eq!(get_op["summary"], "GET /v1/users");
        let params = get_op["parameters"].as_array().expect("parameters");
        let names: Vec<&str> = params.iter().filter_map(|p| p["name"].as_str()).collect();
        // Query params come ONLY from the `queryParams` field (TS behavior),
        // name part before '='; here just "page".
        assert_eq!(names, vec!["page"]);
        for p in params {
            assert_eq!(p["in"], "query");
            assert_eq!(p["required"], false);
            assert_eq!(p["schema"]["type"], "string");
        }

        // 200 response has an inferred schema behind a $ref.
        let resp200 = &get_op["responses"]["200"];
        assert_eq!(resp200["description"], "Response for GET /v1/users");
        let ct = resp200["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .expect("$ref");
        assert_eq!(ct, "#/components/schemas/get_v1_users_200");
        let schemas = spec.spec["components"]["schemas"]
            .as_object()
            .expect("schemas");
        assert!(schemas.contains_key("get_v1_users_200"));
        // 0/1/5 merge to integer in infer.ts (all-int bodies infer integer).
        assert_eq!(
            schemas["get_v1_users_200"]["properties"]["total"]["type"],
            "integer"
        );
        // 201 response inferred; 400 non-JSON response has description only.
        assert!(schemas.contains_key("post_v1_users_201"));
        let resp400 = &paths["/v1/users"]["post"]["responses"]["400"];
        assert_eq!(resp400["description"], "Response for POST /v1/users");
        assert!(resp400.get("content").is_none());
    }

    #[test]
    fn generated_spec_parses_as_openapi_yaml_and_json() {
        let dir =
            write_traffic(&[r#"{"path":"/v1/ping","method":"GET","status":200}"#.to_string()]);
        let spec = generate_spec_from_traffic(&dir.path().join("traffic.jsonl"), "", "")
            .expect("generate");

        // Relative first entry -> localhost server.
        assert_eq!(spec.spec["servers"][0]["url"], "http://localhost");
        // Empty title/version fall back to TS defaults.
        assert_eq!(spec.spec["info"]["title"], "Generated API Specification");
        assert_eq!(spec.spec["info"]["version"], "1.0.0");

        // JSON round-trip.
        let json_text = spec_to_json(&spec);
        let parsed_json: Value = serde_json::from_str(&json_text).expect("valid JSON");
        assert_eq!(parsed_json["openapi"], "3.1.0");

        // YAML round-trip parses back to the same document.
        let yaml_text = spec_to_yaml(&spec);
        let parsed_yaml: Value = serde_yaml::from_str(&yaml_text).expect("valid YAML");
        assert_eq!(parsed_yaml, parsed_json);
    }

    #[test]
    fn sanitize_path_matches_ts() {
        assert_eq!(
            sanitize_path("https://api.example.com/v1/users/{id}"),
            "v1_users_id"
        );
        assert_eq!(sanitize_path("/v1/users"), "v1_users");
        assert_eq!(sanitize_path("https://x.com/a--b__c"), "a_b_c");
        assert_eq!(sanitize_path("/_leading/"), "leading");
    }

    #[test]
    fn malformed_traffic_line_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.jsonl");
        fs::write(&path, "{not json}\n").expect("write");
        let err = generate_spec_from_traffic(&path, "t", "1").expect_err("should fail");
        assert!(err.to_string().contains("failed to parse traffic line"));
    }

    #[test]
    fn absolute_url_traffic_keeps_verbatim_path_key() {
        // TS fidelity: `paths` is keyed by the RAW entry.path, even when it is
        // an absolute URL; only the server URL extraction parses it.
        let dir = write_traffic(&[r#"{"path":"https://api.example.com/v1/ping","method":"GET","status":200,"contentType":"application/json","body":"{\"ok\":true}"}"#.to_string()]);
        let spec = generate_spec_from_traffic(&dir.path().join("traffic.jsonl"), "T", "1")
            .expect("generate");
        assert_eq!(spec.spec["servers"][0]["url"], "https://api.example.com");
        let paths = spec.spec["paths"].as_object().expect("paths object");
        assert!(paths.contains_key("https://api.example.com/v1/ping"));
        let op = &paths["https://api.example.com/v1/ping"]["get"];
        assert_eq!(op["operationId"], "get_v1_ping");
    }
}
