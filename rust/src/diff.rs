//! Port of `src/diff.ts`: diff captured endpoints against an OpenAPI spec,
//! diff traffic JSONL against a spec, and validate schema coverage.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// HTTP methods considered operations when scanning spec/observed paths.
const HTTP_METHODS: [&str; 7] = ["get", "post", "put", "delete", "patch", "options", "head"];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffSummary {
    pub endpoints_in_spec: usize,
    pub endpoints_captured: usize,
    pub missing_from_spec: usize,
    pub untested_in_spec: usize,
    pub query_param_gaps: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingEndpoint {
    pub path: String,
    pub method: String,
    pub query_params_seen: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathMethodEndpoint {
    pub path: String,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryParamGap {
    pub path: String,
    pub method: String,
    pub missing_query_params: Vec<String>,
}

/// Result of `diffAgainstSpec` / `diffFromTraffic` (shape per diff.ts).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffResult {
    pub summary: DiffSummary,
    pub missing_endpoints: Vec<MissingEndpoint>,
    pub untested_endpoints: Vec<PathMethodEndpoint>,
    pub query_param_gaps: Vec<QueryParamGap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SchemaGapCategory {
    #[serde(rename = "missing-response-schema")]
    MissingResponseSchema,
    #[serde(rename = "missing-request-schema")]
    MissingRequestSchema,
    #[serde(rename = "bare-response-schema")]
    BareResponseSchema,
    #[serde(rename = "missing-param-schema")]
    MissingParamSchema,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaGap {
    pub path: String,
    pub method: String,
    pub operation_id: String,
    pub category: SchemaGapCategory,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaValidationSummary {
    pub total_endpoints: usize,
    pub missing_response_schemas: usize,
    pub missing_request_schemas: usize,
    pub bare_response_schemas: usize,
    pub missing_param_schemas: usize,
    pub total_gaps: usize,
}

/// Result of `validateSchemaCoverage` (shape per diff.ts).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaValidationResult {
    pub summary: SchemaValidationSummary,
    pub gaps: Vec<SchemaGap>,
}

/// Mirror of TS `normalizePath`: collapse GUID segments, long opaque
/// segments (>= 30 chars) and numeric segments into parameter placeholders.
fn normalize_path(path: &str) -> String {
    static REGEXES: LazyLock<(Regex, Regex, Regex)> = LazyLock::new(|| {
        (
            Regex::new(
                r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
            )
            .expect("valid regex"),
            Regex::new(r"/([0-9a-zA-Z_-]{30,})").expect("valid regex"),
            Regex::new(r"/(\d+)").expect("valid regex"),
        )
    });
    let (re_guid, re_key, re_id) = &*REGEXES;
    let s = re_guid.replace_all(path, "/{guid}");
    let s = re_key.replace_all(&s, "/{key}");
    re_id.replace_all(&s, "/{id}").into_owned()
}

/// Load an OpenAPI document from disk; `.yaml`/`.yml` parse as YAML,
/// everything else as JSON (matching the TS extension checks exactly).
fn load_spec_document(spec_path: &Path) -> Result<Value> {
    let raw = fs::read_to_string(spec_path).map_err(|e| {
        Error::io(
            format!("failed to read spec file {}", spec_path.display()),
            e,
        )
    })?;
    let text = spec_path.to_string_lossy();
    if text.ends_with(".yaml") || text.ends_with(".yml") {
        serde_yaml::from_str(&raw).map_err(|e| {
            Error::other(format!(
                "failed to parse YAML spec {}: {e}",
                spec_path.display()
            ))
        })
    } else {
        serde_json::from_str(&raw).map_err(|e| Error::Json {
            context: format!("failed to parse JSON spec {}", spec_path.display()),
            source: e,
        })
    }
}

/// Extract `path|METHOD` keys for every operation in a spec document.
fn extract_spec_paths(spec: &Value) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    if let Some(paths) = spec.get("paths").and_then(Value::as_object) {
        for (path, methods) in paths {
            if methods.is_null() {
                continue;
            }
            let norm = normalize_path(path);
            if let Some(methods_obj) = methods.as_object() {
                for method in methods_obj.keys() {
                    if HTTP_METHODS.contains(&method.as_str()) {
                        set.insert(format!("{norm}|{}", method.to_uppercase()));
                    }
                }
            }
        }
    }
    set
}

/// Extract captured `path|METHOD` keys plus observed query parameter names
/// per key from a generated-spec-shaped document (the output of
/// `OpenApiStore::generate_openapi`, mirroring TS `extractCapturedPaths`).
fn extract_captured_paths(
    store_spec: &Value,
) -> (BTreeSet<String>, HashMap<String, BTreeSet<String>>) {
    let mut captured = BTreeSet::new();
    let mut query_params: HashMap<String, BTreeSet<String>> = HashMap::new();

    if let Some(paths) = store_spec.get("paths").and_then(Value::as_object) {
        for (path, methods) in paths {
            if methods.is_null() {
                continue;
            }
            let norm = normalize_path(path);
            let Some(methods_obj) = methods.as_object() else {
                continue;
            };
            for (method, operation) in methods_obj {
                if !HTTP_METHODS.contains(&method.as_str()) {
                    continue;
                }
                let key = format!("{norm}|{}", method.to_uppercase());
                captured.insert(key.clone());

                let mut seen = BTreeSet::new();
                if let Some(params) = operation.get("parameters").and_then(Value::as_array) {
                    for param in params {
                        if param.get("in").and_then(Value::as_str) == Some("query") {
                            if let Some(name) = param.get("name").and_then(Value::as_str) {
                                seen.insert(name.to_string());
                            }
                        }
                    }
                }
                query_params.insert(key, seen);
            }
        }
    }

    (captured, query_params)
}

/// Shared comparison core of `diffAgainstSpec` / `diffFromTraffic`.
fn build_diff_result(
    existing_spec: &Value,
    spec_paths: &BTreeSet<String>,
    captured: &BTreeSet<String>,
    query_params: &HashMap<String, BTreeSet<String>>,
) -> DiffResult {
    let missing: Vec<(String, String)> = captured
        .iter()
        .filter(|cap| !spec_paths.contains(*cap))
        .map(|key| {
            let mut parts = key.splitn(2, '|');
            (
                parts.next().unwrap_or_default().to_string(),
                parts.next().unwrap_or_default().to_string(),
            )
        })
        .collect();

    let untested: Vec<(String, String)> = spec_paths
        .iter()
        .filter(|spec_key| !captured.contains(*spec_key))
        .map(|key| {
            let mut parts = key.splitn(2, '|');
            (
                parts.next().unwrap_or_default().to_string(),
                parts.next().unwrap_or_default().to_string(),
            )
        })
        .collect();

    let missing_endpoints: Vec<MissingEndpoint> = missing
        .iter()
        .map(|(path, method)| MissingEndpoint {
            path: path.clone(),
            method: method.clone(),
            query_params_seen: query_params
                .get(&format!("{path}|{method}"))
                .map(|seen| seen.iter().cloned().collect())
                .unwrap_or_default(),
        })
        .collect();

    let untested_endpoints: Vec<PathMethodEndpoint> = untested
        .iter()
        .map(|(path, method)| PathMethodEndpoint {
            path: path.clone(),
            method: method.clone(),
        })
        .collect();

    // Query param gaps: for paths present in both, which query params are
    // seen in capture but absent from the spec's path-item parameters?
    // NOTE: faithful to TS — parameters are read from the *path item*, not
    // the individual operation.
    let mut param_gaps: Vec<QueryParamGap> = Vec::new();
    for key in spec_paths {
        if !captured.contains(key) {
            continue;
        }
        let (path, method) = key.split_once('|').unwrap_or((key.as_str(), ""));

        let Some(paths) = existing_spec.get("paths").and_then(Value::as_object) else {
            continue;
        };
        let Some(path_item) = paths
            .iter()
            .find(|(p, _)| normalize_path(p) == path)
            .map(|(_, v)| v)
        else {
            continue;
        };

        let mut spec_params = BTreeSet::new();
        if let Some(params) = path_item.get("parameters").and_then(Value::as_array) {
            for param in params {
                if param.get("in").and_then(Value::as_str) == Some("query") {
                    if let Some(name) = param.get("name").and_then(Value::as_str) {
                        spec_params.insert(name.to_string());
                    }
                }
            }
        }

        let seen = query_params.get(key).cloned().unwrap_or_default();
        let missing_params: Vec<String> = seen
            .into_iter()
            .filter(|p| !spec_params.contains(p))
            .collect();
        if !missing_params.is_empty() {
            param_gaps.push(QueryParamGap {
                path: path.to_string(),
                method: method.to_string(),
                missing_query_params: missing_params,
            });
        }
    }

    let summary = DiffSummary {
        endpoints_in_spec: spec_paths.len(),
        endpoints_captured: captured.len(),
        missing_from_spec: missing_endpoints.len(),
        untested_in_spec: untested_endpoints.len(),
        query_param_gaps: param_gaps.len(),
    };

    let mut result = DiffResult {
        summary,
        missing_endpoints,
        untested_endpoints,
        query_param_gaps: param_gaps,
    };
    result
        .missing_endpoints
        .sort_by_cached_key(sort_endpoint_key);
    result
        .untested_endpoints
        .sort_by_cached_key(sort_endpoint_key);
    result.query_param_gaps.sort_by_cached_key(sort_gap_key);
    result
}

fn sort_endpoint_key<T: HasPathMethod>(e: &T) -> String {
    format!("{}|{}", e.path(), e.method())
}

trait HasPathMethod {
    fn path(&self) -> &str;
    fn method(&self) -> &str;
}

impl HasPathMethod for MissingEndpoint {
    fn path(&self) -> &str {
        &self.path
    }
    fn method(&self) -> &str {
        &self.method
    }
}

impl HasPathMethod for PathMethodEndpoint {
    fn path(&self) -> &str {
        &self.path
    }
    fn method(&self) -> &str {
        &self.method
    }
}

impl HasPathMethod for QueryParamGap {
    fn path(&self) -> &str {
        &self.path
    }
    fn method(&self) -> &str {
        &self.method
    }
}

fn sort_gap_key(g: &QueryParamGap) -> String {
    format!("{}|{}", g.path, g.method)
}

/// Diff the process-wide observed-endpoint store (`OpenApiStore::global`,
/// populated by the running proxy) against an existing spec file — port of
/// `diffAgainstSpec`.
pub fn diff_against_spec(spec_path: &Path) -> Result<DiffResult> {
    let existing_spec = load_spec_document(spec_path)?;
    let spec_paths = extract_spec_paths(&existing_spec);

    let observed = crate::store::global().generate_openapi();
    let (captured, query_params) = extract_captured_paths(&observed);

    Ok(build_diff_result(
        &existing_spec,
        &spec_paths,
        &captured,
        &query_params,
    ))
}

/// Diff a traffic JSONL file against an existing spec file — port of
/// `diffFromTraffic`. Traffic lines are `{ path, method, queryParams? }`;
/// when `queryParams` is absent, query parameter names come from the URL.
pub fn diff_from_traffic(spec_path: &Path, traffic_path: &Path) -> Result<DiffResult> {
    let existing_spec = load_spec_document(spec_path)?;
    let spec_paths = extract_spec_paths(&existing_spec);

    let raw = fs::read_to_string(traffic_path).map_err(|e| {
        Error::io(
            format!("failed to read traffic file {}", traffic_path.display()),
            e,
        )
    })?;

    let base = url::Url::parse("http://localhost").expect("constant base URL parses");
    let mut captured = BTreeSet::new();
    let mut query_params: HashMap<String, BTreeSet<String>> = HashMap::new();

    for line in raw.split('\n').filter(|l| !l.trim().is_empty()) {
        #[derive(serde::Deserialize)]
        struct TrafficLine {
            path: String,
            method: String,
            #[serde(default, rename = "queryParams")]
            query_params: Option<Vec<String>>,
        }
        let entry: TrafficLine = serde_json::from_str(line).map_err(|e| Error::Json {
            context: format!("failed to parse traffic line: {line}"),
            source: e,
        })?;

        let parsed = url::Url::options()
            .base_url(Some(&base))
            .parse(&entry.path)
            .map_err(|e| Error::other(format!("invalid traffic URL {}: {e}", entry.path)))?;
        let norm = normalize_path(parsed.path());
        let method = entry.method.to_uppercase();
        let key = format!("{norm}|{method}");
        captured.insert(key.clone());

        let seen = query_params.entry(key).or_default();
        match &entry.query_params {
            Some(qps) => {
                for qp in qps {
                    seen.insert(qp.clone());
                }
            }
            None => {
                for (name, _) in parsed.query_pairs() {
                    seen.insert(name.into_owned());
                }
            }
        }
    }

    Ok(build_diff_result(
        &existing_spec,
        &spec_paths,
        &captured,
        &query_params,
    ))
}

/// Write a stable JSON diff report file — port of `writeDiffReport`.
pub fn write_diff_report(result: &DiffResult, output_path: &Path) -> Result<()> {
    write_json_report(result, output_path)
}

/// Port of `writeSchemaValidationReport` (used by the validate-schemas CLI).
pub fn write_schema_validation_report(
    result: &SchemaValidationResult,
    output_path: &Path,
) -> Result<()> {
    write_json_report(result, output_path)
}

fn write_json_report<T: Serialize>(value: &T, output_path: &Path) -> Result<()> {
    let text = serde_json::to_string_pretty(value).map_err(|e| Error::Json {
        context: "failed to serialize report".to_string(),
        source: e,
    })?;
    fs::write(output_path, text).map_err(|e| {
        Error::io(
            format!("failed to write report {}", output_path.display()),
            e,
        )
    })
}

fn is_truthy(v: &Value) -> bool {
    !matches!(v, Value::Null | Value::Bool(false))
        && !v.as_str().map(str::is_empty).unwrap_or(false)
        && v.as_i64() != Some(0)
}

fn is_bare_object_schema(schema: &Value) -> bool {
    schema.get("type").and_then(Value::as_str) == Some("object")
        && schema.get("properties").is_none()
        && schema.get("allOf").is_none()
        && schema.get("$ref").is_none()
}

fn gap(
    path: &str,
    method: &str,
    op_id: &str,
    category: SchemaGapCategory,
    detail: String,
) -> SchemaGap {
    SchemaGap {
        path: path.to_string(),
        method: method.to_uppercase(),
        operation_id: op_id.to_string(),
        category,
        detail,
    }
}

/// Validate that every operation in a spec has response/request/parameter
/// schemas per the TS heuristics — port of `validateSchemaCoverage`.
pub fn validate_schema_coverage(spec_path: &Path) -> Result<SchemaValidationResult> {
    let spec = load_spec_document(spec_path)?;

    let mut gaps: Vec<SchemaGap> = Vec::new();
    let mut total_endpoints = 0usize;

    let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
        return Ok(SchemaValidationResult {
            summary: SchemaValidationSummary {
                total_endpoints: 0,
                missing_response_schemas: 0,
                missing_request_schemas: 0,
                bare_response_schemas: 0,
                missing_param_schemas: 0,
                total_gaps: 0,
            },
            gaps,
        });
    };

    for (path, methods) in paths {
        let Some(methods_obj) = methods.as_object() else {
            continue;
        };
        for (method, operation) in methods_obj {
            if !HTTP_METHODS.contains(&method.as_str()) {
                continue;
            }
            total_endpoints += 1;
            let op_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .unwrap_or("unknown");

            // Check response schemas.
            if let Some(responses) = operation.get("responses").and_then(Value::as_object) {
                for (code, response) in responses {
                    if code == "204" || code == "101" {
                        continue;
                    }

                    let has_content = response
                        .get("content")
                        .and_then(Value::as_object)
                        .map(|c| !c.is_empty())
                        .unwrap_or(false);

                    if !has_content {
                        if response.get("$ref").is_none() {
                            gaps.push(gap(
                                path,
                                method,
                                op_id,
                                SchemaGapCategory::MissingResponseSchema,
                                format!("Response {code} has no content schema"),
                            ));
                        }
                        continue;
                    }

                    for (media_type, media) in response
                        .get("content")
                        .and_then(Value::as_object)
                        .into_iter()
                        .flatten()
                    {
                        match media.get("schema") {
                            None => gaps.push(gap(
                                path,
                                method,
                                op_id,
                                SchemaGapCategory::MissingResponseSchema,
                                format!("Response {code} ({media_type}) has empty schema"),
                            )),
                            Some(schema) if is_bare_object_schema(schema) => gaps.push(gap(
                                path,
                                method,
                                op_id,
                                SchemaGapCategory::BareResponseSchema,
                                format!("Response {code} ({media_type}) has bare type:object with no properties"),
                            )),
                            _ => {}
                        }
                    }
                }
            }

            // Check request body schemas.
            if let Some(request_content) = operation
                .get("requestBody")
                .and_then(|rb| rb.get("content"))
                .and_then(Value::as_object)
            {
                for (media_type, media) in request_content {
                    match media.get("schema") {
                        None => gaps.push(gap(
                            path,
                            method,
                            op_id,
                            SchemaGapCategory::MissingRequestSchema,
                            format!("Request body ({media_type}) has no schema"),
                        )),
                        Some(schema) if is_bare_object_schema(schema) => gaps.push(gap(
                            path,
                            method,
                            op_id,
                            SchemaGapCategory::MissingRequestSchema,
                            format!("Request body ({media_type}) has bare type:object with no properties"),
                        )),
                        _ => {}
                    }
                }
            }

            // Check parameter schemas.
            if let Some(parameters) = operation.get("parameters").and_then(Value::as_array) {
                for param in parameters {
                    if param.get("$ref").is_some() {
                        continue; // skip refs
                    }
                    let name = param
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("undefined");
                    match param.get("schema") {
                        None => gaps.push(gap(
                            path,
                            method,
                            op_id,
                            SchemaGapCategory::MissingParamSchema,
                            format!("Parameter \"{name}\" has no schema"),
                        )),
                        Some(p_schema)
                            if p_schema.get("type").map(is_truthy) == Some(false)
                                && p_schema.get("$ref").is_none() =>
                        {
                            gaps.push(gap(
                                path,
                                method,
                                op_id,
                                SchemaGapCategory::MissingParamSchema,
                                format!("Parameter \"{name}\" has empty schema"),
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    gaps.sort_by_cached_key(|g| format!("{}|{}", g.path, g.method));

    let summary = SchemaValidationSummary {
        total_endpoints,
        missing_response_schemas: gaps
            .iter()
            .filter(|g| g.category == SchemaGapCategory::MissingResponseSchema)
            .count(),
        missing_request_schemas: gaps
            .iter()
            .filter(|g| g.category == SchemaGapCategory::MissingRequestSchema)
            .count(),
        bare_response_schemas: gaps
            .iter()
            .filter(|g| g.category == SchemaGapCategory::BareResponseSchema)
            .count(),
        missing_param_schemas: gaps
            .iter()
            .filter(|g| g.category == SchemaGapCategory::MissingParamSchema)
            .count(),
        total_gaps: gaps.len(),
    };

    Ok(SchemaValidationResult { summary, gaps })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;

    fn write_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, contents).expect("write fixture");
        path
    }

    const SPEC_YAML: &str = r#"
openapi: 3.1.0
info:
  title: Test
  version: '1.0'
paths:
  /users/{id}:
    parameters:
      - name: verbose
        in: query
        schema:
          type: boolean
    get:
      operationId: getUser
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
  /users:
    post:
      operationId: createUser
      responses:
        '201':
          description: created
"#;

    #[test]
    fn normalize_path_matches_ts() {
        assert_eq!(
            normalize_path("/users/550e8400-e29b-41d4-a716-446655440000"),
            "/users/{guid}"
        );
        assert_eq!(
            normalize_path("/keys/abc-def_0123456789abcdef0123456789"),
            "/keys/{key}"
        );
        assert_eq!(normalize_path("/users/123"), "/users/{id}");
        assert_eq!(normalize_path("/users/me"), "/users/me");
    }

    #[test]
    fn diff_from_traffic_reports_added_changed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = write_file(&dir, "spec.yaml", SPEC_YAML);
        let traffic = write_file(
            &dir,
            "traffic.jsonl",
            concat!(
                "{\"path\":\"http://localhost/users/123?verbose=1&limit=5\",\"method\":\"get\"}\n",
                "\n",
                "{\"path\":\"/orders\",\"method\":\"POST\"}\n",
                "{\"path\":\"/keys/abc-def_0123456789abcdef0123456789\",\"method\":\"GET\"}\n",
            ),
        );

        let result = diff_from_traffic(&spec, &traffic).expect("diff");

        // /users/123 normalizes onto the spec's /users/{id}; the long opaque
        // segment becomes {key} and /orders is new — both missing from spec.
        assert_eq!(result.summary.endpoints_in_spec, 2);
        assert_eq!(result.summary.endpoints_captured, 3);
        assert_eq!(result.summary.missing_from_spec, 2);
        assert_eq!(result.summary.untested_in_spec, 1);
        assert_eq!(result.summary.query_param_gaps, 1);

        let missing_paths: Vec<&str> = result
            .missing_endpoints
            .iter()
            .map(|m| m.path.as_str())
            .collect();
        assert_eq!(missing_paths, vec!["/keys/{key}", "/orders"]);
        assert_eq!(result.missing_endpoints[0].method, "GET");
        assert_eq!(result.missing_endpoints[0].query_params_seen.len(), 0);
        // Query params parsed from the URL when queryParams absent.
        assert_eq!(
            result.missing_endpoints[1].query_params_seen,
            Vec::<String>::new()
        );

        assert_eq!(
            result.untested_endpoints,
            vec![PathMethodEndpoint {
                path: "/users".to_string(),
                method: "POST".to_string()
            }]
        );

        assert_eq!(result.query_param_gaps.len(), 1);
        assert_eq!(result.query_param_gaps[0].path, "/users/{id}");
        assert_eq!(
            result.query_param_gaps[0].missing_query_params,
            vec!["limit"]
        );
    }

    #[test]
    fn diff_report_is_stable_json_with_camel_case_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = write_file(&dir, "spec.yaml", SPEC_YAML);
        let traffic = write_file(
            &dir,
            "traffic.jsonl",
            "{\"path\":\"/orders?since=x\",\"method\":\"POST\"}\n",
        );

        let result = diff_from_traffic(&spec, &traffic).expect("diff");
        let out = dir.path().join("report.json");
        write_diff_report(&result, &out).expect("write report");

        let text = fs::read_to_string(&out).expect("read report");
        let v: Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(v["summary"]["endpointsInSpec"].is_u64());
        assert!(v["summary"]["endpointsCaptured"].is_u64());
        assert!(v["summary"]["missingFromSpec"].is_u64());
        assert!(v["summary"]["untestedInSpec"].is_u64());
        assert!(v["summary"]["queryParamGaps"].is_u64());
        assert_eq!(
            v["missingEndpoints"][0]["queryParamsSeen"],
            json_like(&["since"])
        );
        // Stable output: rewriting produces byte-identical content.
        write_diff_report(&result, &out).expect("rewrite");
        assert_eq!(fs::read_to_string(&out).expect("reread"), text);
    }

    fn json_like(items: &[&str]) -> Value {
        Value::Array(items.iter().map(|s| Value::from(*s)).collect())
    }

    #[test]
    fn validate_schema_coverage_finds_gaps_per_ts_heuristics() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = write_file(
            &dir,
            "spec.json",
            r##"{
              "openapi": "3.1.0",
              "paths": {
                "/a": {
                  "get": {
                    "operationId": "getA",
                    "responses": {
                      "200": { "description": "no content key" },
                      "204": { "description": "skipped" },
                      "4XX": { "$ref": "#/components/responses/Ref" }
                    }
                  }
                },
                "/b": {
                  "post": {
                    "operationId": "postB",
                    "requestBody": {
                      "content": {
                        "application/json": { "schema": { "type": "object" } },
                        "text/plain": {}
                      }
                    },
                    "parameters": [
                      { "$ref": "#/components/parameters/Skipped" },
                      { "name": "q", "in": "query" },
                      { "name": "e", "in": "query", "schema": { "type": null } }
                    ],
                    "responses": {
                      "200": {
                        "description": "bare",
                        "content": {
                          "application/json": { "schema": { "type": "object", "allOf": [] } },
                          "application/xml": { "schema": { "type": "object" } }
                        }
                      },
                      "404": {
                        "description": "empty media schema",
                        "content": { "application/json": {} }
                      }
                    }
                  }
                }
              }
            }"##,
        );

        let result = validate_schema_coverage(&spec).expect("validate");
        assert_eq!(result.summary.total_endpoints, 2);

        let by_cat = |c: SchemaGapCategory| {
            result
                .gaps
                .iter()
                .filter(|g| g.category == c)
                .map(|g| format!("{}|{}|{}", g.path, g.method, g.detail))
                .collect::<Vec<_>>()
        };

        // Response 200 on /a has no content at all.
        assert_eq!(
            by_cat(SchemaGapCategory::MissingResponseSchema),
            vec![
                "/a|GET|Response 200 has no content schema".to_string(),
                "/b|POST|Response 404 (application/json) has empty schema".to_string(),
            ]
        );
        // The allOf-bearing object schema is NOT bare; the xml one is.
        assert_eq!(
            by_cat(SchemaGapCategory::BareResponseSchema),
            vec![
                "/b|POST|Response 200 (application/xml) has bare type:object with no properties"
                    .to_string()
            ]
        );
        assert_eq!(
            by_cat(SchemaGapCategory::MissingRequestSchema),
            vec![
                "/b|POST|Request body (application/json) has bare type:object with no properties"
                    .to_string(),
                "/b|POST|Request body (text/plain) has no schema".to_string(),
            ]
        );
        assert_eq!(
            by_cat(SchemaGapCategory::MissingParamSchema),
            vec![
                "/b|POST|Parameter \"q\" has no schema".to_string(),
                "/b|POST|Parameter \"e\" has empty schema".to_string(),
            ]
        );

        assert_eq!(result.summary.total_gaps, result.gaps.len());
        assert_eq!(result.summary.missing_response_schemas, 2);
        assert_eq!(result.summary.bare_response_schemas, 1);
        assert_eq!(result.summary.missing_request_schemas, 2);
        assert_eq!(result.summary.missing_param_schemas, 2);

        // Gaps sorted by path|method.
        let keys: Vec<String> = result
            .gaps
            .iter()
            .map(|g| format!("{}|{}", g.path, g.method))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn diff_against_spec_reads_global_store() {
        use crate::store;

        let store = store::global();
        let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        store.record_exchange(
            "GET",
            "/__diff_spec_probe__",
            200,
            &headers,
            None,
            &headers,
            Some(b"{}".as_slice()),
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let spec = write_file(&dir, "spec.json", r#"{"openapi":"3.1.0","paths":{}}"#);
        let result = diff_against_spec(&spec).expect("diff");

        assert!(
            result
                .missing_endpoints
                .iter()
                .any(|m| m.path == "/__diff_spec_probe__" && m.method == "GET"),
            "recorded endpoint should be reported as missing from spec: {:?}",
            result.missing_endpoints
        );
    }

    #[test]
    fn yaml_and_json_specs_are_equivalent_inputs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let yaml_spec = write_file(&dir, "spec.yaml", SPEC_YAML);
        let json_spec = write_file(
            &dir,
            "spec.json",
            r#"{"openapi":"3.1.0","paths":{"/users":{"post":{"responses":{"201":{"description":"created"}}}},"/users/{id}":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#,
        );
        let traffic = write_file(
            &dir,
            "traffic.jsonl",
            "{\"path\":\"/orders\",\"method\":\"POST\"}\n",
        );

        let from_yaml = diff_from_traffic(&yaml_spec, &traffic).expect("yaml diff");
        let from_json = diff_from_traffic(&json_spec, &traffic).expect("json diff");
        assert_eq!(
            from_json.summary.missing_from_spec,
            from_yaml.summary.missing_from_spec
        );
        assert_eq!(
            from_json.summary.untested_in_spec,
            from_yaml.summary.untested_in_spec
        );
        assert_eq!(
            from_json
                .untested_endpoints
                .iter()
                .map(|u| (u.path.as_str(), u.method.as_str()))
                .collect::<Vec<_>>(),
            from_yaml
                .untested_endpoints
                .iter()
                .map(|u| (u.path.as_str(), u.method.as_str()))
                .collect::<Vec<_>>()
        );
    }
}
