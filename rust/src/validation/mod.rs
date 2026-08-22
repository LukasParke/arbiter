//! Contract validation adapters. Validation runs on parsed analysis views of
//! captured exchanges and never changes recorded bytes.
//!
//! Port of `src/validation/index.ts` plus the `SpecValidator` subset it uses
//! from `src/validate.ts`.
//!
//! The TypeScript `Violation` carries `{ type, path, method, message, source,
//! detail }`. The Rust surface (fixed by the shared contract) is
//! `{ path, keyword, message, severity }` where:
//! - `path` mirrors the TS violation path verbatim (spec path once matched,
//!   otherwise the incoming request pathname),
//! - `keyword` is a stable rule identifier (`unknown-path`,
//!   `method-not-defined`, `missing-required-query-parameter`,
//!   `missing-required-header`, `status-not-documented`, `schema-violation`);
//!   for external-command violations it carries the TS `type` field
//!   (`request`/`response`),
//! - `severity` is `"error"` unless an external validator supplies its own.
//!
//! Because [`ContractValidator::validate_response`] receives no request path,
//! [`BasicOpenApiValidator`] remembers the path matched during the paired
//! `validate_request` call (the order [`validate_capture`] uses). A standalone
//! response call before any request behaves like the TS unmatched-path case:
//! no violations.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bundle::load_bundle;
use crate::error::{Error, Result};
use crate::types::{CapturedExchange, HeaderMapValues};

const EXTERNAL_VALIDATOR_TIMEOUT_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Violation {
    pub path: String,
    pub keyword: String,
    pub message: String,
    pub severity: String,
}

impl Violation {
    fn new(path: impl Into<String>, keyword: &str, message: impl Into<String>) -> Self {
        Violation {
            path: path.into(),
            keyword: keyword.to_string(),
            message: message.into(),
            severity: "error".to_string(),
        }
    }
}

/// A contract validator over analysis views of a captured exchange.
///
/// `path` includes the query string; validators derive query parameters from
/// it. Bodies are raw canonical bytes (`None` when no analysis view is
/// available).
pub trait ContractValidator: Send + Sync {
    fn validate_request(
        &self,
        method: &str,
        path: &str,
        headers: &HeaderMapValues,
        body: Option<&[u8]>,
    ) -> Vec<Violation>;

    fn validate_response(
        &self,
        status: u16,
        headers: &HeaderMapValues,
        body: Option<&[u8]>,
    ) -> Vec<Violation>;
}

/// Validation outcome. Serialize with [`crate::json::stable_stringify`] when
/// writing deterministic `--report` files; violations appear in exchange
/// iteration order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub valid: bool,
    pub violations: Vec<Violation>,
}

/// Validate every exchange of a stored bundle against an OpenAPI document.
///
/// The spec is parsed as YAML for `.yaml`/`.yml` sources and JSON otherwise.
/// Any bundle read failure (digest mismatch, containment check, ...) fails
/// closed as an [`Error`].
pub async fn validate_capture(bundle_dir: &Path, spec_source: &Path) -> Result<ValidationReport> {
    let spec = load_spec(spec_source)?;
    let mut bundle = load_bundle(bundle_dir)?;
    let validator = BasicOpenApiValidator::new(spec);
    let mut violations = Vec::new();
    // Cloned so body reads can take `&mut self` while iterating exchanges.
    let exchanges: Vec<CapturedExchange> = bundle.exchanges.clone();
    for exchange in &exchanges {
        let request_body = bundle.read_body(&exchange.request.body)?;
        let response_body = bundle.read_body(&exchange.response.body)?;
        violations.extend(validator.validate_request(
            &exchange.request.method,
            &exchange.request.path,
            &exchange.request.headers.values,
            Some(&request_body),
        ));
        violations.extend(validator.validate_response(
            exchange.response.status,
            &exchange.response.headers.values,
            Some(&response_body),
        ));
    }
    Ok(ValidationReport {
        valid: violations.is_empty(),
        violations,
    })
}

/// Validate every exchange of a stored bundle through an external validator
/// command (port of `CommandValidator`). The command runs under the platform
/// shell and receives one JSON document per invocation on stdin —
/// `{ exchange, direction, bodyBase64 }` — and must print a JSON array of
/// violations on stdout. A non-zero exit or unparsable/non-array output is an
/// error, never a silent skip.
pub async fn validate_capture_with_external(
    bundle_dir: &Path,
    command: &str,
) -> Result<ValidationReport> {
    let mut bundle = load_bundle(bundle_dir)?;
    let exchanges: Vec<CapturedExchange> = bundle.exchanges.clone();
    let mut violations = Vec::new();
    for exchange in &exchanges {
        let request_body = bundle.read_body(&exchange.request.body)?;
        let response_body = bundle.read_body(&exchange.response.body)?;
        violations
            .extend(run_external_validator(command, exchange, "request", &request_body).await?);
        violations
            .extend(run_external_validator(command, exchange, "response", &response_body).await?);
    }
    Ok(ValidationReport {
        valid: violations.is_empty(),
        violations,
    })
}

async fn run_external_validator(
    command: &str,
    exchange: &CapturedExchange,
    direction: &str,
    body: &[u8],
) -> Result<Vec<Violation>> {
    let payload = json!({
        "exchange": exchange,
        "direction": direction,
        "bodyBase64": base64::engine::general_purpose::STANDARD.encode(body),
    });

    let mut child = tokio::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" })
        .args(if cfg!(windows) {
            ["/C", command]
        } else {
            ["-c", command]
        })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| Error::other(format!("Failed to spawn validator command: {e}")))?;

    if let Some(stdin) = child.stdin.as_mut() {
        // A validator that exits before reading stdin causes EPIPE here; the
        // exit-status handling below already reports the failure.
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(payload.to_string().as_bytes()).await;
    }
    // Close stdin so the child sees EOF.
    child.stdin.take();

    let timed_out = tokio::time::timeout(
        Duration::from_millis(EXTERNAL_VALIDATOR_TIMEOUT_MS),
        child.wait_with_output(),
    )
    .await;
    let output = match timed_out {
        // On timeout the future is dropped; `kill_on_drop(true)` takes the
        // child process down with it.
        Err(_) => {
            return Err(Error::other(format!(
                "Validator command timed out after {}ms",
                EXTERNAL_VALIDATOR_TIMEOUT_MS
            )));
        }
        Ok(Err(e)) => return Err(Error::other(format!("Validator command failed: {e}"))),
        Ok(Ok(output)) => output,
    };

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        return Err(Error::other(format!(
            "Validator command exited with code {code}"
        )));
    }

    parse_external_violations(&output.stdout)
}

fn parse_external_violations(stdout: &[u8]) -> Result<Vec<Violation>> {
    let text = String::from_utf8_lossy(stdout).trim().to_string();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|e| Error::other(format!("Validator output is not valid JSON: {e}")))?;
    let Some(items) = parsed.as_array() else {
        return Err(Error::other("Validator output is not a JSON array"));
    };
    Ok(items.iter().filter_map(violation_from_json).collect())
}

/// Map a TS-shaped violation object onto the contract `Violation`. Missing
/// `type` defaults the keyword to `external`; missing `severity` defaults to
/// `error`.
fn violation_from_json(value: &Value) -> Option<Violation> {
    let object = value.as_object()?;
    Some(Violation {
        path: object
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        keyword: object
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("external")
            .to_string(),
        message: object
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        severity: object
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("error")
            .to_string(),
    })
}

fn load_spec(path: &Path) -> Result<Value> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::io(format!("read spec {}", path.display()), e))?;
    let lower = path.to_string_lossy().to_lowercase();
    if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        let yaml: serde_yaml::Value = serde_yaml::from_str(&raw)
            .map_err(|e| Error::other(format!("invalid YAML spec {}: {e}", path.display())))?;
        serde_json::to_value(yaml).map_err(|e| Error::Json {
            context: format!("convert YAML spec {} to JSON", path.display()),
            source: e,
        })
    } else {
        serde_json::from_str(&raw).map_err(|e| Error::Json {
            context: format!("spec {} is not valid JSON", path.display()),
            source: e,
        })
    }
}

/// Lightweight OpenAPI validator over a parsed spec document. Checks known
/// path + method, required parameters (query/header), documented status
/// codes, content-type-driven media selection, and basic response schema
/// conformance (required properties and scalar/array types).
pub struct BasicOpenApiValidator {
    spec: Value,
    templates: Vec<PathTemplate>,
    /// Spec path and method matched by the most recent `validate_request`,
    /// mirroring how `validate_capture` pairs request/response checks.
    last_match: Mutex<Option<(String, String)>>,
}

struct PathTemplate {
    spec_path: String,
    segments: Vec<Segment>,
}

enum Segment {
    Literal(String),
    Param,
}

impl BasicOpenApiValidator {
    pub fn new(spec: Value) -> Self {
        let templates = spec
            .get("paths")
            .and_then(Value::as_object)
            .map(|paths| {
                paths
                    .keys()
                    .map(|p| PathTemplate {
                        spec_path: p.clone(),
                        segments: compile_path_template(p),
                    })
                    .collect()
            })
            .unwrap_or_default();
        BasicOpenApiValidator {
            spec,
            templates,
            last_match: Mutex::new(None),
        }
    }

    /// First spec path whose template matches `incoming_path`, or `None`.
    fn match_path(&self, incoming_path: &str) -> Option<&str> {
        self.templates
            .iter()
            .find(|t| template_matches(&t.segments, incoming_path))
            .map(|t| t.spec_path.as_str())
    }

    fn operation_at(&self, spec_path: &str, method: &str) -> Option<&Value> {
        self.spec
            .get("paths")?
            .get(spec_path)?
            .get(method.to_lowercase().as_str())
    }

    fn resolve_ref<'a>(&'a self, reference: &str) -> Option<&'a Value> {
        self.spec
            .get("components")?
            .get("schemas")?
            .get(reference.rsplit('/').next()?)
    }

    fn validate_request_inner(
        &self,
        method: &str,
        pathname: &str,
        query: &BTreeMap<String, String>,
        headers: &BTreeMap<String, String>,
    ) -> (Option<(String, String)>, Vec<Violation>) {
        let upper = method.to_uppercase();
        let Some(spec_path) = self.match_path(pathname) else {
            return (
                None,
                vec![Violation::new(
                    pathname,
                    "unknown-path",
                    "Path not found in spec",
                )],
            );
        };
        let Some(operation) = self.operation_at(spec_path, method) else {
            return (
                Some((spec_path.to_string(), method.to_string())),
                vec![Violation::new(
                    spec_path,
                    "method-not-defined",
                    format!("Method {upper} not defined for path"),
                )],
            );
        };

        let mut violations = Vec::new();
        for param in operation
            .get("parameters")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            if !param
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let Some(name) = param.get("name").and_then(Value::as_str) else {
                continue;
            };
            match param.get("in").and_then(Value::as_str) {
                Some("query") if !query.contains_key(name) => {
                    violations.push(Violation::new(
                        spec_path,
                        "missing-required-query-parameter",
                        format!("Missing required query parameter: {name}"),
                    ));
                }
                Some("header") if !headers.contains_key(&name.to_lowercase()) => {
                    violations.push(Violation::new(
                        spec_path,
                        "missing-required-header",
                        format!("Missing required header: {name}"),
                    ));
                }
                _ => {}
            }
        }
        (
            Some((spec_path.to_string(), method.to_string())),
            violations,
        )
    }

    fn validate_response_inner(
        &self,
        spec_path: &str,
        method: &str,
        status: u16,
        content_type: &str,
        body: Option<&Value>,
    ) -> Vec<Violation> {
        let Some(operation) = self.operation_at(spec_path, method) else {
            return Vec::new();
        };
        let status_str = status.to_string();
        let Some(response) = operation
            .get("responses")
            .and_then(|r| r.get(status_str.as_str()))
        else {
            return vec![Violation::new(
                spec_path,
                "status-not-documented",
                format!("Status code {status} not documented in spec"),
            )];
        };

        let mut violations = Vec::new();
        // For JSON responses, do basic schema validation.
        if content_type.contains("json") && !matches!(body, None | Some(Value::Null)) {
            let media = response
                .get("content")
                .and_then(|c| c.get(content_type).or_else(|| c.get("application/json")));
            if let Some(schema) = media.and_then(|m| m.get("schema")) {
                let body = body.expect("checked non-null above");
                for detail in self.validate_value_against_schema(body, schema, "") {
                    violations.push(Violation::new(
                        spec_path,
                        "schema-violation",
                        format!("Schema violation: {detail}"),
                    ));
                }
            }
        }
        violations
    }

    /// Port of `SpecValidator.validateValueAgainstSchema`. Returns
    /// human-readable details; the caller wraps them into
    /// `Schema violation: ...` messages.
    fn validate_value_against_schema(
        &self,
        value: &Value,
        schema: &Value,
        path: &str,
    ) -> Vec<String> {
        let mut violations = Vec::new();

        if let Some(reference) = schema
            .get("$ref")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty())
        {
            if let Some(resolved) = self.resolve_ref(reference) {
                return self.validate_value_against_schema(value, resolved, path);
            }
            return violations;
        }

        match schema.get("type").and_then(Value::as_str) {
            Some("object") if value.is_object() => {
                for req in schema
                    .get("required")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                {
                    let Some(req) = req.as_str() else { continue };
                    // Presence check (`!(req in value)`); explicit nulls count
                    // as present.
                    if value.get(req).is_none() {
                        violations.push(format!(
                            "{}: missing required property \"{}\"",
                            if path.is_empty() { "root" } else { path },
                            req
                        ));
                    }
                }
                for (prop_name, prop_schema) in schema
                    .get("properties")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                {
                    if let Some(prop_value) = value.get(prop_name) {
                        let child = if path.is_empty() {
                            prop_name.to_string()
                        } else {
                            format!("{path}.{prop_name}")
                        };
                        violations.extend(self.validate_value_against_schema(
                            prop_value,
                            prop_schema,
                            &child,
                        ));
                    }
                }
            }
            Some("array") if value.is_array() => {
                if let Some(items) = schema.get("items") {
                    for (i, item) in value.as_array().expect("checked array").iter().enumerate() {
                        violations.extend(self.validate_value_against_schema(
                            item,
                            items,
                            &format!("{path}[{i}]"),
                        ));
                    }
                }
            }
            Some("string") if !value.is_string() => violations.push(format!(
                "{}: expected string, got {}",
                if path.is_empty() { "root" } else { path },
                js_typeof(value)
            )),
            Some(stype @ ("integer" | "number")) if !value.is_number() => violations.push(format!(
                "{}: expected {stype}, got {}",
                if path.is_empty() { "root" } else { path },
                js_typeof(value)
            )),
            Some("boolean") if !value.is_boolean() => violations.push(format!(
                "{}: expected boolean, got {}",
                if path.is_empty() { "root" } else { path },
                js_typeof(value)
            )),
            _ => {}
        }

        violations
    }
}

fn js_typeof(value: &Value) -> &'static str {
    match value {
        Value::Null => "object", // typeof null === "object"
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) | Value::Object(_) => "object",
    }
}

fn first_values(values: &HeaderMapValues) -> BTreeMap<String, String> {
    values
        .iter()
        .filter_map(|(name, vs)| vs.first().map(|v| (name.clone(), v.clone())))
        .collect()
}

/// Port of `queryRecord`: last value wins on duplicate names.
fn query_record(path_with_query: &str) -> BTreeMap<String, String> {
    let Some((_, query)) = path_with_query.split_once('?') else {
        return BTreeMap::new();
    };
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn compile_path_template(spec_path: &str) -> Vec<Segment> {
    spec_path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if segment.len() >= 2 && segment.starts_with('{') && segment.ends_with('}') {
                Segment::Param
            } else {
                Segment::Literal(segment.to_string())
            }
        })
        .collect()
}

/// Equivalent of the TS regex `^\/lit\/(?<...>[^/]+)$`: literal segments must
/// match exactly; `{param}` matches one or more characters without `/`.
fn template_matches(segments: &[Segment], incoming: &str) -> bool {
    let incoming: Vec<&str> = incoming.split('/').filter(|s| !s.is_empty()).collect();
    incoming.len() == segments.len()
        && incoming.iter().zip(segments).all(|(chunk, seg)| match seg {
            Segment::Literal(lit) => chunk == lit,
            Segment::Param => !chunk.is_empty(),
        })
}

impl ContractValidator for BasicOpenApiValidator {
    fn validate_request(
        &self,
        method: &str,
        path: &str,
        headers: &HeaderMapValues,
        _body: Option<&[u8]>,
    ) -> Vec<Violation> {
        let pathname = path.split('?').next().unwrap_or(path);
        let query = query_record(path);
        let first_header_values = first_values(headers);
        let (matched, violations) =
            self.validate_request_inner(method, pathname, &query, &first_header_values);
        *self
            .last_match
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = matched;
        violations
    }

    fn validate_response(
        &self,
        status: u16,
        headers: &HeaderMapValues,
        body: Option<&[u8]>,
    ) -> Vec<Violation> {
        let header_values = first_values(headers);
        let content_type = header_values
            .get("content-type")
            .map(String::as_str)
            .unwrap_or_default();
        // Compressed canonical bytes: analysis view unavailable here.
        let parsed = if header_values.contains_key("content-encoding") {
            None
        } else {
            parse_analysis_json(content_type, body)
        };
        let last = self
            .last_match
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match last.as_ref() {
            Some((spec_path, method)) => self.validate_response_inner(
                spec_path,
                method,
                status,
                content_type,
                parsed.as_ref(),
            ),
            // Unmatched/unattempted request: same as the TS unmatched-path
            // early return.
            None => Vec::new(),
        }
    }
}

/// Port of `parseAnalysisJson`: only uncompressed JSON bodies yield an
/// analysis view; anything else parses to `undefined`.
fn parse_analysis_json(content_type: &str, body: Option<&[u8]>) -> Option<Value> {
    let bytes = body?;
    if !content_type.contains("json") {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}

/// Runtime callback adapter, e.g. for curated Zod schemas covering providers
/// without official OpenAPI documents. The callback transforms the violations
/// collected for each direction (starting from an empty set).
pub struct CallbackValidator<F: Fn(&[Violation]) -> Vec<Violation> + Send + Sync>(pub F);

impl<F: Fn(&[Violation]) -> Vec<Violation> + Send + Sync> ContractValidator
    for CallbackValidator<F>
{
    fn validate_request(
        &self,
        _method: &str,
        _path: &str,
        _headers: &HeaderMapValues,
        _body: Option<&[u8]>,
    ) -> Vec<Violation> {
        (self.0)(&[])
    }

    fn validate_response(
        &self,
        _status: u16,
        _headers: &HeaderMapValues,
        _body: Option<&[u8]>,
    ) -> Vec<Violation> {
        (self.0)(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{make_captured_body, write_bundle, WriteBundleOptions};
    use crate::types::{
        CapturedBody, CapturedHeaders, CapturedRequest, CapturedResponse, StreamState,
        EXCHANGE_SCHEMA_VERSION,
    };
    use std::collections::HashMap;

    const SPEC_YAML: &str = "
openapi: 3.1.0
info: { title: Test, version: \"1.0\" }
paths:
  /v1/messages:
    post:
      responses:
        \"200\":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id]
                properties:
                  id: { type: string }
";

    fn captured_body(bytes: &[u8]) -> CapturedBody {
        make_captured_body(bytes, Some("application/json"), None, None)
            .expect("inline captured body")
    }

    fn make_exchange(response_json: &str) -> CapturedExchange {
        let mut headers = HeaderMapValues::new();
        headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        let captured_headers = CapturedHeaders {
            values: headers,
            redacted: Vec::new(),
        };
        CapturedExchange {
            schema_version: EXCHANGE_SCHEMA_VERSION,
            sequence: 0,
            started_at: "2025-01-01T00:00:00.000Z".to_string(),
            duration_ms: 5.0,
            request: CapturedRequest {
                method: "POST".to_string(),
                path: "/v1/messages".to_string(),
                http_version: "1.1".to_string(),
                headers: captured_headers.clone(),
                body: captured_body(b"{\"model\":\"m\"}"),
            },
            response: CapturedResponse {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "1.1".to_string(),
                headers: captured_headers,
                body: captured_body(response_json.as_bytes()),
                stream: StreamState {
                    kind: "buffered".to_string(),
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

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join("spec.yaml"), SPEC_YAML.trim_start())
                .expect("write spec");
            let manifest = crate::types::CaptureManifest {
                schema_version: 1,
                arbiter_version: "1.1.0".to_string(),
                mode: crate::types::CaptureMode::Exact,
                target_origin: "https://api.example.com".to_string(),
                started_at: "2025-01-01T00:00:00.000Z".to_string(),
                completed_at: "2025-01-01T00:01:00.000Z".to_string(),
                exchange_count: 1,
                bundle_digest: String::new(),
                redaction: crate::types::RedactionPolicySummary {
                    redact_headers: Vec::new(),
                    allow_query: Vec::new(),
                },
                metadata: None,
            };
            write_bundle(
                &dir.path().join("capture"),
                WriteBundleOptions {
                    manifest,
                    exchanges: vec![make_exchange("{\"missing_id\":true}")],
                    bodies: HashMap::new(),
                    validation: None,
                },
            )
            .expect("write bundle");
            Fixture { dir }
        }

        fn spec_path(&self) -> PathBuf {
            self.dir.path().join("spec.yaml")
        }

        fn bundle_dir(&self) -> PathBuf {
            self.dir.path().join("capture")
        }
    }

    use std::path::PathBuf;

    #[tokio::test]
    async fn reports_schema_violations_from_bundle_exchanges() {
        let fixture = Fixture::new();
        let report = validate_capture(&fixture.bundle_dir(), &fixture.spec_path())
            .await
            .expect("validate capture");
        assert!(!report.valid);
        assert!(
            report.violations.iter().any(|v| v.message.contains("id")),
            "expected an id-related violation, got {:?}",
            report.violations
        );
        let violation = &report.violations[0];
        assert_eq!(violation.severity, "error");
        // The schema violation is a response-direction finding on the spec
        // path.
        assert_eq!(violation.keyword, "schema-violation");
        assert_eq!(
            violation.message,
            "Schema violation: root: missing required property \"id\""
        );
        assert_eq!(violation.path, "/v1/messages");
    }

    #[tokio::test]
    async fn accepts_conforming_bundles() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("spec.yaml"), SPEC_YAML.trim_start()).expect("write spec");
        let manifest = crate::types::CaptureManifest {
            schema_version: 1,
            arbiter_version: "1.1.0".to_string(),
            mode: crate::types::CaptureMode::Exact,
            target_origin: "https://api.example.com".to_string(),
            started_at: "2025-01-01T00:00:00.000Z".to_string(),
            completed_at: "2025-01-01T00:01:00.000Z".to_string(),
            exchange_count: 1,
            bundle_digest: String::new(),
            redaction: crate::types::RedactionPolicySummary {
                redact_headers: Vec::new(),
                allow_query: Vec::new(),
            },
            metadata: None,
        };
        write_bundle(
            &dir.path().join("capture"),
            WriteBundleOptions {
                manifest,
                exchanges: vec![make_exchange("{\"id\":\"ok\"}")],
                bodies: HashMap::new(),
                validation: None,
            },
        )
        .expect("write bundle");
        let report = validate_capture(&dir.path().join("capture"), &dir.path().join("spec.yaml"))
            .await
            .expect("validate capture");
        assert!(report.valid, "{:?}", report.violations);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn flags_unknown_path_and_method() {
        let validator = BasicOpenApiValidator::new(
            serde_yaml::from_str::<serde_yaml::Value>(SPEC_YAML.trim_start())
                .map_err(|e| panic!("{e}"))
                .and_then(serde_json::to_value)
                .unwrap_or_else(|e| panic!("{e}")),
        );
        let headers = HeaderMapValues::new();

        let violations = validator.validate_request("POST", "/nope", &headers, None);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].keyword, "unknown-path");
        assert_eq!(violations[0].message, "Path not found in spec");
        assert_eq!(violations[0].path, "/nope");

        let violations = validator.validate_request("GET", "/v1/messages", &headers, None);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].keyword, "method-not-defined");
        assert_eq!(violations[0].message, "Method GET not defined for path");
        assert_eq!(violations[0].path, "/v1/messages");
    }

    #[test]
    fn path_templates_match_parameters_like_ts_regex() {
        let validator = BasicOpenApiValidator::new(serde_json::json!({
            "paths": {
                "/v1/items/{id}": {
                    "get": { "responses": { "200": { "description": "ok" } } }
                }
            }
        }));
        let headers = HeaderMapValues::new();
        // `{id}` behaves like the TS `[^/]+` fragment.
        assert!(validator
            .validate_request("GET", "/v1/items/abc_123", &headers, None)
            .is_empty());
        // Empty or multi-segment parameters do not match.
        let violations = validator.validate_request("GET", "/v1/items/", &headers, None);
        assert_eq!(violations[0].keyword, "unknown-path");
        let violations = validator.validate_request("GET", "/v1/items/a/b", &headers, None);
        assert_eq!(violations[0].keyword, "unknown-path");
    }

    #[test]
    fn flags_missing_required_parameters() {
        let spec = serde_json::json!({
            "paths": {
                "/v1/things": {
                    "get": {
                        "parameters": [
                            { "name": "limit", "in": "query", "required": true, "schema": { "type": "integer" } },
                            { "name": "x-trace", "in": "header", "required": true },
                            { "name": "optional", "in": "query", "required": false }
                        ],
                        "responses": {}
                    }
                }
            }
        });
        let validator = BasicOpenApiValidator::new(spec);
        let headers = HeaderMapValues::new();

        let violations = validator.validate_request("GET", "/v1/things?other=1", &headers, None);
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(violations
            .iter()
            .any(|v| v.message == "Missing required query parameter: limit"));
        assert!(violations
            .iter()
            .any(|v| v.message == "Missing required header: x-trace"));

        let mut with_headers = HeaderMapValues::new();
        with_headers.insert("x-trace".to_string(), vec!["abc".to_string()]);
        let violations =
            validator.validate_request("GET", "/v1/things?limit=5", &with_headers, None);
        assert!(violations.is_empty());
    }

    #[test]
    fn flags_undocumented_status_codes() {
        let fixture_validator_spec = serde_json::json!({
            "paths": {
                "/v1/messages": {
                    "post": { "responses": { "200": { "description": "ok" } } }
                }
            }
        });
        let validator = BasicOpenApiValidator::new(fixture_validator_spec);

        // Unmatched request first: response validation is a no-op (TS early
        // return).
        let headers = HeaderMapValues::new();
        assert!(validator.validate_response(404, &headers, None).is_empty());

        validator.validate_request("POST", "/v1/messages", &headers, None);
        let violations = validator.validate_response(404, &headers, None);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].keyword, "status-not-documented");
        assert_eq!(
            violations[0].message,
            "Status code 404 not documented in spec"
        );
        assert_eq!(violations[0].path, "/v1/messages");
    }

    #[test]
    fn checks_top_level_types_and_nested_paths() {
        let validator = BasicOpenApiValidator::new(serde_json::json!({
            "paths": {
                "/a": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "required": ["id", "count", "flag"],
                                            "properties": {
                                                "id": { "type": "string" },
                                                "count": { "type": "integer" },
                                                "flag": { "type": "boolean" },
                                                "tags": {
                                                    "type": "array",
                                                    "items": { "type": "string" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }));
        let mut headers = HeaderMapValues::new();
        headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );

        validator.validate_request("GET", "/a", &headers, None);
        let body = br#"{"id":5,"count":"3","flag":"yes","tags":["ok",7]}"#;
        let violations = validator.validate_response(200, &headers, Some(body));
        let messages: Vec<&str> = violations.iter().map(|v| v.message.as_str()).collect();
        assert!(
            messages.contains(&"Schema violation: id: expected string, got number"),
            "{messages:?}"
        );
        assert!(
            messages.contains(&"Schema violation: count: expected integer, got string"),
            "{messages:?}"
        );
        assert!(
            messages.contains(&"Schema violation: flag: expected boolean, got string"),
            "{messages:?}"
        );
        assert!(
            messages.contains(&"Schema violation: tags[1]: expected string, got number"),
            "{messages:?}"
        );
        for violation in &violations {
            assert_eq!(violation.keyword, "schema-violation");
        }

        // Non-JSON content types skip schema validation entirely.
        let mut text_headers = HeaderMapValues::new();
        text_headers.insert("content-type".to_string(), vec!["text/plain".to_string()]);
        assert!(validator
            .validate_response(200, &text_headers, Some(body))
            .is_empty());

        // Explicit null body behaves like the TS undefined check.
        let violations = validator.validate_response(200, &headers, Some(b"null"));
        assert!(violations.is_empty());
    }

    #[test]
    fn resolves_local_refs() {
        let validator = BasicOpenApiValidator::new(serde_json::json!({
            "components": {
                "schemas": {
                    "Message": {
                        "type": "object",
                        "required": ["id"],
                        "properties": { "id": { "type": "string" } }
                    }
                }
            },
            "paths": {
                "/m": {
                    "post": {
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": { "$ref": "#/components/schemas/Message" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }));
        let mut headers = HeaderMapValues::new();
        headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        validator.validate_request("POST", "/m", &headers, None);
        let violations = validator.validate_response(200, &headers, Some(br#"{}"#));
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].message,
            "Schema violation: root: missing required property \"id\""
        );
    }

    #[tokio::test]
    async fn callback_validator_runs_through_validate_capture() {
        let fixture = Fixture::new();
        let validator = CallbackValidator(|_: &[Violation]| {
            vec![Violation {
                path: "/v1/messages".to_string(),
                keyword: "response".to_string(),
                message: "missing id".to_string(),
                severity: "error".to_string(),
            }]
        });
        let mut bundle = load_bundle(&fixture.bundle_dir()).expect("load bundle");
        let mut violations = Vec::new();
        for exchange in bundle.exchanges.clone() {
            let request_body = bundle.read_body(&exchange.request.body).unwrap();
            let response_body = bundle.read_body(&exchange.response.body).unwrap();
            violations.extend(validator.validate_request(
                &exchange.request.method,
                &exchange.request.path,
                &exchange.request.headers.values,
                Some(&request_body),
            ));
            violations.extend(validator.validate_response(
                exchange.response.status,
                &exchange.response.headers.values,
                Some(&response_body),
            ));
        }
        let report = ValidationReport {
            valid: violations.is_empty(),
            violations,
        };
        assert!(!report.valid);
        assert_eq!(report.violations.len(), 2); // one per direction
        assert_eq!(report.violations[0].message, "missing id");
    }

    #[tokio::test]
    async fn external_validator_receives_exchange_json_and_parses_violations() {
        let fixture = Fixture::new();
        // Emits one violation regardless of input; proves stdin piping works.
        let command = "cat >/dev/null; printf '[{\"type\":\"response\",\"path\":\"/v1/messages\",\"message\":\"external says no\",\"source\":\"ext\"}]'";
        let report = validate_capture_with_external(&fixture.bundle_dir(), command)
            .await
            .expect("external validation");
        assert!(!report.valid);
        assert_eq!(report.violations.len(), 2); // request + response direction
        assert!(report
            .violations
            .iter()
            .all(|v| v.message == "external says no"));
        assert_eq!(report.violations[0].keyword, "response");
        assert_eq!(report.violations[0].severity, "error");
    }

    #[tokio::test]
    async fn external_validator_nonzero_exit_is_an_error_never_a_skip() {
        let fixture = Fixture::new();
        let err = validate_capture_with_external(&fixture.bundle_dir(), "exit 2")
            .await
            .expect_err("must fail closed");
        assert!(err.to_string().contains("code 2"), "{err}");
    }

    #[tokio::test]
    async fn external_validator_non_array_output_is_an_error() {
        let fixture = Fixture::new();
        let err = validate_capture_with_external(&fixture.bundle_dir(), "echo '{}'")
            .await
            .expect_err("must reject non-array output");
        assert!(err.to_string().contains("not a JSON array"), "{err}");
    }
}
