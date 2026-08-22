//! Port of `src/store/openApiStore.ts` — thread-safe store of observed
//! endpoints that generates an OpenAPI 3.1 document from proxy traffic.

use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::types::HeaderMapValues;

const DEFAULT_TARGET_URL: &str = "http://localhost:3000";
const HAR_PLACEHOLDER: &str = "[Content stored but not processed for performance]";

/// A security scheme observed on a request, mirroring TS `SecurityInfo`.
/// Serialized shape matches OpenAPI `SecuritySchemeObject` inputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityInfo {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "in", default, skip_serializing_if = "Option::is_none")]
    pub in_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flows: Option<Value>,
    #[serde(
        rename = "openIdConnectUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub open_id_connect_url: Option<String>,
}

/// Per-endpoint accumulated OpenAPI data (TS `EndpointInfo`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EndpointInfo {
    pub path: String,
    pub method: String,
    pub responses: BTreeMap<String, Value>,
    #[serde(default)]
    pub parameters: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<Vec<Value>>,
}

#[derive(Debug, Default)]
struct Inner {
    endpoints: BTreeMap<String, EndpointInfo>,
    har_entries: Vec<Value>,
    target_url: String,
    schema_cache: HashMap<String, Vec<Value>>,
    security_schemes: BTreeMap<String, Value>,
}

/// Thread-safe store of observed endpoints producing an OpenAPI 3.1 document.
pub struct OpenApiStore {
    inner: Mutex<Inner>,
}

impl Default for OpenApiStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenApiStore {
    pub fn new() -> Self {
        OpenApiStore {
            inner: Mutex::new(Inner {
                target_url: DEFAULT_TARGET_URL.to_string(),
                ..Inner::default()
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A poisoned lock still holds valid accumulated data; recover it.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn set_target_url(&self, url: &str) {
        self.lock().target_url = url.to_string();
    }

    pub fn target_url(&self) -> String {
        self.lock().target_url.clone()
    }

    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.endpoints.clear();
        inner.har_entries.clear();
        inner.schema_cache.clear();
        inner.security_schemes.clear();
    }

    pub fn get_endpoint(&self, path: &str, method: &str) -> Option<EndpointInfo> {
        let key = format!("{} {}", method.to_lowercase(), path);
        self.lock().endpoints.get(&key).cloned()
    }

    pub fn import_endpoint(&self, path: &str, method: &str, data: EndpointInfo) {
        let key = format!("{} {}", method.to_lowercase(), path);
        self.lock().endpoints.insert(key, data);
    }

    /// Record one observed exchange from raw HTTP parts. Query parameters are
    /// parsed from `path` when it carries a query string. Security schemes are
    /// detected from request headers (`x-api-key`/any `*api-key*` header,
    /// `Authorization: Bearer …`/`Basic …`).
    #[allow(clippy::too_many_arguments)]
    pub fn record_exchange(
        &self,
        method: &str,
        path: &str,
        status: u16,
        req_headers: &HeaderMapValues,
        req_body: Option<&[u8]>,
        resp_headers: &HeaderMapValues,
        resp_body: Option<&[u8]>,
    ) {
        let detected = detect_security(req_headers);
        self.record_with_security(
            method,
            path,
            status,
            req_headers,
            req_body,
            resp_headers,
            resp_body,
            &detected,
        );
    }

    /// Like [`OpenApiStore::record_exchange`] but with explicitly provided
    /// security entries (JSON objects shaped like TS `SecurityInfo`).
    #[allow(clippy::too_many_arguments)]
    pub fn record_exchange_with_security(
        &self,
        method: &str,
        path: &str,
        status: u16,
        req_headers: &HeaderMapValues,
        req_body: Option<&[u8]>,
        resp_headers: &HeaderMapValues,
        resp_body: Option<&[u8]>,
        security: &[Value],
    ) {
        self.record_with_security(
            method,
            path,
            status,
            req_headers,
            req_body,
            resp_headers,
            resp_body,
            security,
        );
    }

    /// Keep the TS harStore compatibility path used by middleware: append a
    /// prebuilt HAR entry verbatim.
    pub fn record_har_entry(&self, entry: &Value) {
        self.lock().har_entries.push(entry.clone());
    }

    /// Merge persisted endpoint data back into the store. Accepts either the
    /// storage row shape `{ request: {...}, response: {...} }` (replayed
    /// through the full record path, like TS hydration) or a serialized
    /// [`EndpointInfo`] (imported verbatim).
    pub fn merge_endpoint_data(&self, path: &str, method: &str, data: &Value) {
        if data.get("request").is_some() && data.get("response").is_some() {
            let req = &data["request"];
            let resp = &data["response"];

            let mut headers: HeaderMapValues = BTreeMap::new();
            if let Some(obj) = req.get("headers").and_then(Value::as_object) {
                for (name, value) in obj {
                    let val = match value {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    headers.entry(name.to_lowercase()).or_default().push(val);
                }
            }

            let mut query = String::new();
            if let Some(q) = req.get("query").and_then(Value::as_object) {
                if !q.is_empty() {
                    let pairs: Vec<String> = q
                        .iter()
                        .map(|(k, v)| {
                            let v = match v {
                                Value::String(s) => s.clone(),
                                other => other.to_string(),
                            };
                            format!(
                                "{}={}",
                                encode_query_component(k),
                                encode_query_component(&v)
                            )
                        })
                        .collect();
                    query = format!("?{}", pairs.join("&"));
                }
            }

            let status = resp
                .get("status")
                .and_then(Value::as_u64)
                .map(|s| s as u16)
                .unwrap_or(200);
            let resp_headers: HeaderMapValues = resp
                .get("headers")
                .and_then(Value::as_object)
                .map(|obj| {
                    obj.iter()
                        .map(|(name, value)| {
                            let val = match value {
                                Value::String(s) => s.clone(),
                                other => other.to_string(),
                            };
                            (name.to_lowercase(), vec![val])
                        })
                        .collect()
                })
                .unwrap_or_default();

            let req_body_bytes: Option<Vec<u8>> = req.get("body").and_then(|b| match b {
                Value::Null => None,
                Value::String(s) => Some(s.clone().into_bytes()),
                other => serde_json::to_vec(other).ok(),
            });
            let security: Vec<Value> = req
                .get("security")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            let full_path = format!("{path}{query}");
            self.record_with_security(
                method,
                &full_path,
                status,
                &headers,
                req_body_bytes.as_deref(),
                &resp_headers,
                None,
                &security,
            );
            return;
        }

        // Serialized EndpointInfo import.
        if let Ok(info) = serde_json::from_value::<EndpointInfo>(data.clone()) {
            let key = format!("{}:{}", method.to_lowercase(), info.path);
            self.lock().endpoints.insert(key, info);
        }
    }

    /// All accumulated endpoints as `(path, method, data)` rows, matching the
    /// storage `getAllEndpoints` row shape.
    pub fn all_endpoints(&self) -> Vec<(String, String, Value)> {
        self.lock()
            .endpoints
            .values()
            .map(|info| {
                (
                    info.path.clone(),
                    info.method.clone(),
                    serde_json::to_value(info).unwrap_or(Value::Null),
                )
            })
            .collect()
    }

    /// Generate the OpenAPI 3.1 document from everything observed so far.
    pub fn generate_openapi(&self) -> Value {
        let inner = self.lock();
        let mut paths: BTreeMap<String, Value> = BTreeMap::new();

        for (key, info) in &inner.endpoints {
            let (method, path) = split_key(key);
            let method_lower = method.to_lowercase();

            let mut operation = json!({
                "summary": format!("{} {}", method.to_uppercase(), path),
                "responses": info.responses,
            });

            if !info.parameters.is_empty() {
                // Dedupe by (name, in) and format like TS getOpenAPISpec.
                let mut unique_params: Vec<Value> = Vec::new();
                for param in &info.parameters {
                    let name = param.get("name").and_then(Value::as_str).unwrap_or("");
                    let location = param.get("in").and_then(Value::as_str).unwrap_or("");
                    if unique_params.iter().any(|p| {
                        p.get("name").and_then(Value::as_str) == Some(name)
                            && p.get("in").and_then(Value::as_str) == Some(location)
                    }) {
                        continue;
                    }
                    let mut formatted = json!({
                        "name": name,
                        "in": location,
                        "schema": { "type": "string" },
                    });
                    if location == "path" {
                        formatted["required"] = json!(true);
                    }
                    if location == "header" {
                        if let Some(example) = param.pointer("/schema/example") {
                            formatted["schema"]["example"] = example.clone();
                        }
                    }
                    unique_params.push(formatted);
                }
                operation["parameters"] = Value::Array(unique_params);
            }

            if let Some(request_body) = &info.request_body {
                operation["requestBody"] = request_body.clone();
            }

            if let Some(security) = &info.security {
                operation["security"] = json!(security);
            }

            let path_item = paths.entry(path.to_string()).or_insert_with(|| json!({}));
            path_item[&method_lower] = operation;
        }

        json!({
            "openapi": "3.1.0",
            "info": {
                "title": "API Documentation",
                "version": "1.0.0",
                "description": "Automatically generated API documentation from proxy traffic",
            },
            "servers": [ { "url": inner.target_url } ],
            "paths": paths,
            "components": {
                "securitySchemes": inner.security_schemes,
                "schemas": {},
            },
        })
    }

    /// Render the current OpenAPI document as YAML.
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(&self.generate_openapi()).unwrap_or_default()
    }

    /// Generate a HAR 1.2 log of all recorded entries.
    pub fn generate_har(&self) -> Value {
        json!({
            "log": {
                "version": "1.2",
                "creator": { "name": "Arbiter", "version": "1.0.0" },
                "entries": self.lock().har_entries,
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn record_with_security(
        &self,
        method: &str,
        path: &str,
        status: u16,
        req_headers: &HeaderMapValues,
        req_body: Option<&[u8]>,
        resp_headers: &HeaderMapValues,
        resp_body: Option<&[u8]>,
        security: &[Value],
    ) {
        let method_lower = method.to_lowercase();
        let (pathname, query_string) = split_query(path);
        let query_pairs = parse_query(query_string);
        let open_api_path = normalize_path(pathname);
        let key = format!("{method_lower}:{open_api_path}");

        let mut inner = self.lock();

        let mut endpoint = inner.endpoints.get(&key).cloned().unwrap_or(EndpointInfo {
            path: open_api_path.clone(),
            method: method.to_string(),
            responses: BTreeMap::new(),
            parameters: Vec::new(),
            request_body: if method_lower == "get" {
                None
            } else {
                Some(json!({ "required": false, "content": {} }))
            },
            security: None,
        });

        // Register security schemes and attach requirements.
        if !security.is_empty() {
            let mut requirements = Vec::new();
            for sec in security {
                let scheme_name = add_security_scheme(&mut inner.security_schemes, sec);
                requirements.push(json!({ scheme_name: [] }));
            }
            endpoint.security = Some(requirements);
        }

        // Path parameters.
        for name in path_param_names(&open_api_path) {
            if !endpoint.parameters.iter().any(|p| {
                p.get("name").and_then(Value::as_str) == Some(name.as_str())
                    && p.get("in").and_then(Value::as_str) == Some("path")
            }) {
                endpoint.parameters.push(json!({
                    "name": name,
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string" },
                }));
            }
        }

        // Query parameters.
        for (name, _) in &query_pairs {
            if !endpoint.parameters.iter().any(|p| {
                p.get("name").and_then(Value::as_str) == Some(name.as_str())
                    && p.get("in").and_then(Value::as_str) == Some("query")
            }) {
                endpoint.parameters.push(json!({
                    "name": name,
                    "in": "query",
                    "schema": { "type": "string" },
                }));
            }
        }

        // Request headers as parameters (with example values).
        for (name, values) in req_headers {
            if let Some(first) = values.first() {
                if !endpoint.parameters.iter().any(|p| {
                    p.get("name").and_then(Value::as_str) == Some(name.as_str())
                        && p.get("in").and_then(Value::as_str) == Some("header")
                }) {
                    endpoint.parameters.push(json!({
                        "name": name,
                        "in": "header",
                        "required": false,
                        "schema": { "type": "string", "example": first },
                    }));
                }
            }
        }

        // Request body schema (non-GET only).
        let req_content_type = first_header(req_headers, "content-type")
            .unwrap_or("application/json")
            .to_string();
        let mut har_post_data: Option<(String, String)> = None; // (mimeType, text)
        if let Some(bytes) = req_body {
            if method_lower != "get" {
                let text = decode_maybe_gzip(req_headers, bytes);
                let body_value = if req_content_type.contains("json") {
                    serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text.clone()))
                } else {
                    Value::String(text.clone())
                };
                let has_content = endpoint
                    .request_body
                    .as_ref()
                    .and_then(|rb| rb.get("content"))
                    .and_then(Value::as_object)
                    .is_some_and(|c| c.contains_key(&req_content_type));
                if let Some(request_body) = &mut endpoint.request_body {
                    if !has_content {
                        request_body["content"][&req_content_type] =
                            json!({ "schema": generate_json_schema(&body_value) });
                    }
                }
                let text_out = match &body_value {
                    Value::String(s) => s.clone(),
                    other => serde_json::to_string(other).unwrap_or_default(),
                };
                har_post_data = Some((req_content_type.clone(), text_out));
            }
        }

        // Response schema.
        let resp_content_type = first_header(resp_headers, "content-type")
            .unwrap_or("application/json")
            .to_string();
        if !endpoint.responses.contains_key(status.to_string().as_str()) {
            endpoint.responses.insert(
                status.to_string(),
                json!({
                    "description": format!("Response for {} {}", method.to_uppercase(), pathname),
                    "content": {},
                }),
            );
        }

        let resp_encoding = first_header(resp_headers, "content-encoding");
        let text = resp_body
            .map(|bytes| decode_maybe_gzip_encoding(resp_encoding, bytes))
            .unwrap_or_default();
        let (schema, har_text) = analyze_response_body(&resp_content_type, &text);

        let schema_key = format!("{key}:{status}:{resp_content_type}");
        let cache = inner.schema_cache.entry(schema_key).or_default();
        cache.push(schema);
        let merged = deep_merge_schemas(cache);

        let response = endpoint
            .responses
            .get_mut(&status.to_string())
            .expect("response just inserted");
        response["content"][&resp_content_type] = json!({ "schema": merged });

        // Response headers documentation.
        if !resp_headers.is_empty() {
            let mut headers_doc = serde_json::Map::new();
            for (name, values) in resp_headers {
                if let Some(first) = values.first() {
                    headers_doc.insert(
                        name.clone(),
                        json!({
                            "schema": { "type": "string", "example": first },
                            "description": format!("Response header {name}"),
                        }),
                    );
                }
            }
            response["headers"] = Value::Object(headers_doc);
        }

        inner.endpoints.insert(key, endpoint);

        // Record in HAR.
        let har = build_har_entry(
            &inner.target_url,
            method,
            pathname,
            &query_pairs,
            req_headers,
            har_post_data,
            status,
            resp_headers,
            &resp_content_type,
            resp_body.map(|b| b.len()).unwrap_or(0),
            &har_text,
        );
        inner.har_entries.push(har);
    }
}

/// Process-wide shared store, mirroring the TS `openApiStore` singleton.
pub fn global() -> &'static OpenApiStore {
    static GLOBAL: OnceLock<OpenApiStore> = OnceLock::new();
    GLOBAL.get_or_init(OpenApiStore::new)
}

// ---------------------------------------------------------------------------
// Free helpers operating on `Inner` or pure data.
// ---------------------------------------------------------------------------

fn split_key(key: &str) -> (&str, &str) {
    match key.split_once(':') {
        Some((method, path)) => (method, path),
        None => ("", key),
    }
}

fn first_header<'a>(headers: &'a HeaderMapValues, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.first())
        .map(String::as_str)
}

fn split_query(path: &str) -> (&str, &str) {
    match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    }
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_name, raw_value) = match pair.split_once('=') {
            Some((n, v)) => (n, v),
            None => (pair, ""),
        };
        out.push((
            decode_query_component(raw_name),
            decode_query_component(raw_value),
        ));
    }
    out
}

fn decode_query_component(s: &str) -> String {
    let plus_fixed = s.replace('+', " ");
    percent_encoding::percent_decode_str(&plus_fixed)
        .decode_utf8_lossy()
        .into_owned()
}

fn encode_query_component(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn guid_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        )
        .unwrap()
    });
    &RE
}

fn long_key_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/([0-9a-zA-Z_-]{30,})").unwrap());
    &RE
}

fn numeric_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/(\d+)").unwrap());
    &RE
}

fn colon_param_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r":([0-9A-Za-z_]+)").unwrap());
    &RE
}

fn path_param_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{([0-9A-Za-z_]+)\}").unwrap());
    &RE
}

/// Convert raw path segments into OpenAPI path parameters. Handles numeric
/// IDs, UUIDs, long opaque keys and `:param` style segments (TS
/// `recordEndpoint` normalization).
fn normalize_path(path: &str) -> String {
    let s = guid_re().replace_all(path, "/{guid}");
    let s = long_key_re().replace_all(&s, "/{key}");
    let s = numeric_re().replace_all(&s, "/{id}");
    let s = colon_param_re().replace_all(&s, "{$1}");
    s.into_owned()
}

fn path_param_names(path: &str) -> Vec<String> {
    path_param_re()
        .captures_iter(path)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// Detect security schemes from raw request headers, mirroring TS
/// `server.ts` proxy recording: any `*api-key*` header, `Authorization`
/// bearer/basic prefixes. Only the scheme shape is recorded, never values.
fn detect_security(headers: &HeaderMapValues) -> Vec<Value> {
    let mut out = Vec::new();
    for (name, values) in headers {
        if name.contains("api-key") && values.iter().any(|v| !v.is_empty()) {
            out.push(json!({
                "type": "apiKey",
                "name": name,
                "in": "header",
            }));
        }
    }
    if let Some(auth) = first_header(headers, "authorization") {
        if auth.starts_with("Bearer ") {
            out.push(json!({ "type": "http", "scheme": "bearer" }));
        }
        if auth.starts_with("Basic ") {
            out.push(json!({ "type": "http", "scheme": "basic" }));
        }
    }
    out
}

/// Register a security scheme and return its component name (TS
/// `addSecurityScheme`).
fn add_security_scheme(schemes: &mut BTreeMap<String, Value>, security: &Value) -> String {
    let type_ = security
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("http");
    let scheme_name = if type_ == "apiKey" {
        "apiKey_".to_string()
    } else {
        format!("{type_}_")
    };

    let scheme = match type_ {
        "apiKey" => json!({
            "type": "apiKey",
            "name": security.get("name").and_then(Value::as_str).unwrap_or("x-api-key"),
            "in": security.get("in").and_then(Value::as_str).unwrap_or("header"),
        }),
        "oauth2" => json!({
            "type": "oauth2",
            "flows": security.get("flows").cloned().unwrap_or_else(|| {
                json!({
                    "implicit": {
                        "authorizationUrl": "https://example.com/oauth/authorize",
                        "scopes": { "read": "Read access", "write": "Write access" },
                    }
                })
            }),
        }),
        "openIdConnect" => json!({
            "type": "openIdConnect",
            "openIdConnectUrl": security
                .get("openIdConnectUrl")
                .and_then(Value::as_str)
                .unwrap_or("https://example.com/.well-known/openid-configuration"),
        }),
        // "http" and any unknown type fall back to http, like TS's default.
        _ => json!({
            "type": "http",
            "scheme": security.get("scheme").and_then(Value::as_str).unwrap_or("bearer"),
        }),
    };

    schemes.insert(scheme_name.clone(), scheme);
    scheme_name
}

/// Decode a request/response body honoring `content-encoding: gzip`.
fn decode_maybe_gzip(headers: &HeaderMapValues, bytes: &[u8]) -> String {
    let encoding = first_header(headers, "content-encoding");
    decode_maybe_gzip_encoding(encoding, bytes)
}

fn decode_maybe_gzip_encoding(encoding: Option<&str>, bytes: &[u8]) -> String {
    let data: std::borrow::Cow<'_, [u8]> = match encoding {
        Some(e) if e.contains("gzip") => {
            let mut decoder = flate2::read::GzDecoder::new(bytes);
            let mut out = Vec::new();
            match std::io::Read::read_to_end(&mut decoder, &mut out) {
                Ok(_) => std::borrow::Cow::Owned(out),
                Err(_) => std::borrow::Cow::Borrowed(bytes),
            }
        }
        _ => std::borrow::Cow::Borrowed(bytes),
    };
    String::from_utf8_lossy(&data).into_owned()
}

/// Analyze a decoded response body by content type, producing the response
/// schema and the text stored in the HAR entry (TS `processRawData`).
fn analyze_response_body(content_type: &str, text: &str) -> (Value, String) {
    if content_type.contains("json") {
        if let Ok(parsed) = serde_json::from_str::<Value>(text) {
            let har_text = serde_json::to_string(&parsed).unwrap_or_else(|_| text.to_string());
            return (generate_json_schema(&parsed), har_text);
        }
        let cleaned = clean_json_string(text);
        if let Ok(parsed) = serde_json::from_str::<Value>(&cleaned) {
            let har_text = serde_json::to_string(&parsed).unwrap_or_else(|_| text.to_string());
            return (generate_json_schema(&parsed), har_text);
        }
        let trimmed = text.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return (generate_schema_from_structure(text), text.to_string());
        }
        return (
            json!({ "type": "string", "description": "Non-parseable content" }),
            text.to_string(),
        );
    }
    if content_type.contains("xml") {
        return (
            json!({ "type": "string", "format": "xml", "description": "XML content" }),
            text.to_string(),
        );
    }
    if content_type.contains("image/") {
        return (
            json!({ "type": "string", "format": "binary", "description": "Image content" }),
            text.to_string(),
        );
    }
    let description = if text.chars().count() > 100 {
        let truncated: String = text.chars().take(100).collect();
        format!("{truncated}...")
    } else {
        text.to_string()
    };
    (
        json!({ "type": "string", "description": description }),
        text.to_string(),
    )
}

/// Deep-merge response/request schemas across requests (TS
/// `deepMergeSchemas`). Objects merge property-wise; differing schemas are
/// deduplicated and wrapped in `oneOf`.
pub(crate) fn deep_merge_schemas(schemas: &[Value]) -> Value {
    if schemas.is_empty() {
        return json!({ "type": "object" });
    }
    if schemas.len() == 1 {
        return schemas[0].clone();
    }

    // If all schemas are objects, merge their properties.
    if schemas.iter().all(|s| {
        s.get("type").and_then(Value::as_str) == Some("object") && s.get("oneOf").is_none()
    }) {
        let mut merged_properties = serde_json::Map::new();
        for schema in schemas {
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                for (key, value) in props {
                    match merged_properties.get(key) {
                        None => {
                            merged_properties.insert(key.clone(), value.clone());
                        }
                        Some(existing) => {
                            let merged = deep_merge_schemas(&[existing.clone(), value.clone()]);
                            merged_properties.insert(key.clone(), merged);
                        }
                    }
                }
            }
        }
        return json!({ "type": "object", "properties": merged_properties });
    }

    // Different types: dedupe by canonical JSON and use oneOf.
    let mut unique: Vec<Value> = Vec::new();
    for schema in schemas {
        let canonical = serde_json::to_string(schema).unwrap_or_default();
        if !unique
            .iter()
            .any(|s| serde_json::to_string(s).unwrap_or_default() == canonical)
        {
            unique.push(schema.clone());
        }
    }
    if unique.len() == 1 {
        return unique.remove(0);
    }
    json!({ "type": "object", "oneOf": unique })
}

/// Generate an OpenAPI schema from an arbitrary JSON value (TS
/// `generateJsonSchema`).
pub(crate) fn generate_json_schema(obj: &Value) -> Value {
    match obj {
        Value::Null => json!({ "type": "null" }),
        Value::Bool(b) => json!({ "type": "boolean", "example": b }),
        Value::Number(n) => {
            if is_integer_number(n) {
                json!({ "type": "integer", "example": n })
            } else {
                json!({ "type": "number", "example": n })
            }
        }
        Value::String(s) => json!({ "type": "string", "example": s }),
        Value::Array(items) => {
            if items.is_empty() {
                return json!({ "type": "array", "items": { "type": "object" } });
            }

            // All plain objects: use the first object as a template.
            if items.iter().all(|i| i.is_object()) {
                return json!({
                    "type": "array",
                    "items": generate_json_schema(&items[0]),
                    "example": obj,
                });
            }

            // All primitives of the same JS type.
            let all_primitives = items
                .iter()
                .all(|i| i.is_string() || i.is_number() || i.is_boolean());
            if all_primitives {
                let first_type = js_type_of(&items[0]);
                if items.iter().all(|i| js_type_of(i) == first_type) {
                    if first_type == "number" {
                        let all_integers = items
                            .iter()
                            .filter_map(Value::as_number)
                            .all(is_integer_number);
                        return json!({
                            "type": "array",
                            "items": { "type": if all_integers { "integer" } else { "number" } },
                            "example": obj,
                        });
                    }
                    return json!({
                        "type": "array",
                        "items": { "type": first_type },
                        "example": obj,
                    });
                }
            }

            // General case: per-item schemas; equal schemas collapse.
            let item_schemas: Vec<Value> = items.iter().map(generate_json_schema).collect();
            let first = serde_json::to_string(&item_schemas[0]).unwrap_or_default();
            if item_schemas
                .iter()
                .all(|s| serde_json::to_string(s).unwrap_or_default() == first)
            {
                return json!({
                    "type": "array",
                    "items": item_schemas[0],
                    "example": obj,
                });
            }
            json!({
                "type": "array",
                "items": { "type": "object", "oneOf": item_schemas },
                "example": obj,
            })
        }
        Value::Object(map) => {
            let mut properties = serde_json::Map::new();
            for (key, value) in map {
                properties.insert(key.clone(), generate_json_schema(value));
            }
            json!({ "type": "object", "properties": properties, "example": obj })
        }
    }
}

fn js_type_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "object", // unreachable: null filtered by callers
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "object",
        Value::Object(_) => "object",
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

/// Infer a schema from a JSON-like text that fails to parse (TS
/// `generateSchemaFromStructure`).
fn generate_schema_from_structure(text: &str) -> Value {
    let trimmed = text.trim();

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        return json!({
            "type": "array",
            "description": "Array-like structure detected",
            "items": { "type": "object", "description": "Array items (structure inferred)" },
        });
    }

    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        static PROP_RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#"[\"']?([a-zA-Z0-9_$]+)[\"']?\s*:"#).unwrap());

        let mut properties = serde_json::Map::new();
        let mut found = false;
        for capture in PROP_RE.captures_iter(trimmed) {
            let Some(name_match) = capture.get(1) else {
                continue;
            };
            let prop_name = name_match.as_str();
            if prop_name.is_empty() || properties.contains_key(prop_name) {
                continue;
            }
            found = true;

            // Guess the type from what follows the property name.
            let value_pattern = LazyLock::new(|| {
                Regex::new(&format!(
                    r#"["']?{}["']?\s*:\s*(.{{1,50}})"#,
                    regex::escape(prop_name)
                ))
                .unwrap()
            });
            if let Some(value_match) = value_pattern.captures(trimmed) {
                let value_start = value_match
                    .get(1)
                    .map(|m| m.as_str().trim_start())
                    .unwrap_or("");

                let schema = if value_start.starts_with('{') {
                    json!({ "type": "object", "description": "Nested object detected" })
                } else if value_start.starts_with('[') {
                    json!({
                        "type": "array",
                        "description": "Array value detected",
                        "items": { "type": "object", "description": "Array items (structure inferred)" },
                    })
                } else if value_start.starts_with('"') || value_start.starts_with('\'') {
                    json!({ "type": "string" })
                } else if number_prefix_re().is_match(value_start) {
                    json!({ "type": if value_start.contains('.') { "number" } else { "integer" } })
                } else if value_start.starts_with("true") || value_start.starts_with("false") {
                    json!({ "type": "boolean" })
                } else if value_start.starts_with("null") {
                    json!({ "type": "null" })
                } else {
                    json!({
                        "type": "string",
                        "description": "Property detected by structure analysis",
                    })
                };
                properties.insert(prop_name.to_string(), schema);
            } else {
                properties.insert(
                    prop_name.to_string(),
                    json!({
                        "type": "string",
                        "description": "Property detected by structure analysis",
                    }),
                );
            }
        }

        if found {
            return json!({
                "type": "object",
                "properties": properties,
                "description": "Object structure detected with properties",
            });
        }
        return json!({ "type": "object", "description": "Object-like structure detected" });
    }

    json!({ "type": "string", "description": "Unstructured content" })
}

fn number_prefix_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^-?\d+(\.\d+)?([eE][+-]?\d+)?").unwrap());
    &RE
}

/// Best-effort repair of near-JSON text (TS `cleanJsonString`): strip
/// comments, trailing commas, quote bare keys, convert single-quoted strings.
fn clean_json_string(text: &str) -> String {
    static LINE_COMMENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)//.*$").unwrap());
    static BLOCK_COMMENT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());
    static TRAILING_OBJ_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r",\s*\}").unwrap());
    static TRAILING_ARR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r",\s*\]").unwrap());
    static BARE_KEY_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"([{,]\s*)([a-zA-Z0-9_$]+)(\s*:)").unwrap());

    let cleaned = LINE_COMMENT_RE.replace_all(text, "");
    let cleaned = BLOCK_COMMENT_RE.replace_all(&cleaned, "");
    let cleaned = TRAILING_OBJ_RE.replace_all(&cleaned, "}");
    let cleaned = TRAILING_ARR_RE.replace_all(&cleaned, "]");
    let cleaned = BARE_KEY_RE.replace_all(&cleaned, "${1}\"${2}\"${3}");

    // Convert single-quoted strings to double quotes, respecting nesting and
    // escape sequences (same state machine as TS).
    let mut result = String::with_capacity(cleaned.len());
    let mut in_string = false;
    let mut in_single_quoted_string = false;
    let mut prev_was_backslash = false;
    for ch in cleaned.chars() {
        if prev_was_backslash {
            result.push(ch);
            prev_was_backslash = false;
            continue;
        }
        match ch {
            '\\' => {
                result.push(ch);
                prev_was_backslash = true;
            }
            '"' if !in_single_quoted_string => {
                in_string = !in_string;
                result.push(ch);
            }
            '\'' if !in_string => {
                in_single_quoted_string = !in_single_quoted_string;
                result.push('"');
            }
            _ => result.push(ch),
        }
    }
    result
}

/// Build a HAR 1.2 entry (TS `recordHAREntry`).
#[allow(clippy::too_many_arguments)]
fn build_har_entry(
    target_url: &str,
    method: &str,
    pathname: &str,
    query_pairs: &[(String, String)],
    req_headers: &HeaderMapValues,
    post_data: Option<(String, String)>,
    status: u16,
    resp_headers: &HeaderMapValues,
    resp_content_type: &str,
    size: usize,
    har_text: &str,
) -> Value {
    let started = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");

    let mut url = url::Url::parse(target_url)
        .or_else(|_| url::Url::parse(DEFAULT_TARGET_URL))
        .expect("default target URL is valid");
    if let Ok(joined) = url.join(pathname) {
        url = joined;
    }
    if !query_pairs.is_empty() {
        let mut pairs = url.query_pairs_mut();
        pairs.extend_pairs(query_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    }

    let request_headers: Vec<Value> = req_headers
        .iter()
        .flat_map(|(name, values)| values.iter().map(move |v| (name.clone(), v.clone())))
        .map(|(name, value)| json!({ "name": name.to_lowercase(), "value": value }))
        .collect();
    let response_headers: Vec<Value> = resp_headers
        .iter()
        .flat_map(|(name, values)| values.iter().map(move |v| (name.clone(), v.clone())))
        .map(|(name, value)| json!({ "name": name.to_lowercase(), "value": value }))
        .collect();
    let query_string: Vec<Value> = query_pairs
        .iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect();

    json!({
        "startedDateTime": started.to_string(),
        "time": 0,
        "request": {
            "method": method.to_uppercase(),
            "url": url.as_str(),
            "httpVersion": "HTTP/1.1",
            "headers": request_headers,
            "queryString": query_string,
            "postData": post_data.map(|(mime, text)| json!({
                "mimeType": mime,
                "text": text,
            })),
        },
        "response": {
            "status": status,
            "statusText": if status == 200 { "OK" } else { "Error" },
            "httpVersion": "HTTP/1.1",
            "headers": response_headers,
            "content": {
                "size": size,
                "mimeType": if resp_content_type.is_empty() { "application/json" } else { resp_content_type },
                "text": if har_text.is_empty() { HAR_PLACEHOLDER } else { har_text },
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMapValues {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), vec![v.to_string()]))
            .collect()
    }

    #[test]
    fn records_a_new_endpoint() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "get",
            "/test",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"success": true}"#),
        );

        let spec = store.generate_openapi();
        let operation = &spec["paths"]["/test"]["get"];
        assert!(operation.is_object());
        assert!(operation["responses"]["200"]["content"]["application/json"]["schema"].is_object());
        assert_eq!(operation["summary"], json!("GET /test"));
    }

    #[test]
    fn records_multiple_endpoints() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "get",
            "/test1",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"success": true}"#),
        );
        store.record_exchange(
            "post",
            "/test2",
            201,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"id": 1}"#),
        );

        let spec = store.generate_openapi();
        let paths = spec["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths["/test1"].get("get").is_some());
        assert!(paths["/test2"].get("post").is_some());
    }

    #[test]
    fn generates_yaml_spec() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "get",
            "/test",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"success": true}"#),
        );
        let yaml = store.to_yaml();
        assert!(yaml.contains("openapi: 3.1.0"));
        assert!(yaml.contains("paths:"));
        assert!(yaml.contains("/test:"));
        assert!(yaml.contains("get:"));
    }

    #[test]
    fn initializes_with_default_document() {
        let store = OpenApiStore::new();
        store.set_target_url("http://localhost:8080");
        let spec = store.generate_openapi();
        assert_eq!(spec["openapi"], json!("3.1.0"));
        assert_eq!(spec["info"]["title"], json!("API Documentation"));
        assert_eq!(spec["info"]["version"], json!("1.0.0"));
        assert_eq!(spec["servers"][0]["url"], json!("http://localhost:8080"));
        assert_eq!(spec["paths"].as_object().unwrap().len(), 0);
    }

    #[test]
    fn clears_stored_data() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "get",
            "/test",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"success": true}"#),
        );
        assert_eq!(
            store.generate_openapi()["paths"].as_object().unwrap().len(),
            1
        );
        store.clear();
        assert_eq!(
            store.generate_openapi()["paths"].as_object().unwrap().len(),
            0
        );
    }

    #[test]
    fn records_get_with_query_parameters() {
        let store = OpenApiStore::new();
        store.set_target_url("http://localhost:8080");
        store.record_exchange(
            "get",
            "/users?limit=10&offset=0",
            200,
            &headers(&[("accept", "application/json")]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"[{"id": 1, "name": "John Doe"}, {"id": 2, "name": "Jane Smith"}]"#),
        );

        let spec = store.generate_openapi();
        let get = &spec["paths"]["/users"]["get"];
        let params = get["parameters"].as_array().unwrap();
        assert!(params
            .iter()
            .any(|p| p["name"] == json!("limit") && p["in"] == json!("query")));
        assert!(params
            .iter()
            .any(|p| p["name"] == json!("offset") && p["in"] == json!("query")));
        assert!(get["responses"]["200"]["content"]["application/json"].is_object());
    }

    #[test]
    fn records_post_with_request_body() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "post",
            "/users",
            201,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"name": "Test User", "email": "test@example.com"}"#),
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"id": 1, "name": "Test User", "email": "test@example.com"}"#),
        );

        let spec = store.generate_openapi();
        let post = &spec["paths"]["/users"]["post"];
        let request_body = &post["requestBody"];
        assert!(request_body.is_object());
        let schema = &request_body["content"]["application/json"]["schema"];
        assert_eq!(schema["properties"]["name"]["type"], json!("string"));
        assert_eq!(schema["properties"]["email"]["type"], json!("string"));
        assert!(post["responses"]["201"].is_object());
    }

    #[test]
    fn detects_path_parameters_across_requests() {
        let store = OpenApiStore::new();
        for id in [123u32, 456] {
            store.record_exchange(
                "get",
                &format!("/users/{id}"),
                200,
                &headers(&[]),
                None,
                &headers(&[("content-type", "application/json")]),
                Some(format!(r#"{{"id": {id}, "name": "User {id}"}}"#).as_bytes()),
            );
        }

        let spec = store.generate_openapi();
        let paths = spec["paths"].as_object().unwrap();
        assert!(paths.contains_key("/users/{id}"));
        let params = paths["/users/{id}"]["get"]["parameters"]
            .as_array()
            .unwrap();
        assert!(params
            .iter()
            .any(|p| p["name"] == json!("id") && p["in"] == json!("path")));
    }

    #[test]
    fn normalizes_uuid_and_long_keys() {
        assert_eq!(
            normalize_path("/items/123e4567-e89b-12d3-a456-426614174000"),
            "/items/{guid}"
        );
        assert_eq!(
            normalize_path("/files/abcdefghijklmnopqrstuvwxyz012345"),
            "/files/{key}"
        );
        assert_eq!(normalize_path("/v2/things:thingId"), "/v2/things{thingId}");
    }

    #[test]
    fn detects_api_key_security_scheme() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "get",
            "/secure",
            200,
            &headers(&[("x-api-key", "test-api-key")]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"success": true}"#),
        );

        let spec = store.generate_openapi();
        let operation = &spec["paths"]["/secure"]["get"];
        assert_eq!(operation["security"][0], json!({ "apiKey_": [] }));
        assert_eq!(
            spec["components"]["securitySchemes"]["apiKey_"],
            json!({ "type": "apiKey", "name": "x-api-key", "in": "header" })
        );
    }

    #[test]
    fn detects_custom_api_key_header_names() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "get",
            "/secure",
            200,
            &headers(&[("x-custom-api-key", "secret")]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"success": true}"#),
        );
        let spec = store.generate_openapi();
        assert_eq!(
            spec["components"]["securitySchemes"]["apiKey_"],
            json!({ "type": "apiKey", "name": "x-custom-api-key", "in": "header" })
        );
    }

    #[test]
    fn detects_bearer_and_basic_schemes() {
        // Both schemes register under the "http_" component name (last write
        // wins), matching TS addSecurityScheme naming; verify each in its own
        // store.
        let bearer_store = OpenApiStore::new();
        bearer_store.record_exchange(
            "get",
            "/auth/profile",
            200,
            &headers(&[("authorization", "Bearer token123")]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"id": 1}"#),
        );
        let spec = bearer_store.generate_openapi();
        assert_eq!(
            spec["components"]["securitySchemes"]["http_"],
            json!({ "type": "http", "scheme": "bearer" })
        );
        assert!(spec["paths"]["/auth/profile"]["get"]["security"].is_array());

        let basic_store = OpenApiStore::new();
        basic_store.record_exchange(
            "get",
            "/basic",
            200,
            &headers(&[("authorization", "Basic dXNlcm5hbWU6cGFzc3dvcmQ=")]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"ok": true}"#),
        );
        let spec = basic_store.generate_openapi();
        assert_eq!(
            spec["components"]["securitySchemes"]["http_"],
            json!({ "type": "http", "scheme": "basic" })
        );
        assert!(spec["paths"]["/basic"]["get"]["security"].is_array());

        // In one store, both endpoints still get security requirements even
        // though they share the "http_" scheme entry.
        assert!(bearer_store.generate_openapi()["paths"]["/basic"].is_null());
    }

    #[test]
    fn explicit_security_via_record_exchange_with_security() {
        let store = OpenApiStore::new();
        let security = vec![
            json!({ "type": "apiKey", "name": "X-API-Key", "in": "header" }),
            json!({ "type": "http", "scheme": "bearer" }),
        ];
        store.record_exchange_with_security(
            "get",
            "/multi-auth",
            200,
            &headers(&[
                ("X-API-Key", "test-api-key"),
                ("Authorization", "Bearer test-token"),
            ]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"success": true}"#),
            &security,
        );

        let spec = store.generate_openapi();
        let operation = &spec["paths"]["/multi-auth"]["get"];
        let op_security = operation["security"].as_array().unwrap();
        assert_eq!(op_security.len(), 2);
        assert_eq!(op_security[0], json!({ "apiKey_": [] }));
        assert_eq!(op_security[1], json!({ "http_": [] }));
        assert_eq!(
            spec["components"]["securitySchemes"]["apiKey_"]["name"],
            json!("X-API-Key")
        );
    }

    #[test]
    fn oauth2_and_openid_schemes() {
        let store = OpenApiStore::new();
        let security = vec![json!({
            "type": "oauth2",
            "flows": {
                "authorizationCode": {
                    "authorizationUrl": "https://example.com/oauth/authorize",
                    "tokenUrl": "https://example.com/oauth/token",
                    "scopes": { "read": "Read access", "write": "Write access" },
                }
            }
        })];
        store.record_exchange_with_security(
            "get",
            "/oauth",
            200,
            &headers(&[("Authorization", "Bearer test-token")]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"success": true}"#),
            &security,
        );
        let spec = store.generate_openapi();
        let scheme = &spec["components"]["securitySchemes"]["oauth2_"];
        assert_eq!(scheme["type"], json!("oauth2"));
        assert_eq!(
            scheme["flows"]["authorizationCode"]["tokenUrl"],
            json!("https://example.com/oauth/token")
        );
    }

    #[test]
    fn deep_merge_object_schemas() {
        let merged = deep_merge_schemas(&[
            json!({ "type": "object", "properties": { "name": {"type": "string"}, "age": {"type": "number"} } }),
            json!({ "type": "object", "properties": { "email": {"type": "string"}, "age": {"type": "integer"} } }),
        ]);
        assert_eq!(
            merged,
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "email": { "type": "string" },
                    "age": { "type": "object", "oneOf": [ { "type": "number" }, { "type": "integer" } ] },
                }
            })
        );
    }

    #[test]
    fn deep_merge_dedupes_with_one_of() {
        let merged = deep_merge_schemas(&[
            json!({ "type": "string" }),
            json!({ "type": "number" }),
            json!({ "type": "string" }),
        ]);
        assert_eq!(
            merged,
            json!({ "type": "object", "oneOf": [ { "type": "string" }, { "type": "number" } ] })
        );
    }

    #[test]
    fn deep_merge_nested_objects() {
        let merged = deep_merge_schemas(&[
            json!({ "type": "object", "properties": { "user": { "type": "object", "properties": { "name": { "type": "string" } } } } }),
            json!({ "type": "object", "properties": { "user": { "type": "object", "properties": { "age": { "type": "number" } } } } }),
        ]);
        assert_eq!(
            merged["properties"]["user"]["properties"],
            json!({ "name": { "type": "string" }, "age": { "type": "number" } })
        );
    }

    #[test]
    fn json_schema_simple_object() {
        let schema = generate_json_schema(&json!({
            "id": 1, "name": "John Doe", "active": true, "age": 30
        }));
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["properties"]["id"]["type"], json!("integer"));
        assert_eq!(schema["properties"]["name"]["type"], json!("string"));
        assert_eq!(schema["properties"]["active"]["type"], json!("boolean"));
        assert_eq!(schema["properties"]["age"]["type"], json!("integer"));
    }

    #[test]
    fn json_schema_array_of_objects_uses_first_as_template() {
        let schema = generate_json_schema(&json!([
            { "id": 1, "name": "John Doe" },
            { "id": 2, "name": "Jane Smith" }
        ]));
        assert_eq!(schema["type"], json!("array"));
        assert_eq!(schema["items"]["type"], json!("object"));
        assert_eq!(
            schema["items"]["properties"]["id"]["type"],
            json!("integer")
        );
        assert_eq!(
            schema["items"]["properties"]["name"]["type"],
            json!("string")
        );
    }

    #[test]
    fn json_schema_nested_and_null() {
        let schema = generate_json_schema(&json!({
            "id": 1,
            "address": { "street": "123 Main St", "city": "Anytown" },
            "tags": ["developer", "javascript"],
            "description": null
        }));
        assert_eq!(schema["properties"]["address"]["type"], json!("object"));
        assert_eq!(
            schema["properties"]["address"]["properties"]["street"]["type"],
            json!("string")
        );
        assert_eq!(schema["properties"]["tags"]["type"], json!("array"));
        assert_eq!(
            schema["properties"]["tags"]["items"]["type"],
            json!("string")
        );
        assert_eq!(schema["properties"]["description"]["type"], json!("null"));
    }

    #[test]
    fn json_schema_numeric_kinds() {
        let schema = generate_json_schema(&json!({
            "integer": 42, "float": 9.876543, "scientific": 1e6, "zero": 0
        }));
        assert_eq!(schema["properties"]["integer"]["type"], json!("integer"));
        assert_eq!(schema["properties"]["float"]["type"], json!("number"));
        assert_eq!(schema["properties"]["scientific"]["type"], json!("integer"));
        assert_eq!(schema["properties"]["zero"]["type"], json!("integer"));
    }

    #[test]
    fn structure_analysis_array_object_and_text() {
        let array_schema = generate_schema_from_structure(r#"[{"id":1,"name":"test"},{"id":2}]"#);
        assert_eq!(array_schema["type"], json!("array"));
        assert!(array_schema["items"].is_object());

        let object_schema =
            generate_schema_from_structure(r#"{"id":1,"name":"test","active":true}"#);
        assert_eq!(object_schema["type"], json!("object"));
        let props = object_schema["properties"].as_object().unwrap();
        assert!(props.contains_key("id"));
        assert!(props.contains_key("name"));
        assert!(props.contains_key("active"));
        assert_eq!(props["id"]["type"], json!("integer"));
        assert_eq!(props["name"]["type"], json!("string"));
        assert_eq!(props["active"]["type"], json!("boolean"));

        let text_schema = generate_schema_from_structure("This is just plain text");
        assert_eq!(text_schema["type"], json!("string"));
    }

    #[test]
    fn malformed_json_falls_back_to_structure_then_string() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "get",
            "/broken",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"id": 1, "name": 'quoted', // trailing comment}"#),
        );
        let spec = store.generate_openapi();
        let schema = &spec["paths"]["/broken"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"];
        assert_eq!(schema["type"], json!("object"));
        let props = schema["properties"].as_object().unwrap();
        assert!(props.contains_key("id"));
        assert!(props.contains_key("name"));

        store.record_exchange(
            "get",
            "/garbage",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(b"totally not json at all"),
        );
        let spec = store.generate_openapi();
        let schema = &spec["paths"]["/garbage"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"];
        assert_eq!(schema["type"], json!("string"));
        assert_eq!(schema["description"], json!("Non-parseable content"));
    }

    #[test]
    fn xml_image_and_other_content_types() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "get",
            "/xml",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/xml")]),
            Some(b"<root/>"),
        );
        store.record_exchange(
            "get",
            "/img",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "image/png")]),
            Some(b"\x89PNG"),
        );

        let spec = store.generate_openapi();
        assert_eq!(
            spec["paths"]["/xml"]["get"]["responses"]["200"]["content"]["application/xml"]
                ["schema"]["format"],
            json!("xml")
        );
        assert_eq!(
            spec["paths"]["/img"]["get"]["responses"]["200"]["content"]["image/png"]["schema"]
                ["format"],
            json!("binary")
        );
    }

    #[test]
    fn gzipped_response_is_decoded() {
        let store = OpenApiStore::new();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, br#"{"unzipped": true}"#).unwrap();
        let gz = encoder.finish().unwrap();

        store.record_exchange(
            "get",
            "/gz",
            200,
            &headers(&[]),
            None,
            &headers(&[
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
            ]),
            Some(&gz),
        );

        let spec = store.generate_openapi();
        let schema = &spec["paths"]["/gz"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"];
        assert_eq!(schema["properties"]["unzipped"]["type"], json!("boolean"));
    }

    #[test]
    fn merges_schemas_across_requests_for_same_endpoint() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "get",
            "/items",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"a": 1}"#),
        );
        store.record_exchange(
            "get",
            "/items",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"b": "x"}"#),
        );

        let spec = store.generate_openapi();
        let schema = &spec["paths"]["/items"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"];
        let props = schema["properties"].as_object().unwrap();
        assert!(props.contains_key("a"));
        assert!(props.contains_key("b"));
    }

    #[test]
    fn generates_har_format() {
        let store = OpenApiStore::new();
        store.set_target_url("http://localhost:8080");
        store.record_exchange(
            "get",
            "/test",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"success": true}"#),
        );

        let har = store.generate_har();
        assert_eq!(har["log"]["version"], json!("1.2"));
        assert!(har["log"]["creator"].is_object());
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry["request"]["method"], json!("GET"));
        assert_eq!(entry["request"]["url"], json!("http://localhost:8080/test"));
        assert_eq!(entry["response"]["status"], json!(200));
        assert_eq!(
            entry["response"]["content"]["text"],
            json!(r#"{"success":true}"#)
        );
        assert!(
            entry["response"]["headers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|h| h["name"] == json!("content-type")
                    && h["value"] == json!("application/json"))
        );
    }

    #[test]
    fn record_har_entry_appends_verbatim() {
        let store = OpenApiStore::new();
        let entry = json!({
            "startedDateTime": "2026-01-01T00:00:00.000Z",
            "time": 5,
            "request": { "method": "GET", "url": "http://x/y" },
            "response": { "status": 200 }
        });
        store.record_har_entry(&entry);
        let har = store.generate_har();
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], entry);
    }

    #[test]
    fn merge_endpoint_data_replays_persisted_row() {
        let store = OpenApiStore::new();
        let data = json!({
            "path": "/users",
            "method": "get",
            "request": {
                "query": { "limit": "10" },
                "headers": { "x-api-key": "test-key" },
                "contentType": "application/json",
                "security": [ { "type": "apiKey", "name": "x-api-key", "in": "header" } ]
            },
            "response": {
                "status": 200,
                "headers": { "content-type": "application/json" },
                "contentType": "application/json"
            }
        });
        store.merge_endpoint_data("/users", "get", &data);

        let spec = store.generate_openapi();
        let get = &spec["paths"]["/users"]["get"];
        let params = get["parameters"].as_array().unwrap();
        assert!(params
            .iter()
            .any(|p| p["name"] == json!("limit") && p["in"] == json!("query")));
        assert_eq!(
            spec["components"]["securitySchemes"]["apiKey_"]["name"],
            json!("x-api-key")
        );
        assert!(get["security"].is_array());
    }

    #[test]
    fn all_endpoints_round_trips_through_merge() {
        let store = OpenApiStore::new();
        store.record_exchange(
            "post",
            "/things",
            201,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"id": 7}"#),
        );

        let endpoints = store.all_endpoints();
        assert_eq!(endpoints.len(), 1);
        let (path, method, data) = &endpoints[0];
        assert_eq!(path, "/things");
        assert_eq!(method, "post");
        assert_eq!(
            data["responses"]["201"]["description"],
            json!("Response for POST /things")
        );

        // EndpointInfo-shaped data imports verbatim.
        let other = OpenApiStore::new();
        other.merge_endpoint_data(path, method, data);
        assert_eq!(other.all_endpoints().len(), 1);
        assert!(other.generate_openapi()["paths"]["/things"]["post"].is_object());
    }

    #[test]
    fn global_store_is_shared() {
        let store = global();
        store.record_exchange(
            "get",
            "/__global_probe__",
            200,
            &headers(&[]),
            None,
            &headers(&[("content-type", "application/json")]),
            Some(br#"{"ok": true}"#),
        );
        assert!(global().generate_openapi()["paths"]["/__global_probe__"]["get"].is_object());
    }
}
