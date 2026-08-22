//! Sanitize an untrusted capture bundle: reload with full verification,
//! re-apply redaction to headers and paths, run the secret scanner (fail
//! closed), and emit a new deterministic bundle. Never edits in place.
//!
//! Port of `src/bundle/sanitize.ts`.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use base64::Engine as _;

use crate::bundle::store::{load_bundle, write_bundle, WriteBundleOptions, INLINE_BODY_LIMIT};
use crate::error::{Error, Result};
use crate::headers::capture_headers;
use crate::redaction::{RedactionPolicy, RedactionPolicyOptions};
use crate::secret_scan::{ensure_clean, scan_exchanges, SecretScanOptions};
use crate::types::{BodyStorage, CaptureManifest, CapturedBody, CapturedExchange};
use crate::version::ARBITER_VERSION;

#[derive(Debug, Clone)]
pub struct SanitizeOptions {
    /// Exact secret values to reject anywhere in the bundle.
    pub reject_secret_env: Vec<String>,
    /// Media types allowed to remain unscanned binary.
    pub allow_binary_media_types: Vec<String>,
    /// Additional header names or globs to redact on top of the defaults.
    pub redact_headers: Vec<String>,
    /// Query parameter names whose values may be kept.
    pub allow_query: Vec<String>,
    /// Output bundle directory. Must not be the input directory or an
    /// existing non-empty directory.
    pub output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SanitizeResult {
    pub manifest: CaptureManifest,
    pub output_dir: PathBuf,
}

/// Rebuild a captured body from its verified bytes: inline for small
/// payloads, content-addressed blob marker for large ones. The bytes are
/// always recorded in `bodies` so the secret scanner and `write_bundle` can
/// resolve every digest.
fn rebuild_body(
    bytes: &[u8],
    previous: &CapturedBody,
    bodies: &mut HashMap<String, Vec<u8>>,
) -> Result<CapturedBody> {
    let digest = crate::bundle::sha256_hex(bytes);
    let storage = if bytes.len() > INLINE_BODY_LIMIT {
        BodyStorage::Blob {
            path: format!("bodies/{digest}.bin"),
        }
    } else {
        BodyStorage::InlineBase64 {
            value: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    };
    bodies.insert(digest.clone(), bytes.to_vec());
    Ok(CapturedBody {
        sha256: digest,
        size: bytes.len() as u64,
        media_type: previous.media_type.clone(),
        content_encoding: previous.content_encoding.clone(),
        storage,
    })
}

/// Union of freshly redacted names and names already redacted upstream,
/// deduplicated and sorted.
fn merge_redacted(current: Vec<String>, prior: &[String]) -> Vec<String> {
    let set: BTreeSet<String> = current.iter().chain(prior.iter()).cloned().collect();
    set.into_iter().collect()
}

/// Normalize a target URL to its bare origin, mirroring the TS
/// `new URL(...).origin`: credentials, path, and query are stripped. An
/// untrusted manifest must never smuggle userinfo through sanitization.
fn url_origin(raw: &str) -> Result<String> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| Error::other(format!("Invalid targetOrigin {raw:?}: {e}")))?;
    match parsed.scheme() {
        "http" | "https" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| Error::other(format!("targetOrigin {raw:?} has no host")))?;
            let default = if parsed.scheme() == "https" { 443 } else { 80 };
            let port = match parsed.port() {
                Some(p) if p != default => format!(":{p}"),
                _ => String::new(),
            };
            Ok(format!("{}://{host}{port}", parsed.scheme()))
        }
        _ => Ok("null".to_string()),
    }
}

/// Sanitize `input_dir` and write a fresh deterministic bundle to
/// `options.output`. The input bundle is loaded with full verification and
/// never modified; a secret-scan failure aborts before any output is
/// written (fail closed, no partial bundle).
pub fn sanitize_bundle(input_dir: &Path, options: &SanitizeOptions) -> Result<SanitizeResult> {
    let mut input = load_bundle(input_dir)?;

    let input_abs =
        std::path::absolute(input_dir).map_err(|e| Error::io("resolve input dir", e))?;
    let output_root: PathBuf =
        std::path::absolute(&options.output).map_err(|e| Error::io("resolve output dir", e))?;
    if input_abs == output_root {
        return Err(Error::other(
            "Sanitize never edits in place; choose a different output directory",
        ));
    }
    if output_root.exists() {
        let non_empty = std::fs::read_dir(&output_root)
            .map_err(|e| Error::io(format!("read output dir {}", output_root.display()), e))?
            .next()
            .is_some();
        if non_empty {
            return Err(Error::other(format!(
                "Sanitize output directory is not empty: {}",
                output_root.display()
            )));
        }
    }

    let policy = RedactionPolicy::new(&RedactionPolicyOptions {
        redact_headers: options.redact_headers.clone(),
        allow_query: options.allow_query.clone(),
    });

    let mut bodies: HashMap<String, Vec<u8>> = HashMap::new();
    let mut exchanges: Vec<CapturedExchange> = Vec::with_capacity(input.exchanges.len());
    // Clone the exchange list up front: `read_body` mutates the bundle's
    // body cache while we iterate.
    for exchange in &input.exchanges.clone() {
        let request_bytes = input.read_body(&exchange.request.body)?;
        let response_bytes = input.read_body(&exchange.response.body)?;

        let mut request_headers = capture_headers(&exchange.request.headers.values, &policy);
        request_headers.redacted =
            merge_redacted(request_headers.redacted, &exchange.request.headers.redacted);
        let mut response_headers = capture_headers(&exchange.response.headers.values, &policy);
        response_headers.redacted = merge_redacted(
            response_headers.redacted,
            &exchange.response.headers.redacted,
        );

        let request_body = rebuild_body(&request_bytes, &exchange.request.body, &mut bodies)?;
        let response_body = rebuild_body(&response_bytes, &exchange.response.body, &mut bodies)?;

        exchanges.push(CapturedExchange {
            schema_version: exchange.schema_version,
            sequence: exchange.sequence,
            started_at: exchange.started_at.clone(),
            duration_ms: exchange.duration_ms,
            request: crate::types::CapturedRequest {
                method: exchange.request.method.clone(),
                path: policy.redact_path(&exchange.request.path),
                http_version: exchange.request.http_version.clone(),
                headers: request_headers,
                body: request_body,
            },
            response: crate::types::CapturedResponse {
                status: exchange.response.status,
                status_text: exchange.response.status_text.clone(),
                http_version: exchange.response.http_version.clone(),
                headers: response_headers,
                body: response_body,
                stream: exchange.response.stream.clone(),
            },
            failure: exchange.failure.clone(),
            validation: exchange.validation,
            tunnel: None,
            tls: None,
            ws: None,
            llm: None,
        });
    }

    let scan_options = SecretScanOptions {
        reject_secrets: options.reject_secret_env.clone(),
        allow_binary_media_types: options.allow_binary_media_types.clone(),
    };
    let findings = scan_exchanges(
        &exchanges,
        &bodies,
        input.manifest.metadata.as_ref(),
        &scan_options,
    );
    ensure_clean(findings)?;

    let target_origin = url_origin(&input.manifest.target_origin)?;

    let manifest = CaptureManifest {
        schema_version: crate::types::BUNDLE_SCHEMA_VERSION,
        arbiter_version: ARBITER_VERSION.to_string(),
        mode: input.manifest.mode,
        target_origin,
        started_at: input.manifest.started_at.clone(),
        completed_at: input.manifest.completed_at.clone(),
        // Derived by write_bundle.
        exchange_count: 0,
        bundle_digest: String::new(),
        redaction: policy.summary(),
        metadata: input.manifest.metadata.clone(),
    };
    write_bundle(
        &output_root,
        WriteBundleOptions {
            manifest,
            exchanges,
            bodies,
            validation: None,
        },
    )?;

    // Reload the freshly written bundle so the returned manifest reflects
    // the verified on-disk state (and any write problem surfaces here).
    let reloaded = load_bundle(&output_root)?;
    Ok(SanitizeResult {
        manifest: reloaded.manifest,
        output_dir: output_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::store::make_captured_body;
    use crate::types::{
        CaptureMode, CapturedHeaders, CapturedRequest, CapturedResponse, StreamState,
    };

    struct DirtySpec<'a> {
        header_values: Vec<(&'a str, Vec<&'a str>)>,
        request_body: &'a str,
        path: &'a str,
        target_origin: &'a str,
    }

    impl Default for DirtySpec<'_> {
        fn default() -> Self {
            Self {
                header_values: vec![("content-type", vec!["application/json"])],
                request_body: "{\"model\":\"m\"}",
                path: "/v1/messages",
                target_origin: "https://api.example.com",
            }
        }
    }

    fn write_dirty_bundle(input: &Path, spec: &DirtySpec) {
        let bodies: HashMap<String, Vec<u8>> = HashMap::new();
        let mut header_map = crate::types::HeaderMapValues::new();
        for (name, values) in &spec.header_values {
            header_map.insert(
                name.to_string(),
                values.iter().map(|v| v.to_string()).collect(),
            );
        }
        let request_body = make_captured_body(
            spec.request_body.as_bytes(),
            Some("application/json"),
            None,
            None,
        )
        .unwrap();
        let response_body =
            make_captured_body(b"{\"ok\":true}", Some("application/json"), None, None).unwrap();
        let exchange = CapturedExchange {
            schema_version: crate::types::EXCHANGE_SCHEMA_VERSION,
            sequence: 0,
            started_at: "2025-01-01T00:00:00.000Z".into(),
            duration_ms: 5.0,
            request: CapturedRequest {
                method: "POST".into(),
                path: spec.path.into(),
                http_version: "1.1".into(),
                headers: CapturedHeaders {
                    values: header_map,
                    redacted: vec![],
                },
                body: request_body,
            },
            response: CapturedResponse {
                status: 200,
                status_text: "OK".into(),
                http_version: "1.1".into(),
                headers: CapturedHeaders {
                    values: crate::types::HeaderMapValues::new(),
                    redacted: vec![],
                },
                body: response_body,
                stream: StreamState {
                    kind: "buffered".into(),
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
        };
        write_bundle(
            input,
            WriteBundleOptions {
                manifest: CaptureManifest {
                    schema_version: crate::types::BUNDLE_SCHEMA_VERSION,
                    arbiter_version: "1.1.0".into(),
                    mode: CaptureMode::Observe,
                    target_origin: spec.target_origin.into(),
                    started_at: "2025-01-01T00:00:00.000Z".into(),
                    completed_at: "2025-01-01T00:01:00.000Z".into(),
                    exchange_count: 0,
                    bundle_digest: "0".repeat(64),
                    redaction: crate::types::RedactionPolicySummary {
                        redact_headers: vec![],
                        allow_query: vec![],
                    },
                    metadata: None,
                },
                exchanges: vec![exchange],
                bodies,
                validation: None,
            },
        )
        .unwrap();
    }

    fn default_options(output: PathBuf) -> SanitizeOptions {
        SanitizeOptions {
            reject_secret_env: vec![],
            allow_binary_media_types: vec![],
            redact_headers: vec![],
            allow_query: vec![],
            output,
        }
    }

    #[test]
    fn reapplies_redaction_to_headers_and_query_values() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in");
        write_dirty_bundle(
            &input,
            &DirtySpec {
                header_values: vec![
                    ("content-type", vec!["application/json"]),
                    ("authorization", vec!["Bearer leaked-credential"]),
                ],
                path: "/v1/messages?api_key=leaked-query",
                ..Default::default()
            },
        );
        let result = sanitize_bundle(&input, &default_options(dir.path().join("out"))).unwrap();

        let serialized = serde_json::to_string(&result.manifest).unwrap();
        let exchanges_raw =
            std::fs::read_to_string(result.output_dir.join("exchanges.ndjson")).unwrap();
        assert!(!exchanges_raw.contains("leaked-credential"));
        assert!(!exchanges_raw.contains("leaked-query"));
        assert!(exchanges_raw.contains(crate::redaction::REDACTED_VALUE));
        let _ = serialized;
        let reloaded = load_bundle(&result.output_dir).unwrap();
        assert!(reloaded.exchanges[0]
            .request
            .headers
            .redacted
            .iter()
            .any(|n| n == "authorization"));
    }

    #[test]
    fn fails_closed_on_planted_secrets_and_writes_no_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in");
        write_dirty_bundle(
            &input,
            &DirtySpec {
                request_body: "{\"note\":\"key is topsecret-body-value\"}",
                ..Default::default()
            },
        );
        let mut options = default_options(dir.path().join("out"));
        options.reject_secret_env = vec!["topsecret-body-value".into()];
        let err = sanitize_bundle(&input, &options).unwrap_err();
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("secret scan failed"),
            "unexpected error: {err}"
        );
        // Failure must not leave a partial output bundle behind.
        assert!(!dir.path().join("out").join("manifest.json").exists());
    }

    #[test]
    fn never_edits_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in");
        write_dirty_bundle(&input, &DirtySpec::default());
        let options = default_options(input.clone());
        let err = sanitize_bundle(&input, &options).unwrap_err();
        assert!(
            err.to_string().contains("in place"),
            "unexpected error: {err}"
        );
        // Input untouched.
        assert!(load_bundle(&input).is_ok());
    }

    #[test]
    fn refuses_non_empty_output_directory() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in");
        write_dirty_bundle(&input, &DirtySpec::default());
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join("existing.txt"), "x").unwrap();
        let err = sanitize_bundle(&input, &default_options(out)).unwrap_err();
        assert!(
            err.to_string().contains("not empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn normalizes_target_origin_stripping_userinfo() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in");
        write_dirty_bundle(&input, &DirtySpec::default());
        // Tamper the manifest to carry credentials in the target URL. The
        // bundle digest covers exchanges, not the manifest, so load still
        // verifies.
        let manifest_path = input.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["targetOrigin"] = serde_json::Value::String(
            "https://user:supersecretpw@api.example.com/some/path?x=1".into(),
        );
        std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

        let result = sanitize_bundle(&input, &default_options(dir.path().join("out"))).unwrap();
        assert_eq!(result.manifest.target_origin, "https://api.example.com");
        let written = std::fs::read_to_string(result.output_dir.join("manifest.json")).unwrap();
        assert!(!written.contains("supersecretpw"));
    }

    #[test]
    fn produces_loadable_deterministic_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in");
        write_dirty_bundle(&input, &DirtySpec::default());
        let out1 = dir.path().join("out1");
        let out2 = dir.path().join("out2");
        let r1 = sanitize_bundle(&input, &default_options(out1.clone())).unwrap();
        let r2 = sanitize_bundle(&input, &default_options(out2.clone())).unwrap();

        assert_eq!(
            std::fs::read(out1.join("exchanges.ndjson")).unwrap(),
            std::fs::read(out2.join("exchanges.ndjson")).unwrap()
        );
        let reloaded = load_bundle(&out1).unwrap();
        assert_eq!(reloaded.exchanges.len(), 1);
        // Deterministic digest across runs.
        assert_eq!(r1.manifest.bundle_digest, r2.manifest.bundle_digest);
        assert_eq!(r1.manifest.exchange_count, 1);
    }

    #[test]
    fn output_digest_differs_for_tampered_input_content() {
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("clean");
        let tampered = dir.path().join("tampered");
        write_dirty_bundle(&clean, &DirtySpec::default());
        write_dirty_bundle(
            &tampered,
            &DirtySpec {
                request_body: "{\"model\":\"m\",\"injected\":true}",
                ..Default::default()
            },
        );
        let r_clean = sanitize_bundle(&clean, &default_options(dir.path().join("o1"))).unwrap();
        let r_tampered =
            sanitize_bundle(&tampered, &default_options(dir.path().join("o2"))).unwrap();
        assert_ne!(
            r_clean.manifest.bundle_digest,
            r_tampered.manifest.bundle_digest
        );
    }

    #[test]
    fn origin_helper_matches_ts_url_origin() {
        assert_eq!(
            url_origin("https://user:pw@host.example/some/path?x=1").unwrap(),
            "https://host.example"
        );
        assert_eq!(
            url_origin("http://host.example:8080/").unwrap(),
            "http://host.example:8080"
        );
        assert_eq!(
            url_origin("https://host.example:443/").unwrap(),
            "https://host.example"
        );
        assert!(url_origin("not a url").is_err());
    }
}
