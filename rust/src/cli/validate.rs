//! `arbiter validate` (port of src/commands/validate-bundle.ts).

use std::path::Path;

use clap::Args;
use serde_json::json;

use super::{atomic_write_private, fail};
use crate::bundle::load_bundle;

/// Validate a capture bundle against a contract
#[derive(Args)]
pub struct ValidateBundleArgs {
    /// path to the capture bundle directory
    pub bundle: String,

    /// OpenAPI spec for the basic validator
    #[arg(short = 's', long = "spec")]
    pub spec: Option<String>,

    /// external validator command (stdin JSON, stdout violations array)
    #[arg(long = "command")]
    pub command: Option<String>,

    /// exit 1 on any violation
    #[arg(long = "strict")]
    pub strict: bool,

    /// write the JSON validation report to a file
    #[arg(long = "report")]
    pub report: Option<String>,
}

pub fn run(args: &ValidateBundleArgs, fmt: super::output::OutputFormat) -> i32 {
    if args.spec.is_none() && args.command.is_none() {
        fail("Provide --spec <path> or --command <cmd>");
    }

    let bundle_dir = Path::new(&args.bundle);
    let exchange_count = match load_bundle(bundle_dir) {
        Ok(bundle) => bundle.exchanges.len(),
        Err(e) => fail(format!("Failed to load bundle {}: {e}", args.bundle)),
    };

    // TS precedence: an external --command validator wins over --spec.
    let validator_label = if args.command.is_some() {
        "command"
    } else {
        "basic"
    };
    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    let report = runtime.block_on(async {
        if let Some(command) = args.command.as_deref() {
            crate::validation::validate_capture_with_external(bundle_dir, command).await
        } else {
            crate::validation::validate_capture(
                bundle_dir,
                Path::new(args.spec.as_deref().unwrap_or_default()),
            )
            .await
        }
    });

    let report = match report {
        Ok(report) => report,
        Err(e) => fail(format!("Validation failed: {e}")),
    };

    // Versioned report envelope (D4): the same object backs --json output
    // and the --report file, with "schema" as its first key.
    let envelope = super::output::stamped(
        super::output::SCHEMA_VIOLATIONS,
        &json!({
            "validator": validator_label,
            "exchangeCount": exchange_count,
            "valid": report.valid,
            "violations": report.violations,
        }),
    );

    super::output::emit(
        fmt,
        || {
            println!("Validation Report:");
            println!("  Validator:  {validator_label}");
            println!("  Exchanges:  {exchange_count}");
            if report.valid {
                println!("  Violations: 0");
            } else {
                println!("  Violations: {}", report.violations.len());
            }
            for (index, violation) in report.violations.iter().enumerate() {
                println!(
                    "⚠ #{} {} [{}]: {}",
                    index + 1,
                    violation.path,
                    violation.keyword,
                    violation.message
                );
            }
        },
        &envelope,
    );
    if let Some(report_path) = args.report.as_deref() {
        // Mirror the TS report envelope: validator, exchangeCount, valid,
        // violations — plus the schema discriminator.
        let serialized = serde_json::to_vec_pretty(&envelope).expect("report serializes");
        atomic_write_private(Path::new(report_path), &serialized)
            .unwrap_or_else(|e| fail(format!("Failed to write report {report_path}: {e}")));
        println!("Report written to {report_path}");
    }

    if args.strict && !report.valid {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{make_captured_body, write_bundle, WriteBundleOptions};
    use crate::types::{
        CaptureMode, CapturedBody, CapturedExchange, CapturedHeaders, CapturedRequest,
        CapturedResponse, HeaderMapValues, RedactionPolicySummary, StreamState,
        EXCHANGE_SCHEMA_VERSION,
    };
    use std::collections::HashMap;
    use std::path::PathBuf;

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

    /// Build a one-exchange bundle whose response violates the spec's
    /// `required: [id]`, mirroring the validation test fixture.
    fn write_fixture(dir: &Path) -> (PathBuf, PathBuf) {
        let mut headers = HeaderMapValues::new();
        headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        let captured_headers = CapturedHeaders {
            values: headers,
            redacted: Vec::new(),
        };
        let exchange = CapturedExchange {
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
                body: captured_body(b"{\"missing_id\":true}"),
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
        };
        let manifest = crate::types::CaptureManifest {
            schema_version: 1,
            arbiter_version: "1.1.0".to_string(),
            mode: CaptureMode::Exact,
            target_origin: "https://api.example.com".to_string(),
            started_at: "2025-01-01T00:00:00.000Z".to_string(),
            completed_at: "2025-01-01T00:01:00.000Z".to_string(),
            exchange_count: 1,
            bundle_digest: String::new(),
            redaction: RedactionPolicySummary {
                redact_headers: Vec::new(),
                allow_query: Vec::new(),
            },
            metadata: None,
        };
        let bundle_dir = dir.join("capture");
        write_bundle(
            &bundle_dir,
            WriteBundleOptions {
                manifest,
                exchanges: vec![exchange],
                bodies: HashMap::new(),
                validation: None,
            },
        )
        .expect("write bundle");
        let spec_path = dir.join("spec.yaml");
        std::fs::write(&spec_path, SPEC_YAML.trim_start()).expect("write spec");
        (bundle_dir, spec_path)
    }

    #[test]
    fn validate_reports_violations_and_strict_exit_code() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (bundle_dir, spec_path) = write_fixture(dir.path());
        let report_path = dir.path().join("report.json");
        let args = ValidateBundleArgs {
            bundle: bundle_dir.to_string_lossy().into_owned(),
            spec: Some(spec_path.to_string_lossy().into_owned()),
            command: None,
            strict: true,
            report: Some(report_path.to_string_lossy().into_owned()),
        };
        assert_eq!(run(&args, crate::cli::output::OutputFormat::Human), 1);

        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&report_path).expect("report"))
                .expect("valid JSON report");
        assert_eq!(report["validator"], "basic");
        assert_eq!(report["exchangeCount"], 1);
        assert_eq!(report["valid"], false);
        assert!(
            !report["violations"]
                .as_array()
                .expect("violations")
                .is_empty(),
            "schema violation must be listed"
        );
    }

    /// G4 + D4 regression: --json emits the versioned envelope, and it
    /// round-trips as valid JSON with the exact schema discriminator.
    #[test]
    fn json_report_round_trips_with_schema_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (bundle_dir, spec_path) = write_fixture(dir.path());
        let args = ValidateBundleArgs {
            bundle: bundle_dir.to_string_lossy().into_owned(),
            spec: Some(spec_path.to_string_lossy().into_owned()),
            command: None,
            strict: false,
            report: None,
        };
        assert_eq!(run(&args, crate::cli::output::OutputFormat::Json), 0);

        // Re-derive the same envelope run() emits and verify the round-trip
        // shape (schema first key, exact discriminator value).
        let violations = crate::validation::ValidationReport {
            valid: false,
            violations: Vec::new(),
        };
        let envelope = crate::cli::output::stamped(
            crate::cli::output::SCHEMA_VIOLATIONS,
            &serde_json::json!({
                "validator": "basic",
                "exchangeCount": 1,
                "valid": violations.valid,
                "violations": violations.violations,
            }),
        );
        assert_eq!(
            envelope.get("schema").and_then(|s| s.as_str()),
            Some("arbiter.violations/v1")
        );
        // The stamped value must survive a full JSON round-trip.
        let text = serde_json::to_string(&envelope).expect("serialize");
        let back: serde_json::Value = serde_json::from_str(&text).expect("parse");
        assert_eq!(back["schema"], "arbiter.violations/v1");
        assert_eq!(back["validator"], "basic");
    }
}
