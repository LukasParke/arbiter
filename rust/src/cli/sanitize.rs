//! `arbiter sanitize` (port of src/commands/sanitize.ts).

use std::path::{Path, PathBuf};

use clap::Args;

use super::fail;
use crate::bundle::sanitize::{sanitize_bundle, SanitizeOptions};

/// Revalidate an untrusted capture bundle and emit a new deterministic sanitized bundle
#[derive(Args)]
pub struct SanitizeArgs {
    /// path to the input capture bundle directory
    pub bundle: String,

    /// directory for the sanitized bundle (must not exist or be empty)
    #[arg(short = 'o', long = "output")]
    pub output: String,

    /// additional header name/glob to redact (repeatable)
    #[arg(long = "redact-header")]
    pub redact_header: Vec<String>,

    /// query parameter whose value may be kept (repeatable)
    #[arg(long = "allow-query")]
    pub allow_query: Vec<String>,

    /// env var whose value must not appear anywhere (repeatable)
    #[arg(long = "reject-secret-env")]
    pub reject_secret_env: Vec<String>,

    /// media type prefix allowed to remain unscanned binary (repeatable)
    #[arg(long = "allow-binary-media-type")]
    pub allow_binary_media_type: Vec<String>,
}

pub fn run(args: &SanitizeArgs, fmt: super::output::OutputFormat) -> i32 {
    for env_name in &args.reject_secret_env {
        match std::env::var(env_name) {
            Ok(value) if !value.is_empty() => {}
            _ => fail(format!(
                "--reject-secret-env {env_name}: environment variable is not set"
            )),
        }
    }

    let options = SanitizeOptions {
        reject_secret_env: args.reject_secret_env.clone(),
        allow_binary_media_types: args.allow_binary_media_type.clone(),
        redact_headers: args.redact_header.clone(),
        allow_query: args.allow_query.clone(),
        output: PathBuf::from(&args.output),
    };

    match sanitize_bundle(Path::new(&args.bundle), &options) {
        Ok(result) => {
            let summary = serde_json::json!({
                "input": args.bundle,
                "output": args.output,
                "manifest": &result.manifest,
            });
            super::output::emit(
                fmt,
                || {
                    println!(
                        "Sanitized {} exchange(s) to {}",
                        result.manifest.exchange_count, args.output
                    );
                },
                summary,
            );
            0
        }
        Err(e) => fail(format!("Sanitize failed: {e}")),
    }
}

#[cfg(test)]
mod tests {

    use crate::types::{CaptureManifest, CaptureMode, RedactionPolicySummary};

    fn manifest() -> CaptureManifest {
        CaptureManifest {
            schema_version: 1,
            arbiter_version: "1.1.0".into(),
            mode: CaptureMode::Observe,
            target_origin: "https://api.example.com".into(),
            started_at: "2026-08-21T00:00:00.000Z".into(),
            completed_at: "2026-08-21T00:00:01.000Z".into(),
            exchange_count: 3,
            bundle_digest: "ab".repeat(32),
            redaction: RedactionPolicySummary {
                redact_headers: vec![],
                allow_query: vec![],
            },
            metadata: None,
        }
    }

    /// G4 regression: the sanitize summary {input, output, manifest} must
    /// serialize to valid JSON that round-trips (what `--json` consumers do).
    #[test]
    fn json_summary_round_trips() {
        let summary = serde_json::json!({
            "input": "in-bundle",
            "output": "out-bundle",
            "manifest": manifest(),
        });
        let text = serde_json::to_string(&summary).expect("serialize");
        let back: serde_json::Value = serde_json::from_str(&text).expect("parse");
        assert_eq!(back["input"], "in-bundle");
        assert_eq!(back["output"], "out-bundle");
        assert_eq!(back["manifest"]["exchangeCount"], 3);
        assert_eq!(back["manifest"]["targetOrigin"], "https://api.example.com");
    }
}
