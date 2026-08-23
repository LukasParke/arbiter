//! `arbiter replay` (port of src/commands/replay.ts).

use std::path::Path;

use clap::Args;
use url::Url;

use super::{atomic_write_private, fail, parse_positive_int};
use crate::bundle::load_bundle;
use crate::replay::{ReplayCredentialEnv, ReplayMode, ReplayOptions};

const MODES: [&str; 4] = [
    "status-only",
    "exact-response-body",
    "semantic-json-response",
    "semantic-sse-response",
];

/// Replay a capture bundle (or legacy traffic JSONL) for regression testing
#[derive(Args)]
pub struct ReplayArgs {
    /// capture bundle directory (unified input convention: the primary
    /// input is the `[INPUT]` positional)
    pub bundle: Option<String>,

    /// treat the input as legacy traffic JSONL instead of a bundle
    #[arg(long = "legacy-jsonl")]
    pub legacy_jsonl: bool,

    /// target API URL to replay against
    #[arg(long = "target")]
    pub target: String,

    /// comparison mode: status-only, exact-response-body, semantic-json-response, semantic-sse-response
    #[arg(long = "mode", default_value = "status-only")]
    pub mode: String,

    /// ENV:header[:prefix] credential mapping (repeatable)
    #[arg(long = "credential-env")]
    pub credential_env: Vec<String>,

    /// volatile JSON pointer to ignore (repeatable)
    #[arg(long = "ignore-pointer")]
    pub ignore_pointer: Vec<String>,

    /// NAME:ENV replacement for a capture-redacted query value (repeatable)
    #[arg(long = "query-env")]
    pub query_env: Vec<String>,

    /// (legacy) authentication token for replayed requests
    #[arg(long = "token")]
    pub token: Option<String>,

    /// (legacy) only compare status codes
    #[arg(long = "only-status")]
    pub only_status: bool,

    /// delay between requests in milliseconds
    #[arg(long = "delay", default_value = "0")]
    pub delay: String,

    /// write the JSON replay report to a file
    #[arg(long = "report")]
    pub report: Option<String>,

    /// exit with code 1 if any regressions are found
    #[arg(long = "fail-on-diff")]
    pub fail_on_diff: bool,

    /// show details for all requests, not just failures
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

pub fn run(args: &ReplayArgs, fmt: super::output::OutputFormat) -> i32 {
    let Some(input_path) = args.bundle.as_deref() else {
        fail("Provide a capture bundle directory (positional [INPUT])");
    };
    let input_path = input_path.to_string();
    let input = Path::new(&input_path);
    if !input.exists() {
        fail(format!("Capture path not found: {input_path}"));
    }

    let is_legacy = args.legacy_jsonl || input.is_file();
    if is_legacy {
        return run_legacy(args, &input_path);
    }

    if !MODES.contains(&args.mode.as_str()) {
        fail(format!(
            "Unsupported mode: {}. Valid: {}",
            args.mode,
            MODES.join(", ")
        ));
    }
    let mode = mode_from_str(&args.mode);

    let bundle_exchange_count = match load_bundle(input) {
        Ok(bundle) => bundle.exchanges.len(),
        Err(e) => fail(format!("Failed to load bundle {input_path}: {e}")),
    };
    println!(
        "Replaying {bundle_exchange_count} exchange(s) against {}",
        args.target
    );

    // TS resolves each NAME:ENV pair eagerly and fails fast on unset vars.
    for mapping in &args.query_env {
        let Some((name, env_name)) = mapping.split_once(':') else {
            fail(format!(
                "Invalid --query-env mapping: {mapping} (expected NAME:ENV)"
            ));
        };
        if name.is_empty() || env_name.is_empty() || env_name.contains(':') {
            fail(format!(
                "Invalid --query-env mapping: {mapping} (expected NAME:ENV)"
            ));
        }
        if std::env::var(env_name).is_err() {
            fail(format!(
                "--query-env {mapping}: environment variable {env_name} is not set"
            ));
        }
    }

    // Credential mappings ENV:header[:prefix]: resolve the env values now so
    // unset variables exit before any traffic is replayed.
    let mut credentials: Vec<ReplayCredentialEnv> = Vec::new();
    for mapping in &args.credential_env {
        let parts: Vec<&str> = mapping.split(':').collect();
        if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
            fail(format!(
                "Invalid credential mapping: {mapping} (expected ENV:header[:prefix])"
            ));
        }
        let secret = std::env::var(parts[0]).unwrap_or_default();
        if secret.is_empty() {
            fail(format!(
                "Credential environment variable {} is not set",
                parts[0]
            ));
        }
        credentials.push(ReplayCredentialEnv {
            env_var: parts[0].to_string(),
            header: parts[1].to_string(),
            scheme: if parts.len() > 2 {
                Some(parts[2..].join(":"))
            } else {
                None
            },
        });
    }

    let options = ReplayOptions {
        target: Url::parse(&args.target)
            .unwrap_or_else(|e| fail(format!("Invalid --target URL '{}': {e}", args.target))),
        mode,
        credential_env: credentials.first().cloned(),
        query_env: args
            .query_env
            .iter()
            .filter_map(|m| m.split_once(':'))
            .map(|(name, env)| (name.to_string(), env.to_string()))
            .collect(),
        ignore_pointers: args.ignore_pointer.clone(),
        fail_on_diff: args.fail_on_diff,
        legacy_jsonl: false,
        allow_binary_media_types: Vec::new(),
        reject_secret_env: Vec::new(),
        delay_ms: parse_positive_int(&args.delay, "--delay", true),
    };

    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    let report = match runtime.block_on(crate::replay::replay_capture(input, &options)) {
        Ok(report) => report,
        Err(e) => fail(format!("Replay failed: {e}")),
    };

    let total = report.results.len();
    let stamped_report = super::output::stamped(super::output::SCHEMA_REPLAY_REPORT, &report);
    super::output::emit(
        fmt,
        || {
            println!("\nReplay Report:");
            println!("  Total:   {total}");
            println!("  Passed:  {}", report.matched);
            println!("  Failed:  {}", report.diffed);
            println!("  Errors:  {}", count_errors(&report.results));

            for result in &report.results {
                match &result.outcome {
                    crate::replay::ReplayOutcome::Match => {
                        if args.verbose {
                            println!("✓ #{}", result.sequence);
                        }
                    }
                    crate::replay::ReplayOutcome::Diff { detail } => {
                        println!("⚠ #{} — {detail}", result.sequence);
                    }
                    crate::replay::ReplayOutcome::Unreplayable { reason } => {
                        println!("⚠ #{} — {reason}", result.sequence);
                    }
                    crate::replay::ReplayOutcome::Error { message } => {
                        println!("✗ #{} — {message}", result.sequence);
                    }
                }
            }
        },
        &stamped_report,
    );

    if let Some(report_path) = args.report.as_deref() {
        // stamped_view keeps "schema" as the literal first key of the
        // written artifact.
        let serialized = serde_json::to_vec_pretty(&super::output::stamped_view(
            super::output::SCHEMA_REPLAY_REPORT,
            &report,
        ))
        .expect("replay report serializes");
        atomic_write_private(Path::new(report_path), &serialized).unwrap_or_else(|e| {
            fail(format!("Failed to write report {report_path}: {e}"));
        });
        println!("Report written to {report_path}");
    }

    if args.fail_on_diff && (report.diffed > 0 || count_errors(&report.results) > 0) {
        return 1;
    }
    0
}

/// Port of `runLegacyReplay` in src/commands/replay.ts. The unified engine
/// handles legacy traffic via `ReplayOptions.legacy_jsonl`.
fn run_legacy(args: &ReplayArgs, input: &str) -> i32 {
    if let Some(token) = args.token.as_deref() {
        // The engine reads the token from an env var; publish it privately.
        std::env::set_var("ARBITER_REPLAY_TOKEN", token);
    }
    let auth_manager = match args.token.as_deref() {
        Some(token) => crate::auth::AuthManager::from_token(token),
        None => crate::auth::AuthManager::new(),
    };
    if auth_manager.is_authenticated() {
        println!("Using auth token: {}", auth_manager.redacted_token());
    }
    println!("Replaying legacy traffic against {}", args.target);

    let mode = if args.only_status {
        ReplayMode::StatusOnly
    } else {
        mode_from_str(&args.mode)
    };

    let options = ReplayOptions {
        target: Url::parse(&args.target)
            .unwrap_or_else(|e| fail(format!("Invalid --target URL '{}': {e}", args.target))),
        mode,
        credential_env: args.token.as_deref().map(|_| ReplayCredentialEnv {
            env_var: "ARBITER_REPLAY_TOKEN".to_string(),
            header: "X-Plex-Token".to_string(),
            scheme: None,
        }),
        query_env: Vec::new(),
        ignore_pointers: args.ignore_pointer.clone(),
        fail_on_diff: args.fail_on_diff,
        legacy_jsonl: true,
        allow_binary_media_types: Vec::new(),
        reject_secret_env: Vec::new(),
        delay_ms: parse_positive_int(&args.delay, "--delay", true),
    };

    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    let report = match runtime.block_on(crate::replay::replay_capture(Path::new(input), &options)) {
        Ok(report) => report,
        Err(e) => fail(format!("Replay failed: {e}")),
    };

    let total = report.results.len();
    println!("\nReplay Report:");
    println!("  Total:     {total}");
    println!("  Passed:    {}", report.matched);
    println!("  Failed:    {}", report.diffed);
    println!("  Errors:    {}", count_errors(&report.results));

    for result in &report.results {
        match &result.outcome {
            crate::replay::ReplayOutcome::Match => {
                if args.verbose {
                    println!("✓ #{}", result.sequence);
                }
            }
            crate::replay::ReplayOutcome::Diff { detail } => {
                println!("⚠ #{} — {detail}", result.sequence);
            }
            crate::replay::ReplayOutcome::Unreplayable { reason } => {
                println!("⚠ #{} — {reason}", result.sequence);
            }
            crate::replay::ReplayOutcome::Error { message } => {
                println!("✗ #{} — ERROR: {message}", result.sequence);
            }
        }
    }

    if args.fail_on_diff && (report.diffed > 0 || count_errors(&report.results) > 0) {
        return 1;
    }
    0
}

fn mode_from_str(mode: &str) -> ReplayMode {
    match mode {
        "exact-response-body" => ReplayMode::ExactResponseBody,
        "semantic-json-response" => ReplayMode::SemanticJsonResponse,
        "semantic-sse-response" => ReplayMode::SemanticSseResponse,
        _ => ReplayMode::StatusOnly,
    }
}

fn count_errors(results: &[crate::replay::ReplayExchangeResult]) -> usize {
    results
        .iter()
        .filter(|r| matches!(r.outcome, crate::replay::ReplayOutcome::Error { .. }))
        .count()
}

#[cfg(test)]
mod tests {
    use super::super::output::{stamped, SCHEMA_REPLAY_REPORT};
    use crate::replay::{ReplayExchangeResult, ReplayMode, ReplayOutcome, ReplayReport};

    /// G4 + D4 regression: the replay report emits as valid JSON carrying
    /// the exact versioned schema discriminator, and round-trips.
    #[test]
    fn json_report_is_stamped_and_round_trips() {
        let report = ReplayReport {
            mode: ReplayMode::StatusOnly,
            results: vec![ReplayExchangeResult {
                sequence: 1,
                outcome: ReplayOutcome::Match,
            }],
            matched: 1,
            diffed: 0,
        };
        let stamped_report = stamped(SCHEMA_REPLAY_REPORT, &report);
        assert_eq!(
            stamped_report.get("schema").and_then(|s| s.as_str()),
            Some("arbiter.replay-report/v1")
        );

        // Full JSON round-trip (what `--json` consumers do).
        let text = serde_json::to_string(&stamped_report).expect("serialize");
        let back: serde_json::Value = serde_json::from_str(&text).expect("parse");
        assert_eq!(back["schema"], "arbiter.replay-report/v1");
        assert_eq!(back["matched"], 1);
        // The written --report artifact keeps "schema" as its literal
        // first key (struct field order in the pretty writer).
        let pretty = serde_json::to_string_pretty(&super::super::output::stamped_view(
            SCHEMA_REPLAY_REPORT,
            &report,
        ))
        .expect("pretty");
        assert!(
            pretty.starts_with("{\n  \"schema\":"),
            "schema must be first key: {pretty}"
        );
    }
}
