//!
#![allow(dead_code)] // surfaces wired during M3d/next cutover
//! Single output funnel for every result-printing command (W7 DX bar).
//!
//! - [`emit`] routes between human rendering and `--json` output. JSON uses
//!   [`crate::json::stable_stringify`] so machine consumers get key-sorted,
//!   compact, byte-stable documents.
//! - [`print_error`] enforces the house error shape everywhere:
//!   `error: <cause>` followed by a best-effort `  help: <hint>` line.
//! - [`init_tracing`] + [`log`] provide timestamped diagnostics with zero new
//!   dependencies (no `tracing` crate — deps are frozen).
//!
//! Commands keep their own aligned-table human renderers; the funnel only
//! decides *which* representation runs.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use serde_json::Value;

use crate::error::Error;

/// Global output representation selected by the `--json` flag.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Aligned human-readable rendering (the default).
    #[default]
    Human,
    /// Machine-readable stable JSON on stdout.
    Json,
}

impl OutputFormat {
    /// Map a `--json` boolean flag (the current global flag shape) to a format.
    pub fn from_json_flag(json: bool) -> Self {
        if json {
            OutputFormat::Json
        } else {
            OutputFormat::Human
        }
    }
}

// ---------------------------------------------------------------------------
// emit
// ---------------------------------------------------------------------------

/// Print one command result.
///
/// `Human` runs the caller's closure (its own table/prose renderer writing to
/// stdout); `Json` prints `value` as stable JSON plus exactly one trailing
/// newline. Serialization of crate-owned types cannot fail in practice; if it
/// somehow does, a warning goes to stderr and `{}` is printed rather than
/// panicking (external input never panics — DX bar).
pub fn emit<T: Serialize>(fmt: OutputFormat, human: impl FnOnce(), value: T) {
    match fmt {
        OutputFormat::Human => human(),
        OutputFormat::Json => {
            let payload = serde_json::to_value(value).unwrap_or_else(|e| {
                eprintln!("warning: result is not representable as JSON ({e}); printing null");
                Value::Null
            });
            println!("{}", crate::json::stable_stringify(&payload));
        }
    }
}

/// Testable core of [`emit`]: serialize `value` to the exact stable-JSON
/// string the Json branch would print.
#[cfg(test)]
pub(crate) fn json_to_string<T: Serialize>(value: T) -> String {
    let payload = serde_json::to_value(value).unwrap_or(Value::Null);
    crate::json::stable_stringify(&payload)
}

// ---------------------------------------------------------------------------
// Errors: cause line + help hint
// ---------------------------------------------------------------------------

/// Best-effort remediation hint per error variant. Returns `None` only for
/// variants with no actionable advice (currently none — every variant has one).
pub fn hint_for(err: &Error) -> Option<&'static str> {
    Some(match err {
        Error::BundleValidation { .. } => {
            "verify the bundle was produced by arbiter and re-run `arbiter sanitize` if it came from an untrusted source"
        }
        Error::DigestMismatch => {
            "the bundle was modified after capture; regenerate it from source traffic or restore the original files"
        }
        Error::ExchangeCountMismatch { .. } => {
            "manifest.json and exchanges.ndjson disagree; the bundle is incomplete — recapture or fix the manifest exchangeCount"
        }
        Error::SecretFindings(_) => {
            "check --reject-secret values and secret-bearing environment variables; redact or allowlist before persisting"
        }
        Error::BodyLimitExceeded(_) => {
            "raise --max-body-bytes to accommodate larger bodies"
        }
        Error::SymlinkedPath(_) | Error::UnsafePath(_) => {
            "check bundle paths for symlinks or traversal segments; arbiter refuses to read/write through them"
        }
        Error::Io { .. } => {
            "check that the file exists and is readable, and that parent directories are writable"
        }
        Error::Json { .. } => {
            "check that the input is valid JSON (or YAML for OpenAPI specs)"
        }
        Error::Storage(_) => {
            "check the SQLite database path and permissions; delete a corrupt --db-path to rebuild"
        }
        Error::Http(_) => {
            "verify the target URL is reachable and the upstream is running; retry with --verbose for detail"
        }
        Error::Tls(_) => {
            r#"run `arbiter ca` and trust the generated CA in your OS/browser trust store, or pass --tls-passthrough / --no-tls-intercept"#
        }
        Error::WebsocketNotReplayable { .. } => {
            "use mock serve mode or status-only replay (--mode status-only); WebSocket streams cannot be replayed over HTTP replay modes"
        }
        Error::Other(_) => {
            "re-run with --verbose for more detail; see `arbiter --help` for flags"
        }
    })
}

/// Print an error in the two-line house format to stderr:
/// `error: <cause>` then `  help: <hint>`.
pub fn print_error(err: &Error) {
    eprintln!("error: {err}");
    if let Some(hint) = hint_for(err) {
        eprintln!("  help: {hint}");
    }
}

// ---------------------------------------------------------------------------
// Tracing-free logging
// ---------------------------------------------------------------------------

static VERBOSE: AtomicBool = AtomicBool::new(false);
static JSON_LOGS: AtomicBool = AtomicBool::new(false);

/// Log levels for [`log`], ordered by increasing severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

/// Install the global log filter. `verbose` enables debug/info lines; without
/// it only warn/error surface. `json` switches every line to a single-line
/// JSON object (`{"level","message","ts"}`) instead of `<ts> LEVEL message`.
/// Deliberately no `tracing` dependency: deps are frozen and these two knobs
/// cover the CLI's needs.
pub fn init_tracing(verbose: bool, json: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
    JSON_LOGS.store(json, Ordering::Relaxed);
}

/// Emit one timestamped diagnostic line to stderr. Debug/info are suppressed
/// unless verbose logging was enabled by [`init_tracing`].
pub fn log(level: LogLevel, message: impl std::fmt::Display) {
    if level <= LogLevel::Info && !VERBOSE.load(Ordering::Relaxed) {
        return;
    }
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if JSON_LOGS.load(Ordering::Relaxed) {
        // serde_json guarantees valid encoding of the message string.
        eprintln!(
            "{}",
            serde_json::json!({
                "ts": ts,
                "level": level.as_str(),
                "message": message.to_string(),
            })
        );
    } else {
        eprintln!("{ts} {:<5} {message}", level.as_str());
    }
}

/// Convenience wrappers used across commands.
pub fn log_info(message: impl std::fmt::Display) {
    log(LogLevel::Info, message);
}
/// See [`log`].
pub fn log_warn(message: impl std::fmt::Display) {
    log(LogLevel::Warn, message);
}
/// See [`log`].
pub fn log_error(message: impl std::fmt::Display) {
    log(LogLevel::Error, message);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, SecretFindingError};
    use crate::secret_scan::SecretFinding;
    use serde_json::json;

    #[derive(Serialize)]
    struct Sample<'a> {
        zeta: u32,
        alpha: &'a str,
    }

    #[test]
    fn json_branch_prints_stable_sorted_compact() {
        let out = json_to_string(Sample {
            zeta: 1,
            alpha: "x",
        });
        assert_eq!(out, r#"{"alpha":"x","zeta":1}"#);
    }

    #[test]
    fn emit_routes_human_vs_json() {
        // Human: the closure runs; no stdout assertion needed beyond execution.
        let mut human_ran = false;
        emit(
            OutputFormat::Human,
            || human_ran = true,
            Sample { zeta: 0, alpha: "" },
        );
        assert!(human_ran);

        // Human never serializes: even a value that fails serialization is fine.
        emit(
            OutputFormat::Human,
            || {},
            serde_json::to_value(f64::NAN).unwrap_or(Value::Null), // NaN is not valid JSON
        );

        // Json: routed through stable stringify regardless of field order.
        assert_eq!(
            json_to_string(json!({ "b": [1, 2], "a": true })),
            r#"{"a":true,"b":[1,2]}"#
        );
    }

    #[test]
    fn format_from_json_flag() {
        assert_eq!(OutputFormat::from_json_flag(true), OutputFormat::Json);
        assert_eq!(OutputFormat::from_json_flag(false), OutputFormat::Human);
    }

    // -- print_error hint coverage ------------------------------------------

    /// Every constructible variant yields a non-empty help hint, and the
    /// specific variants called out in the spec map to their documented hints.
    #[test]
    fn hint_table_covers_every_error_variant() {
        let secret_err = Error::SecretFindings(SecretFindingError {
            findings: vec![SecretFinding {
                location: "exchange 1 header".into(),
                kind: "sk-ant-".into(),
            }],
        });
        let cases: Vec<(Error, &'static str)> = vec![
            (
                Error::bundle_validation("exchanges.ndjson:4", "missing status"),
                "sanitize",
            ),
            (Error::DigestMismatch, "modified"),
            (
                Error::ExchangeCountMismatch {
                    declared: 3,
                    actual: 2,
                },
                "exchangeCount",
            ),
            (secret_err, "--reject-secret"),
            (
                Error::BodyLimitExceeded("request body 40 MiB".into()),
                "--max-body-bytes",
            ),
            (Error::SymlinkedPath("bodies/abc.bin".into()), "symlink"),
            (Error::UnsafePath("../escape".into()), "traversal"),
            (
                Error::Io {
                    context: "read config".into(),
                    source: std::io::Error::new(std::io::ErrorKind::NotFound, "nope"),
                },
                "file exists",
            ),
            (
                Error::Json {
                    context: "parse report".into(),
                    source: serde_json::from_str::<Value>("{").unwrap_err(),
                },
                "valid JSON",
            ),
            (Error::Storage("locked db".into()), "SQLite"),
            (Error::Http("connect refused".into()), "reachable"),
            (Error::Other("misc".into()), "--verbose"),
        ];
        for (err, needle) in cases {
            let hint = hint_for(&err).expect("every variant must carry a hint");
            assert!(
                hint.to_lowercase().contains(&needle.to_lowercase()),
                "hint for {err:?} should mention {needle:?}, got: {hint}"
            );
            assert!(!hint.contains('\n'), "hints stay on one line: {hint}");
        }
    }

    #[test]
    fn tls_and_websocket_hints_match_documented_remediations() {
        // Constructible TLS variant: CaGeneration(String) is the simplest arm.
        let tls = Error::Tls(crate::tls::TlsError::CaGeneration("no entropy".into()));
        let tls_hint = hint_for(&tls).unwrap();
        assert!(tls_hint.contains("`arbiter ca`"), "got: {tls_hint}");
        assert!(tls_hint.contains("--tls-passthrough"));

        let ws = Error::WebsocketNotReplayable { seq: 7 };
        let ws_hint = hint_for(&ws).unwrap();
        assert!(
            ws_hint.contains("status-only") && ws_hint.contains("mock serve"),
            "got: {ws_hint}"
        );
    }

    // -- logging --------------------------------------------------------------

    #[test]
    fn init_tracing_flips_filters_without_panicking() {
        // No global-state assertions possible without process isolation;
        // exercise both configurations so any panic/regression surfaces.
        init_tracing(true, false);
        log_debug_witness();
        init_tracing(false, true);
        log_warn("structured witness");
        init_tracing(false, false);
    }

    fn log_debug_witness() {
        log(LogLevel::Debug, "witness");
    }
}
