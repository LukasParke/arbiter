//! `arbiter capture` (port of src/commands/capture.ts).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Args;
use serde_json::json;
use url::Url;

use super::start::wait_for_signal;
use super::{absolute_path, atomic_write_private, fail, parse_positive_int};
use crate::capture::{start_capture_session, CaptureSessionOptions, ExportOptions};
use crate::redaction::{RedactionPolicy, RedactionPolicyOptions};
use crate::types::CaptureMode;

/// Run an exact-capture proxy and export a deterministic capture bundle on shutdown
#[derive(Args, Clone)]
pub struct CaptureArgs {
    /// upstream API origin to proxy to
    #[arg(short = 't', long = "target")]
    pub target: String,

    /// directory to write the capture bundle to
    #[arg(short = 'o', long = "output")]
    pub output: String,

    /// port to listen on (0 = random)
    #[arg(short = 'p', long = "port", default_value = "0")]
    pub port: String,

    /// hostname to bind
    #[arg(long = "host", default_value = "127.0.0.1")]
    pub host: String,

    /// fail-closed exact capture semantics (recommended)
    #[arg(long = "exact")]
    pub exact: bool,

    /// additional header name/glob to redact (repeatable)
    #[arg(long = "redact-header")]
    pub redact_header: Vec<String>,

    /// query parameter whose value may be kept (repeatable)
    #[arg(long = "allow-query")]
    pub allow_query: Vec<String>,

    /// name of an env var whose value must not appear anywhere in the bundle (repeatable)
    #[arg(long = "reject-secret")]
    pub reject_secret: Vec<String>,

    /// media type prefix allowed to remain unscanned binary (repeatable)
    #[arg(long = "allow-binary-media-type")]
    pub allow_binary_media_type: Vec<String>,

    /// body size limit before spilling to disk
    #[arg(long = "max-body-bytes", default_value_t = String::from("33554432"))]
    pub max_body_bytes: String,

    /// shut down after this many ms without traffic
    #[arg(long = "idle-timeout")]
    pub idle_timeout: Option<String>,

    /// write listener metadata JSON atomically once ready
    #[arg(long = "ready-file")]
    pub ready_file: Option<String>,

    /// write a machine-readable final report on shutdown
    #[arg(long = "report")]
    pub report: Option<String>,

    /// overwrite a non-empty --output directory
    #[arg(long = "force")]
    pub force: bool,
}

pub fn run(args: &CaptureArgs, fmt: crate::cli::output::OutputFormat) -> i32 {
    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    let code = runtime.block_on(run_async(args.clone()));
    if code == 0 {
        if let Some(result) = last_export() {
            crate::cli::output::emit(
                fmt,
                || {
                    println!(
                        "Exported {} exchange(s) to {}",
                        result.manifest.exchange_count,
                        result.output_dir.display()
                    )
                },
                serde_json::json!({
                    "schema": "arbiter.capture-summary/v1",
                    "outputDir": result.output_dir,
                    "exchangeCount": result.manifest.exchange_count,
                    "bundleDigest": result.manifest.bundle_digest,
                }),
            );
        }
    }
    code
}

thread_local! {
    static LAST_EXPORT: std::cell::RefCell<Option<crate::capture::ExportResult>> =
        const { std::cell::RefCell::new(None) };
}

fn remember_export(result: crate::capture::ExportResult) {
    LAST_EXPORT.with(|cell| *cell.borrow_mut() = Some(result));
}

fn last_export() -> Option<crate::capture::ExportResult> {
    LAST_EXPORT.with(|cell| cell.borrow().clone())
}

/// B2: a capture bundle directory must never be silently overwritten.
/// Refuse when the path exists with content (or exists as a plain file)
/// unless `--force` was passed; an empty existing directory or an absent
/// path is fine.
fn ensure_output_writable(output: &str, force: bool) -> Result<(), String> {
    let path = std::path::Path::new(output);
    if !path.exists() || force {
        return Ok(());
    }
    let empty = path.is_dir()
        && path
            .read_dir()
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
    if empty {
        return Ok(());
    }
    Err(format!(
        "refusing to overwrite existing bundle directory '{output}'\n  help: choose a new --output, remove it, or pass --force"
    ))
}

async fn run_async(args: CaptureArgs) -> i32 {
    let port = parse_positive_int(&args.port, "--port", true);
    let max_body_bytes = parse_positive_int(&args.max_body_bytes, "--max-body-bytes", false);
    let idle_timeout_ms = args
        .idle_timeout
        .as_deref()
        .map(|raw| parse_positive_int(raw, "--idle-timeout", false));

    let mut reject_secrets: Vec<String> = Vec::new();
    for env_name in &args.reject_secret {
        match std::env::var(env_name) {
            Ok(value) if !value.is_empty() => reject_secrets.push(value),
            _ => fail(format!(
                "--reject-secret {env_name}: environment variable is not set"
            )),
        }
    }

    let target: Url = Url::parse(&args.target)
        .unwrap_or_else(|e| fail(format!("Invalid --target URL '{}': {e}", args.target)));
    let listen_host: std::net::IpAddr = args
        .host
        .parse()
        .unwrap_or_else(|_| fail(format!("Invalid --host '{}'", args.host)));
    let listen_port: u16 = port.try_into().unwrap_or_else(|_| {
        fail(format!(
            "--port must be an integer 0-65535 (got {})",
            args.port
        ))
    });

    // B2: fail fast, before any listener binds, when --output would clobber
    // an existing non-empty directory without --force.
    if let Err(message) = ensure_output_writable(&args.output, args.force) {
        fail(message);
    }

    let mode = if args.exact {
        CaptureMode::Exact
    } else {
        CaptureMode::Observe
    };
    let mode_label = mode.as_str();

    let redaction = RedactionPolicy::new(&RedactionPolicyOptions {
        redact_headers: args.redact_header.clone(),
        allow_query: args.allow_query.clone(),
    });

    let session = match start_capture_session(CaptureSessionOptions {
        target: target.clone(),
        listen_host,
        listen_port,
        mode,
        redaction,
        max_body_bytes: Some(max_body_bytes),
        idle_timeout_ms,
        // Session-level output so ANY shutdown path (idle watchdog, signal)
        // exports the bundle to the user's chosen directory.
        output: Some(std::path::PathBuf::from(&args.output)),
        ..CaptureSessionOptions::default()
    })
    .await
    {
        Ok(session) => session,
        Err(e) => fail(format!("Failed to start capture proxy: {e}")),
    };

    println!("Arbiter capture proxy listening");
    println!("  Proxy:  {}", session.url());
    println!("  Target: {}", args.target);
    println!(
        "  Mode:   {}",
        if args.exact {
            "exact (fail-closed)"
        } else {
            "observe"
        }
    );

    if let Some(ready_file) = args.ready_file.as_deref() {
        let payload = session
            .ready_info()
            .await
            .unwrap_or_else(|e| fail(format!("Failed to build ready metadata: {e}")));
        let serialized = serde_json::to_vec(&payload).expect("ready info serializes");
        atomic_write_private(std::path::Path::new(ready_file), &serialized)
            .unwrap_or_else(|e| fail(format!("Failed to write ready file {ready_file}: {e}")));
    }

    // Idle watchdog: re-armed whenever the settled exchange count grows
    // (mirrors the setInterval re-arm loop in src/commands/capture.ts).
    let mut last_count = session.exchanges().await.len();
    let mut idle_deadline = idle_timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let shutdown_code = loop {
        tokio::select! {
            signal_name = wait_for_signal() => {
                let _ = signal_name;
                break 0u32;
            }
            _ = ticker.tick() => {
                let count = session.exchanges().await.len();
                if count != last_count {
                    last_count = count;
                    if let Some(ms) = idle_timeout_ms {
                        idle_deadline = Some(Instant::now() + Duration::from_millis(ms));
                    }
                }
                if let Some(deadline) = idle_deadline {
                    if Instant::now() >= deadline {
                        println!("Idle timeout reached, shutting down");
                        break 0;
                    }
                }
            }
        }
    };

    shutdown(
        session,
        shutdown_code,
        ShutdownContext {
            target: args.target.clone(),
            mode_label: mode_label.to_string(),
            output: PathBuf::from(&args.output),
            report_path: args.report.clone().map(PathBuf::from),
            reject_secrets,
            allow_binary_media_types: args.allow_binary_media_type.clone(),
        },
    )
    .await
}

struct ShutdownContext {
    target: String,
    mode_label: String,
    output: PathBuf,
    report_path: Option<PathBuf>,
    reject_secrets: Vec<String>,
    allow_binary_media_types: Vec<String>,
}

/// Port of `shutdown()` in src/commands/capture.ts. Never returns.
async fn shutdown(session: crate::capture::CaptureSession, code: u32, ctx: ShutdownContext) -> ! {
    let mut exit_code = if code == 0 { 0i32 } else { 1 };
    let exchanges = session.exchanges().await;
    let failures = session.failures().await;
    let mut report = json!({
        "target": ctx.target,
        "mode": ctx.mode_label,
        "exchangeCount": exchanges.len(),
        "failures": failures,
        "bundle": serde_json::Value::Null,
        "error": serde_json::Value::Null,
    });

    // B1: close() enforces the shutdown grace itself — in-flight exchanges
    // past the deadline are finalized as partial captures and the bundle is
    // always written, so a hung upstream can never lose the recording.
    match session
        .close_with_export(Some(ExportOptions {
            output: ctx.output.clone(),
            reject_secrets: ctx.reject_secrets.clone(),
            allow_binary_media_types: ctx.allow_binary_media_types.clone(),
        }))
        .await
    {
        Ok(result) => {
            remember_export(result.clone());
            report["bundle"] = json!({
                "path": absolute_path(&result.output_dir).to_string_lossy(),
                "exchangeCount": result.manifest.exchange_count,
                "bundleDigest": result.manifest.bundle_digest,
            });
            println!(
                "Exported {} exchange(s) to {}",
                result.manifest.exchange_count,
                ctx.output.display()
            );
            if result.interrupted_exchanges > 0 {
                eprintln!(
                    "warning: {} exchange(s) finalized as incomplete due to interrupt",
                    result.interrupted_exchanges
                );
            }
        }
        Err(e) => {
            report["error"] = json!(e.to_string());
            eprintln!("Export failed: {e}");
            exit_code = 1;
        }
    }

    if let Some(report_path) = &ctx.report_path {
        let serialized = serde_json::to_vec_pretty(&report).expect("report serializes");
        atomic_write_private(report_path, &serialized).unwrap_or_else(|e| {
            fail(format!(
                "Failed to write report {}: {e}",
                report_path.display()
            ))
        });
    }

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_guard_refuses_populated_dir_without_force() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("manifest.json"), b"{}").expect("seed entry");
        let error = ensure_output_writable(dir.path().to_str().expect("utf8 tempdir"), false)
            .expect_err("populated dir refused");
        assert!(error.contains("refusing to overwrite existing bundle directory"));
        assert!(error.contains("pass --force"));
    }

    #[test]
    fn output_guard_refuses_plain_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("bundle");
        std::fs::write(&file, b"not a directory").expect("seed file");
        assert!(ensure_output_writable(file.to_str().expect("utf8"), false).is_err());
    }

    #[test]
    fn output_guard_allows_force_absent_and_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let populated = dir.path().join("populated");
        std::fs::create_dir(&populated).expect("mkdir");
        std::fs::write(populated.join("exchanges.ndjson"), b"").expect("seed entry");
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).expect("mkdir");
        let absent = dir.path().join("absent");

        // --force overrides even a populated directory.
        assert!(ensure_output_writable(populated.to_str().expect("utf8"), true).is_ok());
        // An empty existing directory is fine without --force.
        assert!(ensure_output_writable(empty.to_str().expect("utf8"), false).is_ok());
        // An absent path is fine.
        assert!(ensure_output_writable(absent.to_str().expect("utf8"), false).is_ok());
    }

    #[test]
    fn force_flag_parses_and_defaults_false() {
        let parse = |extra: &[&str]| {
            let mut argv = vec![
                "capture",
                "--target",
                "http://127.0.0.1",
                "--output",
                "/tmp/b",
            ];
            argv.extend_from_slice(extra);
            let command = <CaptureArgs as clap::Args>::augment_args(clap::Command::new("capture"));
            let matches = command
                .try_get_matches_from(argv)
                .expect("capture args parse");
            <CaptureArgs as clap::FromArgMatches>::from_arg_matches(&matches)
                .expect("arg round-trip")
        };

        assert!(!parse(&[]).force);
        assert!(parse(&["--force"]).force);
    }
}
