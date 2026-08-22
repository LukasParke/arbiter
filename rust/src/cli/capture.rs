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
}

pub fn run(args: &CaptureArgs) -> i32 {
    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    runtime.block_on(run_async(args.clone()))
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

    let export = async {
        session.wait_for_idle().await;
        session
            .export(Some(ExportOptions {
                output: ctx.output.clone(),
                reject_secrets: ctx.reject_secrets.clone(),
                allow_binary_media_types: ctx.allow_binary_media_types.clone(),
            }))
            .await
    };
    match export.await {
        Ok(result) => {
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
        }
        Err(e) => {
            report["error"] = json!(e.to_string());
            eprintln!("Export failed: {e}");
            exit_code = 1;
        }
    }

    session.close().await.ok();

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
