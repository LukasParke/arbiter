//! `arbiter start` (port of src/commands/start.ts).

use std::path::PathBuf;

use clap::Args;
use url::Url;

use super::{fail, parse_positive_int};

/// Start the proxy and documentation servers
#[derive(Args, Clone)]
pub struct StartArgs {
    /// target API URL to proxy to
    #[arg(short = 't', long = "target")]
    pub target: String,

    /// port to run the proxy server on
    #[arg(short = 'p', long = "port", default_value = "8080")]
    pub port: String,

    /// port to run the documentation server on
    #[arg(short = 'd', long = "docs-port", default_value = "9000")]
    pub docs_port: String,

    /// path to SQLite database file for persistence
    #[arg(long = "db-path")]
    pub db_path: Option<String>,

    /// run only the documentation server
    #[arg(long = "docs-only")]
    pub docs_only: bool,

    /// run only the proxy server
    #[arg(long = "proxy-only")]
    pub proxy_only: bool,

    /// path to an existing OpenAPI spec to diff against
    #[arg(long = "diff-against")]
    pub diff_against: Option<String>,

    /// exit with code 2 if captured endpoints are missing from the spec
    #[arg(long = "exit-on-gap")]
    pub exit_on_gap: bool,

    /// validate requests and responses against an OpenAPI spec in real-time
    #[arg(long = "validate")]
    pub validate: bool,

    /// path to OpenAPI spec for real-time validation (requires --validate)
    #[arg(short = 's', long = "spec")]
    pub spec: Option<String>,

    /// enable verbose logging
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

pub fn run(args: &StartArgs) -> i32 {
    println!("Starting Arbiter...");

    if args.validate {
        match args.spec.as_deref() {
            None => fail("Error: --validate requires --spec <path>"),
            Some(spec_path) => {
                // Mirror the TS SpecValidator constructor: load and parse the
                // spec up front so a bad file fails before the servers start.
                let loaded = std::fs::read_to_string(spec_path)
                    .map_err(|e| crate::error::Error::io("read spec", e))
                    .and_then(|raw| {
                        serde_json::from_str::<serde_json::Value>(&raw).map_err(|e| {
                            crate::error::Error::Json {
                                context: "parse spec".into(),
                                source: e,
                            }
                        })
                    })
                    .map(crate::validation::BasicOpenApiValidator::new);
                match loaded {
                    Ok(_) => println!("Real-time validation enabled using {spec_path}"),
                    Err(e) => fail(format!("Failed to load spec for validation: {e}")),
                }
            }
        }
    }

    let port: u16 = parse_positive_int(&args.port, "--port", true)
        .try_into()
        .unwrap_or_else(|_| {
            fail(format!(
                "--port must be an integer 0-65535 (got {})",
                args.port
            ))
        });
    let docs_port: u16 = parse_positive_int(&args.docs_port, "--docs-port", true)
        .try_into()
        .unwrap_or_else(|_| {
            fail(format!(
                "--docs-port must be an integer 0-65535 (got {})",
                args.docs_port
            ))
        });
    let target: Url = Url::parse(&args.target)
        .unwrap_or_else(|e| fail(format!("Invalid --target URL '{}': {e}", args.target)));

    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    runtime.block_on(run_async(args.clone(), target, port, docs_port))
}

async fn run_async(args: StartArgs, target: Url, port: u16, docs_port: u16) -> i32 {
    let servers = match crate::server::start_servers(crate::server::ServerOptions {
        target,
        port,
        docs_port,
        db_path: args.db_path.as_deref().map(PathBuf::from),
        docs_only: args.docs_only,
        proxy_only: args.proxy_only,
        verbose: args.verbose,
    })
    .await
    {
        Ok(servers) => servers,
        Err(e) => fail(format!("Failed to start servers: {e}")),
    };

    let signal_name = wait_for_signal().await;
    println!("\nReceived {signal_name}, shutting down...");
    (servers.shutdown).await;

    if let Some(diff_path) = args.diff_against.as_deref() {
        return shutdown_diff(diff_path, args.exit_on_gap);
    }

    0
}

/// Port of the diff-on-shutdown block in src/commands/start.ts.
fn shutdown_diff(spec_path: &str, exit_on_gap: bool) -> i32 {
    let result = match crate::diff::diff_against_spec(std::path::Path::new(spec_path)) {
        Ok(result) => result,
        Err(e) => fail(format!("Diff failed: {e}")),
    };

    println!("\nDiff Report:");
    println!("{}", pretty_json(&result.summary));

    if !result.missing_endpoints.is_empty() {
        println!("\nMissing endpoints:");
        for ep in &result.missing_endpoints {
            println!("  {} {}", ep.method, ep.path);
        }
    }
    if !result.query_param_gaps.is_empty() {
        println!("\nQuery param gaps:");
        for gap in &result.query_param_gaps {
            println!(
                "  {} {}: {}",
                gap.method,
                gap.path,
                gap.missing_query_params.join(", ")
            );
        }
    }
    if exit_on_gap && !result.missing_endpoints.is_empty() {
        return 2;
    }
    0
}

pub(super) async fn wait_for_signal() -> &'static str {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = wait_sigterm() => "SIGTERM",
    }
}

async fn wait_sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            term.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

pub(super) fn pretty_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("value serializes")
}
