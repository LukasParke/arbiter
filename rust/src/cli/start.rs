//! `arbiter start` (port of src/commands/start.ts), assembled at M3d from the
//! typed feature exports per AMEND-11:
//!
//! - TLS/CA flags from `cli::ca::CaArgs` (tls-intercept)
//! - fault knobs via `mock::fault::FaultConfig::from_cli` (mock-engine)
//! - header rules via `rules::HeaderRuleSet::from_cli` (hooks-modify)
//! - hooks via `rules::hooks::HookConfig::from_cli` (hooks-modify)
//! - live validation via `validation::violations::{ValidateFlags, LiveValidator}`
//! - layered config via `config` (defaults < file < env < CLI, AMEND-3)
//!
//! Output and error routing go through `cli::output`.

use std::path::PathBuf;

use clap::parser::ValueSource;
use clap::{ArgMatches, Args};
use std::sync::Arc;
use url::Url;

use crate::cli::output::print_error;
use crate::config::{self, FileConfig};
use crate::error::{Error, Result};
use crate::mock::fault::{FaultConfig, FaultInjector, FaultKind};
use crate::rules::hooks::HookConfig;
use crate::rules::HeaderRuleSet;
use crate::server::intercept::InterceptTlsConfig;
use crate::validation::violations::ValidateFlags;

use super::{fail, parse_positive_int};

/// Start the proxy and documentation servers
///
/// Examples:
///   arbiter start -t https://api.anthropic.com
///   arbiter start -t https://api.openai.com --no-tls-intercept --fault-status 503
///   arbiter start -t https://x --validate-spec openapi.yaml --fail-on-violation
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

    /// config file overriding the default location
    /// ($ARBITER_CONFIG or ~/.config/arbiter/config.toml)
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// TLS / certificate-authority flags (AMEND-11 typed surface)
    #[command(flatten)]
    pub tls: crate::cli::ca::CaArgs,

    /// live OpenAPI validation flags (AMEND-11 typed surface)
    #[command(flatten)]
    pub validate_flags: ValidateFlags,

    /// Inject latency before faulted responses (milliseconds).
    /// Example: --fault-latency-ms 250
    #[arg(long, value_name = "MS")]
    pub fault_latency_ms: Option<u64>,

    /// Replace faulted responses with this HTTP status code (100-599).
    /// Example: --fault-status 503
    #[arg(long, value_name = "CODE")]
    pub fault_status: Option<u16>,

    /// Hard error injected on faulted requests: reset (drop connection),
    /// timeout (never answer), garbage (random bytes).
    /// Example: --fault-error reset
    #[arg(long, value_enum, value_name = "reset|timeout|garbage")]
    pub fault_error: Option<FaultKind>,

    /// Percent of proxied requests that receive faults (0-100).
    /// Example: --fault-fraction 20
    #[arg(long, default_value_t = 100, value_name = "PCT")]
    pub fault_fraction: u8,

    /// Request-direction header rewrite rule, repeatable:
    /// `set:Name=Value`, `append:Name=Value`, `remove:Name`, `rename:Old=New`.
    #[arg(long = "request-header-rule", value_name = "SPEC")]
    pub request_header_rules: Vec<String>,

    /// Response-direction header rewrite rule, repeatable (same syntax).
    #[arg(long = "response-header-rule", value_name = "SPEC")]
    pub response_header_rules: Vec<String>,

    /// External hook command run on requests.
    #[arg(long, value_name = "CMD")]
    pub on_request: Option<String>,

    /// External hook command run on responses.
    #[arg(long, value_name = "CMD")]
    pub on_response: Option<String>,

    /// Long-lived hook server URL instead of per-exchange subprocesses.
    #[arg(long, value_name = "URL")]
    pub hook_server: Option<String>,

    /// Hook call timeout in milliseconds (default 5000).
    #[arg(long, value_name = "MS")]
    pub hook_timeout_ms: Option<u64>,
}

/// True when the CLI flag was explicitly passed on the command line. Direct
/// calls without matches (library/tests) treat every value as explicit, which
/// reproduces the historical no-config behavior exactly. Unknown ids count as
/// explicit too — this must never panic on external input.
fn cli_set(matches: Option<&ArgMatches>, id: &str) -> bool {
    let Some(m) = matches else {
        return true;
    };
    if !m.contains_id(id) {
        return true;
    }
    m.value_source(id) == Some(ValueSource::CommandLine)
}

/// Fold the config file (already env-applied) under the CLI args, mutating
/// `args` into the effective configuration. Only unset/implicit CLI values
/// are replaced; an explicit flag always wins.
fn apply_layers(args: &mut StartArgs, matches: Option<&ArgMatches>, cfg: &FileConfig) {
    let set = |id: &str| cli_set(matches, id);

    // [start]
    if !set("target") {
        if let Some(t) = &cfg.start.target {
            args.target = t.clone();
        }
    }
    if !set("port") {
        if let Some(p) = cfg.start.port {
            args.port = p.to_string();
        }
    }
    if !set("docs_port") {
        if let Some(p) = cfg.start.docs_port {
            args.docs_port = p.to_string();
        }
    }
    if args.db_path.is_none() {
        if let Some(p) = &cfg.start.db_path {
            args.db_path = Some(p.to_string_lossy().into_owned());
        }
    }
    if !set("docs_only") {
        args.docs_only = cfg.start.docs_only;
    }
    if !set("proxy_only") {
        args.proxy_only = cfg.start.proxy_only;
    }
    if !set("verbose") {
        args.verbose = cfg.start.verbose;
    }

    // [proxy] TLS
    if !set("ca_dir") {
        if let Some(d) = &cfg.proxy.ca_dir {
            args.tls.ca_dir = d.to_string_lossy().into_owned();
        }
    }
    if !set("no_tls_intercept") {
        args.tls.no_tls_intercept = cfg.proxy.no_tls_intercept;
    }
    if args.tls.tls_passthrough.is_empty() {
        args.tls.tls_passthrough = cfg.proxy.tls_passthrough.clone();
    }
    if args.tls.tls_cert.is_none() {
        args.tls.tls_cert = cfg.proxy.tls_cert.clone();
    }
    if args.tls.tls_key.is_none() {
        args.tls.tls_key = cfg.proxy.tls_key.clone();
    }

    // [proxy] fault (AMEND-5: same FaultConfig shape as mock mode)
    if args.fault_latency_ms.is_none() {
        args.fault_latency_ms = cfg.proxy.fault.latency_ms;
    }
    if args.fault_status.is_none() {
        args.fault_status = cfg.proxy.fault.status;
    }
    if args.fault_error.is_none() {
        if let Some(kind) = cfg.proxy.fault.error.as_deref().and_then(parse_fault_kind) {
            args.fault_error = Some(kind);
        }
    }
    if !set("fault_fraction") {
        if let Some(f) = cfg.proxy.fault.fraction_pct {
            args.fault_fraction = f.min(100) as u8;
        }
    }

    // [proxy] header rules + hooks
    if args.request_header_rules.is_empty() {
        args.request_header_rules = cfg.proxy.request_header_rules.clone();
    }
    if args.response_header_rules.is_empty() {
        args.response_header_rules = cfg.proxy.response_header_rules.clone();
    }
    if args.on_request.is_none() {
        args.on_request = cfg.proxy.on_request.clone();
    }
    if args.on_response.is_none() {
        args.on_response = cfg.proxy.on_response.clone();
    }
    if args.hook_server.is_none() {
        args.hook_server = cfg.proxy.hook_server.clone();
    }
    if args.hook_timeout_ms.is_none() {
        args.hook_timeout_ms = cfg.proxy.hook_timeout_ms;
    }
}

/// Config-file spelling (`reset|timeout|garbage`) → [`FaultKind`].
fn parse_fault_kind(raw: &str) -> Option<FaultKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "reset" => Some(FaultKind::Reset),
        "timeout" => Some(FaultKind::Timeout),
        "garbage" => Some(FaultKind::Garbage),
        _ => None,
    }
}

/// Load the config file for `start` and fold its layers under the parsed CLI
/// args. Missing file = pure defaults; a broken file aborts with cause+help.
fn resolve_layered(args: &StartArgs, matches: Option<&ArgMatches>) -> Result<StartArgs> {
    let mut layered = args.clone();
    let path = args.config.clone().unwrap_or_else(config::default_path);
    let mut cfg = config::load_or_default(&path)?;
    config::apply_env_layer(&mut cfg)?;
    apply_layers(&mut layered, matches, &cfg);
    Ok(layered)
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Direct entry (library/tests): no config layering, every value explicit.
pub fn run(args: &StartArgs) -> i32 {
    run_layered(args, None)
}

/// Assembled entry used by `cli::run`: layers config file + environment under
/// the explicitly-passed CLI flags, then starts the servers.
pub fn run_layered(args: &StartArgs, matches: Option<&ArgMatches>) -> i32 {
    let layered = match resolve_layered(args, matches) {
        Ok(layered) => layered,
        Err(e) => {
            print_error(&e);
            return 1;
        }
    };
    run_resolved(&layered)
}

fn run_resolved(args: &StartArgs) -> i32 {
    println!("Starting Arbiter...");

    if args.validate {
        match args.spec.as_deref() {
            None => fail("Error: --validate requires --spec <path>"),
            Some(spec_path) => {
                // Mirror the TS SpecValidator constructor: load and parse the
                // spec up front so a bad file fails before the servers start.
                let loaded = std::fs::read_to_string(spec_path)
                    .map_err(|e| Error::io("read spec", e))
                    .and_then(|raw| {
                        serde_json::from_str::<serde_json::Value>(&raw).map_err(|e| Error::Json {
                            context: "parse spec".into(),
                            source: e,
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

    // Typed surfaces → engine options. Invalid values abort with cause+help
    // before any socket binds (DX bar).
    let fault = match build_fault(args) {
        Ok(fault) => fault,
        Err(e) => {
            print_error(&e);
            return 1;
        }
    };
    let header_rules = match build_header_rules(args) {
        Ok(rules) => rules,
        Err(e) => {
            print_error(&e);
            return 1;
        }
    };
    let hooks = match build_hooks(args) {
        Ok(hooks) => hooks,
        Err(e) => {
            print_error(&e);
            return 1;
        }
    };
    if args.validate_flags.wants_validation() {
        // Fail fast on a bad spec before binding; the validator itself is
        // loaded on the async path (spawn_blocking inside `load`).
        let path = args.validate_flags.spec_path().expect("checked above");
        if !path.is_file() {
            let e = Error::io(
                format!("read --validate-spec {}", path.display()),
                std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
            );
            print_error(&e);
            return 1;
        }
    }

    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    runtime.block_on(run_async(
        args.clone(),
        target,
        port,
        docs_port,
        fault,
        header_rules,
        hooks,
    ))
}

fn build_fault(args: &StartArgs) -> Result<Option<FaultInjector>> {
    let cfg = FaultConfig::from_cli(
        args.fault_latency_ms,
        args.fault_status,
        args.fault_error,
        args.fault_fraction,
    )?;
    Ok(if cfg.is_enabled() {
        Some(FaultInjector::new(cfg))
    } else {
        None
    })
}

fn build_header_rules(args: &StartArgs) -> Result<Option<(HeaderRuleSet, HeaderRuleSet)>> {
    if args.request_header_rules.is_empty() && args.response_header_rules.is_empty() {
        return Ok(None);
    }
    Ok(Some(HeaderRuleSet::from_cli(
        &args.request_header_rules,
        &args.response_header_rules,
    )?))
}

fn build_hooks(args: &StartArgs) -> Result<Option<HookConfig>> {
    let cfg = HookConfig::from_cli(
        args.on_request.as_deref(),
        args.on_response.as_deref(),
        args.hook_server.as_deref(),
        args.hook_timeout_ms,
    )?;
    Ok(if cfg.is_configured() { Some(cfg) } else { None })
}

async fn run_async(
    args: StartArgs,
    target: Url,
    port: u16,
    docs_port: u16,
    fault: Option<FaultInjector>,
    header_rules: Option<(HeaderRuleSet, HeaderRuleSet)>,
    hooks: Option<HookConfig>,
) -> i32 {
    // TLS interception: resolve-or-generate the CA unless disabled.
    let intercept = if args.tls.no_tls_intercept {
        None
    } else {
        match build_intercept(&args.tls).await {
            Ok(intercept) => Some(intercept),
            Err(e) => {
                print_error(&e);
                return 1;
            }
        }
    };

    // Live OpenAPI validation (W7 seam; consumed by the proxy pipeline).
    let mut validation_collector: Option<Arc<crate::validation::violations::ViolationsCollector>> =
        None;
    let validate = if args.validate_flags.wants_validation() {
        let path = args.validate_flags.spec_path().expect("checked above");
        match crate::validation::violations::LiveValidator::load(path).await {
            Ok(validator) => {
                validation_collector = Some(Arc::clone(&validator.collector));
                println!(
                    "Live validation enabled against {} (--report {}, exit {} on violations)",
                    path.display(),
                    args.validate_flags
                        .report
                        .as_deref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "none".into()),
                    if args.validate_flags.fail_on_violation {
                        "nonzero"
                    } else {
                        "zero"
                    }
                );
                Some(Arc::new(validator))
            }
            Err(e) => {
                print_error(&e);
                return 1;
            }
        }
    } else {
        None
    };

    let servers = match crate::server::start_servers(crate::server::ServerOptions {
        target,
        port,
        docs_port,
        db_path: args.db_path.as_deref().map(PathBuf::from),
        docs_only: args.docs_only,
        proxy_only: args.proxy_only,
        verbose: args.verbose,
        intercept,
        fault,
        header_rules,
        hooks,
        validate,
    })
    .await
    {
        Ok(servers) => servers,
        Err(e) => fail(format!("Failed to start servers: {e}")),
    };

    let signal_name = wait_for_signal().await;
    println!("\nReceived {signal_name}, shutting down...");
    (servers.shutdown).await;

    // Validation report + exit semantics (W7/W14 seam).
    if let Some(collector) = validation_collector {
        let summary = collector.summary();
        if let Some(report) = args.validate_flags.report.as_deref() {
            if let Err(e) = collector.shutdown_report(std::path::Path::new(report)) {
                print_error(&e);
                return 1;
            }
            println!("Validation report written to {}", report.display());
        }
        if summary.total > 0 {
            println!("Validation: {} violation(s) recorded", summary.total);
        }
        return crate::validation::violations::exit_code(
            &summary,
            args.validate_flags.fail_on_violation,
        );
    }

    if let Some(diff_path) = args.diff_against.as_deref() {
        return shutdown_diff(diff_path, args.exit_on_gap);
    }

    0
}

/// Resolve-or-generate the CA and compile passthrough rules into the
/// interception config (M3a typed surface).
async fn build_intercept(tls: &crate::cli::ca::CaArgs) -> Result<InterceptTlsConfig> {
    use crate::server::connect::PassthroughRules;
    use crate::tls::ca::ensure_ca;
    use crate::tls::leaf::LeafCache;

    if tls.tls_cert.is_some() != tls.tls_key.is_some() {
        return Err(Error::other(
            "--tls-cert and --tls-key must be given together\n  help: pass both for downstream reverse-proxy TLS",
        ));
    }

    let dir = crate::cli::ca::expand_tilde(&tls.ca_dir)?;
    let cert_path = tls
        .ca_cert
        .clone()
        .unwrap_or_else(|| dir.join(crate::tls::ca::CA_CERT_FILE));
    let key_path = tls
        .ca_key
        .clone()
        .unwrap_or_else(|| dir.join(crate::tls::ca::CA_KEY_FILE));
    let ca = ensure_ca(&dir, tls.ca_alg.into(), &cert_path, &key_path).await?;

    let rules = PassthroughRules::compile(&tls.tls_passthrough)?;
    Ok(InterceptTlsConfig {
        ca: std::sync::Arc::new(ca),
        cache: std::sync::Arc::new(LeafCache::new(256)),
        rules,
    })
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
