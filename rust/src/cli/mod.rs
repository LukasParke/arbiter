//! Command-line surface (port of src/cli.ts and src/commands/*.ts).
//!
//! Subcommand definitions, flags, defaults and exit-code behavior mirror the
//! TypeScript implementation exactly. Each submodule owns one command's clap
//! `Args` struct plus its dispatch logic.

mod auth;
mod ca;
mod capture;
mod complete;
mod config_cmd;
mod diff_cmd;
mod discover;
mod fingerprint;
mod gateway;
mod generate_spec;
mod generate_traffic;
mod infer_schemas;
mod inspect;
mod mock;
mod output;
mod replay;
mod sanitize;
mod start;
mod tui;
mod validate;
mod validate_schemas;
use clap::parser::ValueSource;
use clap::{ArgMatches, Args, FromArgMatches, Parser, Subcommand};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::version::ARBITER_VERSION;

/// API proxy with OpenAPI generation and HAR export capabilities
///
/// Examples:
///   arbiter start -t https://api.anthropic.com
///   arbiter capture -t http://up.test -o out --exact
///   arbiter replay bundle-dir --mode semantic-json-response
#[derive(Parser)]
#[command(name = "arbiter", version = ARBITER_VERSION, propagate_version = true)]
struct Cli {
    /// Emit machine-readable JSON output for commands that support it.
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Start the proxy and documentation servers
    Start(start::StartArgs),
    /// Diff captured traffic against an existing OpenAPI spec
    Diff(diff_cmd::DiffArgs),
    /// Generate synthetic traffic against a target API
    GenerateTraffic(generate_traffic::GenerateTrafficArgs),
    /// Run full discovery pipeline: start proxy, generate traffic, diff against spec
    Discover(discover::DiscoverArgs),
    /// Validate schema coverage in an OpenAPI spec
    ValidateSchemas(validate_schemas::ValidateSchemasArgs),
    /// Manage authentication tokens for API requests
    Auth(auth::AuthArgs),
    /// Infer OpenAPI schemas from captured traffic
    InferSchemas(infer_schemas::InferSchemasArgs),
    /// Replay a capture bundle (or legacy traffic JSONL) for regression testing
    Replay(replay::ReplayArgs),
    /// Generate a complete OpenAPI spec from captured traffic
    GenerateSpec(generate_spec::GenerateSpecArgs),
    /// Run an exact-capture proxy and export a deterministic capture bundle on shutdown
    Capture(capture::CaptureArgs),
    /// Revalidate an untrusted capture bundle and emit a new deterministic sanitized bundle
    Sanitize(sanitize::SanitizeArgs),
    /// Validate a capture bundle against a contract
    #[command(name = "validate")]
    ValidateBundle(validate::ValidateBundleArgs),
    /// Run a credential-injecting gateway for untrusted clients
    #[command(long_about = gateway::LONG_ABOUT)]
    Gateway(gateway::GatewayArgs),
    /// Generate and manage the local TLS certificate authority
    Ca(ca::CaArgs),
    /// Serve mocked API responses from captures or an OpenAPI spec
    Mock(mock::MockCommand),
    /// Interactive terminal UI for live or captured flows
    Tui(tui::TuiCommand),
    /// Classify LLM traffic in a capture bundle and report schema drift
    Fingerprint(fingerprint::FingerprintCommand),
    /// Inspect and initialize the arbiter config file
    Config(config_cmd::ConfigArgs),
    /// Generate shell completions for bash/zsh/fish/powershell
    Complete(complete::CompleteArgs),
    /// Print a human-readable summary of a capture bundle (read-only)
    Inspect(inspect::InspectArgs),
}

/// Parse args, dispatch the subcommand, and exit with its status code.
///
/// Routing (F1/F2):
/// - bare `arbiter` prints a friendly pointer block to stderr and exits 2;
/// - `arbiter help [SUB...]` renders the (long) help of SUB — or the root —
///   on stdout and exits 0;
/// - otherwise `start` is the default command when no subcommand is given
///   (matching commander's `{ isDefault: true }` registration in cli.ts): an
///   invocation whose first positional token is not a registered subcommand
///   name is parsed entirely as `start` options, flags included.
pub fn run() -> ! {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    match route_argv(&argv) {
        Route::Bare => {
            print_bare_pointer();
            std::process::exit(2);
        }
        Route::Help(tokens) => {
            let token_refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
            match render_help(&token_refs) {
                Ok(text) => {
                    print!("{text}");
                    std::process::exit(0);
                }
                Err(message) => {
                    eprintln!("{message}");
                    std::process::exit(2);
                }
            }
        }
        Route::DefaultStart => {
            let matches = start::StartArgs::augment_args(clap::Command::new("arbiter"))
                .try_get_matches_from(argv)
                .unwrap_or_else(|e| e.exit());
            let args =
                start::StartArgs::from_arg_matches(&matches).expect("start arg matches round-trip");
            std::process::exit(start::run_layered(&args, Some(&matches)));
        }
        Route::Subcommand => {}
    }

    // Parse once against the real root command so `start` layering can read
    // clap value_source() per flag (AMEND-3: CLI flags must beat file/env).
    let matches = <Cli as clap::CommandFactory>::command()
        .try_get_matches_from(std::env::args_os())
        .unwrap_or_else(|e| e.exit());

    let json = matches.get_flag("json");
    let fmt = output::OutputFormat::from_json_flag(json);
    let verbose = ["start", "capture", "replay"]
        .iter()
        .find_map(|name| {
            let m = matches.subcommand_matches(name)?;
            // Not every subcommand defines --verbose; try_get_one returns
            // Err instead of panicking when the id is absent.
            m.try_get_one::<bool>("verbose").ok().flatten().copied()
        })
        .unwrap_or(false);
    crate::cli::output::init_tracing(verbose, json);
    let code = match matches.subcommand() {
        Some(("start", m)) => start::run_layered(
            &start::StartArgs::from_arg_matches(m).expect("start arg matches round-trip"),
            Some(m),
        ),
        Some(("diff", m)) => diff_cmd::run(&diff_cmd::DiffArgs::from_arg_matches(m).expect("args")),
        Some(("generate-traffic", m)) => generate_traffic::run(
            &generate_traffic::GenerateTrafficArgs::from_arg_matches(m).expect("args"),
        ),
        Some(("discover", m)) => {
            discover::run(&discover::DiscoverArgs::from_arg_matches(m).expect("args"))
        }
        Some(("validate-schemas", m)) => validate_schemas::run(
            &validate_schemas::ValidateSchemasArgs::from_arg_matches(m).expect("args"),
        ),
        Some(("auth", m)) => auth::run(&auth::AuthArgs::from_arg_matches(m).expect("args")),
        Some(("infer-schemas", m)) => {
            infer_schemas::run(&infer_schemas::InferSchemasArgs::from_arg_matches(m).expect("args"))
        }
        Some(("replay", m)) => {
            let mut args = replay::ReplayArgs::from_arg_matches(m).expect("args");
            apply_replay_layers(&mut args, m);
            replay::run(&args, fmt)
        }
        Some(("generate-spec", m)) => {
            generate_spec::run(&generate_spec::GenerateSpecArgs::from_arg_matches(m).expect("args"))
        }
        Some(("capture", m)) => {
            let mut args = capture::CaptureArgs::from_arg_matches(m).expect("args");
            apply_capture_layers(&mut args, m);
            capture::run(&args, fmt)
        }
        Some(("sanitize", m)) => sanitize::run(
            &sanitize::SanitizeArgs::from_arg_matches(m).expect("args"),
            fmt,
        ),
        Some(("validate", m)) => validate::run(
            &validate::ValidateBundleArgs::from_arg_matches(m).expect("args"),
            fmt,
        ),
        Some(("gateway", m)) => {
            gateway::run(&gateway::GatewayArgs::from_arg_matches(m).expect("args"))
        }
        Some(("ca", m)) => ca::run_ca(&ca::CaArgs::from_arg_matches(m).expect("args"))
            .unwrap_or_else(|e| report_command_error(&e)),
        Some(("mock", m)) => {
            let mut command = mock::MockCommand::from_arg_matches(m).expect("args");
            apply_mock_layers(&mut command, m);
            run_mock(&command)
        }
        Some(("tui", m)) => tui::run(&tui::TuiCommand::from_arg_matches(m).expect("args")),
        Some(("fingerprint", m)) => fingerprint::run(
            &fingerprint::FingerprintCommand::from_arg_matches(m).expect("args"),
            fmt,
        ),
        Some(("inspect", m)) => inspect::run(
            &inspect::InspectArgs::from_arg_matches(m).expect("args"),
            fmt,
        ),
        Some(("config", m)) => {
            let args = config_cmd::ConfigArgs::from_arg_matches(m).expect("args");
            config_cmd::run(args.command).unwrap_or_else(|e| report_command_error(&e))
        }
        Some(("complete", m)) => {
            complete::run(&complete::CompleteArgs::from_arg_matches(m).expect("args"))
        }
        None => {
            // Flags-only invocation (`arbiter --json`): no positional at all,
            // so route to the same friendly pointer as a bare invocation.
            print_bare_pointer();
            2
        }
        // clap rejects unknown subcommands before we get here.
        _ => 2,
    };
    std::process::exit(code);
}

/// Print a command error in house style (cause + help hint) and map to an
/// exit code for commands returning `Result<i32>`.
fn report_command_error(e: &crate::error::Error) -> i32 {
    crate::cli::output::print_error(e);
    1
}

/// Run the mock server on a dedicated tokio runtime, mapping errors to the
/// house error format.
fn run_mock(command: &mock::MockCommand) -> i32 {
    let runtime = tokio::runtime::Runtime::new().expect("mock tokio runtime");
    match runtime.block_on(command.run()) {
        Ok(()) => 0,
        Err(e) => report_command_error(&e),
    }
}

const SUBCOMMAND_NAMES: [&str; 20] = [
    "start",
    "diff",
    "generate-traffic",
    "discover",
    "validate-schemas",
    "auth",
    "infer-schemas",
    "replay",
    "generate-spec",
    "capture",
    "sanitize",
    "validate",
    "gateway",
    "ca",
    "mock",
    "tui",
    "fingerprint",
    "inspect",
    "config",
    "complete",
];

/// The assembled root command. Single source for both argument parsing and
/// shell-completion generation (`cli::complete::build_cli` delegates here).
pub(crate) fn root_command() -> clap::Command {
    <Cli as clap::CommandFactory>::command()
}

/// What the leading positional token of argv selects (F1/F2 routing).
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// No positional argument at all: bare `arbiter`.
    Bare,
    /// `arbiter help [SUB...]` — tokens following `help`.
    Help(Vec<String>),
    /// Leading positional is not a registered subcommand: default `start`.
    DefaultStart,
    /// Normal subcommand dispatch.
    Subcommand,
}

/// Classify argv for [`run`]. Global help/version flags stay with the
/// top-level parser; flags before the first positional are skipped.
fn route_argv(argv: &[std::ffi::OsString]) -> Route {
    let mut first_positional: Option<(usize, String)> = None;
    for (index, arg) in argv.iter().enumerate().skip(1) {
        let arg = arg.to_string_lossy();
        match arg.as_ref() {
            "-h" | "--help" | "-V" | "--version" => return Route::Subcommand,
            _ if arg.starts_with('-') => continue,
            _ => {
                first_positional = Some((index, arg.into_owned()));
                break;
            }
        }
    }
    let Some((index, token)) = first_positional else {
        return Route::Bare;
    };
    if token == "help" && !SUBCOMMAND_NAMES.contains(&"help") {
        // F2: manual help routing (clap's own help subcommand is disabled by
        // the default-command configuration).
        let tokens = argv[index + 1..]
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        return Route::Help(tokens);
    }
    if SUBCOMMAND_NAMES.contains(&token.as_str()) {
        Route::Subcommand
    } else {
        Route::DefaultStart
    }
}

/// Intercept `arbiter help <sub>` (F2): the default-command configuration
/// disables clap's own `help` subcommand, so help routing is manual. Renders
/// the long help of the subcommand chain named by `tokens` (empty = root).
fn render_help(tokens: &[&str]) -> Result<String, String> {
    let mut cmd = root_command();
    for token in tokens {
        let found = cmd
            .get_subcommands()
            .find(|c| c.get_name() == *token || c.get_all_aliases().any(|a| a == *token))
            .cloned();
        match found {
            Some(next) => cmd = next,
            None => {
                return Err(format!(
                    "error: unrecognized subcommand '{token}'\n  help: run `arbiter --help` \
                     to list commands"
                ))
            }
        }
    }
    Ok(cmd.render_long_help().to_string())
}

/// Friendly pointer block for a bare invocation (F1): printed to stderr,
/// exit 2 — an error, but one that says where to go next.
fn print_bare_pointer() {
    eprintln!("usage: arbiter start -t <url>");
    eprintln!("       arbiter capture -t <url> -o <dir>");
    eprintln!("       arbiter replay <bundle-dir> --target <url>");
    eprintln!();
    eprintln!("  help: run `arbiter --help` for every command, or");
    eprintln!("        `arbiter help <command>` for command details");
}

// ---------------------------------------------------------------------------
// Config layering for mock/replay/capture dispatch (D3)
//
// Precedence (AMEND-3): built-in defaults < config file < environment <
// explicit CLI flag. The file+env layers are resolved here into a
// `FileConfig`; each `apply_*_layers` folds its section under the parsed CLI
// args, skipping every value the user set explicitly on the command line.
// ---------------------------------------------------------------------------

/// True when the flag was explicitly passed on the command line. Unknown
/// ids count as explicit — this must never panic on external input.
fn cli_flag_used(matches: &ArgMatches, id: &str) -> bool {
    if !matches.contains_id(id) {
        return true;
    }
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

/// Load the default config file with the environment layer applied
/// (missing file = pure defaults). A broken file or bad env override aborts
/// in the house error style.
fn layered_config() -> crate::config::FileConfig {
    let path = crate::config::default_path();
    let mut cfg = match crate::config::load_or_default(&path) {
        Ok(cfg) => cfg,
        Err(e) => {
            crate::cli::output::print_error(&e);
            std::process::exit(1);
        }
    };
    if let Err(e) = crate::config::apply_env_layer(&mut cfg) {
        crate::cli::output::print_error(&e);
        std::process::exit(1);
    }
    cfg
}

/// Fold `[replay]` under the parsed CLI args (D3). Explicit flags win.
fn apply_replay_layers(args: &mut replay::ReplayArgs, matches: &ArgMatches) {
    let cfg = layered_config();
    let section = &cfg.replay;
    let used = |id: &str| cli_flag_used(matches, id);

    if !used("mode") {
        if let Some(mode) = &section.mode {
            args.mode = mode.clone();
        }
    }
    if !used("delay") {
        if let Some(ms) = section.delay_ms {
            args.delay = ms.to_string();
        }
    }
    if !used("fail_on_diff") {
        args.fail_on_diff = section.fail_on_diff;
    }
    if args.ignore_pointer.is_empty() {
        args.ignore_pointer = section.ignore_pointer.clone();
    }
    if args.credential_env.is_empty() {
        args.credential_env = section.credential_env.clone();
    }
    if args.query_env.is_empty() {
        args.query_env = section.query_env.clone();
    }
}

/// Fold `[mock]` under the parsed CLI args (D3). Explicit flags win; enum
/// spellings from the file are validated loudly instead of ignored.
fn apply_mock_layers(args: &mut mock::MockCommand, matches: &ArgMatches) {
    use crate::mock::MatchStrategy;
    let cfg = layered_config();
    let section = &cfg.mock;
    let used = |id: &str| cli_flag_used(matches, id);

    if args.spec.is_none() {
        args.spec = section.spec.clone();
    }
    if args.capture.is_none() {
        args.capture = section.capture_dir.clone();
    }
    if !used("watch") {
        args.watch = section.watch;
    }
    if !used("match_strategy") {
        if let Some(raw) = &section.match_strategy {
            args.match_strategy = match raw.trim().to_ascii_lowercase().as_str() {
                "strongest" => MatchStrategy::Strongest,
                "first" => MatchStrategy::First,
                _ => fail(format!(
                    "Invalid [mock].match_strategy value \"{raw}\" (expected strongest|first)"
                )),
            };
        }
    }
    if args.fault_latency_ms.is_none() {
        args.fault_latency_ms = section.fault.latency_ms;
    }
    if args.fault_status.is_none() {
        args.fault_status = section.fault.status;
    }
    if args.fault_error.is_none() {
        if let Some(kind) = section.fault.error.as_deref().and_then(parse_fault_kind) {
            args.fault_error = Some(kind);
        }
    }
    if !used("fault_fraction") {
        if let Some(fraction) = section.fault.fraction_pct {
            args.fault_fraction = fraction.min(100) as u8;
        }
    }
    if args.var.is_empty() && !section.vars.is_empty() {
        args.var = section
            .vars
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
    }
}

/// Config-file spelling (`reset|timeout|garbage`) → [`crate::mock::FaultKind`].
fn parse_fault_kind(raw: &str) -> Option<crate::mock::FaultKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "reset" => Some(crate::mock::FaultKind::Reset),
        "timeout" => Some(crate::mock::FaultKind::Timeout),
        "garbage" => Some(crate::mock::FaultKind::Garbage),
        _ => None,
    }
}
/// Fold `[capture]` under the parsed CLI args (D3). Explicit flags win.
fn apply_capture_layers(args: &mut capture::CaptureArgs, matches: &ArgMatches) {
    let cfg = layered_config();
    let section = &cfg.capture;
    let used = |id: &str| cli_flag_used(matches, id);

    if !used("exact") {
        args.exact = section.exact;
    }
    if !used("host") {
        if let Some(host) = &section.host {
            args.host = host.clone();
        }
    }
    if !used("max_body_bytes") {
        if let Some(max) = section.max_body_bytes {
            args.max_body_bytes = max.to_string();
        }
    }
    if args.idle_timeout.is_none() {
        if let Some(ms) = section.idle_timeout_ms {
            args.idle_timeout = Some(ms.to_string());
        }
    }
    if args.redact_header.is_empty() {
        args.redact_header = section.redact_header.clone();
    }
    if args.allow_query.is_empty() {
        args.allow_query = section.allow_query.clone();
    }
    if args.reject_secret.is_empty() {
        args.reject_secret = section.reject_secret.clone();
    }
    if args.allow_binary_media_type.is_empty() {
        args.allow_binary_media_type = section.allow_binary_media_type.clone();
    }
}

/// Print an error to stderr and exit with code 1.
pub(crate) fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

/// Port of `parsePositiveInt` in src/commands/capture.ts.
pub(crate) fn parse_positive_int(value: &str, flag: &str, allow_zero: bool) -> u64 {
    let min: u64 = if allow_zero { 0 } else { 1 };
    match value.parse::<u64>() {
        Ok(parsed) if parsed >= min => parsed,
        _ => fail(format!("{flag} must be an integer >= {min} (got {value})")),
    }
}

/// Write file contents atomically (tmp + rename) with owner-only permissions,
/// mirroring the `writeFileSync(tmp, payload, { mode: 0o600 })` +
/// `renameSync` pattern used across the TS commands.
pub(crate) fn atomic_write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp = path_with_suffix(path, "tmp");
    if let Some(parent) = tmp.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::create(&tmp)?;
    let mut file = file;
    file.write_all(contents)?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
}

/// `path.resolve` equivalent: make `path` absolute against the current
/// directory without requiring it to exist.
pub(crate) fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".");
    os.push(suffix);
    PathBuf::from(os)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn parse(args: &[&str]) -> Command {
        Cli::try_parse_from(std::iter::once("arbiter").chain(args.iter().copied()))
            .expect("args parse")
            .command
            .expect("subcommand")
    }

    #[test]
    fn capture_defaults_match_commander() {
        let Command::Capture(args) = parse(&["capture", "-t", "http://up.test", "-o", "out"])
        else {
            panic!("capture subcommand expected");
        };
        assert_eq!(args.target, "http://up.test");
        assert_eq!(args.output, "out");
        assert_eq!(args.port, "0");
        assert_eq!(args.host, "127.0.0.1");
        assert!(!args.exact);
        assert!(args.redact_header.is_empty());
        assert!(args.allow_query.is_empty());
        assert!(args.reject_secret.is_empty());
        assert!(args.allow_binary_media_type.is_empty());
        assert_eq!(args.max_body_bytes, (32 * 1024 * 1024).to_string());
        assert!(args.idle_timeout.is_none());
        assert!(args.ready_file.is_none());
        assert!(args.report.is_none());
    }

    #[test]
    fn capture_repeatable_flags_collect() {
        let Command::Capture(args) = parse(&[
            "capture",
            "-t",
            "http://up.test",
            "-o",
            "out",
            "--exact",
            "--redact-header",
            "x-a-*",
            "--redact-header",
            "x-b",
            "--allow-query",
            "keep",
            "--reject-secret",
            "SECRET",
            "--allow-binary-media-type",
            "image/",
            "--idle-timeout",
            "500",
        ]) else {
            panic!("capture subcommand expected");
        };
        assert!(args.exact);
        assert_eq!(args.redact_header, vec!["x-a-*", "x-b"]);
        assert_eq!(args.allow_query, vec!["keep"]);
        assert_eq!(args.reject_secret, vec!["SECRET"]);
        assert_eq!(args.allow_binary_media_type, vec!["image/"]);
        assert_eq!(args.idle_timeout.as_deref(), Some("500"));
    }

    #[test]
    fn start_defaults_match_commander() {
        // `start` is also the default command; its flags must parse standalone
        // so the no-subcommand re-parse path works.
        let matches = start::StartArgs::augment_args(clap::Command::new("arbiter"))
            .try_get_matches_from(["arbiter", "-t", "http://t.test"])
            .expect("start args parse");
        let args = start::StartArgs::from_arg_matches(&matches).expect("start arg matches");
        assert_eq!(args.target, "http://t.test");
        assert_eq!(args.port, "8080");
        assert_eq!(args.docs_port, "9000");
        assert!(!args.docs_only);
        assert!(!args.proxy_only);
        assert!(!args.exit_on_gap);
        assert!(!args.validate);
        assert!(!args.verbose);
    }
    #[test]
    fn replay_defaults_match_commander() {
        let Command::Replay(args) = parse(&["replay", "--target", "http://t.test", "bundle-dir"])
        else {
            panic!("replay subcommand expected");
        };
        assert_eq!(args.bundle.as_deref(), Some("bundle-dir"));
        assert!(!args.legacy_jsonl);
        assert_eq!(args.mode, "status-only");
        assert!(args.credential_env.is_empty());
        assert!(args.ignore_pointer.is_empty());
        assert!(args.query_env.is_empty());
        assert!(args.token.is_none());
        assert!(!args.only_status);
        assert_eq!(args.delay, "0");
        assert!(!args.fail_on_diff);
        assert!(!args.verbose);
    }

    #[test]
    fn gateway_defaults_match_commander() {
        let Command::Gateway(args) = parse(&[
            "gateway",
            "--policy",
            "policy.json",
            "--credential-command",
            "printenv TOKEN",
        ]) else {
            panic!("gateway subcommand expected");
        };
        assert_eq!(args.policy, "policy.json");
        assert_eq!(args.credential_command, "printenv TOKEN");
        assert_eq!(args.credential_header, "authorization");
        assert!(args.credential_prefix.is_none());
        assert_eq!(args.port, "0");
        assert_eq!(args.host, "127.0.0.1");
        assert!(args.capture_output.is_none());
    }

    #[test]
    fn generate_traffic_defaults_match_commander() {
        let Command::GenerateTraffic(args) =
            parse(&["generate-traffic", "--target", "http://t.test"])
        else {
            panic!("generate-traffic subcommand expected");
        };
        assert_eq!(args.delay, "100");
        assert_eq!(args.max_body_size, "50000");
        assert!(!args.capture_bodies);
        assert!(args.output.is_none());
        assert!(args.token.is_none());
    }

    #[test]
    fn sanitize_requires_output_and_bundle() {
        let result = Cli::try_parse_from(["arbiter", "sanitize"]);
        assert!(result.is_err(), "missing required bundle/output must fail");
        let result = Cli::try_parse_from(["arbiter", "sanitize", "in"]);
        assert!(result.is_err(), "missing required -o must fail");
    }

    #[test]
    fn validate_accepts_spec_or_command_at_clap_level() {
        let ok = parse(&["validate", "b", "--spec", "spec.yaml"]);
        assert!(matches!(ok, Command::ValidateBundle(_)));
        let ok = parse(&["validate", "b", "--command", "validator"]);
        assert!(matches!(ok, Command::ValidateBundle(_)));
    }

    #[test]
    fn diff_and_validate_schemas_defaults() {
        let Command::Diff(args) = parse(&["diff", "-s", "spec.yaml", "-i", "traffic.jsonl"]) else {
            panic!("diff subcommand expected");
        };
        assert!(!args.exit_on_gap);
        assert!(args.output.is_none());
        let Command::ValidateSchemas(args) = parse(&["validate-schemas", "-s", "spec.yaml"]) else {
            panic!("validate-schemas subcommand expected");
        };
        assert!(!args.exit_on_gap);
    }

    #[test]
    fn auth_set_defaults_to_plex_token() {
        let Command::Auth(auth) = parse(&["auth", "set", "--token", "abc123"]) else {
            panic!("auth subcommand expected");
        };
        match auth.command {
            crate::cli::auth::AuthCommand::Set {
                token,
                auth_type,
                header,
            } => {
                assert_eq!(token, "abc123");
                assert_eq!(auth_type, "plex-token");
                assert!(header.is_none());
            }
            _ => panic!("set subcommand expected"),
        }
    }

    // ------------------------------------------------------------------
    // F1/F2: bare invocation + manual help routing
    // ------------------------------------------------------------------

    fn os(args: &[&str]) -> Vec<std::ffi::OsString> {
        std::iter::once("arbiter")
            .chain(args.iter().copied())
            .map(std::ffi::OsString::from)
            .collect()
    }

    #[test]
    fn route_bare_and_flags_only_to_bare_pointer() {
        assert_eq!(route_argv(&os(&[])), Route::Bare);
        assert_eq!(route_argv(&os(&["--json"])), Route::Bare);
        assert_eq!(route_argv(&os(&["--json", "-v"])), Route::Bare);
    }

    #[test]
    fn route_default_start_subcommand_and_help() {
        assert_eq!(
            route_argv(&os(&["-t", "http://t.test"])),
            Route::DefaultStart
        );
        assert_eq!(route_argv(&os(&["replay", "b"])), Route::Subcommand);
        assert_eq!(route_argv(&os(&["-h"])), Route::Subcommand);
        assert_eq!(
            route_argv(&os(&["help", "mock"])),
            Route::Help(vec!["mock".to_string()])
        );
        assert_eq!(route_argv(&os(&["help"])), Route::Help(vec![]));
    }

    #[test]
    fn help_renders_root_and_subcommand_long_help() {
        let root = render_help(&[]).expect("root help");
        assert!(root.contains("Usage:"), "root help missing usage");

        let mock = render_help(&["mock"]).expect("mock help");
        assert!(mock.contains("--match-strategy"), "mock help lost flags");

        // Nested subcommand chain resolves too.
        let init = render_help(&["config", "init"]).expect("config init help");
        assert!(init.contains("--force"), "config init help lost --force");

        assert!(render_help(&["definitely-not-a-command"]).is_err());
    }
    #[test]
    fn every_subcommand_accepts_version_flag() {
        for sub in ["replay", "diff", "sanitize", "fingerprint", "inspect"] {
            let Err(err) = Cli::try_parse_from(["arbiter", sub, "-V"]) else {
                panic!("{sub} -V must display version");
            };
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::DisplayVersion,
                "{sub} -V must display version"
            );
        }
        // The root -V still works.
        let Err(err) = Cli::try_parse_from(["arbiter", "-V"]) else {
            panic!("root -V must display version");
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn generate_spec_uses_api_version_flag() {
        let Command::GenerateSpec(_args) = parse(&[
            "generate-spec",
            "-i",
            "traffic.jsonl",
            "--api-version",
            "2.0.0",
        ]) else {
            panic!("generate-spec subcommand expected");
        };
        // `--version` is now the binary's own version flag, not the API one.
        let Err(err) = Cli::try_parse_from([
            "arbiter",
            "generate-spec",
            "-i",
            "traffic.jsonl",
            "--version",
            "2.0.0",
        ]) else {
            panic!("--version must be the binary version flag");
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    // ------------------------------------------------------------------
    // G1/G2: diff input flag unification
    // ------------------------------------------------------------------

    #[test]
    fn diff_input_flag_unified() {
        // Primary spelling.
        assert!(parse(&["diff", "-s", "s.yaml", "-i", "t.jsonl"]).is_parsed_diff());
        // Long form.
        assert!(parse(&["diff", "-s", "s.yaml", "--input", "t.jsonl"]).is_parsed_diff());
        // Deprecated alias still parses (hidden from help).
        assert!(parse(&["diff", "-s", "s.yaml", "--traffic", "t.jsonl"]).is_parsed_diff());
        // The colliding short -t is gone.
        assert!(Cli::try_parse_from(["arbiter", "diff", "-s", "s.yaml", "-t", "t.jsonl"]).is_err());
        // Help text no longer shows a diff -t short.
        let mut cmd = root_command();
        let help = cmd.render_long_help().to_string();
        let diff_block = help.split("diff").nth(1).unwrap_or("");
        assert!(
            !diff_block.contains("-t <PATH>") && !diff_block.contains("--traffic <"),
            "--traffic alias must stay hidden from help"
        );
    }

    trait ParsedDiff {
        fn is_parsed_diff(&self) -> bool;
    }
    impl ParsedDiff for Command {
        fn is_parsed_diff(&self) -> bool {
            matches!(self, Command::Diff(_))
        }
    }

    #[test]
    fn replay_input_alias_removed() {
        // Positional remains primary...
        assert!(matches!(
            parse(&["replay", "--target", "http://t", "bundle-dir"]),
            Command::Replay(_)
        ));
        // ...and the legacy -i/--input spelling is gone entirely.
        for legacy in [["-i", "b"], ["--input", "b"]] {
            let result = Cli::try_parse_from(
                ["arbiter", "replay", "--target", "http://t"]
                    .into_iter()
                    .chain(legacy),
            );
            assert!(result.is_err(), "legacy {legacy:?} spelling must fail");
        }
    }

    // ------------------------------------------------------------------
    // D3: config layering for mock/replay/capture dispatch
    // ------------------------------------------------------------------

    fn cli_matches(args: &[&str]) -> ArgMatches {
        <Cli as clap::CommandFactory>::command()
            .try_get_matches_from(std::iter::once("arbiter").chain(args.iter().copied()))
            .expect("args parse")
    }

    fn isolate_config(dir: &std::path::Path) {
        std::env::set_var("HOME", dir);
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_var("ARBITER_CONFIG", dir.join("config.toml"));
    }

    #[test]
    fn replay_layering_file_env_cli_precedence() {
        let _guard = crate::config::test_support::env_test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        isolate_config(dir.path());
        std::fs::write(
            dir.path().join("config.toml"),
            "[replay]\nmode = \"semantic-json-response\"\ndelay_ms = 42\nfail_on_diff = true\n",
        )
        .expect("write config");

        // File layer applies over defaults.
        let matches = cli_matches(&["replay", "--target", "http://t", "b"]);
        let sub = matches.subcommand_matches("replay").unwrap();
        let mut args = replay::ReplayArgs::from_arg_matches(sub).expect("args");
        apply_replay_layers(&mut args, sub);
        assert_eq!(args.mode, "semantic-json-response");
        assert_eq!(args.delay, "42");
        assert!(args.fail_on_diff);

        // Env beats file.
        std::env::set_var("ARBITER_REPLAY_MODE", "status-only");
        let matches = cli_matches(&["replay", "--target", "http://t", "b"]);
        let sub = matches.subcommand_matches("replay").unwrap();
        let mut args = replay::ReplayArgs::from_arg_matches(sub).expect("args");
        apply_replay_layers(&mut args, sub);
        std::env::remove_var("ARBITER_REPLAY_MODE");
        assert_eq!(args.mode, "status-only");

        // Explicit CLI flag beats both.
        std::env::set_var("ARBITER_REPLAY_MODE", "status-only");
        let matches = cli_matches(&[
            "replay",
            "--target",
            "http://t",
            "--mode",
            "exact-response-body",
            "b",
        ]);
        let sub = matches.subcommand_matches("replay").unwrap();
        let mut args = replay::ReplayArgs::from_arg_matches(sub).expect("args");
        apply_replay_layers(&mut args, sub);
        std::env::remove_var("ARBITER_REPLAY_MODE");
        assert_eq!(args.mode, "exact-response-body");
    }

    #[test]
    fn mock_layering_file_env_cli_precedence() {
        use crate::mock::{FaultKind, MatchStrategy};
        let _guard = crate::config::test_support::env_test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        isolate_config(dir.path());
        std::fs::write(
            dir.path().join("config.toml"),
            "[mock]\nwatch = true\nmatch_strategy = \"first\"\n[mock.fault]\nlatency_ms = 250\nerror = \"reset\"\nfraction_pct = 20\n",
        )
        .expect("write config");

        // File layer applies.
        let matches = cli_matches(&["mock", "--spec", "openapi.yaml"]);
        let sub = matches.subcommand_matches("mock").unwrap();
        let mut command = mock::MockCommand::from_arg_matches(sub).expect("args");
        apply_mock_layers(&mut command, sub);
        assert!(command.watch);
        assert_eq!(command.match_strategy, MatchStrategy::First);
        assert_eq!(command.fault_latency_ms, Some(250));
        assert_eq!(command.fault_error, Some(FaultKind::Reset));
        assert_eq!(command.fault_fraction, 20);

        // Explicit flag wins over the file.
        let matches = cli_matches(&["mock", "--spec", "openapi.yaml", "--fault-fraction", "55"]);
        let sub = matches.subcommand_matches("mock").unwrap();
        let mut command = mock::MockCommand::from_arg_matches(sub).expect("args");
        apply_mock_layers(&mut command, sub);
        assert_eq!(command.fault_fraction, 55);

        // Env beats file for a scalar key ([mock] has no port; use watch).
        std::env::set_var("ARBITER_MOCK_WATCH", "false");
        let matches = cli_matches(&["mock", "--spec", "openapi.yaml"]);
        let sub = matches.subcommand_matches("mock").unwrap();
        let mut command = mock::MockCommand::from_arg_matches(sub).expect("args");
        apply_mock_layers(&mut command, sub);
        std::env::remove_var("ARBITER_MOCK_WATCH");
        assert!(!command.watch);
    }

    #[test]
    fn capture_layering_file_and_explicit_flag() {
        let _guard = crate::config::test_support::env_test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        isolate_config(dir.path());
        std::fs::write(
            dir.path().join("config.toml"),
            "[capture]\nexact = true\nhost = \"0.0.0.0\"\nmax_body_bytes = 1024\nidle_timeout_ms = 500\nredact_header = [\"x-a-*\"]\n",
        )
        .expect("write config");

        let matches = cli_matches(&["capture", "-t", "http://up.test", "-o", "out"]);
        let sub = matches.subcommand_matches("capture").unwrap();
        let mut args = capture::CaptureArgs::from_arg_matches(sub).expect("args");
        apply_capture_layers(&mut args, sub);
        assert!(args.exact);
        assert_eq!(args.host, "0.0.0.0");
        assert_eq!(args.max_body_bytes, "1024");
        assert_eq!(args.idle_timeout.as_deref(), Some("500"));
        assert_eq!(args.redact_header, vec!["x-a-*"]);

        // Explicit flag beats the file.
        let matches = cli_matches(&[
            "capture",
            "-t",
            "http://up.test",
            "-o",
            "out",
            "--host",
            "127.0.0.1",
        ]);
        let sub = matches.subcommand_matches("capture").unwrap();
        let mut args = capture::CaptureArgs::from_arg_matches(sub).expect("args");
        apply_capture_layers(&mut args, sub);
        assert_eq!(args.host, "127.0.0.1");
    }
}
