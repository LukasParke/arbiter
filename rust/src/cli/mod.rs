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
mod output;
mod replay;
mod sanitize;
mod start;
mod tui;
mod validate;
mod validate_schemas;
use clap::{Args, FromArgMatches, Parser, Subcommand};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::version::ARBITER_VERSION;

/// API proxy with OpenAPI generation and HAR export capabilities
#[derive(Parser)]
#[command(name = "arbiter", version = ARBITER_VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

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
    Gateway(gateway::GatewayArgs),
}

/// Parse args, dispatch the subcommand, and exit with its status code.
///
/// `start` is the default command when no subcommand is given (matching
/// commander's `{ isDefault: true }` registration in cli.ts): an invocation
/// whose first positional token is not a registered subcommand name is parsed
/// entirely as `start` options, flags included.
pub fn run() -> ! {
    if argv_targets_default_start() {
        let matches = start::StartArgs::augment_args(clap::Command::new("arbiter"))
            .try_get_matches_from(std::env::args_os())
            .unwrap_or_else(|e| e.exit());
        let args =
            start::StartArgs::from_arg_matches(&matches).expect("start arg matches round-trip");
        std::process::exit(start::run(&args));
    }

    let cli = Cli::parse();
    let code = match cli.command {
        Some(Command::Start(args)) => start::run(&args),
        Some(Command::Diff(args)) => diff_cmd::run(&args),
        Some(Command::GenerateTraffic(args)) => generate_traffic::run(&args),
        Some(Command::Discover(args)) => discover::run(&args),
        Some(Command::ValidateSchemas(args)) => validate_schemas::run(&args),
        Some(Command::Auth(args)) => auth::run(&args),
        Some(Command::InferSchemas(args)) => infer_schemas::run(&args),
        Some(Command::Replay(args)) => replay::run(&args),
        Some(Command::GenerateSpec(args)) => generate_spec::run(&args),
        Some(Command::Capture(args)) => capture::run(&args),
        Some(Command::Sanitize(args)) => sanitize::run(&args),
        Some(Command::ValidateBundle(args)) => validate::run(&args),
        Some(Command::Gateway(args)) => gateway::run(&args),
        None => {
            // Bare invocation: commander still runs the default command,
            // which fails on its required --target.
            let matches = start::StartArgs::augment_args(clap::Command::new("arbiter"))
                .try_get_matches_from(std::env::args_os())
                .unwrap_or_else(|e| e.exit());
            let args =
                start::StartArgs::from_arg_matches(&matches).expect("start arg matches round-trip");
            start::run(&args)
        }
    };
    std::process::exit(code);
}

const SUBCOMMAND_NAMES: [&str; 13] = [
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
];

/// True when the invocation has a leading positional token that is not a
/// registered subcommand — i.e. the args are really options for the default
/// `start` command (e.g. `arbiter -t http://target`). Global help/version
/// flags stay with the top-level parser.
fn argv_targets_default_start() -> bool {
    for arg in std::env::args_os().skip(1) {
        let arg = arg.to_string_lossy();
        match arg.as_ref() {
            "-h" | "--help" | "-V" | "--version" => return false,
            _ if arg.starts_with('-') => continue,
            _ => return !SUBCOMMAND_NAMES.contains(&arg.as_ref()),
        }
    }
    false
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
        assert!(args.input.is_none());
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
        let Command::Diff(args) = parse(&["diff", "-s", "spec.yaml", "-t", "traffic.jsonl"]) else {
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
}
