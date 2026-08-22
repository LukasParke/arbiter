//! `arbiter config` subcommand: init / path / show.
//!
//! - **init**: write a commented starter `config.toml` to the resolved path,
//!   refusing to overwrite an existing file without `--force`.
//! - **path**: print the resolved config file location.
//! - **show**: print the EFFECTIVE layered configuration as stable JSON
//!   (`defaults < file < env`; CLI flags cannot be observed here because no
//!   command runs).
//!
//! Dispatched by cli-dx at M3d assembly when registering the `config`
//! subcommand in `cli/mod.rs`.

#[cfg(test)]
use std::path::Path;

use clap::Subcommand;

use crate::cli::output::{emit, OutputFormat};
use crate::config::{self, FileConfig};
use crate::error::{Error, Result};

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Write a commented starter config.toml.
    Init {
        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Print the resolved config file path.
    Path,
    /// Print the effective layered configuration as JSON
    /// (defaults merged under the config file, environment applied on top).
    Show,
}

/// Dispatch `arbiter config <sub>`.
pub fn run(command: ConfigCommand) -> Result<i32> {
    match command {
        ConfigCommand::Init { force } => init(force),
        ConfigCommand::Path => {
            println!("{}", config::default_path().display());
            Ok(0)
        }
        ConfigCommand::Show => {
            let effective = effective_config()?;
            emit(
                OutputFormat::Json,
                // `show` is intrinsically machine-readable; no human branch.
                || {},
                effective,
            );
            Ok(0)
        }
    }
}

/// Write the commented starter template to [`config::default_path`], refusing
/// to clobber an existing file unless `force`.
fn init(force: bool) -> Result<i32> {
    let path = config::default_path();
    if path.exists() && !force {
        eprintln!("error: {} already exists", path.display());
        eprintln!("  help: re-run with --force to overwrite");
        return Ok(1);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| {
            Error::io(
                format!("create config directory {}", parent.display()),
                source,
            )
        })?;
    }
    super::atomic_write_private(&path, TEMPLATE.as_bytes()).map_err(|source| Error::Io {
        context: format!("writing config {}", path.display()),
        source,
    })?;
    println!(
        "wrote {} — edit it, then inspect with `arbiter config show`",
        path.display()
    );
    Ok(0)
}

/// Effective layered configuration: load the resolved file (missing file =
/// pure defaults), fold the `ARBITER_*` environment layer on top, serialize.
///
/// An explicitly broken file is an error; a *missing* file silently yields
/// defaults so `config show` works on a fresh install.
fn effective_config() -> Result<FileConfig> {
    let path = config::default_path();
    let mut cfg = match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text)
            .map_err(|e| Error::other(format!("invalid config file {}: {e}", path.display())))?,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => FileConfig::default(),
        Err(source) => {
            return Err(Error::io(
                format!("read config file {}", path.display()),
                source,
            ))
        }
    };
    config::apply_env_layer(&mut cfg)?;
    Ok(cfg)
}

/// Commented starter config: every section and field, all commented out so
/// the file is inert until edited. Field list must stay in sync with
/// `config::FileConfig` (AMEND-3 union); `config show` after uncommenting any
/// line is the drift check.
const TEMPLATE: &str = r#"# Arbiter layered configuration.
# Precedence: built-in defaults < this file < ARBITER_* environment < explicit CLI flags.
# Every key is commented out; uncomment to override its default.

[start]
# Upstream target base URL.
#target = "https://api.example.com"
# Proxy listen port.
#port = 8080
# Docs/inspection server port.
#docs_port = 9000
# SQLite capture database location.
#db_path = "~/.local/share/arbiter/captures.db"
# Serve docs only (no upstream forwarding).
#docs_only = false
# Proxy only (no docs endpoints).
#proxy_only = false
# Verbose logging.
#verbose = false

[capture]
# Exact-match capture mode (byte-identical replay; fails closed).
#exact = false
# Per-body spill threshold in bytes.
#max_body_bytes = 10485760
# Idle timeout closing an exchange, in milliseconds.
#idle_timeout_ms = 30000
# Exact secret substrings that abort capture when found (fail-closed guard).
#reject_secret = ["sk-ant-", "AKIA"]
# Binary media types recorded verbatim instead of text-decoded.
#allow_binary_media_type = ["application/octet-stream"]
# Header names redacted from stored exchanges.
#redact_header = ["authorization", "cookie"]
# Query parameter names allowed through redaction.
#allow_query = []
# Host header override applied to forwarded requests.
#host = "0.0.0.0"

[replay]
# Replay mode: status-only | exact-response-body | semantic-json-response | semantic-sse-response.
#mode = "semantic-json-response"
# Inter-exchange delay in milliseconds.
#delay_ms = 0
# Exit non-zero when replayed responses differ from the recording.
#fail_on_diff = false
# RFC 6901 pointers excluded from diff comparison.
#ignore_pointer = []
# HEADER=ENV_VAR pairs replacing redacted credentials at replay time.
#credential_env = ["Authorization=MY_TOKEN"]
# NAME=ENV_VAR pairs restoring redacted query values at replay time.
#query_env = []

[gateway]
# OpenAPI policy document path.
#policy_path = ""
# External command printing the upstream credential on stdout.
#credential_command = ""
# Capture responses passing through the gateway.
#capture_output = false

[tui]
# Attach to an already-running instance's flows endpoint.
#attach_url = "http://127.0.0.1:9000"
# Persisted filters (also written by the TUI `:save` action):
#[[tui.saved_filters]]
#name = "errors"
#query = "provider=anthropic status>=400"

[mock]
# Mock mode (e.g. capture-first, spec-first).
#mode = "capture-first"
# OpenAPI spec used for example generation.
#spec = ""
# Directory served as a capture bundle.
#capture_dir = ""
# Poll spec/bundle mtime and hot-reload (500 ms).
#watch = false
# Candidate selection strategy: first | strongest.
#match_strategy = "strongest"
# Template variables addressable as {{vars.NAME}}.
#[mock.vars]
#env = "staging"

[mock.fault]
# Artificial latency added before responding (ms).
#latency_ms = 0
# Status code forced onto faulted responses.
#status = 503
# Terminal error kind: reset | timeout | garbage.
#error = "timeout"
# Percent of requests receiving ANY injection (0-100).
#fraction_pct = 10

[proxy]
# Request header rewrite rules ("Name: op=value").
#request_header_rules = ["set x-a=b"]
# Response header rewrite rules ("Name: op=value").
#response_header_rules = []
# External request hook command.
#on_request = "./hook.sh request"
# External response hook command.
#on_response = "./hook.sh response"
# Address of a long-lived hook server.
#hook_server = "127.0.0.1:9911"
# Hook call timeout in milliseconds.
#hook_timeout_ms = 250
# Directory holding the generated CA material.
#ca_dir = "~/.local/share/arbiter/ca"
# Disable TLS interception entirely (passthrough-for-all).
#no_tls_intercept = false
# Authority globs routed through without interception.
#tls_passthrough = ["*.internal.corp"]
# Static certificate for downstream reverse-proxy TLS.
#tls_cert = "cert.pem"
# Static key for downstream reverse-proxy TLS.
#tls_key = "key.pem"

[proxy.fault]
# See [mock.fault]; applies to proxied traffic.
#latency_ms = 5
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_support::env_test_lock;
    use tempfile::TempDir;

    fn isolate_home(dir: &Path) {
        std::env::set_var("HOME", dir);
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("ARBITER_CONFIG");
    }

    #[test]
    fn init_writes_template_and_refuses_overwrite_without_force() {
        let _guard = env_test_lock();
        let dir = TempDir::new().unwrap();
        isolate_home(dir.path());

        // init creates nested config directories under the temp HOME.
        let code = init(false).unwrap();
        assert_eq!(code, 0);
        let path = dir.path().join(".config/arbiter/config.toml");
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains("[start]"));
        assert!(first.contains("[mock.fault]"));
        assert!(first.contains("[proxy.fault]"));

        // Overwrite refused without --force (exit 1, not an Err).
        assert_eq!(init(false).unwrap(), 1);

        // --force overwrites with the same template.
        std::fs::write(&path, "# stale\n").unwrap();
        assert_eq!(init(true).unwrap(), 0);
        assert!(std::fs::read_to_string(&path).unwrap().contains("[replay]"));
    }

    #[test]
    fn every_uncommented_template_line_parses_against_fileconfig() {
        // Drift guard: strip comment lines, the remainder must be valid config.
        let body: String = TEMPLATE
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed: Result<FileConfig, _> = toml::from_str(&body);
        assert!(
            parsed.is_ok(),
            "template drifted from FileConfig: {parsed:?}"
        );
    }

    #[test]
    fn show_merges_defaults_file_and_env_layers() {
        let _guard = env_test_lock();
        let dir = TempDir::new().unwrap();
        isolate_home(dir.path());
        let path = config::default_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        // Missing file: pure defaults.
        let defaults = effective_config().unwrap();
        assert_eq!(defaults.start.port, None);
        assert_eq!(defaults.capture.exact, false);

        // File layer.
        std::fs::write(
            &path,
            "[start]\nport = 9443\n[capture]\nhost = \"from-file\"\n",
        )
        .unwrap();
        let layered = effective_config().unwrap();
        assert_eq!(layered.start.port, Some(9443));
        assert_eq!(layered.capture.host.as_deref(), Some("from-file"));
        // Defaults still populate untouched leaves.
        assert_eq!(layered.start.docs_only, false);

        // Env layer beats the file.
        std::env::set_var("ARBITER_START_PORT", "9999");
        let layered = effective_config().unwrap();
        std::env::remove_var("ARBITER_START_PORT");
        assert_eq!(layered.start.port, Some(9999));

        // Broken explicit file content errors rather than panicking.
        std::fs::write(&path, "[start]\nbogus_key = true\n").unwrap();
        let err = effective_config().unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    #[test]
    fn run_dispatches_path_and_show_without_panicking() {
        let _guard = env_test_lock();
        let dir = TempDir::new().unwrap();
        isolate_home(dir.path());

        assert_eq!(run(ConfigCommand::Path).unwrap(), 0);
        assert_eq!(run(ConfigCommand::Show).unwrap(), 0);
    }
}
