//! Layered configuration (W7, AMEND-3).
//!
//! Single owner of the TOML config representation. [`FileConfig`] is the union
//! of every section any command reads: `[start]`, `[capture]`, `[replay]`,
//! `[gateway]`, `[tui]`, `[mock]` (incl. `[mock.fault]`) and `[proxy]`
//! (incl. `[proxy.fault]`).
//!
//! # Precedence (AMEND-3, binding)
//!
//! ```text
//! built-in defaults  <  config file  <  environment  <  explicit CLI flag
//! ```
//!
//! - **Defaults**: every field is `#[serde(default)]`; unset means "fall
//!   through to the next layer".
//! - **File**: `default_path()` (`$ARBITER_CONFIG`, else
//!   `$XDG_CONFIG_HOME/arbiter/config.toml`, else `~/.config/arbiter/config.toml`),
//!   parsed with `deny_unknown_fields` so typos fail loudly.
//! - **Environment**: `ARBITER_<SECTION>_<KEY>` with the key lowercased to its
//!   snake_case TOML name (e.g. `ARBITER_CAPTURE_MAX_BODY_BYTES` →
//!   `[capture].max_body_bytes`). First-level scalar/array keys only; nested
//!   tables (`[mock.fault]`, `[mock.vars]`, `[tui.saved_filters]`) are file/CLI
//!   territory.
//! - **CLI**: an explicitly-passed flag always wins; commands detect this via
//!   `clap::ArgMatches::value_source(...) == ValueSource::CommandLine` and fold
//!   the flag over a [`Layered`] value.
//!
//! Implemented with plain serde + `toml`; deliberately no `config` crate.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Canonical config file name inside the arbiter config directory.
pub const CONFIG_FILE_NAME: &str = "config.toml";
/// Environment-variable prefix for overrides: `ARBITER_<SECTION>_<KEY>`.
pub const ENV_PREFIX: &str = "ARBITER_";

// ---------------------------------------------------------------------------
// FileConfig sections
// ---------------------------------------------------------------------------

/// Mirrors `arbiter start` flags (minus TLS/mock/proxy-only extras, which live
/// in their own sections below).
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StartSection {
    pub target: Option<String>,
    pub port: Option<u16>,
    pub docs_port: Option<u16>,
    pub db_path: Option<PathBuf>,
    pub docs_only: bool,
    pub proxy_only: bool,
    pub verbose: bool,
}

/// Mirrors `arbiter capture` flags.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureSection {
    pub exact: bool,
    pub max_body_bytes: Option<u64>,
    pub idle_timeout_ms: Option<u64>,
    pub reject_secret: Vec<String>,
    pub allow_binary_media_type: Vec<String>,
    pub redact_header: Vec<String>,
    pub allow_query: Vec<String>,
    pub host: Option<String>,
}

/// Mirrors `arbiter replay` flags. `mode` values are validated by the replay
/// engine at startup (status-only | exact-response-body | semantic-json-response
/// | semantic-sse-response), not duplicated here.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReplaySection {
    pub mode: Option<String>,
    pub delay_ms: Option<u64>,
    pub fail_on_diff: bool,
    pub ignore_pointer: Vec<String>,
    /// `HEADER=ENV_VAR_NAME` pairs replacing redacted credentials at replay.
    pub credential_env: Vec<String>,
    /// `NAME=ENV_VAR_NAME` pairs restoring redacted query values at replay.
    pub query_env: Vec<String>,
}

/// Mirrors `arbiter gateway` flags.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewaySection {
    pub policy_path: Option<PathBuf>,
    pub credential_command: Option<String>,
    pub capture_output: bool,
}

/// A named TUI filter persisted from the `:save <name>` palette action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedFilter {
    pub name: String,
    pub query: String,
}

/// Mirrors `arbiter tui` flags plus persisted saved filters. TUI constructs its
/// filter store through `tui::filter::InMemorySavedFilterStore::with_file` /
/// these entries at assembly — never by editing the file itself.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TuiSection {
    pub attach_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub saved_filters: Vec<SavedFilter>,
}

/// Fault injection knobs shared by mock and proxy modes. The authoritative
/// fault model is `mock::fault::FaultConfig` (AMEND-5); this section is its
/// TOML projection and `error` is validated there (`reset|timeout|garbage`)
/// when the injector is constructed at startup.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FaultSection {
    pub latency_ms: Option<u64>,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub fraction_pct: Option<u64>,
}

/// Mirrors `arbiter mock` flags.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MockSection {
    pub mode: Option<String>,
    pub spec: Option<PathBuf>,
    pub capture_dir: Option<PathBuf>,
    pub watch: bool,
    pub match_strategy: Option<String>,
    pub fault: FaultSection,
    pub vars: BTreeMap<String, String>,
}

/// Mirrors the `arbiter start` TLS / header-rule / hook flags (typed exports
/// consumed from tls-intercept and hooks-modify at M3 assembly).
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxySection {
    pub fault: FaultSection,
    pub request_header_rules: Vec<String>,
    pub response_header_rules: Vec<String>,
    /// External hook invoked on requests (command spec owned by hooks-modify).
    pub on_request: Option<String>,
    pub on_response: Option<String>,
    pub hook_server: Option<String>,
    pub hook_timeout_ms: Option<u64>,
    pub ca_dir: Option<PathBuf>,
    pub no_tls_intercept: bool,
    pub tls_passthrough: Vec<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

/// The full config-file surface. Every section defaults; unknown sections or
/// keys are rejected (`deny_unknown_fields`) with the offending field named.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub start: StartSection,
    pub capture: CaptureSection,
    pub replay: ReplaySection,
    pub gateway: GatewaySection,
    pub tui: TuiSection,
    pub mock: MockSection,
    pub proxy: ProxySection,
}

impl FileConfig {
    /// Names of all top-level sections, in canonical order.
    pub const SECTIONS: [&'static str; 7] = [
        "start", "capture", "replay", "gateway", "tui", "mock", "proxy",
    ];
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Parse a config file. Missing file → `Err(Io)`; callers that treat absence
/// as "defaults only" use [`load_or_default`].
pub fn load(path: &Path) -> Result<FileConfig> {
    let text = std::fs::read_to_string(path)
        .map_err(|source| Error::io(format!("read config file {}", path.display()), source))?;
    toml::from_str(&text)
        .map_err(|e| Error::other(format!("invalid config file {}: {e}", path.display())))
}

/// Load a config file, treating "does not exist" as empty (defaults apply).
/// Any other read error or parse error is reported.
pub fn load_or_default(path: &Path) -> Result<FileConfig> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)
            .map_err(|e| Error::other(format!("invalid config file {}: {e}", path.display()))),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(FileConfig::default()),
        Err(source) => Err(Error::io(
            format!("read config file {}", path.display()),
            source,
        )),
    }
}

/// Resolve the config file path:
/// `$ARBITER_CONFIG` → `$XDG_CONFIG_HOME/arbiter/config.toml` →
/// `$HOME/.config/arbiter/config.toml`.
pub fn default_path() -> PathBuf {
    if let Ok(path) = std::env::var("ARBITER_CONFIG") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    config_dir().join(CONFIG_FILE_NAME)
}

/// The arbiter config directory (without the file name), honoring XDG.
fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("arbiter");
        }
    }
    let home = std::env::var_os("HOME").unwrap_or_else(|| OsString::from("."));
    PathBuf::from(home).join(".config").join("arbiter")
}

// ---------------------------------------------------------------------------
// Layered resolution helper
// ---------------------------------------------------------------------------

/// Which precedence layer produced a value (AMEND-3 order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    Default,
    File,
    Env,
    Cli,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::File => "file",
            Source::Env => "env",
            Source::Cli => "cli",
        }
    }
}

/// A resolved value tagged with the layer it came from. Fold higher layers on
/// top; earlier-won layers are never overwritten:
///
/// ```ignore
/// let port = Layered::new(8080u16)                       // default
///     .layered(file.start.port, Source::File)            // [start].port
///     .layered(env_port, Source::Env)                    // ARBITER_START_PORT
///     .layered(cli_port_if_flag_set, Source::Cli);       // clap value_source()
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Layered<T> {
    value: T,
    source: Source,
}

impl<T> Layered<T> {
    /// Start the ladder at the built-in default.
    pub fn new(value: T) -> Self {
        Layered {
            value,
            source: Source::Default,
        }
    }

    /// Fold one candidate from a strictly higher-precedence layer. `None`
    /// (layer unset) or a layer ≤ the current winner changes nothing.
    pub fn layered(self, candidate: Option<T>, source: Source) -> Self {
        match candidate {
            Some(value) if source > self.source => Layered { value, source },
            _ => self,
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn into_value(self) -> T {
        self.value
    }

    pub fn source(&self) -> Source {
        self.source
    }
}

// ---------------------------------------------------------------------------
// Environment layer
// ---------------------------------------------------------------------------

/// Collect `ARBITER_<SECTION>_<KEY>` environment overrides for one section.
///
/// The key is everything after `ARBITER_<SECTION>_`, lowercased verbatim —
/// i.e. env names map 1:1 onto snake_case TOML keys
/// (`ARBITER_CAPTURE_MAX_BODY_BYTES` → `max_body_bytes`). Values stay raw
/// strings; typed coercion against the current document happens in
/// [`apply_env_layer`].
pub fn env_overrides(section: &str) -> BTreeMap<String, String> {
    let prefix = format!("{ENV_PREFIX}{}_", section.to_ascii_uppercase());
    let mut out = BTreeMap::new();
    for (name, value) in std::env::vars() {
        let Some(key) = name.strip_prefix(&prefix) else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        out.insert(key.to_ascii_lowercase(), value);
    }
    out
}

/// Apply the environment layer over a loaded [`FileConfig`], in place.
///
/// Each override must name a first-level scalar or string-array key of its
/// section (typos fail closed, mirroring `deny_unknown_fields`): booleans
/// parse as `true/false`, integers/floats parse numerically, string arrays
/// split on `,` (entries trimmed). Nested tables (`[mock.fault]`,
/// `[mock.vars]`, `[tui.saved_filters]`) are not addressable via env —
/// configure those in the file or on the CLI.
///
/// Key/type validation runs against a fully-populated probe document, NOT
/// the live one: `toml` omits `None` fields when serializing `Option`s, so
/// an unset-but-valid key would otherwise look "unknown".
pub fn apply_env_layer(config: &mut FileConfig) -> Result<()> {
    // Round-trip through a generic tree so coercion can set leaves uniformly.
    let mut doc = toml::Value::try_from(&*config)
        .map_err(|e| Error::other(format!("config is not representable as TOML: {e}")))?;
    let table = doc
        .as_table_mut()
        .expect("FileConfig serializes to a TOML table");

    for section in FileConfig::SECTIONS {
        let overrides = env_overrides(section);
        if overrides.is_empty() {
            continue;
        }
        let Some(section_table) = table.get_mut(section).and_then(|v| v.as_table_mut()) else {
            continue;
        };
        for (key, raw) in &overrides {
            let expected = probe_type(section, key)
                .ok_or_else(|| unknown_override(section, key, raw, "unknown config key"))?;
            let value = coerce(&expected, section, key, raw)?;
            section_table.insert(key.clone(), value);
        }
    }

    *config = doc.try_into().map_err(|e| {
        Error::other(format!(
            "environment overrides produced invalid config: {e}"
        ))
    })?;
    Ok(())
}

/// The expected TOML kind of `(section, key)`, derived from a probe
/// FileConfig whose every `Option` is populated. Returns the probe leaf so
/// `coerce` can match on it; nested tables yield their table node, which
/// `coerce` rejects.
fn probe_type(section: &str, key: &str) -> Option<toml::Value> {
    use std::sync::LazyLock;
    static PROBE: LazyLock<toml::Value> = LazyLock::new(|| {
        let path_of = || Some(PathBuf::from("probe"));
        let text_of = || Some(String::new());
        let fault = FaultSection {
            latency_ms: Some(0),
            status: Some(0),
            error: text_of(),
            fraction_pct: Some(0),
        };
        let probe = FileConfig {
            start: StartSection {
                target: text_of(),
                port: Some(0),
                docs_port: Some(0),
                db_path: path_of(),
                docs_only: false,
                proxy_only: false,
                verbose: false,
            },
            capture: CaptureSection {
                exact: false,
                max_body_bytes: Some(0),
                idle_timeout_ms: Some(0),
                host: text_of(),
                ..Default::default()
            },
            replay: ReplaySection {
                mode: text_of(),
                delay_ms: Some(0),
                ..Default::default()
            },
            gateway: GatewaySection {
                policy_path: path_of(),
                credential_command: text_of(),
                capture_output: false,
            },
            tui: TuiSection {
                attach_url: text_of(),
                saved_filters: Vec::new(),
            },
            mock: MockSection {
                mode: text_of(),
                spec: path_of(),
                capture_dir: path_of(),
                watch: false,
                match_strategy: text_of(),
                fault: fault.clone(),
                vars: BTreeMap::new(),
            },
            proxy: ProxySection {
                fault,
                request_header_rules: Vec::new(),
                response_header_rules: Vec::new(),
                on_request: text_of(),
                on_response: text_of(),
                hook_server: text_of(),
                hook_timeout_ms: Some(0),
                ca_dir: path_of(),
                no_tls_intercept: false,
                tls_passthrough: Vec::new(),
                tls_cert: path_of(),
                tls_key: path_of(),
            },
        };
        toml::Value::try_from(&probe).expect("probe config serializes")
    });
    PROBE.get(section).and_then(|s| s.get(key)).cloned()
}

fn unknown_override(section: &str, key: &str, raw: &str, problem: &str) -> Error {
    Error::other(format!(
        "environment override {ENV_PREFIX}{}_{}={raw:?}: {problem}",
        section.to_ascii_uppercase(),
        key.to_ascii_uppercase(),
    ))
}

fn coerce(expected: &toml::Value, section: &str, key: &str, raw: &str) -> Result<toml::Value> {
    fn parsed<F>(section: &str, key: &str, raw: &str, expected: &str, f: F) -> Result<toml::Value>
    where
        F: FnOnce(&str) -> Option<toml::Value>,
    {
        f(raw.trim()).ok_or_else(|| unknown_override(section, key, raw, expected))
    }

    let value = match expected {
        toml::Value::Boolean(_) => parsed(section, key, raw, "expected true or false", |s| {
            s.parse::<bool>().ok().map(toml::Value::Boolean)
        })?,
        toml::Value::Integer(_) => parsed(section, key, raw, "expected an integer", |s| {
            s.parse::<i64>().ok().map(toml::Value::Integer)
        })?,
        toml::Value::Float(_) => parsed(section, key, raw, "expected a number", |s| {
            s.parse::<f64>().ok().map(toml::Value::Float)
        })?,
        toml::Value::String(_) => toml::Value::String(raw.to_string()),
        toml::Value::Array(items) => {
            if !items.iter().all(|i| matches!(i, toml::Value::String(_))) {
                return Err(unknown_override(
                    section,
                    key,
                    raw,
                    "array entries are strings",
                ));
            }
            let parsed: Vec<toml::Value> = raw
                .split(',')
                .map(|part| toml::Value::String(part.trim().to_string()))
                .collect();
            toml::Value::Array(parsed)
        }
        toml::Value::Datetime(_) | toml::Value::Table(_) => {
            return Err(unknown_override(
                section,
                key,
                raw,
                "nested tables cannot be set via environment variables",
            ));
        }
    };
    Ok(value)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{LazyLock, Mutex, MutexGuard};

    /// Process-wide serialization for tests that touch process-global state
    /// (environment variables). Shared by every module's config tests.
    static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    pub(crate) fn env_test_lock() -> MutexGuard<'static, ()> {
        match TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use test_support::env_test_lock;

    /// Unique-per-section names keep parallel env mutation impossible even
    /// though the mutex already serializes access.
    const START_PORT_ENV: &str = "ARBITER_START_PORT";
    const CAPTURE_HOST_ENV: &str = "ARBITER_CAPTURE_HOST";

    fn set_var(key: &str, value: &str) {
        // SAFETY-free variant: std::env::set_var is safe in edition 2021.
        std::env::set_var(key, value);
    }

    fn remove_var(key: &str) {
        std::env::remove_var(key);
    }

    // -- precedence matrix --------------------------------------------------

    #[test]
    fn layered_precedence_defaults_file_env_cli() {
        // defaults < file < env < cli, exercised as the pure ladder.
        let port = Layered::new(8080u16);
        assert_eq!(port.source(), Source::Default);

        // file wins over default
        let port = port.layered(Some(9000), Source::File);
        assert_eq!((port.value(), port.source()), (&9000, Source::File));

        // lower layer arriving late never overwrites
        let port = port.layered(Some(1), Source::Default);
        assert_eq!(port.value(), &9000);

        // env wins over file
        let port = port.layered(Some(9001), Source::Env);

        // cli wins over env
        let port = port.layered(Some(9002), Source::Cli);
        assert_eq!(port.value(), &9002);

        // unset higher layers change nothing
        let port = port.layered(None, Source::Cli);
        assert_eq!(port.value(), &9002);
        assert_eq!(port.into_value(), 9002);
    }

    #[test]
    fn file_then_env_then_explicit_cli_over_full_config() {
        let _guard = env_test_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[start]\nport = 9000\n\n[capture]\nhost = \"from-file\"\n",
        )
        .unwrap();

        let mut config = load(&path).unwrap();
        // file layer applied
        assert_eq!(config.start.port, Some(9000));
        assert_eq!(config.capture.host.as_deref(), Some("from-file"));

        set_var(START_PORT_ENV, "9001");
        remove_var(CAPTURE_HOST_ENV);
        apply_env_layer(&mut config).unwrap();
        // env layer beat the file for port; absent env left host alone
        assert_eq!(config.start.port, Some(9001));
        assert_eq!(config.capture.host.as_deref(), Some("from-file"));

        // explicit CLI flag beats both: folded via Layered with Source::Cli
        let cli_set = Some(9999u16);
        let effective = Layered::new(8080u16)
            .layered(Some(9000), Source::File)
            .layered(config.start.port, Source::Env)
            .layered(cli_set, Source::Cli);
        assert_eq!(effective.into_value(), 9999);

        remove_var(START_PORT_ENV);
    }

    #[test]
    fn env_layer_coerces_scalars_and_arrays() {
        let _guard = env_test_lock();
        let mut config = FileConfig::default();
        set_var(START_PORT_ENV, "8123");
        set_var(CAPTURE_HOST_ENV, "example.test");
        set_var("ARBITER_CAPTURE_EXACT", "true");
        set_var("ARBITER_CAPTURE_ALLOW_QUERY", " api_key , session , trace ");
        config.capture.exact = false; // ensure env flips it

        apply_env_layer(&mut config).unwrap();

        assert_eq!(config.start.port, Some(8123));
        assert_eq!(config.capture.host.as_deref(), Some("example.test"));
        assert!(config.capture.exact);
        assert_eq!(
            config.capture.allow_query,
            vec![
                "api_key".to_string(),
                "session".to_string(),
                "trace".to_string()
            ]
        );

        remove_var(START_PORT_ENV);
        remove_var(CAPTURE_HOST_ENV);
        remove_var("ARBITER_CAPTURE_EXACT");
        remove_var("ARBITER_CAPTURE_ALLOW_QUERY");
    }

    #[test]
    fn env_layer_rejects_bad_values_and_unknown_keys_fail_closed() {
        let _guard = env_test_lock();
        set_var(START_PORT_ENV, "not-a-port");
        let mut config = FileConfig::default();
        let err = apply_env_layer(&mut config).unwrap_err();
        remove_var(START_PORT_ENV);
        assert!(
            err.to_string().contains("expected an integer"),
            "unexpected error: {err}"
        );

        set_var("ARBITER_START_TOTALLY_UNKNOWN", "x");
        let err = apply_env_layer(&mut config).unwrap_err();
        remove_var("ARBITER_START_TOTALLY_UNKNOWN");
        assert!(
            err.to_string().contains("unknown config key"),
            "unexpected error: {err}"
        );
    }

    // -- file parsing ---------------------------------------------------------

    #[test]
    fn deny_unknown_fields_names_the_offender() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "[start]\nprot = 8080\n").unwrap();
        let err = load(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field `prot`"), "message was: {msg}");
        assert!(msg.contains("invalid config file"), "message was: {msg}");

        let path2 = dir.path().join("bad-section.toml");
        std::fs::write(&path2, "[bogus]\nx = 1\n").unwrap();
        let err = load(&path2).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `bogus`"),
            "message was: {err}"
        );
    }

    #[test]
    fn load_or_default_treats_missing_as_empty() {
        let err = load(Path::new("/nonexistent/arbiter/config.toml")).unwrap_err();
        assert!(matches!(err, Error::Io { .. }));
        let cfg = load_or_default(Path::new("/nonexistent/arbiter/config.toml")).unwrap();
        assert_eq!(cfg, FileConfig::default());
    }

    #[test]
    fn full_document_round_trips_every_section() {
        let text = r#"
[start]
target = "https://api.example.com"
port = 8080
docs_port = 9000
db_path = "traffic.db"
docs_only = false
proxy_only = true
verbose = true

[capture]
exact = true
max_body_bytes = 1048576
idle_timeout_ms = 30000
reject_secret = ["sk-ant-"]
allow_binary_media_type = ["image/png"]
redact_header = ["x-custom-cred"]
allow_query = ["trace"]
host = "0.0.0.0"

[replay]
mode = "semantic-json-response"
delay_ms = 25
fail_on_diff = true
ignore_pointer = ["/timestamps"]
credential_env = ["Authorization=MY_TOKEN"]
query_env = ["api_key=MY_KEY"]

[gateway]
policy_path = "policy.toml"
credential_command = "op read token"
capture_output = true

[[tui.saved_filters]]
name = "anthropic errors"
query = "provider=anthropic status>=400"

[tui]
attach_url = "http://127.0.0.1:9000"

[mock]
mode = "capture-first"
spec = "spec.yaml"
capture_dir = "captures"
watch = true
match_strategy = "strongest"

[mock.fault]
latency_ms = 120
status = 503
error = "timeout"
fraction_pct = 10

[mock.vars]
region = "us-east-1"

[proxy.fault]
latency_ms = 5

[proxy]
request_header_rules = ["set x-a=b"]
response_header_rules = []
on_request = "./hook.sh request"
on_response = "./hook.sh response"
hook_server = "127.0.0.1:9911"
hook_timeout_ms = 250
ca_dir = "~/.local/share/arbiter/ca"
no_tls_intercept = false
tls_passthrough = ["*.internal.corp"]
tls_cert = "cert.pem"
tls_key = "key.pem"
"#;
        let cfg: FileConfig = toml::from_str(text).unwrap();
        assert_eq!(cfg.start.port, Some(8080));
        assert!(cfg.start.proxy_only);
        assert_eq!(cfg.capture.reject_secret, vec!["sk-ant-"]);
        assert_eq!(cfg.replay.mode.as_deref(), Some("semantic-json-response"));
        assert_eq!(cfg.tui.saved_filters.len(), 1);
        assert_eq!(cfg.tui.saved_filters[0].name, "anthropic errors");
        assert_eq!(
            cfg.mock.vars.get("region").map(String::as_str),
            Some("us-east-1")
        );
        assert_eq!(cfg.mock.fault.status, Some(503));
        assert_eq!(cfg.proxy.hook_timeout_ms, Some(250));
        assert_eq!(cfg.proxy.tls_passthrough, vec!["*.internal.corp"]);

        // serialization keeps every populated section addressable again
        let re: FileConfig = toml::from_str(&toml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(re, cfg);
    }

    // -- path resolution ------------------------------------------------------

    #[test]
    fn default_path_prefers_arbiter_config_then_xdg() {
        let _guard = env_test_lock();

        set_var("ARBITER_CONFIG", "/tmp/explicit-config.toml");
        assert_eq!(default_path(), PathBuf::from("/tmp/explicit-config.toml"));

        remove_var("ARBITER_CONFIG");
        set_var("XDG_CONFIG_HOME", "/xdg-root");
        assert_eq!(
            default_path(),
            PathBuf::from("/xdg-root/arbiter/config.toml")
        );

        remove_var("XDG_CONFIG_HOME");
        set_var("HOME", "/home/tester");
        assert_eq!(
            default_path(),
            PathBuf::from("/home/tester/.config/arbiter/config.toml")
        );
    }

    // -- env_overrides mapping -------------------------------------------------

    #[test]
    fn env_overrides_lowercases_to_snake_case_keys() {
        let _guard = env_test_lock();
        set_var("ARBITER_REPLAY_FAIL_ON_DIFF", "true");
        set_var("ARBITER_REPLAY_DELAY_MS", "40");
        set_var("ARBITER_OTHER_SECTION_X", "ignored");
        set_var("ARBITER_REPLAY_", "empty-key-ignored");

        let map = env_overrides("replay");

        remove_var("ARBITER_REPLAY_FAIL_ON_DIFF");
        remove_var("ARBITER_REPLAY_DELAY_MS");
        remove_var("ARBITER_OTHER_SECTION_X");
        remove_var("ARBITER_REPLAY_");

        assert_eq!(map.len(), 2, "map was: {map:?}");
        assert_eq!(map.get("fail_on_diff").map(String::as_str), Some("true"));
        assert_eq!(map.get("delay_ms").map(String::as_str), Some("40"));
    }

    #[test]
    fn source_orders_by_precedence() {
        assert!(Source::Default < Source::File);
        assert!(Source::File < Source::Env);
        assert!(Source::Env < Source::Cli);
    }

    // silence unused-import lint when Result alias is only used in signatures
    #[allow(dead_code)]
    fn _result_witness(_: Result<()>) {}
}
