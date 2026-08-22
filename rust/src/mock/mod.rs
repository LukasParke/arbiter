//! Mock/simulate engine (W3): Prism-parity example generation from an
//! OpenAPI spec, Hoverfly/WireMock-parity capture replay, shared matching
//! predicates (AMEND-1 glob library), six-token templating (AMEND-7), the
//! sole fault injector for both mock and proxy modes (AMEND-5), and the
//! `arbiter mock` HTTP server with 500 ms mtime watch reload (AMEND-6).

pub mod capture_mock;
pub mod example;
pub mod fault;
pub mod matcher;
pub mod server;
pub mod template;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::ValueEnum;

use crate::error::{Error, Result};
use crate::types::HeaderMapValues;
pub use capture_mock::CaptureMock;
pub use fault::{FaultConfig, FaultDecision, FaultInjector, FaultKind};
pub use matcher::{compile_glob, compile_host_glob, GlobPattern, MatchRule, RequestPredicate};

use template::{render, TemplateContext};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// How incoming requests pick a stub in capture mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum MatchStrategy {
    /// Priority desc, then specificity desc, then insertion order.
    #[default]
    Strongest,
    /// First matching rule in insertion order.
    First,
}

impl MatchStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchStrategy::Strongest => "strongest",
            MatchStrategy::First => "first",
        }
    }
}

/// What the engine serves from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockMode {
    /// Generate example responses from an OpenAPI spec.
    Spec,
    /// Replay recorded exchanges byte-exact from a capture bundle.
    Capture,
}

/// A resolved response ready to be written to the wire. Captured responses
/// carry their recorded headers verbatim (`content_type` unset); generated
/// responses carry a content type and no extra headers.
#[derive(Debug, Clone, PartialEq)]
pub struct MockResponse {
    pub status: u16,
    pub content_type: Option<String>,
    /// Lowercase name/value header pairs served as-is.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Decomposed incoming request fed to matching + templating. Header keys
/// are lowercase.
#[derive(Debug, Clone, Default)]
pub struct IncomingRequest {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: HeaderMapValues,
    pub body: Vec<u8>,
}

/// Compiled serving engine: every pattern/template is compiled at
/// construction — never on the request hot path.
#[derive(Clone)]
pub struct MockEngine {
    source: MockSource,
    strategy: MatchStrategy,
    vars: Arc<BTreeMap<String, String>>,
}

#[derive(Clone)]
enum MockSource {
    Spec(Arc<serde_json::Value>),
    Capture(Arc<CaptureMock>),
}

impl MockEngine {
    /// Index a parsed OpenAPI document. Cheap: templates are matched by
    /// segments; no regex compilation needed for spec mode.
    pub fn spec(
        document: serde_json::Value,
        strategy: MatchStrategy,
        vars: BTreeMap<String, String>,
    ) -> Self {
        MockEngine {
            source: MockSource::Spec(Arc::new(document)),
            strategy,
            vars: Arc::new(vars),
        }
    }

    /// Wrap a loaded capture bundle.
    pub fn capture(
        capture: CaptureMock,
        strategy: MatchStrategy,
        vars: BTreeMap<String, String>,
    ) -> Self {
        MockEngine {
            source: MockSource::Capture(Arc::new(capture)),
            strategy,
            vars: Arc::new(vars),
        }
    }

    pub fn mode(&self) -> &'static str {
        match self.source {
            MockSource::Spec(_) => "spec",
            MockSource::Capture(_) => "capture",
        }
    }

    /// Number of matchable rules (spec operations / recorded exchanges).
    pub fn rule_count(&self) -> usize {
        match &self.source {
            MockSource::Spec(doc) => doc
                .get("paths")
                .and_then(serde_json::Value::as_object)
                .map(|paths| {
                    paths
                        .values()
                        .filter_map(serde_json::Value::as_object)
                        .map(|item| {
                            item.keys()
                                .filter(|k| {
                                    matches!(
                                        k.as_str(),
                                        "get"
                                            | "put"
                                            | "post"
                                            | "delete"
                                            | "options"
                                            | "head"
                                            | "patch"
                                            | "trace"
                                    )
                                })
                                .count()
                        })
                        .sum()
                })
                .unwrap_or(0),
            MockSource::Capture(capture) => capture.len(),
        }
    }

    /// Resolve an incoming request to a response, or None on miss.
    /// Spec-mode bodies run through the template renderer; recorded bodies
    /// are served byte-exact and NEVER templated (AMEND-7).
    pub fn respond(&self, req: &IncomingRequest) -> Option<MockResponse> {
        match &self.source {
            MockSource::Spec(spec) => {
                let (status, content_type, body) =
                    example::example_response_for(spec, &req.method, &req.path, None)?;
                // Template only when the body is text; JSON samples are.
                let body = match std::str::from_utf8(&body) {
                    Ok(text) => {
                        let ctx = TemplateContext {
                            path: &req.path,
                            query: &req.query,
                            headers: &req.headers,
                            vars: self.vars.as_ref(),
                        };
                        render(text, &ctx).into_bytes()
                    }
                    Err(_) => body,
                };
                Some(MockResponse {
                    status,
                    content_type: Some(content_type),
                    headers: Vec::new(),
                    body,
                })
            }
            MockSource::Capture(capture) => capture.respond(
                &req.method,
                &req.path,
                &req.query,
                &req.headers,
                &req.body,
                self.strategy,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Options + wiring
// ---------------------------------------------------------------------------

/// Fully-resolved options for `arbiter mock`.
#[derive(Debug, Clone)]
pub struct MockOptions {
    pub mode: MockMode,
    pub spec_path: Option<PathBuf>,
    pub capture_dir: Option<PathBuf>,
    pub host: String,
    pub port: u16,
    pub watch: bool,
    pub match_strategy: MatchStrategy,
    pub fault: FaultConfig,
    pub vars: BTreeMap<String, String>,
}

/// Build options from raw CLI parts (the typed `MockCommand` in
/// cli/mock.rs calls this; kept primitive so the mock engine never depends
/// on the private cli module).
#[allow(clippy::too_many_arguments)]
pub fn options_from_parts(
    spec: Option<PathBuf>,
    capture: Option<PathBuf>,
    host: String,
    port: u16,
    watch: bool,
    match_strategy: MatchStrategy,
    fault_latency_ms: Option<u64>,
    fault_status: Option<u16>,
    fault_error: Option<FaultKind>,
    fault_fraction: u8,
    var_pairs: &[String],
) -> Result<MockOptions> {
    let mode = match (&spec, &capture) {
        (Some(_), Some(_)) => {
            return Err(Error::other(
                "mock: --spec and --capture are mutually exclusive\n  help: pick one source: --spec openapi.yaml OR --capture DIR",
            ));
        }
        (Some(spec), None) => (MockMode::Spec, Some(spec.clone()), None),
        (None, Some(dir)) => (MockMode::Capture, None, Some(dir.clone())),
        (None, None) => {
            return Err(Error::other(
                "mock: no mock source given\n  help: pass --spec openapi.yaml (example generation) or --capture DIR (byte-exact replay)",
            ));
        }
    };

    let mut vars = BTreeMap::new();
    for pair in var_pairs {
        let (k, v) = pair.split_once('=').ok_or_else(|| {
            Error::other(format!(
                "mock: invalid --var '{pair}'\n  help: use KEY=VALUE form, e.g. --var env=test"
            ))
        })?;
        if k.is_empty() {
            return Err(Error::other(format!(
                "mock: empty variable name in --var '{pair}'\n  help: use KEY=VALUE form, e.g. --var env=test"
            )));
        }
        vars.insert(k.to_string(), v.to_string());
    }

    let fault = FaultConfig::from_cli(fault_latency_ms, fault_status, fault_error, fault_fraction)
        .map_err(|e| {
            Error::other(format!(
                "{e}\n  help: see arbiter mock --help for fault flag examples"
            ))
        })?;

    Ok(MockOptions {
        mode: mode.0,
        spec_path: mode.1,
        capture_dir: mode.2,
        host,
        port,
        watch,
        match_strategy,
        fault,
        vars,
    })
}

/// Compile an engine from raw sources. Every glob/regex/template compiles
/// here — call BEFORE binding sockets so bad input fails fast.
pub(crate) fn compile_engine(
    spec_path: Option<&Path>,
    capture_dir: Option<&Path>,
    strategy: MatchStrategy,
    vars: BTreeMap<String, String>,
) -> Result<MockEngine> {
    match (spec_path, capture_dir) {
        (Some(spec), None) => {
            let document = example::load_spec_document(spec)?;
            Ok(MockEngine::spec(document, strategy, vars))
        }
        (None, Some(dir)) => {
            let capture = CaptureMock::load(dir)?;
            Ok(MockEngine::capture(capture, strategy, vars))
        }
        (Some(_), Some(_)) => Err(Error::other(
            "mock: --spec and --capture are mutually exclusive",
        )),
        (None, None) => Err(Error::other("mock: no mock source given")),
    }
}

/// Run `arbiter mock` end-to-end: compile engine (fail fast), bind, serve,
/// optional watch loop, Ctrl-C shutdown.
pub async fn run_mock(opts: MockOptions) -> Result<()> {
    opts.fault.validate()?;

    let engine = match compile_engine(
        opts.spec_path.as_deref(),
        opts.capture_dir.as_deref(),
        opts.match_strategy,
        opts.vars.clone(),
    ) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("  help: check the source path/format (--spec wants yaml|yml|json; --capture wants an arbiter bundle directory)");
            return Err(e);
        }
    };

    let source_paths = server::MockSourcePaths {
        spec_path: opts.spec_path.clone(),
        capture_dir: opts.capture_dir.clone(),
    };
    let state = Arc::new(server::MockAppState::new(
        engine,
        opts.fault,
        opts.match_strategy,
        Arc::new(opts.vars.clone()),
        source_paths,
    ));

    let rules = state.engine.read().await.rule_count();
    let (addr, handle) = server::serve(&opts.host, opts.port, state.clone()).await?;
    eprintln!(
        "mock: {} mode, {rules} rule(s), listening on http://{addr} (strategy={}{})",
        engine_mode(&state).await,
        opts.match_strategy.as_str(),
        if opts.watch {
            ", watching for changes"
        } else {
            ""
        },
    );

    if opts.watch {
        server::spawn_watch(state);
    }

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| Error::io("mock: await ctrl-c", e))?;
    eprintln!("mock: shutting down");
    handle.abort();
    Ok(())
}

async fn engine_mode(state: &server::MockAppState) -> &'static str {
    state.engine.read().await.mode()
}
