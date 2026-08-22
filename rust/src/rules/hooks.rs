//! Scripting hooks (W6): subprocess and webhook modification hooks.
//!
//! Hooks let an external script inspect (a redacted view of) each exchange and
//! optionally rewrite headers/body before the change is applied to the live
//! traffic. Two transports share one JSON protocol:
//!
//! 1. **Subprocess** (`--on-request CMD` / `--on-response CMD`): per event,
//!    `sh -c CMD` receives the event JSON on stdin; its stdout is the reply.
//! 2. **Webhook** (`--hook-server URL`): the same event JSON is POSTed to the
//!    URL; the HTTP response body is the reply. When `--hook-server` is set it
//!    takes precedence over the per-phase subprocess commands (one channel per
//!    event, never both).
//!
//! # Event payload (stdin / POST body)
//!
//! ```json
//! {
//!   "phase": "request" | "response",
//!   "sequence": 7,
//!   "method": "GET",
//!   "path": "/v1/chat",
//!   "query": "model=x",
//!   "headers": {"authorization": ["__redacted__"], "x-ok": ["1"]},
//!   "bodyBase64": "aGVsbG8="
//! }
//! ```
//!
//! Headers are a REDACTED view ([`crate::redaction::RedactionPolicy::default`]):
//! credential-bearing names keep their place but carry the `__redacted__`
//! sentinel, so hooks can branch on their presence without ever seeing the
//! secret. Bodies are base64 and inlined only up to [`MAX_INLINE_BODY`]
//! bytes; larger bodies omit `bodyBase64` and set `bodyOmitted: true` plus
//! `totalSize: N` so scripts still learn the size.
//!
//! # Reply semantics (stdout / 2xx response body)
//!
//! - Empty output → [`HookOutcome::Unchanged`].
//! - A JSON object carrying **only** modification keys — `headers` (a full
//!   replacement name→values map, names lowercased on apply) and/or
//!   `bodyBase64` — → [`HookOutcome::Modified`]. A hook that echoes the event
//!   envelope back (e.g. `cat`) therefore stays `Unchanged`; to modify, emit
//!   exactly a modification object.
//! - Anything else (non-object JSON, envelope echo, unparseable text) →
//!   `Unchanged` with a warning.
//! - Non-zero exit (subprocess) or non-2xx / transport failure (webhook) →
//!   [`HookOutcome::Drop`] with a warning; the proxy turns this into a generic
//!   502 and records the failure at stage `request-capture` /
//!   `response-capture`.
//!
//! # Fail-open guarantee
//!
//! **Hooks must never take down proxying.** On timeout the child process is
//! killed (or the webhook request aborted) and the outcome is `Unchanged` with
//! a single warning — the exchange proceeds unmodified. The only outcomes that
//! drop traffic are explicit ones from the hook itself (non-zero exit /
//! non-2xx), never an infrastructure anomaly.

use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::error::{Error, Result};
use crate::redaction::{RedactionPolicy, REDACTED_VALUE};
use crate::types::HeaderMapValues;

/// Largest body inlined into the hook event as `bodyBase64` (1 MiB). Larger
/// bodies are described with `bodyOmitted`/`totalSize` instead.
pub const MAX_INLINE_BODY: usize = 1024 * 1024;

const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Hook wiring parsed from CLI flags; consumed by cli-dx at assembly.
#[derive(Debug, Clone, PartialEq)]
pub struct HookConfig {
    /// `--on-request CMD`: subprocess run for each request event.
    pub request_cmd: Option<String>,
    /// `--on-response CMD`: subprocess run for each response event.
    pub response_cmd: Option<String>,
    /// `--hook-server URL`: webhook receiver; takes precedence over the
    /// subprocess commands for both phases.
    pub webhook_url: Option<Url>,
    /// Per-event budget in milliseconds (default 5000).
    pub timeout_ms: u64,
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            request_cmd: None,
            response_cmd: None,
            webhook_url: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

impl HookConfig {
    /// Parse the W6 hook flags. Invalid values abort startup with a cause line
    /// plus a `  help:` hint (surfaced verbatim by the CLI layer).
    pub fn from_cli(
        on_request: Option<&str>,
        on_response: Option<&str>,
        hook_server: Option<&str>,
        hook_timeout_ms: Option<u64>,
    ) -> Result<Self> {
        let request_cmd = match on_request {
            Some(cmd) if cmd.trim().is_empty() => {
                return Err(Error::other(
                    "--on-request received an empty command\n  help: \
                     give a shell command, e.g. --on-request 'python3 rewrite.py'",
                ));
            }
            Some(cmd) => Some(cmd.to_string()),
            None => None,
        };
        let response_cmd = match on_response {
            Some(cmd) if cmd.trim().is_empty() => {
                return Err(Error::other(
                    "--on-response received an empty command\n  help: \
                     give a shell command, e.g. --on-response 'python3 rewrite.py'",
                ));
            }
            Some(cmd) => Some(cmd.to_string()),
            None => None,
        };
        let webhook_url = match hook_server {
            Some(raw) if raw.trim().is_empty() => {
                return Err(Error::other(
                    "--hook-server received an empty URL\n  help: \
                     give an http(s) URL, e.g. --hook-server http://127.0.0.1:9000/hooks",
                ));
            }
            Some(raw) => {
                let url = Url::parse(raw).map_err(|e| {
                    Error::other(format!(
                        "invalid --hook-server URL '{raw}': {e}\n  help: \
                         use an absolute http(s) URL, e.g. --hook-server http://127.0.0.1:9000/hooks"
                    ))
                })?;
                if !matches!(url.scheme(), "http" | "https") {
                    return Err(Error::other(format!(
                        "--hook-server must be http(s), got '{}'\n  help: \
                         point --hook-server at an HTTP webhook receiver",
                        url.scheme()
                    )));
                }
                Some(url)
            }
            None => None,
        };
        let timeout_ms = hook_timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        if timeout_ms == 0 {
            return Err(Error::other(
                "--hook-timeout-ms must be at least 1\n  help: \
                 give a positive budget in milliseconds, e.g. --hook-timeout-ms 5000",
            ));
        }
        Ok(Self {
            request_cmd,
            response_cmd,
            webhook_url,
            timeout_ms,
        })
    }

    /// Hot-path short circuit: no hook configured skips the whole pipeline leg.
    pub fn is_configured(&self) -> bool {
        self.request_cmd.is_some() || self.response_cmd.is_some() || self.webhook_url.is_some()
    }
}

/// What a hook decided for one exchange.
#[derive(Debug, Clone, PartialEq)]
pub enum HookOutcome {
    /// Proceed unmodified (also the fail-open result for timeouts).
    Unchanged,
    /// Apply the carried header/body changes to the live exchange.
    Modified(ModifiedExchange),
    /// Drop the exchange; the proxy answers 502 generically and records a
    /// capture failure at stage `request-capture` / `response-capture`.
    Drop,
}

/// The modification payload a hook may return: an optional replacement
/// header map and/or an optional base64 replacement body. Serde shape is the
/// camelCase wire form (`headers`, `bodyBase64`); unknown fields are ignored
/// on deserialize so the protocol can grow additively.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModifiedExchange {
    /// Full replacement name→values map for the phase's headers. Applied
    /// per-name (each name replaces all its previous values); names are
    /// lowercased on apply, matching the capture model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeaderMapValues>,
    /// Base64 replacement body for the phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
}

impl ModifiedExchange {
    /// Apply carried header changes in place. Pure with respect to ordering:
    /// names are applied in map (sorted) order.
    pub fn apply_headers(&self, headers: &mut HeaderMapValues) {
        if let Some(replacement) = &self.headers {
            for (name, values) in replacement {
                headers.insert(name.to_lowercase(), values.clone());
            }
        }
    }

    /// Decode the replacement body, if any. `None` when the hook sent no body
    /// or the base64 payload is malformed (callers treat that as "no body
    /// change" — a malformed reply never fails a capture).
    pub fn decoded_body(&self) -> Option<Vec<u8>> {
        let encoded = self.body_base64.as_deref()?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()
    }
}

/// Per-event context handed to [`run_request_hook`] / [`run_response_hook`].
pub struct HookContext<'a> {
    pub sequence: u64,
    pub method: String,
    pub path: String,
    pub query: String,
    /// End-to-end headers for the phase (pre-hook view).
    pub headers: HeaderMapValues,
    /// Request/response body bytes, when buffered.
    pub body: Option<&'a [u8]>,
}

impl HookContext<'_> {
    /// Build the wire event: a redacted header view (values of
    /// credential-bearing names replaced with `__redacted__`), base64 body up
    /// to [`MAX_INLINE_BODY`], and `bodyOmitted`/`totalSize` for larger ones.
    pub fn to_redacted_json(&self, phase: &str) -> Value {
        let policy = RedactionPolicy::default();
        let mut redacted: HeaderMapValues = HeaderMapValues::new();
        for (name, values) in &self.headers {
            if policy.should_redact_header(name) {
                redacted.insert(name.clone(), vec![REDACTED_VALUE.to_string(); values.len()]);
            } else {
                redacted.insert(name.clone(), values.clone());
            }
        }
        let mut event = json!({
            "phase": phase,
            "sequence": self.sequence,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "headers": redacted,
        });
        let object = event.as_object_mut().expect("event is an object");
        match self.body {
            Some(body) if body.len() <= MAX_INLINE_BODY => {
                object.insert(
                    "bodyBase64".to_string(),
                    Value::String(base64::engine::general_purpose::STANDARD.encode(body)),
                );
            }
            Some(body) => {
                object.insert("bodyOmitted".to_string(), Value::Bool(true));
                object.insert("totalSize".to_string(), json!(body.len()));
            }
            None => {}
        }
        event
    }
}

/// Run the request-phase hook (`phase: "request"`).
pub async fn run_request_hook(cfg: &HookConfig, ctx: &HookContext<'_>) -> HookOutcome {
    dispatch(cfg, ctx, "request", cfg.request_cmd.as_deref()).await
}

/// Run the response-phase hook (`phase: "response"`).
pub async fn run_response_hook(cfg: &HookConfig, ctx: &HookContext<'_>) -> HookOutcome {
    dispatch(cfg, ctx, "response", cfg.response_cmd.as_deref()).await
}

async fn dispatch(
    cfg: &HookConfig,
    ctx: &HookContext<'_>,
    phase: &str,
    cmd: Option<&str>,
) -> HookOutcome {
    if !cfg.is_configured() {
        return HookOutcome::Unchanged;
    }
    let event = ctx.to_redacted_json(phase);
    if let Some(url) = &cfg.webhook_url {
        run_webhook(url, &event, cfg.timeout_ms).await
    } else if let Some(cmd) = cmd {
        run_subprocess(cmd, &event, cfg.timeout_ms).await
    } else {
        // No webhook; the other phase's command may be configured but this
        // phase has none — nothing to run for this event.
        HookOutcome::Unchanged
    }
}

/// `sh -c CMD` transport. Spawn failure or non-zero exit → `Drop`; timeout →
/// kill + fail-open `Unchanged`; exit 0 → parse the reply.
async fn run_subprocess(cmd: &str, event: &Value, timeout_ms: u64) -> HookOutcome {
    let payload = event.to_string();
    let child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(e) => {
            warn(format!("hook command '{cmd}' failed to spawn: {e}"));
            return HookOutcome::Drop;
        }
    };
    {
        let Some(mut stdin) = child.stdin.take() else {
            warn(format!("hook command '{cmd}' has no stdin pipe"));
            return HookOutcome::Drop;
        };
        use tokio::io::AsyncWriteExt;
        if let Err(e) = stdin.write_all(payload.as_bytes()).await {
            // Script exited before consuming stdin; its exit status decides.
            warn(format!("hook command '{cmd}' closed stdin early: {e}"));
        }
        // Drop stdin so the child sees EOF.
    }
    let mut stdout = child.stdout.take();
    let waited = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
        let mut buf = Vec::new();
        if let Some(stdout) = stdout.as_mut() {
            use tokio::io::AsyncReadExt;
            stdout.read_to_end(&mut buf).await?;
        }
        child.wait().await.map(|status| (status, buf))
    })
    .await;
    match waited {
        Ok(Ok((status, buf))) => {
            if !status.success() {
                warn(format!(
                    "hook command '{cmd}' exited with {status}; dropping exchange"
                ));
                return HookOutcome::Drop;
            }
            parse_reply(&String::from_utf8_lossy(&buf), cmd)
        }
        Ok(Err(e)) => {
            warn(format!("hook command '{cmd}' I/O failed: {e}"));
            HookOutcome::Drop
        }
        Err(_elapsed) => {
            // kill_on_drop(true) reaps the child when `child` drops here.
            warn(format!(
                "hook command '{cmd}' timed out after {timeout_ms} ms; \
                 failing open (exchange proceeds unmodified)"
            ));
            HookOutcome::Unchanged
        }
    }
}

/// Webhook transport: POST the event JSON, apply the same reply rules.
/// Non-2xx / transport failure → `Drop`; timeout → fail-open `Unchanged`.
async fn run_webhook(url: &Url, event: &Value, timeout_ms: u64) -> HookOutcome {
    static CLIENT: std::sync::LazyLock<reqwest::Client> =
        std::sync::LazyLock::new(reqwest::Client::new);
    let client = &*CLIENT;
    let payload = event.to_string();
    let request = client
        .post(url.as_str())
        .header("content-type", "application/json")
        .body(payload);
    match tokio::time::timeout(Duration::from_millis(timeout_ms), request.send()).await {
        Ok(Ok(response)) => {
            let status = response.status();
            if !status.is_success() {
                warn(format!(
                    "hook webhook {url} answered {status}; dropping exchange"
                ));
                return HookOutcome::Drop;
            }
            match tokio::time::timeout(Duration::from_millis(timeout_ms), response.text()).await {
                Ok(Ok(body)) => parse_reply(&body, &format!("webhook {url}")),
                Ok(Err(e)) => {
                    warn(format!("hook webhook {url} body read failed: {e}"));
                    HookOutcome::Drop
                }
                Err(_) => {
                    warn(format!(
                        "hook webhook {url} body read timed out after {timeout_ms} ms; \
                         failing open (exchange proceeds unmodified)"
                    ));
                    HookOutcome::Unchanged
                }
            }
        }
        Ok(Err(e)) => {
            warn(format!("hook webhook {url} request failed: {e}"));
            HookOutcome::Drop
        }
        Err(_) => {
            warn(format!(
                "hook webhook {url} timed out after {timeout_ms} ms; \
                 failing open (exchange proceeds unmodified)"
            ));
            HookOutcome::Unchanged
        }
    }
}

/// Interpret hook stdout / webhook body per the reply contract (module docs).
fn parse_reply(text: &str, source: &str) -> HookOutcome {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return HookOutcome::Unchanged;
    }
    let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
        warn(format!(
            "hook {source} wrote non-JSON output; ignoring (exchange proceeds unmodified)"
        ));
        return HookOutcome::Unchanged;
    };
    let Value::Object(map) = value else {
        warn(format!(
            "hook {source} wrote non-object JSON; ignoring (exchange proceeds unmodified)"
        ));
        return HookOutcome::Unchanged;
    };
    // A modification object carries ONLY known modification keys and at least
    // one of them; anything else (e.g. an echoed event envelope) is a
    // passthrough so `cat`-style hooks stay Unchanged.
    let is_modification = !map.is_empty()
        && map.keys().all(|k| k == "headers" || k == "bodyBase64")
        && (map.contains_key("headers") || map.contains_key("bodyBase64"));
    if !is_modification {
        return HookOutcome::Unchanged;
    }
    match serde_json::from_value::<ModifiedExchange>(Value::Object(map)) {
        Ok(modified) => HookOutcome::Modified(modified),
        Err(e) => {
            warn(format!("hook {source} sent a malformed modification: {e}"));
            HookOutcome::Unchanged
        }
    }
}

fn warn(message: String) {
    eprintln!("warn: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn ctx<'a>(headers: HeaderMapValues, body: Option<&'a [u8]>) -> HookContext<'a> {
        HookContext {
            sequence: 7,
            method: "POST".to_string(),
            path: "/v1/chat".to_string(),
            query: "model=x".to_string(),
            headers,
            body,
        }
    }

    fn subprocess_cfg(cmd: &str, timeout_ms: u64) -> HookConfig {
        HookConfig {
            request_cmd: Some(cmd.to_string()),
            response_cmd: None,
            webhook_url: None,
            timeout_ms,
        }
    }

    // ---- reply parsing ----

    #[test]
    fn empty_output_is_unchanged() {
        assert_eq!(parse_reply("", "test"), HookOutcome::Unchanged);
        assert_eq!(parse_reply("   \n ", "test"), HookOutcome::Unchanged);
    }

    #[test]
    fn modification_object_is_modified() {
        let outcome = parse_reply(r#"{"headers":{"x-injected":["1"]}}"#, "test");
        match outcome {
            HookOutcome::Modified(m) => {
                assert_eq!(
                    m.headers.as_ref().unwrap().get("x-injected"),
                    Some(&vec!["1".to_string()])
                );
                assert!(m.body_base64.is_none());
            }
            other => panic!("expected Modified, got {other:?}"),
        }
    }

    #[test]
    fn body_only_modification_is_modified() {
        let outcome = parse_reply(r#"{"bodyBase64":"aGk="}"#, "test");
        match outcome {
            HookOutcome::Modified(m) => {
                assert_eq!(m.decoded_body().as_deref(), Some(b"hi".as_slice()));
            }
            other => panic!("expected Modified, got {other:?}"),
        }
    }

    #[test]
    fn echoed_envelope_is_passthrough() {
        let envelope = r#"{"phase":"request","sequence":7,"method":"POST",
            "path":"/v1/chat","query":"model=x",
            "headers":{"authorization":["__redacted__"]},"bodyBase64":"aGk="}"#;
        assert_eq!(parse_reply(envelope, "test"), HookOutcome::Unchanged);
    }

    #[test]
    fn malformed_output_is_unchanged() {
        assert_eq!(parse_reply("not json", "test"), HookOutcome::Unchanged);
        assert_eq!(parse_reply("[1,2]", "test"), HookOutcome::Unchanged);
    }

    // ---- subprocess mode ----

    #[tokio::test]
    async fn cat_passthrough_is_unchanged() {
        let cfg = subprocess_cfg("cat", 5000);
        let headers = HeaderMapValues::from([("x-ok".to_string(), vec!["1".to_string()])]);
        let outcome = run_request_hook(&cfg, &ctx(headers, Some(b"hello"))).await;
        assert_eq!(outcome, HookOutcome::Unchanged);
    }

    #[tokio::test]
    async fn modified_headers_json_is_modified() {
        let cfg = subprocess_cfg("printf '%s' '{\"headers\":{\"x-injected\":[\"1\"]}}'", 5000);
        let headers = HeaderMapValues::from([("x-original".to_string(), vec!["a".to_string()])]);
        let outcome = run_request_hook(&cfg, &ctx(headers, None)).await;
        match outcome {
            HookOutcome::Modified(m) => {
                assert_eq!(
                    m.headers.as_ref().unwrap().get("x-injected"),
                    Some(&vec!["1".to_string()])
                );
                assert!(m.headers.as_ref().unwrap().get("x-original").is_none());
            }
            other => panic!("expected Modified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn nonzero_exit_drops() {
        let cfg = subprocess_cfg("exit 3", 5000);
        let outcome = run_request_hook(&cfg, &ctx(HeaderMapValues::new(), None)).await;
        assert_eq!(outcome, HookOutcome::Drop);
    }

    #[tokio::test]
    async fn timeout_fails_open_fast() {
        let started = std::time::Instant::now();
        let cfg = subprocess_cfg("sleep 10", 200);
        let outcome = run_request_hook(&cfg, &ctx(HeaderMapValues::new(), None)).await;
        assert_eq!(outcome, HookOutcome::Unchanged);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "timeout must not wait for the child: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn spawn_failure_drops() {
        let cfg = subprocess_cfg("definitely-not-a-real-binary-xyz", 5000);
        let outcome = run_request_hook(&cfg, &ctx(HeaderMapValues::new(), None)).await;
        assert_eq!(outcome, HookOutcome::Drop);
    }

    #[tokio::test]
    async fn response_hook_uses_response_phase() {
        let cfg = HookConfig {
            request_cmd: None,
            response_cmd: Some("cat".to_string()),
            webhook_url: None,
            timeout_ms: 5000,
        };
        let outcome = run_response_hook(&cfg, &ctx(HeaderMapValues::new(), None)).await;
        assert_eq!(outcome, HookOutcome::Unchanged);
    }

    #[tokio::test]
    async fn unconfigured_config_short_circuits() {
        let cfg = HookConfig::default();
        assert!(!cfg.is_configured());
        let outcome = run_request_hook(&cfg, &ctx(HeaderMapValues::new(), None)).await;
        assert_eq!(outcome, HookOutcome::Unchanged);
    }

    // ---- webhook mode ----

    #[tokio::test]
    async fn webhook_receives_redacted_payload_and_reply_applies() {
        use axum::extract::State;
        use axum::http::StatusCode;
        use axum::routing::post;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Value>(1);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router = axum::Router::new()
            .route(
                "/hooks",
                post(
                    |State(tx): State<tokio::sync::mpsc::Sender<Value>>, body: String| async move {
                        let event: Value = serde_json::from_str(&body).unwrap();
                        let _ = tx.send(event).await;
                        (
                            StatusCode::OK,
                            r#"{"headers":{"x-injected":["1"]}}"#.to_string(),
                        )
                    },
                ),
            )
            .with_state(tx);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let cfg = HookConfig {
            request_cmd: None,
            response_cmd: None,
            webhook_url: Some(Url::parse(&format!("http://{addr}/hooks")).unwrap()),
            timeout_ms: 5000,
        };
        let headers = HeaderMapValues::from([
            (
                "authorization".to_string(),
                vec!["Bearer sk-secret".to_string()],
            ),
            ("x-ok".to_string(), vec!["1".to_string()]),
        ]);
        let outcome = run_request_hook(&cfg, &ctx(headers, Some(b"hello"))).await;

        match outcome {
            HookOutcome::Modified(m) => {
                assert_eq!(
                    m.headers.as_ref().unwrap().get("x-injected"),
                    Some(&vec!["1".to_string()])
                );
            }
            other => panic!("expected Modified, got {other:?}"),
        }

        let event = rx.recv().await.unwrap();
        assert_eq!(event["phase"], "request");
        assert_eq!(event["sequence"], 7);
        assert_eq!(event["method"], "POST");
        assert_eq!(event["path"], "/v1/chat");
        assert_eq!(event["query"], "model=x");
        assert_eq!(
            event["headers"]["authorization"],
            serde_json::json!(["__redacted__"])
        );
        assert_eq!(event["headers"]["x-ok"], serde_json::json!(["1"]));
        assert_eq!(event["bodyBase64"], "aGVsbG8=");
        assert!(event.get("bodyOmitted").is_none());
    }

    #[tokio::test]
    async fn webhook_non_2xx_drops() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router = axum::Router::new().route(
            "/hooks",
            axum::routing::post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let cfg = HookConfig {
            request_cmd: None,
            response_cmd: None,
            webhook_url: Some(Url::parse(&format!("http://{addr}/hooks")).unwrap()),
            timeout_ms: 5000,
        };
        let outcome = run_request_hook(&cfg, &ctx(HeaderMapValues::new(), None)).await;
        assert_eq!(outcome, HookOutcome::Drop);
    }

    #[tokio::test]
    async fn webhook_timeout_fails_open_fast() {
        let started = std::time::Instant::now();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app: axum::Router = axum::Router::new().route(
            "/hooks",
            axum::routing::post(|| async {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                (StatusCode::OK, "late")
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let cfg = HookConfig {
            request_cmd: None,
            response_cmd: None,
            webhook_url: Some(Url::parse(&format!("http://{addr}/hooks")).unwrap()),
            timeout_ms: 200,
        };
        let outcome = run_request_hook(&cfg, &ctx(HeaderMapValues::new(), None)).await;
        assert_eq!(outcome, HookOutcome::Unchanged);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "webhook timeout must not wait: {:?}",
            started.elapsed()
        );
    }

    // ---- event shaping ----

    #[test]
    fn redacted_json_masks_sensitive_headers() {
        let headers = HeaderMapValues::from([
            (
                "authorization".to_string(),
                vec!["Bearer sk-secret".to_string()],
            ),
            ("x-ok".to_string(), vec!["1".to_string(), "2".to_string()]),
        ]);
        let event = ctx(headers, None).to_redacted_json("request");
        assert_eq!(event["phase"], "request");
        assert_eq!(event["headers"]["authorization"], json!(["__redacted__"]));
        assert_eq!(event["headers"]["x-ok"], json!(["1", "2"]));
        assert!(event.get("bodyBase64").is_none());
        assert!(event.get("bodyOmitted").is_none());
    }

    #[test]
    fn oversized_body_is_omitted_with_total_size() {
        let big = vec![0u8; MAX_INLINE_BODY + 1];
        let event = ctx(HeaderMapValues::new(), Some(&big)).to_redacted_json("response");
        assert!(event.get("bodyBase64").is_none());
        assert_eq!(event["bodyOmitted"], json!(true));
        assert_eq!(event["totalSize"], json!(MAX_INLINE_BODY + 1));
        assert_eq!(event["phase"], "response");
    }

    #[test]
    fn body_at_cap_is_inlined() {
        let exact = vec![7u8; MAX_INLINE_BODY];
        let event = ctx(HeaderMapValues::new(), Some(&exact)).to_redacted_json("request");
        assert!(event.get("bodyBase64").is_some());
        assert!(event.get("bodyOmitted").is_none());
    }

    // ---- ModifiedExchange application ----

    #[test]
    fn apply_headers_replaces_names_and_lowercases() {
        let mut headers = HeaderMapValues::from([
            ("x-old".to_string(), vec!["keep".to_string()]),
            ("X-Replace".to_string(), vec!["stale".to_string()]),
        ]);
        let modified = ModifiedExchange {
            headers: Some(HeaderMapValues::from([(
                "X-Replace".to_string(),
                vec!["fresh".to_string()],
            )])),
            body_base64: None,
        };
        modified.apply_headers(&mut headers);
        assert_eq!(headers.get("x-replace"), Some(&vec!["fresh".to_string()]));
        assert_eq!(headers.get("x-old"), Some(&vec!["keep".to_string()]));
    }

    // ---- CLI parsing ----

    #[test]
    fn from_cli_defaults_and_roundtrip() {
        let cfg = HookConfig::from_cli(Some("python3 req.py"), Some("python3 resp.py"), None, None)
            .unwrap();
        assert_eq!(cfg.request_cmd.as_deref(), Some("python3 req.py"));
        assert_eq!(cfg.response_cmd.as_deref(), Some("python3 resp.py"));
        assert_eq!(cfg.webhook_url, None);
        assert_eq!(cfg.timeout_ms, 5000);
        assert!(cfg.is_configured());
        assert!(!HookConfig::default().is_configured());
    }

    #[test]
    fn from_cli_parses_hook_server_and_timeout() {
        let cfg = HookConfig::from_cli(None, None, Some("http://127.0.0.1:9000/hooks"), Some(250))
            .unwrap();
        assert_eq!(
            cfg.webhook_url.as_ref().unwrap().as_str(),
            "http://127.0.0.1:9000/hooks"
        );
        assert_eq!(cfg.timeout_ms, 250);
        assert!(cfg.is_configured());
    }

    #[test]
    fn from_cli_rejects_bad_input_with_help() {
        let err = HookConfig::from_cli(Some("   "), None, None, None).unwrap_err();
        assert!(err.to_string().contains("--on-request"), "{err}");
        assert!(err.to_string().contains("help:"), "{err}");

        let err = HookConfig::from_cli(None, Some(""), None, None).unwrap_err();
        assert!(err.to_string().contains("--on-response"), "{err}");

        let err = HookConfig::from_cli(None, None, Some("not a url"), None).unwrap_err();
        assert!(err.to_string().contains("--hook-server"), "{err}");
        assert!(err.to_string().contains("help:"), "{err}");

        let err = HookConfig::from_cli(None, None, Some("ftp://x/hooks"), None).unwrap_err();
        assert!(err.to_string().contains("http(s)"), "{err}");

        let err = HookConfig::from_cli(None, None, None, Some(0)).unwrap_err();
        assert!(err.to_string().contains("--hook-timeout-ms"), "{err}");
    }
}
