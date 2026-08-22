//! Credential-injecting gateway mode.
//!
//! An untrusted client authenticates with an opaque short-lived gateway token.
//! Arbiter validates the request against a policy, records it with the token
//! redacted, obtains the real upstream credential through an injected
//! provider, and attaches it only to the upstream request. The client process
//! and the capture artifact never see the real credential.
//!
//! Port of `src/gateway/index.ts`.

mod policy;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use futures::StreamExt;
use http_body_util::BodyExt as _;
use serde::Serialize;
use tokio::sync::watch;

pub use policy::{
    credential_provider_from_command, extract_model, parse_expiry, path_allowed, token_matches,
    validate_policy, CredentialProvider, GatewayPolicy, CREDENTIAL_COMMAND_HEADER,
    CREDENTIAL_COMMAND_TIMEOUT_MS,
};

use crate::capture::{CaptureSession, CaptureSessionOptions, ExportResult};
use crate::error::{Error, Result};
use crate::headers::{forwardable_headers, from_http_header_map, to_http_header_map};
use crate::redaction::RedactionPolicy;

/// One gateway decision. Requests are observable, secrets are not.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayRequestEvent {
    pub sequence: u64,
    pub allowed: bool,
    pub status: u16,
    pub reason: Option<String>,
}

/// Options for [`start_gateway`].
pub struct GatewayOptions {
    pub policy: GatewayPolicy,
    /// Subprocess command whose stdout is the upstream credential (injected
    /// as `Bearer <stdout>` into [`CREDENTIAL_COMMAND_HEADER`]). stdout is
    /// never logged; empty output fails closed.
    pub credential_command: Option<String>,
    /// Explicit credential provider returning the upstream header map.
    /// Takes precedence over `credential_command`.
    pub credential_provider: Option<CredentialProvider>,
    /// When set, allowed gateway traffic is recorded through an exact
    /// [`CaptureSession`] sitting between the gateway and the upstream.
    pub capture: Option<CaptureSessionOptions>,
    pub listen_host: IpAddr,
    /// 0 = ephemeral.
    pub listen_port: u16,
}

struct SharedState {
    policy: GatewayPolicy,
    expiry: Option<chrono::DateTime<chrono::Utc>>,
    started_at: Instant,
    events: Mutex<Vec<GatewayRequestEvent>>,
    next_sequence: AtomicU64,
    total_response_bytes: AtomicU64,
    upstream_base: url::Url,
    client: reqwest::Client,
    capture_enabled: bool,
    capture_redaction: RedactionPolicy,
    credential: CredentialProvider,
}

/// A running gateway server.
pub struct GatewayServer {
    url: url::Url,
    state: Arc<SharedState>,
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    capture: Option<CaptureSession>,
}

impl GatewayServer {
    pub fn url(&self) -> url::Url {
        self.url.clone()
    }

    /// Decisions recorded so far, in sequence order.
    pub async fn events(&self) -> Vec<GatewayRequestEvent> {
        self.state
            .events
            .lock()
            .expect("gateway event lock poisoned")
            .clone()
    }

    /// Stop the listener, close the capture session, and return the capture
    /// export result when capture was configured.
    pub async fn shutdown(self) -> Result<Option<ExportResult>> {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join.await;
        match self.capture {
            Some(session) => {
                let exported = session.export(None).await?;
                session.close().await?;
                Ok(Some(exported))
            }
            None => Ok(None),
        }
    }
}

/// Start the credential-injecting gateway. Fails closed on invalid policy.
pub async fn start_gateway(options: GatewayOptions) -> Result<GatewayServer> {
    validate_policy(&options.policy)?;
    let policy = options.policy;
    let expiry = parse_expiry(&policy);
    let started_at = Instant::now();

    let credential: CredentialProvider =
        match (options.credential_provider, options.credential_command) {
            (Some(provider), _) => provider,
            (None, Some(command)) => policy::credential_provider_from_command(command),
            (None, None) => {
                return Err(Error::other(
                    "gateway requires either credential_command or credential_provider",
                ));
            }
        };

    // When capture is enabled the gateway routes upstream requests through an
    // exact CaptureSession pointed at the policy target. Recorded exchanges
    // carry the client's byte-exact bodies; the gateway token is stripped
    // before forwarding and the injected credential header is redacted by the
    // session's policy, so neither reaches the bundle.
    let (capture, capture_redaction, upstream_base) = match options.capture {
        Some(capture_options) => {
            let redaction = capture_options.redaction.clone();
            let session = crate::capture::start_capture_session(capture_options).await?;
            let base = session.url();
            (Some(session), redaction, base)
        }
        None => {
            let base = url::Url::parse(&policy.target_origin)
                .map_err(|_| Error::other("policy.targetOrigin must be a valid URL"))?;
            (None, RedactionPolicy::default(), base)
        }
    };

    let client = reqwest::Client::builder()
        // Node's http.request never follows redirects; neither do we.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|source| Error::other(format!("failed to build gateway HTTP client: {source}")))?;

    let state = Arc::new(SharedState {
        expiry,
        started_at,
        total_response_bytes: AtomicU64::new(0),
        next_sequence: AtomicU64::new(0),
        events: Mutex::new(Vec::new()),
        upstream_base,
        client,
        capture_enabled: capture.is_some(),
        capture_redaction,
        credential,
        policy,
    });

    let listener = tokio::net::TcpListener::bind((options.listen_host, options.listen_port))
        .await
        .map_err(|source| Error::io("gateway listener bind failed", source))?;
    let address = listener
        .local_addr()
        .map_err(|source| Error::io("gateway listener address unavailable", source))?;
    let host_text = if address.ip().is_ipv6() {
        format!("[{}]", address.ip())
    } else {
        address.ip().to_string()
    };
    let url = url::Url::parse(&format!("http://{host_text}:{}", address.port()))
        .map_err(|_| Error::other("Failed to determine gateway listener address"))?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let app = axum::Router::new()
        .fallback(handle)
        .with_state(state.clone());
    let join = tokio::spawn(async move {
        let mut shutdown_rx = shutdown_rx;
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await;
    });

    Ok(GatewayServer {
        url,
        state,
        shutdown_tx,
        join,
        capture,
    })
}

fn json_response(status: u16, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("static JSON response parts are always valid")
}

fn deny(state: &SharedState, status: u16, reason: &str) -> Response {
    emit_event(state, false, status, Some(reason.to_string()));
    let body = serde_json::json!({ "error": "gateway_denied", "reason": reason }).to_string();
    json_response(status, &body)
}

fn emit_event(state: &SharedState, allowed: bool, status: u16, reason: Option<String>) {
    let sequence = state.next_sequence.fetch_add(1, Ordering::SeqCst);
    state
        .events
        .lock()
        .expect("gateway event lock poisoned")
        .push(GatewayRequestEvent {
            sequence,
            allowed,
            status,
            reason,
        });
}

async fn handle(State(state): State<Arc<SharedState>>, req: Request) -> Response {
    process(state, req).await
}

async fn process(state: Arc<SharedState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let policy = &state.policy;

    // 1. Authenticate the opaque token.
    let auth = parts
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    match auth.strip_prefix("Bearer ") {
        Some(token) if token_matches(token, &policy.token_sha256) => {}
        _ => return deny(&state, 401, "invalid gateway token"),
    }

    // 2. Policy checks.
    if let Some(expiry) = state.expiry {
        if chrono::Utc::now() > expiry {
            return deny(&state, 403, "gateway token expired");
        }
    }
    if state.started_at.elapsed() > Duration::from_secs(policy.max_duration_secs) {
        return deny(&state, 403, "gateway session duration exceeded");
    }
    // Methods are compared case-sensitively against the normalized uppercase
    // form; a non-uppercase method is not a valid match.
    if method != method.to_uppercase() || !policy.methods.iter().any(|allowed| allowed == &method) {
        return deny(&state, 405, &format!("method {method} not allowed"));
    }
    if !path_allowed(&path, &policy.path_prefixes) {
        return deny(&state, 403, "path not allowed");
    }
    // 3. Buffer the request body under the byte ceiling (needed for the
    // model check, and gateway requests are bounded by policy anyway).
    // Crossing the ceiling yields a clean 413 response.
    let body = match read_bounded_body(body, policy.max_request_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return deny(&state, 413, "request byte limit exceeded");
        }
    };

    if !policy.models.is_empty() {
        let model = extract_model(&body);
        let allowed = model
            .as_ref()
            .map(|model| policy.models.iter().any(|allowed| allowed == model))
            .unwrap_or(false);
        if !allowed {
            let shown = model.unwrap_or_else(|| "(none)".to_string());
            return deny(&state, 403, &format!("model {shown} not allowed"));
        }
    }

    // 4. Obtain the real credential and build the upstream request. The
    // client's gateway token never leaves this process.
    let credential_headers = match (state.credential)().await {
        Ok(headers) => headers,
        Err(_) => {
            // Provider failures must not leak detail to the untrusted client.
            return deny(&state, 502, "credential provider failed");
        }
    };
    if state.capture_enabled {
        // Fail closed: a credential header the capture policy would persist
        // must never be forwarded through the recording path.
        for name in credential_headers.keys() {
            if !state.capture_redaction.should_redact_header(name) {
                return deny(&state, 502, "credential provider failed");
            }
        }
    }

    let mut request_headers = from_http_header_map(&parts.headers);
    request_headers.remove("authorization");
    let forwardable = forwardable_headers(&request_headers, true);
    let mut upstream_headers = to_http_header_map(&forwardable);
    for (name, value) in &credential_headers {
        let (Ok(header_name), Ok(header_value)) = (
            http::HeaderName::from_bytes(name.to_lowercase().as_bytes()),
            http::HeaderValue::from_str(value),
        ) else {
            return deny(&state, 502, "credential provider failed");
        };
        upstream_headers.insert(header_name, header_value);
    }

    let upstream_url = match state.upstream_base.join(&path) {
        Ok(url) => url,
        Err(_) => {
            // Never expose internal error detail to the untrusted client.
            return json_response(502, "{\"error\":\"gateway_error\"}");
        }
    };

    let deadline = Instant::now() + Duration::from_secs(policy.max_duration_secs);
    let upstream = {
        let request = state
            .client
            .request(parts.method, upstream_url)
            .headers(upstream_headers)
            .body(body)
            .send();
        match tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), request)
            .await
        {
            // Upstream failure details are not exposed to the untrusted client.
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => {
                return deny(&state, 502, "upstream request failed");
            }
        }
    };

    let status = upstream.status();
    let response_headers = from_http_header_map(upstream.headers());
    let out_headers = to_http_header_map(&forwardable_headers(&response_headers, false));

    // Stream the response back under the cumulative byte ceiling and the
    // session duration budget: crossing either cuts the stream like the TS
    // destroy().
    let budget = policy.max_total_bytes;
    let stream_state = state.clone();
    let body_stream = futures::stream::unfold(
        (upstream.bytes_stream(), deadline, budget, stream_state),
        |(mut stream, deadline, budget, totals)| async move {
            if Instant::now() > deadline {
                return None;
            }
            match stream.next().await {
                None => None,
                Some(Err(_)) => None,
                Some(Ok(chunk)) => {
                    let total = totals
                        .total_response_bytes
                        .fetch_add(chunk.len() as u64, Ordering::SeqCst)
                        + chunk.len() as u64;
                    if total > budget {
                        return None;
                    }
                    Some((
                        Ok::<_, std::io::Error>(chunk),
                        (stream, deadline, budget, totals),
                    ))
                }
            }
        },
    );

    emit_event(&state, true, status.as_u16(), None);
    let mut builder = Response::builder().status(status);
    for (name, value) in out_headers.iter() {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from_stream(body_stream))
        .expect("upstream response parts are header-valid by construction")
}

enum BodyReadError {
    Oversized,
    Failed,
}

async fn read_bounded_body(
    body: Body,
    max_bytes: u64,
) -> std::result::Result<Vec<u8>, BodyReadError> {
    let mut body = body;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let frame = match body.frame().await {
            Some(Ok(frame)) => frame,
            Some(Err(_)) => return Err(BodyReadError::Failed),
            None => return Ok(out),
        };
        let Some(data) = frame.data_ref() else {
            continue;
        };
        if out.len() as u64 + data.len() as u64 > max_bytes {
            return Err(BodyReadError::Oversized);
        }
        out.extend_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::sha256_hex;
    use crate::types::CaptureMode;

    const TEST_TOKEN: &str = "gateway-test-opaque-token";

    fn test_policy(target: &url::Url) -> GatewayPolicy {
        GatewayPolicy {
            token_sha256: sha256_hex(TEST_TOKEN.as_bytes()),
            expires_at: Some(
                (chrono::Utc::now() + chrono::TimeDelta::try_hours(1).expect("1 hour"))
                    .to_rfc3339(),
            ),
            target_origin: target.origin().ascii_serialization(),
            methods: vec!["POST".to_string()],
            path_prefixes: vec!["/v1".to_string()],
            models: Vec::new(),
            max_request_bytes: 64 * 1024,
            max_total_bytes: 1024 * 1024,
            max_duration_secs: 60,
        }
    }

    /// Loopback upstream echoing method, path, authorization header, and the
    /// raw body back as JSON.
    async fn spawn_echo_upstream() -> url::Url {
        async fn echo(req: Request) -> Response {
            let (parts, body) = req.into_parts();
            let collected = body.collect().await.expect("body collect");
            let bytes = collected.to_bytes();
            let payload = serde_json::json!({
                "method": parts.method.as_str(),
                "path": parts.uri.path(),
                "authorization": parts
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(""),
                "xApiKey": parts
                    .headers
                    .get("x-api-key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(""),
                "body": String::from_utf8_lossy(&bytes),
            });
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(payload.to_string()))
                .expect("static echo response")
        }
        let app = axum::Router::new().fallback(echo);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind echo upstream");
        let addr = listener.local_addr().expect("echo local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        url::Url::parse(&format!("http://{addr}")).expect("echo url")
    }

    async fn start_test_gateway(
        policy: GatewayPolicy,
        credential_command: Option<String>,
        credential_provider: Option<CredentialProvider>,
        capture: Option<CaptureSessionOptions>,
    ) -> GatewayServer {
        start_gateway(GatewayOptions {
            policy,
            credential_command,
            credential_provider,
            capture,
            listen_host: "127.0.0.1".parse().expect("loopback ip"),
            listen_port: 0,
        })
        .await
        .expect("start gateway")
    }

    /// Base URL without the trailing slash url::Url appends.
    fn gw_url(server: &GatewayServer) -> String {
        server.url().to_string().trim_end_matches('/').to_string()
    }

    async fn json_of(response: reqwest::Response) -> serde_json::Value {
        serde_json::from_str(&response.text().await.expect("response text")).expect("response json")
    }

    #[tokio::test]
    async fn policy_gate_matrix_allowed_and_blocked() {
        let upstream = spawn_echo_upstream().await;
        let mut policy = test_policy(&upstream);
        policy.models = vec!["claude-test".to_string()];
        let server = start_test_gateway(
            policy,
            Some("printf static-upstream-secret".to_string()),
            None,
            None,
        )
        .await;
        let base = server.url().to_string().trim_end_matches('/').to_string();
        let client = reqwest::Client::new();

        // Allowed: right method, right prefix, allowed model.
        let allowed = client
            .post(format!("{base}/v1/messages"))
            .bearer_auth(TEST_TOKEN)
            .body(r#"{"model":"claude-test"}"#)
            .send()
            .await
            .expect("allowed request");
        assert_eq!(allowed.status(), 200);
        let echoed: serde_json::Value = json_of(allowed).await;
        assert_eq!(echoed["method"], "POST");
        assert_eq!(echoed["path"], "/v1/messages");
        // The real credential replaced the client token upstream.
        assert_eq!(echoed["authorization"], "Bearer static-upstream-secret");

        // Blocked method.
        let blocked_method = client
            .get(format!("{base}/v1/messages"))
            .bearer_auth(TEST_TOKEN)
            .send()
            .await
            .expect("blocked method request");
        assert_eq!(blocked_method.status(), 405);
        assert_eq!(
            json_of(blocked_method).await["reason"],
            "method GET not allowed"
        );

        // Blocked path: segment semantics, /v1secrets is not under /v1.
        let blocked_path = client
            .post(format!("{base}/v1secrets/leak"))
            .bearer_auth(TEST_TOKEN)
            .send()
            .await
            .expect("blocked path request");
        assert_eq!(blocked_path.status(), 403);
        assert_eq!(json_of(blocked_path).await["reason"], "path not allowed");

        // Blocked model.
        let blocked_model = client
            .post(format!("{base}/v1/messages"))
            .bearer_auth(TEST_TOKEN)
            .body(r#"{"model":"gpt-not-allowed"}"#)
            .send()
            .await
            .expect("blocked model request");
        assert_eq!(blocked_model.status(), 403);
        assert_eq!(
            json_of(blocked_model).await["reason"],
            "model gpt-not-allowed not allowed"
        );

        // Missing model.
        let no_model = client
            .post(format!("{base}/v1/messages"))
            .bearer_auth(TEST_TOKEN)
            .body("not even json".to_string())
            .send()
            .await
            .expect("no model request");
        assert_eq!(no_model.status(), 403);
        assert_eq!(
            json_of(no_model).await["reason"],
            "model (none) not allowed"
        );

        let exported = server.shutdown().await.expect("shutdown");
        assert!(exported.is_none());
    }

    #[tokio::test]
    async fn oversized_request_yields_clean_413_json() {
        let upstream = spawn_echo_upstream().await;
        let mut policy = test_policy(&upstream);
        policy.max_request_bytes = 16;
        let server = start_test_gateway(
            policy,
            Some("printf static-upstream-secret".to_string()),
            None,
            None,
        )
        .await;
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/v1/messages", gw_url(&server)))
            .bearer_auth(TEST_TOKEN)
            .body(vec![b'x'; 128])
            .send()
            .await
            .expect("oversized request");
        assert_eq!(response.status(), 413);
        assert_eq!(
            response.headers().get("content-type").expect("ct"),
            "application/json"
        );
        let body: serde_json::Value = json_of(response).await;
        assert_eq!(body["error"], "gateway_denied");
        assert_eq!(body["reason"], "request byte limit exceeded");
        let exported = server.shutdown().await.expect("shutdown");
        assert!(exported.is_none());
    }

    #[tokio::test]
    async fn token_pin_accepts_valid_and_rejects_wrong_token() {
        let upstream = spawn_echo_upstream().await;
        let server = start_test_gateway(
            test_policy(&upstream),
            Some("printf static-upstream-secret".to_string()),
            None,
            None,
        )
        .await;
        let base = server.url().to_string().trim_end_matches('/').to_string();
        let client = reqwest::Client::new();

        // Wrong token pinned under a different digest.
        let wrong = client
            .post(format!("{base}/v1/messages"))
            .bearer_auth("definitely-not-the-token")
            .send()
            .await
            .expect("wrong token request");
        assert_eq!(wrong.status(), 401);
        assert_eq!(json_of(wrong).await["reason"], "invalid gateway token");

        // Missing Authorization entirely.
        let missing = client
            .post(format!("{base}/v1/messages"))
            .send()
            .await
            .expect("missing token request");
        assert_eq!(missing.status(), 401);

        // Correct opaque token matches its sha256 pin.
        let good = client
            .post(format!("{base}/v1/messages"))
            .bearer_auth(TEST_TOKEN)
            .body(r#"{"ok":true}"#)
            .send()
            .await
            .expect("good token request");
        assert_eq!(good.status(), 200);

        // Events recorded every decision with increasing sequence numbers.
        let events = server.events().await;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 0);
        assert_eq!(events[1].sequence, 1);
        assert_eq!(events[2].sequence, 2);
        assert!(!events[0].allowed);
        assert_eq!(events[0].reason.as_deref(), Some("invalid gateway token"));
        assert!(events[2].allowed);
        assert_eq!(events[2].reason, None);
        assert_eq!(events[2].status, 200);
    }

    #[tokio::test]
    async fn credential_command_consumes_env_printing_stdout() {
        std::env::set_var("ARBITER_GATEWAY_TEST_SECRET", "env-secret-value");
        let upstream = spawn_echo_upstream().await;
        let server = start_test_gateway(
            test_policy(&upstream),
            Some("printenv ARBITER_GATEWAY_TEST_SECRET".to_string()),
            None,
            None,
        )
        .await;
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/v1/messages", gw_url(&server)))
            .bearer_auth(TEST_TOKEN)
            .body(r#"{"ping":true}"#)
            .send()
            .await
            .expect("env command request");
        assert_eq!(response.status(), 200);
        let echoed: serde_json::Value = json_of(response).await;
        assert_eq!(echoed["authorization"], "Bearer env-secret-value");
    }

    #[tokio::test]
    async fn fail_closed_when_injected_header_not_redacted() {
        let upstream = spawn_echo_upstream().await;
        let client = reqwest::Client::new();
        let output = tempfile::tempdir().expect("temp output dir");

        // A credential header the capture policy would persist verbatim must
        // never be forwarded through the recording path.
        let leaky: CredentialProvider = Arc::new(|| {
            Box::pin(async {
                let mut headers = std::collections::HashMap::new();
                headers.insert("x-unrelated-header".to_string(), "leak".to_string());
                Ok(headers)
            })
        });
        let capture = CaptureSessionOptions {
            target: upstream.clone(),
            listen_host: "127.0.0.1".parse().expect("loopback"),
            listen_port: 0,
            mode: CaptureMode::Exact,
            redaction: RedactionPolicy::default(),
            output: Some(output.path().join("leaky-bundle")),
            validation: None,
            max_body_bytes: None,
            idle_timeout_ms: None,
        };
        let server =
            start_test_gateway(test_policy(&upstream), None, Some(leaky), Some(capture)).await;
        let response = client
            .post(format!("{}/v1/messages", gw_url(&server)))
            .bearer_auth(TEST_TOKEN)
            .body(r#"{"a":1}"#)
            .send()
            .await
            .expect("fail-closed request");
        assert_eq!(response.status(), 502);
        assert_eq!(
            json_of(response).await["reason"],
            "credential provider failed"
        );
        server.shutdown().await.expect("shutdown");

        // Positive control: a recognized sensitive header is redacted by the
        // capture policy and therefore allowed through.
        let sane: CredentialProvider = Arc::new(|| {
            Box::pin(async {
                let mut headers = std::collections::HashMap::new();
                headers.insert("x-api-key".to_string(), "real-key".to_string());
                Ok(headers)
            })
        });
        let capture_ok = CaptureSessionOptions {
            target: upstream.clone(),
            listen_host: "127.0.0.1".parse().expect("loopback"),
            listen_port: 0,
            mode: CaptureMode::Exact,
            redaction: RedactionPolicy::default(),
            output: Some(output.path().join("sane-bundle")),
            validation: None,
            max_body_bytes: None,
            idle_timeout_ms: None,
        };
        let server =
            start_test_gateway(test_policy(&upstream), None, Some(sane), Some(capture_ok)).await;
        let response = client
            .post(format!("{}/v1/messages", gw_url(&server)))
            .bearer_auth(TEST_TOKEN)
            .body(r#"{"a":1}"#)
            .send()
            .await
            .expect("positive control");
        assert_eq!(response.status(), 200);
        let echoed: serde_json::Value = json_of(response).await;
        assert_eq!(echoed["xApiKey"], "real-key");
    }

    #[tokio::test]
    async fn expired_token_is_denied() {
        let upstream = spawn_echo_upstream().await;
        let mut policy = test_policy(&upstream);
        policy.expires_at = Some(
            (chrono::Utc::now() - chrono::TimeDelta::try_hours(1).expect("1 hour")).to_rfc3339(),
        );
        let server = start_test_gateway(
            policy,
            Some("printf static-upstream-secret".to_string()),
            None,
            None,
        )
        .await;
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/v1/messages", gw_url(&server)))
            .bearer_auth(TEST_TOKEN)
            .send()
            .await
            .expect("expired request");
        assert_eq!(response.status(), 403);
        assert_eq!(json_of(response).await["reason"], "gateway token expired");
    }

    #[tokio::test]
    async fn duration_ceiling_is_enforced() {
        let upstream = spawn_echo_upstream().await;
        let mut policy = test_policy(&upstream);
        policy.max_duration_secs = 1;
        let server = start_test_gateway(
            policy,
            Some("printf static-upstream-secret".to_string()),
            None,
            None,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/v1/messages", gw_url(&server)))
            .bearer_auth(TEST_TOKEN)
            .send()
            .await
            .expect("late request");
        assert_eq!(response.status(), 403);
        assert_eq!(
            json_of(response).await["reason"],
            "gateway session duration exceeded"
        );
        assert!(server.shutdown().await.expect("shutdown").is_none());
    }
}
