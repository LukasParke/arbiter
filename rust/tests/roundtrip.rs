//! End-to-end round trip: capture session proxies traffic against a fixture
//! upstream, exports a bundle, the bundle loads with digest verification, and
//! replay against a second fixture upstream matches semantically.

use std::collections::BTreeMap;

use arbiter::capture::{start_capture_session, CaptureSessionOptions};
use arbiter::redaction::RedactionPolicy;
use arbiter::replay::{ReplayMode, ReplayOptions};
use arbiter::types::CaptureMode;

use axum::body::Body;
use axum::http::Request;
use axum::routing::{any, post};
use axum::Json;
use serde_json::json;

async fn spawn_upstream(responses: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, responses).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn fixture_app(responses: BTreeMap<String, (u16, serde_json::Value)>) -> axum::Router {
    // Echo-style upstream: POST /v1/messages echoes the body with a fixed id;
    // other paths serve canned responses by path key.
    axum::Router::new()
        .route(
            "/v1/messages",
            post(|Json(body): Json<serde_json::Value>| async move {
                Json(json!({"id": "resp_1", "echo": body}))
            }),
        )
        .fallback(any(move |req: Request<Body>| {
            let key = req.uri().path().to_string();
            async move {
                match responses.get(&key) {
                    Some((status, value)) => (
                        axum::http::StatusCode::from_u16(*status).unwrap(),
                        Json(value.clone()),
                    ),
                    None => (
                        axum::http::StatusCode::NOT_FOUND,
                        Json(json!({"error": "missing"})),
                    ),
                }
            }
        }))
}

#[tokio::test]
async fn capture_export_load_replay_roundtrip() {
    // 1. Capture: proxy a JSON POST with a credential header through the session.
    let (upstream_url, upstream_handle) = spawn_upstream(fixture_app(BTreeMap::new())).await;

    let out_dir = tempfile::tempdir().unwrap();
    let session = start_capture_session(CaptureSessionOptions {
        target: upstream_url.parse().unwrap(),
        listen_host: "127.0.0.1".parse().unwrap(),
        listen_port: 0,
        mode: CaptureMode::Exact,
        redaction: RedactionPolicy::default(),
        output: Some(out_dir.path().to_path_buf()),
        validation: None,
        ..Default::default()
    })
    .await
    .unwrap();

    let proxy = session.url().to_string().trim_end_matches('/').to_string();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{proxy}/v1/messages"))
        .header("authorization", "Bearer sk-super-secret-value")
        .header("x-trace", "keep-me")
        .json(&json!({"model": "test", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["id"], "resp_1");

    session.wait_for_idle().await;
    let export = session
        .export(Some(arbiter::capture::ExportOptions {
            output: out_dir.path().to_path_buf(),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(export.manifest.exchange_count, 1);
    assert_eq!(export.manifest.mode, CaptureMode::Exact);
    session.close().await.unwrap();

    // 2. Load: bundle verifies (digest, sequence, containment) on reload.
    let bundle = arbiter::bundle::load_bundle(&export.output_dir).unwrap();
    assert_eq!(bundle.exchanges.len(), 1);
    let exchange = &bundle.exchanges[0];
    // Credential header redacted by name, benign header kept.
    assert!(exchange
        .request
        .headers
        .redacted
        .contains(&"authorization".to_string()));
    assert!(exchange.request.headers.values.contains_key("x-trace"));

    // 3. Replay against an equivalent upstream: semantic JSON match.
    let (replay_target, replay_handle) = spawn_upstream(fixture_app(BTreeMap::new())).await;
    let report = arbiter::replay::replay_capture(
        &export.output_dir,
        &ReplayOptions {
            target: replay_target.parse().unwrap(),
            mode: ReplayMode::SemanticJsonResponse,
            credential_env: None,
            query_env: vec![],
            ignore_pointers: vec!["/id".to_string()],
            fail_on_diff: false,
            legacy_jsonl: false,
            allow_binary_media_types: vec![],
            reject_secret_env: vec![],
            delay_ms: 0,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        report.matched, 1,
        "expected semantic match, report: {report:?}"
    );

    upstream_handle.abort();
    replay_handle.abort();
}

#[tokio::test]
async fn replay_detects_drift() {
    // Capture against upstream A; replay against upstream B whose response
    // body differs outside ignore pointers -> Diff outcome.
    let (upstream_url, upstream_handle) = spawn_upstream(fixture_app(BTreeMap::new())).await;

    let out_dir = tempfile::tempdir().unwrap();
    let session = start_capture_session(CaptureSessionOptions {
        target: upstream_url.parse().unwrap(),
        listen_host: "127.0.0.1".parse().unwrap(),
        listen_port: 0,
        mode: CaptureMode::Exact,
        redaction: RedactionPolicy::default(),
        output: None,
        validation: None,
        ..Default::default()
    })
    .await
    .unwrap();
    let proxy = session.url().to_string().trim_end_matches('/').to_string();
    reqwest::Client::new()
        .get(format!("{proxy}/v1/known"))
        .send()
        .await
        .unwrap();
    session.wait_for_idle().await;
    let export = session
        .export(Some(arbiter::capture::ExportOptions {
            output: out_dir.path().to_path_buf(),
            ..Default::default()
        }))
        .await
        .unwrap();
    session.close().await.unwrap();
    upstream_handle.abort();

    // Drifted upstream: different payload for the same path.
    let mut responses = BTreeMap::new();
    responses.insert("/v1/known".to_string(), (200u16, json!({"drifted": true})));
    let (drift_target, drift_handle) = spawn_upstream(fixture_app(responses)).await;
    let report = arbiter::replay::replay_capture(
        &export.output_dir,
        &ReplayOptions {
            target: drift_target.parse().unwrap(),
            mode: ReplayMode::SemanticJsonResponse,
            credential_env: None,
            query_env: vec![],
            ignore_pointers: vec![],
            fail_on_diff: false,
            legacy_jsonl: false,
            allow_binary_media_types: vec![],
            reject_secret_env: vec![],
            delay_ms: 0,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        report.diffed, 1,
        "expected drift detection, report: {report:?}"
    );
    drift_handle.abort();
}
