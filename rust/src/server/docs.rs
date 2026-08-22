//! Documentation and export endpoints (`start_servers` docs app).
//!
//! Ports the docs half of `src/server.ts`: `/har` (HAR 1.2 export),
//! `/traffic.jsonl`, `/openapi.json`, `/openapi.yaml`, the Scalar API
//! reference page at `/docs`, and the link home page. When SQLite
//! persistence is configured the exports are served from the persisted
//! endpoint/HAR rows, falling back to the in-memory stores.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use serde_json::json;

use crate::middleware::HarStore;
use crate::storage::SqliteStore;
use crate::store::OpenApiStore;

/// State shared by the docs endpoints.
///
/// When `flows_enabled` is set (proxy-mode `start_servers`), this router
/// also mounts the flows API (`/__flows*`, `/__replay/:seq`,
/// `/__fingerprint`, `/__saved-filters`). On proxy mode those routes serve
/// **HAR-derived views** over the recorded [`HarStore`] entries via
/// [`crate::server::flows_api::HarFlowsBackend`] — no capture session is
/// involved — so `arbiter tui --attach URL` works against a plain
/// `arbiter start`. Capture-session deployments mount the same routes from
/// their own assembly instead of through this flag.
pub struct DocsShared {
    pub target: url::Url,
    pub openapi: Arc<OpenApiStore>,
    pub har: Arc<HarStore>,
    pub db: Option<Arc<SqliteStore>>,
    /// Mounts the flows API on this docs app; proxy mode passes `true`.
    pub flows_enabled: bool,
}

impl DocsShared {
    pub fn new(target: url::Url, openapi: Arc<OpenApiStore>, har: Arc<HarStore>) -> Self {
        Self {
            target,
            openapi,
            har,
            db: None,
            flows_enabled: false,
        }
    }
}

/// The axum app serving API documentation and exports.
pub fn docs_router(shared: Arc<DocsShared>) -> Router {
    let app = Router::new()
        .route("/har", get(har_endpoint))
        .route("/traffic.jsonl", get(traffic_endpoint))
        .route("/openapi.json", get(openapi_json_endpoint))
        .route("/openapi.yaml", get(openapi_yaml_endpoint))
        .route("/docs", get(scalar_page))
        .route("/", get(home_page))
        .with_state(Arc::clone(&shared));
    // Proxy mode mounts the HAR-backed flows API here so
    // `arbiter tui --attach` works against a plain `arbiter start`.
    if !shared.flows_enabled {
        return app;
    }
    let state = crate::server::flows_api::FlowsApiState {
        backend: Arc::new(crate::server::flows_api::HarFlowsBackend::new(
            Arc::clone(&shared.har),
            shared.target.clone(),
        )),
        saved_filters: Arc::new(tokio::sync::RwLock::new(
            crate::tui::filter::InMemorySavedFilterStore::new(),
        )),
    };
    app.merge(crate::server::flows_api::router(state))
}

/// Rebuilds a spec from persisted endpoint rows (the TS tempStore hydration).
fn spec_from_db(shared: &DocsShared) -> Option<serde_json::Value> {
    let db = shared.db.as_ref()?;
    let persisted = db.get_all_endpoints().ok()?;
    let temp = OpenApiStore::new();
    temp.set_target_url(shared.target.as_str());
    for (path, method, data) in persisted {
        temp.merge_endpoint_data(&path, &method, &data);
    }
    Some(temp.generate_openapi())
}

async fn har_endpoint(State(shared): State<Arc<DocsShared>>) -> Response {
    // Full-table sqlite scans are blocking work: run them off the async
    // workers so concurrent proxy recording never queues behind a docs hit.
    let db = shared.db.clone();
    let body = tokio::task::spawn_blocking(move || {
        match db.as_ref().and_then(|db| db.get_har_log().ok()) {
            Some(log) => log.to_string(),
            None => shared.har.get_har().to_string(),
        }
    })
    .await
    .unwrap_or_default();
    json_response(&body)
}

async fn traffic_endpoint(State(shared): State<Arc<DocsShared>>) -> Response {
    let har = shared.har.get_har();
    let entries = har["log"]["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut lines = Vec::with_capacity(entries.len());
    for entry in &entries {
        let url = entry["request"]["url"].as_str().unwrap_or_default();
        let url = url::Url::parse(url).ok();
        let path_with_search = match &url {
            Some(u) => match u.query() {
                Some(query) => format!("{}?{query}", u.path()),
                None => u.path().to_string(),
            },
            None => String::new(),
        };
        let request_headers = pairs_to_object(entry["request"]["headers"].as_array());
        let response_headers = pairs_to_object(entry["response"]["headers"].as_array());
        let line = json!({
            "timestamp": entry["startedDateTime"],
            "method": entry["request"]["method"],
            "path": path_with_search,
            "request_headers": request_headers,
            "request_body": entry["request"]["postData"]["text"].clone(),
            "response_status": entry["response"]["status"],
            "response_headers": response_headers,
            "response_body": entry["response"]["content"]["text"].clone(),
        });
        lines.push(line.to_string());
    }
    let mut body = lines.join("\n");
    if !lines.is_empty() {
        body.push('\n');
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .body(Body::from(body))
        .expect("build ndjson response")
}

fn pairs_to_object(pairs: Option<&Vec<serde_json::Value>>) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    for pair in pairs.into_iter().flatten() {
        if let (Some(name), Some(value)) = (pair["name"].as_str(), pair["value"].as_str()) {
            object.insert(name.to_string(), json!(value));
        }
    }
    serde_json::Value::Object(object)
}

async fn openapi_json_endpoint(State(shared): State<Arc<DocsShared>>) -> Response {
    let spec = tokio::task::spawn_blocking(move || match spec_from_db(&shared) {
        Some(spec) => spec,
        None => shared.openapi.generate_openapi(),
    })
    .await
    .unwrap_or(serde_json::Value::Null);
    json_response(&spec.to_string())
}

async fn openapi_yaml_endpoint(State(shared): State<Arc<DocsShared>>) -> Response {
    let shared2 = Arc::clone(&shared);
    let spec = tokio::task::spawn_blocking(move || match spec_from_db(&shared2) {
        Some(spec) => spec,
        None => shared2.openapi.generate_openapi(),
    })
    .await
    .unwrap_or(serde_json::Value::Null);
    let yaml = serde_yaml::to_string(&spec).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Body::from(yaml))
        .expect("build yaml response")
}

async fn scalar_page() -> Response {
    html_response(SCALAR_PAGE)
}

async fn home_page() -> Response {
    html_response(HOME_PAGE)
}

fn json_response(body: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build json response")
}

fn html_response(body: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html")
        .body(Body::from(body.to_string()))
        .expect("build html response")
}

const SCALAR_PAGE: &str = r#"
      <!doctype html>
      <html>
        <head>
          <title>Scalar API Reference</title>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
        </head>
        <body>
          <script id="api-reference" data-url="/openapi.yaml"></script>
          <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
        </body>
      </html>
    "#;

const HOME_PAGE: &str = r#"
      <!DOCTYPE html>
      <html>
        <head>
          <title>API Documentation</title>
          <style>
            body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            h1 { color: #333; }
            ul { list-style-type: none; padding: 0; }
            li { margin: 10px 0; }
            a { color: #0366d6; text-decoration: none; }
            a:hover { text-decoration: underline; }
          </style>
        </head>
        <body>
          <h1>API Documentation</h1>
          <ul>
            <li><a href="/docs">Swagger UI</a></li>
            <li><a href="/openapi.json">OpenAPI JSON</a></li>
            <li><a href="/openapi.yaml">OpenAPI YAML</a></li>
            <li><a href="/har">HAR Export</a></li>
            <li><a href="/traffic.jsonl">Traffic JSONL</a></li>
          </ul>
        </body>
      </html>
    "#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HeaderMapValues;

    fn seed(shared: &DocsShared) {
        let req_headers: HeaderMapValues = HeaderMapValues::from([(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        )]);
        let resp_headers: HeaderMapValues = HeaderMapValues::from([(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        )]);
        shared.openapi.record_exchange(
            "get",
            "/things",
            200,
            &req_headers,
            None,
            &resp_headers,
            Some(br#"[{"id":1}]"#),
        );
        shared.har.add_entry(json!({
            "startedDateTime": "2026-01-01T00:00:00.000Z",
            "time": 5,
            "request": {
                "method": "GET",
                "url": "http://localhost:3000/things",
                "httpVersion": "HTTP/1.1",
                "headers": [{ "name": "content-type", "value": "application/json" }],
                "queryString": [],
            },
            "response": {
                "status": 200,
                "statusText": "OK",
                "httpVersion": "HTTP/1.1",
                "headers": [],
                "content": { "size": 11, "mimeType": "application/json", "text": "[{\"id\":1}]" },
            },
        }));
    }

    async fn spawn_docs(shared: Arc<DocsShared>) -> url::Url {
        let router = docs_router(shared);
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind docs");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve docs");
        });
        url::Url::parse(&format!("http://{addr}")).expect("docs url")
    }

    #[tokio::test]
    async fn docs_endpoints_serve_seeded_data() {
        let target = url::Url::parse("http://localhost:3000").expect("target");
        let shared = Arc::new(DocsShared::new(
            target,
            Arc::new(OpenApiStore::new()),
            Arc::new(HarStore::new()),
        ));
        seed(&shared);
        let base = spawn_docs(Arc::clone(&shared)).await;
        let base = base.to_string().trim_end_matches('/').to_string();
        let client = reqwest::Client::new();

        // OpenAPI JSON reflects the recorded endpoint.
        let response = client
            .get(format!("{base}/openapi.json"))
            .send()
            .await
            .expect("openapi.json");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .starts_with("application/json"));
        let spec: serde_json::Value = response.json().await.expect("spec json");
        assert!(!spec["openapi"].as_str().unwrap_or_default().is_empty());
        let things = &spec["paths"]["/things"]["get"];
        assert!(things.is_object(), "missing /things get: {spec}");

        // OpenAPI YAML parses back to the same document.
        let response = client
            .get(format!("{base}/openapi.yaml"))
            .send()
            .await
            .expect("openapi.yaml");
        assert_eq!(response.status(), StatusCode::OK);
        let yaml = response.text().await.expect("yaml");
        let parsed: serde_json::Value = serde_yaml::from_str(&yaml).expect("valid yaml");
        assert!(parsed["paths"]["/things"]["get"].is_object());

        // HAR export contains the seeded entry.
        let response = client.get(format!("{base}/har")).send().await.expect("har");
        let har: serde_json::Value = response.json().await.expect("har json");
        assert_eq!(har["log"]["version"], "1.2");
        assert_eq!(har["log"]["entries"].as_array().expect("entries").len(), 1);
        assert_eq!(
            har["log"]["entries"][0]["request"]["url"],
            "http://localhost:3000/things"
        );

        // Scalar page references the CDN bundle and the yaml spec.
        let response = client
            .get(format!("{base}/docs"))
            .send()
            .await
            .expect("docs page");
        let html = response.text().await.expect("html");
        assert!(html.contains("cdn.jsdelivr.net/npm/@scalar/api-reference"));
        assert!(html.contains("data-url=\"/openapi.yaml\""));

        // Home page links the exports.
        let response = client.get(base.clone()).send().await.expect("home page");
        let html = response.text().await.expect("home html");
        assert!(html.contains("/openapi.json"));
        assert!(html.contains("/traffic.jsonl"));

        // Traffic JSONL renders one NDJSON line per entry.
        let response = client
            .get(format!("{base}/traffic.jsonl"))
            .send()
            .await
            .expect("traffic");
        let body = response.text().await.expect("traffic body");
        let line: serde_json::Value = serde_json::from_str(body.trim_end()).expect("ndjson line");
        assert_eq!(line["method"], "GET");
        assert_eq!(line["path"], "/things");
        assert_eq!(line["response_status"], 200);
        assert_eq!(line["request_headers"]["content-type"], "application/json");
    }
    #[tokio::test]
    async fn flows_flag_mounts_har_backed_routes() {
        let target = url::Url::parse("http://localhost:3000").expect("target");
        let make = |flows_enabled: bool| {
            Arc::new(DocsShared {
                target: target.clone(),
                openapi: Arc::new(OpenApiStore::new()),
                har: Arc::new(HarStore::new()),
                db: None,
                flows_enabled,
            })
        };
        let client = reqwest::Client::new();

        // Disabled (docs-only default): flows routes are not mounted.
        let base = spawn_docs(make(false)).await;
        let base = base.to_string().trim_end_matches('/').to_string();
        let response = client
            .get(format!("{base}/__flows"))
            .send()
            .await
            .expect("404 probe");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Enabled (proxy mode): HAR-derived views answer on the same app.
        let shared = make(true);
        shared.har.add_entry(json!({
            "startedDateTime": "2026-01-01T00:00:00.000Z",
            "time": 7,
            "request": {
                "method": "GET",
                "url": "http://localhost:3000/things",
                "httpVersion": "HTTP/1.1",
                "headers": [],
                "queryString": [],
            },
            "response": {
                "status": 200,
                "statusText": "OK",
                "httpVersion": "HTTP/1.1",
                "headers": [],
                "content": { "size": 0, "mimeType": "application/json", "text": "" },
            },
        }));
        let base = spawn_docs(shared).await;
        let base = base.to_string().trim_end_matches('/').to_string();
        let page: serde_json::Value = client
            .get(format!("{base}/__flows"))
            .send()
            .await
            .expect("flows list")
            .json()
            .await
            .expect("flows json");
        assert_eq!(page["latest"], 1);
        assert_eq!(page["flows"][0]["path"], "/things");
    }
}
