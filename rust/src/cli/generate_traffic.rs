//! `arbiter generate-traffic` (full port of src/commands/generate-traffic.ts).

use std::collections::BTreeMap;

use clap::Args;
use serde_json::{json, Map, Value};
use url::Url;

use super::{fail, parse_positive_int};
use crate::auth::AuthManager;

/// Generate synthetic traffic against a target API
#[derive(Args, Clone)]
pub struct GenerateTrafficArgs {
    /// base URL of the target API
    #[arg(long = "target")]
    pub target: String,

    /// X-Plex-Token for authenticated requests
    #[arg(long = "token")]
    pub token: Option<String>,

    /// delay between requests in ms
    #[arg(long = "delay", default_value = "100")]
    pub delay: String,

    /// path to write traffic JSONL file
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// capture response bodies in traffic output
    #[arg(long = "capture-bodies")]
    pub capture_bodies: bool,

    /// maximum body size to capture
    #[arg(long = "max-body-size", default_value = "50000")]
    pub max_body_size: String,
}

/// The endpoint list from src/commands/generate-traffic.ts.
const ENDPOINTS: [&str; 39] = [
    "/",
    "/identity",
    "/library",
    "/library/sections",
    "/library/sections/1/all",
    "/library/sections/1/onDeck",
    "/library/sections/1/recentlyAdded",
    "/library/metadata/1",
    "/library/metadata/1/children",
    "/status/sessions",
    "/status/sessions/history/all",
    "/accounts",
    "/devices",
    "/clients",
    "/servers",
    "/hubs/search",
    "/playlists",
    "/butler",
    "/activities",
    "/updater/status",
    "/system/agents",
    "/system/settings",
    "/system/updates",
    "/statistics/bandwidth",
    "/statistics/resources",
    "/diagnostics",
    "/sync",
    "/sync/items",
    "/sync/queue",
    "/services/browse",
    "/media/grabbers",
    "/livetv/dvrs",
    "/livetv/epg",
    "/channels",
    "/player/timeline/poll",
    "/player/playback/playMedia",
    "/transcode/sessions",
    "/security/resources",
    "/security/token",
];

pub fn run(args: &GenerateTrafficArgs) -> i32 {
    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    runtime.block_on(run_async(args.clone()))
}

async fn run_async(args: GenerateTrafficArgs) -> i32 {
    let base_url = args.target.trim_end_matches('/').to_string();
    let delay_ms = parse_positive_int(&args.delay, "--delay", true);
    let max_body_size = parse_positive_int(&args.max_body_size, "--max-body-size", true);

    // Resolve auth: CLI token takes precedence over saved config.
    let auth_manager = match args.token.as_deref() {
        Some(token) => AuthManager::from_token(token),
        None => AuthManager::new(),
    };
    if auth_manager.is_authenticated() {
        println!("Using auth token: {}", auth_manager.redacted_token());
    }

    let client = reqwest::Client::new();
    let mut traffic: Vec<Value> = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;

    for path in ENDPOINTS {
        let mut url: Url = Url::parse(&format!("{base_url}{path}"))
            .unwrap_or_else(|e| fail(format!("Invalid target URL '{}{}': {e}", base_url, path)));
        for (key, value) in auth_manager.get_query_params() {
            url.query_pairs_mut().append_pair(&key, &value);
        }

        let request = client
            .get(url.as_str())
            .headers(to_reqwest_headers(auth_manager.get_headers()));

        let (status, content_type, body): (u16, Option<String>, Option<String>) =
            match request.send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let content_type = response
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);
                    let body = if args.capture_bodies && response.status().is_success() {
                        match response.text().await {
                            Ok(text) => Some(truncate_body(&text, max_body_size as usize)),
                            Err(_) => None,
                        }
                    } else {
                        None
                    };
                    (status, content_type, body)
                }
                Err(err) => {
                    println!("✗ GET {path} (error: {err})");
                    failed += 1;
                    (0, None, None)
                }
            };

        if status == 0 {
            // already counted above
        } else if (200..300).contains(&status) {
            println!("✓ GET {path}");
            passed += 1;
        } else if status == 401 {
            println!("○ GET {path} (unauthorized)");
            skipped += 1;
        } else {
            println!("✗ GET {path} ({status})");
            failed += 1;
        }

        let mut entry = Map::new();
        entry.insert("path".into(), json!(url.to_string()));
        entry.insert("method".into(), json!("GET"));
        entry.insert(
            "queryParams".into(),
            json!(url
                .query_pairs()
                .map(|(k, _)| k.to_string())
                .collect::<Vec<_>>()),
        );
        entry.insert("status".into(), json!(status));
        if args.capture_bodies {
            if let Some(body) = body {
                entry.insert("body".into(), json!(body));
            }
            if let Some(content_type) = content_type {
                entry.insert("contentType".into(), json!(content_type));
            }
        }
        traffic.push(Value::Object(entry));

        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }

    if let Some(output_path) = args.output.as_deref() {
        let lines: String = traffic
            .iter()
            .map(|entry| serde_json::to_string(entry).expect("traffic entry serializes"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(output_path, format!("{lines}\n")).unwrap_or_else(|e| {
            fail(format!("Failed to write traffic to {output_path}: {e}"));
        });
        println!("Traffic written to {output_path}");
    }

    println!("\nTraffic Generation Complete:");
    println!("  Passed: {passed}");
    println!("  Skipped: {skipped}");
    println!("  Failed: {failed}");
    0
}

fn truncate_body(text: &str, max_chars: usize) -> String {
    if text.chars().count() > max_chars {
        let truncated: String = text.chars().take(max_chars).collect();
        format!("{truncated}...[truncated]")
    } else {
        text.to_string()
    }
}

fn to_reqwest_headers(map: BTreeMap<String, String>) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in map {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::try_from(name.as_str()),
            reqwest::header::HeaderValue::try_from(value),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}
