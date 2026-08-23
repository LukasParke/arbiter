//! `arbiter gateway` (port of src/commands/gateway.ts).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clap::Args;
use futures::future::BoxFuture;
use url::Url;

use super::start::wait_for_signal;
use super::{atomic_write_private, fail, parse_positive_int};
use crate::capture::{CaptureMode, CaptureSessionOptions};
use crate::gateway::{start_gateway, CredentialProvider, GatewayOptions, GatewayPolicy};

/// Long help (`--help`) for `arbiter gateway`, including the full
/// POLICY SCHEMA reference (D2). The embedded example JSON is deserialized
/// and validated by a test below so the docs cannot drift from
/// [`crate::gateway::GatewayPolicy`]. Applied at the `Command::Gateway`
/// variant in `cli/mod.rs` (the variant doc comment would otherwise win).
pub(crate) const LONG_ABOUT: &str = r#"Run a credential-injecting gateway for untrusted clients

The gateway sits between an untrusted client and your upstream API. Every
request must present the opaque token; the policy file governs what that
token may do. The token itself is never stored — only its sha256 pin
(tokenSha256).

POLICY SCHEMA

The --policy file is a single JSON object (camelCase keys):

  tokenSha256      string   REQUIRED sha256 hex digest (64 hex chars) of
                            the opaque client token
  expiresAt        string?  ISO-8601/RFC-3339 expiry for the token; null or
                            absent disables expiry
  targetOrigin     string   REQUIRED allowed upstream origin, e.g.
                            "https://api.anthropic.com" (exact scheme://host[:port])
  methods          string[] REQUIRED allowed request methods (exact,
                            uppercase), e.g. ["POST", "GET"]
  pathPrefixes     string[] REQUIRED allowed path prefixes using segment
                            semantics ("/v1" matches /v1/... but never
                            /v1secrets or encoded traversal)
  models           string[] when non-empty, JSON request bodies must carry
                            one of these "model" values
  maxRequestBytes  u64      REQUIRED per-request body byte ceiling (> 0)
  maxTotalBytes    u64      REQUIRED cumulative response byte ceiling for
                            the session (> 0)
  maxDurationSecs  u64      REQUIRED session duration ceiling in seconds (> 0)

Complete example (validates as-is):

{
  "tokenSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "expiresAt": "2026-12-31T23:59:59Z",
  "targetOrigin": "https://api.anthropic.com",
  "methods": ["POST", "GET"],
  "pathPrefixes": ["/v1/messages", "/v1/models"],
  "models": ["claude-sonnet-4"],
  "maxRequestBytes": 1048576,
  "maxTotalBytes": 104857600,
  "maxDurationSecs": 3600
}"#;

/// Run a credential-injecting gateway for untrusted clients
#[derive(Args, Clone)]
pub struct GatewayArgs {
    /// path to the gateway policy JSON file
    #[arg(long = "policy")]
    pub policy: String,

    /// command whose stdout supplies the upstream credential (never logged)
    #[arg(long = "credential-command")]
    pub credential_command: String,

    /// header to carry the credential upstream
    #[arg(long = "credential-header", default_value = "authorization")]
    pub credential_header: String,

    /// prefix for the credential value, e.g. Bearer
    #[arg(long = "credential-prefix")]
    pub credential_prefix: Option<String>,

    /// port to listen on (0 = random)
    #[arg(short = 'p', long = "port", default_value = "0")]
    pub port: String,

    /// hostname to bind
    #[arg(long = "host", default_value = "127.0.0.1")]
    pub host: String,

    /// write listener metadata JSON atomically once ready
    #[arg(long = "ready-file")]
    pub ready_file: Option<String>,

    /// record allowed gateway traffic and export an exact capture bundle on shutdown
    #[arg(long = "capture-output")]
    pub capture_output: Option<String>,
}

pub fn run(args: &GatewayArgs) -> i32 {
    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    runtime.block_on(run_async(args.clone()))
}

/// Port of `credentialProviderFromCommand` in src/gateway/index.ts: run the
/// command through a shell and consume its (trimmed) stdout as the secret.
fn credential_provider_from_command(
    command: String,
    header: String,
    prefix: Option<String>,
) -> CredentialProvider {
    Arc::new(move || {
        let command = command.clone();
        let header = header.clone();
        let prefix = prefix.clone();
        Box::pin(async move {
            let output = tokio::time::timeout(Duration::from_secs(30), async {
                tokio::process::Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .stdin(std::process::Stdio::null())
                    .output()
                    .await
            })
            .await
            .map_err(|_| crate::error::Error::other("Credential command timed out"))?
            .map_err(|e| crate::error::Error::other(format!("credential command: {e}")))?;

            if !output.status.success() {
                return Err(crate::error::Error::other(format!(
                    "Credential command exited with code {}",
                    output
                        .status
                        .code()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "signal".to_string())
                )));
            }
            let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if secret.is_empty() {
                return Err(crate::error::Error::other(
                    "Credential command produced no output",
                ));
            }
            let mut headers = std::collections::HashMap::new();
            headers.insert(header, format_secret(&prefix, &secret));
            Ok(headers)
        })
            as BoxFuture<'static, crate::error::Result<std::collections::HashMap<String, String>>>
    })
}

fn format_secret(prefix: &Option<String>, secret: &str) -> String {
    match prefix {
        Some(prefix) if !prefix.is_empty() => format!("{prefix} {secret}"),
        _ => secret.to_string(),
    }
}

async fn run_async(args: GatewayArgs) -> i32 {
    let policy: GatewayPolicy = match std::fs::read_to_string(&args.policy)
        .map_err(|e| crate::error::Error::io("read policy", e))
        .and_then(|raw| {
            serde_json::from_str(&raw).map_err(|e| crate::error::Error::Json {
                context: "parse policy".into(),
                source: e,
            })
        }) {
        Ok(policy) => policy,
        Err(e) => fail(format!("Failed to read policy: {e}")),
    };

    let port = parse_positive_int(&args.port, "--port", true);
    if port > 65535 {
        fail(format!(
            "--port must be an integer 0-65535 (got {})",
            args.port
        ));
    }
    let listen_host: std::net::IpAddr = args
        .host
        .parse()
        .unwrap_or_else(|_| fail(format!("Invalid --host '{}'", args.host)));

    let capture = args.capture_output.as_deref().map(|output| {
        let target_origin = Url::parse(&policy.target_origin).unwrap_or_else(|e| {
            fail(format!(
                "Invalid policy targetOrigin '{}': {e}",
                policy.target_origin
            ))
        });
        CaptureSessionOptions {
            target: target_origin,
            mode: CaptureMode::Exact,
            output: Some(std::path::PathBuf::from(output)),
            ..CaptureSessionOptions::default()
        }
    });

    let provider = credential_provider_from_command(
        args.credential_command.clone(),
        args.credential_header.clone(),
        args.credential_prefix.clone(),
    );

    let gateway = match start_gateway(GatewayOptions {
        policy: policy.clone(),
        credential_command: None,
        credential_provider: Some(provider),
        capture,
        listen_host,
        listen_port: port as u16,
    })
    .await
    {
        Ok(gateway) => gateway,
        Err(e) => fail(format!("Failed to start gateway: {e}")),
    };

    println!("Arbiter gateway listening");
    println!("  Gateway: {}", gateway.url());
    println!("  Target:  {}", policy.target_origin);
    println!("  Expires: {}", policy.expires_at.as_deref().unwrap_or(""));

    if let Some(ready_file) = args.ready_file.as_deref() {
        let payload = json_ready(gateway.url().as_ref(), &policy.target_origin);
        atomic_write_private(Path::new(ready_file), &payload)
            .unwrap_or_else(|e| fail(format!("Failed to write ready file {ready_file}: {e}")));
    }

    // Request-event logging: the contract exposes a snapshot accessor rather
    // than a callback hook, so poll for new events until shutdown.
    let mut last_event_seq: u64 = 0;
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = wait_for_signal() => break,
            _ = ticker.tick() => {
                for event in gateway.events().await {
                    if event.sequence > last_event_seq {
                        last_event_seq = event.sequence;
                        log_request_event(&event);
                    }
                }
            }
        }
    }

    match gateway.shutdown().await {
        Ok(Some(result)) => {
            println!(
                "Exported {} exchange(s) to {}",
                result.manifest.exchange_count,
                result.output_dir.display()
            );
            0
        }
        Ok(None) => 0,
        Err(e) => {
            eprintln!("Capture export failed: {e}");
            1
        }
    }
}

fn json_ready(url: &str, target: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "url": url,
        "target": target,
        "pid": std::process::id(),
    }))
    .expect("ready info serializes")
}

fn log_request_event(event: &crate::gateway::GatewayRequestEvent) {
    let mark = if event.allowed { "✓" } else { "✗" };
    let status = event.status.to_string();
    match (&event.reason, event.allowed) {
        (Some(reason), false) => println!("{mark} {} {status} denied: {reason}", event.sequence),
        (_, true) => println!("{mark} {} {status}", event.sequence),
        (None, false) => println!("{mark} {} {status} denied", event.sequence),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D2 regression: the POLICY SCHEMA example embedded in `--help` must
    /// deserialize into GatewayPolicy and pass validation, so the docs can
    /// never drift from the struct.
    #[test]
    fn help_policy_example_deserializes_and_validates() {
        let start = LONG_ABOUT.find('{').expect("example object present");
        let end = LONG_ABOUT.rfind('}').expect("example object closed");
        let policy: crate::gateway::GatewayPolicy = serde_json::from_str(&LONG_ABOUT[start..=end])
            .expect("help example must be valid JSON");
        crate::gateway::validate_policy(&policy).expect("help example must validate");
    }
    /// D2 regression: `--help` renders the POLICY SCHEMA section.
    #[test]
    fn long_help_documents_policy_schema() {
        // long_about is attached at the Command::Gateway variant in
        // cli/mod.rs, so render through the assembled root command.
        let mut sub = crate::cli::root_command()
            .get_subcommands()
            .find(|c| c.get_name() == "gateway")
            .cloned()
            .expect("gateway registered in root command");
        let text = sub.render_long_help().to_string();
        assert!(text.contains("POLICY SCHEMA"), "long help lost schema docs");
        for field in [
            "tokenSha256",
            "expiresAt",
            "targetOrigin",
            "methods",
            "pathPrefixes",
            "models",
            "maxRequestBytes",
            "maxTotalBytes",
            "maxDurationSecs",
        ] {
            assert!(text.contains(field), "policy doc missing {field}");
        }
    }
}
