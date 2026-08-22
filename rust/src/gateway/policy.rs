//! Gateway policy: validation, opaque-token pinning, path allowlisting, and
//! the subprocess-backed credential provider.
//!
//! Port of the policy half of `src/gateway/index.ts`.

use std::collections::HashMap;
use std::time::Duration;

use futures::future::BoxFuture;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::process::Command;

use crate::bundle::is_sha256_hex;
use crate::error::{Error, Result};

/// Policy half of `src/commands/gateway.ts`: the credential command's stdout
/// becomes the upstream bearer credential injected into this header.
pub const CREDENTIAL_COMMAND_HEADER: &str = "authorization";

/// Default subprocess budget for the credential command (`timeoutMs ?? 30_000`).
pub const CREDENTIAL_COMMAND_TIMEOUT_MS: u64 = 30_000;

/// Gateway traffic policy. The opaque client token itself is never stored —
/// only its sha256 pin.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayPolicy {
    /// sha256 hex digest of the opaque gateway token.
    pub token_sha256: String,
    /// ISO-8601 expiry for the token; `None` disables expiry.
    pub expires_at: Option<String>,
    /// Allowed upstream origin, e.g. `https://api.anthropic.com`.
    pub target_origin: String,
    /// Allowed request methods (exact, uppercase).
    pub methods: Vec<String>,
    /// Allowed path prefixes (segment semantics, see [`path_allowed`]).
    pub path_prefixes: Vec<String>,
    /// When non-empty, JSON request bodies must carry one of these `model` values.
    pub models: Vec<String>,
    /// Per-request body byte ceiling.
    pub max_request_bytes: u64,
    /// Cumulative response byte ceiling across the session.
    pub max_total_bytes: u64,
    /// Session duration ceiling in seconds.
    pub max_duration_secs: u64,
}

/// Validate a policy, mirroring TS `validatePolicy`. Fails closed.
pub fn validate_policy(policy: &GatewayPolicy) -> Result<()> {
    if !is_sha256_hex(&policy.token_sha256) {
        return Err(Error::other(
            "policy.tokenSha256 must be a sha256 hex digest",
        ));
    }
    if let Some(expires_at) = &policy.expires_at {
        if chrono::DateTime::parse_from_rfc3339(expires_at).is_err() {
            return Err(Error::other(
                "policy.expiresAt must be an ISO-8601 timestamp",
            ));
        }
    }
    let origin = url::Url::parse(&policy.target_origin).map_err(|_| {
        Error::other(format!(
            "policy.targetOrigin must be an origin (got {})",
            policy.target_origin
        ))
    })?;
    if origin.scheme() != "http" && origin.scheme() != "https" {
        return Err(Error::other(format!(
            "policy.targetOrigin must be an origin (got {})",
            policy.target_origin
        )));
    }
    if origin.origin().ascii_serialization() != policy.target_origin {
        return Err(Error::other(format!(
            "policy.targetOrigin must be an origin (got {})",
            policy.target_origin
        )));
    }
    if policy.methods.is_empty() || policy.path_prefixes.is_empty() {
        return Err(Error::other(
            "policy.methods and policy.pathPrefixes must be non-empty",
        ));
    }
    for (field, value) in [
        ("maxRequestBytes", policy.max_request_bytes),
        ("maxTotalBytes", policy.max_total_bytes),
        ("maxDurationSecs", policy.max_duration_secs),
    ] {
        if value == 0 {
            return Err(Error::other(format!(
                "policy.{field} must be a positive number"
            )));
        }
    }
    Ok(())
}

/// Parse the policy expiry, if set. Callers validated first; used per-request.
pub fn parse_expiry(policy: &GatewayPolicy) -> Option<chrono::DateTime<chrono::Utc>> {
    policy
        .expires_at
        .as_ref()
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// Constant-time-ish comparison of a presented token against the sha256 pin:
/// both sides are hashed/digested and compared byte-wise without early exit
/// on content mismatches.
pub fn token_matches(token: &str, expected_sha256: &str) -> bool {
    let digest = Sha256::digest(token.as_bytes());
    let Ok(expected) = hex::decode(expected_sha256) else {
        return false;
    };
    if digest.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (actual, wanted) in digest.iter().zip(expected.iter()) {
        diff |= actual ^ wanted;
    }
    diff == 0
}

/// Percent-decode exactly like `decodeURIComponent`: `%XX` sequences only,
/// rejecting malformed escapes and invalid UTF-8 outright.
fn decode_uri_component(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = (*bytes.get(i + 1)?) as char;
            let lo = (*bytes.get(i + 2)?) as char;
            let hi = hi.to_digit(16)?;
            let lo = lo.to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn has_hostile_chars(text: &str) -> bool {
    text.chars()
        .any(|c| matches!(c, '\x00'..='\x1f' | '\x7f' | '\\'))
}

/// Path allowlisting by path-segment semantics. Raw startsWith would let
/// `/v1secrets` match a `/v1` prefix and misses encoded traversal; this
/// decodes, normalizes, and rejects hostile shapes outright.
pub fn path_allowed(raw_path: &str, prefixes: &[String]) -> bool {
    let pathname = raw_path.split('?').next().unwrap_or("");
    // Reject control characters, backslashes, and null bytes before decoding.
    if has_hostile_chars(pathname) {
        return false;
    }
    let Some(decoded) = decode_uri_component(pathname) else {
        return false; // malformed percent-encoding
    };
    // Re-check after decoding: %5C, %00, %2e%2e etc.
    if has_hostile_chars(&decoded) {
        return false;
    }
    if !decoded.starts_with('/') {
        return false;
    }
    if decoded
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return false;
    }
    prefixes.iter().any(|prefix| {
        let normalized = prefix.strip_suffix('/').unwrap_or(prefix);
        if normalized.is_empty() {
            return true; // prefix "/" allows everything
        }
        decoded == normalized || decoded.starts_with(&format!("{normalized}/"))
    })
}

/// Extract the `model` field from a JSON request body, if it is a string.
pub fn extract_model(body: &[u8]) -> Option<String> {
    let parsed = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    parsed.get("model")?.as_str().map(str::to_owned)
}

/// Returns the upstream credential header map. Output is treated as secret.
pub type CredentialProvider =
    Arc<dyn Fn() -> BoxFuture<'static, Result<HashMap<String, String>>> + Send + Sync>;

/// Run the credential command via a shell and consume its stdout as the
/// secret value. stdout is never logged. Trailing newline stripped; empty
/// output fails closed.
async fn run_credential_command(command: &str, timeout_ms: u64) -> Result<String> {
    let future = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output();
    let output = tokio::time::timeout(Duration::from_millis(timeout_ms), future)
        .await
        .map_err(|_| Error::other("Credential command timed out"))?
        .map_err(|source| Error::io("credential command failed", source))?;
    if !output.status.success() {
        let code = output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(Error::other(format!(
            "Credential command exited with code {code}"
        )));
    }
    let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if secret.is_empty() {
        return Err(Error::other("Credential command produced no output"));
    }
    Ok(secret)
}

/// Credential provider backed by a subprocess command: stdout becomes
/// `{ [CREDENTIAL_COMMAND_HEADER]: "Bearer <secret>" }`.
pub fn credential_provider_from_command(command: String) -> CredentialProvider {
    Arc::new(move || {
        let command = command.clone();
        Box::pin(async move {
            let secret = run_credential_command(&command, CREDENTIAL_COMMAND_TIMEOUT_MS).await?;
            let mut headers = HashMap::new();
            headers.insert(
                CREDENTIAL_COMMAND_HEADER.to_string(),
                format!("Bearer {secret}"),
            );
            Ok(headers)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(token: &str, expires_at: Option<&str>, origin: &str) -> GatewayPolicy {
        GatewayPolicy {
            token_sha256: token.to_string(),
            expires_at: expires_at.map(str::to_string),
            target_origin: origin.to_string(),
            methods: vec!["POST".to_string()],
            path_prefixes: vec!["/v1".to_string()],
            models: Vec::new(),
            max_request_bytes: 1024,
            max_total_bytes: 4096,
            max_duration_secs: 60,
        }
    }

    #[test]
    fn validate_policy_accepts_well_formed() {
        let policy = policy_with(
            &crate::bundle::sha256_hex(b"token"),
            Some("2030-01-01T00:00:00Z"),
            "http://127.0.0.1:8080",
        );
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn validate_policy_rejects_bad_pin_expiry_origin_limits() {
        let base = policy_with(
            &crate::bundle::sha256_hex(b"token"),
            Some("2030-01-01T00:00:00Z"),
            "http://127.0.0.1:8080",
        );
        let bad_token = policy_with("XYZ", Some("2030-01-01T00:00:00Z"), "http://127.0.0.1:8080");
        assert!(validate_policy(&bad_token).is_err());

        let bad_expiry = policy_with(
            &base.token_sha256,
            Some("not-a-timestamp"),
            "http://127.0.0.1:8080",
        );
        assert!(validate_policy(&bad_expiry).is_err());

        let path_with_route = policy_with(
            &base.token_sha256,
            Some("2030-01-01T00:00:00Z"),
            "http://127.0.0.1:8080/api",
        );
        assert!(validate_policy(&path_with_route).is_err());

        let ftp_origin = policy_with(
            &base.token_sha256,
            Some("2030-01-01T00:00:00Z"),
            "ftp://127.0.0.1",
        );
        assert!(validate_policy(&ftp_origin).is_err());

        let mut empty_methods = base.clone();
        empty_methods.methods.clear();
        assert!(validate_policy(&empty_methods).is_err());

        let mut zero_limit = base;
        zero_limit.max_request_bytes = 0;
        assert!(validate_policy(&zero_limit).is_err());
    }

    #[test]
    fn token_pin_accept_and_reject() {
        let pin = crate::bundle::sha256_hex(b"opaque-token");
        assert!(token_matches("opaque-token", &pin));
        assert!(!token_matches("wrong-token", &pin));
        assert!(!token_matches("opaque-token", "not-hex"));
        assert!(!token_matches("", &pin));
    }

    #[test]
    fn path_allowlist_matrix() {
        let prefixes = vec!["/v1".to_string()];
        assert!(path_allowed("/v1/messages", &prefixes));
        assert!(path_allowed("/v1", &prefixes));
        assert!(path_allowed("/v1/messages?foo=bar", &prefixes));
        // Segment semantics: no bare startsWith.
        assert!(!path_allowed("/v1secrets", &prefixes));
        // Traversal rejected outright.
        assert!(!path_allowed("/v1/../etc/passwd", &prefixes));
        assert!(!path_allowed("/%2e%2e/etc", &prefixes));
        assert!(!path_allowed("/v1/%2e%2e/x", &prefixes));
        // Encoded backslash and control bytes rejected pre- and post-decode.
        assert!(!path_allowed("/v1/%5Cx", &prefixes));
        assert!(!path_allowed("/v1/%00", &prefixes));
        // Malformed percent-encoding rejected.
        assert!(!path_allowed("/v1/%zz", &prefixes));
        assert!(!path_allowed("/v1/%2", &prefixes));
        assert!(!path_allowed("relative/path", &prefixes));
        // Empty prefix ("/") allows everything well-formed.
        let root = vec!["/".to_string()];
        assert!(path_allowed("/anything/at/all", &root));
    }

    #[test]
    fn extract_model_reads_json_field() {
        assert_eq!(
            extract_model(br#"{"model":"claude-3","x":1}"#).as_deref(),
            Some("claude-3")
        );
        assert_eq!(extract_model(br#"{"model":42}"#), None);
        assert_eq!(extract_model(br#"{}"#), None);
        assert_eq!(extract_model(b"not json"), None);
    }

    #[tokio::test]
    async fn credential_command_strips_newline_and_fails_closed_on_empty() {
        let provider = credential_provider_from_command("printf 'secret-value\\n'".to_string());
        let headers = provider().await.expect("command should succeed");
        assert_eq!(
            headers.get(CREDENTIAL_COMMAND_HEADER).map(String::as_str),
            Some("Bearer secret-value")
        );

        let empty = credential_provider_from_command("true".to_string());
        assert!(empty().await.is_err(), "empty stdout must fail closed");

        let failing = credential_provider_from_command("exit 3".to_string());
        let err = failing().await.expect_err("non-zero exit must fail");
        assert!(err.to_string().contains("exited with code 3"));
    }
}
