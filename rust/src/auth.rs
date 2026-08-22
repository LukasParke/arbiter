//! Authentication configuration and security-scheme detection.
//!
//! Ports `src/auth.ts` (`AuthManager` credential config persisted at
//! `~/.arbiter/auth.json`) plus the proxy recorder's observed-header auth
//! detection from `src/server.ts` (securitySchemes extraction: bearer /
//! basic / apiKey). Only scheme shapes are recorded — never token values.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::types::HeaderMapValues;

/// Credential style of a stored auth configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthType {
    PlexToken,
    Bearer,
    ApiKey,
}

/// Persisted authentication configuration (`~/.arbiter/auth.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(rename = "type")]
    pub auth_type: AuthType,
    #[serde(default)]
    pub token: String,
    #[serde(
        rename = "headerName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub header_name: Option<String>,
    #[serde(
        rename = "queryParamName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub query_param_name: Option<String>,
}

fn auth_config_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::Path::new(&home).join(".arbiter")
}

fn auth_config_file() -> std::path::PathBuf {
    auth_config_dir().join("auth.json")
}

fn load_from_disk() -> Option<AuthConfig> {
    let raw = std::fs::read_to_string(auth_config_file()).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Credential manager: loads/saves the on-disk configuration and renders the
/// headers/query parameters needed to authenticate upstream requests.
#[derive(Debug, Clone, Default)]
pub struct AuthManager {
    config: Option<AuthConfig>,
}

impl AuthManager {
    /// Loads the configuration from disk; errors are ignored (matching TS).
    pub fn new() -> Self {
        Self {
            config: load_from_disk(),
        }
    }

    pub fn from_config(config: AuthConfig) -> Self {
        Self {
            config: Some(config),
        }
    }

    pub fn from_token(token: &str) -> Self {
        Self::from_token_as(token, AuthType::PlexToken)
    }

    pub fn from_token_as(token: &str, auth_type: AuthType) -> Self {
        Self::from_config(AuthConfig {
            auth_type,
            token: token.to_string(),
            header_name: None,
            query_param_name: None,
        })
    }

    /// Persists the configuration, creating `~/.arbiter/` when missing.
    pub fn save_to_disk(&self) -> Result<()> {
        let Some(config) = &self.config else {
            return Ok(());
        };
        let dir = auth_config_dir();
        if !dir.exists() {
            std::fs::create_dir_all(&dir)
                .map_err(|e| crate::error::Error::io("create auth config dir", e))?;
        }
        let raw = serde_json::to_string_pretty(config).map_err(|e| crate::error::Error::Json {
            context: "serialize auth config".into(),
            source: e,
        })?;
        std::fs::write(auth_config_file(), raw)
            .map_err(|e| crate::error::Error::io("write auth config", e))
    }

    /// Headers to attach for authenticated requests.
    pub fn get_headers(&self) -> BTreeMap<String, String> {
        let Some(config) = &self.config else {
            return BTreeMap::new();
        };
        match config.auth_type {
            AuthType::PlexToken => {
                BTreeMap::from([("X-Plex-Token".to_string(), config.token.clone())])
            }
            AuthType::Bearer => BTreeMap::from([(
                "Authorization".to_string(),
                format!("Bearer {}", config.token),
            )]),
            AuthType::ApiKey => BTreeMap::from([(
                config
                    .header_name
                    .clone()
                    .unwrap_or_else(|| "X-API-Key".to_string()),
                config.token.clone(),
            )]),
        }
    }

    /// Query parameters to attach for authenticated requests.
    pub fn get_query_params(&self) -> BTreeMap<String, String> {
        let Some(config) = &self.config else {
            return BTreeMap::new();
        };
        match config.auth_type {
            AuthType::PlexToken => {
                BTreeMap::from([("X-Plex-Token".to_string(), config.token.clone())])
            }
            AuthType::ApiKey => match &config.query_param_name {
                Some(name) => BTreeMap::from([(name.clone(), config.token.clone())]),
                None => BTreeMap::new(),
            },
            AuthType::Bearer => BTreeMap::new(),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.config.as_ref().is_some_and(|c| !c.token.is_empty())
    }

    /// Token safe for logs: `***` for short tokens, `first4...last4` otherwise.
    pub fn redacted_token(&self) -> String {
        let Some(config) = &self.config else {
            return "none".to_string();
        };
        let t = &config.token;
        if t.chars().count() <= 8 {
            return "***".to_string();
        }
        let chars: Vec<char> = t.chars().collect();
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}...{tail}")
    }

    pub fn config(&self) -> Option<&AuthConfig> {
        self.config.as_ref()
    }
}

/// OpenAPI-style security scheme description. Only shapes are recorded;
/// credential values never reach this type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityInfo {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "in", skip_serializing_if = "Option::is_none")]
    pub in_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// Detects auth styles from observed (pre-redaction) request headers:
/// - any `x-api-key` header -> `{type: "apiKey", name: "x-api-key", in: "header"}`
/// - `authorization: Bearer ...` -> `{type: "http", scheme: "bearer"}`
/// - `authorization: Basic ...` -> `{type: "http", scheme: "basic"}`
///
/// Matches the detection performed by the TS server proxy recorder
/// (`server.ts`); header names are compared case-insensitively.
pub fn detect_security_schemes(req_headers: &HeaderMapValues) -> Vec<SecurityInfo> {
    let mut schemes = Vec::new();

    let api_key_present = req_headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("x-api-key"));
    if api_key_present {
        schemes.push(SecurityInfo {
            type_: "apiKey".to_string(),
            name: Some("x-api-key".to_string()),
            in_: Some("header".to_string()),
            scheme: None,
        });
    }

    let authorization = req_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .and_then(|(_, values)| values.first().cloned());

    if authorization
        .as_deref()
        .is_some_and(|v| v.starts_with("Bearer "))
    {
        schemes.push(SecurityInfo {
            type_: "http".to_string(),
            name: None,
            in_: None,
            scheme: Some("bearer".to_string()),
        });
    }
    if authorization
        .as_deref()
        .is_some_and(|v| v.starts_with("Basic "))
    {
        schemes.push(SecurityInfo {
            type_: "http".to_string(),
            name: None,
            in_: None,
            scheme: Some("basic".to_string()),
        });
    }

    schemes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(entries: &[(&str, &str)]) -> HeaderMapValues {
        let mut map = HeaderMapValues::new();
        for (name, value) in entries {
            map.entry(name.to_lowercase())
                .or_default()
                .push(value.to_string());
        }
        map
    }

    #[test]
    fn plex_token_headers_and_query_params() {
        let manager = AuthManager::from_token("secret-token-value");
        assert_eq!(
            manager.get_headers(),
            BTreeMap::from([("X-Plex-Token".to_string(), "secret-token-value".to_string())])
        );
        assert_eq!(
            manager.get_query_params(),
            BTreeMap::from([("X-Plex-Token".to_string(), "secret-token-value".to_string())])
        );
        assert!(manager.is_authenticated());
    }

    #[test]
    fn bearer_headers_only() {
        let manager = AuthManager::from_token_as("tok-1234567890", AuthType::Bearer);
        assert_eq!(
            manager.get_headers(),
            BTreeMap::from([(
                "Authorization".to_string(),
                "Bearer tok-1234567890".to_string()
            )])
        );
        assert!(manager.get_query_params().is_empty());
    }

    #[test]
    fn api_key_uses_custom_header_and_query_names() {
        let manager = AuthManager::from_config(AuthConfig {
            auth_type: AuthType::ApiKey,
            token: "key-abcdef".to_string(),
            header_name: Some("X-Custom-Key".to_string()),
            query_param_name: Some("apiKey".to_string()),
        });
        assert_eq!(
            manager.get_headers(),
            BTreeMap::from([("X-Custom-Key".to_string(), "key-abcdef".to_string())])
        );
        assert_eq!(
            manager.get_query_params(),
            BTreeMap::from([("apiKey".to_string(), "key-abcdef".to_string())])
        );
    }

    #[test]
    fn unauthenticated_manager_renders_nothing() {
        let manager = AuthManager::default();
        assert!(!manager.is_authenticated());
        assert!(manager.get_headers().is_empty());
        assert!(manager.get_query_params().is_empty());
        assert_eq!(manager.redacted_token(), "none");
    }

    #[test]
    fn redacted_token_shapes() {
        assert_eq!(AuthManager::from_token("short").redacted_token(), "***");
        assert_eq!(AuthManager::from_token("12345678").redacted_token(), "***");
        assert_eq!(
            AuthManager::from_token("abcdefghijklmnop").redacted_token(),
            "abcd...mnop"
        );
    }

    #[test]
    fn auth_config_round_trips_kebab_case_type() {
        let json = r#"{"type":"api-key","token":"tok","headerName":"X-K","queryParamName":"k"}"#;
        let config: AuthConfig = serde_json::from_str(json).expect("parse auth config");
        assert_eq!(config.auth_type, AuthType::ApiKey);
        assert_eq!(config.header_name.as_deref(), Some("X-K"));
        let encoded = serde_json::to_value(&config).expect("encode");
        assert_eq!(encoded["type"], "api-key");
        assert_eq!(encoded["headerName"], "X-K");
    }

    #[test]
    fn detects_api_key_scheme_from_observed_header() {
        let schemes = detect_security_schemes(&headers(&[("x-api-key", "super-secret")]));
        assert_eq!(
            schemes,
            vec![SecurityInfo {
                type_: "apiKey".into(),
                name: Some("x-api-key".into()),
                in_: Some("header".into()),
                scheme: None,
            }]
        );
        // Case-insensitive header names are recognized too.
        assert_eq!(
            detect_security_schemes(&headers(&[("X-API-Key", "v")])),
            schemes
        );
    }

    #[test]
    fn detects_bearer_and_basic_schemes() {
        let bearer = detect_security_schemes(&headers(&[("authorization", "Bearer abc.def.ghi")]));
        assert_eq!(
            bearer,
            vec![SecurityInfo {
                type_: "http".into(),
                name: None,
                in_: None,
                scheme: Some("bearer".into()),
            }]
        );

        let basic = detect_security_schemes(&headers(&[("authorization", "Basic dXNlcjpwYXNz")]));
        assert_eq!(
            basic,
            vec![SecurityInfo {
                type_: "http".into(),
                name: None,
                in_: None,
                scheme: Some("basic".into()),
            }]
        );
    }

    #[test]
    fn no_auth_headers_yields_no_schemes_and_values_never_leak() {
        assert!(
            detect_security_schemes(&headers(&[("content-type", "application/json")])).is_empty()
        );

        let combined = detect_security_schemes(&headers(&[
            ("X-API-Key", "leaky-key"),
            ("authorization", "Bearer leaky-token"),
        ]));
        assert_eq!(combined.len(), 2);
        let rendered = serde_json::to_string(&combined).expect("render schemes");
        assert!(!rendered.contains("leaky"));
    }

    #[test]
    fn malformed_authorization_prefix_is_ignored() {
        assert!(
            detect_security_schemes(&headers(&[("authorization", "bearer lowercase")])).is_empty()
        );
        assert!(detect_security_schemes(&headers(&[("authorization", "Digest xyz")])).is_empty());
    }

    #[test]
    fn save_to_disk_persists_and_reload_matches() {
        let _env_guard = crate::config::test_support::env_test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        // Point HOME at the tempdir for the duration of this test.
        let previous = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());
        let manager = AuthManager::from_token_as("persisted-token-123", AuthType::Bearer);
        manager.save_to_disk().expect("save");
        let reloaded = AuthManager::new();
        assert_eq!(
            reloaded.config(),
            Some(&AuthConfig {
                auth_type: AuthType::Bearer,
                token: "persisted-token-123".to_string(),
                header_name: None,
                query_param_name: None,
            })
        );
        match previous {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
    }
}
