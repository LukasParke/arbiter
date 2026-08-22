//! Redaction policy for captured traffic.
//!
//! Values for credential-bearing headers are removed before persistence; the
//! header names are retained as evidence. Query parameter values are redacted
//! by default (names retained) unless explicitly allowed.

use std::collections::BTreeSet;

use regex::Regex;
use serde::{Deserialize, Serialize};

const DEFAULT_REDACTED_HEADERS: [&str; 7] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-goog-api-key",
];

fn sensitive_header_pattern() -> &'static Regex {
    static PATTERN: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)api[-_]?key|auth|credential|secret|token|cookie|session").unwrap()
    });
    &PATTERN
}

pub const REDACTED_VALUE: &str = "__redacted__";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RedactionPolicyOptions {
    /// Additional header names or globs (e.g. `x-custom-*`) to redact.
    #[serde(rename = "redactHeaders", default)]
    pub redact_headers: Vec<String>,
    /// Query parameter names whose values may be kept.
    #[serde(rename = "allowQuery", default)]
    pub allow_query: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RedactionPolicy {
    extra_header_matchers: Vec<Regex>,
    extra_header_names: Vec<String>,
    allowed_query: BTreeSet<String>,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::new(&RedactionPolicyOptions::default())
    }
}

impl RedactionPolicy {
    pub fn new(options: &RedactionPolicyOptions) -> Self {
        let extra_header_names: Vec<String> = options
            .redact_headers
            .iter()
            .map(|h| h.to_lowercase())
            .collect();
        let extra_header_matchers = extra_header_names
            .iter()
            .map(|h| glob_to_regex(h))
            .collect();
        let allowed_query = options
            .allow_query
            .iter()
            .map(|q| q.to_lowercase())
            .collect();
        Self {
            extra_header_matchers,
            extra_header_names,
            allowed_query,
        }
    }

    pub fn should_redact_header(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        if DEFAULT_REDACTED_HEADERS.contains(&lower.as_str()) {
            return true;
        }
        if sensitive_header_pattern().is_match(&lower) {
            return true;
        }
        self.extra_header_matchers
            .iter()
            .any(|m| m.is_match(&lower))
    }

    pub fn should_redact_query_value(&self, name: &str) -> bool {
        !self.allowed_query.contains(&name.to_lowercase())
    }

    /// Name-based sensitivity check for contexts that keep benign query
    /// values (legacy observe mode). Exact capture uses
    /// [`should_redact_query_value`], which redacts by default.
    pub fn is_sensitive_name(name: &str) -> bool {
        sensitive_header_pattern().is_match(name)
    }

    /// Redact query values in a path+query string. Names are retained; values
    /// are replaced with a fixed placeholder unless allowed. The original
    /// query text is preserved verbatim for allowed pairs — no re-encoding,
    /// no `+` normalization, and bare flags (`?flag`) keep their form.
    pub fn redact_path(&self, path_with_query: &str) -> String {
        let Some(query_start) = path_with_query.find('?') else {
            return path_with_query.to_string();
        };
        let pathname = &path_with_query[..query_start];
        let raw_query = &path_with_query[query_start + 1..];
        if raw_query.is_empty() {
            return path_with_query.to_string();
        }
        let pairs: Vec<String> = raw_query
            .split('&')
            .map(|pair| {
                let eq = pair.find('=');
                let raw_name = match eq {
                    Some(i) => &pair[..i],
                    None => pair,
                };
                let decoded_name = try_decode(raw_name);
                if !self.should_redact_query_value(&decoded_name) {
                    return pair.to_string(); // preserved byte-for-byte
                }
                if eq.is_none() {
                    return pair.to_string(); // bare flag carries no value to redact
                }
                format!("{raw_name}={REDACTED_VALUE}")
            })
            .collect();
        format!("{pathname}?{}", pairs.join("&"))
    }

    pub fn summary(&self) -> crate::types::RedactionPolicySummary {
        let mut redact_headers: Vec<String> = DEFAULT_REDACTED_HEADERS
            .iter()
            .map(|s| s.to_string())
            .chain(self.extra_header_names.iter().cloned())
            .collect();
        redact_headers.sort();
        crate::types::RedactionPolicySummary {
            redact_headers,
            allow_query: self.allowed_query.iter().cloned().collect(),
        }
    }
}

/// Names of query parameters whose values were redacted in a captured
/// path+query string. The names themselves are retained in the path as
/// evidence; this recovers them for replayability decisions.
pub fn redacted_query_names(path_with_query: &str) -> Vec<String> {
    let Some(query_start) = path_with_query.find('?') else {
        return vec![];
    };
    let mut names: Vec<String> = vec![];
    for pair in path_with_query[query_start + 1..].split('&') {
        let Some(eq) = pair.find('=') else {
            continue;
        };
        let value = &pair[eq + 1..];
        if value == REDACTED_VALUE {
            let name = try_decode(&pair[..eq]);
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// Percent-decode with `+` treated as space; returns input on invalid
/// escapes (mirrors the TS tryDecode).
fn try_decode(text: &str) -> String {
    let plus_fixed = text.replace('+', " ");
    percent_encoding::percent_decode_str(&plus_fixed)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| text.to_string())
}

/// Glob where `*` matches any sequence; everything else literal,
/// case-insensitive, fully anchored (matches the TS globToRegExp).
fn glob_to_regex(glob: &str) -> Regex {
    let mut pattern = String::with_capacity(glob.len() + 2);
    pattern.push('^');
    for c in glob.chars() {
        match c {
            '*' => pattern.push_str(".*"),
            c if ".+^${}()|[]\\".contains(c) => {
                pattern.push('\\');
                pattern.push(c);
            }
            c => pattern.push(c),
        }
    }
    pattern.push('$');
    Regex::new(&format!("(?i){pattern}")).expect("valid glob regex")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_redacts_credential_and_sensitive_headers() {
        let p = RedactionPolicy::default();
        assert!(p.should_redact_header("Authorization"));
        assert!(p.should_redact_header("set-cookie"));
        assert!(p.should_redact_header("X-API-KEY"));
        assert!(p.should_redact_header("x-custom-api-key")); // api[-_]?key
        assert!(p.should_redact_header("Session-Id"));
        assert!(!p.should_redact_header("content-type"));
        assert!(!p.should_redact_header("accept"));
    }

    #[test]
    fn glob_extra_headers() {
        let p = RedactionPolicy::new(&RedactionPolicyOptions {
            redact_headers: vec!["x-custom-*".into()],
            allow_query: vec![],
        });
        assert!(p.should_redact_header("X-CUSTOM-THING"));
        assert!(!p.should_redact_header("x-custom")); // glob requires the hyphen
        assert!(!p.should_redact_header("x-other"));
    }

    #[test]
    fn query_values_redacted_unless_allowed() {
        let p = RedactionPolicy::new(&RedactionPolicyOptions {
            redact_headers: vec![],
            allow_query: vec!["api_version".into()],
        });
        assert_eq!(
            p.redact_path("/v1/messages?key=sk-ant-abc123&api_version=2023-06-01&flag"),
            "/v1/messages?key=__redacted__&api_version=2023-06-01&flag"
        );
        assert_eq!(p.redact_path("/no-query"), "/no-query");
        assert_eq!(p.redact_path("/empty?"), "/empty?");
    }

    #[test]
    fn query_names_preserved_verbatim() {
        let p = RedactionPolicy::default();
        // Raw name kept as-is (no re-encoding), value replaced.
        assert_eq!(
            p.redact_path("/x?a%20b=c&d=e"),
            "/x?a%20b=__redacted__&d=__redacted__"
        );
    }

    #[test]
    fn summary_merges_defaults_sorted() {
        let p = RedactionPolicy::new(&RedactionPolicyOptions {
            redact_headers: vec!["z-auth".into(), "a-secret".into()],
            allow_query: vec!["b".into(), "a".into()],
        });
        let s = p.summary();
        assert_eq!(
            s.redact_headers,
            vec![
                "a-secret",
                "authorization",
                "cookie",
                "proxy-authorization",
                "set-cookie",
                "x-api-key",
                "x-auth-token",
                "x-goog-api-key",
                "z-auth",
            ]
        );
        assert_eq!(s.allow_query, vec!["a", "b"]);
    }

    #[test]
    fn redacted_query_names_recovered() {
        assert_eq!(
            redacted_query_names("/x?token=__redacted__&ok=1&token=__redacted__&flag"),
            vec!["token"]
        );
        assert_eq!(redacted_query_names("/x"), Vec::<String>::new());
    }
}
