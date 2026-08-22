//! Fail-closed secret scanning over captured exchanges.
//!
//! Scan captured exchanges, header values, paths, metadata, and textual
//! bodies for secrets. Findings identify location and kind but never include
//! the complete secret value.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;

use regex::Regex;

use crate::error::{Error, Result, SecretFindingError};
use crate::types::{BodyStorage, CapturedBody, CapturedExchange};

#[derive(Debug, Clone, PartialEq)]
pub struct SecretFinding {
    /// e.g. "exchange 3 request body", "manifest metadata key foo"
    pub location: String,
    /// Pattern or reason; never contains the full secret.
    pub kind: String,
}

#[derive(Debug, Clone, Default)]
pub struct SecretScanOptions {
    /// Exact secret values to reject anywhere. Never persisted.
    pub reject_secrets: Vec<String>,
    /// Media types allowed to remain unscanned binary.
    pub allow_binary_media_types: Vec<String>,
}

struct SecretPattern {
    kind: &'static str,
    regex: Regex,
}

fn secret_patterns() -> &'static [SecretPattern] {
    static PATTERNS: std::sync::LazyLock<Vec<SecretPattern>> = std::sync::LazyLock::new(|| {
        vec![
            SecretPattern {
                kind: "anthropic-api-key",
                regex: Regex::new(r"\bsk-ant-[A-Za-z0-9_-]{10,}").unwrap(),
            },
            SecretPattern {
                kind: "openai-api-key",
                regex: Regex::new(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}").unwrap(),
            },
            SecretPattern {
                kind: "openrouter-api-key",
                regex: Regex::new(r"\bsk-or-[A-Za-z0-9_-]{10,}").unwrap(),
            },
            SecretPattern {
                kind: "github-token",
                regex: Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,}").unwrap(),
            },
            SecretPattern {
                kind: "aws-access-key-id",
                regex: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
            },
            SecretPattern {
                kind: "google-api-key",
                regex: Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap(),
            },
            SecretPattern {
                kind: "slack-token",
                regex: Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
            },
            SecretPattern {
                kind: "jwt",
                regex: Regex::new(
                    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
                )
                .unwrap(),
            },
            SecretPattern {
                kind: "pem-private-key",
                regex: Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(),
            },
            SecretPattern {
                kind: "authorization-value",
                regex: Regex::new(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_.-]{16,}").unwrap(),
            },
        ]
    });
    &PATTERNS
}

fn textual_media() -> &'static Regex {
    static RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)json|text|xml|yaml|x-www-form-urlencoded|event-stream|javascript").unwrap()
    });
    &RE
}

/// Decompression bomb guard for analysis views.
const MAX_DECODED_ANALYSIS_BYTES: usize = 256 * 1024 * 1024;

/// Scan captured exchanges, header values, paths, metadata, and textual
/// bodies for secrets. `bodies` maps sha256 digests to blob bytes for
/// blob-backed bodies.
pub fn scan_exchanges(
    exchanges: &[CapturedExchange],
    bodies: &HashMap<String, Vec<u8>>,
    metadata: Option<&BTreeMap<String, String>>,
    options: &SecretScanOptions,
) -> Vec<SecretFinding> {
    let mut findings: Vec<SecretFinding> = vec![];
    let reject_values: Vec<&String> = options
        .reject_secrets
        .iter()
        .filter(|s| s.len() >= 4)
        .collect();

    let mut scan_text = |text: &str, location: &str, findings: &mut Vec<SecretFinding>| {
        for value in &reject_values {
            if text.contains(value.as_str()) {
                findings.push(SecretFinding {
                    location: location.to_string(),
                    kind: "caller-rejected-secret".into(),
                });
            }
        }
        for pattern in secret_patterns() {
            if pattern.regex.is_match(text) {
                findings.push(SecretFinding {
                    location: location.to_string(),
                    kind: pattern.kind.into(),
                });
            }
        }
    };

    if let Some(metadata) = metadata {
        for (key, value) in metadata {
            let combined = format!("{key}={value}");
            scan_text(
                &combined,
                &format!("manifest metadata key {key}"),
                &mut findings,
            );
        }
    }

    for exchange in exchanges {
        let prefix = format!("exchange {}", exchange.sequence);
        scan_text(
            &exchange.request.path,
            &format!("{prefix} request path"),
            &mut findings,
        );
        scan_header_values(
            &exchange.request.headers.values,
            &format!("{prefix} request headers"),
            &mut scan_text,
            &mut findings,
        );
        scan_header_values(
            &exchange.response.headers.values,
            &format!("{prefix} response headers"),
            &mut scan_text,
            &mut findings,
        );
        scan_body(
            &exchange.request.body,
            bodies,
            &format!("{prefix} request body"),
            options,
            &reject_values,
            &mut findings,
        );
        scan_body(
            &exchange.response.body,
            bodies,
            &format!("{prefix} response body"),
            options,
            &reject_values,
            &mut findings,
        );
    }

    findings
}

fn scan_header_values(
    values: &crate::types::HeaderMapValues,
    location: &str,
    scan_text: &mut impl FnMut(&str, &str, &mut Vec<SecretFinding>),
    findings: &mut Vec<SecretFinding>,
) {
    for (name, header_values) in values {
        // Header NAMES can carry secrets too. Scan them with a generic
        // location so the finding never echoes the (potentially secret) name.
        scan_text(name, &format!("{location} (header name)"), findings);
        for value in header_values {
            scan_text(value, &format!("{location} ({name})"), findings);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_body(
    body: &CapturedBody,
    bodies: &HashMap<String, Vec<u8>>,
    location: &str,
    options: &SecretScanOptions,
    reject_values: &[&String],
    findings: &mut Vec<SecretFinding>,
) {
    if body.size == 0 {
        return;
    }
    let Some(raw_bytes) = read_body_bytes(body, bodies) else {
        findings.push(SecretFinding {
            location: location.to_string(),
            kind: "body-bytes-unavailable".into(),
        });
        return;
    };
    // Scan the decoded analysis view; the canonical bytes stay untouched.
    let Some(bytes) = decode_analysis_view(&raw_bytes, body.content_encoding.as_deref()) else {
        findings.push(SecretFinding {
            location: location.to_string(),
            kind: format!(
                "undecodable-body (content-encoding: {})",
                body.content_encoding.as_deref().unwrap_or("unknown")
            ),
        });
        return;
    };
    let media_type = body.media_type.as_deref().unwrap_or("");
    if textual_media().is_match(media_type) || looks_like_utf8_text(&bytes) {
        let text = String::from_utf8_lossy(&bytes);
        for value in reject_values {
            if text.contains(value.as_str()) {
                findings.push(SecretFinding {
                    location: location.to_string(),
                    kind: "caller-rejected-secret".into(),
                });
            }
        }
        for pattern in secret_patterns() {
            if pattern.regex.is_match(&text) {
                findings.push(SecretFinding {
                    location: location.to_string(),
                    kind: pattern.kind.into(),
                });
            }
        }
        return;
    }
    let allowed = options.allow_binary_media_types.iter().any(|allowed_type| {
        media_type
            .to_lowercase()
            .starts_with(&allowed_type.to_lowercase())
    });
    if !allowed {
        findings.push(SecretFinding {
            location: location.to_string(),
            kind: format!(
                "unscannable-binary-body ({})",
                if media_type.is_empty() {
                    "unknown media type"
                } else {
                    media_type
                }
            ),
        });
    }
}

fn read_body_bytes(body: &CapturedBody, bodies: &HashMap<String, Vec<u8>>) -> Option<Vec<u8>> {
    match &body.storage {
        BodyStorage::InlineBase64 { value } => base64_decode(value).ok().map(|v| v.to_vec()),
        BodyStorage::Blob { .. } => bodies.get(&body.sha256).cloned(),
    }
}

pub(crate) fn base64_decode(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(value)
}

/// Decompress an analysis view according to content-encoding, with a hard
/// output-size cap. Returns `None` for unknown encodings or failures.
fn decode_analysis_view(bytes: &[u8], content_encoding: Option<&str>) -> Option<Vec<u8>> {
    let encoding = match content_encoding {
        None => return Some(bytes.to_vec()),
        Some(e) if e.eq_ignore_ascii_case("identity") => return Some(bytes.to_vec()),
        Some(e) => e,
    };
    let lower = encoding.to_lowercase();
    let mut out: Vec<u8> = Vec::new();
    let bounded_read = |reader: &mut dyn Read, out: &mut Vec<u8>| -> Option<()> {
        let mut limited = reader.take((MAX_DECODED_ANALYSIS_BYTES + 1) as u64);
        limited.read_to_end(out).ok()?;
        if out.len() > MAX_DECODED_ANALYSIS_BYTES {
            return None;
        }
        Some(())
    };
    match lower.as_str() {
        "gzip" | "x-gzip" => {
            let mut reader = flate2::read::MultiGzDecoder::new(bytes);
            bounded_read(&mut reader, &mut out)?;
        }
        "deflate" => {
            let mut reader = flate2::read::ZlibDecoder::new(bytes);
            bounded_read(&mut reader, &mut out)?;
        }
        "br" => {
            let mut reader = brotli::Decompressor::new(bytes, 4096);
            bounded_read(&mut reader, &mut out)?;
        }
        "zstd" => {
            let mut reader = zstd::stream::read::Decoder::new(bytes).ok()?;
            bounded_read(&mut reader, &mut out)?;
        }
        _ => return None,
    }
    Some(out)
}

fn looks_like_utf8_text(bytes: &[u8]) -> bool {
    let end = bytes.len().min(4096);
    let sample = &bytes[..end];
    std::str::from_utf8(sample).is_ok()
}

/// Convenience wrapper that turns findings into the fail-closed error.
pub fn ensure_clean(findings: Vec<SecretFinding>) -> Result<()> {
    if findings.is_empty() {
        Ok(())
    } else {
        Err(Error::SecretFindings(SecretFindingError { findings }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CapturedHeaders, CapturedRequest, CapturedResponse, StreamState};
    use std::collections::BTreeMap;
    use std::io::Write as _;

    fn inline_body(bytes: &[u8], media_type: Option<&str>) -> CapturedBody {
        CapturedBody {
            sha256: crate::bundle::sha256_hex(bytes),
            size: bytes.len() as u64,
            media_type: media_type.map(|m| m.to_string()),
            content_encoding: None,
            storage: BodyStorage::InlineBase64 {
                value: {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                },
            },
        }
    }

    fn exchange(
        seq: u64,
        req_path: &str,
        req_body: CapturedBody,
        resp_body: CapturedBody,
    ) -> CapturedExchange {
        CapturedExchange {
            schema_version: 1,
            sequence: seq,
            started_at: "2026-08-21T00:00:00.000Z".into(),
            duration_ms: 1.0,
            request: CapturedRequest {
                method: "POST".into(),
                path: req_path.into(),
                http_version: "1.1".into(),
                headers: CapturedHeaders {
                    values: BTreeMap::new(),
                    redacted: vec![],
                },
                body: req_body,
            },
            response: CapturedResponse {
                status: 200,
                status_text: "OK".into(),
                http_version: "1.1".into(),
                headers: CapturedHeaders {
                    values: BTreeMap::new(),
                    redacted: vec![],
                },
                body: resp_body,
                stream: StreamState {
                    kind: "buffered".into(),
                    completed: true,
                    client_aborted: false,
                    upstream_aborted: false,
                    terminal_marker: None,
                    error: None,
                },
            },
            failure: None,
            validation: None,
            tunnel: None,
            tls: None,
            ws: None,
            llm: None,
        }
    }

    #[test]
    fn detects_known_credential_patterns() {
        let key = format!("sk-ant-{}", "a".repeat(20));
        let exchanges = vec![exchange(
            3,
            "/v1/messages",
            inline_body(key.as_bytes(), Some("application/json")),
            inline_body(b"{}", Some("application/json")),
        )];
        let findings = scan_exchanges(
            &exchanges,
            &HashMap::new(),
            None,
            &SecretScanOptions::default(),
        );
        // sk-ant-... also matches the generic openai pattern; both are reported.
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].location, "exchange 3 request body");
        assert!(findings.iter().any(|f| f.kind == "anthropic-api-key"));
    }

    #[test]
    fn rejects_exact_caller_secret_anywhere() {
        let secret = "supersecretvalue99";
        let exchanges = vec![exchange(
            1,
            "/x",
            inline_body(b"harmless", Some("text/plain")),
            inline_body(
                format!("prefix-{secret}-suffix").as_bytes(),
                Some("text/plain"),
            ),
        )];
        let options = SecretScanOptions {
            reject_secrets: vec![secret.to_string()],
            allow_binary_media_types: vec![],
        };
        let findings = scan_exchanges(&exchanges, &HashMap::new(), None, &options);
        assert_eq!(findings[0].kind, "caller-rejected-secret");
        assert_eq!(findings[0].location, "exchange 1 response body");
    }

    #[test]
    fn short_reject_values_ignored() {
        let exchanges = vec![exchange(
            1,
            "/x",
            inline_body(b"ab", None),
            inline_body(b"", None),
        )];
        let options = SecretScanOptions {
            reject_secrets: vec!["abc".to_string()],
            allow_binary_media_types: vec![],
        };
        assert!(scan_exchanges(&exchanges, &HashMap::new(), None, &options).is_empty());
    }

    #[test]
    fn binary_body_without_allowed_type_fails_closed() {
        let png = vec![0x89u8, b'P', b'N', b'G', 0, 1, 2, 3];
        let exchanges = vec![exchange(
            1,
            "/img",
            inline_body(&png, Some("image/png")),
            inline_body(b"", None),
        )];
        let findings = scan_exchanges(
            &exchanges,
            &HashMap::new(),
            None,
            &SecretScanOptions::default(),
        );
        assert_eq!(findings[0].kind, "unscannable-binary-body (image/png)");

        let options = SecretScanOptions {
            reject_secrets: vec![],
            allow_binary_media_types: vec!["image/".to_string()],
        };
        assert!(scan_exchanges(&exchanges, &HashMap::new(), None, &options).is_empty());
    }

    #[test]
    fn gzipped_bodies_scanned_after_decode() {
        let payload = format!("data: sk-or-{}\n\n", "x".repeat(30));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut body = inline_body(&compressed, Some("text/event-stream"));
        body.content_encoding = Some("gzip".into());
        let exchanges = vec![exchange(2, "/chat", body, inline_body(b"", None))];
        let findings = scan_exchanges(
            &exchanges,
            &HashMap::new(),
            None,
            &SecretScanOptions::default(),
        );
        assert!(findings.iter().any(|f| f.kind == "openrouter-api-key"));
    }

    #[test]
    fn metadata_scanned() {
        let mut meta = BTreeMap::new();
        meta.insert("note".to_string(), "ghp_".to_string() + &"A".repeat(40));
        let findings = scan_exchanges(
            &[],
            &HashMap::new(),
            Some(&meta),
            &SecretScanOptions::default(),
        );
        assert_eq!(findings[0].kind, "github-token");
        assert_eq!(findings[0].location, "manifest metadata key note");
    }

    #[test]
    fn jwt_and_pem_detected_in_headers() {
        let jwt = format!(
            "eyJ{}.{}.{}",
            "a".repeat(15),
            "b".repeat(15),
            "c".repeat(15)
        );
        let mut headers: crate::types::HeaderMapValues = BTreeMap::new();
        headers.insert("x-trace".into(), vec![jwt]);
        let mut exchange = exchange(1, "/x", inline_body(b"", None), inline_body(b"", None));
        exchange.request.headers.values = headers;
        let findings = scan_exchanges(
            std::slice::from_ref(&exchange),
            &HashMap::new(),
            None,
            &SecretScanOptions::default(),
        );
        assert_eq!(findings[0].kind, "jwt");
        assert_eq!(findings[0].location, "exchange 1 request headers (x-trace)");
    }
}
