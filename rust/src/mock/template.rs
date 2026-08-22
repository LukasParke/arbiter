//! Minimal-but-real response templating (W3, AMEND-7).
//!
//! Exactly six tokens, nothing more:
//! `{{request.path}}`, `{{request.query.NAME}}`, `{{request.header.NAME}}`,
//! `{{now}}` (RFC 3339 UTC), `{{uuid}}` (random v4), `{{vars.NAME}}`.
//!
//! Unknown `{{...}}` tokens pass through VERBATIM and bump the warn counter
//! (see [`unknown_token_warnings`]) — no silent mangling, no template
//! injection surface. Recorded capture bodies are NEVER templated; only
//! spec-generated bodies and stub-declared text go through [`render`].

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use crate::types::HeaderMapValues;

/// Global count of unknown-token sightings across the process (exposed so
/// the CLI can surface a warning without spamming per request).
static UNKNOWN_TOKEN_COUNT: AtomicU64 = AtomicU64::new(0);

/// Per-render accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenderReport {
    pub tokens_rendered: usize,
    pub unknown_tokens: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct TemplateContext<'a> {
    pub path: &'a str,
    pub query: &'a [(String, String)],
    pub headers: &'a HeaderMapValues,
    /// Static overrides seeded from `--var K=V`. Consulted FIRST, so
    /// `--var now=2020-01-01T00:00:00Z` pins `{{now}}` for golden tests.
    pub vars: &'a BTreeMap<String, String>,
}

static UNKNOWN_SEEN: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Total unknown-token sightings since process start.
pub fn unknown_token_warnings() -> u64 {
    UNKNOWN_TOKEN_COUNT.load(Ordering::Relaxed)
}

/// Render a template string against the request context.
pub fn render(template: &str, ctx: &TemplateContext) -> String {
    render_with_report(template, ctx).0
}

/// Render, also returning per-render token accounting.
pub fn render_with_report(template: &str, ctx: &TemplateContext) -> (String, RenderReport) {
    let mut out = String::with_capacity(template.len());
    let mut report = RenderReport::default();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        match rest[start..].find("}}") {
            Some(end_off) => {
                let raw = &rest[start..start + end_off + 2]; // verbatim, braces included
                let token = raw[2..raw.len() - 2].trim();
                match resolve(token, ctx) {
                    Some(value) => {
                        out.push_str(&value);
                        report.tokens_rendered += 1;
                    }
                    None => {
                        out.push_str(raw);
                        report.unknown_tokens += 1;
                        note_unknown(token);
                    }
                }
                rest = &rest[start + end_off + 2..];
            }
            None => {
                // Unbalanced open braces: verbatim, no error.
                out.push_str(&rest[start..]);
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    (out, report)
}

/// Resolve one token name. `None` = unknown token (caller emits verbatim).
fn resolve(token: &str, ctx: &TemplateContext) -> Option<String> {
    // Static overrides win first (pins {{now}}/{{uuid}} for golden tests).
    if let Some(v) = ctx.vars.get(token) {
        return Some(v.clone());
    }
    if let Some(name) = token.strip_prefix("request.query.") {
        return Some(
            ctx.query
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
        );
    }
    if let Some(name) = token.strip_prefix("request.header.") {
        return Some(
            ctx.headers
                .get(&name.to_ascii_lowercase())
                .and_then(|vals| vals.first().cloned())
                .unwrap_or_default(),
        );
    }
    if let Some(name) = token.strip_prefix("vars.") {
        return Some(ctx.vars.get(name).cloned().unwrap_or_default());
    }
    match token {
        "request.path" => Some(ctx.path.to_string()),
        "now" => Some(chrono::Utc::now().to_rfc3339()),
        "uuid" => Some(uuid_v4()),
        _ => None,
    }
}

/// Random UUID v4 via rand, formatted as hyphenated lowercase hex
/// (no uuid crate — rejected dependency).
pub fn uuid_v4() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

fn note_unknown(token: &str) {
    UNKNOWN_TOKEN_COUNT.fetch_add(1, Ordering::Relaxed);
    let mut seen = UNKNOWN_SEEN.lock().expect("unknown-token set");
    if seen.insert(token.to_string()) {
        eprintln!(
            "mock: unknown template token '{{{{{token}}}}}' passed through verbatim\n  help: supported tokens: {{{{request.path}}}}, {{{{request.query.NAME}}}}, {{{{request.header.NAME}}}}, {{{{now}}}}, {{{{uuid}}}}, {{{{vars.NAME}}}}"
        );
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(
        path: &'a str,
        query: &'a [(String, String)],
        headers: &'a HeaderMapValues,
        vars: &'a BTreeMap<String, String>,
    ) -> TemplateContext<'a> {
        TemplateContext {
            path,
            query,
            headers,
            vars,
        }
    }

    fn no_vars() -> &'static BTreeMap<String, String> {
        Box::leak(Box::new(BTreeMap::new()))
    }

    fn base<'a>(
        path: &'a str,
        query: &'a [(String, String)],
        headers: &'a HeaderMapValues,
    ) -> TemplateContext<'a> {
        ctx(path, query, headers, no_vars())
    }

    #[test]
    fn all_six_tokens_render() {
        let headers = HeaderMapValues::from([(
            ("content-type").to_string(),
            vec!["application/json".to_string()],
        )]);
        let vars = BTreeMap::from([("env".to_string(), "test".to_string())]);
        let query = vec![
            ("model".to_string(), "claude".to_string()),
            ("empty".to_string(), String::new()),
        ];
        let c = ctx("/v1/messages", &query, &headers, &vars);

        let out = render(
            "p={{request.path}} m={{request.query.model}} ct={{request.header.Content-Type}} env={{vars.env}} missing={{request.query.nope}}",
            &c,
        );
        assert_eq!(
            out,
            "p=/v1/messages m=claude ct=application/json env=test missing="
        );

        let (out, rep) = render_with_report("{{now}} {{uuid}}", &c);
        assert_eq!(rep.tokens_rendered, 2);
        assert_eq!(rep.unknown_tokens, 0);
        // RFC 3339-ish and v4-shaped.
        assert!(out.contains("T"));
        let uuid = out.split(' ').nth(1).expect("uuid present");
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.as_bytes()[14], b'4');
        assert!(matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }

    #[test]
    fn unknown_tokens_pass_through_verbatim_and_count() {
        let headers = HeaderMapValues::new();
        let before = unknown_token_warnings();
        let c = base("/x", &[], &headers);
        let (out, rep) = render_with_report("keep {{ secret.sauce }} and {{request.path}}", &c);
        assert_eq!(out, "keep {{ secret.sauce }} and /x");
        assert_eq!(rep.unknown_tokens, 1);
        assert!(unknown_token_warnings() >= before + 1);
        // Same unknown token again: still verbatim, counter still grows.
        let (out2, _) = render_with_report("{{ secret.sauce }}", &c);
        assert_eq!(out2, "{{ secret.sauce }}");
    }

    #[test]
    fn unbalanced_braces_are_verbatim() {
        let headers = HeaderMapValues::new();
        let c = base("/x", &[], &headers);
        assert_eq!(render("oops {{now", &c), "oops {{now");
        assert_eq!(render("}} lead", &c), "}} lead");
    }

    #[test]
    fn vars_pin_dynamic_tokens() {
        let headers = HeaderMapValues::new();
        let vars = BTreeMap::from([
            ("now".to_string(), "2020-01-01T00:00:00Z".to_string()),
            ("uuid".to_string(), "fixed".to_string()),
        ]);
        let c = ctx("/x", &[], &headers, &vars);
        assert_eq!(render("{{now}} {{uuid}}", &c), "2020-01-01T00:00:00Z fixed");
    }

    #[test]
    fn uuid_v4_shape() {
        for _ in 0..16 {
            let u = uuid_v4();
            assert_eq!(u.len(), 36);
            assert_eq!(&u[14..15], "4");
            assert!(matches!(u.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        }
    }
}
