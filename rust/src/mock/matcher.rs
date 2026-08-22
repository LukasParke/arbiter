//! Shared request-matching library (W3) — THE glob library of the crate
//! (AMEND-1). `GlobPattern` is the single source of glob semantics; TLS
//! passthrough rules, TUI filters and capture-mock stubs all consume it.
//! Globs are never lowered to regex.
//!
//! Semantics: segment-scoped. `*` matches any text within one path segment
//! (including the empty string) and never crosses `/`. `**` as a complete
//! segment matches zero or more segments. Literal chunks inside a segment
//! (`*.example.com`) are anchored at the segment boundaries.

use crate::error::{Error, Result};
use crate::types::HeaderMapValues;

// ---------------------------------------------------------------------------
// GlobPattern
// ---------------------------------------------------------------------------

/// One compiled path segment of a glob pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternSeg {
    /// `**` — crosses zero or more segments.
    StarStar,
    /// Literal chunks joined by `*` wildcards, matched within one segment.
    Wild(Vec<String>),
}

/// A compiled glob. Compile once at startup (perf bar: never compile on the
/// hot path) and reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobPattern {
    segs: Vec<PatternSeg>,
    case_insensitive: bool,
}

/// Compile a case-sensitive glob (`*` within a segment, `**` across segments).
pub fn compile_glob(pattern: &str) -> Result<GlobPattern> {
    compile_glob_inner(pattern, false)
}

/// Compile a case-insensitive glob — used for host matching
/// (`*.Example.COM` matches `api.example.com`).
pub fn compile_host_glob(pattern: &str) -> Result<GlobPattern> {
    compile_glob_inner(pattern, true)
}

fn compile_glob_inner(pattern: &str, case_insensitive: bool) -> Result<GlobPattern> {
    if pattern.is_empty() {
        return Err(Error::other(
            "mock: empty glob pattern (expected e.g. \"/v1/*/messages\" or \"*.example.com\")",
        ));
    }
    let norm = |s: &str| {
        if case_insensitive {
            s.to_lowercase()
        } else {
            s.to_string()
        }
    };
    let segs = pattern
        .split('/')
        .map(|seg| {
            if seg == "**" {
                PatternSeg::StarStar
            } else {
                PatternSeg::Wild(seg.split('*').map(norm).collect())
            }
        })
        .collect();
    Ok(GlobPattern {
        segs,
        case_insensitive,
    })
}

impl GlobPattern {
    /// Match a `/`-separated candidate string against this pattern.
    pub fn is_match(&self, candidate: &str) -> bool {
        let mut cand: Vec<String> = candidate
            .split('/')
            .map(|s| {
                if self.case_insensitive {
                    s.to_lowercase()
                } else {
                    s.to_string()
                }
            })
            .collect();
        // A trailing slash produces a phantom empty segment; ignore it so
        // "/v1/messages/" matches "/v1/messages".
        if cand.len() > 1 && cand.last().is_some_and(|s| s.is_empty()) {
            cand.pop();
        }
        let refs: Vec<&str> = cand.iter().map(String::as_str).collect();
        match_segs(&self.segs, &refs)
    }

    /// The original-style pattern shape is not retained; this reports whether
    /// the pattern was compiled case-insensitively (host globs).
    pub fn is_case_insensitive(&self) -> bool {
        self.case_insensitive
    }
}

/// Recursive segment matcher. `**` backtracks over every possible segment
/// count; sizes are tiny so plain recursion is fine.
fn match_segs(pat: &[PatternSeg], s: &[&str]) -> bool {
    match pat.split_first() {
        None => s.is_empty(),
        Some((PatternSeg::StarStar, rest)) => {
            let mut k = 0;
            loop {
                if match_segs(rest, &s[k..]) {
                    return true;
                }
                if k == s.len() {
                    return false;
                }
                k += 1;
            }
        }
        Some((PatternSeg::Wild(parts), rest)) => {
            !s.is_empty() && wildcard_within(parts, s[0]) && match_segs(rest, &s[1..])
        }
    }
}

/// Match one segment against its literal chunks joined by `*`.
///
/// Anchoring rules (security bar for host globs): the FIRST chunk is
/// anchored at the start of the segment, the LAST chunk is anchored at the
/// end, and middle chunks appear in order between them. A single-chunk
/// segment must match exactly. This blocks suffix-spoofing bypasses such as
/// `*.internal.example.com` matching `evil.internal.example.com.attacker.test`
/// or `exact.host` matching `exact.host.evil.com`.
fn wildcard_within(parts: &[String], seg: &str) -> bool {
    let Some((first, rest)) = parts.split_first() else {
        return true;
    };
    let Some((last, middles)) = rest.split_last() else {
        // No wildcard in this segment: exact match required.
        return seg == first;
    };
    let Some(tail) = seg.strip_prefix(first.as_str()) else {
        return false;
    };
    let Some(head) = tail.strip_suffix(last.as_str()) else {
        return false;
    };
    let mut pos = head;
    for part in middles {
        match pos.find(part.as_str()) {
            Some(idx) => pos = &pos[idx + part.len()..],
            None => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Request predicates
// ---------------------------------------------------------------------------

/// A single request-matching predicate. All predicates on a rule are ANDed.
#[derive(Debug, Clone)]
pub enum RequestPredicate {
    /// HTTP method equality (case-insensitive).
    MethodEquals(String),
    /// Exact path equality (no query string).
    ExactPath(String),
    /// Glob path match via the crate-wide `GlobPattern` (AMEND-1).
    GlobPath(GlobPattern),
    /// Regular-expression path match.
    RegexPath(regex::Regex),
    /// Header present (name compared case-insensitively).
    HeaderExists { name: String },
    /// Header value equality — matches when ANY recorded value for the
    /// header equals `value` (name compared case-insensitively).
    HeaderEquals { name: String, value: String },
    /// Query parameter equality — first value for `name` must equal `value`.
    QueryEquals { name: String, value: String },
    /// RFC 6901 JSON pointer into the request body must resolve and equal
    /// `value`. Bodies that fail to parse as JSON never match.
    JsonPathEquals {
        pointer: String,
        value: serde_json::Value,
    },
    /// Body contains the given substring (bytes; use lossy text for text
    /// bodies). Empty substring always matches.
    BodyContains(String),
}

impl RequestPredicate {
    /// Specificity weight used by strongest-match selection. Higher = more
    /// specific. Exact anchors outrank regex, regex outranks glob, structural
    /// predicates (JSON path) outrank loose ones (header exists).
    pub fn weight(&self) -> u64 {
        match self {
            RequestPredicate::ExactPath(_) => 100,
            RequestPredicate::RegexPath(_) => 60,
            RequestPredicate::JsonPathEquals { .. } => 50,
            RequestPredicate::GlobPath(_) => 40,
            RequestPredicate::BodyContains(_) => 30,
            RequestPredicate::HeaderEquals { .. } | RequestPredicate::QueryEquals { .. } => 25,
            RequestPredicate::HeaderExists { .. } => 15,
            RequestPredicate::MethodEquals(_) => 10,
        }
    }

    /// Evaluate this predicate against a decomposed request.
    pub fn matches(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        headers: &HeaderMapValues,
        body: &[u8],
    ) -> bool {
        match self {
            RequestPredicate::MethodEquals(want) => method.eq_ignore_ascii_case(want),
            RequestPredicate::ExactPath(want) => path == want,
            RequestPredicate::GlobPath(glob) => glob.is_match(path),
            RequestPredicate::RegexPath(re) => re.is_match(path),
            RequestPredicate::HeaderExists { name } => header_values(headers, name).is_some(),
            RequestPredicate::HeaderEquals { name, value } => {
                header_values(headers, name).is_some_and(|vals| vals.iter().any(|v| v == value))
            }
            RequestPredicate::QueryEquals { name, value } => {
                query.iter().any(|(k, v)| k == name && v == value)
            }
            RequestPredicate::JsonPathEquals { pointer, value } => {
                match serde_json::from_slice::<serde_json::Value>(body) {
                    Ok(doc) => doc.pointer(pointer).is_some_and(|found| found == value),
                    Err(_) => false,
                }
            }
            RequestPredicate::BodyContains(needle) => {
                needle.is_empty()
                    || body
                        .windows(needle.len().max(1))
                        .any(|w| w == needle.as_bytes())
            }
        }
    }
}

/// Case-insensitive header lookup. `headers` keys are expected lowercase
/// (the server normalizes once per request).
fn header_values<'a>(headers: &'a HeaderMapValues, name: &str) -> Option<&'a Vec<String>> {
    headers.get(&name.to_ascii_lowercase())
}

// ---------------------------------------------------------------------------
// Rules and selection
// ---------------------------------------------------------------------------

/// A named matching rule: conjunction of predicates plus a user priority.
/// Higher `priority` wins in strongest-match mode regardless of specificity.
#[derive(Debug, Clone, Default)]
pub struct MatchRule {
    pub predicates: Vec<RequestPredicate>,
    pub priority: i64,
}

impl MatchRule {
    pub fn new(predicates: Vec<RequestPredicate>) -> Self {
        MatchRule {
            predicates,
            priority: 0,
        }
    }

    pub fn with_priority(mut self, priority: i64) -> Self {
        self.priority = priority;
        self
    }

    /// Sum of predicate weights — the rule's structural specificity.
    pub fn specificity(&self) -> u64 {
        self.predicates.iter().map(RequestPredicate::weight).sum()
    }

    /// True when every predicate holds.
    pub fn evaluate(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        headers: &HeaderMapValues,
        body: &[u8],
    ) -> bool {
        self.predicates
            .iter()
            .all(|p| p.matches(method, path, query, headers, body))
    }
}

/// Deterministic strongest-match selection: highest priority, then highest
/// specificity, then lowest insertion index. Returns the winning index.
pub fn choose_strongest(
    rules: &[MatchRule],
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &HeaderMapValues,
    body: &[u8],
) -> Option<usize> {
    choose_strongest_refs(
        &rules.iter().collect::<Vec<_>>(),
        method,
        path,
        query,
        headers,
        body,
    )
}

/// First-match-wins selection in insertion order. Returns the winning index.
pub fn choose_first(
    rules: &[MatchRule],
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &HeaderMapValues,
    body: &[u8],
) -> Option<usize> {
    choose_first_refs(
        &rules.iter().collect::<Vec<_>>(),
        method,
        path,
        query,
        headers,
        body,
    )
}

/// Reference-slice variant of [`choose_strongest`] (avoids cloning rules
/// when the caller keeps them in a larger struct).
pub fn choose_strongest_refs(
    rules: &[&MatchRule],
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &HeaderMapValues,
    body: &[u8],
) -> Option<usize> {
    let mut best: Option<(i64, u64, usize)> = None;
    for (idx, rule) in rules.iter().enumerate() {
        if !rule.evaluate(method, path, query, headers, body) {
            continue;
        }
        let key = (rule.priority, rule.specificity(), idx);
        let better = match best {
            None => true,
            Some(cur) => {
                key.0 > cur.0
                    || (key.0 == cur.0 && (key.1 > cur.1 || (key.1 == cur.1 && key.2 < cur.2)))
            }
        };
        if better {
            best = Some(key);
        }
    }
    best.map(|(_, _, idx)| idx)
}

/// Reference-slice variant of [`choose_first`].
pub fn choose_first_refs(
    rules: &[&MatchRule],
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &HeaderMapValues,
    body: &[u8],
) -> Option<usize> {
    rules
        .iter()
        .position(|rule| rule.evaluate(method, path, query, headers, body))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMapValues {
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in pairs {
            m.entry(k.to_string()).or_default().push(v.to_string());
        }
        m
    }

    fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn ok(pat: &str, cand: &str) -> bool {
        compile_glob(pat).expect("valid glob").is_match(cand)
    }

    #[test]
    fn glob_semantics_table() {
        assert!(!ok("/v1/*/messages", "/v1/abc/extra/messages"));
        // Trailing slash is trimmed ("/v1/" == "/v1"); an explicit empty
        // segment ("/v1//") is what `*` matches against.
        assert!(!ok("/v1/*", "/v1/"));
        assert!(ok("/v1/*", "/v1//"));
        assert!(!ok("/v1/*", "/v1/a/b"));
        // `**` crosses segments, including zero.
        assert!(ok("/v1/**/messages", "/v1/messages"));
        assert!(ok("/v1/**/messages", "/v1/a/b/c/messages"));
        assert!(ok("/**", "/anything/at/all"));
        assert!(!ok("/v1/**", "/v2/x"));
        // Intra-segment wildcards: `*` is segment-scoped only — it matches
        // ANY characters within the segment (including dots) and never
        // crosses '/'.
        assert!(ok("*.example.com", "api.example.com"));
        assert!(ok("*.example.com", "a.b.example.com"));
        assert!(!ok("*.example.com", "other.com"));
        assert!(!ok("*.example.com", "api.example.com/x"));
        assert!(!ok("/files/*.json", "/files/report.json.bak"));
        // Literal.
        assert!(ok("/v1/messages", "/v1/messages"));
        assert!(!ok("/v1/messages", "/v1/messages/x"));
        // Empty pattern is an error, not a panic.
        assert!(compile_glob("").is_err());
    }

    #[test]
    fn host_glob_suffix_spoofing_is_blocked() {
        // Regression pair (Main directive): unanchored tails previously let
        // attacker-controlled suffixes slip past host allowlists.
        assert!(!ok(
            "*.internal.example.com",
            "evil.internal.example.com.attacker.test"
        ));
        assert!(!ok("exact.host", "exact.host.evil.com"));
        // Legitimate matches still work.
        assert!(ok("*.internal.example.com", "svc.internal.example.com"));
        assert!(ok("exact.host", "exact.host"));
        // Case-insensitive host compile keeps the same anchoring.
        let g = compile_host_glob("*.Internal.Example.COM").expect("host glob");
        assert!(g.is_match("svc.internal.example.com"));
        assert!(!g.is_match("svc.internal.example.com.attacker.test"));
    }

    #[test]
    fn host_glob_is_case_insensitive() {
        let g = compile_host_glob("*.Example.COM").expect("host glob");
        assert!(g.is_match("api.example.com"));
        assert!(g.is_match("API.EXAMPLE.COM"));
        assert!(!g.is_match("example.com"));
        // Path globs stay case-sensitive.
        let p = compile_glob("/V1/Messages").expect("path glob");
        assert!(!p.is_match("/v1/messages"));
    }

    fn rule(preds: Vec<RequestPredicate>, priority: i64) -> MatchRule {
        MatchRule::new(preds).with_priority(priority)
    }

    #[test]
    fn strongest_beats_first_on_specificity() {
        let rules = vec![
            rule(
                vec![
                    RequestPredicate::ExactPath("/v1/messages".into()),
                    RequestPredicate::HeaderExists {
                        name: "x-beta".into(),
                    },
                ],
                0,
            ),
            rule(vec![RequestPredicate::ExactPath("/v1/messages".into())], 0),
        ];
        let hdrs = headers(&[("x-beta", "1")]);
        let body = br#"{"a":1}"#;
        let strongest = choose_strongest(&rules, "POST", "/v1/messages", &[], &hdrs, body);
        let first = choose_first(&rules, "POST", "/v1/messages", &[], &hdrs, body);
        assert_eq!(
            strongest,
            Some(0),
            "more specific rule wins in strongest mode"
        );
        assert_eq!(first, Some(0), "first mode keeps insertion order");
        assert_eq!(rules[0].specificity(), 115);
        assert_eq!(rules[1].specificity(), 100);
    }

    #[test]
    fn priority_outranks_specificity_and_ties_break_by_insertion() {
        let rules = vec![
            rule(vec![RequestPredicate::ExactPath("/x".into())], 5),
            rule(
                vec![
                    RequestPredicate::ExactPath("/x".into()),
                    RequestPredicate::HeaderExists { name: "a".into() },
                ],
                0,
            ),
            rule(
                vec![RequestPredicate::GlobPath(
                    compile_glob("/x*").expect("glob"),
                )],
                0,
            ),
            rule(vec![RequestPredicate::ExactPath("/x".into())], 0),
        ];
        // Priority 5 wins over higher specificity.
        assert_eq!(
            choose_strongest(&rules, "GET", "/x", &[], &headers(&[]), b""),
            Some(0)
        );
        // Equal priority + specificity: lowest index wins, deterministically.
        let ties = vec![
            rule(
                vec![RequestPredicate::GlobPath(
                    compile_glob("/y/*").expect("glob"),
                )],
                0,
            ),
            rule(
                vec![RequestPredicate::GlobPath(
                    compile_glob("/y/*").expect("glob"),
                )],
                0,
            ),
        ];
        assert_eq!(
            choose_strongest(&ties, "GET", "/y/z", &[], &headers(&[]), b""),
            Some(0)
        );
        // Same input, same answer — determinism.
        for _ in 0..5 {
            assert_eq!(
                choose_strongest(&rules, "GET", "/x", &[], &headers(&[]), b""),
                Some(0)
            );
        }
    }

    #[test]
    fn predicate_matrix() {
        let hdrs = headers(&[
            ("content-type", "application/json"),
            ("x-multi", "one"),
            ("x-multi", "two"),
        ]);
        let query = q(&[("model", "claude"), ("flag", "")]);
        let body = br#"{"model":"claude-3","n":1}"#;

        assert!(RequestPredicate::MethodEquals("post".into())
            .matches("POST", "/p", &query, &hdrs, body));
        assert!(
            !RequestPredicate::ExactPath("/p".into()).matches("GET", "/p/x", &query, &hdrs, body)
        );
        assert!(RequestPredicate::HeaderExists {
            name: "Content-Type".into()
        }
        .matches("GET", "/p", &query, &hdrs, body));
        assert!(RequestPredicate::HeaderEquals {
            name: "CONTENT-TYPE".into(),
            value: "application/json".into()
        }
        .matches("GET", "/p", &query, &hdrs, body));
        assert!(RequestPredicate::QueryEquals {
            name: "model".into(),
            value: "claude".into()
        }
        .matches("GET", "/p", &query, &hdrs, body));
        assert!(!RequestPredicate::QueryEquals {
            name: "missing".into(),
            value: "".into()
        }
        .matches("GET", "/p", &query, &hdrs, body));
        assert!(RequestPredicate::JsonPathEquals {
            pointer: "/model".into(),
            value: serde_json::json!("claude-3"),
        }
        .matches("GET", "/p", &query, &hdrs, body));
        assert!(!RequestPredicate::JsonPathEquals {
            pointer: "/model".into(),
            value: serde_json::json!("other"),
        }
        .matches("GET", "/p", &query, &hdrs, body));
        assert!(!RequestPredicate::JsonPathEquals {
            pointer: "/model".into(),
            value: serde_json::json!("x"),
        }
        .matches("GET", "/p", &query, &hdrs, b"not json"));
        assert!(RequestPredicate::BodyContains("claude-3".into())
            .matches("GET", "/p", &query, &hdrs, body));
        assert!(!RequestPredicate::BodyContains("nope".into())
            .matches("GET", "/p", &query, &hdrs, body));
        assert!(
            RequestPredicate::RegexPath(regex::Regex::new(r"^/v\d+/m$").expect("re"))
                .matches("GET", "/v1/m", &query, &hdrs, body)
        );
    }

    #[test]
    fn invalid_glob_is_error_not_panic() {
        assert!(compile_glob("").is_err());
        assert!(compile_host_glob("").is_err());
    }
}
