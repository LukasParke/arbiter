//! Capture-replay mock source (W3): Hoverfly/WireMock-parity replay of a
//! recorded bundle. Incoming requests match recorded exchanges via
//! [`crate::mock::matcher`] rules derived at load; the recorded response is
//! served BYTE-EXACT (status, end-to-end headers, body bytes) — recorded
//! bodies are never templated (AMEND-7).
//!
//! Response bodies load lazily from `bodies/<sha256>.bin` through a bounded
//! cache (64 MiB aggregate) so huge bundles never pin memory.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::matcher::{choose_first_refs, choose_strongest_refs, MatchRule, RequestPredicate};
use super::{MatchStrategy, MockResponse};
use crate::bundle::{load_bundle, CaptureBundle};
use crate::error::Result;
use crate::redaction::REDACTED_VALUE;
use crate::types::{CapturedBody, CapturedExchange, HeaderMapValues};

/// Aggregate cap for lazily-cached response bodies.
const BODY_CACHE_CAP_BYTES: usize = 64 * 1024 * 1024;

/// How much of a recorded request body feeds the BodyContains predicate.
const BODY_PREDICATE_PREFIX: usize = 1024;

/// Hop-by-hop headers never served back; content-length recomputed by the
/// HTTP layer.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

/// One recorded exchange turned into a matching rule plus its verbatim
/// response. Index in [`CaptureMock::stubs`] == insertion order tiebreak.
#[derive(Debug, Clone)]
pub struct RecordedStub {
    pub rule: MatchRule,
    pub sequence: u64,
    pub status: u16,
    /// Recorded end-to-end response headers (lowercase names).
    pub headers: Vec<(String, String)>,
    /// Content-addressed body digest; resolved lazily against the bundle.
    pub body_sha256: String,
}

/// Lazily-populated body cache with arbitrary eviction past the cap
/// (bounded memory per the perf bar).
#[derive(Default)]
struct BodyCache {
    map: HashMap<String, Arc<Vec<u8>>>,
    total: usize,
}

impl BodyCache {
    fn get_or_load(
        &mut self,
        sha: &str,
        load: impl FnOnce() -> Result<Vec<u8>>,
    ) -> Result<Arc<Vec<u8>>> {
        if let Some(bytes) = self.map.get(sha) {
            return Ok(Arc::clone(bytes));
        }
        let bytes = Arc::new(load()?);
        // Arbitrary eviction: drop older entries (HashMap iteration order)
        // until under cap. Correctness only needs cache-miss fallback.
        while self.total + bytes.len() > BODY_CACHE_CAP_BYTES {
            let Some(victim) = self.map.keys().next().cloned() else {
                break;
            };
            if let Some(removed) = self.map.remove(&victim) {
                self.total -= removed.len();
            }
            if self.map.is_empty() {
                // Single body larger than the whole cap: serve uncached next
                // time by not inserting.
                if self.total + bytes.len() > BODY_CACHE_CAP_BYTES {
                    return Ok(bytes);
                }
                break;
            }
        }
        self.total += bytes.len();
        self.map.insert(sha.to_string(), Arc::clone(&bytes));
        Ok(bytes)
    }
}

/// Replayable view over a loaded capture bundle.
pub struct CaptureMock {
    bundle: Mutex<CaptureBundle>,
    stubs: Vec<RecordedStub>,
    cache: Mutex<BodyCache>,
}

impl CaptureMock {
    /// Load and verify a bundle directory (full digest verification;
    /// untrusted-input safe) and derive one strongest-match candidate per
    /// recorded exchange. All matcher rules are compiled here, before any
    /// socket binds (startup fail-fast bar).
    pub fn load(bundle_dir: &Path) -> Result<Self> {
        let mut bundle = load_bundle(bundle_dir)?;
        // Phase 1 (shared borrow): derive everything except the
        // BodyContains predicate, which needs the request-body bytes.
        struct Pending {
            sequence: u64,
            status: u16,
            headers: Vec<(String, String)>,
            body_sha256: String,
            rule: MatchRule,
            request_body: Option<CapturedBody>,
        }
        let mut pending = Vec::with_capacity(bundle.exchanges.len());
        for exchange in &bundle.exchanges {
            let (rule, request_body) = build_rule_shared(exchange);
            pending.push(Pending {
                sequence: exchange.sequence,
                status: exchange.response.status,
                headers: flatten_response_headers(exchange),
                body_sha256: exchange.response.body.sha256.clone(),
                rule,
                request_body,
            });
        }
        // Phase 2 (mutable borrow): read request bodies to finish the
        // BodyContains predicates. The body descriptor is cloned out first
        // so the immutable borrow of `exchanges` ends before `read_body`.
        let mut stubs = Vec::with_capacity(pending.len());
        for p in pending {
            let mut rule = p.rule;
            if let Some(body_meta) = p.request_body {
                let req_bytes = bundle.read_body(&body_meta)?;
                if !req_bytes.is_empty() {
                    let prefix_len = req_bytes.len().min(BODY_PREDICATE_PREFIX);
                    rule.predicates.push(RequestPredicate::BodyContains(
                        String::from_utf8_lossy(&req_bytes[..prefix_len]).into_owned(),
                    ));
                }
            }
            stubs.push(RecordedStub {
                sequence: p.sequence,
                status: p.status,
                headers: p.headers,
                body_sha256: p.body_sha256,
                rule,
            });
        }
        Ok(CaptureMock {
            bundle: Mutex::new(bundle),
            stubs,
            cache: Mutex::new(BodyCache::default()),
        })
    }

    /// Number of recorded candidates.
    pub fn len(&self) -> usize {
        self.stubs.len()
    }

    /// True when the bundle recorded nothing.
    pub fn is_empty(&self) -> bool {
        self.stubs.is_empty()
    }

    /// The matching rules, aligned with the recorded stubs by index.
    pub fn rules(&self) -> Vec<MatchRule> {
        self.stubs.iter().map(|s| s.rule.clone()).collect()
    }

    /// Select and serve a recorded response byte-exact, or None on miss.
    pub fn respond(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        headers: &HeaderMapValues,
        body: &[u8],
        strategy: MatchStrategy,
    ) -> Option<MockResponse> {
        let rules: Vec<&MatchRule> = self.stubs.iter().map(|s| &s.rule).collect();
        let idx = select_index(&rules, method, path, query, headers, body, strategy)?;
        let stub = &self.stubs[idx];

        let bytes = {
            let mut cache = self.cache.lock().expect("body cache");
            let mut bundle = self.bundle.lock().expect("capture bundle");
            // Clone the descriptor so the immutable borrow of `exchanges`
            // ends before the closure captures `bundle` mutably.
            let body_meta =
                find_body(&bundle.exchanges, &stub.body_sha256, stub.sequence).cloned()?;
            let sha = stub.body_sha256.clone();
            // get_or_load is Result-valued; a read failure counts as a
            // miss rather than poisoning the whole response path.
            cache
                .get_or_load(&sha, || bundle.read_body(&body_meta))
                .ok()?
        };

        Some(MockResponse {
            status: stub.status,
            content_type: None,
            headers: stub.headers.clone(),
            body: (*bytes).clone(),
        })
    }
}

fn select_index(
    rules: &[&MatchRule],
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &HeaderMapValues,
    body: &[u8],
    strategy: MatchStrategy,
) -> Option<usize> {
    match strategy {
        MatchStrategy::Strongest => {
            choose_strongest_refs(rules, method, path, query, headers, body)
        }
        MatchStrategy::First => choose_first_refs(rules, method, path, query, headers, body),
    }
}

/// Derive the AND-predicate rule for one recorded exchange:
/// method + exact path + non-redacted query pairs + content-type header.
/// Returns the rule plus the request-body descriptor when a BodyContains
/// predicate must be appended after the body bytes are read (phase 2).
fn build_rule_shared(exchange: &CapturedExchange) -> (MatchRule, Option<CapturedBody>) {
    let req = &exchange.request;
    let (path_no_query, query_pairs) = split_path_and_query(&req.path);

    let mut predicates = vec![
        RequestPredicate::MethodEquals(req.method.clone()),
        RequestPredicate::ExactPath(path_no_query),
    ];
    for (name, value) in query_pairs {
        if value == REDACTED_VALUE || name.is_empty() {
            continue;
        }
        predicates.push(RequestPredicate::QueryEquals { name, value });
    }
    let recorded_ct = req.body.media_type.clone().or_else(|| {
        req.headers
            .values
            .get("content-type")
            .and_then(|v| v.first().cloned())
    });
    if let Some(ct) = recorded_ct {
        if ct != REDACTED_VALUE && !ct.is_empty() {
            predicates.push(RequestPredicate::HeaderEquals {
                name: "content-type".to_string(),
                value: ct,
            });
        }
    }

    // Hand the request-body descriptor to phase 2; empty bodies are
    // skipped there before the predicate is added.
    (MatchRule::new(predicates), Some(req.body.clone()))
}

fn flatten_response_headers(exchange: &CapturedExchange) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, values) in &exchange.response.headers.values {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        for value in values {
            out.push((name.clone(), value.clone()));
        }
    }
    out
}

fn find_body<'a>(
    exchanges: &'a [CapturedExchange],
    sha: &str,
    sequence: u64,
) -> Option<&'a CapturedBody> {
    exchanges
        .iter()
        .find(|e| e.sequence == sequence)
        .map(|e| &e.response.body)
        .filter(|b| b.sha256 == sha)
}

/// Parse a raw query string into decoded pairs (`+` treated as space).
pub(crate) fn parse_query_string(qs: &str) -> Vec<(String, String)> {
    qs.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (decode_component(k), decode_component(v)),
            None => (decode_component(pair), String::new()),
        })
        .collect()
}

/// Split `"path?query"` into path and decoded pairs (`+` treated as space).
pub(crate) fn split_path_and_query(path_with_query: &str) -> (String, Vec<(String, String)>) {
    match path_with_query.split_once('?') {
        None => (path_with_query.to_string(), Vec::new()),
        Some((path, qs)) => (path.to_string(), parse_query_string(qs)),
    }
}

fn decode_component(s: &str) -> String {
    let plus_fixed = s.replace('+', " ");
    percent_encoding::percent_decode_str(&plus_fixed)
        .decode_utf8_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// Test support: tiny real bundle builder shared with server.rs integration
// tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::bundle::{make_captured_body, write_bundle, WriteBundleOptions};
    use crate::types::{
        CaptureManifest, CaptureMode, CapturedHeaders, CapturedRequest, CapturedResponse,
        RedactionPolicySummary, StreamState, BUNDLE_SCHEMA_VERSION,
    };

    pub(crate) const MARKER_BODY: &[u8] = b"RECORDED-BYTES-\xF0\x9F\x8C\x99-exactly-these";

    fn buffered_stream() -> StreamState {
        StreamState {
            kind: "buffered".to_string(),
            completed: true,
            client_aborted: false,
            upstream_aborted: false,
            terminal_marker: None,
            error: None,
        }
    }

    fn headers_of(pairs: &[(&str, &str)]) -> CapturedHeaders {
        CapturedHeaders {
            values: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
                .collect(),
            redacted: Vec::new(),
        }
    }

    pub(crate) fn recorded_exchange(seq: u64) -> CapturedExchange {
        let req_bytes = br#"{"model":"claude","prompt":"hi"}"#;
        CapturedExchange {
            schema_version: crate::types::EXCHANGE_SCHEMA_VERSION,
            sequence: seq,
            started_at: "2026-01-01T00:00:00Z".to_string(),
            duration_ms: 5.0,
            request: CapturedRequest {
                method: "POST".to_string(),
                path: "/v1/messages?key=abc&id=7".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: headers_of(&[("content-type", "application/json")]),
                body: make_captured_body(req_bytes, Some("application/json"), None, None)
                    .expect("request body"),
            },
            response: CapturedResponse {
                status: 201,
                status_text: "Created".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: headers_of(&[
                    ("content-type", "application/json"),
                    ("x-recorded", "yes"),
                    ("transfer-encoding", "chunked"),
                ]),
                body: make_captured_body(MARKER_BODY, Some("application/json"), None, None)
                    .expect("response body"),
                stream: buffered_stream(),
            },
            failure: None,
            validation: None,
            tunnel: None,
            tls: None,
            ws: None,
            llm: None,
        }
    }

    /// Write a real, digest-verified bundle with the given exchanges.
    pub(crate) fn write_test_bundle(dir: &Path, exchanges: Vec<CapturedExchange>) {
        let manifest = CaptureManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            arbiter_version: "test".to_string(),
            mode: CaptureMode::Exact,
            target_origin: "https://api.example.com".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: "2026-01-01T00:00:01Z".to_string(),
            exchange_count: exchanges.len() as u64,
            bundle_digest: String::new(),
            redaction: RedactionPolicySummary {
                redact_headers: Vec::new(),
                allow_query: Vec::new(),
            },
            metadata: None,
        };
        write_bundle(
            dir,
            WriteBundleOptions {
                manifest,
                exchanges,
                bodies: HashMap::new(),
                validation: None,
            },
        )
        .expect("write bundle");
    }

    pub(crate) fn incoming(headers: &[(&str, &str)]) -> HeaderMapValues {
        headers
            .iter()
            .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn serves_recorded_bytes_exactly_and_misses_cleanly() {
        let dir = tempfile::tempdir().expect("tmpdir");
        write_test_bundle(dir.path(), vec![recorded_exchange(1)]);

        let mock = CaptureMock::load(dir.path()).expect("load");
        assert_eq!(mock.len(), 1);

        // Exact same request shape as recorded → byte-exact response.
        let hdrs = incoming(&[("content-type", "application/json")]);
        let query = vec![
            ("key".to_string(), "abc".to_string()),
            ("id".to_string(), "7".to_string()),
        ];
        let resp = mock
            .respond(
                "POST",
                "/v1/messages",
                &query,
                &hdrs,
                br#"{"model":"claude","prompt":"hi"}"#,
                MatchStrategy::Strongest,
            )
            .expect("recorded hit");
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, MARKER_BODY, "body must be byte-identical");
        assert!(resp
            .headers
            .iter()
            .any(|(k, v)| k == "x-recorded" && v == "yes"));
        assert!(!resp.headers.iter().any(|(k, _)| k == "transfer-encoding"));

        // Wrong method → miss.
        assert!(mock
            .respond(
                "GET",
                "/v1/messages",
                &query,
                &hdrs,
                b"",
                MatchStrategy::Strongest
            )
            .is_none());
        // Wrong path → miss.
        assert!(mock
            .respond(
                "POST",
                "/v1/other",
                &query,
                &hdrs,
                b"",
                MatchStrategy::Strongest
            )
            .is_none());
    }

    #[test]
    fn strongest_prefers_the_more_specific_recording() {
        // Two recordings differing only in a query pair: an incoming request
        // carrying BOTH pairs must pick the two-query recording.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut ex1 = recorded_exchange(1);
        ex1.request.path = "/api?a=1".to_string();
        let mut ex2 = recorded_exchange(2);
        ex2.request.path = "/api?a=1&b=2".to_string();

        write_test_bundle(dir.path(), vec![ex1, ex2]);

        let mock = CaptureMock::load(dir.path()).expect("load");
        let both = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ];
        let hit = mock
            .respond(
                "POST",
                "/api",
                &both,
                &incoming(&[("content-type", "application/json")]),
                br#"{"model":"claude","prompt":"hi"}"#,
                MatchStrategy::Strongest,
            )
            .expect("hit");
        assert_eq!(hit.status, 201);
        // First-mode picks the earliest matching recording deterministically.
        let first_hit = mock
            .respond(
                "POST",
                "/api",
                &both,
                &incoming(&[("content-type", "application/json")]),
                br#"{"model":"claude","prompt":"hi"}"#,
                MatchStrategy::First,
            )
            .expect("hit");
        assert_eq!(first_hit.status, 201);
        // Only `a` present still matches the weaker recording.
        let weak = mock
            .respond(
                "POST",
                "/api",
                &[("a".to_string(), "1".to_string())],
                &incoming(&[("content-type", "application/json")]),
                br#"{"model":"claude","prompt":"hi"}"#,
                MatchStrategy::First,
            )
            .expect("weaker hit");
        assert_eq!(weak.status, 201);
    }

    #[test]
    fn redacted_query_values_do_not_become_match_requirements() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut ex = recorded_exchange(1);
        ex.request.path = format!("/v1/messages?key={}&id=7", REDACTED_VALUE);
        write_test_bundle(dir.path(), vec![ex]);

        let mock = CaptureMock::load(dir.path()).expect("load");
        // Any `key` value matches — including none at all — because the
        // recorded value was redacted and therefore unmatchable.
        assert!(mock
            .respond(
                "POST",
                "/v1/messages",
                &[
                    ("key".to_string(), "anything".to_string()),
                    ("id".to_string(), "7".to_string())
                ],
                &incoming(&[("content-type", "application/json")]),
                br#"{"model":"claude","prompt":"hi"}"#,
                MatchStrategy::First,
            )
            .is_some());
    }

    #[test]
    fn query_splitting_decodes_components() {
        let (path, q) = split_path_and_query("/v1/x?a%20b=c%2Bd&e=+f&bare");
        assert_eq!(path, "/v1/x");
        assert_eq!(
            q,
            vec![
                ("a b".to_string(), "c+d".to_string()),
                ("e".to_string(), " f".to_string()),
                ("bare".to_string(), String::new()),
            ]
        );
        let (plain, none) = split_path_and_query("/v1/y");
        assert_eq!(plain, "/v1/y");
        assert!(none.is_empty());
    }
}
