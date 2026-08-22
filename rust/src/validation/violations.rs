//! Violation collection, shutdown reporting, and live-validation plumbing for
//! proxy mode (`arbiter start --validate-spec …`, AMEND-14).
//!
//! Three surfaces live here:
//! - [`ViolationsCollector`]: thread-safe store of violations keyed by exchange
//!   sequence, fed from the proxy pipeline and drained into `/__violations`,
//!   TUI panels, and the shutdown `--report` file.
//! - [`LiveValidator`]: wraps [`BasicOpenApiValidator`] behind the
//!   part-shaped calls the proxy pipeline makes (`method/path/query/headers/
//!   body`), compiled once from the spec before sockets bind.
//! - [`ValidateFlags`] / [`exit_code`]: the typed CLI surface cli-dx flattens
//!   into the start command (AMEND-11) plus the `--fail-on-violation` exit
//!   semantics.
//!
//! Report files are deterministic: canonical JSON (sorted keys, compact) with
//! camelCase field names, written atomically (temp file + rename).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::validation::{load_spec_document, BasicOpenApiValidator, Violation};
use chrono::{SecondsFormat, Utc};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::types::HeaderMapValues;

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

/// Thread-safe accumulation of violations keyed by exchange sequence.
///
/// The proxy pipeline records each exchange's violations once its response
/// completes; any number of worker tasks may share one collector.
pub struct ViolationsCollector {
    /// One entry per exchange sequence that produced violations, in first
    /// recorded order. Re-recording an already-present sequence appends to
    /// that entry instead of creating a duplicate.
    entries: Mutex<Vec<(u64, Vec<Violation>)>>,
}

impl Default for ViolationsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ViolationsCollector {
    pub fn new() -> Self {
        ViolationsCollector {
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Record `violations` against exchange sequence `seq`. Empty lists are
    /// ignored so `exchangesWithViolations` counts only real offenders.
    pub fn record(&self, seq: u64, violations: Vec<Violation>) {
        if violations.is_empty() {
            return;
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.iter_mut().find(|(s, _)| *s == seq) {
            Some((_, existing)) => existing.extend(violations),
            None => entries.push((seq, violations)),
        }
    }

    /// Consistent copy of all recorded violations ordered by sequence.
    pub fn snapshot(&self) -> Vec<(u64, Vec<Violation>)> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        entries.sort_by_key(|(seq, _)| *seq);
        entries
    }

    /// Aggregate counts over the current snapshot.
    pub fn summary(&self) -> ViolationsSummary {
        let mut summary = ViolationsSummary {
            total: 0,
            by_keyword: BTreeMap::new(),
            by_severity: BTreeMap::new(),
        };
        for (_, violations) in self.snapshot() {
            for violation in &violations {
                summary.total += 1;
                *summary
                    .by_keyword
                    .entry(violation.keyword.clone())
                    .or_insert(0) += 1;
                *summary
                    .by_severity
                    .entry(violation.severity.clone())
                    .or_insert(0) += 1;
            }
        }
        summary
    }

    /// Write the shutdown `--report` JSON file atomically.
    ///
    /// Synchronous by design: callers invoke this during process shutdown
    /// (wrap in `tokio::task::spawn_blocking` when driving from an async
    /// context).
    pub fn shutdown_report(&self, path: &Path) -> Result<()> {
        let snapshot = self.snapshot();
        let generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let document = report_value(&snapshot, &generated_at);
        let rendered = crate::json::stable_stringify(&document);
        write_file_atomic(path, rendered.as_bytes())
    }
}

/// Aggregated violation counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationsSummary {
    pub total: usize,
    pub by_keyword: BTreeMap<String, usize>,
    pub by_severity: BTreeMap<String, usize>,
}

/// Build the report envelope. Split from [`ViolationsCollector::
/// shutdown_report`] so tests can pin the exact wire shape with a fixed
/// timestamp.
fn report_value(snapshot: &[(u64, Vec<Violation>)], generated_at: &str) -> Value {
    let mut violations = Vec::new();
    let mut total = 0usize;
    for (seq, seq_violations) in snapshot {
        for violation in seq_violations {
            total += 1;
            violations.push(json!({
                "sequence": seq,
                "path": violation.path,
                "keyword": violation.keyword,
                "severity": violation.severity,
                "message": violation.message,
            }));
        }
    }
    json!({
        "generatedAt": generated_at,
        "totalViolations": total,
        "exchangesWithViolations": snapshot.len(),
        "violations": violations,
    })
}

/// Atomic private-permission file write: temp sibling + rename. Mirrors
/// `bundle::store::write_file_atomic`, kept local because that helper is
/// module-private and cross-module imports of private fns are prohibited.
fn write_file_atomic(file_path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let file_path = file_path.as_ref();
    let tmp = file_path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| Error::io("atomic create", e))?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io("atomic chmod", e))?;
        f.write_all(data)
            .map_err(|e| Error::io("atomic write", e))?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, file_path).map_err(|e| Error::io("atomic rename", e))
}

// ---------------------------------------------------------------------------
// Live validation plumbing for M3 wiring
// ---------------------------------------------------------------------------

/// Per-exchange validator wired into the proxy pipeline at M3 assembly.
///
/// Compile once at startup ([`LiveValidator::load`] keeps the YAML/JSON parse
/// off async workers) and share across pipeline stages. Request/response
/// pairing is keyed by exchange sequence, so interleaved exchanges validate
/// correctly under any concurrency: call
/// [`LiveValidator::validate_request_parts`] when the request enters the
/// pipeline and [`LiveValidator::validate_response_parts`] with the same
/// sequence when the response settles.
pub struct LiveValidator {
    pub collector: Arc<ViolationsCollector>,
    pub validator: Arc<BasicOpenApiValidator>,
    /// Request matches awaiting their paired response, keyed by exchange
    /// sequence. FIFO-evicted past [`MAX_PENDING_REQUESTS`] so a stream of
    /// never-settled requests cannot grow it without bound; a response whose
    /// request was evicted validates as unmatched (no violations), mirroring
    /// the TS unmatched-path behavior.
    pending: Mutex<PendingMatches>,
}

/// Pending-request cap. Generous against realistic in-flight exchange counts;
/// bounded so memory stays flat under pathological traffic.
const MAX_PENDING_REQUESTS: usize = 1024;

#[derive(Default)]
struct PendingMatches {
    map: HashMap<u64, (String, String)>,
    order: VecDeque<u64>,
}

impl PendingMatches {
    fn insert(&mut self, seq: u64, matched: (String, String)) {
        if self.map.insert(seq, matched).is_none() {
            self.order.push_back(seq);
        }
        while self.map.len() > MAX_PENDING_REQUESTS {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.map.remove(&oldest);
                }
                None => break,
            }
        }
    }

    fn take(&mut self, seq: u64) -> Option<(String, String)> {
        self.map.remove(&seq)
    }
}

impl LiveValidator {
    /// Compile from an already-parsed spec document.
    pub fn new(spec: Value) -> Self {
        LiveValidator {
            collector: Arc::new(ViolationsCollector::new()),
            validator: Arc::new(BasicOpenApiValidator::new(spec)),
            pending: Mutex::new(PendingMatches::default()),
        }
    }

    /// Load the spec through the single shared loader (AMEND-4). CPU-bound
    /// parse work runs on the blocking pool so startup stays responsive.
    pub async fn load(spec_path: &Path) -> Result<Self> {
        let path = spec_path.to_path_buf();
        let spec = tokio::task::spawn_blocking(move || load_spec_document(&path))
            .await
            .map_err(|e| Error::other(format!("join spec loader: {e}")))??;
        Ok(Self::new(spec))
    }

    /// Validate a request from its proxied parts and remember the spec match
    /// under `seq` for the paired response call. `path` excludes the query
    /// string; `query` is the raw query string without the leading `?`.
    pub fn validate_request_parts(
        &self,
        seq: u64,
        method: &str,
        path: &str,
        query: &str,
        headers: &HeaderMapValues,
        _body: Option<&[u8]>,
    ) -> Vec<Violation> {
        let path_with_query = if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{query}")
        };
        let (matched, violations) = self
            .validator
            .check_request(method, &path_with_query, headers);
        if let Some(matched) = matched {
            self.pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(seq, matched);
        }
        violations
    }

    /// Validate a response from its proxied parts using the match recorded by
    /// the paired request call for `seq`. Unknown/evicted sequences behave
    /// like the unmatched-path case: no violations. The pending entry is
    /// consumed here.
    pub fn validate_response_parts(
        &self,
        seq: u64,
        status: u16,
        headers: &HeaderMapValues,
        body: Option<&[u8]>,
    ) -> Vec<Violation> {
        let matched = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take(seq);
        match matched {
            Some((spec_path, method)) => self
                .validator
                .check_response(&spec_path, &method, status, headers, body),
            None => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// CLI surface for cli-dx assembly
// ---------------------------------------------------------------------------

/// Typed flag surface for live proxy validation, flattened into the start
/// command by cli-dx (AMEND-11): `--validate-spec/--report/--fail-on-violation`.
#[derive(Debug, Clone, Args)]
pub struct ValidateFlags {
    /// OpenAPI spec to validate proxied traffic against while capturing
    #[arg(long = "validate-spec", value_name = "SPEC")]
    pub validate_spec: Option<PathBuf>,

    /// Write the violations report JSON to this path on shutdown
    #[arg(long = "report", value_name = "PATH")]
    pub report: Option<PathBuf>,

    /// Exit nonzero when any violation was recorded
    #[arg(long = "fail-on-violation")]
    pub fail_on_violation: bool,
}

impl ValidateFlags {
    /// Flag values when validation is not requested.
    pub fn disabled() -> Self {
        ValidateFlags {
            validate_spec: None,
            report: None,
            fail_on_violation: false,
        }
    }

    /// Whether live validation should run at all.
    pub fn wants_validation(&self) -> bool {
        self.validate_spec.is_some()
    }

    /// Spec path passed to [`LiveValidator::load`], if requested.
    pub fn spec_path(&self) -> Option<&Path> {
        self.validate_spec.as_deref()
    }
}

/// Process exit code for a validation run: `0` when clean or when
/// `--fail-on-violation` is off; `1` when violations were recorded and
/// `--fail-on-violation` is on.
pub fn exit_code(summary: &ViolationsSummary, fail_on_violation: bool) -> i32 {
    if fail_on_violation && summary.total > 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn violation(path: &str, keyword: &str, severity: &str) -> Violation {
        Violation {
            path: path.to_string(),
            keyword: keyword.to_string(),
            message: format!("{keyword} at {path}"),
            severity: severity.to_string(),
        }
    }

    #[test]
    fn concurrent_recording_keeps_every_violation() {
        let collector = Arc::new(ViolationsCollector::new());
        let workers: Vec<std::thread::JoinHandle<()>> = (0..8)
            .map(|worker| {
                let collector = Arc::clone(&collector);
                std::thread::spawn(move || {
                    for step in 0..25u64 {
                        let seq = worker * 100 + step;
                        collector.record(
                            seq,
                            vec![
                                violation("/a", "unknown-path", "error"),
                                violation("/b", "schema-violation", "warning"),
                            ],
                        );
                        // Empty recordings must be ignored, not create entries.
                        collector.record(seq.wrapping_add(1000), Vec::new());
                    }
                })
            })
            .collect();
        for handle in workers {
            handle.join().expect("worker thread");
        }

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.len(), 8 * 25, "one entry per distinct sequence");
        let sequences: Vec<u64> = snapshot.iter().map(|(seq, _)| *seq).collect();
        let mut sorted = sequences.clone();
        sorted.sort_unstable();
        assert_eq!(sequences, sorted, "snapshot ordered by sequence");

        let summary = collector.summary();
        assert_eq!(summary.total, 8 * 25 * 2);
        assert_eq!(
            summary.by_keyword.get("unknown-path"),
            Some(&(8 * 25)),
            "re-recording the same sequence extends its entry"
        );
        assert_eq!(summary.by_severity.get("error"), Some(&(8 * 25)));
        assert_eq!(summary.by_severity.get("warning"), Some(&(8 * 25)));
    }

    #[test]
    fn report_is_stable_camel_case_json() {
        let collector = ViolationsCollector::new();
        collector.record(
            2,
            vec![violation("/v1/x", "missing-required-header", "error")],
        );
        collector.record(
            7,
            vec![violation("/v1/y", "status-not-documented", "error")],
        );

        let snapshot = collector.snapshot();
        let document = report_value(&snapshot, "2026-08-22T00:00:00.000Z");
        let rendered = crate::json::stable_stringify(&document);

        let expected = concat!(
            r#"{"exchangesWithViolations":2,"#,
            r#""generatedAt":"2026-08-22T00:00:00.000Z","#,
            r#""totalViolations":2,"violations":["#,
            r#"{"keyword":"missing-required-header","message":"missing-required-header at /v1/x","#,
            r#""path":"/v1/x","sequence":2,"severity":"error"},"#,
            r#"{"keyword":"status-not-documented","message":"status-not-documented at /v1/y","#,
            r#""path":"/v1/y","sequence":7,"severity":"error"}]}"#
        );
        assert_eq!(rendered, expected);

        // Round-trip sanity on the parsed shape.
        let parsed: Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(parsed["totalViolations"], json!(2));
        assert_eq!(parsed["violations"][0]["sequence"], json!(2));
    }

    #[test]
    fn shutdown_report_writes_file_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("violations-report.json");

        let collector = ViolationsCollector::new();
        collector.shutdown_report(&path).expect("empty report");
        let empty: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("JSON");
        assert_eq!(empty["totalViolations"], json!(0));
        assert_eq!(empty["violations"], json!([]));
        assert!(std::fs::metadata(dir.path().join("violations-report.tmp")).is_err());

        collector.record(1, vec![violation("/p", "unknown-path", "error")]);
        collector.shutdown_report(&path).expect("non-empty report");
        let content = std::fs::read_to_string(&path).expect("read");
        let parsed: Value = serde_json::from_str(&content).expect("JSON");
        assert_eq!(parsed["exchangesWithViolations"], json!(1));
        // Owner-only permissions, matching every other arbiter artifact write.
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).expect("stat").permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn exit_code_semantics() {
        let clean = ViolationsSummary {
            total: 0,
            by_keyword: BTreeMap::new(),
            by_severity: BTreeMap::new(),
        };
        let dirty = ViolationsSummary {
            total: 3,
            by_keyword: BTreeMap::from([("unknown-path".to_string(), 3)]),
            by_severity: BTreeMap::from([("error".to_string(), 3)]),
        };
        assert_eq!(exit_code(&clean, true), 0);
        assert_eq!(exit_code(&clean, false), 0);
        assert_eq!(
            exit_code(&dirty, false),
            0,
            "no enforcement without the flag"
        );
        assert_eq!(exit_code(&dirty, true), 1);
    }

    const LIVE_SPEC_YAML: &str = "
openapi: 3.1.0
info: { title: Live, version: \"1.0\" }
paths:
  /v1/things:
    get:
      parameters:
        - name: x-request-id
          in: header
          required: true
          schema: { type: string }
      responses:
        \"200\":
          description: ok
";

    fn live_validator() -> LiveValidator {
        let spec: Value =
            serde_yaml::from_str(LIVE_SPEC_YAML.trim_start()).expect("fixture spec parses");
        LiveValidator::new(spec)
    }

    #[test]
    fn live_validation_flags_missing_header_and_undocumented_status() {
        let live = live_validator();

        // Request without the required header -> missing-required-header.
        let mut headers = HeaderMapValues::new();
        headers.insert("accept".to_string(), vec!["application/json".to_string()]);
        let violations = live.validate_request_parts(7, "GET", "/v1/things", "", &headers, None);
        let keywords: Vec<&str> = violations.iter().map(|v| v.keyword.as_str()).collect();
        assert!(
            keywords.contains(&"missing-required-header"),
            "expected missing-required-header, got {keywords:?}"
        );

        // Paired undocumented status -> status-not-documented.
        let mut response_headers = HeaderMapValues::new();
        response_headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        let violations = live.validate_response_parts(
            7,
            500,
            &response_headers,
            Some(b"{\"error\":\"boom\"}".as_slice()),
        );
        let keywords: Vec<&str> = violations.iter().map(|v| v.keyword.as_str()).collect();
        assert!(
            keywords.contains(&"status-not-documented"),
            "expected status-not-documented, got {keywords:?}"
        );

        // Both violations landed in the collector under one synthetic sequence.
        live.collector.record(42, violations);
        let summary = live.collector.summary();
        assert!(summary.by_keyword.contains_key("status-not-documented"));
    }

    #[test]
    fn live_validation_clean_traffic_passes_and_records_nothing() {
        let live = live_validator();

        let mut headers = HeaderMapValues::new();
        headers.insert("x-request-id".to_string(), vec!["req-1".to_string()]);
        let request_violations =
            live.validate_request_parts(1, "GET", "/v1/things", "", &headers, None);
        assert!(request_violations.is_empty());

        let mut response_headers = HeaderMapValues::new();
        response_headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        let response_violations = live.validate_response_parts(
            1,
            200,
            &response_headers,
            Some(b"{\"ok\":true}".as_slice()),
        );
        assert!(response_violations.is_empty());
        assert_eq!(live.collector.summary().total, 0);
    }

    #[test]
    fn interleaved_exchanges_pair_by_sequence() {
        let live = live_validator();
        let mut good = HeaderMapValues::new();
        good.insert("x-request-id".to_string(), vec!["req".to_string()]);
        let mut bad = HeaderMapValues::new();
        bad.insert("accept".to_string(), vec!["application/json".to_string()]);
        let mut json_response = HeaderMapValues::new();
        json_response.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );

        // Two requests enter the pipeline interleaved: seq 10 clean, seq 11
        // missing the required header.
        assert!(live
            .validate_request_parts(10, "GET", "/v1/things", "", &good, None)
            .is_empty());
        assert!(live
            .validate_request_parts(11, "GET", "/v1/things", "", &bad, None)
            .iter()
            .any(|v| v.keyword == "missing-required-header"));

        // seq 11 settles first: its undocumented 500 is flagged...
        let violations = live.validate_response_parts(
            11,
            500,
            &json_response,
            Some(b"{\"error\":\"boom\"}".as_slice()),
        );
        assert!(violations
            .iter()
            .any(|v| v.keyword == "status-not-documented"));

        // ...while seq 10's documented 200 stays clean despite the interleaving
        // (a most-recent-match validator would have mispaired it with seq 11).
        assert!(live
            .validate_response_parts(10, 200, &json_response, Some(b"{\"ok\":true}".as_slice()))
            .is_empty());

        // Pending entry consumed; a second response for the same sequence is
        // treated as unmatched.
        assert!(live
            .validate_response_parts(10, 418, &json_response, None)
            .is_empty());
    }

    #[test]
    fn pending_matches_evict_fifo_at_cap() {
        let live = live_validator();
        let mut good = HeaderMapValues::new();
        good.insert("x-request-id".to_string(), vec!["req".to_string()]);
        // Overflow the pending cap; the oldest entry (seq 0) is evicted.
        for seq in 0..=(MAX_PENDING_REQUESTS as u64) {
            live.validate_request_parts(seq, "GET", "/v1/things", "", &good, None);
        }
        // Evicted sequence: response validates as unmatched, no violations,
        // and no unbounded growth.
        assert!(live
            .validate_response_parts(0, 418, &HeaderMapValues::new(), None)
            .is_empty());
        // Most recent sequence still paired.
        let mut json_response = HeaderMapValues::new();
        json_response.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        let violations =
            live.validate_response_parts(MAX_PENDING_REQUESTS as u64, 500, &json_response, None);
        assert!(violations
            .iter()
            .any(|v| v.keyword == "status-not-documented"));
    }

    #[test]
    fn validate_flags_parse_from_cli_matches() {
        use clap::{Command, FromArgMatches};

        let matches = ValidateFlags::augment_args(Command::new("start"))
            .try_get_matches_from([
                "start",
                "--validate-spec",
                "/etc/api.yaml",
                "--report",
                "out/violations.json",
                "--fail-on-violation",
            ])
            .expect("flags parse");
        let flags = ValidateFlags::from_arg_matches(&matches).expect("typed flags");
        assert_eq!(
            flags.spec_path(),
            Some(Path::new("/etc/api.yaml")),
            "delegates through the AMEND-4 loader"
        );
        assert_eq!(
            flags.report.as_deref(),
            Some(Path::new("out/violations.json"))
        );
        assert!(flags.fail_on_violation);
        assert!(flags.wants_validation());
    }
}
