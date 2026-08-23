//! `arbiter inspect <BUNDLE>` — read-only bundle viewer (D1).
//!
//! Loads a capture bundle through [`load_bundle`] and renders a human table
//! (manifest summary + one row per exchange), an optional full detail dump
//! for one exchange, or — with the global `--json` — the whole exchange list
//! as stable JSON. Never mutates the bundle.

use std::collections::HashMap;
use std::path::PathBuf;

use clap::Args;

use crate::bundle::{load_bundle, CaptureBundle};
use crate::cli::output::{emit, OutputFormat};
use crate::types::{BodyStorage, CaptureManifest, CapturedBody, CapturedExchange, CapturedHeaders};

/// How many bytes of a body to preview in `--exchange` detail output.
const BODY_PREVIEW_BYTES: usize = 4 * 1024;

/// Print a human-readable summary of a capture bundle
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Path to the capture bundle directory (manifest.json + exchanges.ndjson).
    pub bundle: PathBuf,

    /// Dump full detail for one exchange by sequence number.
    #[arg(long = "exchange", value_name = "N")]
    pub exchange: Option<u64>,
}

/// Run the command, returning the process exit code. Errors print in the
/// house style: one-line cause plus a `help:` hint, never a panic.
pub fn run(args: &InspectArgs, fmt: OutputFormat) -> i32 {
    let mut bundle = match load_bundle(&args.bundle) {
        Ok(bundle) => bundle,
        Err(error) => {
            eprintln!(
                "error: cannot inspect bundle {}: {error}",
                args.bundle.display()
            );
            eprintln!(
                "  help: pass a bundle directory written by `arbiter capture` \
                 (it must contain manifest.json and exchanges.ndjson)"
            );
            return 1;
        }
    };
    if let Some(sequence) = args.exchange {
        let exchange = match bundle.exchanges.iter().find(|e| e.sequence == sequence) {
            Some(exchange) => exchange.clone(),
            None => {
                eprintln!(
                    "error: no exchange with sequence {sequence} in {}",
                    args.bundle.display()
                );
                eprintln!(
                    "  help: run `arbiter inspect {}` to list sequences",
                    args.bundle.display()
                );
                return 1;
            }
        };
        let bodies = read_bodies(&mut bundle).unwrap_or_default();
        emit(
            fmt,
            || println!("{}", detail_text(&exchange, &bodies)),
            &exchange,
        );
        return 0;
    }

    let (manifest, exchanges) = (&bundle.manifest, bundle.exchanges.clone());
    emit(fmt, || print_table(manifest, &exchanges), &exchanges);
    0
}

fn read_bodies(bundle: &mut CaptureBundle) -> crate::error::Result<HashMap<String, Vec<u8>>> {
    bundle.read_all_bodies()
}

// ---------------------------------------------------------------------------
// Human rendering (pure builders so tests can assert on rows)
// ---------------------------------------------------------------------------

fn flags_cell(exchange: &CapturedExchange) -> String {
    let mut flags: Vec<&str> = Vec::new();
    if exchange.tunnel.is_some() {
        flags.push("tunnel");
    }
    if exchange.tls.is_some() {
        flags.push("tls");
    }
    if exchange.ws.is_some() {
        flags.push("ws");
    }
    if exchange.llm.is_some() {
        flags.push("llm");
    }
    if flags.is_empty() {
        "-".to_string()
    } else {
        flags.join("+")
    }
}

fn content_type(headers: &CapturedHeaders) -> String {
    headers
        .values
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, values)| values.join(", "))
        .unwrap_or_else(|| "-".into())
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn summary_line(manifest: &CaptureManifest) -> String {
    format!(
        "Bundle: v{}, mode {}, target {}, {} exchange(s), digest {}",
        manifest.schema_version,
        serde_json::to_value(manifest.mode)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "?".into()),
        manifest.target_origin,
        manifest.exchange_count,
        &manifest.bundle_digest[..manifest.bundle_digest.len().min(12)],
    )
}

fn table_row(exchange: &CapturedExchange) -> String {
    let path = exchange.request.path.split('?').next().unwrap_or("");
    let req_type = content_type(&exchange.request.headers);
    let resp_type = content_type(&exchange.response.headers);
    let types = if req_type == resp_type {
        req_type
    } else {
        format!("{req_type}|{resp_type}")
    };
    format!(
        "{:>4}  {:<6} {:<28} {:>4}  {:>8} {:>8}  {:<20} {}",
        exchange.sequence,
        exchange.request.method,
        truncate(path, 28),
        exchange.response.status,
        exchange.request.body.size,
        exchange.response.body.size,
        truncate(&types, 20),
        flags_cell(exchange),
    )
}

fn table_header() -> String {
    format!(
        "{:>4}  {:<6} {:<28} {:>4}  {:>8} {:>8}  {:<20} {}",
        "seq", "method", "path", "stat", "req B", "resp B", "types", "flags"
    )
}

fn print_table(manifest: &CaptureManifest, exchanges: &[CapturedExchange]) {
    println!("{}", summary_line(manifest));
    println!();
    println!("{}", table_header());
    for exchange in exchanges {
        println!("{}", table_row(exchange));
    }
}

fn headers_text(name: &str, headers: &CapturedHeaders) -> String {
    let mut out = format!("\n{name} headers:\n");
    for (header_name, values) in &headers.values {
        for value in values {
            out.push_str(&format!("  {header_name}: {value}\n"));
        }
    }
    for redacted in &headers.redacted {
        out.push_str(&format!("  {redacted}: <redacted>\n"));
    }
    out
}

fn body_preview_text(body: &CapturedBody, bodies: &HashMap<String, Vec<u8>>) -> String {
    // Blob bytes come from the verified reader; inline base64 is decoded here
    // (the loader already checked its digest at load time).
    let bytes = match bodies.get(&body.sha256) {
        Some(bytes) => bytes.clone(),
        None => match &body.storage {
            BodyStorage::InlineBase64 { value } => decode_base64(value),
            _ => Vec::new(),
        },
    };
    if bytes.is_empty() {
        return "  <empty>\n".to_string();
    }
    let preview_len = bytes.len().min(BODY_PREVIEW_BYTES);
    let preview = &bytes[..preview_len];
    let mut out = match std::str::from_utf8(preview) {
        Ok(text) => {
            let mut out = String::new();
            for line in text.lines().take(200) {
                out.push_str(&format!("  {line}\n"));
            }
            out
        }
        Err(_) => format!(
            "  <binary, media type {:?}>\n  {}\n",
            body.media_type,
            encode_base64(preview)
        ),
    };
    if bytes.len() > BODY_PREVIEW_BYTES {
        out.push_str(&format!(
            "  … ({} more bytes)\n",
            bytes.len() - BODY_PREVIEW_BYTES
        ));
    }
    out
}

fn detail_text(exchange: &CapturedExchange, bodies: &HashMap<String, Vec<u8>>) -> String {
    let request = &exchange.request;
    let response = &exchange.response;
    let mut out = format!(
        "#{} {} {}\n",
        exchange.sequence, request.method, request.path
    );
    out.push_str(&format!(
        "status: {} {} ({}, {} ms)\n",
        response.status, response.status_text, response.http_version, exchange.duration_ms
    ));
    out.push_str(&headers_text("request", &request.headers));
    out.push_str(&headers_text("response", &response.headers));
    out.push_str(&format!(
        "\nrequest body ({} bytes):\n{}\n",
        request.body.size,
        body_preview_text(&request.body, bodies)
    ));
    out.push_str(&format!(
        "response body ({} bytes):\n{}",
        response.body.size,
        body_preview_text(&response.body, bodies)
    ));
    out
}

fn decode_base64(value: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap_or_default()
}

fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{make_captured_body, write_bundle, WriteBundleOptions};
    use crate::cli::output::json_to_string;
    use crate::redaction::RedactionPolicy;
    use crate::types::{
        CaptureMode, CapturedRequest, CapturedResponse, StreamState, BUNDLE_SCHEMA_VERSION,
    };
    use std::collections::BTreeMap;
    fn fixture_exchange(seq: u64, body: &[u8]) -> CapturedExchange {
        let captured_body = make_captured_body(body, Some("text/plain"), None, None).expect("body");
        CapturedExchange {
            schema_version: 1,
            sequence: seq,
            started_at: "2026-08-21T00:00:00.000Z".into(),
            duration_ms: 5.0,
            request: CapturedRequest {
                method: "GET".into(),
                path: "/x?q=1".into(),
                http_version: "1.1".into(),
                headers: CapturedHeaders {
                    values: BTreeMap::new(),
                    redacted: vec![],
                },
                body: captured_body.clone(),
            },
            response: CapturedResponse {
                status: 200,
                status_text: "OK".into(),
                http_version: "1.1".into(),
                headers: CapturedHeaders {
                    values: BTreeMap::new(),
                    redacted: vec![],
                },
                body: captured_body,
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

    fn write_fixture(dir: &std::path::Path) -> PathBuf {
        let out = dir.join("bundle");
        let options = WriteBundleOptions {
            manifest: CaptureManifest {
                schema_version: BUNDLE_SCHEMA_VERSION,
                arbiter_version: "1.1.0".into(),
                mode: CaptureMode::Observe,
                target_origin: "https://api.example.com".into(),
                started_at: "2026-08-21T00:00:00.000Z".into(),
                completed_at: "2026-08-21T00:00:01.000Z".into(),
                exchange_count: 2,
                bundle_digest: "ab".repeat(32),
                redaction: RedactionPolicy::default().summary(),
                metadata: None,
            },
            exchanges: vec![fixture_exchange(1, b"hello"), fixture_exchange(2, b"world")],
            bodies: HashMap::new(),
            validation: None,
        };
        write_bundle(&out, options).expect("fixture bundle written");
        out
    }

    #[test]
    fn missing_bundle_errors_with_exit_1() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = InspectArgs {
            bundle: dir.path().join("nope"),
            exchange: None,
        };
        assert_eq!(run(&args, OutputFormat::Human), 1);
    }

    #[test]
    fn unknown_sequence_errors_with_exit_1() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle_dir = write_fixture(dir.path());
        let args = InspectArgs {
            bundle: bundle_dir,
            exchange: Some(99),
        };
        assert_eq!(run(&args, OutputFormat::Human), 1);
    }

    /// D1 acceptance: the human table contains the expected rows.
    #[test]
    fn table_contains_manifest_summary_and_per_exchange_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle_dir = write_fixture(dir.path());
        let mut bundle = load_bundle(&bundle_dir).expect("bundle loads");

        let summary = summary_line(&bundle.manifest);
        assert!(summary.contains("mode observe"));
        assert!(summary.contains("target https://api.example.com"));
        assert!(summary.contains("2 exchange(s)"));
        let digest_cell = summary
            .split("digest ")
            .nth(1)
            .expect("digest cell present");
        assert_eq!(digest_cell.len(), 12);

        assert_eq!(bundle.exchanges.len(), 2);
        let row1 = table_row(&bundle.exchanges[0]);
        assert!(row1.contains("   1"), "seq column: {row1}");
        assert!(row1.contains("GET"));
        assert!(row1.contains("/x")); // query stripped from the path cell
        assert!(row1.contains(" 200 "));
        assert!(row1.ends_with('-'), "no extension flags: {row1}");

        let header = table_header();
        for column in ["seq", "method", "path", "req B", "resp B", "types", "flags"] {
            assert!(header.contains(column));
        }

        let _ = read_bodies(&mut bundle).expect("bodies read");
    }

    /// D1 acceptance: --json output round-trips as the stable exchange list.
    #[test]
    fn json_output_round_trips_as_exchange_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle_dir = write_fixture(dir.path());
        let bundle = load_bundle(&bundle_dir).expect("bundle loads");

        let json = json_to_string(&bundle.exchanges);
        let parsed: Vec<CapturedExchange> =
            serde_json::from_str(&json).expect("inspect json must parse as exchange list");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].sequence, 1);
        assert_eq!(parsed[0].request.method, "GET");
        assert_eq!(parsed[0].response.status, 200);
    }

    /// D1 acceptance: --exchange detail decodes inline base64 bodies to text.
    #[test]
    fn detail_dumps_headers_and_decoded_body_text() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle_dir = write_fixture(dir.path());
        let bundle = load_bundle(&bundle_dir).expect("bundle loads");

        let exchange = bundle
            .exchanges
            .iter()
            .find(|e| e.sequence == 1)
            .expect("exchange 1")
            .clone();
        let text = detail_text(&exchange, &HashMap::new());
        assert!(text.starts_with("#1 GET /x?q=1\n"));
        assert!(text.contains("status: 200 OK (1.1, 5 ms)"));
        assert!(text.contains("request headers:"));
        assert!(text.contains("response headers:"));
        assert!(text.contains("hello"), "decoded request body: {text}");
        // Fixture reuses the same recorded body for request and response.
        assert!(text.contains("request body"), "{text}");
        assert!(text.contains("response body"), "{text}");
    }

    #[test]
    fn binary_bodies_render_as_labeled_base64() {
        let binary_body =
            make_captured_body(&[0u8, 159, 146, 150], Some("image/png"), None, None).expect("body");
        let mut exchange = fixture_exchange(3, b"ignored");
        exchange.request.body = binary_body.clone();
        exchange.response.body = binary_body;

        let text = detail_text(&exchange, &HashMap::new());
        assert!(text.contains("<binary, media type"), "{text}");
    }
}
