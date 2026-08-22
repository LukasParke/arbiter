//! `arbiter fingerprint <bundle>` — LLM provider summary over a capture
//! bundle (W4). Human output is an aligned table; `--json` prints the same
//! [`crate::llm::FingerprintReport`] the `GET /__fingerprint` endpoint
//! serves. Registered in `cli/mod.rs` during M3 assembly (AMEND-11).

use std::path::PathBuf;

use clap::Parser;

use crate::llm::{fingerprint_bundle, FingerprintReport};

/// Fingerprint LLM provider traffic recorded in a capture bundle.
///
/// Examples:
///   arbiter fingerprint ./captures/2026-08-21
///   arbiter fingerprint ./captures/latest --json | jq .driftGroups
#[derive(Debug, Parser)]
pub struct FingerprintCommand {
    /// Path to the capture bundle directory (manifest.json + exchanges.ndjson).
    /// Example: arbiter fingerprint ~/.local/share/arbiter/captures/latest
    pub bundle: PathBuf,

    /// Emit the machine-readable JSON report instead of a table.
    /// Example: arbiter fingerprint ./capture --json > report.json
    #[arg(long)]
    pub json: bool,
}

/// Run the command, returning the process exit code. Errors print in the
/// house style: one-line cause plus a `help:` hint, never a panic.
pub fn run(args: &FingerprintCommand) -> i32 {
    match fingerprint_bundle(&args.bundle) {
        Ok(report) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("report serializes")
                );
            } else {
                print_table(&report);
            }
            0
        }
        Err(error) => {
            eprintln!(
                "error: cannot fingerprint bundle {}: {error}",
                args.bundle.display()
            );
            eprintln!(
                "  help: pass a bundle directory written by `arbiter capture` \
                 (it must contain manifest.json and exchanges.ndjson)"
            );
            1
        }
    }
}

const FP_PREFIX: usize = 12;

fn fp_cell(fp: &Option<String>) -> String {
    match fp {
        Some(fp) => {
            let end = fp.len().min(FP_PREFIX);
            fp[..end].to_string()
        }
        None => "-".to_string(),
    }
}

fn tokens_cell(report_usage: &Option<crate::llm::Usage>) -> String {
    match report_usage {
        Some(usage) => format!(
            "{}/{}",
            usage.prompt_tokens.map_or("-".into(), |p| p.to_string()),
            usage
                .completion_tokens
                .map_or("-".into(), |c| c.to_string())
        ),
        None => "-".to_string(),
    }
}

struct Row {
    sequence: String,
    cells: Vec<String>,
}

fn build_rows(report: &FingerprintReport) -> Vec<Row> {
    let header = Row {
        sequence: "SEQ".into(),
        cells: vec![
            "PROVIDER".into(),
            "MODEL".into(),
            "STREAM".into(),
            "TOKENS(IN/OUT)".into(),
            "REQ-FP".into(),
            "RESP-FP".into(),
            "DRIFT".into(),
        ],
    };
    let mut rows = vec![header];
    for entry in &report.entries {
        let drifting = report
            .drift_groups
            .iter()
            .any(|group| group.sequences.contains(&entry.sequence));
        rows.push(Row {
            sequence: entry.sequence.to_string(),
            cells: vec![
                entry.provider.clone(),
                entry.model.clone().unwrap_or_else(|| "-".into()),
                if entry.streaming { "yes" } else { "no" }.into(),
                tokens_cell(&entry.usage),
                fp_cell(&entry.request_fp),
                fp_cell(&entry.response_fp),
                if drifting { "DRIFT" } else { "-" }.into(),
            ],
        });
    }
    rows
}

fn widths(rows: &[Row]) -> Vec<usize> {
    let mut widths = vec![0usize; rows.first().map(|r| r.cells.len() + 1).unwrap_or(1)];
    for row in rows {
        widths[0] = widths[0].max(row.sequence.len());
        for (index, cell) in row.cells.iter().enumerate() {
            widths[index + 1] = widths[index + 1].max(cell.len());
        }
    }
    widths
}

fn print_table(report: &FingerprintReport) {
    if report.entries.is_empty() {
        println!("No LLM-shaped exchanges found in this bundle.");
        return;
    }
    let rows = build_rows(report);
    let widths = widths(&rows);
    for row in &rows {
        let mut line = format!("{:>width$}", row.sequence, width = widths[0]);
        for (index, cell) in row.cells.iter().enumerate() {
            line.push_str(&format!("  {:<width$}", cell, width = widths[index + 1]));
        }
        println!("{}", line.trim_end());
    }
    if !report.drift_groups.is_empty() {
        println!();
        for group in &report.drift_groups {
            println!(
                "DRIFT {} {} model={}: {} distinct request shapes across sequences {:?}",
                group.provider,
                group.path,
                group.model.as_deref().unwrap_or("-"),
                group.distinct_request_fps,
                group.sequences
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FingerprintCommand;
    use super::*;
    use crate::llm::ExchangeFingerprint;
    use clap::CommandFactory;

    #[test]
    fn table_renders_aligned_columns_and_drift_lines() {
        let report = FingerprintReport {
            entries: vec![ExchangeFingerprint {
                sequence: 1,
                provider: "anthropic".into(),
                model: Some("claude-sonnet-4".into()),
                streaming: true,
                tool_count: None,
                tool_names: vec![],
                usage: Some(crate::llm::Usage {
                    prompt_tokens: Some(24),
                    completion_tokens: Some(101),
                    total_tokens: Some(125),
                }),
                stop_reason: Some("end_turn".into()),
                request_fp: Some("a".repeat(64)),
                response_fp: None,
            }],
            drift_groups: vec![],
        };
        // Smoke: printing must not panic and rows include drift marker only
        // when grouped.
        let rows = build_rows(&report);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].cells[6], "-");
        assert_eq!(fp_cell(&None), "-");
        assert_eq!(
            fp_cell(&Some("abcdef1234567890".to_string())).len(),
            FP_PREFIX
        );
    }

    #[test]
    fn help_prose_mentions_examples() {
        let mut help = FingerprintCommand::command();
        let text = help.render_long_help().to_string();
        assert!(text.contains("Examples"));
        assert!(text.contains("--json"));
    }
}
