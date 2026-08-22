//! `arbiter diff` (port of src/commands/diff.ts).

use std::path::Path;

use clap::Args;

use super::fail;
use crate::diff::{diff_from_traffic, write_diff_report};

/// Diff captured traffic against an existing OpenAPI spec
#[derive(Args)]
pub struct DiffArgs {
    /// path to existing OpenAPI spec
    #[arg(short = 's', long = "spec")]
    pub spec: String,

    /// path to traffic JSONL file
    #[arg(short = 't', long = "traffic")]
    pub traffic: String,

    /// path to write JSON diff report
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// exit with code 2 if gaps are found
    #[arg(long = "exit-on-gap")]
    pub exit_on_gap: bool,
}

pub fn run(args: &DiffArgs) -> i32 {
    let result = match diff_from_traffic(Path::new(&args.spec), Path::new(&args.traffic)) {
        Ok(result) => result,
        Err(e) => fail(format!("Diff failed: {e}")),
    };

    println!("\nDiff Report:");
    println!(
        "{}",
        serde_json::to_string_pretty(&result.summary).expect("summary serializes")
    );

    if !result.missing_endpoints.is_empty() {
        println!("\nMissing endpoints:");
        for ep in &result.missing_endpoints {
            println!("  {} {}", ep.method, ep.path);
        }
    }

    if !result.query_param_gaps.is_empty() {
        println!("\nQuery param gaps:");
        for gap in &result.query_param_gaps {
            println!(
                "  {} {}: {}",
                gap.method,
                gap.path,
                gap.missing_query_params.join(", ")
            );
        }
    }

    if let Some(output) = args.output.as_deref() {
        if let Err(e) = write_diff_report(&result, Path::new(output)) {
            fail(format!("Failed to write report {output}: {e}"));
        }
        println!("\nReport written to {output}");
    }

    if args.exit_on_gap && !result.missing_endpoints.is_empty() {
        return 2;
    }
    0
}
