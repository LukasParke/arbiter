//! `arbiter validate-schemas` (port of src/commands/validate-schemas.ts).

use std::path::Path;

use clap::Args;

use super::fail;
use crate::diff::{validate_schema_coverage, SchemaGap};

/// Validate schema coverage in an OpenAPI spec
#[derive(Args)]
pub struct ValidateSchemasArgs {
    /// path to OpenAPI spec
    #[arg(short = 's', long = "spec")]
    pub spec: String,

    /// path to write JSON validation report
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// exit with code 2 if gaps are found
    #[arg(long = "exit-on-gap")]
    pub exit_on_gap: bool,
}

pub fn run(args: &ValidateSchemasArgs) -> i32 {
    let result = match validate_schema_coverage(Path::new(&args.spec)) {
        Ok(result) => result,
        Err(e) => fail(format!("Schema validation failed: {e}")),
    };

    println!("\nSchema Coverage Report:");
    println!("  Total endpoints: {}", result.summary.total_endpoints);
    println!(
        "  Missing response schemas: {}",
        count_label(result.summary.missing_response_schemas)
    );
    println!(
        "  Missing request schemas: {}",
        count_label(result.summary.missing_request_schemas)
    );
    println!(
        "  Bare response schemas: {}",
        count_label_bare(result.summary.bare_response_schemas)
    );
    println!(
        "  Missing parameter schemas: {}",
        count_label(result.summary.missing_param_schemas)
    );
    println!("  Total gaps: {}", count_label(result.summary.total_gaps));

    if result.gaps.is_empty() {
        println!("\n✓ All endpoints have complete schema coverage!");
    } else {
        for (category, gaps) in group_by_category(&result.gaps) {
            println!("\n{category}:");
            for gap in gaps {
                println!("  {} {} | {}", gap.method, gap.path, gap.operation_id);
                println!("    → {}", gap.detail);
            }
        }
    }

    if let Some(output) = args.output.as_deref() {
        if let Err(e) = crate::diff::write_schema_validation_report(&result, Path::new(output)) {
            fail(format!("Failed to write report {output}: {e}"));
        }
        println!("\nReport written to {output}");
    }

    if args.exit_on_gap && !result.gaps.is_empty() {
        return 2;
    }
    0
}

fn count_label(count: usize) -> String {
    if count > 0 {
        count.to_string()
    } else {
        "0".to_string()
    }
}

/// TS colors bare response schema counts yellow rather than red; the plain
/// rendering is identical either way.
fn count_label_bare(count: usize) -> String {
    count_label(count)
}

/// Group gaps by serialized category, preserving first-seen category order
/// (mirrors the Map insertion order in TS).
fn group_by_category(gaps: &[SchemaGap]) -> Vec<(String, Vec<&SchemaGap>)> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<&SchemaGap>> =
        std::collections::HashMap::new();
    for gap in gaps {
        let category = serde_json::to_value(gap)
            .ok()
            .and_then(|v| v.get("category").and_then(|c| c.as_str()).map(String::from))
            .unwrap_or_default();
        if !groups.contains_key(&category) {
            order.push(category.clone());
        }
        groups.entry(category).or_default().push(gap);
    }
    order
        .into_iter()
        .filter_map(|category| groups.remove_entry(&category))
        .collect()
}
