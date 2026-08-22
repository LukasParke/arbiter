//! `arbiter infer-schemas` (port of src/commands/infer-schemas.ts).

use std::path::Path;

use clap::Args;
use serde_json::json;

use super::fail;
use crate::infer::{format_as_components, infer_from_traffic};

/// Infer OpenAPI schemas from captured traffic
#[derive(Args)]
pub struct InferSchemasArgs {
    /// path to traffic JSONL file
    #[arg(short = 'i', long = "input")]
    pub input: String,

    /// path to write inferred schemas YAML file
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// output as JSON instead of YAML
    #[arg(long = "json")]
    pub json: bool,
}

pub fn run(args: &InferSchemasArgs) -> i32 {
    let input = Path::new(&args.input);
    if !input.exists() {
        fail(format!("Traffic file not found: {}", args.input));
    }

    println!("Inferring schemas from {}", args.input);
    let endpoints = match infer_from_traffic(input) {
        Ok(endpoints) => endpoints,
        Err(e) => fail(format!("Failed to read traffic file {}: {e}", args.input)),
    };

    if endpoints.is_empty() {
        eprintln!("No JSON responses found in traffic file");
        return 0;
    }

    println!("Inferred schemas for {} endpoint(s):", endpoints.len());
    for ep in &endpoints {
        println!(
            "  {} {} ({}) — {} sample(s)",
            ep.method, ep.path, ep.status_code, ep.sample_count
        );
    }

    if args.json {
        let mut schemas = serde_json::Map::new();
        for ep in &endpoints {
            let name = format!(
                "{}_{}_{}_response",
                ep.method.to_lowercase(),
                sanitize_path_segment(&ep.path),
                ep.status_code
            );
            let schema = serde_json::to_value(&ep.schema).expect("inferred schema serializes");
            schemas.insert(name, schema);
        }
        let json_out = serde_json::to_string_pretty(&json!({
            "components": { "schemas": schemas },
        }))
        .expect("schemas serialize");
        match args.output.as_deref() {
            Some(output_path) => {
                std::fs::write(output_path, &json_out).unwrap_or_else(|e| {
                    fail(format!("Failed to write schemas to {output_path}: {e}"))
                });
                println!("Wrote schemas to {output_path}");
            }
            None => println!("{json_out}"),
        }
    } else {
        let yaml_out = format_as_components(&endpoints);
        match args.output.as_deref() {
            Some(output_path) => {
                std::fs::write(output_path, format!("{yaml_out}\n")).unwrap_or_else(|e| {
                    fail(format!("Failed to write schemas to {output_path}: {e}"))
                });
                println!("Wrote schemas to {output_path}");
            }
            None => println!("{yaml_out}"),
        }
    }
    0
}

/// Port of the TS name sanitizer:
/// `path.replace(/[^a-zA-Z0-9]/g, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '')`.
fn sanitize_path_segment(path: &str) -> String {
    let replaced: String = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let collapsed = collapse_underscores(&replaced);
    collapsed.trim_matches('_').to_string()
}

fn collapse_underscores(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_underscore = false;
    for c in input.chars() {
        if c == '_' {
            if !prev_underscore {
                out.push(c);
            }
            prev_underscore = true;
        } else {
            out.push(c);
            prev_underscore = false;
        }
    }
    out
}
