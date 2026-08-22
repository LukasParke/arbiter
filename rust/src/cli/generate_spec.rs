//! `arbiter generate-spec` (port of src/commands/generate-spec.ts).

use std::path::Path;

use clap::Args;

use super::fail;
use crate::generate_spec::{generate_spec_from_traffic, spec_to_json, spec_to_yaml};

/// Generate a complete OpenAPI spec from captured traffic
#[derive(Args)]
pub struct GenerateSpecArgs {
    /// path to traffic JSONL file
    #[arg(short = 'i', long = "input")]
    pub input: String,

    /// path to write the generated spec
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// output as JSON instead of YAML
    #[arg(long = "json")]
    pub json: bool,

    /// API title in generated spec
    #[arg(long = "title", default_value = "Generated API Specification")]
    pub title: String,

    /// API version in generated spec
    #[arg(long = "version", default_value = "1.0.0")]
    pub version: String,

    /// server URL for generated spec
    #[arg(long = "server-url")]
    pub server_url: Option<String>,
}

pub fn run(args: &GenerateSpecArgs) -> i32 {
    let input = Path::new(&args.input);
    if !input.exists() {
        fail(format!("Traffic file not found: {}", args.input));
    }

    println!("Generating OpenAPI spec from {}", args.input);

    let spec = match generate_spec_from_traffic(input, &args.title, &args.version) {
        Ok(spec) => spec,
        Err(e) => fail(format!("Spec generation failed: {e}")),
    };

    let path_count = spec
        .spec
        .get("paths")
        .and_then(|v| v.as_object())
        .map(|o| o.len())
        .unwrap_or(0);
    let schema_count = spec
        .spec
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(|s| s.as_object())
        .map(|o| o.len())
        .unwrap_or(0);

    println!("Generated spec with {path_count} path(s) and {schema_count} schema(s)");

    // TS forwards serverUrl into the generator; the Rust generator infers the
    // server URL from the first traffic entry instead (contract decision), so
    // --server-url is accepted for surface parity.
    let _ = &args.server_url;

    let output = if args.json {
        spec_to_json(&spec)
    } else {
        spec_to_yaml(&spec)
    };

    match args.output.as_deref() {
        Some(output_path) => {
            std::fs::write(output_path, format!("{output}\n"))
                .unwrap_or_else(|e| fail(format!("Failed to write spec to {output_path}: {e}")));
            println!("Wrote spec to {output_path}");
        }
        None => println!("{output}"),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Traffic JSONL in the shape produced by `arbiter generate-traffic` and
    /// consumed by generate-spec.ts: path, method, status, contentType, body.
    /// Paths are relative; generate-spec.ts keys `paths` by the raw entry.path
    /// and infers the server URL from the first entry.
    const TRAFFIC_JSONL: &str = concat!(
        r#"{"path":"/v1/messages","method":"POST","queryParams":[],"status":200,"contentType":"application/json","body":"{\"id\":\"abc\",\"count\":2}"}"#,
        "\n",
        r#"{"path":"/v1/messages","method":"POST","queryParams":[],"status":404,"contentType":"application/json"}"#,
        "\n",
        r#"{"path":"/health","method":"GET","queryParams":["verbose=true"],"status":200}"#,
        "\n"
    );

    fn args(
        input: &std::path::Path,
        output: Option<&std::path::Path>,
        json: bool,
    ) -> GenerateSpecArgs {
        GenerateSpecArgs {
            input: input.to_string_lossy().into_owned(),
            output: output.map(|p| p.to_string_lossy().into_owned()),
            json,
            title: "Generated API Specification".to_string(),
            version: "1.0.0".to_string(),
            server_url: None,
        }
    }

    #[test]
    fn generates_spec_file_from_traffic_fixture() {
        let dir = tempfile::tempdir().expect("tempdir");
        let traffic = dir.path().join("traffic.jsonl");
        std::fs::write(&traffic, TRAFFIC_JSONL).expect("write traffic");
        let out = dir.path().join("spec.yaml");

        let code = run(&args(&traffic, Some(&out), false));
        assert_eq!(code, 0);

        let written = std::fs::read_to_string(&out).expect("spec written");
        assert!(written.contains("/v1/messages"));
        assert!(written.contains("/health"));
        // YAML is the default output format.
        assert!(written.starts_with("openapi:") || written.contains("info:"));
    }

    #[test]
    fn json_output_contains_paths_and_schemas() {
        let dir = tempfile::tempdir().expect("tempdir");
        let traffic = dir.path().join("traffic.jsonl");
        std::fs::write(&traffic, TRAFFIC_JSONL).expect("write traffic");
        let out = dir.path().join("spec.json");

        let code = run(&args(&traffic, Some(&out), true));
        assert_eq!(code, 0);

        let spec: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).expect("spec written"))
                .expect("valid JSON spec");
        assert!(
            spec.get("paths")
                .and_then(|p| p.get("/v1/messages"))
                .is_some(),
            "POST group must appear under paths: {spec}"
        );
        assert!(
            spec.pointer("/paths/~1health/get").is_some(),
            "GET /health must be captured: {spec}"
        );
    }
}
