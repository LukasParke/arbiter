//! `arbiter sanitize` (port of src/commands/sanitize.ts).

use std::path::{Path, PathBuf};

use clap::Args;

use super::fail;
use crate::bundle::sanitize::{sanitize_bundle, SanitizeOptions};

/// Revalidate an untrusted capture bundle and emit a new deterministic sanitized bundle
#[derive(Args)]
pub struct SanitizeArgs {
    /// path to the input capture bundle directory
    pub bundle: String,

    /// directory for the sanitized bundle (must not exist or be empty)
    #[arg(short = 'o', long = "output")]
    pub output: String,

    /// additional header name/glob to redact (repeatable)
    #[arg(long = "redact-header")]
    pub redact_header: Vec<String>,

    /// query parameter whose value may be kept (repeatable)
    #[arg(long = "allow-query")]
    pub allow_query: Vec<String>,

    /// env var whose value must not appear anywhere (repeatable)
    #[arg(long = "reject-secret-env")]
    pub reject_secret_env: Vec<String>,

    /// media type prefix allowed to remain unscanned binary (repeatable)
    #[arg(long = "allow-binary-media-type")]
    pub allow_binary_media_type: Vec<String>,
}

pub fn run(args: &SanitizeArgs) -> i32 {
    for env_name in &args.reject_secret_env {
        match std::env::var(env_name) {
            Ok(value) if !value.is_empty() => {}
            _ => fail(format!(
                "--reject-secret-env {env_name}: environment variable is not set"
            )),
        }
    }

    let options = SanitizeOptions {
        reject_secret_env: args.reject_secret_env.clone(),
        allow_binary_media_types: args.allow_binary_media_type.clone(),
        redact_headers: args.redact_header.clone(),
        allow_query: args.allow_query.clone(),
        output: PathBuf::from(&args.output),
    };

    match sanitize_bundle(Path::new(&args.bundle), &options) {
        Ok(result) => {
            println!(
                "Sanitized {} exchange(s) to {}",
                result.manifest.exchange_count, args.output
            );
            0
        }
        Err(e) => fail(format!("Sanitize failed: {e}")),
    }
}
