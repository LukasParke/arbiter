//! `arbiter discover` (port of src/commands/discover.ts).

use std::process::Command;

use clap::Args;

use super::fail;

/// Run full discovery pipeline: start proxy, generate traffic, diff against spec
#[derive(Args)]
pub struct DiscoverArgs {
    /// path to existing OpenAPI spec to diff against
    #[arg(short = 's', long = "spec")]
    pub spec: String,

    /// target API URL to proxy to
    #[arg(short = 't', long = "target")]
    pub target: String,

    /// docker-compose file for infrastructure
    #[arg(long = "compose-file", default_value = "docker-compose.yml")]
    pub compose_file: String,

    /// path to write traffic JSONL
    #[arg(long = "traffic-output", default_value = "/tmp/traffic.jsonl")]
    pub traffic_output: String,

    /// path to write diff report
    #[arg(long = "report-output", default_value = "/tmp/diff_report.json")]
    pub report_output: String,

    /// X-Plex-Token for authenticated requests
    #[arg(long = "token")]
    pub token: Option<String>,

    /// exit with code 2 if gaps are found
    #[arg(long = "exit-on-gap")]
    pub exit_on_gap: bool,
}

pub fn run(args: &DiscoverArgs) -> i32 {
    let compose_active = std::path::Path::new(&args.compose_file).exists();

    if compose_active {
        println!("Starting docker compose...");
        let up = Command::new("docker")
            .args(["compose", "-f", &args.compose_file, "up", "-d"])
            .status()
            .unwrap_or_else(|e| fail(format!("Failed to start docker compose: {e}")));
        if !up.success() {
            fail("Failed to start docker compose");
        }
        println!("Waiting for services...");
        std::thread::sleep(std::time::Duration::from_secs(15));
    }

    println!("Generating traffic...");
    let exe = std::env::current_exe()
        .unwrap_or_else(|e| fail(format!("Failed to locate arbiter binary: {e}")));
    let mut traffic_cmd = Command::new(&exe);
    traffic_cmd
        .args([
            "generate-traffic",
            "--target",
            &args.target,
            "--output",
            &args.traffic_output,
        ])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    if let Some(token) = args.token.as_deref() {
        traffic_cmd.args(["--token", token]);
    }
    let traffic_output = traffic_cmd
        .output()
        .unwrap_or_else(|e| fail(format!("Failed to run generate-traffic: {e}")));
    if !traffic_output.stdout.is_empty() {
        println!("{}", String::from_utf8_lossy(&traffic_output.stdout));
    }

    println!("Running diff...");
    let mut diff_cmd = Command::new(&exe);
    diff_cmd.args([
        "diff",
        "--spec",
        &args.spec,
        "--traffic",
        &args.traffic_output,
    ]);
    if !args.report_output.is_empty() {
        diff_cmd.args(["--output", &args.report_output]);
    }
    if args.exit_on_gap {
        diff_cmd.arg("--exit-on-gap");
    }
    let diff_status = diff_cmd
        .status()
        .unwrap_or_else(|e| fail(format!("Failed to run diff: {e}")));

    if compose_active {
        println!("Stopping docker compose...");
        Command::new("docker")
            .args(["compose", "-f", &args.compose_file, "down"])
            .status()
            .ok();
    }

    diff_status.code().unwrap_or(0)
}
