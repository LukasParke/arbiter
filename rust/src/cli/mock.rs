//! `arbiter mock` command (W3): serve example responses from an OpenAPI
//! spec or byte-exact replay from a capture bundle. Exported as a typed
//! surface for cli-dx assembly (AMEND-11) — cli/mod.rs wiring lands in the
//! M3 window.

use clap::Args;

use crate::error::Result;
use crate::mock::{options_from_parts, run_mock, MatchStrategy, MockOptions};

/// Help EXAMPLES block (G3): every `arbiter mock ...` line here must parse
/// verbatim — asserted by `every_example_line_parses` below.
const EXAMPLES: &str = "EXAMPLES:\n  arbiter mock --spec openapi.yaml --port 4010 --watch\n      Generate example responses; reload on spec edits.\n\n  arbiter mock --capture .arbiter/bundle --match-strategy strongest\n      Replay a capture bundle byte-exact, best-match selection.\n\n  arbiter mock --spec api.yaml --fault-latency-ms 250 --fault-status 503 --fault-fraction 20\n      20% of requests get 250ms latency then a 503.\n\n  arbiter mock --capture DIR --var env=test --fault-error reset\n      Pin {{vars.env}} in templated bodies and reset connections.";

/// Simulate an API from an OpenAPI spec or a captured bundle.
///
/// Spec mode generates Prism-style example responses (examples >
/// schema-derived sample > empty 200). Capture mode replays recorded
/// exchanges byte-exact. Faults apply to both modes.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct MockCommand {
    /// OpenAPI spec (yaml|yml|json) to generate example responses from.
    /// Mutually exclusive with --capture.
    /// Example: --spec openapi.yaml
    #[arg(long, value_name = "PATH")]
    pub spec: Option<std::path::PathBuf>,

    /// Arbiter capture-bundle directory to replay byte-exact.
    /// Mutually exclusive with --spec.
    /// Example: --capture .arbiter/bundle
    #[arg(long, value_name = "DIR")]
    pub capture: Option<std::path::PathBuf>,

    /// Port to listen on.
    /// Example: --port 4010
    #[arg(long, default_value_t = 4010, value_name = "PORT")]
    pub port: u16,

    /// Address to bind.
    /// Example: --host 0.0.0.0
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    pub host: String,

    /// Watch the source file(s) and hot-reload on change (500 ms poll).
    /// Example: --watch
    #[arg(long)]
    pub watch: bool,

    /// Capture-replay matching: `strongest` scores by priority and
    /// specificity, `first` takes the earliest matching recording.
    /// Example: --match-strategy first
    #[arg(
        long,
        value_enum,
        default_value_t = MatchStrategy::default(),
        value_name = "strongest|first"
    )]
    pub match_strategy: MatchStrategy,

    /// Inject latency before faulted responses (milliseconds).
    /// Example: --fault-latency-ms 250
    #[arg(long, value_name = "MS")]
    pub fault_latency_ms: Option<u64>,

    /// Replace faulted responses with this HTTP status code (100-599).
    /// Example: --fault-status 503
    #[arg(long, value_name = "CODE")]
    pub fault_status: Option<u16>,

    /// Hard error injected on faulted requests: reset (drop connection),
    /// timeout (never answer), garbage (random bytes).
    /// Example: --fault-error reset
    #[arg(long, value_enum, value_name = "reset|timeout|garbage")]
    pub fault_error: Option<crate::mock::FaultKind>,

    /// Percent of requests that receive faults (0-100).
    /// Example: --fault-fraction 20
    #[arg(long, default_value_t = 100, value_name = "PCT")]
    pub fault_fraction: u8,

    /// Static template variable KEY=VALUE, repeatable. Overrides win over
    /// request values; --var now=... pins {{now}} for golden tests.
    /// Example: --var env=test
    #[arg(long, value_name = "K=V")]
    pub var: Vec<String>,
}

// Wired into the CLI by cli-dx at M3 assembly (AMEND-11); until then the
// typed surface is exported but not dispatched.
#[allow(dead_code)]
impl MockCommand {
    /// Resolve CLI args into engine options (validation happens here).
    pub fn to_options(&self) -> Result<MockOptions> {
        options_from_parts(
            self.spec.clone(),
            self.capture.clone(),
            self.host.clone(),
            self.port,
            self.watch,
            self.match_strategy,
            self.fault_latency_ms,
            self.fault_status,
            self.fault_error,
            self.fault_fraction,
            &self.var,
        )
    }

    /// Run the mock server until Ctrl-C. Exported for cli-dx assembly.
    pub async fn run(&self) -> Result<()> {
        run_mock(self.to_options()?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G3 regression: every `arbiter mock ...` line in the EXAMPLES block
    /// must parse verbatim — copy-pasting our own help can never fail.
    #[test]
    fn every_example_line_parses() {
        let lines: Vec<&str> = EXAMPLES
            .lines()
            .filter(|l| l.starts_with("  arbiter "))
            .collect();
        assert!(
            lines.len() >= 4,
            "EXAMPLES block lost its command lines: {lines:?}"
        );
        for line in lines {
            let tokens: Vec<&str> = line.split_whitespace().skip(1).collect();
            MockCommand::augment_args(clap::Command::new("mock"))
                .try_get_matches_from(tokens.iter().copied())
                .unwrap_or_else(|e| panic!("example does not parse ({e}): {line}"));
        }
    }

    /// G3 regression: the fixed example uses the real flag name.
    #[test]
    fn examples_reference_real_match_flag() {
        assert!(!EXAMPLES.contains("--match "), "ghost --match flag back");
        assert!(EXAMPLES.contains("--match-strategy strongest"));
    }
}
