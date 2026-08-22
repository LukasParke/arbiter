//! `arbiter ca` — root-CA generation and TLS flag surface (AMEND-11).
//!
//! The typed [`CaArgs`] struct is the single source for the start-command
//! TLS flags (`--no-tls-intercept`, `--tls-passthrough`, `--tls-cert`,
//! `--tls-key`); the M3 wiring consumes them from here instead of
//! re-parsing. Output prints plainly until cli-dx's `output::emit` lands.

#![allow(dead_code)] // wired into the command tree by cli-dx in the M3 window (AMEND-11)

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use crate::error::{Error, Result};
use crate::tls::ca::{ensure_ca, install_hint, CaAlg, CA_CERT_FILE, CA_KEY_FILE};

/// Typed TLS/CA flag surface shared by the `ca` command and `start`.
#[derive(Debug, Clone, Args)]
pub struct CaArgs {
    /// explicit CA certificate path (overrides --ca-dir)
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,

    /// explicit CA key path (overrides --ca-dir)
    #[arg(long)]
    pub ca_key: Option<PathBuf>,

    /// directory holding ca.pem/key.pem
    #[arg(long, default_value = "~/.arbiter/ca")]
    pub ca_dir: String,

    /// root CA signature algorithm
    #[arg(long, value_enum, default_value_t = CaAlgArg::EcdsaP256)]
    pub ca_alg: CaAlgArg,

    /// disable TLS interception entirely (implicit passthrough-for-all)
    #[arg(long)]
    pub no_tls_intercept: bool,

    /// authority glob routed through untouched (repeatable)
    #[arg(long = "tls-passthrough")]
    pub tls_passthrough: Vec<String>,

    /// static certificate PEM for downstream reverse-proxy TLS
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// static key PEM for downstream reverse-proxy TLS
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// ca subcommand (default: resolve-or-generate and print paths)
    #[command(subcommand)]
    pub command: Option<CaCommand>,
}

/// clap-facing spelling of [`CaAlg`] (`ecdsa-p256` | `rsa-2048`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CaAlgArg {
    /// ECDSA P-256 (fast handshakes)
    EcdsaP256,
    /// RSA 2048 (legacy-client compatibility)
    Rsa2048,
}

impl From<CaAlgArg> for CaAlg {
    fn from(arg: CaAlgArg) -> Self {
        match arg {
            CaAlgArg::EcdsaP256 => CaAlg::EcdsaP256,
            CaAlgArg::Rsa2048 => CaAlg::Rsa2048,
        }
    }
}

/// `arbiter ca <subcommand>`.
#[derive(Debug, Clone, Subcommand)]
pub enum CaCommand {
    /// Generate the root CA pair if absent (or overwrite with --force)
    Generate {
        /// overwrite an existing CA pair with a fresh one
        #[arg(long)]
        force: bool,

        /// print platform trust-store installation instructions
        #[arg(long)]
        install_hint: bool,
    },
}

/// Entry point mirroring the other commands' `run(args) -> i32` shape.
pub fn run_ca(args: &CaArgs) -> Result<i32> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| Error::other(format!("failed to start tokio runtime: {e}")))?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: &CaArgs) -> Result<i32> {
    let dir = expand_tilde(&args.ca_dir)?;
    let cert_path = args
        .ca_cert
        .clone()
        .unwrap_or_else(|| dir.join(CA_CERT_FILE));
    let key_path = args.ca_key.clone().unwrap_or_else(|| dir.join(CA_KEY_FILE));

    let (force, want_hint) = match &args.command {
        Some(CaCommand::Generate {
            force,
            install_hint,
        }) => (*force, *install_hint),
        None => (false, false),
    };

    if force {
        // Best-effort removal; NotFound simply means nothing to overwrite.
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }

    let existed = cert_path.is_file() && key_path.is_file();
    ensure_ca(&dir, args.ca_alg.into(), &cert_path, &key_path).await?;

    if !existed {
        println!("Generated new root CA ({}).", CaAlg::from(args.ca_alg));
    } else {
        println!("Using existing root CA.");
    }
    println!("CA certificate: {}", cert_path.display());
    println!("CA key:         {}", key_path.display());

    if want_hint {
        println!();
        println!("{}", install_hint());
    }
    Ok(0)
}

/// Expand a leading `~` against $HOME ($USERPROFILE on Windows).
fn expand_tilde(raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("~/").or(trimmed.strip_prefix("~\\")) {
        let home = home_dir()?;
        Ok(home.join(rest))
    } else if trimmed == "~" {
        Ok(home_dir()?)
    } else {
        Ok(PathBuf::from(trimmed))
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            Error::other(
                "cannot resolve home directory\n  help: set $HOME or pass an explicit --ca-dir",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expansion_uses_home() {
        let _env_guard = crate::config::test_support::env_test_lock();
        std::env::set_var("HOME", "/home/tester");
        assert_eq!(
            expand_tilde("~/.arbiter/ca").unwrap(),
            PathBuf::from("/home/tester/.arbiter/ca")
        );
    }

    #[test]
    fn generate_writes_pair_and_honors_explicit_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let cert = tmp.path().join("custom-cert.pem");
        let key = tmp.path().join("custom-key.pem");
        let args = CaArgs {
            ca_cert: Some(cert.clone()),
            ca_key: Some(key.clone()),
            ca_alg: CaAlgArg::EcdsaP256,
            no_tls_intercept: false,
            tls_passthrough: vec![],
            tls_cert: None,
            tls_key: None,
            command: Some(CaCommand::Generate {
                force: false,
                install_hint: true,
            }),
            // Neutral dir: never touches $HOME (parallel tests mutate it).
            ca_dir: tmp.path().join("dir").display().to_string(),
        };
        let code = run_ca(&args).expect("run_ca");
        assert_eq!(code, 0);
        assert!(cert.is_file());
        assert!(key.is_file());

        // Second run loads the existing pair (idempotent).
        let code = run_ca(&args).expect("run_ca again");
        assert_eq!(code, 0);
    }

    #[test]
    fn alg_arg_maps_to_ca_alg() {
        assert_eq!(CaAlg::from(CaAlgArg::EcdsaP256), CaAlg::EcdsaP256);
        assert_eq!(CaAlg::from(CaAlgArg::Rsa2048), CaAlg::Rsa2048);
    }
}
