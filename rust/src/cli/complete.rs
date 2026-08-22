//! `arbiter complete <shell>` — shell completion generation (W7).
//!
//! Uses `clap_complete` (approved dependency) to emit completion scripts for
//! bash, zsh, fish, and PowerShell. The script goes to stdout; a one-line
//! install hint goes to stderr so piping the script to a file is never
//! polluted.
//!
//! # Integration seam (M3d)
//!
//! [`build_cli`] below returns a MINIMAL placeholder root command so that
//! completions are generated and testable before assembly. In the M3d window
//! cli-dx replaces it with the real assembled root (the same
//! `clap::Command` built from `cli::mod`'s derive parser), consuming the typed
//! surfaces from tls-intercept / mock-engine / validate-proxy per AMEND-11.
//! Only [`generate`] + [`build_cli`] are consumed by the `complete`
//! subcommand registration; nothing else here survives assembly.

use std::io::Write;

use clap::Command;
use clap_complete::Shell;

/// Binary name completions are generated for.
pub const BIN_NAME: &str = "arbiter";

/// All shells `arbiter complete` accepts.
pub const SUPPORTED_SHELLS: [Shell; 4] = [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell];

/// Generate completions for `shell` from `cmd` and write them to stdout,
/// followed by one stderr install hint for the shell.
pub fn generate(shell: Shell, cmd: &mut Command) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    generate_into(shell, cmd, &mut stdout)?;
    stdout.flush()?;
    print_install_hint(shell);
    Ok(())
}

/// Testable core: write the completion script for `shell` into `out`.
pub fn generate_into(shell: Shell, cmd: &mut Command, out: &mut dyn Write) -> std::io::Result<()> {
    clap_complete::generate(shell, cmd, BIN_NAME, out);
    Ok(())
}

/// One-line sourcing/install hint per shell (stderr; never pollutes stdout).
pub fn print_install_hint(shell: Shell) {
    let hint = match shell {
        Shell::Bash => {
            "install: save as ~/.local/share/bash-completion/completions/arbiter or `source` it from ~/.bashrc"
        }
        Shell::Zsh => {
            "install: save as \"${fpath[1]}/_arbiter\" (compinit) or `source` it from ~/.zshrc"
        }
        Shell::Fish => {
            "install: save as ~/.config/fish/completions/arbiter.fish"
        }
        Shell::PowerShell => {
            "install: dot-source this script from your $PROFILE"
        }
        _ => "see your shell's completion documentation",
    };
    eprintln!("{hint}");
}

/// SEAM (M3d): placeholder root command. Returns the minimal current root with
/// the subcommands that exist today (`ca`, `mock`, `tui`, `fingerprint`,
/// `config`, `complete`) so generated completions are real and testable now.
/// Replaced by the fully assembled root command during M3d — swap this body,
/// keep the signature.
pub fn build_cli() -> Command {
    Command::new(BIN_NAME)
        .version(crate::version::ARBITER_VERSION)
        .about("API proxy with OpenAPI generation, exact capture/replay, and HAR export")
        .subcommand(
            Command::new("ca").about("Generate and manage the local TLS certificate authority"),
        )
        .subcommand(
            Command::new("mock")
                .about("Serve mocked API responses from captures or an OpenAPI spec"),
        )
        .subcommand(
            Command::new("tui")
                .about("Interactive terminal UI for live or captured flows")
                .arg(
                    clap::Arg::new("port")
                        .short('p')
                        .long("port")
                        .value_name("PORT")
                        .help("Attach to a running arbiter instance on this port"),
                ),
        )
        .subcommand(
            Command::new("fingerprint")
                .about("Classify LLM traffic in a capture bundle and report schema drift")
                .arg(clap::Arg::new("bundle").value_name("BUNDLE_DIR")),
        )
        .subcommand(
            Command::new("config")
                .about("Inspect and initialize the arbiter config file")
                .subcommands([
                    Command::new("init").about("Write a commented starter config.toml"),
                    Command::new("show").about("Print the effective layered configuration as JSON"),
                    Command::new("path").about("Print the resolved config file path"),
                ]),
        )
        .subcommand(
            Command::new("complete")
                .about("Generate shell completions")
                .arg(
                    clap::Arg::new("shell")
                        .value_name("SHELL")
                        .required(true)
                        .value_parser(clap::builder::EnumValueParser::<Shell>::new())
                        .help("Shell to generate completions for"),
                ),
        )
        .subcommand_required(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn generates_non_empty_script_for_all_four_shells() {
        for shell in SUPPORTED_SHELLS {
            let mut buf = Cursor::new(Vec::new());
            generate_into(shell, &mut build_cli(), &mut buf).expect("generation must not fail");
            let script = String::from_utf8(buf.into_inner()).expect("script must be UTF-8");
            assert!(
                !script.trim().is_empty(),
                "{shell:?} produced an empty script"
            );
            assert!(
                script.contains(BIN_NAME),
                "{shell:?} script should reference {BIN_NAME}"
            );
            // Every generated script mentions at least two of our subcommands.
            assert!(
                script.contains("config") && script.contains("fingerprint"),
                "{shell:?} script should cover subcommands"
            );
        }
    }

    #[test]
    fn bash_script_contains_dynamic_completion_loader() {
        let mut buf = Cursor::new(Vec::new());
        generate_into(Shell::Bash, &mut build_cli(), &mut buf).unwrap();
        let script = String::from_utf8(buf.into_inner()).unwrap();
        assert!(
            script.contains("__arbiter") || script.contains("complete "),
            "bash script should register completion: first 200 bytes: {}",
            &script.chars().take(200).collect::<String>()
        );
    }

    #[test]
    fn zsh_script_is_zsh_shaped() {
        let mut buf = Cursor::new(Vec::new());
        generate_into(Shell::Zsh, &mut build_cli(), &mut buf).unwrap();
        let script = String::from_utf8(buf.into_inner()).unwrap();
        assert!(
            script.contains("#compdef"),
            "zsh scripts start with #compdef"
        );
    }

    #[test]
    fn shell_names_parse_for_all_supported_shells() {
        use std::str::FromStr;
        for (name, shell) in [
            ("bash", Shell::Bash),
            ("zsh", Shell::Zsh),
            ("fish", Shell::Fish),
            ("powershell", Shell::PowerShell),
        ] {
            assert_eq!(Shell::from_str(name).ok(), Some(shell), "{name} must parse");
        }
    }

    #[test]
    fn fish_and_powershell_scripts_are_nontrivial() {
        for shell in [Shell::Fish, Shell::PowerShell] {
            let mut buf = Cursor::new(Vec::new());
            generate_into(shell, &mut build_cli(), &mut buf).unwrap();
            let script = String::from_utf8(buf.into_inner()).unwrap();
            assert!(script.lines().count() > 5, "{shell:?} script too small");
        }
    }

    #[test]
    fn placeholder_root_carries_the_six_current_subcommands() {
        let cmd = build_cli();
        for name in ["ca", "mock", "tui", "fingerprint", "config", "complete"] {
            assert!(
                cmd.find_subcommand(name).is_some(),
                "placeholder root lacks `{name}`"
            );
        }
    }

    #[test]
    fn shell_enum_parses_all_documented_names() {
        use std::str::FromStr;
        assert_eq!(Shell::from_str("bash").ok(), Some(Shell::Bash));
        assert_eq!(Shell::from_str("zsh").ok(), Some(Shell::Zsh));
        assert_eq!(Shell::from_str("fish").ok(), Some(Shell::Fish));
        assert_eq!(Shell::from_str("powershell").ok(), Some(Shell::PowerShell));
    }
}
