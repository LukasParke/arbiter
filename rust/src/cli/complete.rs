//! `arbiter complete <shell>` — shell completion generation (W7).
//!
//! Uses `clap_complete` (approved dependency) to emit completion scripts for
//! bash, zsh, fish, and PowerShell. The script goes to stdout; a one-line
//! install hint goes to stderr so piping the script to a file is never
//! polluted.
//!
//! Assembled at M3d: [`build_cli`] returns the REAL root command
//! (`crate::cli::root_command()`), so completions cover every registered
//! subcommand and flag — including the typed surfaces flattened into `start`
//! per AMEND-11.

use std::io::Write;

use clap::Command;
use clap_complete::Shell;

/// Binary name completions are generated for.
pub const BIN_NAME: &str = "arbiter";

/// All shells `arbiter complete` accepts.
pub const SUPPORTED_SHELLS: [Shell; 4] = [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell];

/// `arbiter complete <shell>`
#[derive(Debug, clap::Parser)]
pub struct CompleteArgs {
    /// Shell to generate completions for.
    pub shell: Shell,
}

/// Run the command, returning the process exit code.
pub fn run(args: &CompleteArgs) -> i32 {
    match generate(args.shell, &mut build_cli()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: completion generation failed: {e}");
            eprintln!("  help: check that stdout is writable and retry");
            1
        }
    }
}

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

/// The real root command (M3d assembly): the same `clap::Command` the
/// top-level parser builds, so generated completions always match the live
/// CLI surface.
pub fn build_cli() -> Command {
    crate::cli::root_command()
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
