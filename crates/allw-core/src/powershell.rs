//! Build an [`ActionRecord`] from a **PowerShell** command line: the `command` surface for hosts
//! whose shell tool runs PowerShell (Claude Code's `PowerShell` tool, #298). T1 syntactic substrate
//! only, like [`crate::command`].
//!
//! # Why a separate builder
//!
//! [`crate::command::action_from_command`] tokenizes with POSIX rules ([`shlex`]) and assigns risk
//! with a bash-oriented program table. Neither fits PowerShell exactly: PowerShell quotes and
//! escapes differently (a backtick escape, `''` inside single quotes), and its programs are cmdlets
//! and aliases (`Remove-Item -Recurse -Force`, `rm -r -fo`) the table doesn't know. So this builder
//! keeps what is certain, and **fails upward** on what isn't:
//!
//! - **`raw`** is the exact command string. It is what the human sees (WYSIWYS) and what the
//!   verdict binds to, so it never depends on how the line was split.
//! - **argv**: the POSIX split when the line splits cleanly; otherwise a plain whitespace split, so
//!   a PowerShell line is never rejected for POSIX-only syntax. Either way the tokens are a matching
//!   aid, not a claim about what PowerShell will parse.
//! - **risk** is never below `Medium`, because no part of the table knows PowerShell's low-risk
//!   commands. When the POSIX split failed, it is never below `High`: an uncertain parse fails
//!   upward, as unparseable shell lines do in the command risk analyzer. Above the floor, the
//!   command builder's own risk for the argv applies.
//!
//! The record has no PowerShell marker: the `command` surface and the schema are unchanged.
//! Surfaces label the line for the human in the `ApprovalContext` summary (for example
//! `PowerShell: <command>`).
//!
//! # Known T1 limits
//!
//! - `env_refs` uses the command builder's `$NAME` scan on `raw`, so `$env:PATH` records `env`.
//! - Tokens keep PowerShell's own quoting and escapes when the POSIX split can't apply them.
//!
//! @see docs/policy-seam.md §The three tiers (T1 syntactic substrate)
//! @see https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_quoting_rules

use crate::command::{action_from_argv, CommandContext};
use crate::contract::{ActionRecord, Risk};

/// The risk floor for a PowerShell line that split cleanly: no PowerShell command is known to be
/// low-risk at T1.
pub const POWERSHELL_RISK_FLOOR: Risk = Risk::Medium;

/// The risk floor for a PowerShell line whose POSIX split failed, so its argv is only a whitespace
/// split: an uncertain parse fails upward.
pub const POWERSHELL_UNPARSED_RISK_FLOOR: Risk = Risk::High;

/// Build an [`ActionRecord`] from a raw PowerShell command line. Infallible: a line the POSIX split
/// rejects is still recorded (whitespace argv, `High` floor), never refused.
pub fn action_from_powershell_command(command_line: &str, ctx: &CommandContext) -> ActionRecord {
    let (argv, floor) = match shlex::split(command_line) {
        Some(argv) => (argv, POWERSHELL_RISK_FLOOR),
        None => (
            command_line
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>(),
            POWERSHELL_UNPARSED_RISK_FLOOR,
        ),
    };
    let mut record = action_from_argv(&argv, Some(command_line), ctx);
    record.risk = at_least(record.risk, floor);
    record
}

/// The higher of two risk tiers (`Low < Medium < High < Critical`).
fn at_least(risk: Risk, floor: Risk) -> Risk {
    if rank(risk) >= rank(floor) {
        risk
    } else {
        floor
    }
}

fn rank(risk: Risk) -> u8 {
    match risk {
        Risk::Low => 0,
        Risk::Medium => 1,
        Risk::High => 2,
        Risk::Critical => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::Surface;

    fn ctx(cwd: &str) -> CommandContext {
        CommandContext {
            cwd: Some(cwd.to_string()),
        }
    }

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn a_low_risk_program_is_raised_to_the_medium_floor() {
        // `ls` is Low in the command table, but at T1 no PowerShell command is known to be low-risk.
        let record = action_from_powershell_command("ls", &ctx("C:\\work"));
        assert_eq!(record.surface, Surface::Command);
        assert_eq!(record.risk, Risk::Medium);
        assert_eq!(record.syntactic.raw.as_deref(), Some("ls"));
        assert_eq!(record.syntactic.bin.as_deref(), Some("ls"));
        assert_eq!(record.syntactic.cwd.as_deref(), Some("C:\\work"));
    }

    #[test]
    fn a_cmdlet_the_table_does_not_know_is_medium() {
        let record = action_from_powershell_command(
            "Remove-Item -Recurse -Force build",
            &CommandContext::default(),
        );
        assert_eq!(record.risk, Risk::Medium);
        assert_eq!(
            record.syntactic.argv,
            Some(strings(&["Remove-Item", "-Recurse", "-Force", "build"]))
        );
    }

    #[test]
    fn risk_above_the_floor_is_kept() {
        // The command builder already rates `rm -rf` High; the floor never lowers it.
        let record = action_from_powershell_command("rm -rf build", &CommandContext::default());
        assert_eq!(record.risk, Risk::High);
        let record = action_from_powershell_command("dd if=x of=y", &CommandContext::default());
        assert_eq!(record.risk, Risk::Critical);
    }

    #[test]
    fn a_line_the_posix_split_rejects_is_recorded_with_a_high_floor() {
        // PowerShell escapes a quote with a backtick: `"it`"s"` is the string `it"s`. POSIX sees
        // three double quotes, one of them unmatched.
        let line = "Write-Output \"it`\"s\"";
        let record = action_from_powershell_command(line, &CommandContext::default());
        assert_eq!(record.risk, Risk::High, "an uncertain parse fails upward");
        assert_eq!(
            record.syntactic.raw.as_deref(),
            Some(line),
            "raw is verbatim"
        );
        assert_eq!(
            record.syntactic.argv,
            Some(strings(&["Write-Output", "\"it`\"s\""])),
            "argv falls back to a whitespace split"
        );
    }

    #[test]
    fn the_semantic_tier_stays_empty() {
        let record = action_from_powershell_command("Get-ChildItem", &CommandContext::default());
        assert!(record.capabilities.is_none());
        assert!(record.scope.is_none());
    }
}
