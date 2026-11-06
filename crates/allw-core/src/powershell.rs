//! PowerShell token capture and no-program checks; raw caller text remains authoritative.
//! The raw line remains authoritative; this builder makes no danger or reversibility claim.

use crate::command::{build_argv_record, CommandContext, CommandError};
use crate::contract::ActionRecord;

/// Build an [`ActionRecord`] from a raw PowerShell command line. No PowerShell line is refused for
/// its syntax; the only refusals are for a line that runs no program (#376).
///
/// # Errors
///
/// - [`CommandError::NoCommand`] if the line is blank (empty, or only whitespace).
/// - [`CommandError::NoProgram`] if every statement is empty (only separators or operators) or a
///   variable assigned a literal (`$env:FOO=1`, `$x = 'a'`).
/// - [`CommandError::EmptyProgram`] if the first statement that is neither starts with an empty
///   string (`''`, `& ""`).
///
/// See `check_runs_a_powershell_program` and `docs/policy-seam.md` §Command lines that run no
/// program.
pub fn action_from_powershell_command(
    command_line: &str,
    ctx: &CommandContext,
) -> Result<ActionRecord, CommandError> {
    check_runs_a_powershell_program(command_line)?;
    let argv: Vec<String> = command_line
        .split_whitespace()
        .map(str::to_string)
        .collect();
    Ok(build_argv_record(&argv, Some(command_line), ctx))
}

/// Characters that separate PowerShell statements, pipelines or groups on one line: `;`, `|`,
/// `&` (also the call operator, and `&&` / `||` in pwsh 7) and parentheses. The no-program check
/// splits each line on these into pieces.
const STATEMENT_BREAKS: [char; 5] = [';', '|', '&', '(', ')'];

/// Refuse a PowerShell line that runs no program (#376). Quoting is not interpreted, as everywhere
/// in this module. `raw` is read line by line (split on `\n` and `\r`):
///
/// - a `#` that starts a token begins a comment ([`without_comment`]), which runs to the end of
///   its line and is dropped. Only `#` itself: a `<#` block comment is not recognised, so
///   `<# x #> Remove-Item x` is built, and a bare `<# x #>` line is built too (it then goes to a
///   human; that fails toward asking, never toward allowing);
/// - the rest is split on [`STATEMENT_BREAKS`] and the trimmed pieces are read in order:
///   - an empty piece (only separators or operators) is skipped;
///   - a piece that is a variable assigned a literal ([`is_literal_assignment`]) is skipped;
///   - a piece whose first word is an empty string (`''` or `""`) is
///     [`CommandError::EmptyProgram`];
///   - any other piece may run something: the line is built.
///
/// A line that is blank once comments are dropped (`""`, `"  "`, `# rm -rf x`) is
/// [`CommandError::NoCommand`]; a line of only skipped pieces is [`CommandError::NoProgram`].
///
/// It never refuses a line whose first command word runs. A split inside a quoted string can only
/// leave a piece with an unclosed quote, which is neither skipped nor an empty string, so the line
/// is built. Pieces after the first one that is neither skipped nor built are not examined, so
/// `'' ; Remove-Item x` is refused though PowerShell would run the `Remove-Item`; that refusal is
/// deliberate (a deny, so fail-closed).
fn check_runs_a_powershell_program(raw: &str) -> Result<(), CommandError> {
    let mut has_code = false;
    for line in raw.split(['\n', '\r']) {
        let code = without_comment(line);
        has_code |= !code.trim().is_empty();
        for piece in code.split(STATEMENT_BREAKS).map(str::trim) {
            if piece.is_empty() || is_literal_assignment(piece) {
                continue;
            }
            let first = piece.split_whitespace().next().unwrap_or_default();
            if first == "''" || first == "\"\"" {
                return Err(CommandError::EmptyProgram);
            }
            return Ok(());
        }
    }
    if has_code {
        Err(CommandError::NoProgram)
    } else {
        Err(CommandError::NoCommand)
    }
}

/// `line` up to the first `#` that starts a token: at the line's start, or right after whitespace
/// or a [`STATEMENT_BREAKS`] character. That `#` begins a comment running to the end of the line. A
/// `#` inside a word (`a#b`) or after `<` (`<#`) is kept. A `#` inside a quoted string is cut too;
/// that can only leave a piece with an unclosed quote, which the check never skips, so the line is
/// built.
fn without_comment(line: &str) -> &str {
    let mut at_token_start = true;
    for (i, c) in line.char_indices() {
        if c == '#' && at_token_start {
            return &line[..i];
        }
        at_token_start = c.is_whitespace() || STATEMENT_BREAKS.contains(&c);
    }
    line
}

/// Whether `piece` is exactly a PowerShell variable assigned a literal, which runs nothing:
/// `$NAME = VALUE` (spaces around `=` optional), where `NAME` is letters, digits, `_` and `:`
/// (`env:FOO`) and `VALUE` is a number (`1`, `-2`, `3.5`) or a quoted string with no quote, `$` or
/// backtick inside it (`'a b'`, `"x"`). Anything else (a bareword, which PowerShell runs as a
/// command; an expandable string; a cast; `+=`) is not, so the line is built.
fn is_literal_assignment(piece: &str) -> bool {
    let Some(rest) = piece.strip_prefix('$') else {
        return false;
    };
    let Some((name, value)) = rest.split_once('=') else {
        return false;
    };
    let name = name.trim_end();
    let value = value.trim_start();
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
        && (is_number_literal(value) || is_plain_string_literal(value))
}

/// `-?DIGITS(.DIGITS)?`, the plain numbers [`is_literal_assignment`] accepts.
fn is_number_literal(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    let (whole, fraction) = digits.split_once('.').unwrap_or((digits, "0"));
    !whole.is_empty()
        && !fraction.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && fraction.bytes().all(|b| b.is_ascii_digit())
}

/// Quote characters recognized by the literal-assignment refusal.
const QUOTE_CHARS: [char; 9] = [
    '\'', '"', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}', '\u{201C}', '\u{201D}', '\u{201E}',
];

/// A string in ASCII `'…'` or `"…"` with no quote character ([`QUOTE_CHARS`]), `$` or backtick
/// inside, so it neither expands nor ends early.
fn is_plain_string_literal(value: &str) -> bool {
    let inner = value
        .strip_prefix('\'')
        .and_then(|v| v.strip_suffix('\''))
        .or_else(|| value.strip_prefix('"').and_then(|v| v.strip_suffix('"')));
    inner.is_some_and(|inner| {
        !inner.contains(QUOTE_CHARS) && !inner.contains('$') && !inner.contains('`')
    })
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

    /// Build a line the builder must accept.
    fn build(line: &str, ctx: &CommandContext) -> ActionRecord {
        action_from_powershell_command(line, ctx)
            .unwrap_or_else(|e| panic!("{line:?} must build: {e}"))
    }

    fn refused(line: &str) -> CommandError {
        match action_from_powershell_command(line, &CommandContext::default()) {
            Ok(record) => panic!("{line:?} must be refused, built {record:?}"),
            Err(e) => e,
        }
    }

    // ── Refusal: a line that runs no program (#376) ─────────────────────────

    #[test]
    fn a_blank_line_is_refused_as_no_command() {
        for line in ["", " ", "\t", "\r\n", " \t\r\n ", "\u{a0}"] {
            assert_eq!(refused(line), CommandError::NoCommand, "{line:?}");
        }
    }

    #[test]
    fn a_comment_only_line_is_refused_as_no_command() {
        for line in ["# rm -rf x", "  # Remove-Item x", "# a\n# b", "#"] {
            assert_eq!(refused(line), CommandError::NoCommand, "{line:?}");
        }
    }

    #[test]
    fn a_comment_after_no_program_is_still_no_program() {
        for line in ["$env:FOO=1 # set it", "; # nothing", "$x=1\n# done"] {
            assert_eq!(refused(line), CommandError::NoProgram, "{line:?}");
        }
    }

    /// Only a `#` that starts a piece is a comment, and it ends at the line break: a command after
    /// the break, a block comment, or a `#` inside a word keeps the line.
    #[test]
    fn a_command_beside_a_comment_is_not_refused() {
        for line in [
            "# note\nRemove-Item x",
            "Remove-Item x # why",
            "$x = 'a #b'",
            "$x = 'a #b'; Remove-Item y",
            "<# x #> Remove-Item x",
            "<# x #>",
            "a#b",
        ] {
            assert!(
                action_from_powershell_command(line, &CommandContext::default()).is_ok(),
                "{line:?} may run something"
            );
        }
    }

    /// A later statement after an empty-string program is not examined: the line is refused even
    /// though PowerShell would run the later statement. A deny, so fail-closed (#376).
    #[test]
    fn a_statement_after_an_empty_string_program_is_not_examined() {
        assert_eq!(refused("'' ; Remove-Item x"), CommandError::EmptyProgram);
    }

    #[test]
    fn a_literal_assignment_only_line_is_refused_as_no_program() {
        for line in [
            "$env:FOO=1",
            "$env:FOO = 1",
            "$env:FOO='bar'",
            "$env:FOO = \"bar baz\"",
            "$x = -2.5",
            "$x=1; $y='a'",
            "$x=1;",
        ] {
            assert_eq!(refused(line), CommandError::NoProgram, "{line:?}");
        }
    }

    #[test]
    fn an_operator_only_line_is_refused_as_no_program() {
        for line in [";", ";;", "&&", "||", "|", "&", "()", "; | &", "\n;\n"] {
            assert_eq!(refused(line), CommandError::NoProgram, "{line:?}");
        }
    }

    #[test]
    fn an_empty_string_program_is_refused_as_empty_program() {
        for line in ["''", "\"\"", "'' rm x", "& ''", "& \"\" -Force", "$x=1; ''"] {
            assert_eq!(refused(line), CommandError::EmptyProgram, "{line:?}");
        }
    }

    /// Only a line that runs nothing is refused: a command anywhere, an assignment whose value runs
    /// or expands something, or a string the check can't read keeps the line, which then goes to a
    /// human as before.
    #[test]
    fn a_line_that_may_run_something_is_not_refused() {
        for line in [
            "Get-ChildItem",
            "$env:FOO=1; Remove-Item x",
            "$x = Get-Thing",
            "$x = notepad",
            "$x = $(Remove-Item x)",
            "$x = \"$(Remove-Item x)\"",
            "$x = 'a;Remove-Item x;'",
            "$x = 'it''s'",
            "$x += 1",
            "[int]$x = 1",
            "$x = 1 | Remove-Item",
            "& 'C:\\tools\\x.exe'",
            "Write-Output ''",
            "'a' | Out-File x",
            "> out.txt",
        ] {
            assert!(
                action_from_powershell_command(line, &CommandContext::default()).is_ok(),
                "{line:?} may run something"
            );
        }
    }

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn a_low_risk_program_is_raised_to_the_medium_floor() {
        // `ls` is Low in the command table, but at T1 no PowerShell command is known to be low-risk.
        let record = build("ls", &ctx("C:\\work"));
        assert_eq!(record.surface, Surface::Command);

        assert_eq!(record.syntactic.raw.as_deref(), Some("ls"));
        assert_eq!(record.syntactic.bin.as_deref(), Some("ls"));
        assert_eq!(record.syntactic.cwd.as_deref(), Some("C:\\work"));
    }

    #[test]
    fn a_cmdlet_the_table_does_not_know_is_medium() {
        let record = build(
            "Remove-Item -Recurse -Force build",
            &CommandContext::default(),
        );

        assert_eq!(
            record.syntactic.argv,
            Some(strings(&["Remove-Item", "-Recurse", "-Force", "build"]))
        );
    }

    #[test]
    fn argv_is_a_whitespace_split_that_hides_no_part_of_the_line() {
        // Regression (#316 review B1): in PowerShell `"a\"` is a complete string (`\` is literal), so
        // `;` ends the statement and `Remove-Item` runs. A POSIX split read the whole line as one
        // harmless `echo` argument; a whitespace split keeps `Remove-Item` as its own token.
        let line = r#"echo "a\" ; Remove-Item -Recurse -Force C:\Users ; echo \"b""#;
        let record = build(line, &CommandContext::default());
        assert_eq!(
            record.syntactic.raw.as_deref(),
            Some(line),
            "raw is verbatim"
        );
        assert_eq!(
            record.syntactic.argv,
            Some(strings(&[
                "echo",
                r#""a\""#,
                ";",
                "Remove-Item",
                "-Recurse",
                "-Force",
                r"C:\Users",
                ";",
                "echo",
                r#"\"b""#,
            ]))
        );
    }

    #[test]
    fn windows_paths_keep_their_backslashes() {
        let line = r"Remove-Item C:\Users\me\proj\build -Recurse";
        let record = build(line, &CommandContext::default());
        assert_eq!(
            record.syntactic.argv,
            Some(strings(&[
                "Remove-Item",
                r"C:\Users\me\proj\build",
                "-Recurse"
            ]))
        );
    }
}
