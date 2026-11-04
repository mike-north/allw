//! Build an [`ActionRecord`] from a shell command — T1 syntactic substrate only.
//!
//! This module implements the **syntactic tier (T1)** of the policy-seam
//! (`docs/policy-seam.md §The three tiers`).  It captures **what the human typed** — the
//! exact token stream — without any attempt to infer meaning.  The semantic tier (T3,
//! capability inference) is explicitly deferred; [`ActionRecord::capabilities`] and
//! [`ActionRecord::scope`] are always `None` from this module.
//!
//! # Public API
//!
//! ```rust,ignore
//! // From a raw command string (common case):
//! let record = action_from_command("rm -rf /tmp/scratch", &CommandContext::default())?;
//!
//! // From a pre-tokenized argv (e.g. when the shell has already split arguments):
//! let argv = vec!["git".to_string(), "push".to_string(), "--force".to_string()];
//! let record = action_from_argv(&argv, None, &CommandContext::default())?;
//!
//! // …or a pre-tokenized argv that also carries the original command text, so `raw` (and the
//! // `env_refs` derived from it) are populated without re-tokenizing:
//! let record = action_from_argv(&argv, Some("git push --force"), &CommandContext::default())?;
//! ```
//!
//! # Tokenization
//!
//! [`action_from_command`] uses the [`shlex`] crate for POSIX-compatible word-splitting.
//! This is the same algorithm as Python's `shlex.split()` and handles:
//!
//! - Single-quoted strings: `'hello world'` → one token `hello world`
//! - Double-quoted strings: `"echo hi"` → one token `echo hi` (with `\`-escape processing)
//! - Backslash escapes outside quotes: `hello\ world` → `hello world`
//! - Whitespace as delimiter (any sequence of spaces/tabs)
//!
//! If the shell string is syntactically invalid (unmatched quotes), the tokenization
//! returns an error.  [`action_from_argv`] does not tokenize; it fails only for an argv with no
//! program (empty, an empty program word, or only assignments; #376), as both builders do.
//!
//! # Command lines with shell syntax (risk only)
//!
//! Tokenization only splits words, so `ls && rm -rf /` records `bin: "ls"` and the argv
//! `["ls", "&&", "rm", "-rf", "/"]`. Those fields are unchanged. **Risk**, though, covers the
//! commands a shell would run for the line: [`action_from_command`] also scans the raw line (see
//! § Risk heuristic). [`action_from_argv`] records an argv that runs without a shell, so its words
//! are never read as shell syntax.
//!
//! # Flag classification
//!
//! A token is classified as a **flag** if it begins with `-` (single-dash short options,
//! double-dash long options, combined short flags like `-rf`).  This includes:
//!
//! - Short flags: `-x`, `-rf` (combined)
//! - Long flags: `--force`, `--dry-run`
//! - Long flags with attached values: `--key=value` (classified as a single flag token)
//!
//! The token `--` (POSIX end-of-options separator) is classified as a flag token to
//! preserve it in the flags list; subsequent tokens after `--` are classified as positionals
//! regardless of their leading `-`.
//!
//! # Positional classification
//!
//! Positionals are tokens in `argv[1..]` that are not flags.  For long flags with
//! **separate** value tokens (`--key value`), the value token `value` is classified as a
//! positional because syntactically it is indistinguishable from any other non-flag token
//! at the T1 tier (no per-command schema is available in T1).  Only at T2 (curated-command
//! schemas) or T3 (full semantic inference) would `value` be recognized as a parameter.
//!
//! After a `--` end-of-options separator, all subsequent tokens are positionals regardless
//! of whether they start with `-`.
//!
//! # Host extraction
//!
//! A conservative heuristic extracts the remote host for commands that trivially target one.
//! Only `ssh` and `scp` are recognized; every other command returns `None`.
//!
//! - `ssh`: the first positional containing `@` → the part after `@` (e.g. `user@host` →
//!   `host`); otherwise the first positional that contains `.` and starts with neither `/`
//!   nor `.` (a bare hostname, not a path).
//! - `scp`: the first positional that does not start with `/` and contains `:` → the part
//!   before `:` (the `host` of `host:path`).
//!
//! This is intentionally conservative: over-inferring the host would produce noisy,
//! incorrect data.
//!
//! # Environment variable references
//!
//! The command string is scanned for shell variable references of the forms `$VAR` and
//! `${VAR}`.  Only the variable **name** is captured; values are never read.  This is a
//! purely textual scan — a hand-rolled scanner (no `regex` dependency) equivalent to the
//! pattern `\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?` walks the raw command string before
//! tokenization.  Names are deduplicated and returned in first-seen order.
//!
//! # Risk heuristic (v1)
//!
//! A coarse, documented heuristic assigns a [`Risk`] tier.  This is a v1 placeholder;
//! `docs/policy-seam.md §The three tiers` states that T3 will derive risk from capabilities.
//!
//! The rules live in the private `command/risk.rs` module, whose module doc is the reference: the
//! program table, how the program that actually runs is found (assignments, wrappers, shells with
//! `-c`, `eval`), how a command line is scanned (operators, substitutions, heredocs), the bounds
//! (all failing upward to `High`), and the known T1 limits. The table, in short:
//!
//! | Risk       | Matched commands / flags                                                      |
//! |------------|-------------------------------------------------------------------------------|
//! | `Critical` | `dd`, `mkfs`, `mkfs.*`, `fdisk`, `parted`, `shred`                           |
//! | `High`     | `rm` recursive+force, `git push` with a force flag, `chmod -R`, `sudo`, `doas`, `run0`, `pkexec`, `su` |
//! | `Low`      | `ls`, `cat`, `echo`, `pwd`, `whoami`, `date`, `env`, `printenv`, `which`     |
//! | `Medium`   | everything else                                                               |
//!
//! Only `risk` follows what really runs. `bin` / `argv` / `flags` / `positionals` / `env_refs`
//! stay `argv[0]`-based, so policy matching (which keys on `bin`) is unchanged; see
//! `docs/policy-seam.md` §v1 command risk.

use crate::contract::{ActionRecord, Risk, Surface, SyntacticSubstrate};
use std::collections::HashSet;

mod risk;

// ── Record schema version ─────────────────────────────────────────────────────

/// The `record_schema_version` stamped on every `ActionRecord` built by this module.
///
/// This matches the value used in the existing contract tests (see `contract.rs`).
pub const RECORD_SCHEMA_VERSION: u32 = 1;

// ── CommandContext ────────────────────────────────────────────────────────────

/// Non-derivable context that accompanies a shell command.
///
/// Values that can be inferred from the command string itself (tokens, flags, etc.) are
/// derived by the builder; values that must be supplied by the caller are here.
#[derive(Debug, Clone, Default)]
pub struct CommandContext {
    /// The working directory at the time of invocation.
    ///
    /// `None` means the cwd is unknown (e.g. the caller didn't capture it).
    pub cwd: Option<String>,
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors that can occur when building an [`ActionRecord`] from a command string.
///
/// Every variant is a **refusal**: the caller must deny (fail-closed), never ask a human to approve
/// the line. The last three are the "no program" refusals (#376): a line that runs nothing a human
/// could meaningfully approve is refused here, in the core, so every surface inherits the refusal
/// (`docs/policy-seam.md` §Command lines that run no program).
#[derive(Debug, PartialEq)]
pub enum CommandError {
    /// The command string has unmatched quotes or other shell-tokenization errors.
    ///
    /// Use [`action_from_argv`] if you already have a pre-tokenized argv.
    InvalidShellSyntax,
    /// The line holds no words at all: empty, whitespace only, or only a comment.
    NoCommand,
    /// The line has words, but none of them is a program: only variable assignments (`FOO=1`)
    /// and/or shell control operators (`;`, `&&`, `|`, …).
    NoProgram,
    /// The line's first program word is the empty string (`''`, `'' rm -rf x`, `FOO=1 "" ls`).
    EmptyProgram,
}

impl CommandError {
    /// A stable, machine-readable code for the refusal. Surfaces classify on this, never on the
    /// human-readable message (the WASM binding exposes it as the thrown error's `kind`).
    pub fn code(&self) -> &'static str {
        match self {
            CommandError::InvalidShellSyntax => "invalid_shell_syntax",
            CommandError::NoCommand => "no_command",
            CommandError::NoProgram => "no_program",
            CommandError::EmptyProgram => "empty_program",
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::InvalidShellSyntax => {
                write!(
                    f,
                    "command string has unmatched quotes or invalid shell syntax"
                )
            }
            CommandError::NoCommand => write!(f, "command line contains no command"),
            CommandError::NoProgram => write!(
                f,
                "command line runs no program (only variable assignments or shell operators)"
            ),
            CommandError::EmptyProgram => {
                write!(f, "command line's first program word is empty")
            }
        }
    }
}

impl std::error::Error for CommandError {}

// ── Public builders ───────────────────────────────────────────────────────────

/// Build an [`ActionRecord`] from a raw shell command string.
///
/// The string is tokenized using POSIX word-splitting (via [`shlex`]).
///
/// # Errors
///
/// - [`CommandError::InvalidShellSyntax`] if the string has unmatched quotes or other
///   tokenization errors.
/// - [`CommandError::NoCommand`] if it is blank (empty, or only whitespace by Unicode's
///   definition) or tokenizes to no words (only a comment).
/// - [`CommandError::NoProgram`] if every word is a variable assignment or a control operator.
/// - [`CommandError::EmptyProgram`] if the first program word is the empty string.
///
/// The last three are checked by `check_runs_a_program` on the tokens; see
/// `docs/policy-seam.md` §Command lines that run no program.
///
/// # Examples
///
/// ```rust,ignore
/// let ctx = CommandContext { cwd: Some("/home/user".to_string()) };
/// let record = action_from_command("rm -rf /tmp/scratch", &ctx)?;
/// ```
pub fn action_from_command(
    command_line: &str,
    ctx: &CommandContext,
) -> Result<ActionRecord, CommandError> {
    // A line that is blank to the eye is refused before tokenizing. `shlex` (like bash) does not
    // split on every whitespace character (`\r`, U+00A0), so a "blank" line could otherwise tokenize
    // to a word made only of whitespace, which a human would see as nothing.
    if command_line.trim().is_empty() {
        return Err(CommandError::NoCommand);
    }
    let argv = shlex::split(command_line).ok_or(CommandError::InvalidShellSyntax)?;
    // Refuse a line that runs no program before building anything: a human must never be asked to
    // approve nothing (#376).
    check_runs_a_program(&argv)?;
    // A command line can hold more than one command (`ls && rm -rf /`). `bin` / `argv` / `flags`
    // / `positionals` still describe the word list, but risk covers every command a shell would
    // run (`risk` module).
    let risk = risk::command_line_risk(command_line, &argv);
    Ok(build_record(
        argv,
        ctx,
        Some(command_line.to_string()),
        risk,
    ))
}

/// Build an [`ActionRecord`] from a pre-tokenized argument vector, optionally carrying the
/// original command text.
///
/// This is the variant for callers that have already split the command into tokens (e.g.
/// received from a shell hook, a process execution API, or an agent runtime that stores a
/// canonical execution plan). Such callers **must not** re-tokenize their own command text:
/// re-parsing risks binding a different token vector than the one that actually executes
/// (`docs/openclaw-integration.md` §5.1).
///
/// `raw` is the original command string as the upstream gate renders it, when the caller has one.
/// It is recorded verbatim in [`SyntacticSubstrate::raw`] and is the **only** source the builder
/// extracts `env_refs` from — passing `None` therefore also yields `env_refs: None`, since a token
/// vector has already had its `$VAR` references resolved by whatever produced it.
///
/// # Errors
///
/// It refuses an argv with no program to show the human (#376), whatever `raw` says:
///
/// - [`CommandError::NoCommand`] for an empty `argv`;
/// - [`CommandError::EmptyProgram`] when the first word that is not a pure assignment is `""`
///   (`[""]`, `["", "rm", "-rf", "x"]`, `["FOO=1", ""]`);
/// - [`CommandError::NoProgram`] when every word is a pure assignment (`["FOO=1"]`).
///
/// The words are never read as shell syntax: an operator word (`["&&"]`) is a program name, so it
/// is built. Assignments are recognised as the line builder recognises them (a shell-identifier name,
/// [`is_assignment_name`]), even though an argv runs without a shell, where `FOO=1` would be a
/// program name: no real program is named like an assignment, so refusing it fails closed and keeps
/// both builders consistent. (The risk rules use a wider, first-character test; see
/// `risk::is_assignment_like`.) See `docs/policy-seam.md` §Command lines that run no program.
///
/// # Examples
///
/// ```rust,ignore
/// let argv = vec!["git".to_string(), "push".to_string()];
/// let record = action_from_argv(&argv, None, &CommandContext::default())?;
/// let bound = action_from_argv(&argv, Some("git push"), &CommandContext::default())?;
/// ```
pub fn action_from_argv(
    argv: &[String],
    raw: Option<&str>,
    ctx: &CommandContext,
) -> Result<ActionRecord, CommandError> {
    check_argv_has_a_program(argv)?;
    Ok(build_argv_record(argv, raw, ctx))
}

/// [`action_from_argv`] without the no-program check, for a builder that has already done its own
/// (the PowerShell builder, whose whitespace tokens are not POSIX words).
pub(crate) fn build_argv_record(
    argv: &[String],
    raw: Option<&str>,
    ctx: &CommandContext,
) -> ActionRecord {
    // The argv runs without a shell, so `raw` is display text and is not read for risk.
    let risk = risk::argv_risk(argv);
    build_record(argv.to_vec(), ctx, raw.map(str::to_string), risk)
}

// ── No-program refusal ───────────────────────────────────────────────────────

/// The characters bash reads as (part of) a control operator: `;`, `&`, `|`, `(`, `)`. A tokenized
/// word is split on these to find what it holds, because `shlex` keeps `FOO=1;ls` as one word.
const CONTROL_OPERATOR_CHARS: [char; 5] = [';', '&', '|', '(', ')'];

/// Characters that make an assignment word run something or touch a file: a command or process
/// substitution (`` ` ``, `$(`, `<(`, `>(`) or a redirection (`<`, `>`). A word containing one is
/// never a *pure* assignment, so a line holding it is not refused as running no program.
const ASSIGNMENT_EFFECT_CHARS: [char; 3] = ['`', '<', '>'];

/// Is `piece` a pure shell variable assignment (`NAME=value`, `NAME+=value`, `A[0]=value`), one
/// that runs nothing? The name must be a shell identifier (`[A-Za-z_][A-Za-z0-9_]*`), optionally
/// followed by a `[…]` subscript, then `=` or `+=` (#391); the value must hold no
/// [`ASSIGNMENT_EFFECT_CHARS`] (`$(` and `<(` are already split apart on their `(`). So a piece
/// holding a command with an `=` in it (`git log --format=%H`, split out of `$( … )`) is a
/// program, not an assignment.
fn is_pure_assignment(piece: &str) -> bool {
    piece
        .split_once('=')
        .is_some_and(|(name, _)| is_assignment_name(name))
        && !piece.contains(ASSIGNMENT_EFFECT_CHARS)
}

/// Is `name` (the text before an assignment's first `=`) a shell identifier, optionally followed by
/// one `[…]` subscript whose body holds no `[` or `]`, and then a `+` (for `+=`)? `X`, `_x1`, `A[0]`,
/// `X+`, `A[i]+` are; `nice -n 1 dd if`, `FO-O`, `1X`, `A[0`, `A[a]b]`, `A[]]` and `` are not (bash
/// runs each of those as a command).
///
/// This is deliberately narrower than the risk rules' `is_assignment_like` (first character only):
/// refusing must never catch a word bash runs as a command, while risk over-matching only raises the
/// tier.
fn is_assignment_name(name: &str) -> bool {
    let name = name.strip_suffix('+').unwrap_or(name);
    let (ident, subscript) = match name.find('[') {
        Some(open) => (&name[..open], Some(&name[open..])),
        None => (name, None),
    };
    let mut bytes = ident.bytes();
    bytes.next().is_some_and(is_ident_start)
        && bytes.all(is_ident_cont)
        && subscript.is_none_or(|s| {
            s.len() >= 2 && s.ends_with(']') && !s[1..s.len() - 1].contains(['[', ']'])
        })
}

/// Refuse a tokenized command line that runs no program (#376):
///
/// - no words at all → [`CommandError::NoCommand`];
/// - the first word that is not a pure assignment or a control operator is the empty string →
///   [`CommandError::EmptyProgram`];
/// - no such word → [`CommandError::NoProgram`].
///
/// Each word is split on [`CONTROL_OPERATOR_CHARS`]; an empty piece (an operator) or a
/// [pure assignment](is_pure_assignment) is skipped, and any other piece is a program. This reads
/// the tokens only; it does not change them or the record.
///
/// It never refuses a line whose first command word runs: a program word, a substitution or a
/// redirection (such as `> f`) leaves a piece that is not skipped, so the line is built and goes to
/// a human as before. It can refuse a line where the shell would still run something, and that is
/// deliberate (a deny, so fail-closed):
///
/// - only the words up to the first program word are read, so a later segment after an empty
///   program word is not examined (`'' || rm -rf x`, `'' ; rm -rf x` are refused);
/// - `shlex` removes quotes, so a quoted operator or assignment (`';'`, `'FOO=1'`) is read as
///   unquoted, though bash runs it as a program name.
fn check_runs_a_program(argv: &[String]) -> Result<(), CommandError> {
    if argv.is_empty() {
        return Err(CommandError::NoCommand);
    }
    for word in argv {
        if word.is_empty() {
            return Err(CommandError::EmptyProgram);
        }
        let runs_something = word
            .split(CONTROL_OPERATOR_CHARS)
            .any(|piece| !piece.is_empty() && !is_pure_assignment(piece));
        if runs_something {
            return Ok(());
        }
    }
    Err(CommandError::NoProgram)
}

/// Refuse an argv with no program (#376), the [`action_from_argv`] rules: empty →
/// [`CommandError::NoCommand`]; leading [pure assignments](is_pure_assignment) skipped, then `""` →
/// [`CommandError::EmptyProgram`]; only assignments → [`CommandError::NoProgram`]. Words are not
/// split on operators: an argv runs without a shell.
fn check_argv_has_a_program(argv: &[String]) -> Result<(), CommandError> {
    if argv.is_empty() {
        return Err(CommandError::NoCommand);
    }
    match argv.iter().find(|word| !is_pure_assignment(word)) {
        Some(word) if word.is_empty() => Err(CommandError::EmptyProgram),
        Some(_) => Ok(()),
        None => Err(CommandError::NoProgram),
    }
}

// ── Core builder ─────────────────────────────────────────────────────────────

/// Assemble the record for `argv`. `risk` is computed by the caller, because only the caller knows
/// whether a shell runs the line (`risk::command_line_risk`) or not (`risk::argv_risk`).
fn build_record(
    argv: Vec<String>,
    ctx: &CommandContext,
    raw: Option<String>,
    risk: Risk,
) -> ActionRecord {
    let bin = argv.first().cloned().unwrap_or_default();
    let (flags, positionals) = split_flags_and_positionals(&argv);
    let env_refs = raw.as_deref().map(extract_env_refs).unwrap_or_default();
    let env_refs_opt = if env_refs.is_empty() {
        None
    } else {
        Some(env_refs)
    };

    let host = extract_host(&bin, &positionals);

    let bin_opt = if argv.is_empty() {
        None
    } else {
        Some(bin.clone())
    };
    let argv_opt = if argv.is_empty() { None } else { Some(argv) };
    let flags_opt = if flags.is_empty() { None } else { Some(flags) };
    let positionals_opt = if positionals.is_empty() {
        None
    } else {
        Some(positionals)
    };

    ActionRecord {
        record_schema_version: RECORD_SCHEMA_VERSION,
        surface: Surface::Command,
        syntactic: SyntacticSubstrate {
            bin: bin_opt,
            argv: argv_opt,
            flags: flags_opt,
            positionals: positionals_opt,
            cwd: ctx.cwd.clone(),
            host,
            env_refs: env_refs_opt,
            server: None,
            tool: None,
            params: None,
            operation: None,
            paths: None,
            diff_summary: None,
            diff_hash: None,
            raw,
        },
        risk,
        capabilities: None,
        scope: None,
    }
}

// ── Flag / positional splitting ───────────────────────────────────────────────

/// Split `argv[1..]` into (flags, positionals).
///
/// Classification rules (see module-level doc):
/// - Any token starting with `-` is a flag, INCLUDING `--`.
/// - After `--`, all subsequent tokens are positionals (POSIX end-of-options).
/// - Everything else (including values after `--key value` flags) is a positional.
fn split_flags_and_positionals(argv: &[String]) -> (Vec<String>, Vec<String>) {
    let mut flags = Vec::new();
    let mut positionals = Vec::new();
    let mut end_of_options = false;

    for token in argv.iter().skip(1) {
        if end_of_options {
            positionals.push(token.clone());
        } else if token == "--" {
            flags.push(token.clone());
            end_of_options = true;
        } else if token.starts_with('-') {
            flags.push(token.clone());
        } else {
            positionals.push(token.clone());
        }
    }

    (flags, positionals)
}

// ── Environment variable extraction ──────────────────────────────────────────

/// Extract the names of environment variables referenced in `cmd`.
///
/// Recognizes `$VAR` and `${VAR}` patterns.  Names are returned in first-seen order,
/// deduplicated.  Values are never captured.
fn extract_env_refs(cmd: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let bytes = cmd.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' {
            i += 1;
            // ${VAR} form
            let braced = i < bytes.len() && bytes[i] == b'{';
            if braced {
                i += 1; // skip '{'
            }
            // Collect identifier: [A-Za-z_][A-Za-z0-9_]*
            let start = i;
            if i < bytes.len() && is_ident_start(bytes[i]) {
                while i < bytes.len() && is_ident_cont(bytes[i]) {
                    i += 1;
                }
                let name = &cmd[start..i];
                if braced {
                    // expect closing '}'
                    if i < bytes.len() && bytes[i] == b'}' {
                        i += 1;
                    }
                    // malformed ${... without closing brace: still captured the name
                }
                if seen.insert(name.to_string()) {
                    result.push(name.to_string());
                }
            }
            // If the char after $ is not an identifier start, skip the $ and continue
        } else {
            i += 1;
        }
    }

    result
}

#[inline]
fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

#[inline]
fn is_ident_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ── Host extraction ───────────────────────────────────────────────────────────

/// Extract the remote host from commands that trivially target one.
///
/// Only `ssh` and `scp` are handled; all other commands return `None`.
/// See module-level doc for the exact rules.
fn extract_host(bin: &str, positionals: &[String]) -> Option<String> {
    let base = basename(bin);
    match base {
        "ssh" => extract_ssh_host(positionals),
        "scp" => extract_scp_host(positionals),
        _ => None,
    }
}

/// For `ssh`: first positional containing `@` → take the part after `@`.
/// If none contain `@`, take the first positional that looks like a hostname
/// (contains `.`, is not a path starting with `/`).
fn extract_ssh_host(positionals: &[String]) -> Option<String> {
    // Prefer user@host form
    for p in positionals {
        if let Some(at_pos) = p.find('@') {
            let host = &p[at_pos + 1..];
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
    }
    // Fall back to bare hostname: first positional with a dot that is not a path
    for p in positionals {
        if !p.starts_with('/') && !p.starts_with('.') && p.contains('.') {
            return Some(p.clone());
        }
    }
    None
}

/// For `scp`: scan positionals for `host:path`; return the `host` part.
/// Skips tokens that begin with `/` (local absolute paths).
fn extract_scp_host(positionals: &[String]) -> Option<String> {
    for p in positionals {
        if p.starts_with('/') {
            continue;
        }
        if let Some(colon_pos) = p.find(':') {
            let host = &p[..colon_pos];
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
    }
    None
}

/// Returns the final component of a path-like string (basename).
/// Used to normalize `bin` before pattern matching, e.g. `/usr/bin/rm` → `rm`.
fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ─────────────────────────────────────────────────────────

    /// Default context with a fixed cwd for determinism.
    fn ctx_with_cwd() -> CommandContext {
        CommandContext {
            cwd: Some("/home/user/repo".to_string()),
        }
    }

    fn ctx_no_cwd() -> CommandContext {
        CommandContext { cwd: None }
    }

    /// Unwrap the flags list from an ActionRecord; panics with a message if None.
    fn flags(r: &ActionRecord) -> Vec<String> {
        r.syntactic.flags.clone().unwrap_or_default()
    }

    /// Unwrap the positionals list from an ActionRecord; panics with a message if None.
    fn positionals(r: &ActionRecord) -> Vec<String> {
        r.syntactic.positionals.clone().unwrap_or_default()
    }

    fn bin(r: &ActionRecord) -> String {
        r.syntactic.bin.clone().unwrap_or_default()
    }

    fn argv(r: &ActionRecord) -> Vec<String> {
        r.syntactic.argv.clone().unwrap_or_default()
    }

    // ── Required test cases (from issue spec) ────────────────────────────────

    /// T1 rule: `bin` == argv[0] as-given.
    /// T1 rule: `-rf` is a single combined short-flag token (not split into `-r`, `-f`).
    ///   Classification rationale: shlex treats `-rf` as one token; at T1 we do not
    ///   expand combined flags. The risk heuristic inspects character membership inside
    ///   the combined token to detect `-rf` (see `combined_short_flags`).
    /// T1 rule: positionals are non-flag tokens after argv[0].
    /// Risk: `rm` with recursive+force flags → `Risk::High` (module doc table).
    #[test]
    fn rm_rf_slash_x() {
        let r = action_from_command("rm -rf /x", &ctx_no_cwd()).unwrap();

        // bin: argv[0] as-given (T1 rule)
        assert_eq!(bin(&r), "rm", "bin must be argv[0]");

        // argv: full token vector
        assert_eq!(
            argv(&r),
            vec!["rm", "-rf", "/x"],
            "argv must be the full token vector"
        );

        // flags: `-rf` is a single combined short-flag token at T1 (shlex does not split it)
        assert!(
            flags(&r).contains(&"-rf".to_string()),
            "flags must contain the combined token `-rf` (T1 does not expand combined flags)"
        );

        // positionals: non-flag tokens after argv[0]
        assert_eq!(
            positionals(&r),
            vec!["/x"],
            "positionals must be non-flag tokens after argv[0]"
        );

        // risk: rm + recursive + force → High (module doc table: `rm -rf` → High)
        assert_eq!(
            r.risk,
            Risk::High,
            "rm -rf must be classified as Risk::High (recursive+force heuristic)"
        );

        // reserved fields: T1 guarantee
        assert!(r.capabilities.is_none(), "capabilities must be None in T1");
        assert!(r.scope.is_none(), "scope must be None in T1");
    }

    /// `git push` — no flags, single positional, deterministic.
    #[test]
    fn git_push_no_flags() {
        let r = action_from_command("git push", &ctx_no_cwd()).unwrap();

        assert_eq!(bin(&r), "git");
        assert_eq!(argv(&r), vec!["git", "push"]);
        // no flags
        assert!(
            r.syntactic.flags.is_none() || r.syntactic.flags.as_ref().unwrap().is_empty(),
            "git push has no flags"
        );
        // "push" is a positional (not a flag)
        assert_eq!(positionals(&r), vec!["push"]);

        // plain git push without --force → Medium
        assert_eq!(r.risk, Risk::Medium);

        assert!(r.capabilities.is_none());
        assert!(r.scope.is_none());
    }

    /// `curl https://example.com -d @f`
    ///
    /// T1 flag rule: `-d` starts with `-` → flag.
    /// T1 positional rule: `https://example.com` does not start with `-` → positional.
    /// `@f` does not start with `-` → positional.
    ///
    /// Note (T1 limitation): `-d` and `@f` are adjacent as flag+value, but at T1 (no
    /// per-command schema) the value token is indistinguishable from a positional.  Both
    /// are captured as positionals when they appear as non-flag tokens.  The `-d` flag is
    /// recorded in flags; `@f` appears in positionals.
    #[test]
    fn curl_with_data_flag() {
        let r = action_from_command("curl https://example.com -d @f", &ctx_no_cwd()).unwrap();

        assert_eq!(bin(&r), "curl");

        // `-d` is a flag (starts with `-`)
        assert!(
            flags(&r).contains(&"-d".to_string()),
            "flags must contain `-d`"
        );

        // `https://example.com` does not start with `-` → positional
        assert!(
            positionals(&r).contains(&"https://example.com".to_string()),
            "positionals must contain the URL"
        );

        // `@f` does not start with `-` → positional (T1: value token indistinguishable
        // from positional without a per-command schema)
        assert!(
            positionals(&r).contains(&"@f".to_string()),
            "positionals must contain `@f` (T1: no schema to identify it as `-d`'s value)"
        );

        // reserved fields
        assert!(r.capabilities.is_none());
        assert!(r.scope.is_none());
    }

    // ── Determinism ──────────────────────────────────────────────────────────

    /// Same input → identical ActionRecord output (determinism guarantee).
    #[test]
    fn same_input_produces_identical_records() {
        let cmd = "git push --force origin main";
        let ctx = ctx_with_cwd();
        let r1 = action_from_command(cmd, &ctx).unwrap();
        let r2 = action_from_command(cmd, &ctx).unwrap();
        assert_eq!(r1, r2, "action_from_command must be deterministic");
    }

    // ── Quoting ──────────────────────────────────────────────────────────────

    /// A double-quoted argument is tokenized as a single positional by shlex.
    /// Rule: `"echo hi"` after `sh -c` → argv[2] is the single token `echo hi`.
    #[test]
    fn quoted_arg_tokenized_as_single_token() {
        let r = action_from_command(r#"sh -c "echo hi""#, &ctx_no_cwd()).unwrap();

        assert_eq!(bin(&r), "sh");
        assert!(
            flags(&r).contains(&"-c".to_string()),
            "flags must contain `-c`"
        );
        // "echo hi" (with the quotes stripped by shlex) should be a single positional
        assert!(
            positionals(&r).contains(&"echo hi".to_string()),
            "quoted string must be a single positional token (shlex strips quotes)"
        );
    }

    // ── env_refs ─────────────────────────────────────────────────────────────

    /// `echo $HOME ${AWS_PROFILE}` → env_refs contains exactly ["HOME", "AWS_PROFILE"]
    /// (names only, in first-seen order, deduplicated).
    #[test]
    fn env_refs_extracted_from_dollar_syntax() {
        let r = action_from_command("echo $HOME ${AWS_PROFILE}", &ctx_no_cwd()).unwrap();

        let env_refs = r.syntactic.env_refs.as_deref().unwrap_or(&[]);
        assert_eq!(
            env_refs,
            &["HOME", "AWS_PROFILE"],
            "env_refs must contain variable names in first-seen order, deduplicated"
        );
    }

    /// Duplicate references are deduplicated; order is first-seen.
    #[test]
    fn env_refs_deduplicated() {
        let r = action_from_command("cp $HOME/a $HOME/b", &ctx_no_cwd()).unwrap();

        let env_refs = r.syntactic.env_refs.as_deref().unwrap_or(&[]);
        assert_eq!(env_refs, &["HOME"], "duplicate $HOME must appear only once");
    }

    // ── Reserved fields (T1 guarantee) ───────────────────────────────────────

    /// capabilities and scope MUST be None for all records produced by this module.
    #[test]
    fn reserved_fields_always_none() {
        let commands = [
            "rm -rf /",
            "git push",
            "curl https://example.com",
            "sudo bash",
            "ls -la",
        ];
        for cmd in &commands {
            let r = action_from_command(cmd, &ctx_no_cwd()).unwrap();
            assert!(
                r.capabilities.is_none(),
                "capabilities must be None for `{cmd}` (T1 guarantee)"
            );
            assert!(
                r.scope.is_none(),
                "scope must be None for `{cmd}` (T1 guarantee)"
            );
        }
    }

    // ── Serde round-trip ─────────────────────────────────────────────────────

    /// A built ActionRecord must survive a JSON round-trip.
    #[test]
    fn action_record_serde_round_trip() {
        let r = action_from_command("rm -rf /tmp/scratch", &ctx_with_cwd()).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        let back: ActionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back, "ActionRecord must survive a serde JSON round-trip");
    }

    // ── Refusal: a line that runs no program (#376) ─────────────────────────

    /// Builds `line` and asserts the core refuses it with `expected` — no record is produced, so no
    /// surface can ask a human to approve it.
    fn assert_refused(line: &str, expected: CommandError) {
        assert_eq!(
            action_from_command(line, &ctx_no_cwd()),
            Err(expected),
            "{line:?} must be refused"
        );
    }

    #[test]
    fn empty_command_string_is_refused_as_no_command() {
        assert_refused("", CommandError::NoCommand);
    }

    #[test]
    fn whitespace_only_command_is_refused_as_no_command() {
        for line in [
            " ",
            "   ",
            "\t",
            "\n",
            "\r",
            " \t\r\n ",
            "\u{a0}",
            "\u{2003}\u{3000}",
        ] {
            assert_refused(line, CommandError::NoCommand);
        }
    }

    #[test]
    fn comment_only_command_is_refused_as_no_command() {
        assert_refused("# rm -rf /", CommandError::NoCommand);
    }

    #[test]
    fn assignment_only_command_is_refused_as_no_program() {
        for line in [
            "FOO=1",
            "FOO=",
            "FOO=1 BAR=2",
            "_X=1",
            "X+=1",
            "A[0]=1",
            "FOO=$BAR",
            "FOO=1;",
            "FOO=1 && BAR=2",
        ] {
            assert_refused(line, CommandError::NoProgram);
        }
    }

    #[test]
    fn operator_only_command_is_refused_as_no_program() {
        for line in [";", "&&", "||", "|", "&", ";;", "( )", "; && |", "&&&"] {
            assert_refused(line, CommandError::NoProgram);
        }
    }

    #[test]
    fn empty_program_word_is_refused_as_empty_program() {
        for line in [
            "''",
            "\"\"",
            "'' rm -rf x",
            "\"\" ls",
            "FOO=1 '' rm -rf x",
            "&& '' rm",
            "FOO=1; \"\"",
        ] {
            assert_refused(line, CommandError::EmptyProgram);
        }
    }

    /// The refusal reads only what runs nothing: a line with a program word, a substitution or a
    /// redirection anywhere is still built (and goes to a human), never refused.
    #[test]
    fn a_line_that_runs_something_is_not_refused() {
        for line in [
            "ls",
            "FOO=1 ls",
            "FOO=1; ls",
            "FOO=1;ls",
            "FOO=1 && rm -rf x",
            "ls ''",
            "FOO=$(rm -rf ~)",
            "FOO=$(id)",
            "FOO=`id`",
            "FOO=<(id)",
            "> out.txt",
            "FOO=1 >out.txt",
            "2>&1",
            "!",
            "=1",
        ] {
            let result = action_from_command(line, &ctx_no_cwd());
            assert!(result.is_ok(), "{line:?} runs something: {result:?}");
        }
    }

    // ── #391: a command with an `=` inside `$( … )` is not an assignment ────────

    /// Regression for #391: `$( … )` is split out of an assignment on its parentheses, and the
    /// command inside it holds an `=` (`--format=%H`). Its "name" (`git log --format`) is not a shell
    /// identifier, so it is a program and the line is built, not refused as `no_program`.
    #[test]
    fn issue_391_substitution_with_an_equals_sign_is_not_refused() {
        for line in [
            r#"VERSION="$(git log --format=%H -1)""#,
            r#"x="$(nice -n 1 dd if=/dev/zero of=/dev/sda)""#,
            "x=$(env A=1 ls)",
            "x=`git log --format=%H -1`",
        ] {
            let result = action_from_command(line, &ctx_no_cwd());
            assert!(result.is_ok(), "{line:?} runs a program: {result:?}");
        }
    }

    /// Regression for #391: the substitution's command keeps its risk once the line is built; the
    /// inner `dd of=/dev/sda` is Critical.
    #[test]
    fn issue_391_substitution_with_dd_inside_an_assignment_is_critical() {
        let r = action_from_command(
            r#"x="$(nice -n 1 dd if=/dev/zero of=/dev/sda)""#,
            &ctx_no_cwd(),
        )
        .unwrap();
        assert_eq!(r.risk, Risk::Critical);
    }

    /// Regression for #391: genuine all-assignment lines are still refused as `no_program`.
    #[test]
    fn issue_391_genuine_assignments_are_still_refused() {
        for line in [
            "X=1",
            "A=1 B=2",
            "A[0]=1",
            "X+=y",
            "A[i]+=1",
            "_x1=v",
            "FOO='a b'",
        ] {
            assert_refused(line, CommandError::NoProgram);
        }
    }

    /// Regression for #391: a name that is not a shell identifier (with an optional `[…]`) is a
    /// program word, so the line is built.
    #[test]
    fn issue_391_a_non_identifier_name_is_not_an_assignment() {
        for line in [
            "FO-O=1", "1X=1", "A[0=1", "A]=1", "A[0]x=1", "X++=1", "=1", "A[a]b]=1", "A[]]=1",
            "A[a]]=1", "A[x]]+=1",
        ] {
            let result = action_from_command(line, &ctx_no_cwd());
            assert!(result.is_ok(), "{line:?} is not an assignment: {result:?}");
        }
        for name in ["X", "_x1", "A[0]", "X+", "A[i]+"] {
            assert!(is_assignment_name(name), "{name:?}");
        }
        for name in [
            "",
            "nice -n 1 dd if",
            "git log --format",
            "FO-O",
            "1X",
            "A[0",
            "A[]x",
            "X++",
            "A[a]b",
            "A[]]",
            "A[a]]",
            "A[x]]+",
        ] {
            assert!(!is_assignment_name(name), "{name:?}");
        }
        // The argv builder uses the same rule: bash would run each of these words as a command.
        for word in ["FO-O=1", "A[a]b]=1", "A[]]=1", "A[a]]=1", "A[x]]+=1"] {
            let argv = vec![word.to_string()];
            let result = action_from_argv(&argv, None, &ctx_no_cwd());
            assert!(result.is_ok(), "{argv:?} is not an assignment: {result:?}");
        }
        // `["FO-O=1", ""]` used to be refused as `empty_program`; `FO-O=1` is now the program.
        let argv = vec!["FO-O=1".to_string(), String::new()];
        let r = action_from_argv(&argv, None, &ctx_no_cwd()).unwrap();
        assert_eq!(r.syntactic.bin.as_deref(), Some("FO-O=1"));
        assert_eq!(r.risk, Risk::Medium);
    }

    /// A substitution hidden in an assignment keeps its risk: the line is not refused, and risk
    /// still covers the command it runs.
    #[test]
    fn assignment_with_a_substitution_keeps_its_risk() {
        let r = action_from_command("FOO=$(rm -rf ~)", &ctx_no_cwd()).unwrap();
        assert_eq!(r.risk, Risk::High);
    }

    #[test]
    fn every_refusal_has_a_distinct_stable_code_and_message() {
        let all = [
            CommandError::InvalidShellSyntax,
            CommandError::NoCommand,
            CommandError::NoProgram,
            CommandError::EmptyProgram,
        ];
        let codes: HashSet<&str> = all.iter().map(CommandError::code).collect();
        let messages: HashSet<String> = all.iter().map(ToString::to_string).collect();
        assert_eq!(codes.len(), all.len());
        assert_eq!(messages.len(), all.len());
        assert_eq!(CommandError::NoCommand.code(), "no_command");
        assert_eq!(CommandError::NoProgram.code(), "no_program");
        assert_eq!(CommandError::EmptyProgram.code(), "empty_program");
        assert_eq!(
            CommandError::InvalidShellSyntax.code(),
            "invalid_shell_syntax"
        );
    }

    // ── Edge case: invalid shell syntax ──────────────────────────────────────

    /// A command string with unmatched quotes must return CommandError::InvalidShellSyntax.
    #[test]
    fn unmatched_quote_returns_error() {
        let result = action_from_command(r#"echo "hello world"#, &ctx_no_cwd());
        assert_eq!(
            result,
            Err(CommandError::InvalidShellSyntax),
            "unmatched quote must return CommandError::InvalidShellSyntax"
        );
    }

    // ── action_from_argv ─────────────────────────────────────────────────────

    /// action_from_argv builds a record from a pre-tokenized argv.
    #[test]
    fn action_from_argv_basic() {
        let argv = vec!["git".to_string(), "push".to_string(), "--force".to_string()];
        let r = action_from_argv(&argv, None, &ctx_with_cwd()).unwrap();

        assert_eq!(bin(&r), "git");
        assert_eq!(positionals(&r), vec!["push"]);
        assert!(flags(&r).contains(&"--force".to_string()));
        assert_eq!(r.risk, Risk::High, "git push --force is High risk");
    }

    /// An argv with no program is refused (#376), whatever `raw` says: empty → NoCommand, an
    /// empty program word → EmptyProgram, only assignments → NoProgram.
    #[test]
    fn action_from_argv_refuses_an_argv_with_no_program() {
        let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for (argv, raw, expected) in [
            (words(&[]), None, CommandError::NoCommand),
            (words(&[]), Some("rm -rf x"), CommandError::NoCommand),
            (words(&[""]), None, CommandError::EmptyProgram),
            (
                words(&["", "rm", "-rf", "x"]),
                Some("rm -rf x"),
                CommandError::EmptyProgram,
            ),
            (words(&["FOO=1", ""]), None, CommandError::EmptyProgram),
            (words(&["FOO=1"]), None, CommandError::NoProgram),
            (
                words(&["FOO=1", "BAR=2"]),
                Some("FOO=1 BAR=2"),
                CommandError::NoProgram,
            ),
        ] {
            assert_eq!(
                action_from_argv(&argv, raw, &ctx_no_cwd()),
                Err(expected),
                "{argv:?}"
            );
        }
    }

    /// An argv runs without a shell, so its words are never read as operators: an argv with a
    /// program word (even one named like an operator, or after an assignment) is built.
    #[test]
    fn action_from_argv_builds_an_argv_with_a_program() {
        for argv in [vec!["&&"], vec![";"], vec!["FOO=1", "ls"], vec!["ls", ""]] {
            let argv: Vec<String> = argv.into_iter().map(str::to_string).collect();
            assert!(
                action_from_argv(&argv, None, &ctx_no_cwd()).is_ok(),
                "{argv:?}"
            );
        }
    }

    /// `raw` is recorded verbatim and is **not** re-tokenized: the bound `argv` stays exactly the
    /// caller's canonical token vector even when the raw text would word-split differently
    /// (`docs/openclaw-integration.md` §5.1).
    #[test]
    fn action_from_argv_binds_caller_argv_not_a_reparse_of_raw() {
        let argv = vec![
            "bash".to_string(),
            "-lc".to_string(),
            "echo hello world".to_string(),
        ];
        let raw = "bash -lc echo hello world";
        let r = action_from_argv(&argv, Some(raw), &ctx_no_cwd()).unwrap();

        assert_eq!(r.syntactic.raw.as_deref(), Some(raw));
        assert_eq!(
            r.syntactic.argv.as_deref(),
            Some(argv.as_slice()),
            "argv must be the caller's canonical tokens, never a re-parse of raw"
        );
        // A re-parse of `raw` would have produced 6 tokens; the canonical vector has 3.
        assert_eq!(r.syntactic.argv.as_ref().map(Vec::len), Some(3));
    }

    /// `env_refs` are extracted from `raw`, so an argv-based caller that supplies the original
    /// command text gets the same name-only capture `action_from_command` produces.
    #[test]
    fn action_from_argv_extracts_env_refs_from_raw() {
        let argv = vec![
            "curl".to_string(),
            "-H".to_string(),
            "Authorization: Bearer $API_TOKEN".to_string(),
            "https://example.test/${TENANT}".to_string(),
        ];
        let r = action_from_argv(
            &argv,
            Some("curl -H \"Authorization: Bearer $API_TOKEN\" https://example.test/${TENANT}"),
            &ctx_no_cwd(),
        )
        .unwrap();

        assert_eq!(
            r.syntactic.env_refs.as_deref(),
            Some(&["API_TOKEN".to_string(), "TENANT".to_string()][..]),
            "env_refs come from raw, names only, in first-seen order"
        );
    }

    /// Without `raw` there is no text to scan, so `env_refs` stays `None` even when a token
    /// happens to contain a `$VAR` sequence (the producing shell already expanded it).
    #[test]
    fn action_from_argv_without_raw_has_no_env_refs() {
        let argv = vec!["echo".to_string(), "$HOME".to_string()];
        let r = action_from_argv(&argv, None, &ctx_no_cwd()).unwrap();

        assert!(r.syntactic.env_refs.is_none());
    }

    // ── Host extraction ──────────────────────────────────────────────────────

    /// ssh user@host → host extracted.
    #[test]
    fn host_extracted_for_ssh_user_at_host() {
        let r = action_from_command("ssh user@example.com", &ctx_no_cwd()).unwrap();
        assert_eq!(
            r.syntactic.host.as_deref(),
            Some("example.com"),
            "ssh user@host → host is the part after @"
        );
    }

    /// ssh with bare hostname (contains dot, not a path).
    #[test]
    fn host_extracted_for_ssh_bare_hostname() {
        let r = action_from_command("ssh example.com", &ctx_no_cwd()).unwrap();
        assert_eq!(r.syntactic.host.as_deref(), Some("example.com"));
    }

    /// Non-SSH commands do not trigger host extraction.
    #[test]
    fn no_host_for_non_ssh_commands() {
        let r = action_from_command("git push origin main", &ctx_no_cwd()).unwrap();
        assert!(
            r.syntactic.host.is_none(),
            "non-SSH commands must not have host extracted"
        );
    }

    // ── cwd passthrough ──────────────────────────────────────────────────────

    /// cwd from context is passed through to the substrate.
    #[test]
    fn cwd_from_context_passed_through() {
        let ctx = CommandContext {
            cwd: Some("/workspace/myproject".to_string()),
        };
        let r = action_from_command("ls", &ctx).unwrap();
        assert_eq!(
            r.syntactic.cwd.as_deref(),
            Some("/workspace/myproject"),
            "cwd must be passed through from CommandContext"
        );
    }

    // ── record_schema_version ────────────────────────────────────────────────

    /// All records built by this module use RECORD_SCHEMA_VERSION (== 1, matching contract tests).
    #[test]
    fn record_schema_version_is_one() {
        let r = action_from_command("ls", &ctx_no_cwd()).unwrap();
        assert_eq!(
            r.record_schema_version, RECORD_SCHEMA_VERSION,
            "record_schema_version must be RECORD_SCHEMA_VERSION"
        );
        assert_eq!(
            RECORD_SCHEMA_VERSION, 1,
            "RECORD_SCHEMA_VERSION must equal 1"
        );
    }

    // ── surface ──────────────────────────────────────────────────────────────

    /// surface is always Surface::Command.
    #[test]
    fn surface_is_always_command() {
        let r = action_from_command("ls", &ctx_no_cwd()).unwrap();
        assert_eq!(r.surface, Surface::Command);
    }

    // ── raw field ────────────────────────────────────────────────────────────

    /// raw field is set to the original command string for action_from_command.
    #[test]
    fn raw_is_original_command_string() {
        let cmd = "rm -rf /tmp/scratch";
        let r = action_from_command(cmd, &ctx_no_cwd()).unwrap();
        assert_eq!(
            r.syntactic.raw.as_deref(),
            Some(cmd),
            "raw must be the original command string"
        );
    }

    /// raw field is None for action_from_argv when the caller has no original string.
    #[test]
    fn raw_is_none_for_action_from_argv() {
        let argv = vec!["ls".to_string()];
        let r = action_from_argv(&argv, None, &ctx_no_cwd()).unwrap();
        assert!(
            r.syntactic.raw.is_none(),
            "action_from_argv with raw=None sets raw to None"
        );
    }

    // ── end-of-options separator ─────────────────────────────────────────────

    /// Tokens after `--` are positionals regardless of their leading `-`.
    #[test]
    fn end_of_options_separator_makes_subsequent_tokens_positionals() {
        let r = action_from_command("grep -- -v file.txt", &ctx_no_cwd()).unwrap();

        // `--` is in flags
        assert!(
            flags(&r).contains(&"--".to_string()),
            "-- must appear in flags"
        );
        // `-v` after `--` is a positional
        assert!(
            positionals(&r).contains(&"-v".to_string()),
            "`-v` after `--` must be a positional, not a flag"
        );
        assert!(
            positionals(&r).contains(&"file.txt".to_string()),
            "file.txt must be a positional"
        );
    }

    // ── long flag with attached value ────────────────────────────────────────

    /// `--key=value` is a single flag token (attached form).
    #[test]
    fn long_flag_with_attached_value_is_single_flag_token() {
        let r = action_from_command(
            "curl --output=result.html https://example.com",
            &ctx_no_cwd(),
        )
        .unwrap();

        assert!(
            flags(&r).contains(&"--output=result.html".to_string()),
            "--output=result.html must be a single flag token (attached form)"
        );
        // `result.html` must NOT appear separately in positionals
        assert!(
            !positionals(&r).contains(&"result.html".to_string()),
            "result.html must not appear as a separate positional (attached form)"
        );
    }

    // ── absolute path bin ────────────────────────────────────────────────────

    /// bin is stored as-given (full path), basename is used only for heuristics.
    #[test]
    fn bin_stored_as_given_full_path() {
        let r = action_from_command("/usr/bin/rm -rf /x", &ctx_no_cwd()).unwrap();
        assert_eq!(
            bin(&r),
            "/usr/bin/rm",
            "bin must be stored as-given (not basename-normalized)"
        );
        // Risk heuristic uses basename internally: /usr/bin/rm → rm → High
        assert_eq!(
            r.risk,
            Risk::High,
            "risk heuristic must use basename of bin path"
        );
    }

    /// #268 changes only `risk`: `bin` is still `argv[0]` and the syntactic fields keep their
    /// documented T1 meaning (module doc §Flag/§Positional classification), so policy matching
    /// cannot shift.
    #[test]
    fn risk_268_syntactic_fields_unchanged() {
        let r = action_from_command("FOO=1 git push --force origin main", &ctx_no_cwd()).unwrap();
        assert_eq!(bin(&r), "FOO=1");
        assert_eq!(
            argv(&r),
            ["FOO=1", "git", "push", "--force", "origin", "main"]
        );
        assert_eq!(flags(&r), ["--force"]);
        assert_eq!(positionals(&r), ["git", "push", "origin", "main"]);
        assert_eq!(r.syntactic.env_refs, None);
        assert_eq!(r.syntactic.host, None);

        let r = action_from_command("env X=$HOME rm -rf ~", &ctx_no_cwd()).unwrap();
        assert_eq!(bin(&r), "env");
        assert_eq!(argv(&r), ["env", "X=$HOME", "rm", "-rf", "~"]);
        assert_eq!(flags(&r), ["-rf"]);
        assert_eq!(positionals(&r), ["X=$HOME", "rm", "~"]);
        assert_eq!(r.syntactic.env_refs, Some(vec!["HOME".to_string()]));

        let r = action_from_command("sh -c 'ssh user@example.com'", &ctx_no_cwd()).unwrap();
        assert_eq!(bin(&r), "sh");
        assert_eq!(positionals(&r), ["ssh user@example.com"]);
        assert_eq!(r.syntactic.host, None, "host stays argv[0]-based");
    }

    /// #272 changes only `risk`: the record's words are still the shlex split of the line, so
    /// policy matching cannot shift.
    #[test]
    fn risk_272_syntactic_fields_unchanged() {
        let r = action_from_command("ls && rm -rf /", &ctx_no_cwd()).unwrap();
        assert_eq!(bin(&r), "ls");
        assert_eq!(argv(&r), ["ls", "&&", "rm", "-rf", "/"]);
        assert_eq!(flags(&r), ["-rf"]);
        assert_eq!(positionals(&r), ["&&", "rm", "/"]);
        assert_eq!(r.syntactic.env_refs, None);

        let r = action_from_command("echo $(rm -rf $HOME)", &ctx_no_cwd()).unwrap();
        assert_eq!(bin(&r), "echo");
        assert_eq!(argv(&r), ["echo", "$(rm", "-rf", "$HOME)"]);
        assert_eq!(r.syntactic.env_refs, Some(vec!["HOME".to_string()]));
    }
}
