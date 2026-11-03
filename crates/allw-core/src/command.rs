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
//! let record = action_from_argv(&argv, None, &CommandContext::default());
//!
//! // …or a pre-tokenized argv that also carries the original command text, so `raw` (and the
//! // `env_refs` derived from it) are populated without re-tokenizing:
//! let record = action_from_argv(&argv, Some("git push --force"), &CommandContext::default());
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
//! returns an error.  [`action_from_argv`] does not tokenize and never fails.
//!
//! # Command lines with shell syntax (risk only)
//!
//! Tokenization only splits words, so `ls && rm -rf /` records `bin: "ls"` and the argv
//! `["ls", "&&", "rm", "-rf", "/"]`. Those fields are unchanged. **Risk**, though, covers every
//! command a shell would run for the line: [`action_from_command`] also scans the raw line.
//!
//! - Each segment between unquoted control operators (`&&`, `||`, `;`, `|`, `&`, `(`, `)`, a
//!   newline) is classified, after leading shell keywords (`if`, `then`, `do`, `{`, `!`, …).
//! - Each command or process substitution (`$(…)`, backticks, `<(…)`, `>(…)`) is classified as a
//!   command line. So are the arguments of `eval`.
//! - Any operator, substitution or redirection makes the line at least `Medium`.
//! - The tier is never lower than the first word's own tier.
//!
//! Quoting follows POSIX: single quotes are literal; double quotes stop operators but not
//! substitutions; a backslash escapes the next character. Where shells or tokenizers can
//! disagree, every reading is analyzed and the highest tier is kept:
//!
//! - whether `#` starts a comment;
//! - whether `$'…'` is an ANSI-C string (bash) or not (dash, `shlex`).
//!
//! Bounds: nesting past 4 levels is `High`. Heredoc bodies are not recognized; their lines are
//! read as commands, which can only raise the result. [`action_from_argv`] records an argv that
//! runs without a shell, so its words are never read as shell syntax.
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
//! | Risk       | Matched commands / flags                                                      |
//! |------------|-------------------------------------------------------------------------------|
//! | `Critical` | `dd`, `mkfs`, `mkfs.*`, `fdisk`, `parted`, `shred`                           |
//! | `High`     | `rm` recursive+force, `git push` with a force flag, `chmod -R` (recursive), `sudo` |
//! | `Low`      | `ls`, `cat`, `echo`, `pwd`, `whoami`, `date`, `env`, `printenv`, `which`     |
//! | `Medium`   | everything else                                                               |
//!
//! Matching is case-sensitive on `bin` (exact match after basename extraction) and flag
//! presence checks use a set membership test on the `flags` list.

use crate::contract::{ActionRecord, Risk, Surface, SyntacticSubstrate};
use std::collections::HashSet;

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
#[derive(Debug, PartialEq)]
pub enum CommandError {
    /// The command string has unmatched quotes or other shell-tokenization errors.
    ///
    /// Use [`action_from_argv`] if you already have a pre-tokenized argv.
    InvalidShellSyntax,
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
        }
    }
}

impl std::error::Error for CommandError {}

// ── Public builders ───────────────────────────────────────────────────────────

/// Build an [`ActionRecord`] from a raw shell command string.
///
/// The string is tokenized using POSIX word-splitting (via [`shlex`]).  Returns
/// [`CommandError::InvalidShellSyntax`] if the string has unmatched quotes or other
/// tokenization errors.
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
    let argv = shlex::split(command_line).ok_or(CommandError::InvalidShellSyntax)?;
    let mut record = build_record(argv, ctx, Some(command_line.to_string()));
    // A command line can hold more than one command (`ls && rm -rf /`). `bin` / `argv` / `flags`
    // / `positionals` still describe the word list, but risk must cover every command a shell
    // would run (see `shell_line_risk`).
    if let Some(line_risk) = shell_line_risk(command_line, 0) {
        record.risk = max_risk(record.risk, line_risk);
    }
    Ok(record)
}

/// Build an [`ActionRecord`] from a pre-tokenized argument vector, optionally carrying the
/// original command text.
///
/// This is the infallible variant for callers that have already split the command into
/// tokens (e.g. received from a shell hook, a process execution API, or an agent runtime that
/// stores a canonical execution plan). Such callers **must not** re-tokenize their own command
/// text: re-parsing risks binding a different token vector than the one that actually executes
/// (`docs/openclaw-integration.md` §5.1).
///
/// `raw` is the original command string as the upstream gate renders it, when the caller has one.
/// It is recorded verbatim in [`SyntacticSubstrate::raw`] and is the **only** source the builder
/// extracts `env_refs` from — passing `None` therefore also yields `env_refs: None`, since a token
/// vector has already had its `$VAR` references resolved by whatever produced it.
///
/// An empty `argv` slice produces an [`ActionRecord`] whose `bin`, `argv`, `flags`, and
/// `positionals` are all `None` (there is nothing to populate); `raw` still reflects the argument.
///
/// # Examples
///
/// ```rust,ignore
/// let argv = vec!["git".to_string(), "push".to_string()];
/// let record = action_from_argv(&argv, None, &CommandContext::default());
/// let bound = action_from_argv(&argv, Some("git push"), &CommandContext::default());
/// ```
pub fn action_from_argv(argv: &[String], raw: Option<&str>, ctx: &CommandContext) -> ActionRecord {
    build_record(argv.to_vec(), ctx, raw.map(str::to_string))
}

// ── Core builder ─────────────────────────────────────────────────────────────

fn build_record(argv: Vec<String>, ctx: &CommandContext, raw: Option<String>) -> ActionRecord {
    let bin = argv.first().cloned().unwrap_or_default();
    let (flags, positionals) = split_flags_and_positionals(&argv);
    let env_refs = raw.as_deref().map(extract_env_refs).unwrap_or_default();
    let env_refs_opt = if env_refs.is_empty() {
        None
    } else {
        Some(env_refs)
    };

    let host = extract_host(&bin, &positionals);

    let risk = classify_risk(&bin, &flags, &positionals);

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

// ── Risk classification ───────────────────────────────────────────────────────

/// Classify the coarse risk tier for a command.
///
/// v1 heuristic only; T3 will derive this from capabilities.
/// Documented rules are in the module-level doc table.
fn classify_risk(bin: &str, flags: &[String], positionals: &[String]) -> Risk {
    let base = basename(bin);

    // Critical: disk/partition destructive tools
    match base {
        "dd" | "fdisk" | "parted" | "shred" => return Risk::Critical,
        b if b.starts_with("mkfs") => return Risk::Critical,
        _ => {}
    }

    // Low: read-only utilities
    match base {
        "ls" | "cat" | "echo" | "pwd" | "whoami" | "date" | "env" | "printenv" | "which" => {
            return Risk::Low
        }
        _ => {}
    }

    // High: dangerous flag combinations or commands
    match base {
        "rm" => {
            // rm with any combination that includes both -r/-R (recursive) and -f (force)
            let has_recursive = flags.iter().any(|f| {
                f == "-r"
                    || f == "-R"
                    || f == "--recursive"
                    || combined_short_flags(f).contains('r')
                    || combined_short_flags(f).contains('R')
            });
            let has_force = flags
                .iter()
                .any(|f| f == "-f" || f == "--force" || combined_short_flags(f).contains('f'));
            if has_recursive && has_force {
                return Risk::High;
            }
        }
        "git" => {
            // Only `git push` with a force flag is High — NOT e.g. `git checkout -f`.
            // The subcommand is the first positional (`git push ...` → positionals[0] == "push").
            let is_push = positionals.first().is_some_and(|p| p == "push");
            let has_force = flags.iter().any(|f| {
                f == "--force"
                    || f == "-f"
                    || f == "--force-with-lease"
                    || combined_short_flags(f).contains('f')
            });
            if is_push && has_force {
                return Risk::High;
            }
        }
        "chmod" => {
            let has_recursive = flags
                .iter()
                .any(|f| f == "-R" || combined_short_flags(f).contains('R'));
            if has_recursive {
                return Risk::High;
            }
        }
        "sudo" => return Risk::High,
        _ => {}
    }

    Risk::Medium
}

/// Extract the single-character flags from a combined short-flag token like `-rf`.
///
/// Only applies to tokens that start with exactly one `-` (not `--`).
/// Returns the characters after the `-` (e.g. `rf` for `-rf`).
fn combined_short_flags(token: &str) -> &str {
    if token.starts_with("--") {
        return "";
    }
    token.strip_prefix('-').unwrap_or_default()
}

// ── Shell-line risk ───────────────────────────────────────────────────────────

/// Numeric order of the risk tiers (`Low` < `Medium` < `High` < `Critical`).
fn risk_rank(risk: Risk) -> u8 {
    match risk {
        Risk::Low => 0,
        Risk::Medium => 1,
        Risk::High => 2,
        Risk::Critical => 3,
    }
}

/// The higher of two risk tiers.
fn max_risk(a: Risk, b: Risk) -> Risk {
    if risk_rank(b) > risk_rank(a) {
        b
    } else {
        a
    }
}

/// The higher of an optional running maximum and a new tier.
fn raise(current: Option<Risk>, tier: Risk) -> Option<Risk> {
    Some(current.map_or(tier, |c| max_risk(c, tier)))
}

/// How many levels of command substitution (`$(…)`, backticks, `<(…)`) and `eval` are analyzed.
/// Deeper nesting is classified [`Risk::High`] rather than analyzed further, so the classifier is
/// bounded and never under-reports it.
const MAX_SHELL_NESTING: usize = 4;

/// Words a shell reads as syntax at the start of a command (`if x; then rm -rf /; fi`). They are
/// skipped before a segment is classified, so they can't hide the program after them.
const SHELL_KEYWORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for",
    "select", "case", "esac", "function", "coproc", "time",
];

/// What a shell does with a command line, as far as risk needs to know.
#[derive(Default)]
struct ShellLine<'a> {
    /// The text between unquoted control operators (`&&`, `||`, `;`, `|`, `&`, `(`, `)`, a
    /// newline): each is one simple command, still quoted as written.
    segments: Vec<&'a str>,
    /// The bodies of command and process substitutions (`$(…)`, `` `…` ``, `<(…)`, `>(…)`). Each
    /// runs as a command line of its own.
    substitutions: Vec<&'a str>,
    /// Whether any operator, substitution or redirection appeared: shell syntax beyond plain words.
    has_shell_syntax: bool,
}

/// Index of the next `quote` byte at or after `from`, or `None`.
fn find_byte(b: &[u8], from: usize, quote: u8) -> Option<usize> {
    b.get(from..)?
        .iter()
        .position(|&c| c == quote)
        .map(|p| from + p)
}

/// How a shell may read quoting and comments where shells (or this scanner) can disagree. Every
/// reading is analyzed and the highest tier wins, so an ambiguity can only raise risk.
#[derive(Clone, Copy)]
struct Reading {
    /// An unquoted `#` at the start of a word starts a comment that runs to the end of the line.
    honor_comments: bool,
    /// `$'…'` is an ANSI-C string in which `\'` does not end the string (bash, zsh, ksh; not
    /// dash, and not the `shlex` tokenizer).
    ansi_c_quotes: bool,
}

/// Every [`Reading`] [`shell_line_risk`] analyzes.
const READINGS: [Reading; 4] = [
    Reading {
        honor_comments: true,
        ansi_c_quotes: true,
    },
    Reading {
        honor_comments: true,
        ansi_c_quotes: false,
    },
    Reading {
        honor_comments: false,
        ansi_c_quotes: true,
    },
    Reading {
        honor_comments: false,
        ansi_c_quotes: false,
    },
];

/// Index just past the `'` closing an ANSI-C string whose body starts at `start`, or `b.len()`.
fn skip_ansi_c_string(b: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'\'' => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

/// Index of the `)` closing a `(` whose body starts at `start`, honoring quotes and backslashes,
/// or `b.len()` if it is never closed (the rest of the line is then the body).
fn find_closing_paren(b: &[u8], start: usize, reading: Reading) -> usize {
    let mut depth = 1usize;
    let mut in_double = false;
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'\'' if !in_double => {
                i = find_byte(b, i + 1, b'\'').map_or(b.len(), |q| q + 1);
                continue;
            }
            b'$' if reading.ansi_c_quotes && !in_double && b.get(i + 1) == Some(&b'\'') => {
                i = skip_ansi_c_string(b, i + 2);
                continue;
            }
            b'"' => in_double = !in_double,
            b'(' if !in_double => depth += 1,
            b')' if !in_double => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// Index of the backtick closing a `` ` `` whose body starts at `start`, or `b.len()`.
fn find_closing_backtick(b: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'`' => return i,
            _ => i += 1,
        }
    }
    b.len()
}

/// Split a command line the way a POSIX shell does for risk: segments between unquoted control
/// operators, and the bodies of substitutions. Single quotes are literal; double quotes stop
/// operators but not substitutions; a backslash escapes the next byte.
///
/// `reading` decides comments and `$'…'` strings (see [`Reading`]).
///
/// Only ASCII bytes are ever matched, so every slice boundary falls on a UTF-8 char boundary.
fn scan_shell_line(text: &str, reading: Reading) -> ShellLine<'_> {
    let b = text.as_bytes();
    let mut line = ShellLine::default();
    let mut seg_start = 0;
    let mut in_double = false;
    let mut i = 0;
    while i < b.len() {
        let at_word_start = i == 0
            || matches!(
                b[i - 1],
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
            );
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'\'' if !in_double => {
                i = find_byte(b, i + 1, b'\'').map_or(b.len(), |q| q + 1);
                continue;
            }
            b'$' if reading.ansi_c_quotes && !in_double && b.get(i + 1) == Some(&b'\'') => {
                i = skip_ansi_c_string(b, i + 2);
                continue;
            }
            b'"' => in_double = !in_double,
            b'#' if reading.honor_comments && !in_double && at_word_start => {
                line.segments.push(&text[seg_start..i]);
                i = find_byte(b, i, b'\n').unwrap_or(b.len());
                seg_start = i;
                continue;
            }
            b'`' => {
                let end = find_closing_backtick(b, i + 1);
                line.substitutions.push(&text[i + 1..end]);
                line.has_shell_syntax = true;
                i = end + 1;
                continue;
            }
            b'$' | b'<' | b'>' if b.get(i + 1) == Some(&b'(') && (b[i] == b'$' || !in_double) => {
                let end = find_closing_paren(b, i + 2, reading);
                line.substitutions.push(&text[i + 2..end]);
                line.has_shell_syntax = true;
                i = end + 1;
                continue;
            }
            b'<' | b'>' if !in_double => line.has_shell_syntax = true,
            b';' | b'&' | b'|' | b'(' | b')' | b'\n' if !in_double => {
                line.segments.push(&text[seg_start..i]);
                line.has_shell_syntax = true;
                seg_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    line.segments
        .push(text.get(seg_start..).unwrap_or_default());
    line
}

/// Risk of one simple command (a segment's words, with leading [`SHELL_KEYWORDS`] removed).
/// `eval` runs its arguments as a command line, so that line is classified too.
fn segment_risk(words: &[String], depth: usize) -> Risk {
    let (flags, positionals) = split_flags_and_positionals(words);
    let own = classify_risk(&words[0], &flags, &positionals);
    if basename(&words[0]) != "eval" || words.len() < 2 {
        return own;
    }
    let evaluated = if depth >= MAX_SHELL_NESTING {
        Risk::High
    } else {
        shell_line_risk(&words[1..].join(" "), depth + 1).unwrap_or(Risk::Medium)
    };
    max_risk(own, evaluated)
}

/// Risk of every command a shell would run for `text`, or `None` when it holds no command.
///
/// - Each segment between control operators is classified on its own.
/// - Each substitution body is classified as a command line, `depth + 1` levels down. Past
///   [`MAX_SHELL_NESTING`] it is [`Risk::High`].
/// - Any operator, substitution or redirection makes the line at least [`Risk::Medium`].
/// - A segment the tokenizer can't split is at least [`Risk::Medium`].
///
/// The line is analyzed under every [`Reading`] and the highest tier is kept. Heredoc bodies are
/// not recognized; their lines are read as commands, which can only raise the result.
fn shell_line_risk(text: &str, depth: usize) -> Option<Risk> {
    let mut tier = None;
    for reading in READINGS {
        let line = scan_shell_line(text, reading);
        for segment in &line.segments {
            match shlex::split(segment) {
                Some(words) => {
                    let skip = words
                        .iter()
                        .take_while(|w| SHELL_KEYWORDS.contains(&w.as_str()))
                        .count();
                    if skip < words.len() {
                        tier = raise(tier, segment_risk(&words[skip..], depth));
                    }
                }
                None => tier = raise(tier, Risk::Medium),
            }
        }
        for body in &line.substitutions {
            let body_risk = if depth >= MAX_SHELL_NESTING {
                Some(Risk::High)
            } else {
                shell_line_risk(body, depth + 1)
            };
            if let Some(r) = body_risk {
                tier = raise(tier, r);
            }
        }
        if line.has_shell_syntax {
            tier = raise(tier, Risk::Medium);
        }
    }
    tier
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

    // ── Edge case: empty command string ─────────────────────────────────────

    /// An empty command string tokenizes to an empty argv (shlex returns `Some([])`).
    /// The builder returns an ActionRecord with all command fields None (no bin, no argv,
    /// no flags, no positionals) and risk Medium.
    #[test]
    fn empty_command_string_returns_record_with_no_fields() {
        let r = action_from_command("", &ctx_no_cwd()).unwrap();

        assert!(
            r.syntactic.bin.is_none(),
            "empty command → bin must be None"
        );
        assert!(
            r.syntactic.argv.is_none(),
            "empty command → argv must be None"
        );
        assert!(
            r.syntactic.flags.is_none(),
            "empty command → flags must be None"
        );
        assert!(
            r.syntactic.positionals.is_none(),
            "empty command → positionals must be None"
        );
        assert_eq!(
            r.risk,
            Risk::Medium,
            "empty command defaults to Risk::Medium"
        );
        assert!(r.capabilities.is_none());
        assert!(r.scope.is_none());
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

    /// action_from_argv accepts a pre-tokenized argv and never fails.
    #[test]
    fn action_from_argv_basic() {
        let argv = vec!["git".to_string(), "push".to_string(), "--force".to_string()];
        let r = action_from_argv(&argv, None, &ctx_with_cwd());

        assert_eq!(bin(&r), "git");
        assert_eq!(positionals(&r), vec!["push"]);
        assert!(flags(&r).contains(&"--force".to_string()));
        assert_eq!(r.risk, Risk::High, "git push --force is High risk");
    }

    /// action_from_argv with empty argv → all command fields None.
    #[test]
    fn action_from_argv_empty() {
        let r = action_from_argv(&[], None, &ctx_no_cwd());

        assert!(r.syntactic.bin.is_none());
        assert!(r.syntactic.argv.is_none());
        assert!(r.syntactic.flags.is_none());
        assert!(r.syntactic.positionals.is_none());
        // raw is None for action_from_argv (no original string available)
        assert!(r.syntactic.raw.is_none());
    }

    /// An empty argv still records the caller's `raw`, so a malformed upstream plan is visible in
    /// the record rather than silently erased.
    #[test]
    fn action_from_argv_empty_keeps_raw() {
        let r = action_from_argv(&[], Some("  "), &ctx_no_cwd());

        assert!(r.syntactic.bin.is_none());
        assert!(r.syntactic.argv.is_none());
        assert_eq!(r.syntactic.raw.as_deref(), Some("  "));
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
        let r = action_from_argv(&argv, Some(raw), &ctx_no_cwd());

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
        );

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
        let r = action_from_argv(&argv, None, &ctx_no_cwd());

        assert!(r.syntactic.env_refs.is_none());
    }

    // ── Risk heuristic ───────────────────────────────────────────────────────

    /// Critical: disk destructive tools.
    #[test]
    fn risk_critical_for_disk_tools() {
        for cmd in &[
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sdb1",
            "fdisk /dev/sda",
            "shred /dev/sda",
        ] {
            let r = action_from_command(cmd, &ctx_no_cwd()).unwrap();
            assert_eq!(
                r.risk,
                Risk::Critical,
                "`{cmd}` must be classified as Risk::Critical"
            );
        }
    }

    /// Low: read-only utilities.
    #[test]
    fn risk_low_for_read_only_tools() {
        for cmd in &["ls -la", "cat /etc/hosts", "echo hello", "pwd", "whoami"] {
            let r = action_from_command(cmd, &ctx_no_cwd()).unwrap();
            assert_eq!(r.risk, Risk::Low, "`{cmd}` must be classified as Risk::Low");
        }
    }

    /// High: sudo.
    #[test]
    fn risk_high_for_sudo() {
        let r = action_from_command("sudo apt-get install vim", &ctx_no_cwd()).unwrap();
        assert_eq!(r.risk, Risk::High);
    }

    /// High: git push --force.
    #[test]
    fn risk_high_for_git_push_force() {
        let r = action_from_command("git push --force origin main", &ctx_no_cwd()).unwrap();
        assert_eq!(r.risk, Risk::High);
    }

    /// Regression (#33 review): a force flag on a NON-`push` git subcommand must NOT be High.
    /// The risk rule requires `positionals[0] == "push"`, so `git checkout -f` stays Medium —
    /// before the fix, any `git` with a force flag was wrongly elevated.
    #[test]
    fn risk_not_high_for_git_force_without_push_subcommand() {
        let r = action_from_command("git checkout -f main", &ctx_no_cwd()).unwrap();
        assert_eq!(
            r.risk,
            Risk::Medium,
            "git checkout -f is not a force-push; must not be High"
        );
    }

    /// Medium: unrecognized commands default to medium.
    #[test]
    fn risk_medium_for_unknown_commands() {
        let r = action_from_command("docker build .", &ctx_no_cwd()).unwrap();
        assert_eq!(r.risk, Risk::Medium);
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
        let r = action_from_argv(&argv, None, &ctx_no_cwd());
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

    // ── Risk of every command on a shell line (#272) ─────────────────────────
    //
    // Expected tiers are derived by hand from the module-doc risk table: operators, substitutions
    // and redirections never make a line look less risky than a command it runs. The shared
    // Rust ↔ WASM table is `tests/fixtures/command_line_risk_vectors.json`.

    fn line_risk(cmd: &str) -> Risk {
        action_from_command(cmd, &ctx_no_cwd()).unwrap().risk
    }

    /// Regression (#272): `ls && rm -rf /` was Low because only `ls` was classified.
    #[test]
    fn risk_272_control_operators_expose_every_command() {
        for cmd in [
            "ls && rm -rf /",
            "ls || rm -rf /",
            "ls & rm -rf /",
            "ls; rm -rf /",
            "ls\nrm -rf /",
            "git status && git push --force",
        ] {
            assert_eq!(line_risk(cmd), Risk::High, "{cmd:?} runs a High command");
        }
    }

    /// Regression (#272): a substitution's command ran unseen.
    #[test]
    fn risk_272_substitutions_are_classified() {
        for cmd in [
            "echo $(rm -rf ~)",
            "echo `rm -rf ~`",
            "echo \"$(rm -rf ~)\"",
            "cat <(rm -rf ~)",
            "echo $(echo $(rm -rf ~))",
        ] {
            assert_eq!(line_risk(cmd), Risk::High, "{cmd:?} runs a High command");
        }
    }

    /// Shell syntax with only low-risk commands is at least Medium.
    #[test]
    fn risk_272_shell_syntax_is_at_least_medium() {
        assert_eq!(line_risk("echo hi > /etc/passwd"), Risk::Medium);
        assert_eq!(line_risk("ls 2>&1"), Risk::Medium);
        assert_eq!(line_risk("ls | cat"), Risk::Medium);
    }

    /// Compound commands: keywords, groups and subshells don't hide the program.
    #[test]
    fn risk_272_keywords_groups_and_subshells_do_not_hide_program() {
        for cmd in [
            "if true; then rm -rf /; fi",
            "for f in a; do rm -rf $f; done",
            "{ rm -rf /; }",
            "(rm -rf /)",
            "! rm -rf /",
        ] {
            assert_eq!(line_risk(cmd), Risk::High, "{cmd:?} runs a High command");
        }
    }

    /// `eval` runs its arguments as a command line.
    #[test]
    fn risk_272_eval_classifies_its_arguments() {
        assert_eq!(line_risk("eval 'rm -rf /'"), Risk::High);
        assert_eq!(line_risk("eval rm -rf /"), Risk::High);
        assert_eq!(
            line_risk("eval 'ls && dd if=/dev/zero of=/dev/sda'"),
            Risk::Critical
        );
    }

    /// Negative: quoted or escaped operators and substitutions are literal and don't raise risk.
    #[test]
    fn risk_272_quoted_or_escaped_syntax_is_literal() {
        for cmd in [
            "echo 'ls && rm -rf /'",
            "echo \"a && rm -rf /\"",
            "echo \\&\\& rm -rf /",
            "echo '$(rm -rf ~)'",
            "echo \"a\nb\"",
            "echo $HOME",
        ] {
            assert_eq!(line_risk(cmd), Risk::Low, "{cmd:?} is one echo");
        }
    }

    /// A quote inside a comment must not hide the next line: comments are read both ways.
    #[test]
    fn risk_272_quote_in_comment_does_not_hide_next_line() {
        assert_eq!(line_risk("ls # it's\nrm -rf /"), Risk::High);
    }

    /// In bash, `$'\''` is a one-character string, so the next line runs. The plain-quote reading
    /// (shlex, dash) would see one long quoted word; the ANSI-C reading must still find `rm`.
    #[test]
    fn risk_272_ansi_c_quote_does_not_hide_next_line() {
        assert_eq!(line_risk("echo $'\\''\nrm -rf /\n'"), Risk::High);
    }

    /// An unterminated substitution still has its body classified.
    #[test]
    fn risk_272_unterminated_substitution_body_is_classified() {
        assert_eq!(line_risk("echo $(rm -rf ~"), Risk::High);
        assert_eq!(line_risk("echo `rm -rf ~"), Risk::High);
    }

    /// Non-ASCII text around operators is handled without slicing inside a character.
    #[test]
    fn risk_272_non_ascii_text_is_scanned_safely() {
        assert_eq!(line_risk("echo héllo && rm -rf /"), Risk::High);
        assert_eq!(line_risk("echo 日本 $(rm -rf ~)"), Risk::High);
        assert_eq!(line_risk("echo 'é'"), Risk::Low);
    }

    /// `levels` nested `$(…)` substitutions around `innermost`.
    fn nested_substitutions(levels: usize, innermost: &str) -> String {
        let mut line = innermost.to_string();
        for _ in 0..levels {
            line = format!("echo $({line})");
        }
        line
    }

    /// Substitutions are analyzed up to `MAX_SHELL_NESTING` levels deep.
    #[test]
    fn risk_272_nested_substitutions_up_to_limit_are_analyzed() {
        let line = nested_substitutions(MAX_SHELL_NESTING, "dd if=/dev/zero of=/dev/sda");
        assert_eq!(line_risk(&line), Risk::Critical);
        let line = nested_substitutions(MAX_SHELL_NESTING, "echo hi");
        assert_eq!(
            line_risk(&line),
            Risk::Medium,
            "syntax makes it Medium; echo is Low"
        );
    }

    /// Nesting past the limit is not analyzed and is High, so depth cannot hide a command.
    #[test]
    fn risk_272_nested_substitutions_past_limit_are_high() {
        let line = nested_substitutions(MAX_SHELL_NESTING + 1, "echo hi");
        assert_eq!(line_risk(&line), Risk::High);
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

    /// Negative: `action_from_argv` binds an argv that runs without a shell, so operator words in
    /// it are literal arguments and don't raise risk (`raw` is display text, not what runs).
    #[test]
    fn risk_272_argv_records_are_not_read_as_shell_lines() {
        let argv: Vec<String> = ["ls", "&&", "rm", "-rf", "/"].map(String::from).to_vec();
        let r = action_from_argv(&argv, Some("ls && rm -rf /"), &ctx_no_cwd());
        assert_eq!(r.risk, Risk::Low);
    }
}
