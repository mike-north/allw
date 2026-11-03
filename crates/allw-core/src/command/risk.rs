//! The v1 risk tier of a `command` action: a coarse, documented heuristic for **what actually
//! runs**, not just for the first word the human typed.
//!
//! Risk is shown to the human, and surfaces derive decisions from it: the Codex hook and the
//! OpenClaw bridge set `reversible` from it (low/medium ⇒ reversible), and the bridge requires a
//! challenge for `critical`. So understating risk is a real defect. Every rule here fails
//! **upward**: when the analyzer can't tell, the tier goes up, never down. `policy::evaluate` does
//! not read risk.
//!
//! # The program table
//!
//! | Risk       | Program (matched by basename)                                                    |
//! |------------|----------------------------------------------------------------------------------|
//! | `Critical` | `dd`, `mkfs`, `mkfs.*`, `fdisk`, `parted`, `shred`                              |
//! | `High`     | `rm` recursive+force, `git push` with a force flag, `chmod -R`, `sudo`, `doas`, `run0`, `pkexec`, `su` |
//! | `Low`      | `ls`, `cat`, `echo`, `pwd`, `whoami`, `date`, `env`, `printenv`, `which`        |
//! | `Medium`   | everything else                                                                  |
//!
//! # The program that actually runs (argv)
//!
//! An argv is classified right to left. Each position gets the tier of the command that would start
//! there. A record's tier is that of position 0, and it is never lower than the table's tier for
//! `argv[0]` alone.
//!
//! - **Assignments.** A leading assignment-like word (`NAME=value`, and also `X+=1`, `A[0]=1`: any
//!   word with an `=` whose name starts with a letter or `_`) is skipped. The tier is that of the
//!   command after it, and at least `Medium`.
//! - **Wrappers** ([`WRAPPERS`]: `env`, `sudo`, `nice`, `xargs`, `find`, `ssh`, `watch`, …) are at
//!   least as risky as anything they may run:
//!   - every later non-flag word, as a program start;
//!   - every later word containing whitespace, read as a command line (`watch 'rm -rf ~'`). For a
//!     flag such as `env -S'…'` or `--split-string=…`, that is the flag's value.
//!
//!   `env` with a non-assignment word after it is at least `Medium`.
//! - **Shells** ([`SHELLS`]: `sh`, `bash`, `zsh`, `fish`, `csh`, …) with `-c` (or `--command`) read
//!   every later non-flag word as a command line, like `eval`. `pwsh` / `powershell`:
//!   `-Command` (any prefix) is read the same way; `-EncodedCommand` is unreadable: `High`.
//! - **`eval`** reads its arguments, joined by spaces, as a command line.
//!
//! # Command lines (`action_from_command`)
//!
//! The raw line is also scanned the way bash would, and risk is the highest tier of any command it
//! runs:
//!
//! - Segments between unquoted control operators (`&&`, `||`, `;`, `|`, `&`, `(`, `)`, newline, and
//!   a lone `{` / `}` word) are classified on their own.
//! - Leading words that aren't the command are skipped before the command word is found:
//!   - keywords (`if`, `then`, `do`, `!`, `time [-p]`, …)
//!   - redirections (`2>/dev/null`, `> f`)
//!   - zsh precommand words (`noglob`, `nocorrect`, `-`, `repeat N`)
//!
//!   Assignments are kept for the argv rules, and zsh `=cmd` is read as `cmd`.
//! - A command word holding an expansion (`$x`, `$(…)`, a backtick, a glob `* ? [`, or a brace list
//!   `{a,b}`) can't be known statically: `High`. In bash, `$'…'` and `$"…"` are decoded first, so
//!   `$'rm'` is `rm`.
//! - Command and process substitutions (`$(…)`, backticks, `<(…)`, `>(…)`) are classified as
//!   command lines.
//! - Heredocs (`<<`, `<<-`; not `<<<`) are recognized:
//!   - a quoted delimiter makes the body literal;
//!   - an unquoted one makes only its substitutions run;
//!   - a body fed to a shell is classified as a script.
//! - Any operator, substitution or redirection makes the line at least `Medium`. A line that ends
//!   inside an open quote or substitution is `High`: the shell runs what comes before the syntax
//!   error.
//!
//! Quoting follows bash. Two ambiguities are read both ways, and the higher tier wins: whether `#`
//! starts a comment, and whether `$'…'` is an ANSI-C string (bash) or not (dash, `shlex`). These
//! alternate readings run only when the line holds an unquoted `#` or a `$'`. zsh-only syntax gets
//! fail-upward handling only: its precommand words, and `&!` / `&|` as operators.
//!
//! # Bounds (all fail upward)
//!
//! - Nesting of `-c`, `eval` and substitutions past [`MAX_SHELL_NESTING`] levels: `High`.
//! - Argv positions past [`MAX_PROGRAM_CANDIDATES`] are not analyzed. They count as a `High`
//!   candidate for any wrapper, shell or assignment in front of them.
//! - All analysis of one record shares one budget of [`MAX_RISK_WORK`] units (bytes scanned or
//!   split, plus argv positions classified). Exhausting it makes the record at least `High`. Every
//!   candidate string is analyzed once per level, so work grows linearly with input size.
//!
//! # Known T1 limits (the tier can understate these)
//!
//! - Wrappers and interpreters not listed: `parallel`, `git -c core.sshCommand=…`, `source` / `.`,
//!   and code in other languages (`python -c`, `node -e`, `perl -e`).
//! - Input piped into a shell (`echo 'rm -rf ~' | sh`) is not analyzed: the shell keeps its own tier.
//! - Aliases, functions and `PATH` lookups defined outside the line.
//! - Arithmetic evaluation of data: `x='a[$(rm -rf ~)]'; echo $((x))` runs a substitution held in a
//!   variable's value.
//! - Program names are matched exactly: a renamed or symlinked binary is unknown (`Medium`).
//! - Non-bash grammars (fish, csh, PowerShell `-c` strings) are read with bash's rules.

use super::{basename, is_ident_start, split_flags_and_positionals};
use crate::contract::Risk;

// ── Limits ────────────────────────────────────────────────────────────────────

/// How many levels of `-c` strings, `eval` and substitutions are analyzed. Deeper nesting is
/// classified [`Risk::High`] instead, so the analysis is bounded and never under-reports it.
const MAX_SHELL_NESTING: usize = 4;

/// How many argv positions are analyzed as possible program starts. Positions past it are not
/// analyzed; a wrapper, shell or assignment in front of them counts them as a [`Risk::High`]
/// candidate, so padding an argv can't push the real program out of view.
const MAX_PROGRAM_CANDIDATES: usize = 256;

/// The total work allowed for one record, in units: one per byte scanned or split, plus one per
/// argv position classified. Ordinary commands use a tiny fraction. Hostile nesting or megabyte
/// `eval` chains exhaust it, and the record is then at least [`Risk::High`]. The cap keeps
/// classification bounded in time: the call is synchronous WASM inside the hook, and a hook that
/// outlives the agent's timeout fails open.
const MAX_RISK_WORK: usize = 4 * 1024 * 1024;

/// Programs that run another command given later in their argv.
const WRAPPERS: &[&str] = &[
    "env",
    "genv",
    "sudo",
    "doas",
    "run0",
    "pkexec",
    "su",
    "nice",
    "gnice",
    "ionice",
    "nohup",
    "gnohup",
    "time",
    "timeout",
    "gtimeout",
    "command",
    "builtin",
    "exec",
    "xargs",
    "stdbuf",
    "gstdbuf",
    "setsid",
    "find",
    "caffeinate",
    "arch",
    "script",
    "chroot",
    "flock",
    "watch",
    "busybox",
    "ssh",
];

/// Shells whose `-c` (or `--command`) runs a command string.
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh",
];

/// PowerShell, whose `-Command` takes a command string and `-EncodedCommand` an unreadable one.
const POWERSHELLS: &[&str] = &["pwsh", "powershell"];

/// Words bash reads as syntax at the start of a command. They are skipped before the command word.
const SHELL_KEYWORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for",
    "select", "case", "esac", "function", "coproc", "time",
];

/// zsh precommand words that run the next word as the command (`repeat` also takes a count).
const ZSH_PRECOMMANDS: &[&str] = &["noglob", "nocorrect", "-"];

// ── Entry points ──────────────────────────────────────────────────────────────

/// Risk of an argv that runs without a shell (the argv of `action_from_argv`).
pub(super) fn argv_risk(argv: &[String]) -> Risk {
    let mut budget = Budget::new(MAX_RISK_WORK);
    let risk = classify_argv(argv, 0, &mut budget);
    budget.finish(risk)
}

/// Risk of a command line a shell runs: the highest tier of any command in it, and never lower
/// than the tier of its word list (`words`, the line's `shlex` split).
pub(super) fn command_line_risk(line: &str, words: &[String]) -> Risk {
    let mut budget = Budget::new(MAX_RISK_WORK);
    let risk = line_and_words_risk(line, words, &mut budget);
    budget.finish(risk)
}

fn line_and_words_risk(line: &str, words: &[String], budget: &mut Budget) -> Risk {
    let risk = classify_argv(words, 0, budget);
    match shell_line_risk(line, 0, budget) {
        Some(line_risk) => max_risk(risk, line_risk),
        None => risk,
    }
}

// ── Work budget ───────────────────────────────────────────────────────────────

/// The work left for one record's risk analysis. Once exhausted, every step returns
/// [`Risk::High`] at once, and [`Budget::finish`] raises the result to at least `High`.
struct Budget {
    limit: usize,
    used: usize,
    exhausted: bool,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Budget {
            limit,
            used: 0,
            exhausted: false,
        }
    }

    /// Spend `units`. Returns `false`, and marks the budget exhausted, if they don't fit.
    fn spend(&mut self, units: usize) -> bool {
        if self.exhausted || units > self.limit - self.used {
            self.exhausted = true;
            return false;
        }
        self.used += units;
        true
    }

    fn finish(&self, risk: Risk) -> Risk {
        if self.exhausted {
            max_risk(risk, Risk::High)
        } else {
            risk
        }
    }
}

// ── Tiers ─────────────────────────────────────────────────────────────────────

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

/// The higher of an optional running maximum and an optional tier.
fn raise_opt(current: Option<Risk>, tier: Option<Risk>) -> Option<Risk> {
    match tier {
        Some(t) => raise(current, t),
        None => current,
    }
}

/// The program table (module doc § The program table) for one program and its own words.
fn classify_program(bin: &str, flags: &[String], positionals: &[String]) -> Risk {
    let base = basename(bin);

    match base {
        "dd" | "fdisk" | "parted" | "shred" => return Risk::Critical,
        b if b.starts_with("mkfs") => return Risk::Critical,
        _ => {}
    }

    match base {
        "ls" | "cat" | "echo" | "pwd" | "whoami" | "date" | "env" | "printenv" | "which" => {
            return Risk::Low
        }
        _ => {}
    }

    match base {
        "rm" => {
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
            // Only `git push` with a force flag is High; `git checkout -f` is not.
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
        "sudo" | "doas" | "run0" | "pkexec" | "su" => return Risk::High,
        _ => {}
    }

    Risk::Medium
}

/// The letters of a single-dash short-flag bundle (`rf` for `-rf`); empty for `--long` flags.
fn combined_short_flags(token: &str) -> &str {
    if token.starts_with("--") {
        return "";
    }
    token.strip_prefix('-').unwrap_or_default()
}

// ── Argv analysis ─────────────────────────────────────────────────────────────

/// Is `token` assignment-like for risk: an `=` whose name starts with a letter or `_`
/// (`NAME=v`, `X+=1`, `A[0]=1`)? Over-matching only raises risk.
fn is_assignment_like(token: &str) -> bool {
    token
        .split_once('=')
        .is_some_and(|(name, _)| name.bytes().next().is_some_and(is_ident_start))
}

fn is_flag(token: &str) -> bool {
    token.starts_with('-')
}

fn has_whitespace(token: &str) -> bool {
    token.bytes().any(|b| b.is_ascii_whitespace())
}

/// Does a shell flag ask it to run a command string (`-c`, a bundle like `-lc`, `--command`)?
fn is_shell_command_flag(token: &str) -> bool {
    token == "--command"
        || token.starts_with("--command=")
        || combined_short_flags(token).contains('c')
}

/// Is `token` an abbreviation of PowerShell's `-Command`?
fn is_pwsh_command_flag(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.len() >= 2 && "-command".starts_with(lower.as_str())
}

/// Is `token` PowerShell's `-EncodedCommand` (`-e`, `-ec`, or an abbreviation)?
fn is_pwsh_encoded_flag(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower == "-e"
        || lower == "-ec"
        || (lower.len() >= 3 && "-encodedcommand".starts_with(lower.as_str()))
}

/// The values a flag with whitespace in it may carry as a command: the text after `=`, and for a
/// short-flag bundle every suffix of its leading letters (`-iSrm -rf ~` → `rm -rf ~`, among
/// others). Over-reading only raises risk.
fn flag_command_values(token: &str) -> Vec<&str> {
    let mut values = Vec::new();
    if let Some((_, value)) = token.split_once('=') {
        values.push(value);
    }
    if !token.starts_with("--") {
        let bytes = token.as_bytes();
        let mut i = 1;
        while i < bytes.len() && bytes[i].is_ascii_alphanumeric() {
            values.push(&token[i..]);
            i += 1;
        }
        if i < bytes.len() {
            values.push(&token[i..]);
        }
    }
    values
}

/// Risk of `text` read as a command line nested one level below `depth`, or `None` when it holds
/// no command. Past [`MAX_SHELL_NESTING`] it is [`Risk::High`] unread.
fn command_string_risk(text: &str, depth: usize, budget: &mut Budget) -> Option<Risk> {
    if depth >= MAX_SHELL_NESTING {
        return Some(Risk::High);
    }
    shell_line_risk(text, depth + 1, budget)
}

/// The table's tier for the command starting at `argv[j]`. Only `rm` / `git` / `chmod` read their
/// own flags, so only they pay for the split.
fn direct_risk(argv: &[String], j: usize, budget: &mut Budget) -> Risk {
    let program = argv[j].as_str();
    match basename(program) {
        "rm" | "git" | "chmod" => {
            if !budget.spend(argv.len() - j) {
                return Risk::High;
            }
            let (flags, positionals) = split_flags_and_positionals(&argv[j..]);
            classify_program(program, &flags, &positionals)
        }
        _ => classify_program(program, &[], &[]),
    }
}

/// The tier of `argv[j + 1..]` joined by spaces and read as a command line (`eval`).
fn eval_risk(argv: &[String], j: usize, depth: usize, budget: &mut Budget) -> Option<Risk> {
    let rest = &argv[j + 1..];
    let len: usize = rest.iter().map(|w| w.len() + 1).sum();
    if !budget.spend(len) {
        return Some(Risk::High);
    }
    command_string_risk(&rest.join(" "), depth, budget)
}

/// Classify an argv: the tier of the command that runs, per the module doc § The program that
/// actually runs. One right-to-left pass; each word's command-string reading is computed at most
/// once, so a long run of shells or wrappers can't multiply the work.
fn classify_argv(argv: &[String], depth: usize, budget: &mut Budget) -> Risk {
    let n = argv.len();
    if n == 0 {
        return classify_program("", &[], &[]);
    }
    let analyzed = n.min(MAX_PROGRAM_CANDIDATES);
    if !budget.spend(analyzed) {
        return Risk::High;
    }
    let truncated = n > analyzed;
    // Unseen positions past `analyzed` count as a High candidate.
    let unseen = truncated.then_some(Risk::High);

    // Command strings matter only after a wrapper or shell; find the first of each.
    let first_wrapper = argv[..analyzed]
        .iter()
        .position(|t| WRAPPERS.contains(&basename(t)));
    let first_shell = argv[..analyzed]
        .iter()
        .position(|t| SHELLS.contains(&basename(t)) || POWERSHELLS.contains(&basename(t)));

    // `eval` reads the rest of the argv as a command line. Only an `eval` whose tier is read needs
    // that: one reached through leading assignments, or the first after a wrapper (any later
    // `eval` is inside the text that one reads). Evaluating every `eval` would be quadratic.
    let leading_assignments = argv[..analyzed]
        .iter()
        .take_while(|t| is_assignment_like(t))
        .count();
    let first_eval_after_wrapper = first_wrapper.and_then(|w| {
        argv[w + 1..analyzed]
            .iter()
            .position(|t| basename(t) == "eval")
            .map(|p| w + 1 + p)
    });

    let mut risk = vec![Risk::Low; analyzed];
    // Suffix state over positions k > j.
    let mut later_max: Option<Risk> = unseen; // tier of a later non-flag word as a program start
    let mut later_ws_max: Option<Risk> = unseen; // a later whitespace word read as a command line
    let mut later_string_max: Option<Risk> = unseen; // a later non-flag word read as a command line
    let mut later_command_flag = truncated;
    let mut later_pwsh_command = truncated;
    let mut later_pwsh_encoded = false;
    let mut later_non_assignment = truncated;

    for j in (0..analyzed).rev() {
        if budget.exhausted {
            return Risk::High;
        }
        let token = argv[j].as_str();
        let base = basename(token);
        let direct = direct_risk(argv, j, budget);
        let tier = if is_assignment_like(token) {
            let after = if j + 1 < analyzed {
                risk[j + 1]
            } else {
                unseen.unwrap_or(Risk::Medium)
            };
            max_risk(max_risk(Risk::Medium, direct), after)
        } else {
            let mut tier = direct;
            if WRAPPERS.contains(&base) {
                tier = max_risk(tier, later_max.unwrap_or(tier));
                tier = max_risk(tier, later_ws_max.unwrap_or(tier));
                if (base == "env" || base == "genv") && later_non_assignment {
                    tier = max_risk(tier, Risk::Medium);
                }
            }
            if SHELLS.contains(&base) && later_command_flag {
                tier = max_risk(tier, later_string_max.unwrap_or(tier));
            }
            if POWERSHELLS.contains(&base) {
                if later_pwsh_encoded {
                    tier = max_risk(tier, Risk::High);
                } else if later_pwsh_command {
                    tier = max_risk(tier, later_string_max.unwrap_or(tier));
                }
            }
            let eval_is_read = j <= leading_assignments || first_eval_after_wrapper == Some(j);
            if base == "eval" && eval_is_read && j + 1 < n {
                if let Some(evaluated) = eval_risk(argv, j, depth, budget) {
                    tier = max_risk(tier, evaluated);
                }
            }
            tier
        };
        risk[j] = tier;

        // Fold position j into the suffix state seen by positions left of it.
        let flag = is_flag(token);
        let ws = has_whitespace(token);
        let mut string_risk: Option<Option<Risk>> = None; // memo: token read as a command line
        if first_shell.is_some_and(|s| j > s) {
            if !flag {
                let r = command_string_risk(token, depth, budget);
                string_risk = Some(r);
                later_string_max = raise_opt(later_string_max, r);
            } else if let Some(value) = token.strip_prefix("--command=") {
                later_string_max =
                    raise_opt(later_string_max, command_string_risk(value, depth, budget));
            }
        }
        if ws && first_wrapper.is_some_and(|w| j > w) {
            let r = if flag {
                flag_command_values(token).into_iter().fold(None, |acc, v| {
                    raise_opt(acc, command_string_risk(v, depth, budget))
                })
            } else {
                match string_risk {
                    Some(memo) => memo,
                    None => command_string_risk(token, depth, budget),
                }
            };
            later_ws_max = raise_opt(later_ws_max, r);
        }
        if flag {
            later_command_flag |= is_shell_command_flag(token);
            later_pwsh_command |= is_pwsh_command_flag(token);
            later_pwsh_encoded |= is_pwsh_encoded_flag(token);
        } else {
            later_max = raise(later_max, tier);
            later_non_assignment |= !is_assignment_like(token);
        }
    }
    if budget.exhausted {
        return Risk::High;
    }
    risk[0]
}

// ── Shell-line scanning ───────────────────────────────────────────────────────

/// How the scanner reads the two places where shells (or tokenizers) disagree. The bash reading
/// ([`Reading::BASH`]) is authoritative; the others are analyzed only when the line holds the
/// ambiguous syntax, and can only raise the tier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Reading {
    /// An unquoted `#` at the start of a word starts a comment that runs to the end of the line.
    honor_comments: bool,
    /// `$'…'` is an ANSI-C string in which `\'` does not end the string (bash, zsh, ksh; not
    /// dash, and not the `shlex` tokenizer).
    ansi_c_quotes: bool,
}

impl Reading {
    const BASH: Reading = Reading {
        honor_comments: true,
        ansi_c_quotes: true,
    };
}

/// A heredoc whose body begins at the next unquoted newline.
struct PendingHeredoc {
    delimiter: String,
    strip_tabs: bool,
    quoted: bool,
    /// Index of the segment holding the `<<` (the segment that receives the body as stdin).
    segment: usize,
}

/// What a shell does with a command line, as far as risk needs to know.
#[derive(Default)]
struct ShellLine<'a> {
    /// The text of each simple command between control operators, still quoted as written.
    segments: Vec<&'a str>,
    /// Bodies of command and process substitutions, each a command line of its own.
    substitutions: Vec<&'a str>,
    /// Heredoc bodies with the index of the segment that reads them.
    heredocs: Vec<(usize, &'a str)>,
    /// Any operator, substitution or redirection: shell syntax beyond plain words.
    has_shell_syntax: bool,
    /// The line ends inside an open quote, substitution or backtick.
    unterminated: bool,
    /// The line holds an unquoted `#` at a word start (the comment reading is ambiguous).
    saw_comment: bool,
    /// The line holds an unquoted `$'` (the ANSI-C reading is ambiguous).
    saw_ansi_c: bool,
}

/// Index of the next `byte` at or after `from`, or `None`.
fn find_byte(b: &[u8], from: usize, byte: u8) -> Option<usize> {
    b.get(from..)?
        .iter()
        .position(|&c| c == byte)
        .map(|p| from + p)
}

/// Index just past the `'` closing an ANSI-C string whose body starts at `start`, or `None`.
fn skip_ansi_c_string(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'\'' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Index of the `)` closing a `(` whose body starts at `start`, honoring quotes and backslashes,
/// or `None` if it is never closed.
fn find_closing_paren(b: &[u8], start: usize, reading: Reading) -> Option<usize> {
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
                i = skip_ansi_c_string(b, i + 2).unwrap_or(b.len());
                continue;
            }
            b'"' => in_double = !in_double,
            b'(' if !in_double => depth += 1,
            b')' if !in_double => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Index of the backtick closing one whose body starts at `start`, or `None`.
fn find_closing_backtick(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'`' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Bytes that end a word (and start a new one) outside quotes.
fn is_word_break(c: u8) -> bool {
    matches!(
        c,
        b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
    )
}

/// Read a heredoc delimiter word starting at `i`: its unquoted text, whether any part was quoted,
/// and the index just past it.
fn read_heredoc_delimiter(b: &[u8], mut i: usize) -> (String, bool, usize) {
    let mut word = Vec::new();
    let mut quoted = false;
    while i < b.len() && !is_word_break(b[i]) {
        match b[i] {
            b'\\' => {
                quoted = true;
                if let Some(&c) = b.get(i + 1) {
                    word.push(c);
                }
                i += 2;
            }
            q @ (b'\'' | b'"') => {
                quoted = true;
                let end = find_byte(b, i + 1, q).unwrap_or(b.len());
                word.extend_from_slice(&b[i + 1..end]);
                i = end + 1;
            }
            c => {
                word.push(c);
                i += 1;
            }
        }
    }
    (
        String::from_utf8_lossy(&word).into_owned(),
        quoted,
        i.min(b.len()),
    )
}

/// Consume a heredoc body starting at `pos`: the body's byte range and the index just past its
/// delimiter line (or the end of the text when there is none).
fn consume_heredoc(text: &str, pos: usize, heredoc: &PendingHeredoc) -> (usize, usize, usize) {
    let b = text.as_bytes();
    let start = pos;
    let mut line_start = pos;
    while line_start < b.len() {
        let line_end = find_byte(b, line_start, b'\n').unwrap_or(b.len());
        let line = &text[line_start..line_end];
        let line = if heredoc.strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line
        };
        if line == heredoc.delimiter {
            return (start, line_start, (line_end + 1).min(b.len()));
        }
        line_start = line_end + 1;
    }
    (start, b.len(), b.len())
}

/// The command substitutions in an unquoted heredoc body. Quotes are literal there; only `$(…)`,
/// backticks and backslash escapes are special.
fn heredoc_substitutions<'a>(body: &'a str, reading: Reading, out: &mut Vec<&'a str>) -> bool {
    let b = body.as_bytes();
    let mut unterminated = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'$' if b.get(i + 1) == Some(&b'(') => match find_closing_paren(b, i + 2, reading) {
                Some(end) => {
                    out.push(&body[i + 2..end]);
                    i = end + 1;
                }
                None => {
                    out.push(&body[i + 2..]);
                    unterminated = true;
                    i = b.len();
                }
            },
            b'`' => match find_closing_backtick(b, i + 1) {
                Some(end) => {
                    out.push(&body[i + 1..end]);
                    i = end + 1;
                }
                None => {
                    out.push(&body[i + 1..]);
                    unterminated = true;
                    i = b.len();
                }
            },
            _ => i += 1,
        }
    }
    unterminated
}

/// Split a command line the way bash does for risk: segments between unquoted control operators,
/// substitution bodies, and heredoc bodies. See [`Reading`] for the two ambiguous rules.
///
/// Only ASCII bytes are ever matched, so every slice boundary falls on a UTF-8 char boundary.
fn scan_shell_line(text: &str, reading: Reading) -> ShellLine<'_> {
    let b = text.as_bytes();
    let mut line = ShellLine::default();
    let mut pending: Vec<PendingHeredoc> = Vec::new();
    let mut seg_start = 0;
    let mut in_double = false;
    let mut i = 0;
    while i < b.len() {
        let at_word_start = i == 0 || is_word_break(b[i - 1]);
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'\'' if !in_double => {
                match find_byte(b, i + 1, b'\'') {
                    Some(q) => i = q + 1,
                    None => {
                        line.unterminated = true;
                        i = b.len();
                    }
                }
                continue;
            }
            b'$' if !in_double && b.get(i + 1) == Some(&b'\'') => {
                line.saw_ansi_c = true;
                if reading.ansi_c_quotes {
                    match skip_ansi_c_string(b, i + 2) {
                        Some(end) => i = end,
                        None => {
                            line.unterminated = true;
                            i = b.len();
                        }
                    }
                    continue;
                }
            }
            b'"' => in_double = !in_double,
            b'#' if !in_double && at_word_start => {
                line.saw_comment = true;
                if reading.honor_comments {
                    line.segments.push(&text[seg_start..i]);
                    i = find_byte(b, i, b'\n').unwrap_or(b.len());
                    seg_start = i;
                    continue;
                }
            }
            b'`' => {
                line.has_shell_syntax = true;
                match find_closing_backtick(b, i + 1) {
                    Some(end) => {
                        line.substitutions.push(&text[i + 1..end]);
                        i = end + 1;
                    }
                    None => {
                        line.substitutions.push(&text[i + 1..]);
                        line.unterminated = true;
                        i = b.len();
                    }
                }
                continue;
            }
            b'$' | b'<' | b'>' if b.get(i + 1) == Some(&b'(') && (b[i] == b'$' || !in_double) => {
                line.has_shell_syntax = true;
                match find_closing_paren(b, i + 2, reading) {
                    Some(end) => {
                        line.substitutions.push(&text[i + 2..end]);
                        i = end + 1;
                    }
                    None => {
                        line.substitutions.push(&text[i + 2..]);
                        line.unterminated = true;
                        i = b.len();
                    }
                }
                continue;
            }
            b'<' if !in_double && b.get(i + 1) == Some(&b'<') => {
                line.has_shell_syntax = true;
                if b.get(i + 2) == Some(&b'<') {
                    i += 3; // `<<<` is a here-string, not a heredoc
                    continue;
                }
                let strip_tabs = b.get(i + 2) == Some(&b'-');
                let mut p = i + 2 + usize::from(strip_tabs);
                while p < b.len() && (b[p] == b' ' || b[p] == b'\t') {
                    p += 1;
                }
                let (delimiter, quoted, end) = read_heredoc_delimiter(b, p);
                if !delimiter.is_empty() {
                    pending.push(PendingHeredoc {
                        delimiter,
                        strip_tabs,
                        quoted,
                        segment: line.segments.len(),
                    });
                }
                i = end;
                continue;
            }
            b'<' | b'>' if !in_double => line.has_shell_syntax = true,
            b'&' if !in_double => {
                line.has_shell_syntax = true;
                let redirect =
                    (i > 0 && matches!(b[i - 1], b'<' | b'>')) || b.get(i + 1) == Some(&b'>');
                if !redirect {
                    line.segments.push(&text[seg_start..i]);
                    seg_start = i + 1;
                }
            }
            b';' | b'|' | b'(' | b')' if !in_double => {
                line.has_shell_syntax = true;
                line.segments.push(&text[seg_start..i]);
                seg_start = i + 1;
            }
            b'{' | b'}'
                if !in_double
                    && at_word_start
                    && b.get(i + 1).is_none_or(|&c| is_word_break(c)) =>
            {
                line.has_shell_syntax = true;
                line.segments.push(&text[seg_start..i]);
                seg_start = i + 1;
            }
            b'\n' if !in_double => {
                line.segments.push(&text[seg_start..i]);
                let mut pos = i + 1;
                for heredoc in pending.drain(..) {
                    let (start, end, next) = consume_heredoc(text, pos, &heredoc);
                    let body = &text[start..end];
                    if !heredoc.quoted
                        && heredoc_substitutions(body, reading, &mut line.substitutions)
                    {
                        line.unterminated = true;
                    }
                    line.heredocs.push((heredoc.segment, body));
                    pos = next;
                }
                i = pos;
                seg_start = pos;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    line.segments
        .push(text.get(seg_start..).unwrap_or_default());
    if in_double {
        line.unterminated = true;
    }
    line
}

// ── Words of a segment ────────────────────────────────────────────────────────

/// Split a segment into its raw words at unquoted blanks, keeping quotes and substitutions intact.
fn raw_words(segment: &str, reading: Reading) -> Vec<&str> {
    let b = segment.as_bytes();
    let mut words = Vec::new();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        let mut in_double = false;
        while i < b.len() && (in_double || !b[i].is_ascii_whitespace()) {
            match b[i] {
                b'\\' => i += 2,
                b'\'' if !in_double => {
                    i = find_byte(b, i + 1, b'\'').map_or(b.len(), |q| q + 1);
                }
                b'$' if reading.ansi_c_quotes && !in_double && b.get(i + 1) == Some(&b'\'') => {
                    i = skip_ansi_c_string(b, i + 2).unwrap_or(b.len());
                }
                b'$' if b.get(i + 1) == Some(&b'(') => {
                    i = find_closing_paren(b, i + 2, reading).map_or(b.len(), |e| e + 1);
                }
                b'`' => {
                    i = find_closing_backtick(b, i + 1).map_or(b.len(), |e| e + 1);
                }
                b'"' => {
                    in_double = !in_double;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        let end = i.min(b.len());
        words.push(&segment[start..end]);
    }
    words
}

/// Decode one ANSI-C escape at `b[i]` (just after the backslash) into `out`; returns the index
/// after it.
fn decode_ansi_c_escape(b: &[u8], i: usize, out: &mut Vec<u8>) -> usize {
    let Some(&c) = b.get(i) else {
        return i;
    };
    let simple = match c {
        b'n' => Some(b'\n'),
        b't' => Some(b'\t'),
        b'r' => Some(b'\r'),
        b'a' => Some(0x07),
        b'b' => Some(0x08),
        b'e' | b'E' => Some(0x1b),
        b'f' => Some(0x0c),
        b'v' => Some(0x0b),
        b'\\' | b'\'' | b'"' | b'?' => Some(c),
        _ => None,
    };
    if let Some(byte) = simple {
        out.push(byte);
        return i + 1;
    }
    if c == b'x' {
        let mut j = i + 1;
        let mut value = 0u32;
        while j < b.len() && j < i + 3 && b[j].is_ascii_hexdigit() {
            value = value * 16 + char::from(b[j]).to_digit(16).unwrap_or(0);
            j += 1;
        }
        if j > i + 1 {
            out.push(u8::try_from(value).unwrap_or(b'?'));
            return j;
        }
    }
    if (b'0'..=b'7').contains(&c) {
        let mut j = i;
        let mut value = 0u32;
        while j < b.len() && j < i + 3 && (b'0'..=b'7').contains(&b[j]) {
            value = value * 8 + u32::from(b[j] - b'0');
            j += 1;
        }
        out.push(u8::try_from(value).unwrap_or(b'?'));
        return j;
    }
    out.push(b'\\');
    out.push(c);
    i + 1
}

/// A word with its quotes removed, and whether it holds an expansion whose value T1 can't know:
/// a parameter or command substitution (`$x`, `${x}`, `$(…)`, a backtick; quoted or not, since
/// double quotes don't stop expansion), or an unquoted glob (`*`, `?`, `[…]`) or brace list
/// (`{a,b}`).
fn unquote_word(raw: &str, reading: Reading) -> (String, bool) {
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut expansion = false;
    let mut brace_open = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                if let Some(&c) = b.get(i + 1) {
                    if c != b'\n' {
                        out.push(c);
                    }
                }
                i += 2;
            }
            b'\'' => {
                let end = find_byte(b, i + 1, b'\'').unwrap_or(b.len());
                out.extend_from_slice(&b[i + 1..end]);
                i = end + 1;
            }
            b'$' if reading.ansi_c_quotes && b.get(i + 1) == Some(&b'\'') => {
                let mut j = i + 2;
                while j < b.len() && b[j] != b'\'' {
                    if b[j] == b'\\' {
                        j = decode_ansi_c_escape(b, j + 1, &mut out);
                    } else {
                        out.push(b[j]);
                        j += 1;
                    }
                }
                i = j + 1;
            }
            b'$' if b.get(i + 1) == Some(&b'"') => i += 1, // `$"…"` is a double-quoted string
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    match b[j] {
                        b'\\' if matches!(b.get(j + 1), Some(b'$' | b'`' | b'"' | b'\\')) => {
                            out.push(b[j + 1]);
                            j += 2;
                        }
                        b'\\' if b.get(j + 1) == Some(&b'\n') => j += 2,
                        b'$' if b.get(j + 1).is_some_and(|&c| starts_expansion(c)) => {
                            expansion = true;
                            out.push(b[j]);
                            j += 1;
                        }
                        b'`' => {
                            expansion = true;
                            out.push(b[j]);
                            j += 1;
                        }
                        c => {
                            out.push(c);
                            j += 1;
                        }
                    }
                }
                i = j + 1;
            }
            b'$' if b.get(i + 1).is_some_and(|&c| starts_expansion(c)) => {
                expansion = true;
                out.push(b'$');
                i += 1;
            }
            b'`' | b'*' | b'?' => {
                expansion = true;
                out.push(b[i]);
                i += 1;
            }
            b'[' => {
                // `[` is a glob only with a later `]` (`[` and `[[` alone are commands).
                expansion |= find_byte(b, i + 1, b']').is_some();
                out.push(b'[');
                i += 1;
            }
            b'{' => {
                brace_open = true;
                out.push(b'{');
                i += 1;
            }
            b',' if brace_open => {
                expansion = true;
                out.push(b',');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    (String::from_utf8_lossy(&out).into_owned(), expansion)
}

/// Does `$` followed by `c` start an expansion (a name, `{`, `(`, a digit, or a special
/// parameter)?
fn starts_expansion(c: u8) -> bool {
    is_ident_start(c)
        || c.is_ascii_digit()
        || matches!(
            c,
            b'{' | b'(' | b'?' | b'#' | b'@' | b'*' | b'!' | b'$' | b'-'
        )
}

/// If `word` is a redirection, whether its target is the next word (`>` alone) rather than
/// attached (`>f`, `2>&1`). `None` if it isn't one.
fn redirection(word: &str) -> Option<bool> {
    let rest = word
        .strip_prefix("&>>")
        .or_else(|| word.strip_prefix("&>"))
        .or_else(|| {
            let digits = word.bytes().take_while(u8::is_ascii_digit).count();
            let op_part = &word[digits..];
            [">>", ">&", ">|", "<>", "<&", "<<<", "<<-", "<<", ">", "<"]
                .iter()
                .find_map(|op| op_part.strip_prefix(op))
        })?;
    Some(rest.is_empty())
}

/// What one segment runs: its tier (`None` when it runs nothing), and its command word.
fn segment_risk(
    segment: &str,
    depth: usize,
    reading: Reading,
    budget: &mut Budget,
) -> (Option<Risk>, Option<String>) {
    if !budget.spend(segment.len()) {
        return (Some(Risk::High), None);
    }
    let raw = raw_words(segment, reading);
    let mut words: Vec<String> = Vec::new();
    let mut has_assignment = false;
    let mut i = 0;
    let mut command: Option<(String, bool)> = None;
    while i < raw.len() {
        let (word, expansion) = unquote_word(raw[i], reading);
        if !expansion {
            if SHELL_KEYWORDS.contains(&word.as_str()) {
                let skip_p = word == "time"
                    && raw
                        .get(i + 1)
                        .is_some_and(|w| unquote_word(w, reading).0 == "-p");
                i += 1 + usize::from(skip_p);
                continue;
            }
            if ZSH_PRECOMMANDS.contains(&word.as_str()) {
                i += 1;
                continue;
            }
            if word == "repeat" {
                i += 2;
                continue;
            }
            if let Some(target_is_next) = redirection(&word) {
                i += 1 + usize::from(target_is_next);
                continue;
            }
            if is_assignment_like(&word) {
                has_assignment = true;
                words.push(word);
                i += 1;
                continue;
            }
        }
        command = Some((word, expansion));
        i += 1;
        break;
    }
    let Some((command_word, expansion)) = command else {
        return (has_assignment.then_some(Risk::Medium), None);
    };
    if expansion {
        // The command word is computed at run time (decision: unknowable ⇒ High).
        return (Some(Risk::High), None);
    }
    // zsh `=cmd` expands to the path of `cmd`.
    let command_word = match command_word.strip_prefix('=') {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => command_word,
    };
    words.push(command_word.clone());
    words.extend(raw[i..].iter().map(|w| unquote_word(w, reading).0));
    (
        Some(classify_argv(&words, depth, budget)),
        Some(command_word),
    )
}

/// The tier of one reading of a line: its segments, substitutions and heredoc bodies.
fn reading_risk(
    line: &ShellLine<'_>,
    depth: usize,
    reading: Reading,
    budget: &mut Budget,
) -> Option<Risk> {
    let mut tier = None;
    let mut commands: Vec<Option<String>> = Vec::with_capacity(line.segments.len());
    for segment in &line.segments {
        let (risk, command) = segment_risk(segment, depth, reading, budget);
        tier = raise_opt(tier, risk);
        commands.push(command);
    }
    for body in &line.substitutions {
        tier = raise_opt(tier, command_string_risk(body, depth, budget));
    }
    for (segment, body) in &line.heredocs {
        // A heredoc fed to a shell is a script.
        let fed_to_shell = commands
            .get(*segment)
            .and_then(Option::as_deref)
            .is_some_and(|c| SHELLS.contains(&basename(c)) || POWERSHELLS.contains(&basename(c)));
        if fed_to_shell {
            tier = raise_opt(tier, command_string_risk(body, depth, budget));
        }
    }
    if line.has_shell_syntax {
        tier = raise(tier, Risk::Medium);
    }
    tier
}

/// Risk of every command a shell would run for `text`, or `None` when it runs nothing. See the
/// module doc § Command lines.
fn shell_line_risk(text: &str, depth: usize, budget: &mut Budget) -> Option<Risk> {
    if !budget.spend(text.len()) {
        return Some(Risk::High);
    }
    let primary = scan_shell_line(text, Reading::BASH);
    let mut tier = reading_risk(&primary, depth, Reading::BASH, budget);
    if primary.unterminated {
        // The shell runs what precedes the syntax error, and what follows can't be read.
        tier = raise(tier, Risk::High);
    }
    let mut alternates = Vec::new();
    if primary.saw_comment {
        alternates.push(Reading {
            honor_comments: false,
            ansi_c_quotes: true,
        });
    }
    if primary.saw_ansi_c {
        alternates.push(Reading {
            honor_comments: true,
            ansi_c_quotes: false,
        });
    }
    if primary.saw_comment && primary.saw_ansi_c {
        alternates.push(Reading {
            honor_comments: false,
            ansi_c_quotes: false,
        });
    }
    for reading in alternates {
        if !budget.spend(text.len()) {
            return Some(Risk::High);
        }
        let line = scan_shell_line(text, reading);
        tier = raise_opt(tier, reading_risk(&line, depth, reading, budget));
    }
    if budget.exhausted {
        return Some(Risk::High);
    }
    tier
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
