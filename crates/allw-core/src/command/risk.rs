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
//!   - redirections (`2>/dev/null`, `> f`), including ones attached to a word: bash reads `<` and
//!     `>` as metacharacters, so `dd>/dev/null` runs `dd`
//!   - zsh precommand words (`noglob`, `nocorrect`, `-`, `repeat N`)
//!
//!   Assignments are kept for the argv rules, and zsh `=cmd` is read as `cmd`.
//! - A command word holding an expansion (`$x`, `$(…)`, a backtick, a glob `* ? [`, or a brace list
//!   `{a,b}`) can't be known statically: `High`. In bash, `$'…'` and `$"…"` are decoded first, so
//!   `$'rm'` is `rm`, and a decoded NUL ends the word (`$'dd\0x'` is `dd`). A decoding bash may do
//!   differently (`\u`, `\c`, an unknown escape, a byte that isn't UTF-8) makes it at least `High`.
//!   The decoded name still applies, so `$'\u0064\u0064'` is `Critical`.
//! - Command and process substitutions (`$(…)`, backticks, `<(…)`, `>(…)`) are classified as
//!   command lines. Inside one, a `#` comment runs to the end of its line, so a `)` or quote in it
//!   doesn't end the substitution.
//! - Heredocs (`<<`, `<<-`) are recognized:
//!   - the delimiter is read as bash reads it: an empty quoted delimiter (`<<''`) ends the body at
//!     the first empty line, a backslash-newline is removed, and inside double quotes `\"`, `\\`,
//!     `\$` and `` \` `` are unescaped;
//!   - a delimiter T1 can't read for sure (`$'…'`, a backtick, none at all) makes the line `High`;
//!   - an unquoted delimiter's body has its substitutions classified.
//! - **Every heredoc and here-string (`<<<`) body is also read as a script**, whatever consumes it
//!   (a shell, a wrapper, a compound command, `eval`, or `cat`), and the higher tier wins. This is a
//!   deliberate fail-upward rule: deciding which consumers run their input is a moving target
//!   (`{ bash; } <<'EOF'`, `eval bash <<'EOF'`, …), and over-reading a body only raises the tier.
//!   An open quote inside a heredoc body doesn't raise the tier on its own: a shell fed the body
//!   stops at that syntax error before running anything after the quote, and everything before it
//!   is still classified. So commit and PR bodies (`it's`, `don't`) keep their command's tier.
//! - `((…))` at a command position (including `for ((…))`) is arithmetic: a `<<` inside it is a
//!   shift, not a heredoc.
//! - Any operator, substitution or redirection makes the line at least `Medium`. A line that ends
//!   inside an open quote or substitution is `High`: the shell runs what comes before the syntax
//!   error.
//!
//! Quoting follows bash ≥ 4. Where shells, versions or tokenizers disagree, the line is read
//! both ways and the higher tier wins:
//!
//! - whether `#` starts a comment;
//! - whether `$'…'` is an ANSI-C string (bash) or not (dash, `shlex`);
//! - whether `((` opens an arithmetic command or two subshells;
//! - whether a heredoc inside `$(…)` is read before the closing `)` (bash ≥ 4, zsh, dash, ksh)
//!   or the first `)` closes the substitution (bash 3.2);
//! - whether a body line `EOF)` ends a heredoc inside `$(…)` and closes the substitution
//!   (bash 5).
//!
//! Each alternate reading runs only when the line holds the syntax it is about, at every nesting
//! level (a nested `dash -c` string gets dash's reading), charged to the shared budget. An
//! alternate reading's substitutions keep the open-quote floor, with one exception: a
//! substitution the bash 3.2 reading never closes runs to the end of the input, and bash 3.2
//! stops at its open quote with nothing later to run, so that open quote alone doesn't raise the
//! tier. zsh-only syntax gets fail-upward handling only: its precommand words, and `&!` / `&|`
//! as operators.
//!
//! # Bounds (all fail upward)
//!
//! - Nesting of `-c`, `eval` and substitutions past [`MAX_SHELL_NESTING`] levels: `High`.
//! - Argv positions past [`MAX_PROGRAM_CANDIDATES`] are not analyzed. They count as a `High`
//!   candidate for any wrapper, shell or assignment in front of them.
//! - Before any budgeted work, an unbudgeted pre-pass records the tier of every visible program
//!   word: each argv word, and the command word of every segment, descending into substitutions,
//!   backticks and heredoc bodies down to [`MAX_SHELL_NESTING`] levels. It scans each level's
//!   text once, so it is linear for each level.
//! - All analysis of one record shares one budget of [`MAX_RISK_WORK`] units (bytes scanned,
//!   split or copied, plus argv positions classified). Exhausting it makes the record at least
//!   `High`, and never lowers a tier already found: any program word the pre-pass sees keeps its
//!   tier on exhaustion (a `dd` or `$(dd)` padded with megabytes after it stays `Critical`). Only
//!   text the analysis never reached falls back to `High`.
//!   Every look-ahead scan is linear and charged. Alternate readings can multiply with nesting
//!   depth; the budget, not skipped readings, bounds that cost.
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
    note_visible_programs(None, argv, &mut budget);
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
    note_visible_programs(Some(line), words, budget);
    let risk = classify_argv(words, 0, budget);
    match shell_line_risk(line, Source::CommandLine, 0, budget) {
        Some(line_risk) => max_risk(risk, line_risk),
        None => risk,
    }
}

// ── Work budget ───────────────────────────────────────────────────────────────

/// The work left for one record's risk analysis. Once exhausted, every step returns
/// [`Risk::High`] at once, and [`Budget::finish`] raises the result to at least `High` and to
/// every tier already found, so running out of budget never lowers a tier (a `dd` found before
/// the budget ran out stays `Critical`).
struct Budget {
    limit: usize,
    used: usize,
    exhausted: bool,
    /// The highest program-table tier found so far, for any word classified as a program start.
    /// Only read on exhaustion, where it may over-count a word that turned out not to run.
    found: Risk,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Budget {
            limit,
            used: 0,
            exhausted: false,
            found: Risk::Low,
        }
    }

    /// Record a tier the analysis found.
    fn note(&mut self, tier: Risk) {
        self.found = max_risk(self.found, tier);
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

    /// The record's tier: `risk`, or on exhaustion at least `High` and every tier already found.
    fn finish(&self, risk: Risk) -> Risk {
        if self.exhausted {
            max_risk(max_risk(risk, Risk::High), self.found)
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
    script_risk(text, Source::CommandLine, depth, budget)
}

/// [`command_string_risk`] for text from `source`, one nesting level below `depth`.
fn script_risk(text: &str, source: Source, depth: usize, budget: &mut Budget) -> Option<Risk> {
    if depth >= MAX_SHELL_NESTING {
        return Some(Risk::High);
    }
    shell_line_risk(text, source, depth + 1, budget)
}

/// The table's tier for the command starting at `argv[j]`. Only `rm` / `git` / `chmod` read their
/// own flags, so only they pay for the split, charged by the bytes it copies (`suffix_bytes`, the
/// size of `argv[j..]`).
fn direct_risk(argv: &[String], j: usize, suffix_bytes: usize, budget: &mut Budget) -> Risk {
    let program = argv[j].as_str();
    let tier = match basename(program) {
        "rm" | "git" | "chmod" => {
            if !budget.spend(suffix_bytes) {
                return Risk::High;
            }
            note_scanned(suffix_bytes);
            let (flags, positionals) = split_flags_and_positionals(&argv[j..]);
            classify_program(program, &flags, &positionals)
        }
        _ => classify_program(program, &[], &[]),
    };
    budget.note(tier);
    tier
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

    // Bytes in `argv[j..]` for each analyzed `j`, for charging `direct_risk`'s split.
    let mut suffix_bytes = vec![0usize; analyzed + 1];
    suffix_bytes[analyzed] = argv[analyzed..].iter().map(|w| w.len() + 1).sum();
    for j in (0..analyzed).rev() {
        suffix_bytes[j] = suffix_bytes[j + 1] + argv[j].len() + 1;
    }

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
        let direct = direct_risk(argv, j, suffix_bytes[j], budget);
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

/// How the scanner reads the places where shells (or tokenizers, or bash versions) disagree. The
/// bash ≥ 4 reading ([`Reading::BASH`]) is authoritative; the others are analyzed at every
/// nesting level, only when the line holds the ambiguous syntax, and can only raise the tier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Reading {
    /// An unquoted `#` at the start of a word starts a comment that runs to the end of the line.
    honor_comments: bool,
    /// `$'…'` is an ANSI-C string in which `\'` does not end the string (bash, zsh, ksh; not
    /// dash, and not the `shlex` tokenizer).
    ansi_c_quotes: bool,
    /// `((…))` at a command position is an arithmetic command: no heredocs or operators inside it
    /// (bash, zsh, ksh). Otherwise it is two subshells.
    arithmetic_commands: bool,
    /// A heredoc inside `$(…)` is read as a heredoc, so a `)` in its body doesn't close the
    /// substitution (bash ≥ 4, zsh, dash, ksh). Otherwise the first unquoted `)` closes it
    /// (bash 3.2).
    heredocs_in_substitutions: bool,
    /// Inside `$(…)`, a body line that starts with the delimiter followed by `)` ends the heredoc,
    /// and that `)` closes the substitution (bash 5 accepts `EOF)` with a warning). Off in bash 4
    /// and zsh, where only a line equal to the delimiter ends it.
    heredoc_ends_before_paren: bool,
}

impl Reading {
    const BASH: Reading = Reading {
        honor_comments: true,
        ansi_c_quotes: true,
        arithmetic_commands: true,
        heredocs_in_substitutions: true,
        heredoc_ends_before_paren: false,
    };
}

/// Where a line handed to [`shell_line_risk`] comes from, which decides how an open quote at its
/// end counts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Source {
    /// A command line, `-c` string, `eval` argument, here-string, or substitution in the bash
    /// reading: an open quote at the end hides what follows it, so the line is at least High.
    CommandLine,
    /// A heredoc body read as a script (the always-a-script rule). A shell fed this body stops at
    /// the syntax error before running anything after the open quote, and everything before it is
    /// still classified, so an open quote alone doesn't raise the tier. This keeps ordinary
    /// commit and PR bodies (`it's`, `don't`) at the tier of the command that consumes them.
    HeredocBody,
    /// A substitution that the bash 3.2 reading (`heredocs_in_substitutions` off) never closes,
    /// so it runs to the end of the input. bash 3.2 stops at the open quote and has no later
    /// command to run, and the bash reading applies its own floors. (bash 3.2 reads
    /// `"$(cat <<'EOF'`⏎`it's`⏎`EOF`⏎`)"` as an unterminated quote and runs nothing.) A
    /// substitution any other alternate delimits, or one bash 3.2 closes, is a
    /// [`Source::CommandLine`].
    UnclosedBash32Substitution,
}

/// A heredoc whose body begins at the next unquoted newline.
struct PendingHeredoc {
    delimiter: Vec<u8>,
    strip_tabs: bool,
    quoted: bool,
}

/// A command substitution, process substitution or backtick, as one reading delimits it.
#[derive(Clone, Copy)]
struct Substitution<'a> {
    /// The text between the delimiters, or to the end of the input when it never closes.
    body: &'a str,
    /// The reading found its closing `)` or backtick.
    closed: bool,
}

impl<'a> Substitution<'a> {
    fn closed(body: &'a str) -> Self {
        Substitution { body, closed: true }
    }

    fn unclosed(body: &'a str) -> Self {
        Substitution {
            body,
            closed: false,
        }
    }

    /// How an open quote at the end of this substitution counts in `reading`. See
    /// [`Source::UnclosedBash32Substitution`].
    fn source(&self, reading: Reading) -> Source {
        if !reading.heredocs_in_substitutions && !self.closed {
            Source::UnclosedBash32Substitution
        } else {
            Source::CommandLine
        }
    }
}

/// What a shell does with a command line, as far as risk needs to know.
#[derive(Default)]
struct ShellLine<'a> {
    /// The text of each simple command between control operators, still quoted as written.
    segments: Vec<&'a str>,
    /// Command and process substitutions, each body a command line of its own.
    substitutions: Vec<Substitution<'a>>,
    /// Substitutions inside unquoted heredoc bodies. They are also inside [`ShellLine::heredocs`],
    /// so the lexical pre-pass doesn't descend into them twice.
    body_substitutions: Vec<Substitution<'a>>,
    /// Heredoc bodies. Each is always also classified as a script, whatever reads it.
    heredocs: Vec<&'a str>,
    /// Any operator, substitution or redirection: shell syntax beyond plain words.
    has_shell_syntax: bool,
    /// The line ends inside an open substitution or backtick, or holds syntax T1 can't read for
    /// sure (an uncertain heredoc delimiter). Either way the line is at least High.
    unterminated: bool,
    /// The line ends inside an open quote (`'`, `"` or `$'`). See [`Source`] for how it counts.
    open_quote: bool,
    /// The line holds an unquoted `#` at a word start (the comment reading is ambiguous).
    saw_comment: bool,
    /// The line holds an unquoted `$'` (the ANSI-C reading is ambiguous).
    saw_ansi_c: bool,
    /// The line holds an arithmetic command `((…))` (the arithmetic reading is ambiguous).
    saw_arithmetic: bool,
}

#[cfg(test)]
thread_local! {
    /// Bytes examined by the look-ahead scans below, so tests can measure the work actually done
    /// rather than only what was charged to the [`Budget`].
    static SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Count `n` bytes examined by a look-ahead scan (tests only).
#[cfg(test)]
fn note_scanned(n: usize) {
    SCANNED.with(|c| c.set(c.get() + n));
}

#[cfg(not(test))]
fn note_scanned(_: usize) {}

/// Index of the next `byte` at or after `from`, or `None`.
fn find_byte(b: &[u8], from: usize, byte: u8) -> Option<usize> {
    let found = b
        .get(from..)?
        .iter()
        .position(|&c| c == byte)
        .map(|p| from + p);
    note_scanned(found.map_or(b.len(), |f| f + 1).saturating_sub(from));
    found
}

/// Index just past the `'` closing an ANSI-C string whose body starts at `start`, or `None`.
fn skip_ansi_c_string(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'\'' => {
                note_scanned(i + 1 - start);
                return Some(i + 1);
            }
            _ => i += 1,
        }
    }
    note_scanned(b.len().saturating_sub(start));
    None
}

/// Index of the `)` closing a `(` whose body starts at `start`, honoring quotes and backslashes,
/// or `None` if it is never closed. With [`Reading::heredocs_in_substitutions`], a heredoc
/// inside is read as one, so a `)` in its body doesn't close the substitution. With
/// [`Reading::honor_comments`], a comment runs to the end of its line, so neither a `)` nor a
/// quote in it counts.
fn find_closing_paren(b: &[u8], start: usize, reading: Reading) -> Option<usize> {
    let mut depth = 1usize;
    let mut in_double = false;
    let mut pending: Vec<PendingHeredoc> = Vec::new();
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'#' if reading.honor_comments
                && !in_double
                && (i == start || is_word_break(b[i - 1])) =>
            {
                // Stop at the newline, which still ends any pending heredoc's operator line.
                i = find_byte(b, i, b'\n').unwrap_or(b.len());
                continue;
            }
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
            b'<' if reading.heredocs_in_substitutions
                && !in_double
                && b.get(i + 1) == Some(&b'<')
                && b.get(i + 2) != Some(&b'<') =>
            {
                let (heredoc, end) = heredoc_operator(b, i);
                pending.push(heredoc);
                i = end;
                continue;
            }
            b'\n' if !in_double && !pending.is_empty() => {
                let mut pos = i + 1;
                for heredoc in pending.drain(..) {
                    if reading.heredoc_ends_before_paren {
                        if let Some(paren) = heredoc_end_before_paren(b, pos, &heredoc) {
                            // bash 5: the body ends, and the `)` is read as syntax again.
                            pos = paren;
                            break;
                        }
                    }
                    pos = consume_heredoc(b, pos, &heredoc).1;
                }
                i = pos;
                continue;
            }
            b'"' => in_double = !in_double,
            b'(' if !in_double => depth += 1,
            b')' if !in_double => {
                depth -= 1;
                if depth == 0 {
                    note_scanned(i + 1 - start);
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    note_scanned(b.len().saturating_sub(start));
    None
}

/// Index of the backtick closing one whose body starts at `start`, or `None`.
fn find_closing_backtick(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'`' => {
                note_scanned(i + 1 - start);
                return Some(i);
            }
            _ => i += 1,
        }
    }
    note_scanned(b.len().saturating_sub(start));
    None
}

/// Bytes that end a word (and start a new one) outside quotes.
fn is_word_break(c: u8) -> bool {
    matches!(
        c,
        b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
    )
}

/// A heredoc delimiter word as bash reads it.
struct HeredocDelimiter {
    /// The delimiter text after quote removal; may be empty (`<<''`).
    text: Vec<u8>,
    /// Any part was quoted or escaped, so the body is literal.
    quoted: bool,
    /// The word holds syntax whose delimiter meaning T1 doesn't model (`$'…'`, `$"…"`, a
    /// backtick, an unterminated quote) or is missing: the caller fails upward.
    uncertain: bool,
    /// Index just past the word.
    end: usize,
}

/// Read a heredoc delimiter word starting at `i`, removing quotes as bash does:
/// - unquoted, a backslash-newline is a line continuation and is removed; another backslash
///   quotes the next byte;
/// - in single quotes every byte is literal;
/// - in double quotes, a backslash-newline is removed and `\"`, `\\`, `\$`, `` \` `` lose their
///   backslash; any other backslash is literal.
fn read_heredoc_delimiter(b: &[u8], mut i: usize) -> HeredocDelimiter {
    let start = i;
    let mut word = Vec::new();
    let mut quoted = false;
    let mut uncertain = false;
    while i < b.len() && !is_word_break(b[i]) {
        match b[i] {
            b'\\' if b.get(i + 1) == Some(&b'\n') => i += 2,
            b'\\' => {
                quoted = true;
                if let Some(&c) = b.get(i + 1) {
                    word.push(c);
                }
                i += 2;
            }
            b'$' if matches!(b.get(i + 1), Some(b'\'' | b'"')) => {
                uncertain = true;
                i += 1;
            }
            b'`' => {
                uncertain = true;
                word.push(b'`');
                i += 1;
            }
            b'\'' => {
                quoted = true;
                let end = find_byte(b, i + 1, b'\'').unwrap_or_else(|| {
                    uncertain = true;
                    b.len()
                });
                word.extend_from_slice(&b[i + 1..end]);
                i = end + 1;
            }
            b'"' => {
                quoted = true;
                let mut j = i + 1;
                loop {
                    match b.get(j) {
                        None => {
                            uncertain = true;
                            break;
                        }
                        Some(b'"') => break,
                        Some(b'\\') if b.get(j + 1) == Some(&b'\n') => j += 2,
                        Some(b'\\') if matches!(b.get(j + 1), Some(b'"' | b'\\' | b'$' | b'`')) => {
                            word.push(b[j + 1]);
                            j += 2;
                        }
                        Some(&c) => {
                            word.push(c);
                            j += 1;
                        }
                    }
                }
                note_scanned(j.min(b.len()) - i);
                i = j + 1;
            }
            c => {
                word.push(c);
                i += 1;
            }
        }
    }
    // `<<` with no word at all is a syntax error.
    uncertain |= i == start;
    HeredocDelimiter {
        text: word,
        quoted,
        uncertain,
        end: i.min(b.len()),
    }
}

/// Read the heredoc operator `<<` or `<<-` at `b[i]` and its delimiter: the pending heredoc,
/// whether its delimiter is uncertain, and the index just past the delimiter word.
fn heredoc_operator(b: &[u8], i: usize) -> (PendingHeredoc, usize) {
    let (heredoc, end, _) = heredoc_operator_checked(b, i);
    (heredoc, end)
}

/// [`heredoc_operator`], also reporting whether the delimiter is uncertain.
fn heredoc_operator_checked(b: &[u8], i: usize) -> (PendingHeredoc, usize, bool) {
    let strip_tabs = b.get(i + 2) == Some(&b'-');
    let mut p = i + 2 + usize::from(strip_tabs);
    while p < b.len() && (b[p] == b' ' || b[p] == b'\t') {
        p += 1;
    }
    let delimiter = read_heredoc_delimiter(b, p);
    (
        PendingHeredoc {
            delimiter: delimiter.text,
            strip_tabs,
            quoted: delimiter.quoted,
        },
        delimiter.end,
        delimiter.uncertain,
    )
}

/// Consume a heredoc body starting at `pos`: the index where the body ends, and the index just
/// past its delimiter line (both the end of the text when there is no delimiter line).
fn consume_heredoc(b: &[u8], pos: usize, heredoc: &PendingHeredoc) -> (usize, usize) {
    let mut line_start = pos;
    while line_start < b.len() {
        let line_end = find_byte(b, line_start, b'\n').unwrap_or(b.len());
        let mut line = &b[line_start..line_end];
        if heredoc.strip_tabs {
            while let Some((b'\t', rest)) = line.split_first() {
                line = rest;
            }
        }
        if line == heredoc.delimiter.as_slice() {
            return (line_start, (line_end + 1).min(b.len()));
        }
        line_start = line_end + 1;
    }
    (b.len(), b.len())
}

/// For a heredoc inside `$(…)` read the bash 5 way: the index of the `)` on the first body line
/// that starts with the delimiter followed by `)`, if that line comes before one equal to the
/// delimiter. bash 5 ends the body there and reads the `)` as closing the substitution.
fn heredoc_end_before_paren(b: &[u8], pos: usize, heredoc: &PendingHeredoc) -> Option<usize> {
    let mut line_start = pos;
    while line_start < b.len() {
        let line_end = find_byte(b, line_start, b'\n').unwrap_or(b.len());
        let mut start = line_start;
        if heredoc.strip_tabs {
            while b.get(start) == Some(&b'\t') && start < line_end {
                start += 1;
            }
        }
        let line = &b[start..line_end];
        if line == heredoc.delimiter.as_slice() {
            return None;
        }
        if line.starts_with(&heredoc.delimiter) && line.get(heredoc.delimiter.len()) == Some(&b')')
        {
            return Some(start + heredoc.delimiter.len());
        }
        line_start = line_end + 1;
    }
    None
}

/// The command substitutions in an unquoted heredoc body. Quotes are literal there; only `$(…)`,
/// backticks and backslash escapes are special.
fn heredoc_substitutions<'a>(
    body: &'a str,
    reading: Reading,
    out: &mut Vec<Substitution<'a>>,
) -> bool {
    let b = body.as_bytes();
    let mut unterminated = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'$' if b.get(i + 1) == Some(&b'(') => match find_closing_paren(b, i + 2, reading) {
                Some(end) => {
                    out.push(Substitution::closed(&body[i + 2..end]));
                    i = end + 1;
                }
                None => {
                    out.push(Substitution::unclosed(&body[i + 2..]));
                    unterminated = true;
                    i = b.len();
                }
            },
            b'`' => match find_closing_backtick(b, i + 1) {
                Some(end) => {
                    out.push(Substitution::closed(&body[i + 1..end]));
                    i = end + 1;
                }
                None => {
                    out.push(Substitution::unclosed(&body[i + 1..]));
                    unterminated = true;
                    i = b.len();
                }
            },
            _ => i += 1,
        }
    }
    unterminated
}

/// Is `prefix` (the text of a segment before some position) only shell keywords, so the next
/// word is at a command position?
fn at_command_position(prefix: &str) -> bool {
    prefix
        .split_ascii_whitespace()
        .all(|w| SHELL_KEYWORDS.contains(&w))
}

/// Split a command line the way bash does for risk: segments between unquoted control operators,
/// substitution bodies, and heredoc bodies. See [`Reading`] for the ambiguous rules.
///
/// Only ASCII bytes are ever matched, so every slice boundary falls on a UTF-8 char boundary.
fn scan_shell_line(text: &str, reading: Reading) -> ShellLine<'_> {
    let b = text.as_bytes();
    let mut line = ShellLine::default();
    let mut pending: Vec<PendingHeredoc> = Vec::new();
    let mut seg_start = 0;
    let mut in_double = false;
    // After a `((` that isn't an arithmetic command, don't retry inside the text already scanned
    // for its closing `))`: each byte is scanned for arithmetic at most once.
    let mut no_arithmetic_before = 0;
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
                        line.open_quote = true;
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
                            line.open_quote = true;
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
                        line.substitutions
                            .push(Substitution::closed(&text[i + 1..end]));
                        i = end + 1;
                    }
                    None => {
                        line.substitutions
                            .push(Substitution::unclosed(&text[i + 1..]));
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
                        line.substitutions
                            .push(Substitution::closed(&text[i + 2..end]));
                        i = end + 1;
                    }
                    None => {
                        line.substitutions
                            .push(Substitution::unclosed(&text[i + 2..]));
                        line.unterminated = true;
                        i = b.len();
                    }
                }
                continue;
            }
            b'(' if !in_double
                && b.get(i + 1) == Some(&b'(')
                && i >= no_arithmetic_before
                && at_command_position(&text[seg_start..i]) =>
            {
                // `((…))` at a command position: an arithmetic command, with no heredocs or
                // operators inside. Where the reading is off, it is two subshells (below).
                line.has_shell_syntax = true;
                match find_closing_paren(b, i + 2, reading) {
                    Some(inner) if b.get(inner + 1) == Some(&b')') => {
                        line.saw_arithmetic = true;
                        if reading.arithmetic_commands {
                            i = inner + 2;
                            continue;
                        }
                    }
                    Some(inner) => no_arithmetic_before = inner,
                    None => no_arithmetic_before = b.len(),
                }
                line.segments.push(&text[seg_start..i]);
                seg_start = i + 1;
            }
            b'<' if !in_double && b.get(i + 1) == Some(&b'<') => {
                line.has_shell_syntax = true;
                if b.get(i + 2) == Some(&b'<') {
                    i += 3; // `<<<` is a here-string, read with its segment's words
                    continue;
                }
                let (heredoc, end, uncertain) = heredoc_operator_checked(b, i);
                // A delimiter T1 can't read for sure fails upward: the body and what follows it
                // are still scanned as well as T1 can, and the line is at least High.
                line.unterminated |= uncertain;
                pending.push(heredoc);
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
                    let (end, next) = consume_heredoc(b, pos, &heredoc);
                    let body = &text[pos..end];
                    if !heredoc.quoted
                        && heredoc_substitutions(body, reading, &mut line.body_substitutions)
                    {
                        line.unterminated = true;
                    }
                    line.heredocs.push(body);
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
    line.open_quote |= in_double;
    line
}

// ── Words of a segment ────────────────────────────────────────────────────────

/// Split a segment into its raw words, keeping quotes and substitutions intact. Words end at
/// unquoted blanks, and also where an unquoted redirection operator (`<`, `>`, `&>`) starts after
/// other text, since bash reads those as metacharacters: `dd>/dev/null` is the word `dd` and the
/// redirection `>/dev/null`. A leading file-descriptor number stays with its operator (`2>&1`).
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
        // The word so far holds text other than an fd number or operator characters.
        let mut has_text = false;
        while i < b.len() && (in_double || !b[i].is_ascii_whitespace()) {
            let c = b[i];
            let starts_redirection = !in_double
                && ((matches!(c, b'<' | b'>') && b.get(i + 1) != Some(&b'('))
                    || (c == b'&' && b.get(i + 1) == Some(&b'>')));
            if starts_redirection && has_text {
                break;
            }
            if !matches!(c, b'<' | b'>' | b'&' | b'|') && !c.is_ascii_digit() {
                has_text = true;
            }
            match c {
                b'\\' => i += 2,
                b'\'' if !in_double => {
                    i = find_byte(b, i + 1, b'\'').map_or(b.len(), |q| q + 1);
                }
                b'$' if reading.ansi_c_quotes && !in_double && b.get(i + 1) == Some(&b'\'') => {
                    i = skip_ansi_c_string(b, i + 2).unwrap_or(b.len());
                }
                b'$' | b'<' | b'>' if b.get(i + 1) == Some(&b'(') && (c == b'$' || !in_double) => {
                    has_text = true;
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
/// after it, and whether the decoding is uncertain: an escape bash may decode differently (or not
/// at all, depending on its version), such as `\u` / `\U`, `\c`, an unknown escape, or a value
/// that isn't one byte.
fn decode_ansi_c_escape(b: &[u8], i: usize, out: &mut Vec<u8>) -> (usize, bool) {
    let Some(&c) = b.get(i) else {
        return (i, true);
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
        return (i + 1, false);
    }
    let hex_value = |from: usize, max_digits: usize| {
        let mut j = from;
        let mut value = 0u32;
        while j < b.len() && j < from + max_digits && b[j].is_ascii_hexdigit() {
            value = value * 16 + char::from(b[j]).to_digit(16).unwrap_or(0);
            j += 1;
        }
        (j, value)
    };
    match c {
        b'x' => {
            let (j, value) = hex_value(i + 1, 2);
            if j > i + 1 {
                out.push(u8::try_from(value).unwrap_or(b'?'));
                return (j, false);
            }
        }
        b'u' | b'U' => {
            // Unicode escapes exist in bash 4.2 and later only: decode them, but as uncertain.
            let (j, value) = hex_value(i + 1, if c == b'u' { 4 } else { 8 });
            if j > i + 1 {
                if let Some(ch) = char::from_u32(value) {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                return (j, true);
            }
        }
        b'c' => {
            if let Some(&ctl) = b.get(i + 1) {
                out.push(ctl & 0x1f);
                return (i + 2, true);
            }
        }
        b'0'..=b'7' => {
            let mut j = i;
            let mut value = 0u32;
            while j < b.len() && j < i + 3 && (b'0'..=b'7').contains(&b[j]) {
                value = value * 8 + u32::from(b[j] - b'0');
                j += 1;
            }
            let byte = u8::try_from(value);
            out.push(*byte.as_ref().unwrap_or(&b'?'));
            return (j, byte.is_err());
        }
        _ => {}
    }
    out.push(b'\\');
    out.push(c);
    (i + 1, true)
}

/// One word after quote removal.
struct Word {
    /// The word's text as the shell would pass it.
    text: String,
    /// It holds an expansion whose value T1 can't know: a parameter or command substitution
    /// (`$x`, `${x}`, `$(…)`, `<(…)`, a backtick; quoted or not, since double quotes don't stop
    /// expansion), or an unquoted glob (`*`, `?`, `[…]`) or brace list (`{a,b}`).
    expansion: bool,
    /// Its text may not be what bash passes: an ANSI-C escape bash may decode differently, a
    /// decoded NUL (bash ends the word there), or bytes that aren't UTF-8.
    uncertain: bool,
}

/// Remove a word's quotes the way bash would, charging its bytes to `budget`. Linear in the word:
/// no byte is examined more than twice (once to find the last `]`, once to unquote).
fn unquote_word(raw: &str, reading: Reading, budget: &mut Budget) -> Word {
    let b = raw.as_bytes();
    if !budget.spend(b.len()) {
        return Word {
            text: String::new(),
            expansion: true,
            uncertain: true,
        };
    }
    // `[` starts a glob only with a later `]` (`[` and `[[` alone are commands). One pass finds
    // the last `]`, so the check costs nothing per `[`.
    let last_close_bracket = b.iter().rposition(|&c| c == b']');
    note_scanned(b.len());
    let mut out = Vec::with_capacity(b.len());
    let mut expansion = false;
    let mut uncertain = false;
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
                        let (next, unsure) = decode_ansi_c_escape(b, j + 1, &mut out);
                        uncertain |= unsure;
                        j = next;
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
            b'<' | b'>' if b.get(i + 1) == Some(&b'(') => {
                expansion = true;
                out.push(b[i]);
                i += 1;
            }
            b'`' | b'*' | b'?' => {
                expansion = true;
                out.push(b[i]);
                i += 1;
            }
            b'[' => {
                expansion |= last_close_bracket.is_some_and(|close| close > i);
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
    // bash passes words as C strings: a decoded NUL ends the word.
    if let Some(nul) = out.iter().position(|&c| c == 0) {
        out.truncate(nul);
        uncertain = true;
    }
    let text = match String::from_utf8(out) {
        Ok(text) => text,
        Err(e) => {
            uncertain = true;
            String::from_utf8_lossy(e.as_bytes()).into_owned()
        }
    };
    Word {
        text,
        expansion,
        uncertain,
    }
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
    if word.contains("<(") || word.contains(">(") {
        return None; // a process substitution, not a redirection
    }
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

/// If `word` is a here-string redirection (`<<<`, optionally after an fd number), its attached
/// text (`Some("")` when the text is the next word).
fn here_string(word: &str) -> Option<&str> {
    let digits = word.bytes().take_while(u8::is_ascii_digit).count();
    word[digits..].strip_prefix("<<<")
}

/// The command word of a segment's unquoted words: the first word that isn't a keyword, a zsh
/// precommand, a redirection (with its target) or an assignment. Also returns the assignments
/// in front of it.
fn command_word(unquoted: &[Word]) -> (Option<usize>, Vec<String>) {
    let mut assignments = Vec::new();
    let mut i = 0;
    while i < unquoted.len() {
        let word = &unquoted[i];
        let text = word.text.as_str();
        if !word.expansion {
            if SHELL_KEYWORDS.contains(&text) {
                let skip_p = text == "time" && unquoted.get(i + 1).is_some_and(|w| w.text == "-p");
                i += 1 + usize::from(skip_p);
                continue;
            }
            if ZSH_PRECOMMANDS.contains(&text) {
                i += 1;
                continue;
            }
            if text == "repeat" {
                i += 2;
                continue;
            }
            if let Some(target_is_next) = redirection(text) {
                i += 1 + usize::from(target_is_next);
                continue;
            }
            if is_assignment_like(text) {
                assignments.push(word.text.clone());
                i += 1;
                continue;
            }
        }
        return (Some(i), assignments);
    }
    (None, assignments)
}

/// The program name a command word runs: zsh `=cmd` expands to the path of `cmd`.
fn program_name(word: &str) -> &str {
    match word.strip_prefix('=') {
        Some(name) if !name.is_empty() => name,
        _ => word,
    }
}

/// Classify one segment: skip the words in front of the command word, then classify the argv.
/// Every here-string in it is also classified as a script, whatever reads it (see
/// [`reading_risk`] for heredocs). `None` when the segment runs nothing.
fn segment_risk(
    segment: &str,
    depth: usize,
    reading: Reading,
    budget: &mut Budget,
) -> Option<Risk> {
    if !budget.spend(segment.len()) {
        return Some(Risk::High);
    }
    let raw = raw_words(segment, reading);
    let unquoted: Vec<Word> = raw
        .iter()
        .map(|w| unquote_word(w, reading, budget))
        .collect();
    let (command, mut words) = command_word(&unquoted);
    let mut risk = match command {
        None => (!words.is_empty()).then_some(Risk::Medium),
        // The command word is computed at run time (decision: unknowable ⇒ High).
        Some(c) if unquoted[c].expansion => Some(Risk::High),
        Some(c) => {
            words.push(program_name(&unquoted[c].text).to_string());
            words.extend(unquoted[c + 1..].iter().map(|w| w.text.clone()));
            let mut tier = classify_argv(&words, depth, budget);
            if unquoted[c].uncertain {
                // bash may run a different name than the one decoded: at least High.
                tier = max_risk(tier, Risk::High);
            }
            Some(tier)
        }
    };
    // A here-string is always also read as a script (deliberate fail-upward rule): whatever
    // consumes it may be a shell, directly or through a compound command, `eval` or a wrapper.
    for (k, w) in unquoted.iter().enumerate() {
        let script = match here_string(&w.text) {
            Some("") => unquoted.get(k + 1).map(|t| t.text.as_str()),
            Some(attached) => Some(attached),
            None => None,
        };
        if let Some(script) = script {
            risk = raise_opt(risk, command_string_risk(script, depth, budget));
        }
    }
    risk
}

/// The tier of one reading of a line: its segments, substitutions and heredoc bodies.
fn reading_risk(
    line: &ShellLine<'_>,
    depth: usize,
    reading: Reading,
    budget: &mut Budget,
) -> Option<Risk> {
    let mut tier = None;
    for segment in &line.segments {
        tier = raise_opt(tier, segment_risk(segment, depth, reading, budget));
    }
    for sub in line.substitutions.iter().chain(&line.body_substitutions) {
        tier = raise_opt(
            tier,
            script_risk(sub.body, sub.source(reading), depth, budget),
        );
    }
    // A heredoc body is always also read as a script (deliberate fail-upward rule): whatever
    // consumes it may be a shell, directly or through a compound command, `eval` or a wrapper.
    // Over-counting a body that is only data (`cat <<EOF`) can only raise the tier.
    for body in &line.heredocs {
        tier = raise_opt(tier, script_risk(body, Source::HeredocBody, depth, budget));
    }
    if line.has_shell_syntax {
        tier = raise(tier, Risk::Medium);
    }
    tier
}

/// The alternate readings worth analyzing for a line whose bash reading is `primary`: one per
/// ambiguity the line actually holds.
fn alternate_readings(text: &str, primary: &ShellLine<'_>) -> Vec<Reading> {
    let bash = Reading::BASH;
    let mut alternates = Vec::new();
    if primary.saw_comment {
        alternates.push(Reading {
            honor_comments: false,
            ..bash
        });
    }
    if primary.saw_ansi_c {
        alternates.push(Reading {
            ansi_c_quotes: false,
            ..bash
        });
    }
    if primary.saw_comment && primary.saw_ansi_c {
        alternates.push(Reading {
            honor_comments: false,
            ansi_c_quotes: false,
            ..bash
        });
    }
    if primary.saw_arithmetic {
        alternates.push(Reading {
            arithmetic_commands: false,
            ..bash
        });
    }
    if text.contains("<<") && (text.contains('(') || text.contains('`')) {
        alternates.push(Reading {
            heredocs_in_substitutions: false,
            ..bash
        });
    }
    if text.contains("<<") && text.contains("$(") {
        alternates.push(Reading {
            heredoc_ends_before_paren: true,
            ..bash
        });
    }
    alternates
}

/// Risk of every command a shell would run for `text`, or `None` when it runs nothing. See the
/// module doc § Command lines. Every alternate reading the line calls for is analyzed at every
/// nesting level, charged to the shared budget: a nested `dash -c` string gets dash's reading
/// too. The budget, not skipped readings, bounds the cost, and [`note_visible_programs`] keeps
/// the visible tiers if it runs out.
fn shell_line_risk(text: &str, source: Source, depth: usize, budget: &mut Budget) -> Option<Risk> {
    if !budget.spend(text.len()) {
        return Some(Risk::High);
    }
    let primary = scan_shell_line(text, Reading::BASH);
    let mut tier = reading_risk(&primary, depth, Reading::BASH, budget);
    if primary.unterminated || (primary.open_quote && source == Source::CommandLine) {
        // The shell runs what precedes the syntax error, and what follows can't be read.
        tier = raise(tier, Risk::High);
    }
    for reading in alternate_readings(text, &primary) {
        if !budget.spend(text.len()) {
            break;
        }
        let line = scan_shell_line(text, reading);
        tier = raise_opt(tier, reading_risk(&line, depth, reading, budget));
    }
    if budget.exhausted {
        // Keep what was found; what wasn't read counts as High.
        return raise(tier, Risk::High);
    }
    tier
}

// ── Lexical pre-pass ──────────────────────────────────────────────────────────

/// Record, before any budgeted work, the program-table tier of every program word visible in the
/// text: every word of `words` (the line's `shlex` split, or the argv), and the command word of
/// every segment of `line` in the bash reading, descending into substitutions, backticks and
/// heredoc bodies down to [`MAX_SHELL_NESTING`] levels. The pass isn't charged; each level scans
/// its text once, so it is linear for each level. Its tiers are only read if the budget runs out,
/// so a `dd` the line plainly runs, at the top level or in a `$(dd)`, keeps its tier however much
/// padding follows it. Counting a word that turns out not to run (`echo dd`) can only raise the
/// tier.
fn note_visible_programs(line: Option<&str>, words: &[String], budget: &mut Budget) {
    for word in words {
        budget.note(classify_program(word, &[], &[]));
    }
    if let Some(line) = line {
        note_line_programs(line, 0, budget);
    }
}

/// The [`note_visible_programs`] pass over one line at nesting `depth`.
fn note_line_programs(text: &str, depth: usize, budget: &mut Budget) {
    let mut unlimited = Budget::new(usize::MAX);
    let line = scan_shell_line(text, Reading::BASH);
    for segment in &line.segments {
        let unquoted: Vec<Word> = raw_words(segment, Reading::BASH)
            .iter()
            .map(|w| unquote_word(w, Reading::BASH, &mut unlimited))
            .collect();
        if let (Some(c), _) = command_word(&unquoted) {
            if !unquoted[c].expansion {
                let argv: Vec<String> = unquoted[c..].iter().map(|w| w.text.clone()).collect();
                let (flags, positionals) = split_flags_and_positionals(&argv);
                budget.note(classify_program(
                    program_name(&unquoted[c].text),
                    &flags,
                    &positionals,
                ));
            }
        }
    }
    if depth >= MAX_SHELL_NESTING {
        return;
    }
    // Substitutions inside heredoc bodies are reached through the bodies themselves.
    let substitutions = line.substitutions.iter().map(|sub| sub.body);
    for nested in substitutions.chain(line.heredocs.iter().copied()) {
        note_line_programs(nested, depth + 1, budget);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
