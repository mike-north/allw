//! Unit tests for the v1 command risk tier.
//!
//! Expected tiers are written by hand from the rules in the `risk` module doc and from what bash
//! actually runs, never from the analyzer's output. A prefix, wrapper, operator or substitution
//! never makes a command look less risky than a program it runs. The shared Rust ↔ WASM tables
//! are `tests/fixtures/command_risk_vectors.json` and `tests/fixtures/command_line_risk_vectors.json`.
//!
//! @see https://www.gnu.org/software/bash/manual/bash.html#Shell-Syntax
//! @see https://www.gnu.org/software/bash/manual/bash.html#Here-Documents
//! @see https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html

use super::*;
use crate::command::{action_from_argv, action_from_command, CommandContext};

fn ctx() -> CommandContext {
    CommandContext { cwd: None }
}

/// Risk of a command line through the public builder.
fn line_risk(cmd: &str) -> Risk {
    action_from_command(cmd, &ctx())
        .unwrap_or_else(|e| panic!("{cmd:?} must tokenize: {e}"))
        .risk
}

/// Risk of an argv that runs without a shell, through the public builder.
fn argv_of(argv: &[&str]) -> Risk {
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    action_from_argv(&argv, None, &ctx()).risk
}

fn assert_all(cmds: &[&str], expected: Risk) {
    for cmd in cmds {
        assert_eq!(line_risk(cmd), expected, "{cmd:?}");
    }
}

/// Run the analysis for `line` with a budget of `limit` units; return the tier and the budget.
fn analyze_with_budget(line: &str, limit: usize) -> (Risk, Budget) {
    let words = shlex::split(line).expect("test line must tokenize");
    let mut budget = Budget::new(limit);
    let risk = line_and_words_risk(line, &words, &mut budget);
    let risk = budget.finish(risk);
    (risk, budget)
}

// ── The program table ─────────────────────────────────────────────────────────

#[test]
fn table_critical_for_disk_tools() {
    assert_all(
        &[
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sdb1",
            "fdisk /dev/sda",
            "shred /dev/sda",
        ],
        Risk::Critical,
    );
}

#[test]
fn table_low_for_read_only_tools() {
    assert_all(
        &["ls -la", "cat /etc/hosts", "echo hello", "pwd", "whoami"],
        Risk::Low,
    );
}

/// Privilege escalation ranks High whichever tool does it (review decision: `doas`, `run0`,
/// `pkexec` like `sudo`).
#[test]
fn table_high_for_privilege_escalation() {
    assert_all(
        &[
            "sudo apt-get install vim",
            "doas ls",
            "run0 ls",
            "pkexec ls",
            "su root",
        ],
        Risk::High,
    );
}

#[test]
fn table_high_for_git_push_force() {
    assert_eq!(line_risk("git push --force origin main"), Risk::High);
}

/// Regression (#33 review): a force flag on a non-`push` git subcommand is not High.
#[test]
fn table_git_force_without_push_is_medium() {
    assert_eq!(line_risk("git checkout -f main"), Risk::Medium);
}

#[test]
fn table_unknown_commands_are_medium() {
    assert_eq!(line_risk("docker build ."), Risk::Medium);
}

// ── Assignments (#268) ────────────────────────────────────────────────────────

/// Regression (#268): a leading `NAME=value` hid the program, so `X=1 rm -rf ~` was Medium.
#[test]
fn assignment_prefix_does_not_hide_program() {
    assert_all(
        &["X=1 rm -rf ~", "FOO=1 git push --force origin main"],
        Risk::High,
    );
    assert_eq!(
        line_risk("A=1 B=2 dd if=/dev/zero of=/dev/sda"),
        Risk::Critical
    );
}

/// Regression (review of #268): bash also treats `X+=1` and `A[0]=1` as assignment prefixes.
#[test]
fn append_and_array_assignments_do_not_hide_program() {
    assert_all(&["X+=1 rm -rf ~", "A[0]=1 rm -rf ~"], Risk::High);
    assert_eq!(argv_of(&["X+=1", "rm", "-rf", "~"]), Risk::High);
    assert_eq!(argv_of(&["A[0]=1", "rm", "-rf", "~"]), Risk::High);
}

/// An assignment can change what a program does (`LD_PRELOAD`, `PATH`), so it is at least Medium.
#[test]
fn assignment_before_low_program_is_medium() {
    assert_eq!(line_risk("X=1 ls"), Risk::Medium);
    assert_eq!(line_risk("FOO=bar"), Risk::Medium);
}

/// Negative: a word whose name doesn't start like an identifier is the command, not skipped.
#[test]
fn invalid_assignment_name_is_the_command() {
    assert_eq!(line_risk("1FOO=1 rm -rf ~"), Risk::Medium);
    assert_eq!(line_risk("=1 rm -rf ~"), Risk::Medium);
}

// ── Wrappers (#268) ───────────────────────────────────────────────────────────

/// Regression (#268): `env rm -rf ~` was Low because `env` is on the read-only list.
#[test]
fn wrapper_never_lowers_wrapped_risk() {
    assert_all(
        &[
            "env rm -rf ~",
            "env FOO=1 rm -rf ~",
            "/usr/bin/env rm -rf ~",
            "command rm -rf ~",
            "builtin eval 'rm -rf ~'",
            "nice rm -rf ~",
            "nice -n 10 rm -rf ~",
            "exec rm -rf ~",
            "exec -a NAME rm -rf ~",
            "time rm -rf ~",
            "nohup rm -rf ~",
            "timeout 5 git push -f origin main",
            "xargs rm -rf",
            "gtimeout 5 rm -rf ~",
            "gnice rm -rf ~",
            "genv rm -rf ~",
            "gnohup rm -rf ~",
            "gstdbuf -o0 rm -rf ~",
            "caffeinate -i rm -rf ~",
            "arch -arm64 rm -rf ~",
            "script -q /dev/null rm -rf ~",
            "chroot / rm -rf ~",
            "flock /tmp/lock rm -rf ~",
            "busybox rm -rf ~",
            "find . -exec rm -rf {} +",
            "find . -execdir rm -rf {} ;",
            "find . -ok rm -rf {} ;",
            "ssh host rm -rf ~",
        ],
        Risk::High,
    );
    assert_eq!(
        line_risk("sudo dd if=/dev/zero of=/dev/sda"),
        Risk::Critical
    );
}

/// A wrapper word holding whitespace is a command line (`watch 'rm -rf ~'`, `ssh host 'cmd'`).
#[test]
fn wrapper_word_with_whitespace_is_read_as_a_command_line() {
    assert_all(
        &[
            "watch 'rm -rf ~'",
            "ssh host 'rm -rf ~'",
            "ssh host 'ls && rm -rf ~'",
            "nohup 'rm -rf ~'",
        ],
        Risk::High,
    );
}

/// Regression (review of #268): `env -S` splits its value into a command (attached, `=`, or the
/// next word, and inside a short-flag bundle such as `-iS`).
#[test]
fn env_split_string_is_read_as_a_command_line() {
    assert_all(
        &[
            "env -S 'rm -rf ~'",
            "env -S'rm -rf ~'",
            "env -iS'rm -rf ~'",
            "env --split-string='rm -rf ~'",
            "env --split-string 'rm -rf ~'",
        ],
        Risk::High,
    );
    assert_eq!(
        line_risk("env -S'dd if=/dev/zero of=/dev/sda'"),
        Risk::Critical
    );
}

/// A wrapper with nothing to run keeps its own tier; `env` running a program is never Low.
#[test]
fn wrapper_alone_keeps_own_tier_and_env_running_a_program_is_not_low() {
    assert_eq!(line_risk("env"), Risk::Low);
    assert_eq!(line_risk("env -i"), Risk::Low);
    assert_eq!(line_risk("env ls"), Risk::Medium);
    assert_eq!(line_risk("nice ls"), Risk::Medium);
}

/// Padding a wrapper's argv past `MAX_PROGRAM_CANDIDATES` can't push the real program out of view.
#[test]
fn padding_past_candidate_limit_does_not_hide_program() {
    let mut argv = vec!["env".to_string()];
    argv.extend(std::iter::repeat_n(
        "echo".to_string(),
        MAX_PROGRAM_CANDIDATES,
    ));
    argv.extend(["rm", "-rf", "~"].map(String::from));
    assert_eq!(action_from_argv(&argv, None, &ctx()).risk, Risk::High);

    let mut argv = vec!["X=1".to_string(); MAX_PROGRAM_CANDIDATES];
    argv.extend(["rm", "-rf", "~"].map(String::from));
    assert_eq!(action_from_argv(&argv, None, &ctx()).risk, Risk::High);
}

/// Negative: a long argv for a program that isn't a wrapper is not raised by truncation.
#[test]
fn long_non_wrapper_argv_is_not_raised() {
    let mut argv = vec!["ls".to_string()];
    argv.extend((0..MAX_PROGRAM_CANDIDATES + 10).map(|i| format!("file{i}")));
    assert_eq!(action_from_argv(&argv, None, &ctx()).risk, Risk::Low);
}

// ── Shells and eval ───────────────────────────────────────────────────────────

/// Regression (#268): `sh -c '<cmd>'` hid the command string. The string is a full command line
/// (wired to the shell-line rules), in every listed shell.
#[test]
fn shell_dash_c_reads_its_string_as_a_command_line() {
    assert_all(
        &[
            "sh -c 'rm -rf ~'",
            "bash -c 'git push --force'",
            "sh -c 'true; rm -rf ~'",
            "bash -o pipefail -c 'ls | rm -rf ~'",
            "zsh -c 'echo $(rm -rf ~)'",
            "fish -c 'rm -rf ~'",
            "csh -c 'rm -rf ~'",
            "tcsh -c 'rm -rf ~'",
            "mksh -c 'rm -rf ~'",
            "ash -c 'rm -rf ~'",
            "dash -c 'rm -rf ~'",
            "ksh -c 'rm -rf ~'",
            "bash --command 'rm -rf ~'",
            "xargs sh -c 'rm -rf ~'",
        ],
        Risk::High,
    );
    assert_eq!(
        line_risk("bash -lc 'dd if=/dev/zero of=/dev/sda'"),
        Risk::Critical
    );
    assert_eq!(
        line_risk("su -c 'dd if=/dev/zero of=/dev/sda'"),
        Risk::Critical
    );
}

/// PowerShell: `-Command` (any prefix) is read; `-EncodedCommand` can't be.
#[test]
fn powershell_command_strings() {
    assert_eq!(
        line_risk("pwsh -c 'dd if=/dev/zero of=/dev/sda'"),
        Risk::Critical
    );
    assert_eq!(
        line_risk("powershell -Command 'dd if=/dev/zero of=/dev/sda'"),
        Risk::Critical
    );
    assert_eq!(line_risk("pwsh -EncodedCommand ZABkAA=="), Risk::High);
    assert_eq!(line_risk("pwsh -ec ZABkAA=="), Risk::High);
    assert_eq!(line_risk("pwsh -File build.ps1"), Risk::Medium);
}

/// Negative: a shell running a script file keeps its own tier.
#[test]
fn shell_without_c_keeps_own_tier() {
    assert_eq!(line_risk("bash script.sh"), Risk::Medium);
    assert_eq!(line_risk("bash --norc script.sh"), Risk::Medium);
}

/// Regression (review of #268): an unreadable `-c` string is not one that runs nothing. bash runs
/// the lines before a syntax error, so it is High.
#[test]
fn unterminated_shell_string_is_high() {
    assert_eq!(line_risk("sh -c 'echo \"unterminated'"), Risk::High);
    assert_eq!(line_risk("bash -c \"rm -rf ~\necho 'x\""), Risk::High);
    assert_eq!(line_risk("sh -c 'echo $(ls'"), Risk::High);
}

/// Build an argv of `levels` nested `sh -c` wrappers around `innermost`.
fn nested_sh(levels: usize, innermost: &str) -> Vec<String> {
    let mut argv: Vec<String> = shlex::split(innermost).expect("innermost must tokenize");
    for _ in 0..levels {
        let inner = shlex::try_join(argv.iter().map(String::as_str)).expect("joinable");
        argv = vec!["sh".to_string(), "-c".to_string(), inner];
    }
    argv
}

/// `sh -c` nesting is analyzed up to `MAX_SHELL_NESTING` levels, and is High past it.
#[test]
fn nested_shells_up_to_limit_are_analyzed_and_past_it_are_high() {
    let argv = nested_sh(MAX_SHELL_NESTING, "dd if=/dev/zero of=/dev/sda");
    assert_eq!(action_from_argv(&argv, None, &ctx()).risk, Risk::Critical);
    let argv = nested_sh(MAX_SHELL_NESTING, "echo hi");
    assert_eq!(action_from_argv(&argv, None, &ctx()).risk, Risk::Medium);
    let argv = nested_sh(MAX_SHELL_NESTING + 1, "echo hi");
    assert_eq!(action_from_argv(&argv, None, &ctx()).risk, Risk::High);
}

#[test]
fn eval_reads_its_arguments_as_a_command_line() {
    assert_all(
        &["eval 'rm -rf /'", "eval rm -rf /", "eval 'ls; rm -rf /'"],
        Risk::High,
    );
    assert_eq!(
        line_risk("eval 'ls && dd if=/dev/zero of=/dev/sda'"),
        Risk::Critical
    );
    assert_eq!(argv_of(&["eval", "rm -rf /"]), Risk::High);
}

/// Mutant M2 (review of #272): `eval` nested past `MAX_SHELL_NESTING` is High, not analyzed.
#[test]
fn eval_nested_past_limit_is_high() {
    let evals = |n: usize| format!("{}dd if=/dev/zero of=/dev/sda", "eval ".repeat(n));
    assert_eq!(line_risk(&evals(MAX_SHELL_NESTING)), Risk::Critical);
    assert_eq!(line_risk(&evals(MAX_SHELL_NESTING + 1)), Risk::High);
}

/// Mutant M3 (review of #272): `eval` with nothing to run keeps its own tier (Medium), not Low.
#[test]
fn eval_with_no_command_is_medium() {
    assert_eq!(line_risk("eval"), Risk::Medium);
    assert_eq!(line_risk("eval ''"), Risk::Medium);
    assert_eq!(line_risk("eval '   '"), Risk::Medium);
}

// ── Command lines (#272) ──────────────────────────────────────────────────────

/// Regression (#272): `ls && rm -rf /` was Low because only `ls` was classified.
#[test]
fn control_operators_expose_every_command() {
    assert_all(
        &[
            "ls && rm -rf /",
            "ls || rm -rf /",
            "ls & rm -rf /",
            "ls; rm -rf /",
            "ls\nrm -rf /",
            "ls | rm -rf /",
            "git status && git push --force",
            "ls &! rm -rf /",
            "ls &| rm -rf /",
        ],
        Risk::High,
    );
}

/// Regression (#272): a substitution's command ran unseen.
#[test]
fn substitutions_are_classified() {
    assert_all(
        &[
            "echo $(rm -rf ~)",
            "echo `rm -rf ~`",
            "echo \"$(rm -rf ~)\"",
            "cat <(rm -rf ~)",
            "tee >(rm -rf ~)",
            "echo $(echo $(rm -rf ~))",
            "X=$(rm -rf ~) ls",
        ],
        Risk::High,
    );
}

/// An unterminated substitution still has its body classified, and the line is High.
#[test]
fn unterminated_substitution_is_high() {
    assert_all(
        &["echo $(rm -rf ~", "echo `rm -rf ~", "echo $(ls"],
        Risk::High,
    );
}

/// Shell syntax with only Low commands is at least Medium.
#[test]
fn shell_syntax_is_at_least_medium() {
    assert_all(
        &[
            "echo hi > /etc/passwd",
            "ls 2>&1",
            "ls | cat",
            "ls &>/dev/null",
            "echo $((1+2))",
            "cat <<< hi",
        ],
        Risk::Medium,
    );
}

/// Compound commands: keywords, groups and subshells don't hide the program.
#[test]
fn keywords_groups_and_subshells_do_not_hide_program() {
    assert_all(
        &[
            "if true; then rm -rf /; fi",
            "for f in a; do rm -rf $f; done",
            "{ rm -rf /; }",
            "(rm -rf /)",
            "! rm -rf /",
            "time -p rm -rf ~",
            "coproc NAME { rm -rf ~; }",
            "function f { rm -rf ~; }",
            "if true { rm -rf ~ }",
            "while true; do rm -rf ~; done",
            "case x in x) rm -rf ~;; esac",
        ],
        Risk::High,
    );
}

/// Redirections and assignments in front of the command word are skipped (review of #272).
#[test]
fn prefix_redirections_do_not_hide_program() {
    assert_all(
        &[
            "2>/dev/null rm -rf ~",
            "> out rm -rf ~",
            ">out rm -rf ~",
            "2>&1 rm -rf ~",
            "&>/dev/null rm -rf ~",
            "< in rm -rf ~",
            "FOO=1 2>/dev/null rm -rf ~",
            ">> log X=1 rm -rf ~",
        ],
        Risk::High,
    );
}

/// zsh precommand words get fail-upward handling: they are skipped like wrappers.
#[test]
fn zsh_precommands_do_not_hide_program() {
    assert_all(
        &[
            "noglob rm -rf ~",
            "nocorrect rm -rf ~",
            "- rm -rf ~",
            "repeat 3 rm -rf ~",
            "=rm -rf ~",
        ],
        Risk::High,
    );
}

/// Decision (a) of the #272 review: a command word T1 can't know statically is High.
#[test]
fn unknowable_command_word_is_high() {
    assert_all(
        &[
            "$CMD -rf ~",
            "${CMD} x",
            "\"$CMD\" x",
            "$(echo ls) x",
            "`echo ls` x",
            "r* -rf ~",
            "r? -rf ~",
            "[r]m -rf ~",
            "{rm,ls} -rf ~",
            "X=1 $CMD",
        ],
        Risk::High,
    );
}

/// In bash, `$'…'` and `$"…"` are decoded before the command word is classified.
#[test]
fn ansi_c_and_locale_strings_are_decoded() {
    assert_all(
        &[
            "$'rm' -rf ~",
            "$'\\x72m' -rf ~",
            "$'\\162m' -rf ~",
            "$\"rm\" -rf ~",
            "r$'m' -rf ~",
        ],
        Risk::High,
    );
    assert_eq!(line_risk("$'dd' if=/dev/zero of=/dev/sda"), Risk::Critical);
}

/// Negative: expansions and globs in arguments don't make a Low command High, and a bare `[`
/// is the `test` command, not a glob.
#[test]
fn expansions_in_arguments_do_not_raise() {
    assert_all(
        &["echo $HOME", "ls *.txt", "ls {a,b}", "echo ${HOME}"],
        Risk::Low,
    );
    assert_eq!(line_risk("[ -f x ]"), Risk::Medium);
    assert_eq!(line_risk("[[ -f x ]] && ls"), Risk::Medium);
}

/// Negative: quoted or escaped operators and substitutions are literal and don't raise risk.
#[test]
fn quoted_or_escaped_syntax_is_literal() {
    assert_all(
        &[
            "echo 'ls && rm -rf /'",
            "echo \"a && rm -rf /\"",
            "echo \\&\\& rm -rf /",
            "echo '$(rm -rf ~)'",
            "echo \"a\nb\"",
            "echo '{ rm -rf / }'",
        ],
        Risk::Low,
    );
}

/// A quote inside a comment must not hide the next line.
#[test]
fn quote_in_comment_does_not_hide_next_line() {
    assert_eq!(line_risk("ls # it's\nrm -rf /"), Risk::High);
}

/// `#` mid-word is not a comment; an unquoted `#` at a word start is read both ways.
#[test]
fn comment_readings() {
    assert_eq!(line_risk("ls # && rm -rf /"), Risk::High);
    assert_eq!(line_risk("echo a#b"), Risk::Low);
}

/// In bash, `$'\''` is a one-character string, so the next line runs.
#[test]
fn ansi_c_quote_does_not_hide_next_line() {
    assert_eq!(line_risk("echo $'\\''\nrm -rf /\n'"), Risk::High);
}

/// Mutant M6 (review of #272): `find_closing_paren` skips `$'…'`, so a `)` inside one doesn't
/// close the substitution.
#[test]
fn closing_paren_skips_ansi_c_strings() {
    let text = b"echo $'\\')' x) y";
    let close = find_closing_paren(text, 0, Reading::BASH).expect("closed");
    assert_eq!(&text[close..], b") y");
    let plain = Reading {
        ansi_c_quotes: false,
        ..Reading::BASH
    };
    let close = find_closing_paren(text, 0, plain).expect("closed");
    assert_eq!(&text[close..], b")' x) y");
}

#[test]
fn non_ascii_text_is_scanned_safely() {
    assert_eq!(line_risk("echo héllo && rm -rf /"), Risk::High);
    assert_eq!(line_risk("echo 日本 $(rm -rf ~)"), Risk::High);
    assert_eq!(line_risk("echo \\é && rm -rf /"), Risk::High);
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

#[test]
fn nested_substitutions_up_to_limit_are_analyzed_and_past_it_are_high() {
    let line = nested_substitutions(MAX_SHELL_NESTING, "dd if=/dev/zero of=/dev/sda");
    assert_eq!(line_risk(&line), Risk::Critical);
    let line = nested_substitutions(MAX_SHELL_NESTING, "echo hi");
    assert_eq!(line_risk(&line), Risk::Medium);
    let line = nested_substitutions(MAX_SHELL_NESTING + 1, "echo hi");
    assert_eq!(line_risk(&line), Risk::High);
}

/// Negative: `action_from_argv` binds an argv that runs without a shell, so operator words in it
/// are literal arguments and don't raise risk (`raw` is display text, not what runs).
#[test]
fn argv_records_are_not_read_as_shell_lines() {
    let argv: Vec<String> = ["ls", "&&", "rm", "-rf", "/"].map(String::from).to_vec();
    let r = action_from_argv(&argv, Some("ls && rm -rf /"), &ctx());
    assert_eq!(r.risk, Risk::Low);
}

// ── Heredocs (review of #272, blocker) ────────────────────────────────────────

/// Regression (review of #272): a quote in a heredoc body desynchronized the scanner and hid
/// every later line. These are the review's three rows.
#[test]
fn heredoc_body_quotes_do_not_hide_later_lines() {
    assert_all(
        &[
            "cat > notes.md <<EOF\nDon't panic\nEOF\nrm -rf / # '",
            "cat <<'EOF'\nit's\nEOF\nrm -rf / #'",
            "cat <<EOF\nsay \"hi\nEOF\nrm -rf /\necho \"",
        ],
        Risk::High,
    );
}

/// `<<-` strips leading tabs before matching the delimiter.
#[test]
fn heredoc_dash_strips_tabs() {
    assert_eq!(
        line_risk("cat <<-EOF\n\tDon't\n\tEOF\nrm -rf / #'"),
        Risk::High
    );
}

/// `<<<` is a here-string, not a heredoc: the next line is a command.
#[test]
fn here_string_is_not_a_heredoc() {
    assert_eq!(line_risk("cat <<<EOF\nrm -rf /"), Risk::High);
    assert_eq!(line_risk("cat <<< \"it's\"; rm -rf /"), Risk::High);
}

/// Deliberate fail-upward rule (round 3 of the #284 review): a heredoc body is always also read
/// as a script, whatever consumes it, quoted delimiter or not. An unquoted delimiter's body
/// substitutions run in any case.
#[test]
fn heredoc_bodies_are_always_also_scripts() {
    assert_all(
        &[
            "cat <<EOF\nrm -rf /\nEOF",
            "cat <<EOF\n$(rm -rf ~)\nEOF",
            "cat <<EOF\n`rm -rf ~`\nEOF",
            "cat <<'EOF'\n$(rm -rf ~)\nEOF",
            "cat <<\"EOF\"\nrm -rf ~\nEOF",
            "cat <<\\EOF\nrm -rf ~\nEOF",
        ],
        Risk::High,
    );
    // Negative: a harmless body keeps the line's own tier.
    assert_eq!(line_risk("cat <<EOF\nhello world\nEOF"), Risk::Medium);
    // Prose with paired apostrophes reads as a harmless script. (An odd apostrophe makes the line
    // fail to tokenize before risk is computed.)
    assert_eq!(
        line_risk("cat > notes.md <<'EOF'\nDon't panic, it's fine\nEOF"),
        Risk::Medium
    );
}

/// With no delimiter line the body runs to the end of the text.
#[test]
fn heredoc_without_delimiter_runs_to_end() {
    assert_eq!(line_risk("cat <<EOF\nrm -rf /"), Risk::High);
    assert_eq!(line_risk("cat <<EOF\nhello"), Risk::Medium);
}

/// Two heredocs on one line are consumed in order, and both bodies are read as scripts.
#[test]
fn multiple_heredocs_are_consumed_in_order() {
    assert_eq!(line_risk("cat <<A <<B\nx\nA\ny\nB\nrm -rf /"), Risk::High);
    assert_eq!(line_risk("cat <<A <<B\nx\nA\nrm -rf /\nB"), Risk::High);
    assert_eq!(line_risk("cat <<A <<B\nx\nA\ny\nB"), Risk::Medium);
}

/// A heredoc fed to a shell is a script, so its body is classified as one even when quoted.
#[test]
fn heredoc_fed_to_a_shell_is_a_script() {
    assert_eq!(line_risk("bash <<'EOF'\nrm -rf /\nEOF"), Risk::High);
    assert_eq!(line_risk("sh <<EOF\nls\nEOF"), Risk::Medium);
}

// ── Work budget ───────────────────────────────────────────────────────────────

/// The review's input for #268: 4 levels of `bash … bash -c '<inner>'` around `dd`.
fn review_nested_bash(k: usize) -> String {
    let mut s = "dd if=/dev/zero of=/dev/sda".to_string();
    for _ in 0..4 {
        s = format!(
            "{}-c {}",
            "bash ".repeat(k),
            shlex::try_quote(&s).expect("quotable")
        );
    }
    s
}

/// Regression (review of #268, blocker): every shell position re-split every later word, so this
/// input cost about k^4. Each string is now analyzed once per level: at k = 80 the analysis
/// finishes well inside the budget, reaches `dd`, and its work is linear in the input.
#[test]
fn budget_review_nested_bash_is_linear_and_reaches_the_program() {
    let line = review_nested_bash(80);
    let (risk, budget) = analyze_with_budget(&line, MAX_RISK_WORK);
    assert_eq!(risk, Risk::Critical);
    assert!(!budget.exhausted);
    assert!(
        budget.used < 64 * line.len(),
        "work {} for a {}-byte line is not linear",
        budget.used,
        line.len()
    );
}

/// The same input with a budget too small for it takes the exhaustion branch and is at least High.
#[test]
fn budget_exhaustion_on_review_nested_bash_is_high() {
    let line = review_nested_bash(80).replace("dd if=/dev/zero of=/dev/sda", "echo hi");
    let (full, budget) = analyze_with_budget(&line, MAX_RISK_WORK);
    assert_eq!(full, Risk::Medium, "the full analysis finds only echo");
    let (risk, small) = analyze_with_budget(&line, budget.used / 2);
    assert!(small.exhausted);
    assert_eq!(risk, Risk::High);
}

/// A megabyte `eval` chain exhausts the default budget and is High.
#[test]
fn budget_exhaustion_on_megabyte_eval_chain_is_high() {
    let line = format!("{}echo hi", "eval ".repeat(220_000));
    let (risk, budget) = analyze_with_budget(&line, MAX_RISK_WORK);
    assert!(budget.exhausted);
    assert_eq!(risk, Risk::High);
    assert_eq!(line_risk(&line), Risk::High);
}

/// A megabyte `$(` chain exhausts the default budget and is High.
#[test]
fn budget_exhaustion_on_megabyte_substitution_chain_is_high() {
    let n = 150_000;
    let line = format!("{}true{}", "echo $(".repeat(n), ")".repeat(n));
    let (risk, budget) = analyze_with_budget(&line, MAX_RISK_WORK);
    assert!(budget.exhausted);
    assert_eq!(risk, Risk::High);
}

/// Negative: exhaustion never lowers a tier already found.
#[test]
fn budget_exhaustion_keeps_a_higher_tier() {
    let budget = Budget {
        limit: 0,
        used: 0,
        exhausted: true,
        found: Risk::Low,
    };
    assert_eq!(budget.finish(Risk::Critical), Risk::Critical);
    assert_eq!(budget.finish(Risk::Low), Risk::High);
}

// ── Review of #284 (second round): each probe is a regression test ───────────

/// Measure the bytes the look-ahead scans actually examine while analyzing `line`.
fn scanned_while(line: &str) -> (Risk, Budget, usize) {
    SCANNED.with(|c| c.set(0));
    let (risk, budget) = analyze_with_budget(line, MAX_RISK_WORK);
    (risk, budget, SCANNED.with(std::cell::Cell::get))
}

/// Regression (#284 review, finding 1): each `[` rescanned the rest of the word for a `]`, so
/// `[` × n cost n²/2 byte examinations that the budget never saw. The work actually done is now
/// linear, measured by the scan counter rather than the budget's own debits.
#[test]
fn repeated_brackets_are_scanned_in_linear_work() {
    for line in [
        "[".repeat(160_000),
        format!("echo {}", "[".repeat(160_000)),
        format!("sh -c '{}'", "[".repeat(160_000)),
    ] {
        let (risk, budget, scanned) = scanned_while(&line);
        assert!(!budget.exhausted, "{} bytes", line.len());
        assert!(
            scanned < 16 * line.len(),
            "scanned {scanned} bytes for a {}-byte line",
            line.len()
        );
        assert!(budget.used < 16 * line.len());
        assert_eq!(risk, line_risk(&line));
    }
    // With a closing bracket the command word is a glob.
    assert_eq!(line_risk(&format!("{}]", "[".repeat(1_000))), Risk::High);
}

/// Other look-ahead shapes stay linear too: unclosed quotes, substitutions, backticks, ANSI-C
/// strings and heredocs.
#[test]
fn adversarial_scan_shapes_are_linear() {
    let n = 50_000;
    for line in [
        format!("echo {}", "$(".repeat(n)),
        format!("echo {}", "`a` ".repeat(n)),
        format!("echo {}", "$'a' ".repeat(n)),
        format!("echo {}", "'a' ".repeat(n)),
        format!("cat {}\nx", "<<A ".repeat(n)),
        format!("echo {}", "{a,".repeat(n)),
        format!("echo {}", "a>b".repeat(n)),
    ] {
        let (_, _, scanned) = scanned_while(&line);
        assert!(
            scanned < 64 * line.len(),
            "scanned {scanned} bytes for {} bytes",
            line.len()
        );
    }
}

/// Regression (#284 review, finding 2): padding after a found `dd` exhausted the budget, and the
/// exhaustion path returned High, erasing Critical. Exhaustion now keeps every tier found.
#[test]
fn budget_exhaustion_never_lowers_a_found_tier() {
    let line = format!("echo $(dd) $(echo {})", "x".repeat(1_100_000));
    let (risk, budget) = analyze_with_budget(&line, MAX_RISK_WORK);
    assert!(budget.exhausted);
    assert_eq!(risk, Risk::Critical);
    assert_eq!(line_risk(&line), Risk::Critical);

    // A tier found in an earlier segment survives exhaustion in a later one.
    let line = format!("dd; echo $(echo {})", "x".repeat(2_000_000));
    let (risk, budget) = analyze_with_budget(&line, MAX_RISK_WORK);
    assert!(budget.exhausted);
    assert_eq!(risk, Risk::Critical);

    // The same through the alternate (no-comment) reading running out of budget.
    let line = format!("dd if=/dev/zero of=/dev/sda # {}", "x".repeat(1_500_000));
    let (risk, budget) = analyze_with_budget(&line, MAX_RISK_WORK);
    assert!(budget.exhausted);
    assert_eq!(risk, Risk::Critical);
}

/// Regression (#284 review, finding 3): bash reads `<` / `>` as metacharacters, so `dd>/dev/null`
/// runs `dd`. The word splitter took `dd>/dev/null` as one command name.
#[test]
fn adjacent_redirections_do_not_hide_the_program() {
    assert_all(
        &[
            "dd>/dev/null",
            "dd</dev/null",
            "dd&>/dev/null",
            "dd 2>/dev/null",
            "dd>>log",
            "bash -c 'dd</dev/null'",
            "X=1>out dd",
        ],
        Risk::Critical,
    );
    assert_eq!(line_risk("rm -rf ~>/dev/null"), Risk::High);
    // Negative: an fd number stays with its operator, and redirections alone are Medium.
    assert_eq!(line_risk("ls 2>&1"), Risk::Medium);
    assert_eq!(line_risk("echo hi>out"), Risk::Medium);
}

/// Regression (#284 review, finding 4): an empty quoted delimiter (`<<''`) was dropped, and a
/// backslash-newline inside a delimiter was kept, so the body's quote hid the next command.
#[test]
fn empty_and_continued_heredoc_delimiters_do_not_hide_later_lines() {
    assert_eq!(line_risk("cat <<''\nit's\n\ndd # '\n"), Risk::Critical);
    assert_eq!(
        line_risk("cat <<E\\\nOF\nit's\nEOF\ndd # '\n"),
        Risk::Critical
    );
    // The empty delimiter ends the body at the first empty line; the body is read as a script.
    assert_eq!(line_risk("cat <<''\ndd\n\nls"), Risk::Critical);
}

/// A delimiter T1 can't read for sure fails upward to at least High.
#[test]
fn uncertain_heredoc_delimiters_fail_upward() {
    assert_eq!(line_risk("cat <<$'EOF'\nx\nEOF"), Risk::High);
    assert_eq!(line_risk("cat <<`x`\nx\n`x`"), Risk::High);
    assert_eq!(line_risk("cat <<"), Risk::High);
}

/// Regression (#284 review, finding 5): bash ends a word at a decoded NUL, and modern bash
/// decodes `\u` escapes, so both of these run `dd`. The decoder kept NUL and its suffix, and left
/// `\u` undecoded, inventing a Medium name.
#[test]
fn ansi_c_decoding_matches_bash_or_fails_upward() {
    assert_eq!(
        line_risk("$'dd\\0ignored' if=/dev/zero of=/dev/sda"),
        Risk::Critical
    );
    assert_eq!(
        line_risk("$'\\u0064\\u0064' if=/dev/zero of=/dev/sda"),
        Risk::Critical
    );
    assert_eq!(
        line_risk("$'\\U00000064d' if=/dev/zero of=/dev/sda"),
        Risk::Critical
    );
    // Decodings bash may do differently are at least High even when they name a Low program.
    assert_all(
        &[
            "$'\\u006c\\u0073'",
            "$'l\\0x's",
            "$'\\q'",
            "$'\\777'",
            "$'\\xff'",
        ],
        Risk::High,
    );
    // Negative: plain escapes decode exactly and aren't raised (the shlex word `$l\x73` reading
    // keeps it at Medium).
    assert_eq!(line_risk("$'l\\x73' -la"), Risk::Medium);
}

/// Regression (#284 review, finding 6): `fed_to_shell` checked only the first word, so a curated
/// wrapper in front of the shell hid a heredoc script.
#[test]
fn wrapped_shell_reads_heredoc_as_a_script() {
    assert_all(
        &[
            "env bash <<'EOF'\necho hi;dd if=/dev/zero of=/dev/sda\nEOF",
            "nohup sh <<EOF\ndd if=/dev/zero of=/dev/sda\nEOF",
            "sudo -u nobody bash <<'EOF'\ndd if=/dev/zero of=/dev/sda\nEOF",
            "FOO=1 env -i zsh <<'EOF'\ndd if=/dev/zero of=/dev/sda\nEOF",
        ],
        Risk::Critical,
    );
    // A heredoc body is always also read as a script, so a non-shell consumer counts too
    // (deliberate fail-upward rule, round 3 of the #284 review).
    assert_eq!(
        line_risk("cat <<'EOF'\ndd if=/dev/zero of=/dev/sda\nEOF"),
        Risk::Critical
    );
}

/// #284 review, finding 7: a here-string fed to a shell is a script, through the same
/// shell detection as heredocs.
#[test]
fn here_string_fed_to_a_shell_is_a_script() {
    assert_all(
        &[
            "bash <<< \"dd if=/dev/zero of=/dev/sda\"",
            "bash<<<'dd if=/dev/zero of=/dev/sda'",
            "env sh <<< 'ls; dd if=/dev/zero of=/dev/sda'",
            "<<< 'dd if=/dev/zero of=/dev/sda' bash",
            "bash 0<<<'dd if=/dev/zero of=/dev/sda'",
        ],
        Risk::Critical,
    );
    // A here-string is always also read as a script, whatever consumes it.
    assert_eq!(
        line_risk("cat <<< \"dd if=/dev/zero of=/dev/sda\""),
        Risk::Critical
    );
    // Negative: a harmless here-string keeps the line's own tier.
    assert_eq!(line_risk("cat <<< hello"), Risk::Medium);
}

// ── Review of #284 (round 3): each repro is a regression test ────────────────

const DD: &str = "dd if=/dev/zero of=/dev/sda";

/// The reviewer's nested `#` + `$'…'` + `$(` bomb around `n` filler words.
fn readings_bomb(n: usize) -> String {
    let mut s = "x ".repeat(n);
    for _ in 0..4 {
        s = format!("#\n$'a' $({s})");
    }
    s
}

/// Regression (#284 review round 2, R2-1): `dd` runs first, but padding after it exhausted the
/// budget before `argv[0]` was recorded, so the line was High. The unbudgeted pre-pass records
/// every visible program word first.
#[test]
fn a_visible_first_program_survives_budget_exhaustion() {
    let bomb = shlex::try_quote(&readings_bomb(4000))
        .expect("quotable")
        .into_owned();
    for line in [
        format!("{DD}; sh -c {bomb}"),
        format!("{DD}; : sh {bomb}"),
        format!("{DD}; :{}", " rm".repeat(17_000)),
        format!("{DD}{}", " rm".repeat(20_000)),
    ] {
        assert_eq!(line_risk(&line), Risk::Critical, "{} bytes", line.len());
    }
}

/// Alternate readings run at every nesting level (review round 3, R3-1), so readings can
/// multiply with depth. The shared budget bounds that: the reviewer's 8 KB readings bomb
/// exhausts it and is High, and the work actually done stays a small multiple of the budget.
#[test]
fn nested_alternate_readings_are_bounded_by_the_budget() {
    for bomb in [readings_bomb(4000), readings_bomb(40_000)] {
        let line = format!("sh -c {}", shlex::try_quote(&bomb).expect("quotable"));
        let (risk, budget, scanned) = scanned_while(&line);
        assert_eq!(risk, Risk::High);
        assert!(budget.used <= MAX_RISK_WORK);
        assert!(scanned < 8 * MAX_RISK_WORK, "scanned {scanned}");
    }
}

/// Regression (R2-2): inside a double-quoted delimiter bash removes `\⏎`, so the delimiter is
/// `EOF` and the line after the body runs.
#[test]
fn double_quoted_delimiter_drops_backslash_newline() {
    assert_eq!(
        line_risk(&format!("cat <<\"E\\\nOF\"\nit's\nEOF\n{DD} # '\n")),
        Risk::Critical
    );
    // `\"` inside double quotes is a literal quote in the delimiter.
    assert_eq!(
        line_risk(&format!("cat <<\"E\\\"F\"\nit's\nE\"F\n{DD} # '\n")),
        Risk::Critical
    );
}

/// Regression (R2-3): `<<` inside an arithmetic command is a shift, not a heredoc.
#[test]
fn arithmetic_commands_have_no_heredocs() {
    assert_all(
        &[
            &format!("(( x = 1<<2 ))\n{DD}"),
            &format!("for ((i=1<<2; i<0; i++)); do :; done\n{DD}"),
            &format!("if ((1<<2)); then :; fi\n{DD}"),
        ],
        Risk::Critical,
    );
    // Two subshells that aren't arithmetic are still read as subshells.
    assert_eq!(line_risk(&format!("((ls); {DD})")), Risk::Critical);
}

/// Regression (R2-4): bash ≥ 4 reads a heredoc inside `$( )`, so a `)` in its body doesn't end
/// the substitution. bash 3.2 closes at the first `)`; both readings are analyzed.
#[test]
fn heredoc_inside_substitution_does_not_end_it_early() {
    assert_eq!(
        line_risk(&format!("echo $(cat <<'EOF'\n) it's\nEOF\n)\n{DD} # '")),
        Risk::Critical
    );
}

/// Regression (R2-5): a heredoc or here-string on a compound command or behind `eval` feeds a
/// shell. Bodies are now always read as scripts, whatever consumes them.
#[test]
fn heredoc_on_compound_command_or_eval_is_read() {
    assert_all(
        &[
            &format!("{{ bash; }} <<'EOF'\n{DD}\nEOF"),
            &format!("( bash ) <<'EOF'\n{DD}\nEOF"),
            &format!("{{ bash; }} <<< '{DD}'"),
            &format!("if true; then bash; fi <<'EOF'\n{DD}\nEOF"),
            &format!("eval bash <<'EOF'\n{DD}\nEOF"),
            &format!("while read x; do bash; done <<'EOF'\n{DD}\nEOF"),
        ],
        Risk::Critical,
    );
}

/// R2-6: `rm`'s flag split copies `argv[j..]`, so it is charged by bytes copied, not by words.
#[test]
fn rm_flag_split_is_charged_by_bytes() {
    let mut argv: Vec<String> = vec!["env".to_string()];
    argv.extend(std::iter::repeat_n("rm".to_string(), 255));
    argv.push("x".repeat(4 * 1024 * 1024));
    SCANNED.with(|c| c.set(0));
    let risk = action_from_argv(&argv, None, &ctx()).risk;
    let scanned = SCANNED.with(std::cell::Cell::get);
    assert!(matches!(risk, Risk::High | Risk::Critical), "{risk:?}");
    assert!(scanned < 3 * MAX_RISK_WORK, "copied {scanned} bytes");
}

// ── Review of #284 (round 3 findings): each repro is a regression test ───────

/// dash runs the `dd` in these; bash reads `$'\''` as one ANSI-C string, and `((…))` as
/// arithmetic.
const DASH_ANSI_C: &str = "echo $'\\' ; dd if=/dev/zero of=/dev/sda ; echo \\'''";
const DASH_ARITH: &str = "((: ; dd if=/dev/zero of=/dev/sda))";

fn quoted(text: &str) -> String {
    shlex::try_quote(text).expect("quotable").into_owned()
}

/// Regression (R3-1): alternate readings ran only at the top level, so a nested `dash -c`
/// string was read the bash way only and dash's `dd` was missed (Medium). They run at every
/// level again.
#[test]
fn nested_lines_get_every_reading() {
    let one_line = format!("echo $'\\'\n{DD}\necho \\''");
    let mut lines = vec![format!("dash -c {}", quoted(&one_line))];
    for text in [DASH_ANSI_C, DASH_ARITH] {
        for shell in ["dash", "sh", "ash", "bash"] {
            lines.push(format!("{shell} -c {}", quoted(text)));
        }
        lines.push(format!("eval {}", quoted(text)));
        lines.push(format!("echo \"$({text})\""));
        lines.push(format!("dash <<'EOF'\n{text}\nEOF"));
        lines.push(format!("dash <<< {}", quoted(text)));
    }
    for line in &lines {
        assert_eq!(line_risk(line), Risk::Critical, "{line:?}");
    }
}

/// The reviewer's unquoted-heredoc doubling bomb.
fn heredoc_bomb(n: usize) -> String {
    let mut s = "x ".repeat(n);
    for _ in 0..4 {
        s = format!("cat <<EOF\n$({s})\nEOF\n");
    }
    s
}

/// Regression (R3-2): the pre-pass didn't descend into substitutions, so a `$(dd)` or `` `dd` ``
/// that runs first was lost when later padding exhausted the budget (High). The pre-pass now
/// notes command words inside substitutions, backticks and heredoc bodies.
#[test]
fn a_first_running_substitution_survives_budget_exhaustion() {
    let bomb = quoted(&heredoc_bomb(100_000));
    for line in [
        format!("echo $({DD}) ; sh -c {bomb}"),
        format!("echo `{DD}` ; sh -c {bomb}"),
        format!("echo $({DD}) ; :{}", " rm".repeat(200_000)),
        format!("echo $({DD}) ; echo {}", "x ".repeat(2_200_000)),
        format!("echo $(echo $({DD})) ; :{}", " rm".repeat(200_000)),
        format!("bash <<'EOF'\n{DD}\nEOF\n:{}", " rm".repeat(200_000)),
    ] {
        let (risk, budget) = analyze_with_budget(&line, MAX_RISK_WORK);
        assert!(budget.exhausted, "{} bytes did not exhaust", line.len());
        assert_eq!(risk, Risk::Critical, "{} bytes", line.len());
    }
}

/// The pre-pass stays linear for each nesting level: the doubling bomb is scanned in a small
/// multiple of its length.
#[test]
fn the_pre_pass_is_linear_per_level() {
    let line = heredoc_bomb(200_000);
    SCANNED.with(|c| c.set(0));
    let mut budget = Budget::new(MAX_RISK_WORK);
    note_visible_programs(Some(&line), &[], &mut budget);
    let scanned = SCANNED.with(std::cell::Cell::get);
    assert!(
        scanned < 4 * (MAX_SHELL_NESTING + 1) * line.len(),
        "scanned {scanned} for {} bytes",
        line.len()
    );
}

/// Regression (R3-3): bash 5 ends a heredoc inside `$(…)` at a body line `EOF)`, and the `)`
/// closes the substitution. That is now one more reading.
#[test]
fn bash5_ends_a_substitution_heredoc_at_delimiter_paren() {
    assert_eq!(
        line_risk(&format!("echo \"$(cat <<EOF\nit's\nEOF)\"\n{DD} # '")),
        Risk::Critical
    );
    assert_eq!(
        line_risk(&format!("x=$(cat <<-EOF\n\tit's\n\tEOF)\n{DD} # '")),
        Risk::Critical
    );
}

/// Decision (R3-4): an open quote inside a heredoc body doesn't raise the tier on its own, so
/// ordinary commit and PR bodies keep the tier of the command that consumes them.
#[test]
fn open_quote_in_a_heredoc_body_does_not_raise_the_tier() {
    assert_all(
        &[
            "git commit -m \"$(cat <<'EOF'\nFix the parser's bug\nEOF\n)\"",
            "gh pr create --body \"$(cat <<'EOF'\n## Summary\n- we don't touch rm -rf paths\nEOF\n)\"",
            "cat > notes.md <<'EOF'\nIt's done. Don't panic.\nEOF",
            "git commit -m \"$(cat <<'EOF'\nQuote the \\\"title\nEOF\n)\"",
        ],
        Risk::Medium,
    );
    // Everything before the open quote is still classified.
    assert_all(
        &[
            &format!("git commit -m \"$(cat <<'EOF'\n{DD}\nit's done\nEOF\n)\""),
            &format!("bash -s \"$(cat <<'EOF'\n{DD}\nit's\nEOF\n)\""),
        ],
        Risk::Critical,
    );
    // Outside a heredoc body an open quote still makes the line High.
    assert_all(
        &[
            "sh -c 'echo \"unterminated'",
            "bash <<< \"it's\"",
            "sh -c 'echo \"$(echo it)'",
        ],
        Risk::High,
    );
}

/// Inside `$( )`, an unquoted `#` at a word start begins a comment that runs to the end of the
/// line (bash ≥ 4, zsh, dash, ksh), so a `)` in it doesn't close the substitution. Before this,
/// the closing-paren scan ended the substitution at that `)` and left the `dd` on the next line
/// as quoted text: Medium for a line every shell runs `dd` from.
#[test]
fn a_paren_in_a_comment_does_not_close_a_substitution() {
    assert_all(
        &[
            &format!("echo \"$(true # )\n{DD}\n)\""),
            &format!("x=$(true # )\n{DD}\n)"),
        ],
        Risk::Critical,
    );
}

/// The word-start test for a comment looks only at the byte before the `#`, so a `#` after an
/// escaped blank (`a\ #`) or right after a nested substitution's `)` (`$(true)#x`) is read as a
/// comment, though bash reads it mid-word. That can only stretch the substitution, never shorten
/// it: the stretched body is still classified, or the line ends unterminated. No shell runs the
/// `dd` in these lines, so `Critical` and `High` here pin the fail-upward direction. The bash and
/// bash 3.2 readings share the rule, so it can't reach the open-quote exemption.
#[test]
fn a_hash_after_an_escape_or_a_nested_paren_fails_upward() {
    assert_all(
        &[
            &format!("echo \"$(echo a\\ # )\n{DD}\n)\""),
            &format!("echo \"$(echo $(true)#x )\n{DD}\n)\""),
        ],
        Risk::Critical,
    );
    assert_all(
        &["echo \"$(echo a\\ # )\"", "echo \"$(echo $(true)#x )\""],
        Risk::High,
    );
}

/// Decision (R4, option A): a substitution an alternate reading delimits gets no open-quote floor
/// only in the bash 3.2 reading (`heredocs_in_substitutions` off), and only when the substitution
/// never closes there, so it runs to the end of the input and bash 3.2 has nothing later to run.
/// Every other alternate-delimited substitution that ends in an open quote is at least High.
#[test]
fn the_alternate_open_quote_exemption_is_narrow() {
    // The bash 3.2 reading never closes the substitution: no floor, as for the commit bodies.
    assert_eq!(
        line_risk("git commit -m \"$(cat <<'EOF'\nFix the parser's bug\nEOF\n)\""),
        Risk::Medium
    );
    // The ANSI-C-off (dash) reading of the line leaves the substitution open in a quote: High.
    // (The top-level `$'x'` makes the line call for that reading.)
    assert_eq!(line_risk("echo $'x' \"$(echo $'it\\'s' )\""), Risk::High);
    // A comment apostrophe can't fake a never-closing substitution in the bash 3.2 reading: the
    // closing-paren scan honors comments there, so the substitution closes at the body's `)` and
    // the `dd` after it is a top-level command in that reading.
    assert_eq!(
        line_risk(&format!(
            "echo \"$(cat <<EOF # it's\n)\"; {DD}; echo \"\nEOF\n)\""
        )),
        Risk::Critical
    );
    // bash 3.2 closes `$( )` at a `)` inside a heredoc body and runs the rest of the line.
    assert_eq!(
        line_risk(&format!(
            "echo \"$(cat <<'EOF'\nfoo )\"; {DD}; echo \"\nEOF\n)\""
        )),
        Risk::Critical
    );
    // A substitution no reading closes stays High.
    assert_eq!(line_risk("echo \"$(echo hi # it's )\""), Risk::High);
}
