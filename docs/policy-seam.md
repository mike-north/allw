# allw — Policy Layer Seam

**Scope:** the _seam_ between the approval primitive and the (later) policy layer — the parts that are expensive
to retrofit and must be pinned in `allw-core` v1: the **record of an action**, the **decision interface**, the
**rule shape**, and the **audit fields**. The policy _engine_ is built later. **And a tiering discipline:** early
allw matches actions **syntactically**; the **semantic** (capability/meaning) tier is the deferred north star.

> This aligns to the **AgentRC / Arc Flow** model (capabilities, per-command schemas, the syntactic→semantic
> tiering). allw's policy layer _is_ Arc Flow; the human gate is the **`ask`** outcome of its permission model,
> sitting after `attestation → approval → permission`.

---

## Where the policy layer sits

For each agent action, _before_ the primitive is invoked:

```
evaluate(ActionRecord) ──▶  Allow    → execute, no human
                            Deny     → refuse
                            Escalate → allw.requestApproval(...)   (= the "ask" effect; one-shot human gate)
```

The primitive fires only on **Escalate**. Auto-allow inside the envelope reduces fatigue; the primitive stays
one-shot and scope-free.

---

## The three tiers (and where early allw lives)

The cost of policy is not in any one command — it's in classifying actions **generally and semantically**.
That generality is what made Flow expensive. So we tier it:

| Tier                                | What it matches                                                                                                                                                  | Needs                                                                | allw                                |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------------- |
| **T1 — pure syntactic**             | command name, `command_pattern` globs, `args_any` (exact-token/glob), flags, env; MCP `server`/`tool`/`params`-as-strings                                        | nothing (no schema)                                                  | **v1 lives here**                   |
| **T2 — curated-command syntactic**  | precise positional / path / target matching for ~15–20 high-value dangerous commands (`rm`, `find`, `git`, `curl`, `chmod`, `dd`, `kubectl`, key MCP CRUD tools) | hand-written arg grammar for _that curated set only_                 | optional early stretch              |
| **T3 — full semantic / capability** | abstract capabilities (`delete`, `network`, …) + named fields/scope, generalized across hundreds of commands ("`rm` _means_ delete; arg1 _is a path_")           | per-command schema DB, capability inference, doc-extraction pipeline | **deferred north star (paid tier)** |

> **Why the line is here:** T1/T2 are mechanical. T3 is the syntax→meaning bridge — the classification product
> (man-page extraction, capability inference, version graphs) that made Flow hard. allw must ship without it.

**Business-model alignment:** **syntactic = free**, **semantic = paid** — the same Sync/Flow line. Syntactic
rules are a strict subset of semantic, so nothing written at T1/T2 breaks when T3 lands.

---

## Structure vs. data in the ActionRecord

The `ActionRecord` has a **structure/data** boundary that maps directly onto the relay's zero-knowledge
invariant (see [contract.md](./contract.md) Invariant 2 and [threat-model.md](./threat-model.md) §R7):

- **Structure** — the parts the relay may observe at the default privacy tier:
  - `surface` kind (`"command"` / `"mcp_tool_call"` / `"agent_tool_call"` / `"file_edit"` / …)
  - function identity: program name (`syntactic.bin`) for commands; **`syntactic.server` + `syntactic.tool`**
    for MCP calls — the (server, tool) pair is the MCP function identity, parallel to a command's program name
  - `session_label` (carried at the `ApprovalRequest` envelope level, not inside `ActionRecord`)

  These are what the `action_structure` plaintext envelope field may expose; they tell the relay _what function_
  is being invoked, never _what arguments_ were given. Orgs that consider server identity itself sensitive
  (parallel to a sensitive internal program name) should use the **paranoid/enterprise tier**, which hides all
  structure — reclassifying server as data is not the right escape hatch for that concern.

- **Data** — the parts that must never leave the JWE; relay never sees these even at the default tier:
  - `syntactic.argv`, `syntactic.flags`, `syntactic.positionals`, `syntactic.cwd`, `syntactic.env_refs`
  - `syntactic.params` (MCP parameter values)
  - `syntactic.paths`, `syntactic.diff_summary`, `syntactic.diff_hash` (file-edit content)
  - `syntactic.raw` (original form)
  - any future server connection details / URL / endpoint field (only the server **name** is structure,
    parallel to program name vs. path/cwd)

The syntactic **substrate** in the `ActionRecord` is therefore split: surface, function identity (bin for
commands; server + tool for MCP), and session label are structure; arguments, parameter values, env, paths,
and content are data. The `capabilities`/`scope` semantic enrichment fields (T3, reserved) are data. This
split is enforced on-device (in the WASM/native client) when constructing the `ApprovalRequest` envelope —
not by the relay, and not post-hoc.

**`agent_tool_call`** — an agent-runtime or plugin-owned tool call gated by the harness rather than by an
MCP server (specified in [openclaw-integration.md](./openclaw-integration.md) §5.2). It **reuses the same
`(server, tool)` function-identity pair** as `mcp_tool_call` — `server` holds the gating provider id, `tool`
the tool name — so it adds no new syntactic field and inherits the classification above unchanged: the pair
is structure, `params` / `raw` remain data. It is a distinct `surface` rather than an `mcp_tool_call` because
`surface` is the relay-visible, policy-matchable namespace: a rule or registry scoped to "MCP calls" must not
silently sweep in tool calls that no MCP server ever served.

## The action record (what `allw-core` captures)

`allw-core` reduces every approvable action to an `ActionRecord` and embeds it in both the `ApprovalRequest`
context and the `AuditRecord`. **v1 populates the syntactic fields; the semantic fields are reserved (null) and
filled later by the T3 engine** — adding them must not break the wire format.

`actor` is not part of `ActionRecord`: it is carried at the `ApprovalRequest` / `AuditRecord` envelope level, and
policy evaluation receives `actor` plus `ActionRecord` as separate inputs (`PolicyRule.subject` matches the actor;
`PolicyRule.match` matches the action).

```
ActionRecord {
  record_schema_version: int

  surface: "command" | "mcp_tool_call" | "agent_tool_call" | "file_edit"
                                              // interception paradigm (more added as needed:
                                              //   delegated_fetch …)

  // --- syntactic substrate (v1, always present) ---
  syntactic: {
    // surface=command:
    bin?, argv?, flags?, positionals?, cwd?, host?, env_refs?
    // surface=mcp_tool_call / agent_tool_call:
    server?, tool?, params?                    // params as raw/structured values
    // surface=file_edit:
    operation?, paths?, diff_summary?, diff_hash?
                                                // target paths + compact WYSIWYS summary/hash
    raw?                                        // original form, for fallback + display; on
                                                //   mcp_tool_call / agent_tool_call, the caller's
                                                //   description of the call (see below)
  }

  // --- semantic enrichment (T3, reserved; null in v1) ---
  capabilities?: CapabilityAction[]            // Arc Flow taxonomy: filesystem.*, network.*, process.*,
                                               //   arbitrary.execute, privilege.*, environment.*, git.* …
  scope?:        CapabilityScope               // path/pattern/url/domain/resource/resourceName/namespace …

  risk: "low" | "medium" | "high" | "critical" // v1: coarse heuristic; T3: capability-derived
}
```

**On a tool surface, `raw` is a description, not the action.** On `mcp_tool_call` and `agent_tool_call` the action
is the hash-bound `server`/`tool` (plus `params`), and `raw` is the caller's own prose about the call: an OpenClaw
plugin's `description` and `detail`, for example ([openclaw-integration.md](./openclaw-integration.md) §5.2). Both
approvers therefore head a tool call with its identity (`server :: tool`) and show `raw` labelled as the
description, never as the action (#321). A tool-surface record is not meant to carry `bin`/`argv`: the core's tool-call
builders leave them unset, and every in-repo producer gates a shell tool on the `command` surface (the Claude Code
hook's Bash and PowerShell tools, OpenClaw exec). If a hand-built record does pair a tool with a command form (say
`agent_tool_call` with `tool: "Bash"`, `raw: "rm -rf /tmp/x"` and the same tokens as `argv`), both are hash-bound, so
the approvers show the command next to the tool identity with a warning on every such request, even when `argv`
matches `raw`. An integrator gating a command should use the `command` surface instead
([threat-model.md](./threat-model.md) R3).

**Every caller that runs a command uses the `command` surface.** A plain script or CLI about to run a command
(for example `stripe refunds create …`) is a `command` caller, exactly like the agent hooks. There is no
separate "generic" or "script" surface (decided 2026-11-02, #231). What differs is the `actor`, not the
surface. Integrators build the record with `@allw/sdk`'s `commandAction` / `commandActionFromLine`, which
return the core's `action_from_argv` / `action_from_command` record unchanged. `commandRequest` wraps that
record into a full request. By default it sets `actor: { id: "machine:<hostname>", kind: "script" }`,
`reversible: false` and `cwd: process.cwd()` (an explicit `cwd: null` leaves the record unbound). It copies the
record's `risk` into the request's top-level `risk`, which the caller cannot override. A command line is only split
into words: shell operators, substitutions and newlines are not parsed into the record's fields, and `bin` /
`argv` describe the word list (the first program). So callers must run `argv` without a shell.

**Risk on a command line covers the commands the shell would run** (#272). `action_from_command` also scans the
raw line as bash would; §v1 command risk below lists the rules and their limits. So `ls && rm -rf /` is `high`, and
`echo hi > f` is `medium`. Only `risk` changes. Two things are deliberately **not** changed:

- `bin` / `argv` / `flags` / `positionals`.
- Policy matching. A `{ bin: "ls" }` any-args allow rule still matches `ls && rm -rf /`. Making the matcher fail
  closed on compound lines is an open policy-seam decision (#272).

`action_from_argv` records an argv run without a shell, so its words are never read as shell syntax. (Both
builders refuse a line or argv that runs no program; see §Command lines that run no program.)

**PowerShell lines** (Claude Code's `PowerShell` tool, #298) are also `command` records, built by the core's
`action_from_powershell_command` (decided 2026-11-03). `raw` is the exact line and argv is **always** a plain
whitespace split of it: PowerShell quoting is never interpreted with POSIX rules (inside `"…"` its escape is the
backtick and `\` is literal, so a POSIX split could hide a `; Remove-Item …` inside one harmless token, and it strips
Windows paths' backslashes). Every non-whitespace byte of `raw` stays visible in some token. Because the v1 risk table
knows no PowerShell commands, risk is at least `medium`, and at least `high` when `raw` contains a construct that runs more
than one command, runs one T1 can't read, or builds one at run time (uncertain ⇒ upward): `;`, `|`, `&`, a line break,
a backtick, `(` or `{`, `[scriptblock]` or `.Invoke`, a command word that runs other code (`iex`, `Invoke-Expression`,
`Invoke-Command` / `icm`, `Start-Process` / `start` / `saps`, `Start-Job` / `sajb`, `powershell`, `pwsh`, `cmd`;
quotes inside the word are ignored, so `i''ex` and `I"nvoke-Expression` count (#341)), a
program named like PowerShell itself (a name starting `pwsh` or `powershell` after any path, with its quotes removed,
such as `pwsh-preview`, `powershell_ise` or `p''wsh`), an `-EncodedCommand` parameter or any prefix of it (or `-ec`) led
by one or two of `-`, `/` and the Unicode dashes U+2013, U+2014, U+2015, with every quote character in the token
ignored (`'-enc'`, `-"enc"`, `-e''nc`, #328), or dot-sourcing (a leading `.`
word, or `.` directly followed by a quoted or variable path such as `.'x.ps1'`). There is no PowerShell field on the
record and no schema change: surfaces label the line for the human in the summary (`PowerShell: <command>`). The
other substrate fields come from the command builder's T1 scans of the tokens and `raw`, so they can disagree with
PowerShell: for example `$env:PATH` records `env` in `env_refs`. `raw` is authoritative. A line that runs no program (blank, only separators or
literal assignments, an empty-string program) is refused instead (§Command lines that run no program, #376).

### Forward-compat requirements on `allw-core` v1 (cheap now, painful later)

1. **Capture the syntactic substrate** (tokenized command / MCP call) for every action — the durable base all
   three tiers match against.
2. **Stamp `record_schema_version`.**
3. **Reserve the optional `capabilities` / `scope` fields** so the semantic tier layers on with no wire break.
   They **MUST be null in v1**: a device refuses a context that sets either one to any non-null value, because the
   hash binds them but no approver shows them ([contract.md](./contract.md) §Device-side context checks, #296).
4. **Reserve a `policy` block in `AuditRecord`:** `{ decision: allow|deny|escalate, rule_id?, tier, schema_version }`.
   v1 always writes `escalate`; the field exists so history is policy-analyzable later.
5. **Enforce the structure/data split** when constructing `ApprovalRequest` envelopes: surface + tool/bin name
   may appear in the plaintext `action_structure` envelope field; everything else (argv, params, env, paths,
   diff, raw) must stay inside the JWE. New syntactic fields must be classified (structure or data) at the time
   they are added — see §Structure vs. data above.

Do **not** build capability inference or a schema DB in v1. Just don't foreclose them.

### v1 command risk: classify what actually runs

`risk` on a `command` record is a coarse T1 heuristic. Its rules and table live in
`crates/allw-core/src/command/risk.rs`.

**Who reads it.** `policy::evaluate` does not read risk, so risk never makes an action allowed. Risk is not only
display, though:

- The human sees it.
- The Codex hook and the OpenClaw bridge derive `reversible` from it (`low` / `medium` ⇒ reversible).
- The OpenClaw bridge requires a challenge for `critical`.

So understating risk is a real defect. Every rule fails **upward**: where T1 can't tell, the tier goes up.

**Rules** (decided 2026-11-02, #268 and #272). Risk is classified on what actually runs, not only `argv[0]`.
Within the limits below, a prefix, wrapper, operator or substitution does not make a command look less risky than
a program it runs.

- **Assignments.** Leading assignment-like words (`NAME=value`, `X+=1`, `A[0]=1`) are skipped. The tier is that
  of the command after them, and at least `medium`: an assignment can change what a program does (`LD_PRELOAD`,
  `PATH`, `GIT_SSH_COMMAND`). `X=1 rm -rf ~` is `high`.
- **Wrappers.** The wrappers are a curated list:
  - `env`, `sudo`, `doas`, `run0`, `pkexec`, `su`, `nice`, `ionice`, `nohup`, `time`, `timeout`
  - `command`, `builtin`, `exec`, `xargs`, `stdbuf`, `setsid`, `find`, `caffeinate`, `arch`
  - `script`, `chroot`, `flock`, `watch`, `busybox`, `ssh`
  - the GNU-prefixed `genv`, `gnice`, `gnohup`, `gtimeout`, `gstdbuf`

  A wrapper is at least as risky as anything it may run. T1 can't tell an option value (`nice -n 10`) from the
  wrapped program, so every later non-flag word counts as a program start. Every later word holding whitespace
  counts as a command line too: `watch 'rm -rf ~'`, `ssh host 'cmd'`, and a flag value such as
  `env -S'rm -rf ~'`. `env` running a program is at least `medium`, and `env` alone stays `low`.

- **Shells and `eval`.** These read their string as a full command line under the rules here:
  - `sh` / `bash` / `zsh` / `dash` / `ksh` / `mksh` / `ash` / `fish` / `csh` / `tcsh` with `-c`;
  - `pwsh` / `powershell` with `-Command`;
  - `eval`'s arguments.

  An unreadable string (`-EncodedCommand`, an unterminated quote) is `high`.

- **Command lines** (`action_from_command` only):
  - Segments are split at unquoted control operators (`&&`, `||`, `;`, `|`, `&`, `(`, `)`, newline, a lone
    `{` / `}`, zsh `&!` / `&|`). Each segment is classified.
  - Words before the command word are skipped: keywords (`if`, `do`, `!`, `time [-p]`, …), redirections
    (`2>/dev/null`, `> f`, and attached ones: `dd>/dev/null` runs `dd`) and the zsh precommands (`noglob`,
    `nocorrect`, `-`, `repeat N`).
  - A command word T1 can't know (`$x`, `$(…)`, a backtick, a glob, a `{a,b}` list) is `high`. bash `$'…'` /
    `$"…"` strings are decoded first. A decoded NUL ends the word, as in bash. A decoding bash may do
    differently (`\u`, `\c`, an unknown escape) makes it at least `high`.
  - Substitutions (`$(…)`, backticks, `<(…)`, `>(…)`) are classified. Inside one, a `#` comment runs to the end
    of its line, so a `)` or quote in it doesn't end the substitution.
  - Heredoc delimiters are read as bash reads them (`<<''`, backslash-newline, `\"` inside double quotes). One
    T1 can't read for sure makes the line `high`. An unquoted delimiter's body has its substitutions
    classified.
  - **Every heredoc and here-string body is also read as a script, whatever consumes it.** This is a deliberate
    fail-upward rule. Which consumers run their input (a shell, a wrapper, `{ bash; }`, `( bash )`, `eval`,
    an `if` / `while` compound) is a moving target. Reading every body as a script means a new consumer can't
    hide one, and over-reading a `cat <<EOF` body only raises the tier.
  - **An open quote inside a heredoc body doesn't raise the tier on its own.** A shell fed the body stops at
    that syntax error before running anything after the open quote, and everything before it is still
    classified. So ordinary commit and PR bodies (`git commit -m "$(cat <<'EOF'`… `it's` …) keep the tier of the
    command that consumes them (`medium`), while a `dd` before the quote is still `critical`. Elsewhere (a
    command line, a `-c` string, a substitution) an open quote still makes the line `high`.
  - `((…))` at a command position (including `for ((…))`) is arithmetic, so a `<<` inside it is a shift.
  - Any operator, substitution or redirection makes the line at least `medium`. A line ending inside an open
    quote or substitution is `high`, because the shell runs what comes before the syntax error.
  - bash ≥ 4 grammar is authoritative. Where shells or versions disagree, the line is read both ways and the
    higher tier wins:
    - `#` as a comment or not;
    - `$'…'` as an ANSI-C string or not;
    - `((` as an arithmetic command or two subshells;
    - a heredoc inside `$(…)` read before the closing `)` (bash ≥ 4, zsh, dash, ksh) or the first `)` closing it
      (bash 3.2);
    - a body line `EOF)` ending a heredoc inside `$(…)` and closing the substitution (bash 5).

    These alternate readings run at every nesting level, so a nested `sh -c` string also gets dash's reading
    (`sh` is dash on Debian and Ubuntu). They are charged to the shared budget, which bounds their cost. An
    alternate reading's substitutions keep the open-quote floor, with one exception: a substitution the bash 3.2
    reading never closes runs to the end of the input (or of the heredoc body holding it), and bash 3.2 stops at
    its open quote with nothing later in it to run, so that open quote alone doesn't raise the tier. This keeps the commit and PR bodies above at `medium`.

- **Bounds.** Each bound fails upward to `high`:
  - nesting of `-c`, `eval` and substitutions past 4 levels;
  - argv words past the 256th, which count as a `high` candidate;
  - one shared work budget per record (bytes scanned, split or copied, plus words classified), so
    classification time stays linear and bounded inside the synchronous hook. Running out of it never lowers a
    tier already found. An unbudgeted pre-pass first records every visible program word (each argv word,
    each segment's command word, and every later non-flag word of a segment whose command word is a wrapper,
    descending into substitutions, backticks, heredoc bodies, the `-c` / `--command` / PowerShell `-Command`
    strings of the curated shells, `eval` arguments (also after leading assignments), and the whitespace words
    a wrapper runs (`su -c '…'`, `watch '…'`, `env -S'…'`), down to the nesting limit), so those keep their
    tier on exhaustion: a `$(dd …)`, `"$(sudo dd …)"`, `sh -c 'dd …'` or `eval 'dd …'` that runs first stays
    `critical` however much padding follows it (#323, #324). It reads each word a bounded number of times per
    level, so it stays linear for each level. Only text never reached falls back to `high`. Known limits
    (#389): here-strings and the alternate readings (dash, no ANSI-C quotes, no arithmetic commands) are read
    only by the budgeted analysis, so a `dd` only they reach can still drop to `high` on exhaustion.

**Known T1 limits.** For these the tier can still understate what runs (decision B: curated list plus documented
limits, no name-sniffing of later words):

- wrappers and interpreters that aren't listed: `parallel`, `git -c core.sshCommand=…` / `-c alias.*`,
  `source` / `.`, and code in other languages (`python -c`, `node -e`, `perl -e`); tracked in #289;
- input piped into a shell (`echo 'rm -rf ~' | sh`): the shell keeps its own tier;
- aliases, functions and `PATH` lookups defined outside the line, and renamed or symlinked binaries;
- arithmetic evaluation of data (`x='a[$(rm -rf ~)]'; echo $((x))` runs a substitution stored in a variable);
- non-bash grammars (fish, csh, PowerShell strings) are read with bash's rules.

This changes **only `risk`**. `bin`, `argv`, `flags`, `positionals` and `env_refs` keep their T1 meaning, and
`bin` is still `argv[0]` (`X=1 rm -rf ~` has `bin: "X=1"`). The `bin` question is **open**: `CommandMatcher`
matches `bin` exactly, so a `{ bin: "ls" }` any-args `allow` rule would start matching
`LD_PRELOAD=/tmp/evil.so ls` if `bin` became the real program. Changing `bin` therefore needs a matching
policy-matcher rule for prefixed commands first (see #268).

Shared Rust ↔ WASM vectors are in `crates/allw-core/tests/fixtures/command_risk_vectors.json` (argv rules) and
`command_line_risk_vectors.json` (command lines).

### Command lines that run no program

The core refuses, with a typed error, a command line or argv that runs nothing a human could meaningfully approve,
instead of building a record with no program (#376). The refusal lives in the core builders, so every surface inherits it:
the hooks, the SDK, the OpenClaw bridge, native (UniFFI) callers and third-party integrators. Like every other
builder error it is fail-closed: the caller denies, and no human is asked.

`action_from_command` (`CommandError`, `crates/allw-core/src/command.rs`):

| Code (`CommandError::code`) | When                                                                                     | Examples                           |
| --------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------- |
| `no_command`                | the line is blank (empty, or only whitespace by Unicode's definition), or only a comment | `""`, `"  \t"`, `"\r"`, `# x`      |
| `no_program`                | every word is a pure variable assignment or a control operator                           | `FOO=1`, `FOO=1; BAR=2`, `&&`, `;` |
| `empty_program`             | the first word that is neither is the empty string                                       | `''`, `'' rm -rf x`, `FOO=1 "" ls` |

The check reads the tokens only. Each word is split on `;`, `&`, `|`, `(`, `)`; an empty piece (an operator) or a
pure assignment (`NAME=…`, `NAME+=…`, `A[0]=…`, with no backtick, `<` or `>` in it) is skipped, and any other piece
is a program, so the line is built. A substitution or a redirection therefore always counts as running something
(`FOO=$(id)` and `> out.txt` are built and go to a human).

**What the refusal guarantees.** It never refuses a line whose first command word runs. It can refuse a line where
the shell would still run something, and that is deliberate: every refusal is a deny, so it fails closed.

- Only the words up to the first program word are read, so a later segment after an empty program word is not
  examined: `'' || rm -rf x` and `'' ; rm -rf x` are refused (`empty_program`).
- `shlex` drops quotes, so a quoted operator or assignment (`';'`, `'FOO=1'`) is read as unquoted, though bash would
  run it as a program name.
- An assignment is recognised by its first character only, so `FO-O=1` is refused, though bash would run it as a
  program name.

**`action_from_argv`** (a canonical, pre-tokenized argv, such as the OpenClaw bridge's `systemRunPlan.argv` or a
native caller's) is fallible with the same `CommandError`, whatever `raw` says: an empty argv is `no_command`; leading
pure assignments are skipped, then an empty word is `empty_program` (`[""]`, `["", "rm", "-rf", "x"]`,
`["FOO=1", ""]`); only assignments is `no_program` (`["FOO=1"]`). Words are not split on operators, because an argv
runs without a shell: `["&&"]` names a program and is built. Assignments are treated as the line builder treats them
(and as the risk rules skip them), although without a shell `FOO=1` would be a program name: no real program is
named like an assignment, so refusing it fails closed and keeps the two builders consistent (decided for #376).

`action_from_powershell_command` is fallible with the same `CommandError`, and refuses only these (no PowerShell line
is refused for its syntax). Quoting is not interpreted. The raw line is read line by line; a `#` that starts a token
begins a comment, which is dropped up to the end of its line. The rest is split on `;`, `|`, `&`, `(`, `)`, and the
trimmed pieces are read in order. Empty pieces and a variable assigned a literal (`$env:FOO=1`, `$x = 'a'`,
`$x = -2.5`: a quoted string with no quote, `$` or backtick inside, or a plain number) are skipped. A piece whose
first word is `''` or `""` (including after the call operator, `& ''`) is `empty_program`. Any other piece may run
something, so the line is built. A bareword value runs a command in PowerShell (`$x = notepad`), so it is not a
literal. A line that is blank once comments are dropped (`# rm -rf x`) is `no_command`. A `<#` block comment is not
recognised: `<# x #> Remove-Item x` is built, and so is a bare `<# x #>` line, which then goes to a human (that
fails toward asking, never toward allowing). As on POSIX, later statements after the first one that is neither
skipped nor built are not examined, so `'' ; Remove-Item x` is refused (a deliberate deny).

The WASM bindings throw an `Error` whose own `kind` property is the code (callers classify on it, never on the
message); UniFFI fails with the core message. The SDK maps the codes to its `CommandActionError` reasons:
`commandActionFromLine` to `command_line_empty`, `command_line_no_program` and `argv_program_empty`, and
`commandAction` to `argv_empty`, `argv_no_program` and `argv_program_empty`. `commandAction` still validates an
argv first, so an empty argv or an empty `argv[0]` is refused before the core is called, as before; the only change
there is that an all-assignment argv is now refused (`argv_no_program`). The SDK and the hooks keep their own checks
on the record as defence in depth, with the same messages. The shared Rust ↔ WASM vector is
`crates/allw-core/tests/fixtures/command_refusal_vector.json`.

---

## The rule shape

A `PolicyRule` is **as trusted as a verdict** — signed by a device key. v1 rules are **syntactic**; semantic
(capability) rules are a strict-superset upgrade.

```
PolicyRule {
  id
  account_id: string                           // account root that must certify the signing device
  subject:    ActorMatcher                    // actor.id == "machine:macbook" | any
  match:      Predicate                       // T1/T2: surface + bin/tool + glob/args/flag/param matchers
                                              // T3 (later): capability + named-field/scope matchers
  effect:     "allow" | "ask" | "deny"
  bounds?:    { ttl?, max_uses?, time_window? }
  provenance: "manual" | "from_approval"
  tier:       "syntactic" | "semantic"
  created_at, expires_at?
  sig:        device-key compact JWS over every unsigned field above
  device_cert?: account-root compact JWS       // chains device key -> account root
}
```

**Precedence within a policy:** `deny` > `ask` > `allow`. **No match ⇒ `ask` (Escalate).** Unknown is fail-safe.

An empty `match: {}` is invalid. A rule must constrain the action through at least one surface,
command, or MCP predicate field; otherwise it would become an accidental match-everything grant.
For command argument matching, `args_any_globs` runs only against structured `argv` / positional
tokens, never raw shell text. Patterns without `*` or `?` are exact token matches; explicit glob
patterns are still anchored to one structured token and cannot span whitespace or shell
metacharacter boundaries.

Policy rule verification mirrors verdict verification for key trust: the verifier takes an account-root public key,
verifies `device_cert`, requires the signed cert `account_id` to match the rule `account_id`, verifies the policy JWS
with the certified device key, and requires the policy JWS `kid` to match the certified `device_id`. A rule missing a
cert, signed by an uncertified key, bound to a different account, or carrying a confused `kid` fails closed.
Multi-account verifiers that already know the account namespace they intended to verify SHOULD also pass that
`expected_account_id`; a rule whose signed `account_id` does not match it fails closed before policy evaluation.

---

## The approval → rule bridge ("approve & don't ask again")

The fatigue-reducing affordance emits a **signed `PolicyRule`, not a scoped verdict** (the verdict stays
one-shot). The scope chooser's options derive from the action's **syntactic** form in v1:

| Choice                      | Generated `match` (v1, syntactic)                           | `effect` |
| --------------------------- | ----------------------------------------------------------- | -------- |
| Just this once              | (none — one-shot verdict only)                              | —        |
| This exact call             | `surface + bin/tool + exact argv/params`                    | allow    |
| This command/tool, any args | `surface + bin/tool`                                        | allow    |
| This tool with param P = V  | `mcp + tool + params.P == V` (e.g. `list == "Agent Inbox"`) | allow    |
| Glob over a path-ish arg    | `args_any.match: "<glob>"`                                  | allow    |

(Once T3 exists, the chooser can also offer capability/scope-level rules — "any delete under this folder.")

---

## Composition & monotonicity

- **Within one user's policy:** matching rules combine by precedence (`deny` > `ask` > `allow`); no match ⇒ ask.
- **Across gates (a chain):** effective = **intersection** — a downstream gate can only further restrict.
  `allw` contributes `human_decision ∧ verified`; a corporate gate's policy intersects.
- **Widening your own envelope is not "loosening."** An `allow` rule is the user's deliberate grant; the
  most-restrictive-wins property governs _cross-gate_ composition, not a user's own policy.

---

## Network egress & the credential perimeter (why `http_request` is dropped)

Raw network egress (`curl`, `wget`, `node -e "fetch(...)"`, the agent's own web-fetch tools) is **deliberately
not an early surface or capability** — because gating egress is the wrong defense. The governing axiom:

> **Assume any value an agent can _read_ can be exfiltrated.** You cannot reliably block every egress path. The
> only durable defense is to keep sensitive values **out of the agent's read-set** — which is what **vaultkeeper**
> does: the agent _uses_ a secret via last-moment delegated injection, but never _reads_ one.

Consequences:

1. Raw http **collapses into `network.egress`** (a T3 capability), not a distinct kind.
2. **"Exfil a secret" is removed at the source, not policed at egress.** With vaultkeeper there is no readable
   `secret.txt` / `.env` for the agent to read and then POST anywhere. This is vaultkeeper's reason for existing —
   and what makes "lock the agent out of secrets" **non-Faustian**: the agent keeps its usefulness (it can still
   _use_ credentials) without holding exfiltratable ones.
3. **Ambient credentials** the agent can read (`~/.aws/credentials`, env vars, repo tokens) are not a vaultkeeper
   _gap_ — they're an **incomplete migration**. The fix is clear-cut: move them into vaultkeeper; until then,
   treat them as already compromised.

**Where credentialed-network approval lives:** not "parse curl args," but **gating the `delegated_fetch`
invocation** — the structured chokepoint (which credential, which host/path) vaultkeeper exposes. If allw gates
"network," it gates `delegated_fetch`.

**The one genuine residual** (neither vaultkeeper's nor allw's job): **non-secret sensitive data the agent must
read to do its work** — source code, PII in a database it queries, the file it's editing. You can't
delegate-inject "the content it needs to see," so if the agent reads it and has egress, it can leak it. That's
inherent DLP for agent working-material — handled by sandboxing / egress controls / not pointing agents at the
crown jewels, not by a credential vault or an approval gate.

---

## Explicitly out of scope (deferred)

- **The entire semantic / T3 engine:** capability inference, per-command schema DB, the doc-extraction &
  classification pipeline, capability-based rules, named-field/typed/scope matchers. (Reuse Arc Flow when we get
  there — do not rebuild it.) **The recognized-tool registry** that defines which tools are "recognized" is part
  of this deferred tier; the decision-history flywheel's tallies depend on it only through a narrow structure-only
  `is_recognized` seam (stubbed `false` until T3 lands) — see
  [decision-flywheel.md](./decision-flywheel.md) §"The recognized-tool registry boundary".
- The **suggestion loop** ("approved 20× → propose a rule") — needs the accumulated decision history; the
  reflection pass over the on-device, ephemeral, structure-only history ([decision-history.md](./decision-history.md),
  #134) is what surfaces these candidate rules. Reflection only **proposes**; the rule itself is still a signed
  `PolicyRule` the user accepts (§The approval → rule bridge).
- Rule **storage/sync** and management UI; conflict resolution beyond precedence; org-distributed policy.

## Open questions

- **T2 curated set:** which ~15–20 commands + MCP tools earn hand-written arg grammar first.
- **Rule residence & sync:** device-local first, or E2EE-synced via the relay from day one.
- **Where T3 plugs in:** confirm allw reuses Arc Flow's capability model + schema DB wholesale (read
  `permission-model`, `policy-evaluation-v2` [privacy-preserving client-side eval — fits E2EE], `danger.ts`,
  `attestation-model` before building the semantic tier).
- **Instance identity stability** for param/scope matching: stable id vs human-readable label.
