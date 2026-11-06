# allw — Policy Layer Seam

**Scope:** the policy layer is a separate project. allw does not evaluate policy, hold rules, generate rules,
or decide whether an action should run. A caller may consult its own policy before requesting a one-shot human
decision. allw never widens the caller's boundary itself.

allw's relationship to policy is carrying policy-adjustment options from that layer to the human and passing
the human's policy modification signal back. That feature is not built here; there is no replacement API or
placeholder. [hitl-seam.md](./hitl-seam.md) §6 describes the host-offer/human-choice direction; authentication of
that choice remains open until scheduled.

**#406 partial implementation:** allw does not interpret what an action does or rate its danger.
Risk labels/scoring and policy-only wire metadata are removed. `reversible` is an optional caller assertion;
hooks and the OpenClaw bridge omit it. Command/PowerShell tokenization, no-program refusals, web command
interpretation, and parsed/derived fields remain temporarily and are scheduled for removal in slice 2.
They are not product scope. Faithful raw/cwd/caller argv/MCP/file-edit display and escaping remain.

## Where the policy layer sits

The caller evaluates its own policy. It may refuse, proceed within its own authority, or ask a human through
`allw.requestApproval(...)`. The returned decision satisfies only the human term of the caller's gates.

## Relay data boundary

All action-record fields stay inside JWE ciphertext. The implemented relay envelope carries only
routing/lifecycle metadata and ciphertext; it carries no program, server/tool, surface or session label.
The proposed structure-visible envelope is not implemented (#216) and must be reconsidered after slice 2.

## The action record (what `allw-core` captures)

`allw-core` reduces every approvable action to an `ActionRecord` and embeds it in both the `ApprovalRequest`
context and the `AuditRecord`. **The record carries caller facts.** Policy-only slots and risk are removed; temporary parsed fields
remain only until #406 slice 2.

`actor` is not part of `ActionRecord`: it is carried at the `ApprovalRequest` / `AuditRecord` envelope level, and
the caller may use that actor identity alongside the action in its external policy.

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
record into a full request. By default it sets `actor: { id: "machine:<hostname>", kind: "script" }`
and `cwd: process.cwd()` (an explicit `cwd: null` leaves the record unbound). Reversibility is optional,
asserted only by a caller that supplies it. No risk classification is produced.

The temporary command builder still tokenizes and derives fields and refuses no-program inputs as
described below. This implementation is scheduled for removal in slice 2; it is not accepted product scope.

**PowerShell lines** (Claude Code's `PowerShell` tool, #298) are also `command` records, built by the core's
`action_from_powershell_command` (decided 2026-11-03). `raw` is the exact line and argv is **always** a plain
whitespace split of it: PowerShell quoting is never interpreted with POSIX rules (inside `"…"` its escape is the
backtick and `\` is literal, so a POSIX split could hide a `; Remove-Item …` inside one harmless token, and it strips
Windows paths' backslashes). Every non-whitespace byte of `raw` stays visible in some token. There is no PowerShell field on the
record and no schema change: surfaces label the line for the human in the summary (`PowerShell: <command>`). The
other substrate fields come from the command builder's T1 scans of the tokens and `raw`, so they can disagree with
PowerShell: for example `$env:PATH` records `env` in `env_refs`. `raw` is authoritative. A line that runs no program (blank, only separators or
literal assignments, an empty-string program) is refused instead (§Command lines that run no program, #376).

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
pure assignment (`NAME=…`, `NAME+=…`, `A[0]=…`, where `NAME` is a shell identifier with at most one `[…]`
subscript whose body holds no `[` or `]`, and with no backtick, `<` or `>` in it) is skipped, and any other piece is
a program, so the line is built. A command with an `=` in it split out of a
substitution (`git log --format=%H` from `V="$(git log --format=%H)"`) is not an assignment, because its "name" is
not an identifier (#391). A substitution or a redirection therefore always counts as running something
(`FOO=$(id)` and `> out.txt` are built and go to a human).

**What the refusal guarantees.** It never refuses a line whose first command word runs. It can refuse a line where
the shell would still run something, and that is deliberate: every refusal is a deny, so it fails closed.

- Only the words up to the first program word are read, so a later segment after an empty program word is not
  examined: `'' || rm -rf x` and `'' ; rm -rf x` are refused (`empty_program`).
- `shlex` drops quotes, so a quoted operator or assignment (`';'`, `'FOO=1'`) is read as unquoted, though bash would
  run it as a program name.

**`action_from_argv`** (a canonical, pre-tokenized argv, such as the OpenClaw bridge's `systemRunPlan.argv` or a
native caller's) is fallible with the same `CommandError`, whatever `raw` says: an empty argv is `no_command`; leading
pure assignments are skipped, then an empty word is `empty_program` (`[""]`, `["", "rm", "-rf", "x"]`,
`["FOO=1", ""]`); only assignments is `no_program` (`["FOO=1"]`). Words are not split on operators, because an argv
runs without a shell: `["&&"]` names a program and is built. Assignments are recognised as the line builder
recognises them (a shell-identifier name), although without a shell `FOO=1` would be a program name: no real program
is named like an assignment, so refusing it fails closed and keeps the two builders consistent (decided for #376).

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

## External policy responsibility

Rule evaluation, storage, generation, signing, composition, synchronization, and capability inference belong
outside allw. `PolicyDecision`, `PolicyBlock`, the audit policy block, and semantic slots are removed.

## Open questions

- Command interpretation and derived fields are directed out; slice 2 completes their removal and renames
  this document to `action-record.md`.
- Authentication of the human's policy-modification choice remains open until that work is scheduled.
