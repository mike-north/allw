# Claude Code Integration

`@allw/hook` is a [Claude Code **PreToolUse** hook](https://code.claude.com/docs/en/hooks) — the
v1 beachhead integrator. It turns a pending sensitive tool call into a phone approval: it builds an
`ActionRecord` from the call through the WASM core, requests a human decision over the
zero-knowledge relay (via `@allw/sdk`), and lets the call proceed **only** on a verified human
approval. This is the structural peer of [`docs/codex-integration.md`](./codex-integration.md) —
same shape, Claude Code specifics. It consolidates what was previously scattered across
[`docs/quickstart.md`](./quickstart.md) §4, [`packages/hook/README.md`](../packages/hook/README.md),
and the doc comments in `packages/hook/src/lib/*.ts`; those sources remain accurate but this is the
single place to check the full contract.

For the zero-to-first-approval walkthrough (pairing an approver, starting the relay, running a
gated command), see [`docs/quickstart.md`](./quickstart.md) §§0–5. This document is the reference
contract, not a tutorial.

## Integration Shape

Claude Code hooks are configured under `hooks.PreToolUse` in `.claude/settings.json` (project,
user, or managed scope). `@allw/hook` is installed as a **`command`**-type hook handler — the
supported, evaluated install path this doc documents:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|Edit|MultiEdit|Write)$|^mcp__",
        "hooks": [
          {
            "type": "command",
            "command": "node /absolute/path/to/packages/hook/dist/cli.js",
            "timeout": 480,
            "onFailure": "block"
          }
        ]
      }
    ]
  },
  "permissions": {
    "deny": ["Monitor", "PowerShell", "NotebookEdit"]
  }
}
```

- `matcher` is evaluated against `tool_name`. `^(Bash|Edit|MultiEdit|Write)$|^mcp__` contains
  regex characters, so Claude Code reads it as a JavaScript regular expression, and the anchors make
  it match whole names: exactly `Bash`, `Edit`, `MultiEdit` and `Write`, plus every tool whose name
  starts with `mcp__` (every MCP tool). Unanchored, `Edit` would also match `NotebookEdit`, which
  the hook doesn't gate. (Claude Code now calls `MultiEdit` legacy; it stays in the matcher for
  versions that still have it.)
- **The `deny` rules turn off the tools that can run commands or change files but that allw doesn't
  gate yet** ([#298](https://github.com/mike-north/allw/issues/298)): `Monitor` and `PowerShell` run
  shell commands, and `NotebookEdit` edits notebook files. A deny rule that names a bare tool removes
  it from Claude's context ([Permissions](https://code.claude.com/docs/en/permissions#manage-permissions)).
  Without them, those tools reach your files and shell under Claude Code's own rules alone, with no
  approver in the loop. **`Monitor` uses your `Bash` permission rules**
  ([Monitor tool](https://code.claude.com/docs/en/tools-reference#monitor-tool)), so a `Bash` allow
  rule also lets it run any command with no prompt at all.
- **Always pin `"timeout": 480`** (seconds). Without it the hook inherits Claude Code's 600s
  command-hook default, and the timeout-ordering invariant below depends on a known pinned value.
- Use an absolute path to `dist/cli.js`, or `npx --no-install allw-hook` — `command` runs under
  `node`, never a standalone native binary (`docs/architecture.md`'s WASM-local hard constraint).
  **Never plain `npx allw-hook`:** where no local or global bin resolves (a user-level
  `~/.claude/settings.json`, a project without the package), plain `npx` downloads and runs the
  registry package of that name without prompting, so a squatted package would run as the gate.
  `--no-install` makes `npx` exit 1 instead and downloads nothing (checked on npm 10.9.4 and
  11.21.1; it still makes a metadata request to the registry before giving up). See
  [`npm exec`](https://docs.npmjs.com/cli/commands/npm-exec).
- **Set `"onFailure": "block"`** (Claude Code v2.1.295 or later; older versions ignore the key
  without warning, so a hook that can't start still lets the call through — check
  `claude --version`). Without it, a hook that can't
  start, exits with a code other than 0 or 2, or times out is a non-blocking error and the tool call
  goes ahead (see [Fail-Closed Analysis](#fail-closed-analysis)). With it, Claude Code
  [blocks the call](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails).
  `@allw/hook` exits 0 on every decision, deny included, so the setting never turns one of its own
  decisions into a failure.

### Install the hook where the agent can't write it

**The gate is only as strong as the agent's inability to change it.** An agent that can edit the
hook's code (`node_modules/@allw/hook/dist/cli.js`) or the settings file that registers it can turn
the gate off without asking anyone. A project-local install sits inside the working directory, where
`acceptEdits` mode auto-approves file edits, and a matcher without `Edit`, `MultiEdit` and `Write`
doesn't gate edits at all. So install the hook **outside any tree the agent works in** and register it in your
**user-level** `~/.claude/settings.json` by absolute path:

```sh
# A user-owned install, outside every project:
npm install --prefix "$HOME/.allw/hook" @allw/hook

# The absolute path to put in "command":
echo "$HOME/.allw/hook/node_modules/@allw/hook/dist/cli.js"
```

(Until `@allw/hook` is published, pass the packed `@allw/sdk` and `@allw/hook` tarballs to the same
`npm install --prefix` command instead of the package name.)

Then register it in `~/.claude/settings.json` with the full matcher, `onFailure` and the `deny`
rules, and put the export lines for the `ALLW_*` variables in the shell profile Claude Code launches
from:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|Edit|MultiEdit|Write)$|^mcp__",
        "hooks": [
          {
            "type": "command",
            "command": "node /Users/you/.allw/hook/node_modules/@allw/hook/dist/cli.js",
            "timeout": 480,
            "onFailure": "block"
          }
        ]
      }
    ]
  },
  "permissions": {
    "deny": ["Monitor", "PowerShell", "NotebookEdit"]
  }
}
```

`"onFailure": "block"` needs Claude Code v2.1.295 or later; older versions ignore the key without
warning, so check `claude --version`. Why this holds:

- `~/.claude/` is one of Claude Code's
  [protected paths](https://code.claude.com/docs/en/permission-modes#protected-paths): writes there
  are never auto-approved (except in `bypassPermissions`), and allow rules don't pre-approve them.
- `~/.allw/hook` is outside the working directory, so `acceptEdits` doesn't auto-approve edits to it.
- **allw gates exactly these tools:** `Bash`, `Edit`, `MultiEdit`, `Write` and every MCP tool. A
  change to either location through one of them reaches your approver first. **Deny any request that
  writes under `~/.allw/` or `~/.claude/`.**
- **allw doesn't gate `Monitor`, `PowerShell` or `NotebookEdit`**
  ([#298](https://github.com/mike-north/allw/issues/298)), and `Monitor` and `PowerShell` can run
  any shell command, including one that edits or deletes the hook. That is why the config above
  denies all three. If you remove those deny rules, these tools reach the hook's files under Claude
  Code's own rules alone, and a `Bash` allow rule lets `Monitor` do it with no prompt.

This is guidance, not a tamper-proof boundary: in `bypassPermissions` mode allw is the only gate, and
the agent still runs as your OS user. Moving the account root off the agent's machine is tracked in
[#244](https://github.com/mike-north/allw/issues/244).

**stdin** (the pending tool call — Claude Code sends more fields than the hook reads; see
[Hook input and output](https://code.claude.com/docs/en/hooks#hook-input-and-output)):

```jsonc
{
  "session_id": "…",
  "transcript_path": "…",
  "cwd": "/abs/path",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash", // or "Edit" / "Write" / "MultiEdit" / "mcp__<server>__<tool>"
  "tool_input": { "command": "rm -rf build" }, // tool-specific
  "tool_use_id": "toolu_…",
}
```

`parseHookInput` (`packages/hook/src/lib/hook-io.ts`) reads only `hook_event_name`, `tool_name`,
`tool_input`, and `cwd`; every other field (`session_id`, `permission_mode`, `tool_use_id`, …) is
ignored. `permission_mode` is not consulted — the hook's decision is uniform regardless of the
session's Claude Code permission mode. See [Permission-Mode Interactions](#permission-mode-interactions).

**stdout** (the hook always exits `0`): **empty** when allw has no objection, or one `deny`:

```jsonc
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny", // the only decision allw ever emits
    "permissionDecisionReason": "allw: …",
  },
}
```

`permissionDecision` is one of four values Claude Code understands on `PreToolUse`: `allow`,
`deny`, `ask`, or `defer` (`hookSpecificOutput.permissionDecision`,
[PreToolUse decision control](https://code.claude.com/docs/en/hooks#pretooluse-decision-control)).
**allw only ever emits `deny`.** A verified human approval, a non-gated tool and a pass-through all
get **no decision**: exit `0` with empty stdout, which Claude Code treats as a plain success with no
fields to apply ([Exit code output](https://code.claude.com/docs/en/hooks#exit-code-output)), so it
goes on to its own permission rules exactly as if allw weren't installed.

allw never emits `allow` because in Claude Code an `allow` **skips the permission prompt** (deny and
ask rules are still evaluated). That would let an allw approval, or a matcher widened to tools allw
never asks about, grant access the user's own permission setup would have prompted for. A verdict
may only tighten access (`docs/contract.md` §Invariants). It never emits `ask` (there is no
"escalate to Claude Code's own prompt" tier) or `defer` (only for non-interactive `-p` / Agent-SDK
integrations pausing a call for external resumption). `@allw/codex-hook` uses the same deny-only
encoding ([#191](https://github.com/mike-north/allw/issues/191)); both CLIs share one writer
(`packages/hook/src/lib/decision-output.ts`). For `deny`, `permissionDecisionReason` is shown to
Claude.

## What Is Gated

The matcher above routes candidate tool calls to the hook; `isGatedTool` /
`gateToolCall` (`packages/hook/src/lib/gating.ts`) then decide what actually requires a human
approval:

| Tool name(s)                                            | Gated? | Substrate                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Bash`                                                  | Yes    | `command` — built from `tool_input.command` (+ `cwd` when present).                                                                                                                                                                                                                      |
| `Edit`, `Write`, `MultiEdit`                            | Yes    | `file_edit` — built from the operation kind, target path(s), a compact summary, and a hash of the full edit bytes.                                                                                                                                                                       |
| any `mcp__<server>__<tool>` name                        | Yes    | `mcp_tool_call` — built from the parsed server/tool name and the raw `tool_input` params object.                                                                                                                                                                                         |
| `apply_patch`                                           | Yes    | `file_edit`, via the same Codex apply-patch-grammar parser. Claude Code has no `apply_patch` tool, so this branch is never reached in a Claude Code session; it exists because `gateToolCall` is the same shared function `@allw/codex-hook` imports (`packages/codex-hook/src/cli.ts`). |
| `Monitor`, `PowerShell`, `NotebookEdit`                 | No     | **Not gated yet** ([#298](https://github.com/mike-north/allw/issues/298)), though they run shell commands (`Monitor`, `PowerShell`) or edit files (`NotebookEdit`). The recommended config denies them outright; see [Integration Shape](#integration-shape).                            |
| everything else (`Read`, `Glob`, `Grep`, `WebFetch`, …) | No     | **No decision** (empty stdout) without contacting the relay, and **without requiring `allw` config** — a missing/misconfigured install never blocks reads; Claude Code's own permission rules apply.                                                                                     |

Two fail-closed subtleties worth calling out precisely, because they are easy to get wrong when
widening the matcher:

- **Gating an `mcp__`-prefixed name does not require it to parse.** `isGatedTool` gates on the
  `mcp__` prefix alone; a name that carries the prefix but doesn't parse as
  `mcp__<server>__<tool>` (e.g. `mcp__server__` or `mcp__onlytwo`) is still routed to `gateToolCall`,
  which then returns a `build-error` (→ `deny`). Treating an unparseable MCP name as non-gated would
  let it through without a human, which would break fail-closed for MCP calls — so the hook denies
  instead.
- **Widening the matcher only adds gating; it never grants.** A tool name that isn't `Bash`, a
  file-edit tool, or `mcp__`-prefixed falls through to the `pass-through` branch, which makes **no
  decision**: Claude Code applies its own permission rules to that call exactly as it would without
  the hook. (Before [#247](https://github.com/mike-north/allw/issues/247) the pass-through emitted
  `allow`, which skipped Claude Code's prompt, so a matcher such as `.*` made allw grant tools it never
  asked a human about.) The matcher decides which calls reach the hook at all; the hook can only ever
  add a `deny`.

## Configuration

The hook has no config file; it reads its environment (`packages/hook/src/lib/config.ts`):

| Variable                 | Required | Meaning                                                                                                                                  |
| ------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLW_RELAY_URL`         | yes      | Base URL of the zero-knowledge relay.                                                                                                    |
| `ALLW_ACCOUNT_ID`        | yes      | The approver's relay account id (routes to their devices).                                                                               |
| `ALLW_APPROVER_ROOT_KEY` | yes      | The approver account-root Ed25519 public key (base64url).                                                                                |
| `ALLW_TIMEOUT_MS`        | no       | Fail-closed approval deadline in ms (default `300000` = 5 min; must be **strictly below `420000`**, rejected — fail-closed — otherwise). |
| `ALLW_FETCH_TIMEOUT_MS`  | no       | Per-relay-fetch timeout in ms (default/max `30000`); may only lower the SDK's per-fetch timeout, never raise it.                         |

Same shape as `docs/codex-integration.md`'s "Decision Mapping" env-var table — both hooks read the
identical `ALLW_*` variables, because `readConfig` is one shared function
(`packages/hook/src/lib/config.ts`, imported by `@allw/codex-hook`). A missing required variable, or
an `ALLW_TIMEOUT_MS`/`ALLW_FETCH_TIMEOUT_MS` outside its bound, is a fail-closed `deny` at
config-read time — see [Fail-Closed Analysis](#fail-closed-analysis).

## Decision Mapping

`decide` (`packages/hook/src/lib/decide.ts`) reduces every path to exactly one of "no decision"
(empty stdout) or `deny`.
The Claude Code hook's `hookSpecificOutput` carries no machine-readable category field — only the
human-readable `permissionDecisionReason` string shown below. The Codex hook briefly added a
`denyReason` field in [#166](https://github.com/mike-north/allw/pull/166), but Codex's `PreToolUse`
output schema rejects unknown fields on that object, which silently discarded every deny; it now
carries the same category as an `allw[<category>]: ` prefix on `permissionDecisionReason` instead
(see [`docs/codex-integration.md`](./codex-integration.md#decision-mapping) and
[#191](https://github.com/mike-north/allw/issues/191)) — there still isn't a Claude Code
equivalent field, nor should there be:

| allw result                                                                                                                                                                  | `permissionDecision` | `permissionDecisionReason` (pattern)                                                                     |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------- |
| non-gated tool (`Read`, `Grep`, `Glob`, `WebFetch`, …)                                                                                                                       | none (empty stdout)  | —                                                                                                        |
| gated, verified verdict `decision === "approved"`                                                                                                                            | none (empty stdout)  | —                                                                                                        |
| gated, verified verdict `denied` / `expired` / `aborted`                                                                                                                     | `deny`               | `allw: <summary> — not approved (verdict: <decision>)`                                                   |
| gated, `ActionRecord` could not be built (malformed `tool_input`, invalid shell syntax, unparseable MCP name/params, malformed file-edit payload)                            | `deny`               | `allw: <reason> (fail-closed deny)` — reason names the specific field/shape problem                      |
| gated, the built `ActionRecord` JSON was not in the expected shape (defense in depth; the core always emits a well-formed record)                                            | `deny`               | `allw: built ActionRecord was not in the expected shape (fail-closed deny)`                              |
| gated, `requestApproval` threw (network/relay error, no enrolled devices, relay rejection)                                                                                   | `deny`               | `allw: approval request failed (fail-closed deny): <error message>`                                      |
| malformed hook stdin (not JSON, not an object, wrong `hook_event_name`, missing/non-string `tool_name`)                                                                      | `deny`               | `allw: hook input was not valid JSON (fail-closed deny)` (or the sibling reason for the specific defect) |
| missing or invalid config (`ALLW_RELAY_URL`/`ALLW_ACCOUNT_ID`/`ALLW_APPROVER_ROOT_KEY` unset, or `ALLW_TIMEOUT_MS`/`ALLW_FETCH_TIMEOUT_MS` out of bounds)                    | `deny`               | `allw: ALLW_RELAY_URL is not set (fail-closed deny)` (or the sibling reason)                             |
| any unexpected internal error (defense in depth; the process-level catch-all in `cli.ts`'s `main()`)                                                                         | `deny`               | `allw: hook failed unexpectedly (fail-closed deny): <error message>`                                     |
| the process reaches `beforeExit`/`exit`, or gets `SIGTERM`/`SIGINT`/`SIGHUP`, before `main()` decided (exit backstop, [#265](https://github.com/mike-north/allw/issues/265)) | `deny`               | `allw: hook exited before reaching a decision (fail-closed deny)`                                        |

A gated call loses allw's `deny` **only** when its verdict is delivered, cryptographically
verified against the approver's account-root key, bound to this exact request (WYSIWYS), fresh,
and a human "yes" — the verification lives in the audited Rust core; the hook only maps the
verified result onto the decision (`docs/contract.md` §Invariants #6). Even then the hook grants
nothing: Claude Code's own permission rules still decide the call (see
[After an approval](#after-an-approval-claude-codes-own-permissions-still-apply)).

**Exit backstop.** Because empty stdout means "no objection", a process that exits _before_
deciding must not read as one. The hook installs a backstop
(`packages/hook/src/lib/decision-output.ts`, shared with `@allw/codex-hook`): if the process reaches
Node's `beforeExit` or `exit` without `main()` having written its decision (the event loop drained
while an approval was pending, the shape of [#254](https://github.com/mike-north/allw/issues/254); an
uncaught exception; a stray `process.exit(n)`), or receives `SIGTERM`, `SIGINT` or `SIGHUP` while
waiting, it prints the backstop `deny` above once and exits `0`. What the process can't answer is
covered in [Fail-Closed Analysis](#fail-closed-analysis).

### After an approval: Claude Code's own permissions still apply

With no hook decision, Claude Code evaluates the call exactly as it would without allw: deny rules
block, ask rules prompt, allow rules and the permission mode decide the rest
([Permissions](https://code.claude.com/docs/en/permissions#manage-permissions)). **allw only adds a
gate; it never grants.** So in the default mode an approved `Bash` command can still show Claude
Code's own prompt at the desk after you approved it on your phone.

If you want the phone approval to be the only prompt for the gated tools, add allow rules for them
in the same settings file as the hook:

```json
{
  "permissions": {
    "allow": ["Bash", "Edit", "MultiEdit", "Write", "mcp__<server>__*"],
    "deny": ["Monitor", "PowerShell", "NotebookEdit"]
  }
}
```

> **Keep the `deny` rules whenever you add these allow rules.** A `Bash` allow rule also covers the
> `Monitor` tool, which runs shell commands under your `Bash` rules
> ([Monitor tool](https://code.claude.com/docs/en/tools-reference#monitor-tool)) and which allw
> doesn't gate. An `Edit` allow rule also covers `NotebookEdit`
> ([tool-specific rules](https://code.claude.com/docs/en/tools-reference#configure-tools-with-permission-rules-and-hooks)).
> Without the deny rules, the agent could run any command through `Monitor`, or edit notebooks,
> with no phone approval and no prompt at the desk.

- An allow rule never overrides allw: a hook `deny` blocks the call even when an allow rule matches
  ([Extend permissions with hooks](https://code.claude.com/docs/en/permissions#extend-permissions-with-hooks)).
- MCP allow rules must name the server (`mcp__github__*`); an unanchored `mcp__*` allow rule is
  skipped and approves nothing
  ([MCP rules](https://code.claude.com/docs/en/permissions#mcp)). Add one per MCP
  server you use.
- The trade-off: these allow rules also apply when allw doesn't run. If the hook can't start, crashes
  or times out, Claude Code treats that as a non-blocking error and the call proceeds without any
  prompt, unless the hook sets `"onFailure": "block"` (Claude Code v2.1.295 or later; older versions
  ignore the key without warning). Don't add these allow rules without it.
- Your own deny and ask rules keep working on top of allw. An ask rule still prompts after a phone
  approval.

## Fail-Closed Analysis

`allw`'s fail-closed guarantee has two layers: what **the hook process** does, and what **Claude
Code** does when the hook process doesn't finish normally.

**Inside the hook process.** Every path in the table above ends in either no decision or one
`deny`, with exit `0`. `cli.ts`'s `main()` turns an unanticipated internal throw into a `deny`. The
exit backstop covers the remaining early ends the process can still see: reaching `beforeExit` or
`exit` without a decision (a drained event loop, an uncaught async exception, a stray
`process.exit(n)`), and `SIGTERM`, `SIGINT` or `SIGHUP` while waiting. Each prints one `deny` and
exits `0`.

**What the process can't answer:** `SIGKILL`, a native crash or `process.abort()`, running out of
memory, a crash while loading modules before the backstop is installed, the hook never starting (a
wrong path, `node` missing from `PATH`, `npx --no-install` finding no installed bin), and Claude
Code's own `timeout`, after which Claude Code discards the hook's output. Each of these ends with
no decision from allw. What happens next depends on `onFailure`.

**At the boundary** (the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails),
checked 2026-11-02):

- **With `"onFailure": "block"`** (Claude Code v2.1.295 or later; older versions silently ignore the
  key, so check `claude --version`): Claude Code blocks the tool call, as exit `2` would, when the
  hook can't start, exits with a code other than `0` or `2`, times out, or prints JSON it can't parse
  or validate. A hook killed by a signal or a crash doesn't exit `0` or `2`, so it falls under that
  rule (the reference doesn't name signals separately). Every failure above therefore blocks the
  call. Empty or plain-text stdout on exit `0` is a success, not a failure, and still proceeds: that
  is allw's "no decision".
- **Without it**, each of those failures is a _non-blocking error_ and the action goes ahead: "a
  hook that can't start is a non-blocking error too", and a timed-out `PreToolUse` hook "doesn't
  block the tool call. The call continues through the normal permission flow." A crashed hook is
  then **indistinguishable from a hook that made no decision**: the call goes on to Claude Code's
  own permission rules and mode, exactly as an approved call does. Whether a human sees it depends
  on those alone. Default mode with no matching allow rule still shows Claude Code's prompt at the
  desk. An allow rule for the tool (see
  [After an approval](#after-an-approval-claude-codes-own-permissions-still-apply)), `auto`,
  `bypassPermissions` or a non-interactive run lets it run with no human prompt at all.

So the recommended config always sets `"onFailure": "block"`, and you shouldn't add allow rules for
the gated tools without it. allw never relies on exit `2` itself: it always reports a `deny` as JSON
on exit `0`, so its own decisions never depend on that mechanism.

**Contrast with Codex** (`docs/codex-integration.md` §"Codex Hook Constraints"): "a failed,
malformed, or timed-out hook invocation is a non-blocking error; Codex reports the hook problem and
continues the tool call," uniformly, and Codex has no `onFailure` equivalent
([`docs/codex-integration.md`](./codex-integration.md#if-the-hook-cant-start)). On Codex the
residual stands: a hook that is killed, hangs past its timeout or never starts contributes nothing
to that call.

The timeout residual, on Codex and on Claude Code without `onFailure`, is why the
[timeout-ordering invariant (issue #52)](https://github.com/mike-north/allw/issues/52) exists and is enforced twice over, identically for both hooks: the install block pins the hook
`timeout` to `480` seconds (`PINNED_HOOK_TIMEOUT_MS`), and `readConfig` rejects any
`ALLW_TIMEOUT_MS` at or above `420000` ms (`MAX_TIMEOUT_MS`) as a fail-closed `deny` at
config-read time — never a silent clamp. So long as the hook process starts at all, the SDK's own
deadline (plus its bounded per-relay-fetch timeouts, capped by `ALLW_FETCH_TIMEOUT_MS` ≤ `30000` ms)
resolves to an explicit `deny` with 60 seconds of margin before Claude Code's pinned timeout could
ever fire, so a hook timeout is an edge case the design guards against, not the common path.

## Permission-Mode Interactions

Claude Code sessions run in one of six [permission modes](https://code.claude.com/docs/en/permission-modes):

| Mode                         | What runs without asking (Claude Code's own gate)                                |
| ---------------------------- | -------------------------------------------------------------------------------- |
| `default` (labeled "Manual") | Reads only.                                                                      |
| `acceptEdits`                | Reads, file edits, and common filesystem commands.                               |
| `plan`                       | Reads, plus classifier-approved commands when auto mode is available.            |
| `auto`                       | Everything, reviewed by a background classifier model instead of a human prompt. |
| `dontAsk`                    | Only pre-approved tools — everything else is auto-**denied**, never prompted.    |
| `bypassPermissions`          | Everything, including protected-path writes.                                     |

Two properties, both drawn directly from the Claude Code docs, matter for how `allw`'s gate
composes with these modes:

1. **PreToolUse hooks run before the permission prompt, in every mode, for every tool except
   `EndConversation`** ("[Extend permissions with hooks](https://code.claude.com/docs/en/permissions#extend-permissions-with-hooks)").
   The mode governs what _Claude Code's own_ prompt/classifier auto-approves; it does not gate
   whether the hook runs. This is explicit even for the two extremes: `dontAsk` mode's own
   description names "calls approved by a PreToolUse hook" as one of only three ways a tool call
   can run at all in that mode (alongside `permissions.allow` rules and read-only Bash), and the
   critical-path `rm`/`rmdir` circuit-breaker is stated to override a hook `"allow"` "even in modes
   that skip other prompts" — implying the hook is consulted in those modes too, not bypassed.
2. **A hook `deny` — or an exit-`2` block — is decisive and is not overridable by an allow rule or
   a permissive mode.** allw's only decision is `deny`, so this is the whole of its effect.

Because allw makes **no decision** on an approval or a pass-through, every mode then behaves exactly
as it would without allw for that call. Consequences for `allw` specifically:

- **allw never loosens a mode.** In `default` mode an approved `Bash` call can still get Claude
  Code's own prompt; in `acceptEdits` an approved edit inside the working directory runs without one;
  in `bypassPermissions` everything allw doesn't deny runs. See
  [After an approval](#after-an-approval-claude-codes-own-permissions-still-apply) for allow rules
  that make the phone the only prompt.
- **`dontAsk` mode denies an approved call unless an allow rule covers it.** `dontAsk` runs only
  pre-approved tools (allow rules, read-only Bash, or a hook `allow`), and allw never emits `allow`.
  Add `permissions.allow` rules for the gated tools if you use `dontAsk`.
- Because `allw` only ever emits `deny` (never `ask`), it never itself triggers "a hook's `ask`
  forces a permission prompt even in auto mode" — an approval is either a verified human "yes" on
  the paired device, or the call is denied.
- Claude Code's own circuit breakers stay in place:
  ["actions no mode auto-approves"](https://code.claude.com/docs/en/permission-modes#actions-no-mode-auto-approves)
  (an explicit `ask` rule match, `AskUserQuestion`, MCP tools marked `requiresUserInteraction`,
  `rm`/`rmdir` on a critical path) still prompt after an allw approval.

## Claude Code Hook Constraints

This design depends on the current Claude Code hooks contract, checked on 2026-08-23 (`onFailure`,
timeouts and matcher rules re-checked 2026-11-02):

- Hook commands receive one JSON object on stdin (event-specific fields plus common fields like
  `cwd`, `permission_mode`, `hook_event_name`) and communicate results through exit codes, stdout,
  and stderr.
- `PreToolUse` fires before a tool call executes and can `allow`/`deny`/`ask`/`defer` it via
  `hookSpecificOutput.permissionDecision`; `deny`/`defer`/`ask` outrank `allow` when multiple
  `PreToolUse` hooks disagree (precedence: `deny` > `defer` > `ask` > `allow`). allw uses only
  `deny`, so it outranks every other hook's decision and never overrides one.
- Matcher patterns for `PreToolUse` are evaluated against `tool_name`: a name made only of letters,
  digits, `_`/`-`/spaces/`,`/`|` is an exact-match list; anything else (including a trailing `.*`)
  is an unanchored JavaScript regular expression, so `Edit.*` also matches `NotebookEdit`. allw's
  recommended matcher anchors each name with `^…$` for that reason.
- All matching hooks (from every settings source — user, project, local, managed, plugin) run in
  parallel.
- **As of 2026, Claude Code hook handlers also support `type: "http"` (POST the event JSON to a
  URL, read the decision from the response body) and `type: "mcp_tool"` (call a tool on an
  already-connected MCP server), alongside `type: "command"`. Handlers also accept an `if` field
  using [permission-rule syntax](https://code.claude.com/docs/en/permissions) (e.g.
  `"Bash(git *)"`, `"Edit(*.ts)"`) to filter more narrowly than the matcher, evaluated against the
  tool name and arguments together.** `@allw/hook` documents and ships only the `command`-handler
  install above — the primary, supported path. `http`/`mcp_tool`/`if` exist in the platform and are
  noted here for completeness only; evaluating whether `allw` should adopt any of them (e.g. an
  `if` filter to narrow `Bash` gating to specific subcommands) is explicitly out of scope for this
  document.
- Hook `timeout` is in **seconds** and defaults to `600` for `command`/`http`/`mcp_tool` handlers;
  `allw` pins `480` so the SDK's fail-closed deadline resolves first (see
  [Fail-Closed Analysis](#fail-closed-analysis)).

Source: [Claude Code hooks reference](https://code.claude.com/docs/en/hooks),
[Choose a permission mode](https://code.claude.com/docs/en/permission-modes),
[Permissions](https://code.claude.com/docs/en/permissions).

## UAT Checklist

There is no automated UAT-prep script for the Claude Code hook yet (the Codex-parallel
`scripts/uat-codex.sh` has no Claude Code twin) — use [`docs/quickstart.md`](./quickstart.md) §§0–4
to stand up a local relay, pair an approver, and export the `ALLW_*` env vars, then wire the hook
into a scratch project's `.claude/settings.json` and drive a real Claude Code session by hand.
Record the result on the relevant tracking issue:

1. **Approve path**: ask Claude Code to run a harmless gated `Bash` command, approve it on the
   paired approver device, and confirm Claude Code proceeds.
2. **Deny path**: ask Claude Code to run another gated `Bash` command, deny it on the approver
   device, and confirm Claude Code receives `permissionDecision: "deny"` and does not run the tool.
3. **Timeout path**: set a short `ALLW_TIMEOUT_MS`, leave the approval unanswered, and confirm
   Claude Code denies the tool call before its pinned `480`-second hook timeout.
4. **Actor identity**: confirm the approval inbox shows the request as `machine:<hostname>` /
   `claude-code` rather than the Codex actor (`codex:<hostname>`).
5. **File-edit path**: ask Claude Code to make a simple `Edit` or `Write` and confirm the hook
   gates the resulting `file_edit` action with the target path, summary, and diff hash visible.

```md
Approve: PASS/FAIL - command ran only after approval
Deny: PASS/FAIL - command was blocked after denial
Timeout: PASS/FAIL - command failed closed after ALLW_TIMEOUT_MS
Actor identity: PASS/FAIL - inbox showed machine:<hostname> / claude-code
File edit: PASS/FAIL - Edit/Write was gated with path, summary, and diff hash
Notes:
```

The automated test suite (`packages/hook/test/*.test.mjs`, especially `cli.test.mjs` and
`integration.test.mjs`) already exercises the full stdin→stdout decision path — approve, deny,
missing config, malformed stdin, and bounded-time denial against a hung/refused relay — against a
relay double and a WASM-signed verdict. This checklist is the remaining product-acceptance proof
that a real Claude Code session invokes the hook and honors the result.
