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
        "matcher": "Bash|Edit|MultiEdit|Write|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "node /absolute/path/to/packages/hook/dist/cli.js",
            "timeout": 480
          }
        ]
      }
    ]
  }
}
```

- `matcher` is evaluated against `tool_name`. `Bash|Edit|MultiEdit|Write|mcp__.*` is the
  recommended install matcher (`packages/hook/README.md`); `mcp__.*` is required (not
  `mcp__<server>`) because a bare server prefix without `.*` is treated as an exact-string match
  and matches nothing.
- **Always pin `"timeout": 480`** (seconds). Without it the hook inherits Claude Code's 600s
  command-hook default, and the timeout-ordering invariant below depends on a known pinned value.
- Use an absolute path to `dist/cli.js` (or the resolved `allw-hook` bin) — `command` runs under
  `node`, never a standalone native binary (`docs/architecture.md`'s WASM-local hard constraint).

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

**stdout** (the permission decision; the hook always exits `0`):

```jsonc
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow", // or "deny" — allw never emits "ask" or "defer"
    "permissionDecisionReason": "allw: …",
  },
}
```

`permissionDecision` is one of four values Claude Code understands on `PreToolUse`: `allow`,
`deny`, `ask`, or `defer` (`hookSpecificOutput.permissionDecision`,
[PreToolUse decision control](https://code.claude.com/docs/en/hooks#pretooluse-decision-control)).
`allw` only ever emits `allow` (a verified human approval, or a non-gated pass-through) or `deny`
(everything else); it never emits `ask` (there is no "escalate to Claude Code's own prompt" tier —
a gated action either reaches a verified human decision on the paired approver device or fails
closed) or `defer` (which only applies to non-interactive `-p` / Agent-SDK integrations pausing a
tool call for external resumption — not this hook's use case). `permissionDecisionReason` is shown
to the user for `allow` (not to Claude); for `deny`, it is shown to Claude.

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
| everything else (`Read`, `Glob`, `Grep`, `WebFetch`, …) | No     | Passes through as `allow` without contacting the relay, and **without requiring `allw` config** — a missing/misconfigured install never blocks reads.                                                                                                                                    |

Two fail-closed subtleties worth calling out precisely, because they are easy to get wrong when
widening the matcher:

- **Gating an `mcp__`-prefixed name does not require it to parse.** `isGatedTool` gates on the
  `mcp__` prefix alone; a name that carries the prefix but doesn't parse as
  `mcp__<server>__<tool>` (e.g. `mcp__server__` or `mcp__onlytwo`) is still routed to `gateToolCall`,
  which then returns a `build-error` (→ `deny`). Treating an unparseable MCP name as non-gated would
  pass it through as `allow`, which would break fail-closed for MCP calls — so the hook denies
  instead.
- Widening the matcher to a new tool name is additive and safe by construction: an unrecognized
  tool name that isn't `Bash`, a file-edit tool, or `mcp__`-prefixed falls through to the
  `pass-through` branch (`allow`) regardless of matcher — the matcher only ever narrows which calls
  reach the hook process at all, never what the hook decides once it does.

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

`decide` (`packages/hook/src/lib/decide.ts`) reduces every path to exactly one of `allow`/`deny`.
Unlike the Codex hook, the Claude Code hook's `hookSpecificOutput` carries no machine-readable
`denyReason` field — only the human-readable `permissionDecisionReason` string shown below (the
Codex hook added `denyReason` in [#166](https://github.com/mike-north/allw/pull/166); it has no
Claude Code equivalent):

| allw result                                                                                                                                               | `permissionDecision` | `permissionDecisionReason` (pattern)                                                                     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------- |
| non-gated tool (`Read`, `Grep`, `Glob`, `WebFetch`, …)                                                                                                    | `allow`              | `allw: tool '<name>' is not gated by allw; passing through`                                              |
| gated, verified verdict `decision === "approved"`                                                                                                         | `allow`              | `allw: <summary> — approved by the human`                                                                |
| gated, verified verdict `denied` / `expired` / `aborted`                                                                                                  | `deny`               | `allw: <summary> — not approved (verdict: <decision>)`                                                   |
| gated, `ActionRecord` could not be built (malformed `tool_input`, invalid shell syntax, unparseable MCP name/params, malformed file-edit payload)         | `deny`               | `allw: <reason> (fail-closed deny)` — reason names the specific field/shape problem                      |
| gated, the built `ActionRecord` JSON was not in the expected shape (defense in depth; the core always emits a well-formed record)                         | `deny`               | `allw: built ActionRecord was not in the expected shape (fail-closed deny)`                              |
| gated, `requestApproval` threw (network/relay error, no enrolled devices, relay rejection)                                                                | `deny`               | `allw: approval request failed (fail-closed deny): <error message>`                                      |
| malformed hook stdin (not JSON, not an object, wrong `hook_event_name`, missing/non-string `tool_name`)                                                   | `deny`               | `allw: hook input was not valid JSON (fail-closed deny)` (or the sibling reason for the specific defect) |
| missing or invalid config (`ALLW_RELAY_URL`/`ALLW_ACCOUNT_ID`/`ALLW_APPROVER_ROOT_KEY` unset, or `ALLW_TIMEOUT_MS`/`ALLW_FETCH_TIMEOUT_MS` out of bounds) | `deny`               | `allw: ALLW_RELAY_URL is not set (fail-closed deny)` (or the sibling reason)                             |
| any unexpected internal error (defense in depth; the process-level catch-all in `cli.ts`'s `main()`)                                                      | `deny`               | `allw: hook failed unexpectedly (fail-closed deny): <error message>`                                     |

A verdict becomes `allow` **only** when it is delivered, cryptographically verified against the
approver's account-root key, bound to this exact request (WYSIWYS), fresh, and a human "yes" — the
verification lives in the audited Rust core; the hook only maps the verified result onto the
decision (`docs/contract.md` §Invariants #6).

## Fail-Closed Analysis

`allw`'s fail-closed guarantee has two layers: what **the hook itself** always does, and what
**Claude Code** does at the process boundary around it. The hook's own half is airtight by
construction — every code path in the table above resolves to an explicit `allow`/`deny`, and
`cli.ts`'s `main()` wraps the whole run in a catch-all that turns even an unanticipated internal
throw into a parseable `deny`, still exiting `0` so Claude Code can read it as a decision rather
than a hook error. The open question — the one this section answers precisely — is what happens
when the hook process itself never gets that far: killed before it can write to stdout, or too slow
to finish.

**Claude Code's own documented behavior at that boundary, per its exit-code and timeout contract**
(verified against the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks),
checked 2026-08-23):

- **Exit `0` with valid decision JSON on stdout** → the JSON decides; this is the hook's own normal
  path and is closed by construction.
- **Exit `2`** → always blocks the tool call regardless of any JSON, "the one outcome JSON can't
  override." `allw` deliberately does not rely on this path (see `packages/hook/README.md` and
  `cli.ts`'s header comment) — it always emits a `deny` decision JSON on exit `0` instead, so its
  fail-closed behavior never depends on this Claude-Code-specific mechanism.
- **Any other exit code (including `0`) with invalid/absent JSON on stdout** (a crash, `SIGKILL`, a
  script that can't start, or a bug that writes non-JSON) → **a non-blocking error: "the action
  proceeds."** This is an unconditional fail-open — the tool call runs exactly as if the hook had
  returned `allow`.
- **A `command` hook that exceeds its pinned `timeout`** → canceled; Claude Code discards its
  output and the hook "renders no decision." Distinctly from the bullet above, a _timed-out_
  `PreToolUse` hook "doesn't block the tool call. The call continues through **the normal
  permission flow**" — i.e. it falls through to Claude Code's own permission system (mode/rules),
  not to an unconditional proceed. In an interactive session with no matching allow rule, that
  still surfaces Claude Code's own confirmation prompt to the person at the terminal; under
  `bypassPermissions`, an existing allow rule, or a non-interactive/headless run, it silently
  proceeds — full fail-open.

**Contrast with Codex** (`docs/codex-integration.md` §"Codex Hook Constraints"): Codex's documented
contract is flatter — "a failed, malformed, or timed-out hook invocation is a non-blocking error;
Codex reports the hook problem and continues the tool call," uniformly, for every failure mode
including timeout. Claude Code's contract is **materially different on the timeout path
specifically**: a crashed/malformed-output hook fails open exactly like Codex (an unconditional
proceed), but a _timed-out_ hook falls through to Claude Code's own permission flow rather than a
flat proceed — which can still put a human in front of the action in an interactive session (a
different, weaker gate than allw's — no second device, no cryptographic binding, and skippable by
`bypassPermissions` — but not a silent bypass). Both hosts share the same underlying residual this
design cannot close from inside the hook process: if the process is killed, hangs before producing
output, or is never started (a bad path in `settings.json`/`hooks.json`), the _governing_ host's
gate is skipped and allw contributes nothing to that call.

This residual is exactly why the [timeout-ordering invariant (issue #52)](https://github.com/mike-north/allw/issues/52)
exists and is enforced twice over, identically for both hooks: the install block pins the hook
`timeout` to `480` seconds (`PINNED_HOOK_TIMEOUT_MS`), and `readConfig` rejects any
`ALLW_TIMEOUT_MS` at or above `420000` ms (`MAX_TIMEOUT_MS`) as a fail-closed `deny` at
config-read time — never a silent clamp. So long as the hook process starts at all, the SDK's own
deadline (plus its bounded per-relay-fetch timeouts, capped by `ALLW_FETCH_TIMEOUT_MS` ≤ `30000` ms)
resolves to an explicit `deny` with 60 seconds of margin before Claude Code's pinned timeout could
ever fire — keeping the "hook times out" bullet above a designed-against edge case, not the common
path.

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
   a permissive mode**; conversely, **an explicit `ask`/`deny` permission _rule_ the user configured
   separately from allw still applies even after allw's hook returns `allow`** ("[h]ook decisions
   don't bypass permission rules. Claude Code evaluates deny and ask rules regardless of what a
   PreToolUse hook returns"). So a hook `allow` can be layered under an additional Claude-Code-level
   prompt the human configured — it is a floor, not a ceiling, on what still requires confirmation.

Two consequences for `allw` specifically:

- Because `allw` only ever emits `allow`/`deny` (never `ask`), it never itself triggers "a hook's
  `ask` forces a permission prompt even in auto mode" — that's a capability the Claude Code contract
  offers hook authors, but `allw`'s v1 design doesn't use it: an approval is either a verified human
  "yes" on the paired device, or the call is denied.
- `allw`'s own `allow` is **not absolute**: a fixed, mode-independent list of actions —
  ["actions no mode auto-approves"](https://code.claude.com/docs/en/permission-modes#actions-no-mode-auto-approves) —
  is never auto-approved by _any_ `PreToolUse` hook `"allow"`, including allw's. This covers an
  explicit user-configured `ask` rule match, the built-in `AskUserQuestion` tool, MCP tools marked
  `requiresUserInteraction`, and `rm`/`rmdir` targeting a critical path. None of these overlap with
  what `allw` v1 gates today (`Bash`, `Edit`/`Write`/`MultiEdit`, `mcp__*`) in a way that changes the
  decision itself, but a human may still see Claude Code's own confirmation on top of an allw
  approval for a critical-path deletion — this is Claude Code's own circuit breaker, not something
  `allw`'s hook can (or should) suppress.

## Claude Code Hook Constraints

This design depends on the current Claude Code hooks contract, checked on 2026-08-23:

- Hook commands receive one JSON object on stdin (event-specific fields plus common fields like
  `cwd`, `permission_mode`, `hook_event_name`) and communicate results through exit codes, stdout,
  and stderr.
- `PreToolUse` fires before a tool call executes and can `allow`/`deny`/`ask`/`defer` it via
  `hookSpecificOutput.permissionDecision`; `deny`/`defer`/`ask` outrank `allow` when multiple
  `PreToolUse` hooks disagree (precedence: `deny` > `defer` > `ask` > `allow`).
- Matcher patterns for `PreToolUse` are evaluated against `tool_name`: a name made only of letters,
  digits, `_`/`-`/spaces/`,`/`|` is an exact-match list; anything else (including a trailing `.*`)
  is an unanchored JavaScript regular expression.
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
