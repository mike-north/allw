# Codex Approval Gating

Issue #97 adds a Codex-local approval hook that mirrors the Claude Code hook while preserving the
project's Node + WASM local-surface constraint.

## Integration Shape

Codex exposes lifecycle hooks through `~/.codex/hooks.json`, `.codex/hooks.json`, or inline
`[hooks]` tables in `config.toml`. The allw integration uses Codex `PreToolUse`: it is the only
event that fires for **every** matched tool call — independent of the user's `approval_policy`,
`sandbox_mode`, `permission_mode`, or execpolicy `.rules` — and can block that call before it runs.
Codex's `PermissionRequest` event can also block, and its no-decision fallback is safer, but it
runs only inside Codex's approval path and "doesn't run for commands that don't need approval,"
so its coverage is a function of local Codex configuration. That disqualifies it as allw's
enforcement point. See
[Event Choice: `PreToolUse` vs `PermissionRequest`](#event-choice-pretooluse-vs-permissionrequest)
for the re-verified analysis behind this decision.

Recommended hook configuration:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "node /absolute/path/to/packages/codex-hook/dist/cli.js",
            "timeout": 480,
            "statusMessage": "Requesting allw approval"
          }
        ]
      }
    ]
  }
}
```

## Quickstart

This is the Codex-parallel install path for developers who already have a paired allw approver:

1. Build the Node + WASM surfaces:

   ```sh
   pnpm install
   pnpm run build:wasm
   pnpm --filter @allw/codex-hook build
   ```

2. Export the relay and account trust anchor:

   ```sh
   export ALLW_RELAY_URL="https://relay.example"
   export ALLW_ACCOUNT_ID="acct_..."
   export ALLW_APPROVER_ROOT_KEY="..."
   ```

3. Add the `PreToolUse` block above to `~/.codex/hooks.json` or a trusted project
   `.codex/hooks.json`, replacing the command path with the absolute path to
   `packages/codex-hook/dist/cli.js`.

4. Start Codex, run `/hooks`, review the hook, and trust it. Codex skips untrusted non-managed
   hooks by design.

5. Trigger a gated action such as a Bash command, `apply_patch`, or an `mcp__<server>__<tool>`
   call. The hook submits a Codex-scoped approval request (`actor.id = "codex:<hostname>"`), and
   Codex proceeds only after a verified allw approval.

## Human-Run UAT Setup

The real-Codex UAT is intentionally operator-run. The automated/headless attempt triggered macOS
malware detection on the local Codex binary, so repository automation must prepare the environment
but must not spawn Codex.

Use the helper from the repo root:

```sh
scripts/uat-codex.sh
```

The script builds the WASM and TypeScript packages, starts a local relay, pairs a temporary
`allw-approver` keyfile, and then writes a self-contained temporary project to a system temp
directory. The project contains:

- `.codex/allw-hook.sh` — a small wrapper script that `export`s the three `ALLW_*` env vars
  (relay URL, account ID, approver root key) baked in at generation time, then `exec`s the hook
  CLI. The Codex command-hook schema has no per-handler `env` field, so the variables are baked
  into the wrapper rather than placed in `hooks.json`.
- `.codex/hooks.json` — the project-scoped Codex hook config; its `"command"` field invokes the
  wrapper via `bash <abs-path>/allw-hook.sh`. No manual `export` step is needed.

The helper prints the exact `codex exec` commands for the operator to run in a second terminal,
then runs `allw-approver watch` in the foreground. It never touches `~/.codex` global config
and never invokes `codex`; the human runs Codex directly.

When UAT is complete, press `Ctrl-C` in the script terminal. Its exit trap stops the relay and
removes the temporary keyfile/project.

## UAT Checklist

Run a live Codex session against the temporary project prepared by `scripts/uat-codex.sh` and
record the result on issue #97:

1. **Approve path**: ask Codex to run a harmless gated Bash command, approve it on the second
   device, and confirm Codex proceeds.
2. **Deny path**: ask Codex to run another gated Bash command, deny it on the second device, and
   confirm Codex receives `permissionDecision: "deny"` and does not run the tool.
3. **Timeout path**: set a short `ALLW_TIMEOUT_MS`, leave the approval unanswered, and confirm
   Codex denies before its 480 second hook timeout.
4. **Actor identity**: confirm the approval inbox shows the request as `codex:<hostname>` rather
   than the Claude Code actor.
5. **File-edit path**: ask Codex for a simple file edit through `apply_patch` and confirm the hook
   gates the resulting `file_edit` action with the target path, summary, and diff hash visible.

> **Known defect affecting step 2.** The deny path is expected to FAIL until
> [#191](https://github.com/mike-north/allw/issues/191) lands: the hook emits an undocumented
> `denyReason` field that Codex rejects, so the deny is discarded and the command runs. Record the
> observed behavior rather than skipping the step — it is the acceptance proof for that fix. See
> [Fail-Open Residual](#fail-open-residual).

Use this comment template on #97:

```md
Approve: PASS/FAIL - command ran only after approval
Deny: PASS/FAIL - command was blocked after denial
Timeout: PASS/FAIL - command failed closed after ALLW_TIMEOUT_MS
Actor identity: PASS/FAIL - inbox showed codex:<hostname>
File edit: PASS/FAIL - apply_patch was gated with path, summary, and diff hash
Notes:
```

The automated tests cover the same SDK/WASM verification path with a relay double; this checklist
is the remaining product acceptance proof that Codex itself invokes the hook and honors the result.

The matcher intentionally matches the hook's v1 surfaces:

- `Bash` commands are converted to command `ActionRecord`s through the WASM core.
- `apply_patch` calls are converted to file-edit `ActionRecord`s through the WASM core.
- `mcp__<server>__<tool>` calls are converted to MCP `ActionRecord`s through the WASM core.
- Other Codex tools pass through when they do not map to a supported allw approval surface.

## Decision Mapping

The hook reads the same allw environment as the Claude Code hook:

| Variable                 | Required | Meaning                                                       |
| ------------------------ | -------- | ------------------------------------------------------------- |
| `ALLW_RELAY_URL`         | yes      | Base URL of the zero-knowledge relay.                         |
| `ALLW_ACCOUNT_ID`        | yes      | The approver's relay account id.                              |
| `ALLW_APPROVER_ROOT_KEY` | yes      | The approver account-root Ed25519 public key.                 |
| `ALLW_TIMEOUT_MS`        | no       | Fail-closed approval deadline in ms, capped below hook time.  |
| `ALLW_FETCH_TIMEOUT_MS`  | no       | Per-relay-fetch timeout in ms, only allowed to lower the cap. |

For gated calls, the hook builds the syntactic `ActionRecord`, requests approval through
`@allw/sdk`, and returns Codex's `hookSpecificOutput.permissionDecision`:

| allw result                              | Codex decision | `hookSpecificOutput.denyReason` |
| ---------------------------------------- | -------------- | ------------------------------- |
| verified verdict `decision === approved` | `allow`        | _(absent)_                      |
| verified verdict `decision === denied`   | `deny`         | `no-approval`                   |
| verified verdict `decision === expired`  | `deny`         | `timeout`                       |
| verified verdict `decision === aborted`  | `deny`         | `aborted`                       |
| malformed gated input / ActionRecord     | `deny`         | `build-error`                   |
| missing or invalid allw config           | `deny`         | `config-error`                  |
| relay/network/approval error             | `deny`         | `transport-error`               |
| malformed hook stdin                     | `deny`         | `input-parse-error`             |
| non-gated tool                           | `allow`        | _(absent)_                      |

On deny decisions, `denyReason` carries a machine-readable category so operators can distinguish
why the hook blocked an action without parsing the human-readable `permissionDecisionReason` string.

> **Defect — `denyReason` is not a Codex field.** The 2026-08-23 re-verification found that
> `denyReason` is outside Codex's documented `PreToolUse` output contract, and that Codex rejects
> unknown fields inside `hookSpecificOutput`. On the current implementation that makes the entire
> deny payload unparseable, which Codex reports as a hook error and then **continues the tool
> call**. The table above describes what the hook emits today, not a shape that works. See
> [Fail-Open Residual](#fail-open-residual) and
> [#191](https://github.com/mike-north/allw/issues/191); the emitted shape changes there, not here.

The actor is distinct from the Claude Code hook: Codex requests use `actor.kind = "codex"` and
`actor.id = "codex:<hostname>"`, so a single allw inbox can distinguish "Claude Code on devbox-1"
from "Codex on devbox-1".

## Event Choice: `PreToolUse` vs `PermissionRequest`

Re-verified against the Codex docs on **2026-08-23** (issue
[#179](https://github.com/mike-north/allw/issues/179)). The 2026-06-12 check predated Codex's
`PermissionRequest` hook event and the granular `approval_policy`, so the justification for
`PreToolUse` had to be re-derived rather than re-asserted.

### What `PermissionRequest` actually is

| Property                       | Verified behavior                                                                                                                                                               |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| When it runs                   | "Runs when Codex is about to ask for approval, such as a shell escalation or managed-network approval… **It doesn't run for commands that don't need approval.**"               |
| `matcher`                      | Matches `tool_name` and aliases — `Bash`, `apply_patch` (also `Edit` / `Write`), and `mcp__<server>__<tool>`. Same vocabulary as `PreToolUse`.                                  |
| Output shape                   | `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"\|"deny","message":"…"}}}`. `exit 2` + a stderr reason is an equivalent deny channel. |
| Folding across hooks           | Any `deny` wins; otherwise an `allow` lets the request proceed **without surfacing the approval prompt**.                                                                       |
| No decision                    | "If no matching hook decides, Codex uses the normal approval flow." A crashed, killed, timed-out, or malformed handler produces no decision and therefore falls into this case. |
| Reserved fields                | `updatedInput`, `updatedPermissions`, and `interrupt` are reserved and **fail closed** today.                                                                                   |
| Position in the approval chain | Runs in the approval path **before** the auto-review reviewer agent or the user approval UI is shown.                                                                           |

The last two rows come from the open-source implementation
([`codex-rs/hooks/src/events/permission_request.rs`](https://github.com/openai/codex/blob/main/codex-rs/hooks/src/events/permission_request.rs)
and the generated `permission-request.command.output` schema) as a cross-check on the docs page,
which is the release-behavior reference.

### The options

| Option                                  | Coverage                                                                                               | Behavior when the handler dies                                                   | Verdict                                                     |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| **(a) `PreToolUse` only** _(current)_   | Every matched tool call, independent of `approval_policy`, `sandbox_mode`, `permission_mode`, `.rules` | Hook error → **the tool call proceeds**                                          | **Chosen**                                                  |
| **(b) `PermissionRequest` only**        | Only actions Codex already decided to ask about — a function of the user's local config                | No decision → Codex's own approval flow (local prompt, or the auto-review agent) | Rejected: coverage is not ours to guarantee                 |
| **(c) Dual-home, `allow` on both**      | Union of (a) and (b)                                                                                   | Mixed                                                                            | Rejected: a `PermissionRequest` `allow` widens, see below   |
| **(c′) Dual-home, deny-only companion** | Union of (a) and (b), tightening-only                                                                  | No decision → Codex's own approval flow                                          | Deferred: no enforcement value today, real correlation cost |

### Decision: stay on `PreToolUse` only

**Coverage is the load-bearing property, and only `PreToolUse` has coverage allw controls.**
`PermissionRequest` fires only when Codex was already going to ask. Under the default
`workspace-write` sandbox most commands run inside the sandbox with no approval step at all, and
under `approval_policy = "never"` there are no approval prompts to hook. A gate whose reach shrinks
silently when the user edits `config.toml` is not an approval primitive — it is a suggestion. This
is the same conclusion the 2026-06-12 check reached, but it now rests on the current docs rather
than on an event that has since changed shape.

**`PermissionRequest`'s failure semantics really are better, and that still does not win.** This is
the one place where the older doc understated the alternative: a dead `PreToolUse` handler lets the
tool run unattended, whereas a dead `PermissionRequest` handler falls back to Codex's _normal
approval flow_ — a local prompt (or the auto-review agent), never silent execution. Moving events
would trade a smaller residual for a coverage hole whose size is set by someone else's config. We
take the residual and shrink it by other means (see [Fail-Open Residual](#fail-open-residual)).

**Emitting `allow` on `PermissionRequest` would violate the contract.** A `PermissionRequest`
`allow` "lets the request proceed without surfacing the approval prompt" — it _removes_ a gate that
would otherwise have run. `docs/contract.md` §6 is explicit that the primitive never returns
"allow" and that a verdict may only **tighten**. Using an allw approval to suppress Codex's own
approval prompt is a widening, and it is disallowed regardless of how convenient the
double-prompt cleanup would be. If allw is ever dual-homed, the `PermissionRequest` handler may
emit `deny` and nothing else.

**A deny-only companion is permitted but currently pointless.** Anything that reaches
`PermissionRequest` as a tool call has already passed (or will pass) the `PreToolUse` gate, so a
deny-only handler adds no enforcement. The categories `PreToolUse` cannot see — MCP elicitations,
`request_permissions` grants, skill-script approvals — are better handled at the config layer,
where Codex already auto-rejects them (see the next section). Deny-only dual-homing is worth
revisiting only if Codex adds a _tool-call_ approval category that bypasses the `PreToolUse` path.

**Correlation cost, for the record.** `PermissionRequest` input carries `session_id`, `turn_id`,
`tool_name`, and `tool_input` — but **no `tool_use_id`** (`PreToolUse` has one). Any dual-homed
design would have to correlate the two events by hashing canonicalized `tool_input`, and would
need the two events' relative ordering, which is not documented. That ordering question is filed
in [#192](https://github.com/mike-north/allw/issues/192) as a UAT item.

### Revisit this decision if

- `PermissionRequest` gains a "fires for every tool call" mode, or `approval_policy` gains a mode
  that guarantees every tool call raises an approval request.
- `PreToolUse`'s failure handling changes from "report and continue" to "report and block".
- Codex adds an approval category that runs tool-equivalent side effects without a `PreToolUse`
  event.

## Approval Policy, Auto-Review, and execpolicy `.rules`

Three Codex mechanisms sit near the allw gate. None of them can weaken it; two of them need
configuration to stay fail-closed.

### Granular `approval_policy`

`approval_policy` is now `untrusted | on-request | never | { granular = { … } }`. The older
`suggest` / `auto-edit` / `full-auto` vocabulary is no longer part of that enumeration
(`on-failure` is deprecated in favor of `on-request`, and `codex exec --full-auto` survives only as
a deprecated compatibility flag that prints a warning). The granular form takes five booleans — `sandbox_approval`, `rules`,
`mcp_elicitations`, `request_permissions`, `skill_approval` — and each means "prompts in this
category are **allowed to surface**." Setting one to `false` **auto-rejects** that category. The
granular policy is therefore fail-closed by construction and aligns with `docs/contract.md` §7.

Because `PreToolUse` sees tool calls and nothing else, three categories are structurally invisible
to the allw hook: MCP elicitations (server-initiated), `request_permissions` grants (permission
widening rather than a tool call), and skill-script approvals. The config layer, not a second hook,
is the right answer for those:

```toml
approval_policy = { granular = {
  sandbox_approval    = true,   # second gate after allw; can only tighten
  rules               = true,   # execpolicy `prompt` rules stay interactive
  mcp_elicitations    = false,  # invisible to the allw hook -> auto-reject
  request_permissions = false,  # permission widening the hook cannot see -> auto-reject
  skill_approval      = false,  # auto-reject
} }
approvals_reviewer = "user"
```

Wiring this posture into the generated UAT project is tracked in
[#192](https://github.com/mike-north/allw/issues/192).

### `approvals_reviewer = "auto_review"`

`approvals_reviewer` selects who reviews _Codex's own_ approval prompts: `user` (default) or
`auto_review`, a reviewer subagent. It **cannot** weaken the allw gate, because that gate is a
`PreToolUse` hook that runs whether or not Codex raises an approval request at all. When
auto-review is enabled it replaces the _second_, Codex-side gate with a model — and since every
gate is an `∧` term (`docs/contract.md` §6), a model that can only deny is a tightening.

One correction to an earlier assumption: `request_permissions` prompts are **not** exempt from
auto-review. The docs list them among what the reviewer evaluates; the only category that always
surfaces directly to the user is Computer Use app approval. This does not change the decision
above — under `PreToolUse` the allw gate is upstream of the reviewer either way — but it does mean
"a human always sees `request_permissions`" is not a property to rely on. Auto-rejecting that
category (above) is the property to rely on.

### execpolicy `.rules`

`.rules` files (Starlark `prefix_rule`) decide whether a command may run **outside the sandbox**,
with `decision` in `allow | prompt | forbidden` and most-restrictive-wins across matching rules.
Their interaction with the allw gate:

| `.rules` decision | Codex behavior                                | Effect on the allw gate                                                                       |
| ----------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `allow`           | Runs outside the sandbox without prompting    | **No hole.** `PreToolUse` still fires for the tool call; the allw approval is still required. |
| `prompt`          | Codex prompts before each matching invocation | Redundant second gate — a **double prompt** (allw on the second device, then Codex locally).  |
| `forbidden`       | Blocked without prompting                     | Tightening: an allw-approved command can still be refused. Correct per `docs/contract.md` §6. |

The `allow` row is the reason this section exists. If allw had moved to `PermissionRequest`, a
`.rules` `allow` — including one Codex itself proposes during an escalation, or one the TUI writes
to `~/.codex/rules/default.rules` when the user picks "always allow" — would suppress the approval
request and therefore the allw gate with it. On `PreToolUse` that path is closed.

Double-prompting under `prompt` rules is a real UX cost and is the honest price of refusing to
emit `PermissionRequest` `allow`. `approval_policy.granular.rules = false` converts it into an
auto-reject instead, which is fail-closed but blunt. The ordering of the two prompts is not
documented and is a UAT item in [#192](https://github.com/mike-north/allw/issues/192).

## Fail-Open Residual

Re-analyzed 2026-08-23 against the current surface. **The residual is larger than previously
documented** — not because the event choice changed, but because two of the hook's own output
paths turn out to land inside it.

### Structural residual (unchanged, inherent to `PreToolUse`)

Codex reports a failed, malformed, or timed-out command hook as a non-blocking error and continues
the tool call. So allw's fail-closed behavior depends on the hook process starting and returning an
explicit, well-formed `deny` before Codex's pinned 480 second hook timeout:

- Process never starts (missing `node`, bad path, unresolvable bin, `PATH` differences under the
  Codex launch environment).
- Process is killed externally (SIGKILL, OOM) before writing stdout.
- Codex's own hook timeout elapses. This is the timeout-ordering invariant from
  [#52](https://github.com/mike-north/allw/issues/52): `ALLW_TIMEOUT_MS` must stay below the pinned
  hook timeout so the SDK reaches a verified approval or explicit denial first.
- Hooks are disabled or never trusted: `[features] hooks = false`, a hook left un-trusted in
  `/hooks`, or an enterprise `allow_managed_hooks_only = true` that skips user and project hooks.
- The handler is misconfigured as `"async": true`. Background hooks "can't block, approve, rewrite,
  or otherwise control the operation that triggered them" — the gate silently becomes advisory.
  **Never set `async` on the allw handler.**

The CLI catch-all still converts internal throws into a `deny`, so in-process failures are covered.

### Implementation residual (new, and fixable)

1. **Every deny is currently dropped.** `hookSpecificOutput.denyReason` is not part of Codex's
   `PreToolUse` output contract, and Codex rejects unknown fields inside that object, so the whole
   payload fails to parse and the tool call continues. This is the single largest gap on this
   surface: today the deny path is _inside_ the fail-open set rather than outside it. Fixed in
   [#191](https://github.com/mike-north/allw/issues/191).
2. **Deny without a reason degrades to fail-open.** `permissionDecision: "deny"` requires a
   non-empty `permissionDecisionReason`; an empty one is treated as an invalid decision, i.e. a
   hook error, i.e. proceed. Also covered by [#191](https://github.com/mike-north/allw/issues/191).
3. **`allow` is not the right encoding of an approval.** A bare `permissionDecision: "allow"`
   without `updatedInput` is an unsupported decision that Codex reports as a hook failure (the
   tool then proceeds, which is the intended outcome, so this is noise rather than risk). The
   correct encoding of "allw did not block" is **empty stdout and exit 0** — which is also the
   encoding `docs/contract.md` §6 requires, since the primitive never returns "allow."

### What is _not_ residual

- `approvals_reviewer = "auto_review"` — a second, downstream gate; can only tighten.
- `.rules` `allow` — does not suppress `PreToolUse`.
- `approval_policy = "never"` / `granular` with categories set to `false` — auto-rejects; tightening.
- `permission_mode` (`dontAsk`, `bypassPermissions`) — Codex reports the mode to the hook rather
  than skipping it. Worth confirming empirically; it is a UAT item in
  [#192](https://github.com/mike-north/allw/issues/192).

## Codex Hook Constraints

This design depends on the OpenAI Codex hooks contract, re-checked on **2026-08-23** (previously
checked 2026-06-12):

- Hook commands receive one JSON object on stdin and may return JSON on stdout. Exit 0 with no
  output is a clean success.
- **Only `type: "command"` handlers execute.** `prompt` and `agent` handler types are parsed from
  config and skipped — so the allw handler must stay a command handler, and a `prompt`/`agent`
  handler is never a fallback.
- `PreToolUse` can intercept Bash / unified exec, `apply_patch` (aliases `Edit`, `Write`), MCP tool
  calls, and other local function tools. Hosted tools such as `WebSearch` do not use the local
  function-tool hook path. The docs describe tool hooks as "a useful guardrail, not a complete
  enforcement boundary."
- A failed, malformed, or timed-out hook invocation is a non-blocking error: Codex reports the hook
  problem and continues the tool call.
- `PreToolUse` output supports `permissionDecision` (`allow` with `updatedInput`, or `deny` with a
  non-empty `permissionDecisionReason`), `additionalContext`, and `systemMessage`. `ask`, legacy
  `decision: "approve"`, `continue`, `stopReason`, and `suppressOutput` are parsed but unsupported
  and are reported as hook failures. Unknown fields are rejected.
- Matching command hooks can run concurrently, and multiple hook sources all load; higher-precedence
  config layers do not replace lower-precedence hooks.
- Non-managed hooks must be reviewed and trusted with `/hooks` before Codex runs them. Trust is
  recorded against the hook definition's hash, so changing the `command` string re-arms review.
- Enterprise deployments can pin the handler as a **managed** hook from `requirements.toml`
  (with `[features].hooks = true`), which cannot be disabled from the user hook browser. That is
  the deployment shape for making the allw gate non-optional on a fleet.
- Hook `timeout` is in seconds and defaults to 600; allw pins 480 seconds so the SDK deadline wins
  before Codex can time the hook out.
- `async: true` makes a handler advisory — it cannot block. The allw handler must never set it.
- Oversized hook output is spilled to `<temp_dir>/hook_outputs/<session_id>/<uuid>.txt`, so hook
  output must never carry plaintext action data. allw's reason strings are categories and
  human-readable summaries, never the `ActionRecord` payload.
- `notify` fires only for `agent-turn-complete`; it never fires for approval requests. No part of
  this integration may be built on `notify`.

Sources (all re-checked 2026-08-23):

- Codex hooks: <https://learn.chatgpt.com/docs/hooks>
  (the former <https://developers.openai.com/codex/hooks> now redirects here).
- Configuration reference (`approval_policy`, `approvals_reviewer`, `notify`):
  <https://learn.chatgpt.com/docs/config-file/config-reference>
- Advanced configuration (`notify` events): <https://learn.chatgpt.com/docs/config-file/config-advanced>
- Agent approvals & security (granular policy, auto-review): <https://learn.chatgpt.com/docs/agent-approvals-security>
- Auto-review lifecycle: <https://learn.chatgpt.com/docs/sandboxing/auto-review>
- execpolicy rules: <https://learn.chatgpt.com/docs/agent-configuration/rules>
- Cross-checks against the open-source implementation: <https://github.com/openai/codex/tree/main/codex-rs/hooks>
  (the docs note that `main`-branch schemas may include fields absent from the current release, so
  the docs page is the release-behavior reference and the source is corroboration only).

## Codex Hook Constraints

This design depends on the current OpenAI Codex hooks contract, checked on 2026-06-12:

- Hook commands receive one JSON object on stdin and may return JSON on stdout.
- `PreToolUse` can intercept Bash, `apply_patch`, and MCP tool calls, but the docs describe it as a
  guardrail rather than a complete enforcement boundary.
- A failed, malformed, or timed-out hook invocation is a non-blocking error; Codex reports the hook
  problem and continues the tool call.
- Matching command hooks can run concurrently, and multiple hook sources all load.
- Non-managed hooks must be reviewed and trusted with `/hooks` before Codex runs them.
- Hook `timeout` is in seconds and defaults to 600; allw pins 480 seconds so the SDK deadline wins
  before Codex can time the hook out.

Source: OpenAI Codex hooks docs, <https://developers.openai.com/codex/hooks>.
