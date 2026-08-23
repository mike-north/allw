# Codex Approval Gating

Issue #97 adds a Codex-local approval hook that mirrors the Claude Code hook while preserving the
project's Node + WASM local-surface constraint. For the Claude Code hook's own structural peer of
this document, see [`docs/claude-code-integration.md`](./claude-code-integration.md).

## Integration Shape

Codex exposes lifecycle hooks through `~/.codex/hooks.json`, `.codex/hooks.json`, or inline
`[hooks]` tables in `config.toml`. The allw integration uses Codex `PreToolUse` because that is the
only current hook event that can block a supported tool before it runs. Codex's `PermissionRequest`
event only fires when Codex was already going to ask for approval, so it cannot enforce a uniform
allw approval gate over every sensitive action.

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
The deny decision itself is unaffected — fail-closed semantics are unchanged.

Codex itself fails open if a command hook fails to emit a well-formed, exit-0
`permissionDecision`: startup failure, malformed stdout, process crash, SIGKILL, or Codex's hook
timeout are reported as hook errors and the tool call continues. allw's fail-closed behavior
therefore depends on the hook process starting and returning an explicit `deny` before Codex's
pinned 480 second timeout. The CLI catch-all covers internal throws by emitting `deny`; startup
failures, external kills, and process death before stdout remain unavoidable residual fail-open
cases. This is the same timeout-ordering invariant documented for
[#52](https://github.com/mike-north/allw/issues/52): `ALLW_TIMEOUT_MS` must stay below the pinned
hook timeout so the SDK reaches a verified approval or explicit denial first.

The actor is distinct from the Claude Code hook: Codex requests use `actor.kind = "codex"` and
`actor.id = "codex:<hostname>"`, so a single allw inbox can distinguish "Claude Code on devbox-1"
from "Codex on devbox-1".

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
