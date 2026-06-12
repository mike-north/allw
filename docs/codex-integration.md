# Codex Approval Gating

Issue #97 adds a Codex-local approval hook that mirrors the Claude Code hook while preserving the
project's Node + WASM local-surface constraint.

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
        "matcher": "Bash|mcp__.*",
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

5. Trigger a gated action such as a Bash command or `mcp__<server>__<tool>` call. The hook submits
   a Codex-scoped approval request (`actor.id = "codex:<hostname>"`), and Codex proceeds only after
   a verified allw approval.

The matcher intentionally matches the Claude Code hook's v1 surface:

- `Bash` commands are converted to command `ActionRecord`s through the WASM core.
- `mcp__<server>__<tool>` calls are converted to MCP `ActionRecord`s through the WASM core.
- Other Codex tools pass through for now.

Codex can also expose `apply_patch` through `PreToolUse`, but allw does not yet have a core
`ActionRecord` surface for file edits. Gating it in this slice would either duplicate policy in
TypeScript or build an ambiguous record, so this package documents the limitation instead of
pretending file edits are covered.

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

| allw result                              | Codex decision |
| ---------------------------------------- | -------------- |
| verified verdict `decision === approved` | `allow`        |
| verified `denied`, `expired`, `aborted`  | `deny`         |
| malformed gated input                    | `deny`         |
| missing or invalid allw config           | `deny`         |
| relay/network/approval error             | `deny`         |
| non-gated tool                           | `allow`        |

The actor is distinct from the Claude Code hook: Codex requests use `actor.kind = "codex"` and
`actor.id = "codex:<hostname>"`, so a single allw inbox can distinguish "Claude Code on devbox-1"
from "Codex on devbox-1".

## Codex Hook Constraints

This design depends on the current OpenAI Codex hooks contract, checked on 2026-06-12:

- Hook commands receive one JSON object on stdin and may return JSON on stdout.
- `PreToolUse` can intercept Bash, `apply_patch`, and MCP tool calls, but the docs describe it as a
  guardrail rather than a complete enforcement boundary.
- Matching command hooks can run concurrently, and multiple hook sources all load.
- Non-managed hooks must be reviewed and trusted with `/hooks` before Codex runs them.
- Hook `timeout` is in seconds and defaults to 600; allw pins 480 seconds so the SDK deadline wins
  before Codex can time the hook out.

Source: OpenAI Codex hooks docs, <https://developers.openai.com/codex/hooks>.
