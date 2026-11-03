# `@allw/codex-hook` — Codex PreToolUse approval hook

This package gates Codex `Bash` and MCP tool calls through `allw` before they run. It mirrors the
Claude Code hook's fail-closed behavior but emits Codex's `PreToolUse` hook output shape and uses a
distinct `codex:<hostname>` actor identity.

See [`docs/codex-integration.md`](../../docs/codex-integration.md) for the integration shape,
configuration block, and current Codex hook limitations.

## Install & Configure

Build the local package from the repo root:

```sh
pnpm install
pnpm run build:wasm
pnpm --filter @allw/codex-hook build
```

Pair an approver device with `@allw/approver`, then export the same relay/account environment the
Claude Code hook uses:

```sh
export ALLW_RELAY_URL="https://relay.example"
export ALLW_ACCOUNT_ID="acct_..."
export ALLW_APPROVER_ROOT_KEY="..."
```

Add the hook to `~/.codex/hooks.json` or a trusted project `.codex/hooks.json`:

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

Run `/hooks` in Codex and trust the hook definition. A gated Bash or MCP tool call then blocks on an
allw approval. A verified approval writes **no decision** (empty stdout, exit 0), so Codex's normal
flow continues; denial, timeout, malformed input, or relay failure writes an explicit `deny`. The hook
never emits `permissionDecision: "allow"` — see
[`docs/codex-integration.md`](../../docs/codex-integration.md) §Fail-Open Residual for why.

## Development

```sh
pnpm --filter @allw/codex-hook typecheck
pnpm --filter @allw/codex-hook lint
pnpm --filter @allw/codex-hook test
```
