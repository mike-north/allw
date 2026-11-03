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

Pair an approver device with `@allw/approver`, then write the same integrator config file the
Claude Code hook uses, `~/.allw/config.json` (`0600`; see `docs/quickstart.md` §4):

```json
{
  "version": 1,
  "relay_url": "https://relay.example",
  "account_id": "<account id from pair>",
  "approver_root_key": "<account-root public key from pair>"
}
```

`ALLW_RELAY_URL`, `ALLW_ACCOUNT_ID`, and `ALLW_APPROVER_ROOT_KEY` override the file per field;
`ALLW_CONFIG` moves it.

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
allw approval; a verified approval returns Codex `allow`, while denial, timeout, malformed input, or
relay failure returns `deny`.

## Development

```sh
pnpm --filter @allw/codex-hook typecheck
pnpm --filter @allw/codex-hook lint
pnpm --filter @allw/codex-hook test
```
