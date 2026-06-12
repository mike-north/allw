# `@allw/codex-hook` — Codex PreToolUse approval hook

This package gates Codex `Bash` and MCP tool calls through `allw` before they run. It mirrors the
Claude Code hook's fail-closed behavior but emits Codex's `PreToolUse` hook output shape and uses a
distinct `codex:<hostname>` actor identity.

See [`docs/codex-integration.md`](../../docs/codex-integration.md) for the integration shape,
configuration block, and current Codex hook limitations.

## Development

```sh
pnpm --filter @allw/codex-hook typecheck
pnpm --filter @allw/codex-hook lint
pnpm --filter @allw/codex-hook test
```
