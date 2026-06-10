# `@allw/hook` — Claude Code permission hook (Node + WASM)

The first real `allw` integrator: a [Claude Code **PreToolUse** hook](https://code.claude.com/docs/en/hooks)
that turns a pending sensitive operation into a **phone approval**. When Claude Code is about to run a
gated tool call, the hook builds an `ActionRecord` from it, requests a human decision over the
zero-knowledge relay (via [`@allw/sdk`](../sdk)), and lets the call proceed **only** on a verified
human approval. Everything else — a human "no", a timeout, missing configuration, any error — blocks
the call. This is the v1 beachhead: one inbox where a human approves or denies what their agents do.

## Runs entirely under Node + WASM (a hard constraint)

The hook is a `node` entrypoint over the same audited Rust core the rest of `allw` uses, compiled to
**WebAssembly** — never a standalone native binary. This is deliberate: enterprise binary
allow-listing (Google Santa) and MDM cannot block a `node` invocation the way they block an unsigned
executable, so the local approval surface stays installable. All `ActionRecord` construction goes
through the WASM core, and all crypto goes through `@allw/sdk` (which loads the same `.wasm`). The
hook reimplements none of it. See [`docs/architecture.md`](../../docs/architecture.md).

## Install & configure

The hook reads its configuration from the environment, so there is no config file of its own:

| Variable                 | Required | Meaning                                                    |
| ------------------------ | -------- | ---------------------------------------------------------- |
| `ALLW_RELAY_URL`         | yes      | Base URL of the zero-knowledge relay.                      |
| `ALLW_ACCOUNT_ID`        | yes      | The approver's relay account id (routes to their devices). |
| `ALLW_APPROVER_ROOT_KEY` | yes      | The approver account-root Ed25519 public key (base64url).  |
| `ALLW_TIMEOUT_MS`        | no       | Fail-closed deadline in ms (default `300000` = 5 minutes). |

Pair an approver device first (e.g. with [`@allw/approver`](../approver)) to obtain the account id and
the account-root public key.

Wire the hook into your project's (or user's) `.claude/settings.json` as a `PreToolUse` hook. The
matcher selects which tools `allw` gates — `Bash` for shell commands and `mcp__.*` for any MCP tool
call:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "node /absolute/path/to/packages/hook/dist/cli.js"
          }
        ]
      }
    ]
  }
}
```

> Use an absolute path to `dist/cli.js` (or the resolved `allw-hook` bin). The `command` is run under
> `node`; there is no native binary to sign or allow-list.

The hook is built with the workspace and depends on the vendored WASM core. From the repo root:

```sh
pnpm run build:wasm                # builds the vendored .wasm the hook + SDK load
pnpm --filter @allw/sdk build      # the hook depends on @allw/sdk's dist
pnpm --filter @allw/hook build     # compiles dist/cli.js (the bin)
```

## The contract: input, output, decision

The hook implements the Claude Code PreToolUse wire contract verbatim.

**stdin** (the pending tool call):

```jsonc
{
  "hook_event_name": "PreToolUse",
  "cwd": "/abs/path",
  "tool_name": "Bash", // or "mcp__<server>__<tool>"
  "tool_input": { "command": "rm -rf build" }, // tool-specific
}
```

**stdout** (the permission decision; the hook exits 0):

```jsonc
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow", // or "deny"
    "permissionDecisionReason": "allw: …",
  },
}
```

`allw` only ever emits `allow` (a verified human approval, or a non-gated pass-through) or `deny`
(everything else). It never emits `ask`. The hook always exits `0` with a parseable decision — it
speaks in decisions, not error codes.

## What is gated (v0)

Deliberately conservative, so the human is only interrupted for actions that actually run side
effects:

- **`Bash`** — a shell command (`tool_input.command`).
- **`mcp__<server>__<tool>`** — any MCP tool call (`tool_input` is the raw params object).
- **everything else** (`Read`, `Edit`, `Write`, `Glob`, `Grep`, `WebFetch`, …) — **not gated**; it
  passes through as `allow` without bothering the human (and without needing any `allw` config).

Widening the matcher later is an additive change.

## Fail-closed (contract §Invariants #6)

The primitive never returns a bare "allow"; the hook composes it. Every uncertain path blocks:

| Situation                                                    | Decision               |
| ------------------------------------------------------------ | ---------------------- |
| Not a gated tool                                             | `allow` (pass-through) |
| Gated, verified verdict `decision === "approved"`            | `allow`                |
| Gated, verified human `denied` / `expired` / `aborted`       | `deny`                 |
| Gated, request timed out (no response by the deadline)       | `deny`                 |
| Gated, the `ActionRecord` could not be built                 | `deny`                 |
| Gated, the approval request threw (network/relay/no devices) | `deny`                 |
| Malformed hook stdin (not JSON, wrong event, …)              | `deny`                 |
| Missing/invalid configuration                                | `deny`                 |
| Any unexpected internal error                                | `deny`                 |

A verdict is `allow` **only** when it is delivered, cryptographically verified against the approver's
account-root key, bound to this exact request (WYSIWYS), fresh, and a human "yes". The verification
itself lives in the audited core; the hook just maps the verified result onto the Claude Code
decision.

## Development

```sh
pnpm --filter @allw/hook typecheck
pnpm --filter @allw/hook lint
pnpm --filter @allw/hook test    # requires `pnpm run build:wasm` + the dist build first
```
