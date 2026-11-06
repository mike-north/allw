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
`ALLW_CONFIG` moves it (an absolute path; a leading `~/` is expanded).

The SDK encrypts each request only to the devices your account root vouches for in signed account
state (`GET /{acct}/account-states`), never to the relay's device list, so a relay that lists a key it
holds cannot read the request (`docs/enrollment.md` §Model, #243). `allw-approver pair` publishes that
state. If the relay has none, the call is denied with an error naming `allw-approver pair`; a state that does not verify is denied too. Each machine records the highest account-state sequence it has accepted in
`~/.allw/state/<account-id>.floor.json` (`0600` in a `0700` directory) before sending, and denies a
request when the relay serves an older state. A floor file that is unreadable, corrupt, or not owned
by you also denies; delete it only if you know why it is wrong.

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

Use the absolute path to `dist/cli.js`, or `npx --no-install allw-codex-hook`. Never plain
`npx allw-codex-hook`: when no installed bin resolves, plain `npx` downloads and runs the registry
package of that name, so a squatted package would run as the gate; `--no-install` exits 1 instead.

If Codex can't start the hook (a wrong path, `node` missing from `PATH`, the package not
installed), **the tool call goes ahead ungated**: Codex reports the hook as failed and continues, and
it has no setting to block on hook failure. After wiring the hook, run one gated call and confirm it
reaches your approver. See
[`docs/codex-integration.md`](../../docs/codex-integration.md#if-the-hook-cant-start).

Run `/hooks` in Codex and trust the hook definition. A gated Bash or MCP tool call then blocks on an
allw approval. A verified approval writes **no decision** (empty stdout, exit 0), so Codex's normal
flow continues; denial, timeout, malformed input, or relay failure writes an explicit `deny`. The hook
never emits `permissionDecision: "allow"` — see
[`docs/codex-integration.md`](../../docs/codex-integration.md) §Fail-Open Residual for why.

Empty/whitespace-only `Bash` command text is denied without asking. Every nonblank line is opaque
caller text: comments, assignments, operators, substitutions and unmatched quotes are carried
verbatim without inferred argv or program identity. A blank cwd counts as unknown; the request is
still sent, bound to no directory. Malformed input and core build errors still deny.

## Development

```sh
pnpm run build:wasm                          # once, from the repo root
pnpm --filter "@allw/codex-hook..." build    # this package and its workspace deps
pnpm --filter @allw/codex-hook typecheck
pnpm --filter @allw/codex-hook lint
pnpm --filter @allw/codex-hook test
```
