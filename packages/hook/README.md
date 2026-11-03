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

The hook reads the relay coordinates and the approver trust anchor through the shared
[`@allw/sdk`](../sdk) `loadClientConfig` loader: **one non-secret config file**,
`~/.allw/config.json` (moved with `ALLW_CONFIG`), with per-field env-var overrides (env wins):

```json
{
  "version": 1,
  "relay_url": "https://relay.example.com",
  "account_id": "<account id printed by allw-approver pair>",
  "approver_root_key": "<account-root public key printed by allw-approver pair>"
}
```

Keep it `0600` in a `0700` `~/.allw`: it holds no secrets, but `approver_root_key` is your trust
anchor — whoever can rewrite it can redirect approvals. On POSIX the loader enforces this on read:
a file not owned by you, or group- or world-writable, is rejected (fix with `chmod 600`), as is
anything that is not a regular file (a FIFO, device, directory) or is over 64 KiB.

| Variable                 | Required | Meaning                                                                                                                                                                                                                                            |
| ------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLW_CONFIG`            | no       | Config-file path (default `~/.allw/config.json`). When set, the file must exist and the path must be an **absolute** path (a leading `~/` is expanded; a relative path is rejected, since it would resolve against the agent's working directory). |
| `ALLW_RELAY_URL`         | no       | Overrides `relay_url`: base URL of the zero-knowledge relay.                                                                                                                                                                                       |
| `ALLW_ACCOUNT_ID`        | no       | Overrides `account_id`: the approver's self-certifying relay account id (must derive from the root key).                                                                                                                                           |
| `ALLW_APPROVER_ROOT_KEY` | no       | Overrides `approver_root_key`: the approver account-root Ed25519 public key (base64url-unpadded, 32 bytes).                                                                                                                                        |
| `ALLW_TIMEOUT_MS`        | no       | Fail-closed deadline in ms (default `300000` = 5 minutes; must be **below `420000`** — see [the timeout-ordering invariant](#the-timeout-ordering-invariant-issue-52)).                                                                            |
| `ALLW_FETCH_TIMEOUT_MS`  | no       | Per-relay-fetch timeout in ms (default/max `30000`); may lower the SDK default for faster fail-closed decisions, but may not raise it.                                                                                                             |

Each of `relay_url`, `account_id`, `approver_root_key` must come from the file or its env override.
With neither, or with a malformed/unknown-version/incomplete file, a malformed root key, or an
account id that does not derive from the root key, every gated call is **denied** with a reason
naming the file path and the env vars.

Pair an approver device first (e.g. with [`@allw/approver`](../approver)) to obtain the account id and
the account-root public key.

Wire the hook into your user-level `~/.claude/settings.json` (or a project's `.claude/settings.json`
for a demo) as a `PreToolUse` hook. Install it outside any tree the agent works in, so the agent
can't edit the gate: see
[Install the hook where the agent can't write it](../../docs/claude-code-integration.md#install-the-hook-where-the-agent-cant-write-it).
The matcher `^(Bash|Edit|MultiEdit|Write)$|^mcp__` is a regular expression anchored to whole tool
names: it sends exactly `Bash` (shell commands), `Edit`/`MultiEdit`/`Write` (direct file edits) and
every `mcp__…` tool to `allw`, and nothing else (not `NotebookEdit`). The `deny` rules turn off
`Monitor`, `PowerShell` and `NotebookEdit`, which run shell commands or edit files without passing
through `allw` ([#298](https://github.com/mike-north/allw/issues/298)). `Monitor` also follows your
`Bash` permission rules, so a `Bash` allow rule would run it with no prompt at all:

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

> Use an absolute path to `dist/cli.js`, or `npx --no-install allw-hook`. **Never plain
> `npx allw-hook`:** when no installed bin resolves, plain `npx` downloads and runs the registry
> package of that name, so a squatted package would run as the gate; `--no-install` exits 1 instead
> (checked on npm 10.9.4 and 11.21.1). The `command` is run under `node`; there is no native binary
> to sign or allow-list.

> **Set `"onFailure": "block"`** (Claude Code v2.1.295 or later; older versions ignore the key
> without warning, so check `claude --version`). Without it, if Claude Code can't start the hook (a
> wrong path, `node` missing from `PATH`, the package not installed), the [hooks
> reference](https://code.claude.com/docs/en/hooks#exit-code-output) treats that as a non-blocking
> error and **the tool call goes ahead ungated**. With it, Claude Code [blocks the
> call](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails) when the hook
> fails to start, exits with a code other than 0 or 2, or times out. This hook exits 0 on every
> decision, deny included, so the setting only matters when the hook never gets to decide.

> **Always pin `"timeout"`** (here `480`, in seconds). Without it the hook inherits Claude Code's
> 600s default, and a too-large `ALLW_TIMEOUT_MS` could let that timeout fire before the hook decides
> — see [the timeout-ordering invariant](#the-timeout-ordering-invariant-issue-52) below.

### The timeout-ordering invariant (issue #52)

`allw` is fail-closed only because the hook **always reaches its decision (exit 0) before any
external timeout fires.** This must never depend on what Claude Code does when a hook
fails to emit a decision, because that behavior is fail-**open** and partly undocumented:

- Claude Code's command-hook `timeout` defaults to **600 seconds**.
- A hook **timeout** does not block the call → **the tool proceeds** through Claude Code's normal
  permission flow (fail-open), unless the hook sets `"onFailure": "block"`.
- (Likewise, a non-zero, non-2 hook _exit code_ is a non-blocking error → the tool proceeds.)

So we never rely on it. The invariant we control:

> **SDK deadline (`ALLW_TIMEOUT_MS`) + the SDK's per-request relay-fetch timeouts MUST all fire
> before Claude Code's hook timeout** — otherwise the tool's fate depends on Claude Code internals
> we don't control.

The hook enforces this at two points:

1. The install block above **pins** the hook `timeout` to `480` seconds (well below the 600s default,
   well above the 5-minute `ALLW_TIMEOUT_MS` default).
2. `readConfig` **caps** `ALLW_TIMEOUT_MS` strictly below the pinned timeout (must be **`< 420000`**
   ms, i.e. ≥ `420000` is rejected), leaving a 60s margin for the relay-fetch timeouts to fire too.
   An oversized value is a **fail-closed `deny`** at config-read time, not a silent acceptance into a
   regime where Claude Code could kill the hook before it decides. (A user setting `900000` —
   "give me time to reach my phone" — is refused with an actionable reason.)

Independently, `@allw/sdk` bounds **every** relay `fetch` (device list, submit, each poll) with a
per-request timeout, so a relay that accepts the connection but never responds can no longer wedge
`requestApproval` indefinitely; it fails closed to a non-approving verdict well within the deadline.
`ALLW_FETCH_TIMEOUT_MS` can lower that per-fetch timeout (for example, in UAT or stricter local
installs), but the hook rejects values above `30000` so config cannot erode the margin above.

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
  "tool_name": "Bash", // or "Edit" / "Write" / "mcp__<server>__<tool>"
  "tool_input": { "command": "rm -rf build" }, // tool-specific
}
```

**stdout** (the hook always exits 0): **empty** when allw has no objection, or one `deny`:

```jsonc
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny", // the only decision allw ever emits
    "permissionDecisionReason": "allw: …",
  },
}
```

**allw only adds a gate; it never grants.** A verified human approval, a non-gated tool and a
pass-through all get **no decision** (empty stdout), so Claude Code goes on to apply your own
permission rules exactly as without allw. allw never emits `allow`, because in Claude Code an `allow`
skips the permission prompt: an approval (or a matcher widened to tools allw never asks about) would
then grant access your own rules would have asked about. It never emits `ask` either. Approved calls
can therefore still get Claude Code's own prompt at the desk; to make the phone the only prompt, see
[After an approval](../../docs/claude-code-integration.md#after-an-approval-claude-codes-own-permissions-still-apply).

Because empty stdout means "no objection", the hook also has an **exit backstop**: if the process
reaches exit before it has decided (for example, the event loop drained while an approval was
pending, an uncaught exception, or a stray `process.exit`), or receives `SIGTERM`, `SIGINT` or
`SIGHUP` while waiting, it prints one `deny` and exits 0 instead of exiting with nothing (or exits
1 if the deny can't be written, so it never reads as "no objection"). A
`SIGKILL`, a native crash or Claude Code's own timeout can't be answered from inside the process;
`"onFailure": "block"` makes Claude Code block the call in those cases.

## What is gated (v0)

Deliberately conservative, so the human is only interrupted for actions that actually run side
effects:

- **`Bash`** — a shell command (`tool_input.command`).
- **`Edit` / `Write` / `MultiEdit`** — direct file edits (`tool_input.file_path` plus edit
  payload).
- **`mcp__<server>__<tool>`** — any MCP tool call (`tool_input` is the raw params object).
- **everything else** (`Read`, `Glob`, `Grep`, `WebFetch`, …) — **not gated**; allw makes no
  decision for it, without bothering the human (and without needing any `allw` config).
- **Not gated yet, so the install block turns them off:** `Monitor` and `PowerShell` (both run shell
  commands; `Monitor` follows your `Bash` permission rules) and `NotebookEdit` (edits notebook
  files). Gating them is [#298](https://github.com/mike-north/allw/issues/298).

Widening the matcher only ever adds gating: a tool allw doesn't gate gets no decision, never an
`allow`.

## Fail-closed (contract §Invariants #6)

The primitive never returns a bare "allow", and neither does the hook. Every uncertain path blocks:

| Situation                                                    | Decision            |
| ------------------------------------------------------------ | ------------------- |
| Not a gated tool                                             | none (empty stdout) |
| Gated, verified verdict `decision === "approved"`            | none (empty stdout) |
| Gated, verified human `denied` / `expired` / `aborted`       | `deny`              |
| Gated, request timed out (no response by the deadline)       | `deny`              |
| Gated, the `ActionRecord` could not be built                 | `deny`              |
| Gated, the approval request threw (network/relay/no devices) | `deny`              |
| Malformed hook stdin (not JSON, wrong event, …)              | `deny`              |
| Missing/invalid configuration (file and env)                 | `deny`              |
| Any unexpected internal error                                | `deny`              |
| The process reached exit before deciding (exit backstop)     | `deny`              |

A gated call escapes allw's `deny` **only** when its verdict is delivered, cryptographically verified
against the approver's account-root key, bound to this exact request (WYSIWYS), fresh, and a human
"yes". The verification itself lives in the audited core; the hook just maps the verified result
onto the Claude Code decision.

## Development

```sh
pnpm --filter @allw/hook typecheck
pnpm --filter @allw/hook lint
pnpm --filter @allw/hook test    # requires `pnpm run build:wasm` + the dist build first
```
