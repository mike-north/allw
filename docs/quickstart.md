# Quickstart: zero → first approval

Goal: install `allw`, pair an approver, wire the Claude Code hook, and get a real shell command
**blocked until you approve it from a separate approver** — cryptographically verified, end to end.
(The CLI approver this guide uses is a demo when it runs on the agent's machine; see §2.)

This is the v0 "walking skeleton" experience. Read it honestly: some pieces are deliberate v0
stand-ins, called out inline. Where a step is **not yet wired**, it says so rather than pretending.

> **What's real today**
>
> - One audited Rust core (crypto, contract, verdict verification), shipped as **WASM** — every
>   surface below runs it under `node`, with **no Rust toolchain at install time**.
> - A fail-closed Claude Code **PreToolUse hook** (`@allw/hook`) that turns a gated tool call into an
>   approval request and denies anything but a verified human "yes". It never grants: on a "yes"
>   it steps aside and Claude Code's own permission rules decide.
> - The same gate for **Codex** (`@allw/codex-hook`) — see [`docs/codex-integration.md`](./codex-integration.md)
>   for the Codex-specific hook config; steps 0–3 below (relay, install, pairing, watch) are identical.
> - An **approver** (`@allw/approver`, a CLI stand-in for a second device; demo-only when run on the
>   agent's machine, see §2) that renders the exact action (WYSIWYS), prompts Approve / Deny, and
>   returns a signed verdict.
> - A **relay** (`@allw/relay`) designed to be zero-knowledge — this quickstart defaults to the hosted
>   relay at `https://allw-relay.mnorth.workers.dev`; you can also run your own (Cloudflare or locally
>   via `wrangler dev`). **Not yet zero-knowledge against a malicious relay operator:** see the caveat
>   in step 0.
>
> **v0 stand-ins (not production):**
>
> - The "second device" in this walkthrough is a **CLI** (`allw-approver`). A hosted **web approver**
>   is also live (see the browser option in step 2); the native phone app is not shipped yet. The wire
>   protocol does not change when the phone surface lands.
> - The approver holds its keys in a **software keyfile**, not hardware (Secure Enclave / StrongBox).
>   Tracked by [#23](https://github.com/mike-north/allw/issues/23). The protocol is unchanged.
> - The requesting **actor identity is unverified** in v0 ([#16](https://github.com/mike-north/allw/issues/16));
>   the approver marks it `UNVERIFIED` on screen.

---

## Prerequisites

- **Node.js ≥ 24** (the surfaces use Node 24 globals: `fetch`, `WebSocket`, `WebAssembly`).
- **Claude Code** (for the hook step).
- No Cloudflare account needed — step 0 below defaults to the hosted relay. A Cloudflare account is
  only required if you choose to self-host instead.

You do **not** need Rust or `wasm-pack`: the WASM core ships pre-built inside `@allw/sdk`'s npm
package, and `@allw/hook` / `@allw/approver` load it from there.

---

## 0. The relay endpoint

`allw` routes encrypted requests through a relay designed to be **zero-knowledge**. This quickstart uses the
**hosted relay** so you can start without standing up any infrastructure:

```
https://allw-relay.mnorth.workers.dev
```

That's the `<RELAY_URL>` referenced in the steps below — no Cloudflare account or setup needed.

> The relay is only ever sent **ciphertext + signed verdicts** — never plaintext or any signing key
> (`docs/architecture.md`, `docs/contract.md`).
>
> **Caveat — not yet zero-knowledge against the relay itself.** The SDK encrypts each request to the
> device list the relay returns (`GET /{account}/devices`), and the shipped hooks do not yet check that
> list against root-signed account state. A malicious or compromised relay operator could therefore
> list a key it holds as a device and decrypt the action context. Until the fix lands
> ([#243](https://github.com/mike-north/allw/issues/243): encrypt only to root-vouched devices), only
> use a relay whose operator you trust — or run your own. See `docs/threat-model.md` §Residual Risks.

**Prefer to self-host?** Either option below gives you a `<RELAY_URL>` to use in place of the
hosted one — everything else in this quickstart is unchanged.

- **Local relay** (fastest for trying it out; no Cloudflare account needed). In a terminal you'll
  leave running:

  ```sh
  # In a checkout of this repo (the relay is not published to npm; you deploy it from source):
  git clone https://github.com/mike-north/allw.git
  cd allw
  pnpm install
  pnpm --filter @allw/relay dev          # boots `wrangler dev` → http://127.0.0.1:8787
  ```

  Your relay URL is then `http://127.0.0.1:8787`.

- **Deploy your own to Cloudflare** (shareable, for real phone-in-pocket use) — follow the full
  runbook in [`docs/relay-deploy.md`](./relay-deploy.md).

---

## 1. Install the CLIs

> **Not on npm yet.** The `@allw/*` packages on npm are only `0.0.0-bootstrap` name reservations with
> no bin, so `npm install` below gives you nothing to run. Until the first release, install from a
> checkout: `pnpm install && pnpm run build:wasm && pnpm -r build` (needs Rust and `wasm-pack`), then
> `pnpm pack` in `packages/sdk`, `packages/hook` and `packages/approver` and `npm install` the three
> tarballs (as `scripts/smoke-packaged-install.mjs` does).

In the project where you run Claude Code (or globally):

```sh
npm install @allw/hook @allw/approver
# the @allw/sdk dependency (with the bundled WASM core) is installed automatically
```

Confirm they're installed and which version you have (useful for bug reports):

```sh
npx --no-install allw-hook --version
npx --no-install allw-approver --version
```

> **Always run the allw bins as `npx --no-install …`** (or by absolute path, see step 4). Plain
> `npx allw-hook` downloads and runs whatever package of that name the registry serves when it can't
> find the bin locally, without asking when there's no terminal. `--no-install` makes `npx` exit with
> an error instead, so a mistyped or squatted package can never run in place of the gate.

> Using **Codex** instead of Claude Code? Install `@allw/codex-hook` in place of `@allw/hook`
> (`npm install @allw/codex-hook @allw/approver`) and skip to
> [`docs/codex-integration.md`](./codex-integration.md) for step 4's Codex-equivalent hook wiring —
> steps 0, 2, 3, and 5 below are unchanged.

---

## 2. Pair an approver

The approver is the surface where **you** see and decide the request.

> **Browser option.** A hosted web approver is live at
> [https://allw-web-approver.pages.dev](https://allw-web-approver.pages.dev) — open it from any
> browser (including your phone) and paste the pairing output from the CLI below into its pairing
> form. See [`web-approver-deploy.md`](./web-approver-deploy.md) for details or self-hosting.

> **⚠ The CLI approver is for demos only.** It keeps the account root key and the device signing key
> in a keyfile on the machine where you run it. Any process running as the same user, including the
> AI agent you are gating, can read that file and approve its own requests. The signatures still
> verify; you are just no longer the one deciding. `allw-approver pair`, `watch` and `keygen` print
> this warning every time they run.
>
> For real use, approve from a device the agent can't reach: the
> [hosted web approver](https://allw-web-approver.pages.dev) on your phone. Today the web approver is
> paired with the values `allw-approver pair` produces, so run `pair` on a machine (or OS user) the
> agent can't read, not on the machine the agent runs on. Moving the account root off the agent's
> machine entirely is tracked in [#244](https://github.com/mike-north/allw/issues/244).

For the CLI approver demo, in a **second terminal** (leave it running), pair it with an account on
your relay:

```sh
npx --no-install allw-approver pair \
  --relay <RELAY_URL> \
  --label "my-laptop"
```

- `<RELAY_URL>` is from step 0 — `https://allw-relay.mnorth.workers.dev` by default, or your own
  URL if you chose to self-host.
- The **account id is derived from the account-root key** in your keyfile (a 43-character
  base64url string) — you don't choose it. Only the holder of that key can add devices to the
  account. `--account <id>` is optional and only checks that you got the id you expected.

This generates a local keyfile (`~/.allw/approver-keyfile.json`, mode `0600`), registers the device,
mints a device certificate, and prints two things you need for the hook:

- the **account id** (derived from the account root), and
- the **account-root public key** (base64url) — the integrator's trust anchor.

Copy both values from the output.

> v0 stand-in: keys are software-held in the keyfile (→ [#23](https://github.com/mike-north/allw/issues/23)).

---

## 3. Start watching for requests

In that same second terminal, start the watch loop. It opens the device presence socket and prompts
you Approve / Deny for each incoming request:

```sh
npx --no-install allw-approver watch
```

Leave this running. It stands in for your phone in this demo; on the agent's machine it offers no
protection against the agent (see the warning in §2).

---

## 4. Wire the Claude Code hook

> For the full integration contract (matcher set, decision mapping, fail-closed analysis,
> permission-mode interactions) see [`docs/claude-code-integration.md`](./claude-code-integration.md).

The hook (like `@allw/sdk`'s `loadClientConfig` and every other integrator surface) reads its
coordinates from **one non-secret config file**, `~/.allw/config.json`. Create it with the values
from step 2, user-only:

```sh
mkdir -p -m 700 ~/.allw
cat > ~/.allw/config.json <<'JSON'
{
  "version": 1,
  "relay_url": "<RELAY_URL>",
  "account_id": "<ACCOUNT_ID_FROM_STEP_2>",
  "approver_root_key": "<ACCOUNT_ROOT_PUBLIC_KEY_FROM_STEP_2>"
}
JSON
chmod 600 ~/.allw/config.json
```

> Automatic writing of this file by `allw-approver pair` is tracked in
> [#230](https://github.com/mike-north/allw/issues/230); until it lands, write it by hand as above.
> If the agent runs on a different machine from the one that ran `pair`, copy the file there.

The file holds no secrets (never put the approver keyfile's seeds or tokens in it), but it is your
**trust anchor**: `approver_root_key` decides whose signatures the hook accepts, so anyone who can
rewrite it can redirect approvals. Keep it `0600` in a `0700` directory. On macOS/Linux the loader
enforces this on read: a file that is not owned by you, or is group- or world-writable, is rejected
(fix it with `chmod 600 ~/.allw/config.json`).

The loader fails closed — the hook **denies** — if the file is missing and no env vars are set, is
not a regular file (a FIFO, device or directory), is over 64 KiB, fails the ownership/permission
check above, is not valid JSON, has an unknown `version`, is missing a key or has an unknown one, holds a malformed
`approver_root_key`, or holds an `account_id` that does not derive from `approver_root_key`.

**Overrides.** Each field can be overridden by an env var, field by field (env wins over the file).
You don't need any of these if the file is in place:

| Env var                  | Overrides                                                                                                                                                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLW_CONFIG`            | the file's location (default `~/.allw/config.json`); must be an **absolute** path (a leading `~/` is expanded; a relative path is rejected, since it would resolve against the agent's working directory) |
| `ALLW_RELAY_URL`         | `relay_url`                                                                                                                                                                                               |
| `ALLW_ACCOUNT_ID`        | `account_id`                                                                                                                                                                                              |
| `ALLW_APPROVER_ROOT_KEY` | `approver_root_key`                                                                                                                                                                                       |

Then register the hook in your project's (or user's) `.claude/settings.json` as a **PreToolUse**
hook. The matcher sends exactly the shell tools (`Bash`, `PowerShell`, `Monitor`), the file-edit
tools (`Edit`, `MultiEdit`, `Write`, `NotebookEdit`) and every MCP tool (`mcp__…`) to allw: every
tool that runs a command or changes a file. (Beyond a demo, install the hook outside the project and register it in
`~/.claude/settings.json`, so the agent can't edit the gate:
[Install the hook where the agent can't write it](./claude-code-integration.md#install-the-hook-where-the-agent-cant-write-it).)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|PowerShell|Monitor|Edit|MultiEdit|Write|NotebookEdit)$|^mcp__",
        "hooks": [
          {
            "type": "command",
            "command": "npx --no-install allw-hook",
            "timeout": 480,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

> **Always pin `"timeout": 480`** (seconds). Without it the hook inherits Claude Code's 600s default;
> the pin guarantees the hook always reaches its decision before Claude Code could time
> it out (the fail-closed timeout-ordering invariant — see [`@allw/hook`](../packages/hook/README.md)).
>
> **Use `npx --no-install allw-hook`, never plain `npx allw-hook`.** With `--no-install`, `npx` runs
> the bin installed in the project (or globally) and exits with an error if there is none. It never
> downloads a package from the registry and runs it as your gate. (Checked on npm 10.9.4 and 11.21.1:
> with no local install, `npx --no-install allw-hook` exits 1 with "npx canceled due to missing
> packages" and downloads nothing; plain `npx allw-hook` downloads and runs the registry package.)
> If your Claude Code launch environment doesn't run from the project directory, use the absolute
> path to the installed bin instead (find it with
> `node -e "console.log(require.resolve('@allw/hook/package.json'))"` → the `dist/cli.js` beside
> it), e.g. `"command": "node /abs/path/to/@allw/hook/dist/cli.js"`.

### If the hook can't start

If Claude Code can't start the hook (a wrong path, `node` missing from `PATH`, the package not
installed so `npx --no-install` exits 1), the **tool call is not gated by default**. Claude Code's
[hooks reference](https://code.claude.com/docs/en/hooks#exit-code-output) treats a hook that fails
to start, or exits with any code other than 0 or 2, as a _non-blocking error_: it shows a
`PreToolUse:<tool> hook error` notice in the transcript and **the action goes ahead**.

`"onFailure": "block"` in the config above reverses that: if the hook fails to start, exits with a
code other than 0 or 2, or times out, Claude Code
[blocks the tool call](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails)
instead. It needs **Claude Code v2.1.295 or later**. On older versions Claude Code ignores the key
without warning, so a hook that can't start still lets the call through. Check `claude --version`.
`@allw/hook` exits 0 on every decision it makes, deny included, so the setting only changes what
happens when the hook never gets to decide.

Codex has no equivalent setting: a Codex hook that can't start is reported and the tool call goes
ahead. See [`docs/codex-integration.md`](./codex-integration.md#if-the-hook-cant-start).

---

## 5. Run a gated command and approve it

Ask Claude Code to run a shell command, e.g.:

> Run `git status` in this repo.

What happens:

1. Claude Code calls the `Bash` tool; the **hook intercepts** it before it runs.
2. The hook builds the exact action, encrypts it to your approver device, and requests a decision
   over the relay.
3. Your **watch terminal (step 3) prints the exact command** (WYSIWYS) and prompts
   `Approve / Deny / Skip?`.
4. Press **`a`** to approve. The hook verifies the verdict and steps aside (no decision; it never
   emits `allow`). Claude Code then applies its own permission rules, so in the default mode it may
   still ask you at the desk; see
   [After an approval](./claude-code-integration.md#after-an-approval-claude-codes-own-permissions-still-apply)
   to make the phone the only prompt.
5. Press **`d`** to deny (or just wait for the timeout): the hook emits `deny` and Claude Code is
   blocked. **Fail-closed both ways.**

That's the full loop: a real agent action, gated by a human decision in a separate approver,
end-to-end-encrypted and cryptographically verified. With the CLI approver on the same machine as the
agent, that decision is only as trustworthy as the machine: the agent can read the keyfile (§2).

---

## Troubleshooting

| Symptom                                                                  | Cause / fix                                                                                                                                                          |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hook denies with "group- or world-writable" or "not by the current user" | Run `chmod 600 ~/.allw/config.json` (and `chown` it to the user Claude Code runs as).                                                                                |
| Hook always denies with "no allw config found"                           | `~/.allw/config.json` (step 4) doesn't exist for the user Claude Code runs as, and no `ALLW_*` overrides are set. Write the file (or set `ALLW_CONFIG` to its path). |
| Hook denies with "vendored wasm not found"                               | You're running an unbuilt checkout, not the installed package. `npm install @allw/hook` (it bundles the WASM via `@allw/sdk`).                                       |
| No prompt appears in the watch terminal                                  | The account id / `--relay` printed by `pair` must match `account_id` / `relay_url` in `~/.allw/config.json` (or their `ALLW_*` overrides).                           |
| Request times out immediately                                            | Check the relay is running (step 0) and reachable at the configured `relay_url`.                                                                                     |
| Transcript shows `PreToolUse:… hook error`                               | The hook couldn't start (bad path, or not installed). See [If the hook can't start](#if-the-hook-cant-start).                                                        |
| A read or search runs without your approver                              | By design: only `Bash`, `Edit`/`MultiEdit`/`Write` and `mcp__*` are gated. allw makes no decision for the rest.                                                      |

---

## What's not in this quickstart (yet)

- **A phone/web approval surface.** Today the approver is the `allw-approver` CLI. The hosted web
  inbox is designed (`design/`) but not shipped; when it lands, the relay/account/keys here are
  unchanged.
- **Hardware key custody** ([#23](https://github.com/mike-north/allw/issues/23)) and **verified actor
  identity** ([#16](https://github.com/mike-north/allw/issues/16)).

For a scripted, fully-automated end-to-end run (boots a local relay, pairs, drives the hook, and
asserts the decision), see [`examples/walking-skeleton`](../examples/walking-skeleton/README.md).
