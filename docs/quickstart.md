# Quickstart: zero → first approval

Goal: install `allw`, pair a second device, wire the Claude Code hook, and get a real shell command
**blocked until you approve it from a second surface** — cryptographically verified, end to end.

This is the v0 "walking skeleton" experience. Read it honestly: some pieces are deliberate v0
stand-ins, called out inline. Where a step is **not yet wired**, it says so rather than pretending.

> **What's real today**
>
> - One audited Rust core (crypto, contract, verdict verification), shipped as **WASM** — every
>   surface below runs it under `node`, with **no Rust toolchain at install time**.
> - A fail-closed Claude Code **PreToolUse hook** (`@allw/hook`) that turns a gated tool call into an
>   approval request and only emits `allow` for a verified human "yes".
> - The same gate for **Codex** (`@allw/codex-hook`) — see [`docs/codex-integration.md`](./codex-integration.md)
>   for the Codex-specific hook config; steps 0–3 below (relay, install, pairing, watch) are identical.
> - A **second-device approver** (`@allw/approver`) that renders the exact action (WYSIWYS), prompts
>   Approve / Deny, and returns a signed verdict.
> - A **zero-knowledge relay** (`@allw/relay`) you run on Cloudflare (or locally via `wrangler dev`).
>
> **v0 stand-ins (not production):**
>
> - The "second device" is a **CLI** (`allw-approver`), not yet a phone/web app. The hosted web
>   inbox is designed but not shipped (see `design/` and issue tracker). The wire protocol does not
>   change when the phone/web surface lands.
> - The approver holds its keys in a **software keyfile**, not hardware (Secure Enclave / StrongBox).
>   Tracked by [#23](https://github.com/mike-north/allw/issues/23). The protocol is unchanged.
> - The requesting **actor identity is unverified** in v0 ([#16](https://github.com/mike-north/allw/issues/16));
>   the approver marks it `UNVERIFIED` on screen.

---

## Prerequisites

- **Node.js ≥ 24** (the surfaces use Node 24 globals: `fetch`, `WebSocket`, `WebAssembly`).
- A **Cloudflare account** for the relay (free tier is fine), **or** run the relay locally with
  `wrangler dev` (no account needed for local-only testing).
- **Claude Code** (for the hook step).

You do **not** need Rust or `wasm-pack`: the WASM core ships pre-built inside `@allw/sdk`'s npm
package, and `@allw/hook` / `@allw/approver` load it from there.

---

## 0. The relay endpoint

`allw` routes encrypted requests through a **zero-knowledge relay**. There is **no default hosted
relay yet**, so you stand up your own. It is a single Cloudflare Worker + Durable Object.

**Option A — local relay (fastest for trying it out).** In a terminal you'll leave running:

```sh
# In a checkout of this repo (the relay is not published to npm; you deploy it from source):
git clone https://github.com/mike-north/allw.git
cd allw
pnpm install
pnpm --filter @allw/relay dev          # boots `wrangler dev` → http://127.0.0.1:8787
```

Your relay URL is then `http://127.0.0.1:8787`.

**Option B — deploy to Cloudflare (shareable, for real phone-in-pocket use later).**

```sh
cd allw
pnpm install
pnpm --filter @allw/relay deploy       # `wrangler deploy`; prints your https://<name>.workers.dev URL
```

Your relay URL is the `https://…workers.dev` URL it prints.

> The relay only ever sees **ciphertext + signed verdicts** — never plaintext or any signing key
> (`docs/architecture.md`, `docs/contract.md`). Running your own is safe by design.

---

## 1. Install the CLIs

In the project where you run Claude Code (or globally):

```sh
npm install @allw/hook @allw/approver
# the @allw/sdk dependency (with the bundled WASM core) is installed automatically
```

Confirm they're installed and which version you have (useful for bug reports):

```sh
npx allw-hook --version
npx allw-approver --version
```

> Using **Codex** instead of Claude Code? Install `@allw/codex-hook` in place of `@allw/hook`
> (`npm install @allw/codex-hook @allw/approver`) and skip to
> [`docs/codex-integration.md`](./codex-integration.md) for step 4's Codex-equivalent hook wiring —
> steps 0, 2, 3, and 5 below are unchanged.

---

## 2. Pair a second device (the approver)

The approver is the surface where **you** see and decide the request. In a **second terminal**
(leave it running), pair it with an account on your relay:

```sh
npx allw-approver pair \
  --relay <RELAY_URL> \
  --account my-account \
  --label "my-laptop"
```

- `<RELAY_URL>` is from step 0 (e.g. `http://127.0.0.1:8787` or your `…workers.dev` URL).
- `--account` is any id you choose; it routes requests to this device.

This generates a local keyfile (`~/.allw/approver-keyfile.json`, mode `0600`), registers the device,
mints a device certificate, and prints two things you need for the hook:

- the **account id** (what you passed to `--account`), and
- the **account-root public key** (base64url) — the integrator's trust anchor.

Copy the account-root public key from the output.

> v0 stand-in: keys are software-held in the keyfile (→ [#23](https://github.com/mike-north/allw/issues/23)).

---

## 3. Start watching for requests

In that same second terminal, start the watch loop. It opens the device presence socket and prompts
you Approve / Deny for each incoming request:

```sh
npx allw-approver watch
```

Leave this running. This is your "phone" for now.

---

## 4. Wire the Claude Code hook

> For the full integration contract (matcher set, decision mapping, fail-closed analysis,
> permission-mode interactions) see [`docs/claude-code-integration.md`](./claude-code-integration.md).

The hook reads its config from the environment. Export these in the shell where Claude Code runs
(using the values from step 2):

```sh
export ALLW_RELAY_URL="<RELAY_URL>"
export ALLW_ACCOUNT_ID="my-account"
export ALLW_APPROVER_ROOT_KEY="<ACCOUNT_ROOT_PUBLIC_KEY_FROM_STEP_2>"
```

Then register the hook in your project's (or user's) `.claude/settings.json` as a **PreToolUse**
hook. The matcher `Bash|mcp__.*` gates shell commands and any MCP tool call:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "npx allw-hook",
            "timeout": 480
          }
        ]
      }
    ]
  }
}
```

> **Always pin `"timeout": 480`** (seconds). Without it the hook inherits Claude Code's 600s default;
> the pin guarantees the hook always emits an explicit `allow`/`deny` before Claude Code could time
> it out (the fail-closed timeout-ordering invariant — see [`@allw/hook`](../packages/hook/README.md)).
>
> `npx allw-hook` resolves the installed bin. If your Claude Code launch environment does not see the
> project's `node_modules/.bin` on `PATH`, use the absolute path to the resolved bin instead (find it
> with `node -e "console.log(require.resolve('@allw/hook/package.json'))"` → the `dist/cli.js` beside
> it), e.g. `"command": "node /abs/path/to/@allw/hook/dist/cli.js"`.

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
4. Press **`a`** to approve. The hook receives the verified verdict and emits `allow`; Claude Code
   runs the command.
5. Press **`d`** to deny (or just wait for the timeout): the hook emits `deny` and Claude Code is
   blocked. **Fail-closed both ways.**

That's the full loop: a real agent action, gated by a human decision on a second device,
end-to-end-encrypted and cryptographically verified.

---

## Troubleshooting

| Symptom                                      | Cause / fix                                                                                                                    |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Hook always denies with "ALLW\_… is not set" | The hook env vars (step 4) aren't visible to Claude Code's shell. Export them where Claude Code launches.                      |
| Hook denies with "vendored wasm not found"   | You're running an unbuilt checkout, not the installed package. `npm install @allw/hook` (it bundles the WASM via `@allw/sdk`). |
| No prompt appears in the watch terminal      | The `--account` / `--relay` in the approver must match the hook's `ALLW_ACCOUNT_ID` / `ALLW_RELAY_URL`.                        |
| Request times out immediately                | Check the relay is running (step 0) and reachable at `ALLW_RELAY_URL`.                                                         |
| `git status` runs without prompting          | Only `Bash` and `mcp__*` are gated. Reads/edits/greps pass through by design (v0 conservative matcher).                        |

---

## What's not in this quickstart (yet)

- **A phone/web approval surface.** Today the approver is the `allw-approver` CLI. The hosted web
  inbox is designed (`design/`) but not shipped; when it lands, the relay/account/keys here are
  unchanged.
- **A hosted relay.** You run your own (step 0). A hosted default relay URL is a future addition.
- **Hardware key custody** ([#23](https://github.com/mike-north/allw/issues/23)) and **verified actor
  identity** ([#16](https://github.com/mike-north/allw/issues/16)).

For a scripted, fully-automated end-to-end run (boots a local relay, pairs, drives the hook, and
asserts the decision), see [`examples/walking-skeleton`](../examples/walking-skeleton/README.md).
