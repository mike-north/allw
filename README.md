# allw

One inbox for every agent approval, across every machine.

A cheap, end-to-end-encrypted human-in-the-loop **approval primitive** for AI agents — and the user-owned
governance layer that grows around it. See [`docs/`](./docs):

- [positioning.md](./docs/positioning.md) — what allw is and why it's different.
- [mvp-scope.md](./docs/mvp-scope.md) — v1 scope: integration goals, steel threads, capability milestones.
- [architecture.md](./docs/architecture.md) — tech stack and system design.
- [contract.md](./docs/contract.md) — the approval-primitive contract (the keystone).
- [enrollment.md](./docs/enrollment.md) — account/device enrollment, rotation, revocation, and recovery.
- [action-record.md](./docs/action-record.md) — the seam to the (later) policy layer.
- [hitl-seam.md](./docs/hitl-seam.md) — the provider-neutral, layered policy + human-decision contract;
  [decision log](./docs/hitl-seam-decisions.md).
- [decision-history.md](./docs/decision-history.md) — on-device, encrypted, ephemeral decision history and the reflection pass (post-v1).
- [decision-flywheel.md](./docs/decision-flywheel.md) — recognized-tool tallies: the only sanctioned, aggregate-only egress.
- [threat-model.md](./docs/threat-model.md) — adversaries, residual risks, and the security review checklist.
- [releasing.md](./docs/releasing.md) — how the `@allw/*` npm packages are released (CI-only, npm trusted publishing) and the one-time bootstrap.

## Quickstart (zero → first approval)

Get a real shell command **blocked until you approve it from a separate approver** — verified end to
end. (The CLI approver below is a demo when it runs on the agent's machine.)
Full walkthrough with troubleshooting: **[docs/quickstart.md](./docs/quickstart.md)**.

> Requires Node ≥ 24 and Claude Code. **No Rust toolchain needed** — the audited core ships pre-built
> as WASM inside `@allw/sdk`. v0 stand-ins (CLI approver instead of a phone app; software-held keys)
> are called out in the full doc.

```sh
# 0. Use the hosted relay — no Cloudflare account needed (self-host instead per
#    docs/quickstart.md §0): https://allw-relay.mnorth.workers.dev

# 1. Install the CLIs in your project (the @allw/sdk + bundled WASM come along automatically):
npm install @allw/hook @allw/approver

# 2. Pair an approver (demo: a second terminal on this machine). Prints your account id + account-root public key
#    (the account id is derived from the account-root key — you don't choose it):
npx --no-install allw-approver pair --relay https://allw-relay.mnorth.workers.dev --label my-laptop

# 3. Watch for requests in that terminal (leave running; it stands in for your phone):
npx --no-install allw-approver watch
```

> **⚠ Demo only.** The CLI approver keeps the account root and signing keys on the machine it runs on,
> so the agent you are gating can read them and approve its own requests. For real use, pair the
> [hosted web approver](https://allw-web-approver.pages.dev) from a machine the agent can't read
> (quickstart §2).

Then point the Claude Code **PreToolUse** hook at `npx --no-install allw-hook` (never plain `npx`,
which can download and run a registry package of that name) with the relay URL, account id, and
account-root key as env vars, ask Claude Code to run `git status`, and approve it from the watch
terminal. The exact hook config block and env vars are in
**[docs/quickstart.md](./docs/quickstart.md)** (steps 4–5).

## Workspace

Polyglot monorepo — one audited Rust core, thin surfaces around it.

| Path                       | What                                                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `crates/allw-core`         | Rust core: contract types, crypto, verdict signing/verification, audit chaining.                                                                             |
| `packages/sdk`             | TypeScript SDK (`@allw/sdk`) — the integrator call site; wraps the core via WASM.                                                                            |
| `packages/relay`           | Zero-knowledge relay (`@allw/relay`) — Cloudflare Workers + Durable Objects.                                                                                 |
| `packages/hook`            | Claude Code `PreToolUse` hook — gates Bash/MCP through allw, fail-closed.                                                                                    |
| `packages/codex-hook`      | Codex `PreToolUse` hook — same allw gate with a distinct Codex actor identity.                                                                               |
| `packages/openclaw-bridge` | OpenClaw gateway operator client; current upstream reviewer-visibility blocker is documented in [`openclaw-integration.md`](./docs/openclaw-integration.md). |

### Demo

[`examples/walking-skeleton`](./examples/walking-skeleton) — the v0 **walking skeleton**: one real
Claude Code action approved from a second surface, end-to-end over the zero-knowledge relay,
fail-closed and cryptographically verified. It composes every surface and is reproducible from its
README (a mostly one-command live demo plus an all-real-crypto CI round-trip).

### Develop

```sh
cargo check                 # Rust core
pnpm install && pnpm -r typecheck   # TypeScript surfaces
```

## License

MIT
