# allw

One inbox for every agent approval, across every machine.

A cheap, end-to-end-encrypted human-in-the-loop **approval primitive** for AI agents — and the user-owned
governance layer that grows around it. See [`docs/`](./docs):

- [positioning.md](./docs/positioning.md) — what allw is and why it's different.
- [architecture.md](./docs/architecture.md) — tech stack and system design.
- [contract.md](./docs/contract.md) — the approval-primitive contract (the keystone).
- [enrollment.md](./docs/enrollment.md) — account/device enrollment, rotation, revocation, and recovery.
- [policy-seam.md](./docs/policy-seam.md) — the seam to the (later) policy layer.
- [threat-model.md](./docs/threat-model.md) — adversaries, residual risks, and the security review checklist.

## Workspace

Polyglot monorepo — one audited Rust core, thin surfaces around it.

| Path               | What                                                                              |
| ------------------ | --------------------------------------------------------------------------------- |
| `crates/allw-core` | Rust core: contract types, crypto, verdict signing/verification, audit chaining.  |
| `packages/sdk`     | TypeScript SDK (`@allw/sdk`) — the integrator call site; wraps the core via WASM. |
| `packages/relay`   | Zero-knowledge relay (`@allw/relay`) — Cloudflare Workers + Durable Objects.      |

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
