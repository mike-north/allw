# allw

One inbox for every agent approval, across every machine.

A cheap, end-to-end-encrypted human-in-the-loop **approval primitive** for AI agents — and the user-owned
governance layer that grows around it. See [`docs/`](./docs):

- [positioning.md](./docs/positioning.md) — what allw is and why it's different.
- [architecture.md](./docs/architecture.md) — tech stack and system design.
- [contract.md](./docs/contract.md) — the approval-primitive contract (the keystone).
- [policy-seam.md](./docs/policy-seam.md) — the seam to the (later) policy layer.

## Workspace

Polyglot monorepo — one audited Rust core, thin surfaces around it.

| Path               | What                                                                              |
| ------------------ | --------------------------------------------------------------------------------- |
| `crates/allw-core` | Rust core: contract types, crypto, verdict signing/verification, audit chaining.  |
| `packages/sdk`     | TypeScript SDK (`@allw/sdk`) — the integrator call site; wraps the core via WASM. |
| `packages/relay`   | Zero-knowledge relay (`@allw/relay`) — Cloudflare Workers + Durable Objects.      |

### Develop

```sh
cargo check                 # Rust core
pnpm install && pnpm -r typecheck   # TypeScript surfaces
```

## License

MIT
