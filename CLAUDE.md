# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`allw` is an end-to-end-encrypted, human-in-the-loop **approval primitive** for AI agents, plus the user-owned
governance layer growing around it. The design is **documentation-driven**: `docs/` is the source of truth; the
code is currently a skeleton built down from those decisions. **Read the relevant `docs/*.md` before
implementing** — the architecture only makes sense across several docs together:

- `docs/contract.md` — the approval-primitive contract (the keystone everything else consumes).
- `docs/policy-seam.md` — the policy layer's `ActionRecord` and its syntactic-first tiering.
- `docs/architecture.md` — tech-stack and system-design decisions (and their rationale).
- `docs/threat-model.md` — adversaries, residual risks, and the security review checklist.
- `docs/positioning.md` — the product thesis (why decisions are shaped the way they are).

When you change a design decision, update the doc that owns it in the same change.

## Commands

Polyglot workspace: a Cargo workspace (Rust) **and** a pnpm workspace (TypeScript).

```sh
# Rust core
cargo check                       # type-check
cargo fmt                         # format (cargo fmt --check to verify)
cargo clippy --all-targets        # lint
cargo test -p allw-core           # tests (append a name to run one)

# TypeScript surfaces
pnpm install
pnpm -r typecheck                 # tsc --noEmit across packages
pnpm -r lint                      # ESLint (type-checked)
pnpm -r build
pnpm exec prettier --check "**/*.{ts,js,json,md}"   # --write to fix
pnpm --filter @allw/relay typecheck                 # a single package
```

**Verification gate before declaring work done:** `cargo check` + `cargo clippy` + `pnpm -r typecheck` +
`pnpm -r lint` + `prettier --check` must all pass. No test runner is wired yet — package `test` scripts are
placeholders; Rust uses `cargo test`.

## Architecture: the load-bearing ideas

**One audited Rust core; thin surfaces.** All security-critical logic (crypto, contract types, verdict
signing/verification, audit chaining) lives once in `crates/allw-core`. Every other surface is a thin shell over
it — the TS SDK / relay / hook via **WASM**, native apps via **UniFFI**. Never reimplement core logic in a surface.

**The contract has invariants that constrain all code** (`docs/contract.md`):

- The primitive **never returns "allow."** It returns a _verified human decision_ bound to an exact request;
  callers compute `allow = approved ∧ verified ∧ policy ∧ other_gates`. A verdict can only ever **tighten**
  access, never grant it. (`Verdict::is_human_approved` reports the decision — it is not authorization.)
- **Fail-closed:** timeout / no-response / unverifiable ⇒ deny.
- **WYSIWYS:** the verdict binds to a hash of the exact plaintext the human saw, computed device-side.
- **E2EE:** the relay is zero-knowledge — it routes ciphertext + signed verdicts, never plaintext.
- **One-shot & scope-free verdicts:** reuse / "don't ask again" is the _policy layer's_ job (it emits signed
  rules), never a field on the verdict.

**Policy is tiered; build syntactic-first** (`docs/policy-seam.md`). Every action reduces to an `ActionRecord`
with a `surface` (`command` | `mcp_tool_call` | …) and a **syntactic substrate**. The semantic
`capabilities` / `scope` fields are **reserved and null in v1** — the capability-inference engine (which aligns
to the AgentRC / Arc Flow model) is the deferred, paid tier. v1's only forward-compat duty is to capture the
syntactic substrate and reserve the semantic slots; **do not build capability inference.**

**WASM-local is a hard constraint, not a preference** (`docs/architecture.md`). On-machine code (the hook, the
SDK) runs as **WASM under `node`**, never a standalone native binary — so enterprise binary-allowlisting (Google
Santa) and MDM can't block it. Consequence: the TS↔Rust binding is **WASM only; `napi` is avoided** (a napi
addon is itself a native binary). Native binaries belong only in signed, store-distributed apps.

## Workspace layout

| Path                             | Role                                                                                                                                                  |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/allw-core`               | Rust core: `contract` (wire types), `crypto` (JOSE — JWE/X25519 + JWS/Ed25519, shared with vaultkeeper), `audit` (hash chain).                        |
| `packages/sdk` (`@allw/sdk`)     | Integrator call site (`requestApproval`); wraps the core via WASM.                                                                                    |
| `packages/relay` (`@allw/relay`) | Zero-knowledge relay — Cloudflare Workers + a per-account `AccountRelay` Durable Object (device presence, push fan-out, cross-device retract/dedupe). |

## Related repos (context; not in this tree)

- **vaultkeeper** — holds the _credential perimeter_: agents _use_ secrets via delegated injection, never _read_
  them. This is why `allw` deliberately does not gate raw network egress (`docs/policy-seam.md`).
- **macts / ofocus** — turn macOS apps into MCP surfaces; the eventual semantic policy tier reuses their
  AgentRC / Arc Flow capability model rather than inventing its own.

## Commits

The remote is personal (`github.com/mike-north/allw`) → author commits as
`Mike North <michael.l.north@gmail.com>`. Prefer two or three logical commits per change; no AI-attribution trailers.
