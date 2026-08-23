# @allw/web-approver

Browser approver surface for issue #93. It renders the approval inbox, WYSIWYS detail view, and
number-match decision flow.

This is slice 1 of #93: controller state, safe rendering, and a static shell for runtime integration.

The package deliberately keeps cryptographic work behind an injected `WebApproverRuntime`:

- `prepare(envelope)` decrypts the relay envelope, recomputes the WYSIWYS `request_hash`, and returns the exact
  plaintext model to render.
- `signDecision(input)` signs the human's approve/deny decision.

Both methods must be backed by the allw WASM/core surfaces. The UI/controller code treats preparation failures as
fail-closed unverified requests and never reimplements hashing, verification, decryption, or signing.

## Production bundle & deploy (issue #180)

`pnpm --filter @allw/web-approver build` (after `pnpm run build:wasm` from the repo root) produces
`dist-site/` — a deployable, plain static site (HTML/CSS/JS + the vendored WASM core), bundled from
`src/app.ts` by `scripts/build-site.mjs` (esbuild). It boots the pairing gate, loads WASM from a
same-origin asset URL, and mounts the live inbox; the relay URL it connects to is resolved at
runtime (`?relay=` query param, `localStorage`, or a small config prompt) rather than baked into
the bundle. See [`docs/web-approver-deploy.md`](../../docs/web-approver-deploy.md) for the full
build/deploy runbook (Cloudflare Pages or any static host).

`public/index.html` is the static HTML shell `scripts/build-site.mjs` copies into `dist-site/`; its
`<script type="module" src="./app.js">` picks up the bundled production entry point once built.

## Building blocks (for embedding a custom host)

`browser.ts` also exports `mountWebApprover`, which a custom host can call directly with an
already-constructed `WebApproverRuntime` (bypassing `app.ts`'s pairing/WASM-loading sequence) —
this is the seam the package's own tests use, and remains available for hosts with a different
runtime-construction flow. Setting `window.allwWebApprover` before `browser.js` loads triggers the
same auto-mount as a convenience for that use case.
