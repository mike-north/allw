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

## This device's keys (vouching)

After pairing, the app shows a collapsed **This device's keys (for vouching)** panel under the inbox
(`src/device-details.ts`). It lists the device id, both public keys (each with a copy button), the
core fingerprint of each key (eight groups of four hex digits), and a ready-to-copy
`allw-approver vouch --device-id … --encryption-pubkey … --signing-pubkey …` command. The public keys
are derived from the stored seeds by the WASM core, and every shown value goes through the core
escape. The command is offered only when the core accepts the id and keys
(`check_device_enrollment`); otherwise the panel says why.

Integrators encrypt each request only to devices the root-signed account state lists. Whether this
browser needs vouching depends on where its keys came from:

- **Set up from the CLI keyfile** (the pairing form takes its seeds, cert and token): this browser
  _is_ the CLI's device, and `allw-approver pair` already lists it. The panel is informational. After
  a re-pair, paste the keyfile's new values (`docs/quickstart.md` §Upgrading an existing pairing):
  the account state names only the new device id (#378).
- **Keys of its own**: the account-root holder runs the panel's command
  (`allw-approver vouch`, **interim until #199**) and compares the device id and all eight groups of
  both fingerprints with this panel before confirming. Until then, requests reach this browser but
  it cannot decrypt them.

See `docs/enrollment.md` §Interim vouching.

## Building blocks (for embedding a custom host)

`browser.ts` also exports `mountWebApprover`, which a custom host can call directly with an
already-constructed `WebApproverRuntime` (bypassing `app.ts`'s pairing/WASM-loading sequence) —
this is the seam the package's own tests use, and remains available for hosts with a different
runtime-construction flow. Setting `window.allwWebApprover` before `browser.js` loads triggers the
same auto-mount as a convenience for that use case.
