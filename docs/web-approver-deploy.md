# Web Approver Deployment Runbook

This runbook covers building and hosting `packages/web-approver`'s production static bundle
(issue #180). Every step a human must run is labelled **[OPERATOR]**. It is a peer of
[`docs/relay-deploy.md`](./relay-deploy.md) — deploy the relay first; the web approver needs a
reachable relay URL to connect to.

> **Thin-shell reminder.** The bundle is a plain static site: HTML/CSS/JS plus the vendored
> `allw-wasm` core. All cryptographic work (decrypt, verify, sign) happens inside that WASM core in
> the browser — the bundle contains no server-side runtime and the host it's deployed to never sees
> plaintext action context or key material (`docs/architecture.md`, `docs/contract.md`).

---

## 1. Build the bundle

**[OPERATOR]** From the repo root:

```sh
pnpm install
pnpm run build:wasm                        # vendors the allw-wasm core (crates/allw-wasm)
pnpm --filter @allw/web-approver build      # tsc, then scripts/build-site.mjs
```

This produces `packages/web-approver/dist-site/`:

```
dist-site/
  index.html                    # copied from public/index.html
  tokens.css                    # copied from public/tokens.css (vendored design/web-approver/inbox/tokens.css)
  styles.css                    # copied from public/styles.css
  app.js (+ app.js.map)         # esbuild bundle of src/app.ts
  vendor/allw-wasm/allw_wasm.js
  vendor/allw-wasm/allw_wasm_bg.wasm
```

`dist-site/` is a **flat directory of static files with no server-side dependency and no
Cloudflare-specific runtime API** — it is hostable on Cloudflare Pages, Netlify, GitHub Pages,
S3+CloudFront, or a plain `npx serve dist-site` for local testing. Cloudflare Pages is the natural
choice alongside the Workers-based relay, but nothing in the bundle requires it.

**Tooling choice — esbuild, not Vite.** The repo's existing tooling taste is plain `tsc` plus small
single-purpose scripts (e.g. `scripts/postbuild-wasm.mjs`); esbuild's JS API is a single function
call from `scripts/build-site.mjs` with no dev-server or plugin ecosystem to introduce, and
esbuild's postinstall lifecycle script is already allow-listed at the workspace root
(`pnpm.onlyBuiltDependencies` in the root `package.json`). Vite would work too, but would add a
config file and a dependency category (a dev-server framework) the workspace doesn't otherwise
need for a single static bundle.

**CI.** `.github/workflows/ci.yml`'s `wasm` job re-runs `pnpm --filter @allw/web-approver build`
immediately after `pnpm run build:wasm` (the `typescript` job's `pnpm -r build` runs before wasm
exists, so the site-bundle step there is a no-op skip — see `scripts/build-site.mjs`'s module doc).
`pnpm -r test` in that same job then exercises `dist-site/` end-to-end: `test/site-build.test.mjs`
serves it over a real `http` server and fetches + instantiates the `.wasm` asset exactly the way a
browser would (`WebAssembly.instantiateStreaming`/`instantiate` against a `fetch()`ed `Response`),
not a Node `fs.readFileSync` shortcut.

---

## 2. Runtime relay configuration (never baked into the bundle)

The same static bundle is deployed once and can be pointed at any relay — self-hosted, staging, or
the hosted `allw-relay` Worker — **without a rebuild**. `src/app.ts` resolves the relay URL, in
priority order (`src/relay-config.ts`):

1. a `?relay=` query-string parameter, e.g.
   `https://approvals.example.com/?relay=https://relay.example.com` — validated (must be an
   absolute `http(s)` URL) and persisted to `localStorage` under `allw:relay-url:v1` so a
   subsequent visit (or a home-screen bookmark without the query string) keeps working;
2. a previously-persisted `localStorage` value;
3. neither present → a minimal one-field config prompt is rendered before the pairing gate, so
   first-time visitors without a `?relay=` link can still type in a relay URL by hand.

**[OPERATOR]** To hand a user a working link, share the deployed bundle's URL with `?relay=`
appended, e.g.:

```
https://approvals.example.com/?relay=https://allw-relay.mnorth.workers.dev
```

---

## 3. Deploy to Cloudflare Pages

**[OPERATOR]**

```sh
cd packages/web-approver
npx wrangler@latest pages deploy dist-site --project-name allw-web-approver
```

The first run prompts for Cloudflare authentication (or reuses `wrangler login` from
`docs/relay-deploy.md` §1 if you've already authenticated for the relay) and creates the
`allw-web-approver` Pages project if it doesn't exist. Wrangler prints the deployed URL, e.g.
`https://allw-web-approver.pages.dev`.

No environment variables, secrets, or build configuration are required on the Pages side — the
bundle is fully static and reads its relay URL at runtime (§2 above).

### Alternative: any static host

Since `dist-site/` has no Cloudflare-specific runtime dependency, any static host works instead:

```sh
# Netlify
npx netlify-cli deploy --dir=packages/web-approver/dist-site --prod

# A plain S3 bucket (with static-site hosting enabled) + your CDN of choice
aws s3 sync packages/web-approver/dist-site s3://your-bucket/ --delete

# Local smoke test before deploying anywhere
npx serve packages/web-approver/dist-site
```

---

## 4. Smoke check (mobile browser, against a deployed relay)

**[OPERATOR]** This is the step that confirms issue #180's original problem — opening the approver
from a phone — is actually solved. It cannot be automated in CI (it requires a physical device on
a real network and a live relay), so it is a manual post-deploy check:

1. Deploy the relay (`docs/relay-deploy.md`) and note its URL.
2. Deploy the web approver bundle (§3 above) and note its URL.
3. Pair a device against the relay (e.g. `npx allw-approver pair --relay <RELAY_URL> --account
<ACCOUNT_ID> --label web-phone`), noting the printed `device_id`, `device_auth_token`, seeds,
   and device cert — the pairing form on the phone (§5 below) collects these same 7 fields.
4. On a phone, open `<WEB_APPROVER_URL>/?relay=<RELAY_URL>` in the browser.
5. Complete the pairing form with the values from step 3 (this is the same dev-mode
   credential-stub path `packages/approver` uses locally; a QR/deep-link flow that pre-fills these
   fields is tracked separately, see `design/web-approver/onboarding/`).
6. Trigger a request against the paired account (e.g. via the Claude Code hook or
   `allw-approver watch` on another device) and confirm it appears in the phone's inbox, the
   WYSIWYS plaintext renders correctly, and Approve/Deny signs and clears it.

---

## 5. Pairing-identity note

The pairing form (`src/pairing.ts`) collects all 7 fields `ApproverIdentity` requires: `accountId`,
`deviceId`, `deviceEncryptionSeed`, `deviceSigningSeed`, `deviceCert`, `accountRootPubkey`, and
`deviceAuthToken` (the relay bearer token from `docs/relay-api.md` §Pairing — distinct from
`deviceCert`, which chains verdict signatures to the account root rather than authorizing relay
HTTP calls). A friendlier pairing UX (QR code / deep link that pre-fills these fields instead of
manual entry) is tracked separately and out of scope for this bundling/deploy issue.

---

## Appendix: what this runbook has and has not verified

| Item                                                                          | Status                                                               |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `pnpm --filter @allw/web-approver build` produces a working `dist-site/`      | Verified                                                             |
| `dist-site/` builds without wasm (skips cleanly, `pnpm -r build` still green) | Verified                                                             |
| `.wasm` served with correct content-type and instantiates over real HTTP      | Verified (`test/site-build.test.mjs`)                                |
| Relay URL resolved at runtime (query param / storage / config prompt)         | Verified (`test/relay-config.test.mjs`)                              |
| No literal relay URL embedded in the bundled `app.js`                         | Verified (`test/site-build.test.mjs`)                                |
| Actual deploy to Cloudflare Pages (or any host)                               | **Not run** — human operator step (§3)                               |
| Mobile-browser smoke test against a live deployed relay                       | **Not run** — human operator step (§4); requires a real device/relay |
