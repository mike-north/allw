# Relay Production Deployment Runbook

This runbook guides an operator through deploying the `@allw/relay` Cloudflare Worker to production.
Every step a human must run is labelled **[OPERATOR]**.

> **Zero-knowledge reminder.** The relay routes ciphertext and signed verdicts only. It never sees
> plaintext action context, private keys, or decrypted approval details. Deploying it to production
> does **not** change the trust posture — the relay cannot learn anything by eavesdropping. This means
> you must **not** add plaintext logging or observability hooks to the relay code: doing so would break
> the E2EE invariant for every user and is explicitly prohibited by the design
> (`docs/architecture.md`, `docs/contract.md`).

---

## Prerequisites

Before starting, ensure you have:

- **A Cloudflare account** (free tier is sufficient for development; Workers Paid plan is recommended
  for production traffic because it removes the 100,000 req/day free-tier cap and enables more
  Durable Object storage).
- **`wrangler` CLI** — installed automatically when you run `pnpm install` from the repo root.
  Available at `packages/relay/node_modules/.bin/wrangler`.
- **The `allw` repo** checked out locally.
- A **custom domain** on your Cloudflare account, OR accept the default `workers.dev` subdomain
  (simpler; no DNS setup required).

---

## 1. Authenticate with Cloudflare

**[OPERATOR]** Log in once. This opens a browser window:

```sh
cd packages/relay
node_modules/.bin/wrangler login
```

Verify you are logged in and note your account id:

```sh
node_modules/.bin/wrangler whoami
```

---

## 2. Fill in `wrangler.jsonc` placeholders

Open `packages/relay/wrangler.jsonc` and replace every `REPLACE_ME` value under `env.production`:

| Field                       | What to put                                                  |
| --------------------------- | ------------------------------------------------------------ |
| `account_id`                | Your Cloudflare account id (from `wrangler whoami`).         |
| `routes[0].pattern`         | The hostname + path pattern, e.g. `relay.example.com/*`.     |
| `routes[0].zone_name`       | The root domain managed by Cloudflare, e.g. `example.com`.   |
| `vars.CORS_ALLOWED_ORIGINS` | Browser origins allowed to read relay responses (see below). |

**If you want to use the default `workers.dev` subdomain instead of a custom domain**, delete the
`"routes"` array from the `env.production` block. The worker will be reachable at
`https://allw-relay.<your-subdomain>.workers.dev` after deploy.

**Browser origins (CORS).** `env.production.vars.CORS_ALLOWED_ORIGINS` is a comma-separated list of
the origins a browser approver may call the relay from. It ships as the hosted web approver,
`https://allw-web-approver.pages.dev`. If you serve your own web approver (`docs/web-approver-deploy.md`),
put its origin here: scheme, host and port only, with no path or trailing slash, e.g.
`https://approver.example.com`. Each entry is normalized to the origin a browser sends (lowercase
host, punycode for an internationalized host, default port dropped), so `https://Approver.example.com:443`
works too. An entry that is not an origin (a path or trailing slash, a query or fragment,
credentials, a non-http(s) scheme, a wildcard host, `null`) is ignored and logged once
(`wrangler tail`); it never widens the list. Matching is exact: Cloudflare Pages preview and branch
origins (`<hash>.allw-web-approver.pages.dev`) are not admitted by the hosted origin and there is no
suffix wildcard. A port of `*` matches any port and is meant for loopback dev only
(the top-level dev config allows `http://localhost:*` and `http://127.0.0.1:*`). Setting the var
replaces the default, and an empty value allows no browser origin. This is not a secret and not an
access control: non-browser clients are unaffected, and every request is still authorized by its
bearer token. Other plain vars (`APNS_*`, `FCM_ENDPOINT`, `VAPID_PUBLIC_KEY`, `VAPID_SUBJECT`) go in
the same `vars` block, because Wrangler does not inherit top-level vars into an environment, and a
second `"vars"` key in `env.production` silently replaces the first (dropping `CORS_ALLOWED_ORIGINS`).

**[OPERATOR]** Commit the filled-in placeholders (no secrets — they go in the next step):

```sh
git add packages/relay/wrangler.jsonc
git commit -m "chore(relay): fill in production wrangler.jsonc placeholders"
```

---

## 3. Set secrets

Secrets are set via `wrangler secret put` and stored encrypted in Cloudflare. Never commit them to
the repository.

### 3a. Mandatory secrets

None are mandatory for a working relay. The relay degrades gracefully when push credentials are
absent: a transport without credentials is simply not registered, so its tokens stay stored but are
never sent (nor counted in a submit's `push_wakeups`), and devices receive requests via WebSocket
presence and polling rather than push wakeups. This is confirmed in `packages/relay/src/index.ts` at
`buildPushTransports`: each transport is registered only when all of its required env vars are
present (for Web Push, a well-formed VAPID keypair and subject).

### 3b. Optional: Apple Push Notification service (APNs)

Required only if you want push wakeups to iOS / macOS devices. Use APNs token-auth (a `.p8` key
file from the Apple Developer portal).

**[OPERATOR]**

```sh
# The APNs topic is your app bundle id — not a secret; safe to set as a plain env var.
# Add it to the existing "vars" block under env.production in wrangler.jsonc:
#   "APNS_TOPIC": "com.yourcompany.allw", "APNS_ENDPOINT": "https://api.push.apple.com"
# Use "https://api.development.push.apple.com" for the APNs sandbox.

# The bearer token is a short-lived JWT you generate from your .p8 private key.
# Generate it with your preferred APNs JWT library, then:
node_modules/.bin/wrangler secret put APNS_BEARER_TOKEN --env production
# Paste the JWT when prompted. Note: APNs JWTs expire after 1 hour; you will need to rotate this
# secret periodically until automatic token refresh is implemented.
```

### 3c. Optional: Firebase Cloud Messaging (FCM) — Android push wakeups

Required only if you want push wakeups to Android devices.

**[OPERATOR]**

```sh
# FCM_ENDPOINT is the FCM HTTP v1 send URL for your Firebase project:
#   https://fcm.googleapis.com/v1/projects/<YOUR_PROJECT_ID>/messages:send
# Add it to the existing "vars" block under env.production in wrangler.jsonc (it contains your
# project id, not a secret).

# FCM_BEARER_TOKEN is an OAuth 2.0 access token for a service account with Firebase Cloud Messaging
# API enabled. Generate one with: gcloud auth print-access-token --scopes=https://www.googleapis.com/auth/firebase.messaging
# (access tokens expire after 1 hour; see the FCM docs for long-lived service account keys as an alternative).
node_modules/.bin/wrangler secret put FCM_BEARER_TOKEN --env production
# Paste the token when prompted.
```

### 3d. Optional: Web Push (VAPID) — browser approver wakeups

Required only if you want the web approver to be woken by a push notification when no tab is open.
The relay authenticates to browser push services with a VAPID keypair (P-256, RFC 8292). The private
key is a secret; the public key and the contact subject are not.

**[OPERATOR]**

```sh
# Generate a VAPID keypair (Node 20+, no dependencies). Prints both halves as base64url.
node -e '
const { subtle } = globalThis.crypto;
const b64 = (b) => Buffer.from(b).toString("base64url");
subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]).then(async (k) => {
  console.log("VAPID_PUBLIC_KEY=" + b64(await subtle.exportKey("raw", k.publicKey)));
  console.log("VAPID_PRIVATE_KEY=" + (await subtle.exportKey("jwk", k.privateKey)).d);
});'

# The public key and subject are plain vars. Add them to the existing "vars" block under
# env.production in wrangler.jsonc (a second "vars" key would silently drop CORS_ALLOWED_ORIGINS):
#   "VAPID_PUBLIC_KEY": "<the printed public key>", "VAPID_SUBJECT": "mailto:ops@yourcompany.example"
# VAPID_SUBJECT is the operator contact push services may use; it must be mailto: or https:.

node_modules/.bin/wrangler secret put VAPID_PRIVATE_KEY --env production
# Paste the printed private key when prompted. Then discard the local copy.
```

Verify after deploy: `curl https://<relay>/.well-known/allw/vapid-public-key` returns
`{"vapid_public_key":"<your public key>"}`. A 404 means one of the three values is missing or
malformed, or the public and private keys are not one keypair (the relay checks by signing and
verifying once).

**Rotating the keypair invalidates every existing browser subscription**: browsers must re-subscribe
with the new public key. The relay does **not** prune the old endpoints: a push service rejects them
with an auth error (401/403), which the relay deliberately treats as transient, so a misconfigured
relay can never unregister every device. Stale endpoints stay registered until the device
re-registers its push tokens (#236).

### Secrets inventory summary

| Secret / var           | Required  | Description                                                                                                                                        |
| ---------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CORS_ALLOWED_ORIGINS` | Defaulted | Comma-separated browser origins allowed to read relay responses (plain var in `wrangler.jsonc`, §2). Default: the hosted web approver.             |
| `APNS_ENDPOINT`        | Optional  | APNs base URL (plain var in `wrangler.jsonc`). Production: `https://api.push.apple.com`; sandbox: `https://api.development.push.apple.com`.        |
| `APNS_TOPIC`           | Optional  | App bundle id, e.g. `com.example.allw` (plain var in `wrangler.jsonc`).                                                                            |
| `APNS_BEARER_TOKEN`    | Optional  | APNs token-auth JWT (set via `wrangler secret put`). Short-lived; rotate hourly.                                                                   |
| `FCM_ENDPOINT`         | Optional  | FCM HTTP v1 send URL (plain var in `wrangler.jsonc`).                                                                                              |
| `FCM_BEARER_TOKEN`     | Optional  | FCM OAuth 2.0 access token for a service account (set via `wrangler secret put`).                                                                  |
| `VAPID_PUBLIC_KEY`     | Optional  | Web Push VAPID public key, base64url uncompressed P-256 point (plain var in `wrangler.jsonc`). Served at `GET /.well-known/allw/vapid-public-key`. |
| `VAPID_PRIVATE_KEY`    | Optional  | Web Push VAPID private key, base64url 32-byte scalar (set via `wrangler secret put`). Long-lived; rotating it invalidates subscriptions.           |
| `VAPID_SUBJECT`        | Optional  | Web Push operator contact, `mailto:` or `https:` URI (plain var in `wrangler.jsonc`).                                                              |

No other secrets are required. The relay derives all per-account auth tokens internally and stores
only SHA-256 hashes in the Durable Object SQLite database. Its only static signing key is the
optional VAPID key, a push-provider transport credential (like the APNs bearer) that never signs
anything in the approval contract.

---

## 4. Migrations

The `AccountRelay` Durable Object uses a single migration tag: `"v1"` (declared in `wrangler.jsonc`
under `"migrations"`). This tag causes Cloudflare to create the SQLite-backed DO class on first
deploy.

The DO schema itself is applied by `AccountRelay.initSchema()` (called in the constructor) using
`CREATE TABLE IF NOT EXISTS` for every table, so the schema is fully idempotent. Additional columns
added after the initial release are applied as `ALTER TABLE … ADD COLUMN` inside a `try/catch` that
silently ignores the `duplicate column` error from already-upgraded instances — also idempotent.

**You do not need any manual migration steps.** When the DO first activates on a fresh account, it
creates all tables. When it reactivates after a code deploy that adds columns, it applies the
`ALTER TABLE` migrations automatically.

Verification: The full Vitest test suite (`pnpm --filter @allw/relay test`) exercises the DO via
`@cloudflare/vitest-pool-workers` against a real `workerd` runtime and confirms the test cases
pass against the current schema. Run this locally before deploying to confirm no regression.

**[OPERATOR]** Run the tests locally before deploying:

```sh
# From the repo root. The relay verifies root signatures through the allw-core wasm build,
# so build it first (needs the Rust toolchain from rust-toolchain.toml + wasm-pack):
pnpm run build:wasm
pnpm --filter @allw/relay test
```

All tests must pass. If any fail, do not deploy until they are fixed.

---

## 5. Deploy

**[OPERATOR]** Deploy the production environment. The worker bundles the `allw-core` wasm from
`packages/sdk/vendor/allw-wasm`, so `pnpm run build:wasm` (step 4) must have run in this checkout:

```sh
cd packages/relay
node_modules/.bin/wrangler deploy --env production
# equivalently, from the repo root: pnpm --filter @allw/relay run deploy
```

The package's `deploy` script always passes `--env production`. A bare `wrangler deploy` would
publish the top-level dev config under the same worker name, replacing production's vars (with
loopback CORS origins) and routes, so the script never does that. Use `wrangler dev` for local work.

Wrangler will print the deployed URL, e.g.:

```
Published allw-relay (production) (https://relay.example.com)
```

or (if using workers.dev):

```
Published allw-relay (production) (https://allw-relay.<subdomain>.workers.dev)
```

Note this URL — it is your `ALLW_RELAY_URL` for SDK / hook configuration.

---

## 6. Custom domain / route setup

If you used the `routes` block in step 2, the domain is live immediately after deploy (Cloudflare
propagates the route to the edge globally within seconds). No further DNS action is needed if the
zone is already on Cloudflare.

If you need to add a new DNS record (e.g. `relay.example.com` does not yet exist):

**[OPERATOR]** In the Cloudflare dashboard for your zone, add an `A` or `CNAME` record pointing to
Cloudflare's proxy (`1.1.1.1` / `@` / whatever the proxied placeholder is), then enable the orange
cloud (proxy). Workers routes override the origin, so the record value does not matter as long as it
is proxied.

---

## 7. Smoke check (end-to-end)

Verify the deployed relay works by running the pairing + approval flow against it.

**[OPERATOR]** In a second terminal, start the approver watching:

```sh
# In the repo root (ensure @allw/approver is installed):
RELAY_URL="https://relay.example.com"   # Replace with your deployed URL
KEYFILE="/tmp/allw-smoke-$(date +%s).json"

# Use a throwaway keyfile so the smoke test gets a fresh account root (and so a fresh account id,
# which is derived from the root).
npx --no-install allw-approver pair \
  --relay "$RELAY_URL" \
  --keyfile "$KEYFILE" \
  --label "smoke-test-device"
```

Copy the printed account id and account-root public key, then start watching:

```sh
npx --no-install allw-approver watch --keyfile "$KEYFILE"
```

In a third terminal, wire the hook and run a test request. Set the env vars printed during pairing:

```sh
export ALLW_RELAY_URL="$RELAY_URL"
export ALLW_ACCOUNT_ID="<ACCOUNT_ID_FROM_PAIR_OUTPUT>"
export ALLW_APPROVER_ROOT_KEY="<ROOT_KEY_FROM_PAIR_OUTPUT>"

# Trigger a request (simulating the Claude Code hook):
npx --no-install allw-hook <<'EOF'
{"tool_name":"Bash","tool_input":{"command":"echo smoke-test"}}
EOF
```

The watch terminal should display the pending approval. Press `a` to approve.

The hook should exit 0 with **empty stdout**: after a verified approval allw makes no decision (it
never emits `allow`), so Claude Code's own permission rules apply. This confirms:

1. The relay is reachable at the deployed URL.
2. Pairing, device presence (WebSocket), and request submission all work.
3. A verdict is returned and verified end-to-end.

---

## 8. Rollback

Cloudflare Workers support instant rollback to the previous deployment via the dashboard or CLI.

**[OPERATOR]** To roll back:

```sh
cd packages/relay
# List recent deployments:
node_modules/.bin/wrangler deployments list --env production

# Roll back to the previous version:
node_modules/.bin/wrangler rollback --env production
```

Or in the Cloudflare dashboard: Workers & Pages → `allw-relay` → Deployments → the prior version → Roll back.

**DO schema note:** Rollback reverts the Worker code but does **not** undo Durable Object schema
changes. The `CREATE TABLE IF NOT EXISTS` and `ALTER TABLE` migration approach is forward-only and
tolerates running against a newer schema (the `try/catch` ignores already-existing columns). Rolling
back to older code against a newer DO schema is safe as long as older code does not depend on columns
being absent.

---

## 9. Quickstart wiring

`docs/quickstart.md` §0 "The relay endpoint" now defaults new users to the hosted relay at
`https://allw-relay.mnorth.workers.dev`, so a first-time user never needs a Cloudflare account or
this runbook. Run through this runbook instead when you want your own deployment — isolation,
control over uptime, or scale beyond the shared hosted relay. The `ALLW_RELAY_URL` your deploy
prints in step 5 above drops directly into the quickstart's pairing and hook-wiring steps in place
of the hosted URL.

---

## 10. Web approver static bundle (peer runbook)

The browser approver surface (`packages/web-approver`) has its own deploy runbook —
[`docs/web-approver-deploy.md`](./web-approver-deploy.md). It covers building the production
static bundle, runtime relay-URL configuration (the same static bundle can point at any relay
deployed via this runbook without a rebuild), and deploying to Cloudflare Pages or any static host.

---

## Appendix: what this runbook has and has not verified

| Item                                                          | Status                                                                                 |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `wrangler deploy --env production --dry-run` passes locally   | Verified (~995 KiB / ~358 KiB gzip upload incl. the allw-core wasm; DO binding listed) |
| All relay Vitest tests pass (DO migration + full API surface) | Verified                                                                               |
| TypeScript type-check passes                                  | Verified                                                                               |
| Push no-op default when credentials absent                    | Verified (`buildPushTransports` at `src/index.ts:1602`)                                |
| Actual deploy to a real Cloudflare account                    | Verified — live at `https://allw-relay.mnorth.workers.dev` (production `env`)          |
| APNs / FCM push wakeup with live credentials                  | **Not verified** — requires real APNs/FCM account                                      |
| Custom domain DNS propagation                                 | **Not verified** — depends on operator's zone config                                   |
| APNs JWT rotation strategy                                    | **Not implemented** — tokens expire hourly; tracked as a follow-up                     |
