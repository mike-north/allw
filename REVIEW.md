VERDICT: OK-WITH-NITS

# PR #255 — second adversarial review (Web Push transport)

Reviewed head: `f693d74` (relay: adapt Web Push tests to root-signed pairing; refresh stale comments).
Scope read: `packages/relay/src/{web-push,push,well-known,index}.ts`, `packages/relay/test/{web-push,web-push-relay,push}.test.ts`, the doc diffs (`relay-api.md`, `relay-deploy.md`, `threat-model.md`, `architecture.md`).

## Gate

| Step | Result |
| --- | --- |
| `cargo fmt --check` / `cargo clippy --all-targets --locked -- -D warnings` / `cargo check --locked` / `cargo test --locked` | pass |
| `pnpm install` | pass |
| `pnpm run build:wasm` | could not run as written: the sandbox can't download binaryen, so `wasm-opt` failed. I ran the same `wasm-pack build … --release --no-opt` plus `postbuild-wasm.mjs` instead, which passed. This is an environment problem, not the PR. |
| `pnpm -r build` / `typecheck` / `lint` | pass |
| `pnpm -r test` | relay **214/214 pass**. sdk, approver, hook, web-approver, walking-skeleton and the other packages all pass. **One codex-hook test fails** (`integration.test.mjs:207`, "no approver response … category=timeout", `cancelledByParent: Promise resolution is still pending but the event loop has already resolved`). It fails on serial re-runs too, so it isn't the known concurrency flake. The PR changes nothing that codex-hook depends on (it uses a relay double; the diff is relay + docs only), and the sandbox runs Node 22 while the repo requires Node ≥24. **Not attributed to this PR**, but I did not confirm on main. |
| `prettier --check` | pass |

## Findings (ranked)

### 1. should-fix — An unauthenticated submit triggers a real Web Push to every registered token, with no rate limit or coalescing
- **Where:** `packages/relay/src/index.ts:1427` (`schedulePushWakeups` from `handleSubmit`); `handleSubmit` has no caller auth.
- **Scenario:** Anyone who knows an account id can POST junk envelopes (fresh `id`, junk `context_ciphertext`, future `expires_at`) to `/{acct}/requests`. Each one fans out up to 32 real, VAPID-signed POSTs to Google, Mozilla, Apple or Microsoft. The account budget limits the cost **per submit**; nothing limits submits. Before this PR the `webpush` transport did nothing, so this PR turns that into real traffic. Two consequences:
  - (a) **Notification spam and approval fatigue on the user's browser.** Browsers require `userVisibleOnly`, so the service worker must show a notification for every push (Safari revokes the subscription otherwise).
  - (b) **Every account on the relay is affected.** One VAPID key is shared across all of them, so a single abused account can get that key throttled or blocked by push services.
- The threat-model checklist line this PR adds ("budgeted … can neither stall nor fail a submit") is true, but it doesn't mention this amplification. The "no rate limits or quotas (#248)" residual covers it only implicitly.
- **Fix:**
  - Coalesce Web Push per token: skip if a wakeup to that `(device_id, token)` is in flight or was sent within the last N seconds. Because the wakeup is payload-less ("go check your inbox"), coalescing loses nothing, and it caps push volume at 1/N s per subscription no matter how fast submits arrive.
  - Name this vector explicitly in the threat-model push row and link it to #248.
- **REPRODUCED:** I added a vitest-pool-workers case to a temporary copy of `web-push-relay.test.ts`. Pairing with 2 Web Push tokens, then sending 10 `POST /requests` with **no Authorization header** and junk ciphertext, makes the injected fetcher get called **20 times**. The test passed. I removed the file afterwards.

### 2. should-fix (low) — The URL fragment is kept in the stored endpoint, so one subscription can be stored as several rows
- **Where:** `packages/relay/src/index.ts:362-366` (normalization stores `endpoint.href`); `web-push.ts:70-87` (no hash check).
- **Scenario:** `…/fcm/send/X#a` and `…/fcm/send/X#b` are accepted as two distinct rows. `fetch` drops the fragment, so both POST to the same subscription:
  - two pushes per submit to one browser;
  - the per-transport and account budgets are used up by duplicates.
- This contradicts `relay-api.md` §3: "stored in normalized form (`URL.href`), so two spellings of one subscription are one token". A query string is a real difference on the wire; a fragment is not.
- **Fix:** In `parseWebPushEndpoint`, reject a non-empty `url.hash` (a real `PushSubscription.endpoint` never has one), or clear it before taking `href`. Add a test.
- **REPRODUCED:** temporary relay test. Pairing with those two tokens returns 201 and stores 2 rows.

### 3. nit — `push_wakeups` counts tokens whose transport is the no-op, which the docs say it shouldn't
- **Where:** `index.ts:1988-2008` (`buildPushTransports` always registers a `NoopPushTransport` for every kind, including `webpush` when VAPID is unset), so `schedulablePushTokens` never filters anything out. `relay-api.md` §5 says the count is "tokens with a configured transport".
- **Scenario:** On a relay without VAPID configured, submit responds `push_wakeups: 1` for one `webpush` token that is never sent. The SDK or ops dashboards will over-report reach.
- **Fix:** Either leave unconfigured transports out of the registry, or fix the doc wording ("registered tokens", including no-op transports).
- **REPRODUCED:** temporary relay test on the default test Worker (no VAPID bindings); `push_wakeups` was 1.

### 4. nit — The allowlist is looser than it needs to be: any-depth `*.notify.windows.com`, and any path or query on allowlisted hosts
- **Where:** `web-push.ts:50,83-85`.
- **Scenario:** These are accepted (WHATWG parser, same semantics as workerd):
  - `https://a.b.notify.windows.com/…`, `https://..notify.windows.com/…`, `https://-.notify.windows.com/…`, `https://169.254.169.254.notify.windows.com/…`
  - `https://fcm.googleapis.com/../../v1/projects/p/messages:send`, which normalizes to the FCM v1 admin API path.
- Every target is still a push provider's own host and the only credential sent is the VAPID JWT, so I found **no off-allowlist SSRF**. It's still a broader surface than real subscriptions use.
- **Fix:**
  - Match WNS with `^[a-z0-9-]+\.notify\.windows\.com$` (one label).
  - Optionally require a per-host path prefix: FCM `/fcm/send/` or `/wp/`, Mozilla `/wpush/`, WNS `/w/`.
- **REPRODUCED:** node probe of the same parser logic (scratch script).

### 5. nit — A token that fails the allowlist at send time is pruned permanently, despite the "transient by default" stance
- **Where:** `web-push.ts:230-233`; this conflicts with the `push.ts` doc comment ("a … relay misconfiguration can never silently unregister a device").
- **Scenario:** A future change that narrows the allowlist, or a regression in `parseWebPushEndpoint`, would delete every affected device's registration on the next submit with no signal. The legacy-row cleanup it was written for is a one-time migration concern.
- **Fix:** Either treat a send-time allowlist miss as transient and skip it (refuse to send, keep the row, log it), or keep the prune and reword the `push.ts` comment to admit this exception. Your call (see design decisions).
- **Reasoned** (the PR's own test `prunes a stored row that fails the allowlist` shows the behaviour).

### 6. nit — The TTL header tells the push service each request's deadline
- **Where:** `web-push.ts:243,292-295`.
- **Scenario:** Because `TTL` is the remaining lifetime to the second, the push provider learns each request's `expires_at`. That's metadata beyond a bare wakeup, and integrator policy (e.g. a per-tool timeout) may shape it. It's small next to timing, but the docs sell this as "no payload at all".
- **Fix:** Quantize the TTL to a few buckets (e.g. 60 s / 5 min / 1 h / 1 d / 28 d, rounding up), or use one constant. Note the metadata in the threat-model push row.
- **Reasoned.**

### 7. nit — The "token kept" relay tests pass on a fixed 50 ms sleep, so they could pass without testing anything
- **Where:** `web-push-relay.test.ts` `settle()` and its callers (the 401/403/429/5xx, network-error and timeout keep-tests).
- **Scenario:** These negative assertions ("token still present") run after a fixed `setTimeout(50)`. On a slow runner, a wrong DELETE that lands after 50 ms would let the test pass anyway.
- **Fix:** Expose the fan-out promise to tests (e.g. keep the last `deliverPushWakeups` promise on the DO, test-only), await it, then assert.
- **Reasoned.**

### 8. nit — Some new behaviours have no direct test
- (a) After a budget 409, retrying **the same** pairing code works. The docs promise "code not consumed", but the PR's test pairs with a fresh code. I REPRODUCED that it works (temporary test: 409, then the same code without tokens gives 201), so only the test is missing.
- (b) Allowlist edge cases: trailing-dot host, fragment (see #2), IP-literal or odd labels under the WNS suffix, `:443` normalization (covered only at relay level).
- (c) `MAX_PUSH_TOKENS_PER_REGISTRATION` at exactly 4 (the accept boundary).

### 9. nit — Legacy accounts with more than 32 rows: the newest rows are silently never woken or pruned
- **Where:** `index.ts:1479-1482` (`ORDER BY created_at ASC LIMIT 32`).
- **Scenario:** Only accounts created before the budget existed can hold more than 32 rows. They then (a) always get 409 on registration and (b) never wake their newest devices.
- **Fix:** Order by `created_at DESC`, or trim to budget in a one-off migration.
- **Reasoned.**

## Design decisions for Mike

1. **Coalescing versus a rate limit (finding 1).** The cheapest strong mitigation is per-subscription coalescing; a payload-less wakeup is idempotent. Do you want that in this PR, or tracked under #248 with an explicit threat-model line?
2. **Prune on allowlist miss (finding 5):** permanent deletion versus refuse-and-keep.
3. **CORS.** The relay sets no CORS headers anywhere, and `/.well-known/allw/vapid-public-key` is meant to be fetched by browsers. If the web approver is served from a different origin than the relay (it takes a configurable `relayUrl`), it can't read this key (or `/inbox` from its service worker) without `Access-Control-Allow-Origin`. That's out of this PR's scope, but it blocks the end-to-end browser flow this PR exists for.
4. **`userVisibleOnly` contract.** Payload-less pushes mean the service worker has to fetch `/inbox` (holding a device token) and then show a notification **every time**, or Chrome shows a generic notice and Safari revokes the subscription. That belongs in the web-approver design and makes finding 1 more serious.
5. **Status-code overloading.** A 404 from the VAPID key route covers both "not configured" and "misconfigured pair"; a 409 from pairing covers both "code used" and "budget full". Clients can only tell them apart by the error string. That's acceptable, but if the SDK needs to branch, consider machine-readable `error` codes.
6. **TTL quantization (finding 6).**

## What I tried that held up

- **SSRF host parsing:**
  - Uppercase host → normalized to the allowlisted host.
  - Fullwidth `ｆｃｍ` (IDN), `fcm%2Egoogleapis.com` → both normalize to `fcm.googleapis.com`, which is the same host, so no bypass.
  - Backslash/userinfo confusion (`fcm.googleapis.com\@evil.com` → host stays fcm; `evil.com\@fcm…`, `evil.com#@fcm…` → rejected).
  - `user@` → rejected; `:@` → empty credentials, normalized away.
  - Explicit `:8443` → rejected; `:443` and `:` → normalize to the default port.
  - Trailing dot `fcm.googleapis.com.` → rejected (fail-closed).
  - Lookalike suffix `fcm.googleapis.com.attacker.example` and `evilnotify.windows.com` → rejected.
  - Bare apex `notify.windows.com` → rejected.
  - `http:` and `ftp:` → rejected.
  - Tab, newline, or surrounding whitespace in the host → stripped by WHATWG, so it's still the allowlisted host.
  - **No input reached a host outside the allowlist.**
- **Redirects:** `redirect: "manual"`; a 3xx is transient and never followed (tested at 301).
- **Re-validation at send time:** stored rows are re-checked before every fetch, and the injected fetcher is never called for a non-allowlisted row.
- **VAPID JWT:**
  - `aud` = `endpoint.origin` (scheme+host, no path or trailing slash).
  - `exp` = now + 1 h, under RFC 8292's 24 h cap.
  - `sub` must be `mailto:<non-empty>` or `https:`; an `http:` subject or a bare email is refused.
  - Header is `{typ:JWT, alg:ES256}`.
  - The signature verifies against the configured public key (the test checks it with WebCrypto).
  - The keypair is checked by sign+verify, so mismatched and off-curve pairs disable both the transport and the key endpoint.
  - The private key is never returned (the endpoint body is exactly `{vapid_public_key}`).
- **No plaintext reaches a push service:**
  - The body is empty (byteLength 0 asserted, `Content-Encoding` absent).
  - The headers are only Authorization, TTL and Urgency; no request id, no ciphertext.
  - APNs and FCM are unchanged (request id only).
- **Prune semantics:**
  - Only `UndeliverablePushTokenError` prunes: 404/410 or an allowlist miss.
  - 400/401/403/413/429/5xx, 3xx, network errors and timeouts all leave the token.
  - The DELETE is keyed by `(device_id, transport, token)`. Device ids are random, and revocation deletes a device's rows, so a stale fan-out can't delete another device's row. Concurrent 404s just DELETE twice, which is idempotent.
- **Budget race:**
  - The count check (`pushTokenBudgetFailure`) runs after the last `await` and is synchronous with the inserts, so there's no TOCTOU between concurrent pairings in the DO.
  - The budget is checked after pairing-token auth, so its state isn't revealed to unauthenticated callers.
  - Over budget is rejected, never truncated.
  - Pairing is the only `INSERT INTO device_push_token` path, so there's no other way around the caps.
- **Fan-out:**
  - It runs under `ctx.waitUntil`. Per the Cloudflare docs, `waitUntil` on `DurableObjectState` prevents eviction until the promise settles (up to 15 min), so the background fan-out isn't cut short.
  - `dispatchPushWakeups` never throws.
  - At most 4 sends are in flight, with a 5 s `AbortSignal.timeout` each, and the response body is cancelled.
  - The submit returns 202 while a push hangs (tested).
- **`/.well-known` routing:**
  - It's claimed before account routing, and unknown sub-paths (including a trailing slash) are 404.
  - `/%2Ewell-known` falls through to the account `%2Ewell-known`, which is harmless.
  - The old `/push/vapid-public-key` path no longer serves the key.
- **Thin shell:** VAPID is a push-provider transport credential, not contract crypto. Keeping it in WebCrypto in the Worker is consistent with CLAUDE.md, and nothing contract-related was reimplemented in TS.
- **Contract invariants:** push is a wakeup optimization only. It never feeds a verdict, never returns allow, and a push failure can't affect fail-closed deny paths.
