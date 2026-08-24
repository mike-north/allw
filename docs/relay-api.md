# Relay HTTP + WebSocket API contract

Status: **active** · Owner: PM · The wire contract between client surfaces (the Apple approver app,
the web approver, integrators) and the zero-knowledge relay (`packages/relay`). Extracted from the
relay source + tests; this doc is the source of truth for client implementations.

> **Zero-knowledge.** The relay routes ciphertext (`context_ciphertext` JWE) and opaque signed
> verdicts (JWS). It never parses them and never sees plaintext, private keys, or push payloads with
> content. Honor `docs/contract.md` / `docs/threat-model.md` — clients decrypt/verify/sign **on
> device** via the core; the relay is a dumb router.

---

## 0. Base URL & environments

The relay is a Cloudflare Worker. **It is not yet deployed** — production `wrangler.jsonc` still has
`REPLACE_ME` and deploy is a human `[OPERATOR]` step (`docs/relay-deploy.md`). Point the app at a
**configurable base URL**, never a hardcoded host.

| Environment    | Base URL                                                                                             | How                                                   |
| -------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| **Local dev**  | `http://127.0.0.1:8787` (WS: `ws://127.0.0.1:8787`)                                                  | `cd packages/relay && node_modules/.bin/wrangler dev` |
| **Production** | custom domain (e.g. `https://relay.example.com`) **or** `https://allw-relay.<subdomain>.workers.dev` | `wrangler deploy --env production` (operator)         |

WebSocket endpoints use `ws://` / `wss://` matching the base scheme.

---

## 1. Conventions

- **Account prefix.** Every path is `/{account_id}/<subpath>`. `account_id` selects the per-account
  Durable Object.
- **Auth.** `Authorization: Bearer <token>` (token = base64url, `^[A-Za-z0-9_-]+$`, ~43 chars). For
  **WebSocket** upgrades (which can't easily set headers), pass `?auth=<token>` as a query param.
  The relay stores only `SHA-256(token)`; the plaintext is returned **once** at issuance — cache it.
  Missing token ⇒ **401**; wrong/expired/cross-scope token ⇒ **403**.
- **Four token scopes:**

  | Token                   | Issued by                     | Used for                                                                      | Lifetime                     |
  | ----------------------- | ----------------------------- | ----------------------------------------------------------------------------- | ---------------------------- |
  | `pairing_auth_token`    | `POST /pairing/start`         | `POST /pairing/complete`                                                      | 10 min (`PAIRING_TTL_MS`)    |
  | `enrollment_auth_token` | `POST /enrollments/start`     | `GET …/enrollments/{id}/csr`, `POST …/cert`, `POST …/abort` (the root holder) | 10 min (`ENROLLMENT_TTL_MS`) |
  | `device_auth_token`     | `POST /pairing/complete`      | all `devices/{id}/…`, `actors`, `account-states`, the enrollee's courier legs | until revoked                |
  | `request_auth_token`    | `POST /requests` (integrator) | `requests/{id}` polling/wait                                                  | 7 days post-terminal         |

- **Errors** are plain bodies with the status code; `400` covers malformed JSON / bad fields /
  unexpected envelope keys (zero-knowledge guard).

---

## 2. Approver-device client flow (what the Apple app does)

```
PAIR (once)
  POST /{acct}/pairing/start            → { code, expires_at, pairing_auth_token }
     (code reaches the device out-of-band — QR/deep-link/manual; UX layer, not relay)
  POST /{acct}/pairing/complete         (Bearer pairing_auth_token)
     body: { code, pubkey, label?, push_tokens? }   ← APNs token goes HERE
                                        → { device_id, device_auth_token }   (cache both)

GET A device_cert (once, right after pairing — you cannot approve without one)
  POST /{acct}/enrollments/{id}/csr     (Bearer device_auth_token)
     body: { csr: {…signing_pubkey…}, mac }        ← mac keyed by the out-of-band enrollment secret
  GET  /{acct}/enrollments/{id}/cert    (Bearer device_auth_token; poll)
                                        → { status:"issued", device_cert }
     VERIFY it against your pinned account-root pubkey before persisting. See §3 Enrollment courier.

RECEIVE PENDING  (pick one; native app SHOULD use the WebSocket)
  A) GET  /{acct}/devices/{device_id}/inbox        (Bearer device_auth_token)
        → { envelopes: [ ApprovalEnvelope … ] }    (poll, 1–5s)
  B) GET  /{acct}/devices/{device_id}/connect?surface_id=…&auth=<device_auth_token>  (WebSocket)
        ← { type:"request", request_id, envelope }   (on connect: offline queue flush; then live)
        ← { type:"retract", request_id }             (another surface/device resolved it, or expired)

DECRYPT / VERIFY / RENDER  (on device, via AllwIOSApprover → UniFFI → core; NOT the relay)

SUBMIT VERDICT   ⚠ WebSocket ONLY — there is no HTTP verdict endpoint
  → { type:"verdict", request_id, verdict }   (verdict = JWS signed by the device key)
  ← { type:"ack", request_id, status:"resolved" | "already_resolved" | "expired" }

REFRESH TRUST  (periodically, to verify actor attestation / feed AccountStateResolver)
  GET /{acct}/account-states            (Bearer device_auth_token)
     → { account_states: [ <compact JWS> … ], max_sequence }
```

**Mapping to the `AllwIOSApprover` package seams:**

| Need                                     | Endpoint                             | Package seam                                                                                                                                                                                                                                                        |
| ---------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pair + store creds                       | `pairing/start` + `pairing/complete` | persist via `NativeCredentialStore` (`device_id`, `device_auth_token`, account-root pubkey)                                                                                                                                                                         |
| Obtain the `device_cert`                 | `enrollments/{id}/csr` + `…/cert`    | scan the enrollment QR, generate keys on-device, deposit the MAC'd CSR, poll for the cert, verify against the pinned root, persist via `NativeCredentialStore` — no cert ⇒ no inbox                                                                                 |
| Register APNs token                      | `push_tokens` in `pairing/complete`  | `PushTokenRegistering` / `HexApnsTokenRegistrar` `send` closure posts it here                                                                                                                                                                                       |
| Poll inbox                               | `GET …/inbox`                        | `RelayInboxFetching` / `UrlSessionRelayInboxClient.fetchPendingEnvelopes()`                                                                                                                                                                                         |
| Live push + **verdict submit + retract** | `…/connect` WebSocket                | **NOT in the package yet — the app builds this WS client.** Feed `{type:"request"}` into `ApprovalInboxStore.sync`; on resolve, send the `SignedVerdict.signedVerdictJson` as `{type:"verdict"}`; on `{type:"retract"}` clear via `PushInboxCoordinator.didResolve` |
| Verify origins (VERIFIED badge)          | `GET …/account-states`               | the `AccountStateResolver` feed (#155); verify root sig on device, keep a highest-sequence floor                                                                                                                                                                    |

> ⚠ **Build note for the Xcode agent:** the package fetches the inbox but does **not** implement the
> `/connect` WebSocket or verdict submission. The app must implement the WS client (URLSessionWebSocketTask):
> send `{type:"verdict", request_id, verdict}` with the `SignedVerdict` JSON the core produced, handle
> the `ack` (`already_resolved`/`expired` are fail-closed terminal states), and handle inbound
> `request`/`retract`. Inbox-poll is the fallback when the socket is down (fail-closed: never show an
> approvable item you couldn't fetch/verify).

---

## 3. Endpoint reference

### Pairing

**`POST /{acct}/pairing/start`** — no auth. Body `{ label?: string }`. → **201**
`{ code: string (8-char Crockford base32), expires_at: number(ms), pairing_auth_token: string }`.
Code is single-use, 10-min TTL.

**`POST /{acct}/pairing/complete`** — Bearer `pairing_auth_token`. Body:

```json
{
  "code": "string",
  "pubkey": "base64url 32-byte key, 43 chars",
  "label": "string (optional)",
  "push_tokens": [{ "transport": "apns" | "fcm" | "webpush", "token": "string" }]
}
```

→ **201** `{ device_id: string, device_auth_token: string }`. APNs `token` = 64-char hex.
Errors: 400 (bad body/pubkey/push_token/unexpected key), 401/403 (token), 404 (code unknown),
409 (code already used), 410 (code expired). Atomic — no half-enrollment.

### Enrollment courier (cross-device `device_cert` issuance, #175)

Two write-once mailboxes that carry a **certificate signing request** from a new device to the account-root
holder, and the issued **`device_cert`** back. Full ceremony, derivations, and failure semantics:
`docs/enrollment.md` §Cross-Device `device_cert` Issuance Ceremony.

> **The relay is a courier, not a validator.** It stores an opaque CSR object and an opaque compact JWS. It
> **never** checks `mac` (it holds no key that could), **never** parses or validates `device_cert`, and is never
> a trust anchor for either. Its shape/ownership checks below are anti-abuse only. The `enrollment_secret` that
> keys the CSR MAC travels **only** out of band (QR / pasted link) and must never appear in any request to the
> relay.

**`POST /{acct}/enrollments/start`** — no auth (account-owner ceremony boundary, same rationale as
`pairing/start`). Body `{ label?: string }`. → **201**
`{ enrollment_id: string (base64url 16 bytes), expires_at: number(ms), enrollment_auth_token: string }`.
Single-use, 10-min TTL.

**`POST /{acct}/enrollments/{enrollment_id}/csr`** — Bearer `device_auth_token` (the **enrollee**). Body:

```json
{
  "csr": {
    "v": 1,
    "enrollment_id": "string",
    "account_id": "string",
    "device_id": "string",
    "signing_pubkey": "base64url 32-byte Ed25519 key, 43 chars",
    "encryption_pubkey": "base64url 32-byte X25519 key, 43 chars",
    "label": "string (optional)",
    "purpose": "enroll" | "rotate",
    "created_at": 0
  },
  "mac": "base64url HMAC-SHA256, 43 chars"
}
```

→ **201** `{ status: "awaiting_cert" }`. Errors: `400` (malformed body, bad pubkey/mac encoding, unexpected key,
body > 4 KiB), `401`/`403` (missing/wrong device token), **`403` when `csr.device_id` is not the authenticated
device** (a device may only request a certificate for itself), `404` (unknown enrollment), `409` (a CSR is
already stored, or the enrollment was aborted/issued — write-once), `410` (enrollment expired).

**`GET /{acct}/enrollments/{enrollment_id}/csr`** — Bearer `enrollment_auth_token` (the **root holder**). → **200**
`{ status: "awaiting_csr" }` while empty, or `{ status: "awaiting_cert", csr: {…}, mac: "…" }`. `404` unknown,
`409` aborted, `410` expired. The relay returns the deposited bytes verbatim; the root holder authenticates them
with the MAC before trusting any field.

**`POST /{acct}/enrollments/{enrollment_id}/cert`** — Bearer `enrollment_auth_token`. Body
`{ device_cert: string (compact JWS, ≤ 4 KiB) }` → **200** `{ issued: true }`. `400` (malformed/oversized),
`404`, `409` (already issued, aborted, or no CSR deposited yet), `410` (expired). Stored opaquely.

**`GET /{acct}/enrollments/{enrollment_id}/cert`** — Bearer `device_auth_token`, and only for the device that
deposited the CSR (cross-device ⇒ `403`). → **200** `{ status: "pending" }` or
`{ status: "issued", device_cert: "<compact JWS>" }`. `409` aborted, `410` expired. **Verify the cert against
your pinned account-root pubkey before persisting anything** — signature, `typ`/`kid`, `account_id`, `device_id`,
`device_pubkey` == your own signing key, `expires_at`. A failing cert is discarded, never stored.

**`POST /{acct}/enrollments/{enrollment_id}/abort`** — Bearer `enrollment_auth_token`. → **200**
`{ aborted: true }`. Terminal: both mailboxes answer `409` afterwards, so the enrollee learns the ceremony died
instead of timing out silently. The root holder MUST call this on MAC failure, confirmation-code mismatch, a
declining human, or a revoked `device_id`.

Polling is the v1 delivery mechanism for both sides (2 s interval, bounded by the enrollment TTL); a socket
wakeup would shorten the ceremony but changes no trust property.

### Device (approver) endpoints — Bearer `device_auth_token`

**`GET /{acct}/devices/{device_id}/inbox`** → **200** `{ envelopes: [ ApprovalEnvelope ] }` —
pending only, `expires_at > now`, oldest first. (404 if device not enrolled.)

**`GET /{acct}/devices/{device_id}/connect?surface_id=…`** — WebSocket (101). See §4.
`surface_id` (optional, 1–128 `[A-Za-z0-9._:-]`) dedupes delivery to **one socket per surface**
(e.g. a Mac + a Mirrored iPhone on one screen get one notification). 426 if not a WS upgrade.

**`POST /{acct}/devices/{device_id}/revoke`** — Bearer the device's own token (self-revoke only;
cross-device ⇒ 403). → **200** `{ revoked: true }`. Closes the live socket (1008). 404 if not enrolled.

**`GET /{acct}/devices`** — no auth. → **200**
`{ devices: [{ device_id, pubkey, label|null, created_at }] }`. No secrets / no push tokens.

### Actors (requester attestation) — Bearer `device_auth_token` for POST

**`POST /{acct}/actors`** body `{ actor_id, pubkey (Ed25519, 43 chars), label? }` → **201**
`{ actor_id }`. 409 if `actor_id` already enrolled. **`GET /{acct}/actors`** (no auth) → **200**
`{ actors: [{ actor_id, pubkey, label|null, created_at }] }`.

### Account state (trust distribution) — Bearer `device_auth_token`

**`GET /{acct}/account-states`** → **200**
`{ account_states: [ "<compact JWS>" … ], max_sequence: number }`. Opaque JWS — **verify the
account-root signature on device**; reject rollbacks below your highest-verified sequence floor.
**`POST /{acct}/account-states`** body `{ account_states: string[] (≤16, ≤32KiB each), max_sequence }`
→ **200** (echo). 409 on `max_sequence` regression.

### Integrator endpoints (the app does NOT call these — listed for completeness)

**`POST /{acct}/requests`** — no auth; submits the `ApprovalRequest` envelope (only keys `v`, `id`,
`created_at`, `expires_at`, `approver`, `context_ciphertext`, `action_structure?`,
`privacy_preference?`-reserved; any other key ⇒ 400; `expires_at ≤ now` ⇒ 400). → **202**
`{ request_id, status:"pending", delivered_to, push_wakeups, request_auth_token }`. 409 on dup `id`.
**`GET /{acct}/requests/{id}`** and **`GET /{acct}/requests/{id}/wait`** (WS) — Bearer
`request_auth_token`; poll/await `{ status, verdict? }`.

---

## 4. WebSocket protocol — `/{acct}/devices/{device_id}/connect`

Upgrade with `?auth=<device_auth_token>` (or Bearer header). On connect the relay flushes the
offline queue (still-pending, non-expired) as `request` messages. Hibernatable.

**relay → device**

- `{ "type": "request", "request_id": string, "envelope": ApprovalEnvelope }`
- `{ "type": "retract", "request_id": string }` — resolved elsewhere or expired; clear the notification.
- `{ "type": "error", "error": string }` — your last message was malformed.

**device → relay**

- `{ "type": "verdict", "request_id": string, "verdict": <Verdict object> }` — the JWS-signed
  decision (the `SignedVerdict.signedVerdictJson` the core produced; see `docs/contract.md` Verdict).
- relay replies `{ "type": "ack", "request_id": string, "status": "resolved" | "already_resolved" | "expired" }`.
  Idempotent: a second verdict is `already_resolved` (not overwritten); a verdict past `expires_at`
  is `expired` (rejected, fail-closed).

Only device sockets may submit verdicts. On the first valid verdict the relay marks the request
`resolved`, retracts it from other device sockets, and pushes it to any waiting integrator.

### `ApprovalEnvelope` (relay-visible; wire field names)

```json
{
  "v": 1,
  "id": "string (request_id)",
  "created_at": 0,
  "expires_at": 0,
  "approver": "string (routing id)",
  "context_ciphertext": "string (JWE — decrypt on device)",
  "action_structure": null
}
```

(The Swift `ApprovalEnvelope` mirrors this in camelCase: `createdAt`, `expiresAt`,
`contextCiphertext`. `action_structure` is the structure-not-data view, #131 — never carries args/values.)

---

## 5. Push wakeups

Integrator submission fans out **request-id-only** wakeups (no context, not E2EE) to registered
tokens. APNs payload: `{ "aps": { "content-available": 1 }, "request_id": "…" }`. The device wakes,
then fetches the full envelope via the socket or `/inbox`. (WebPush reserved, not in v1.)

---

## 6. Known gaps / client-owned concerns

1. **Pairing-code delivery** (QR / deep-link / manual entry) is a UX layer — not defined by the relay.
2. **`device_cert`** (binds the device signing key to the account root) is signed by the **account-root
   holder** and persisted **on device**; the relay never issues or validates it. A device that is not the root
   holder obtains one through the enrollment courier (§3) — the relay stores the CSR and the cert as opaque
   bytes and can neither forge nor authenticate either. Include the cert in verdicts per the Verdict schema.
3. **Verdict submission is WS-only** (§2 build note) — there is no HTTP fallback today. If the app
   needs an HTTP verdict path (e.g. background-task constraints), that's a relay change — file an issue.
4. **Account-state signing/publishing** (who holds the root, how docs are produced) is out of relay
   scope; the relay is a distribution cache. Verify on device.
5. **Number-match challenge** is derived + verified on device (`docs/contract.md`); the relay never
   sees it.

## 7. Integration clarifications (client FAQ)

Answers to load-bearing client questions, confirmed against the relay source + the reference
`packages/approver` client.

1. **`verdict` is a JSON object, not a string.** The `{type:"verdict", request_id, verdict}` message
   must embed the **parsed** Verdict object (the relay rejects a scalar/string:
   `isPlainObject(msg.verdict)` ⇒ else `{type:"error"}`). The core's `sign_verdict_json` returns the
   canonical Verdict **object** JSON (`{ v, request_id, request_hash, decision, decided_at,
approver:{account_id,device_id}, sig:<compact JWS>, note?, challenge_response?, device_cert? }`) —
   `JSON.parse` it and inline the object. The relay stores it opaquely and forwards the object to the
   integrator; only `sig`/`device_cert` carry the cryptography (verified downstream, never by the relay).

2. **`ack` reconciliation.** The relay replies `{type:"ack", status}`:
   - `resolved` — your verdict won; row is terminal.
   - `already_resolved` — another surface/device (or a retry) resolved it first; **your verdict was not
     recorded.** Treat as resolved-elsewhere: clear the row (it will also arrive as a `retract`).
   - `expired` — the request passed its deadline before your verdict landed; **refused, fail-closed.**
     Surface this to the user ("expired before your approval reached the relay") — they must not believe
     it took effect.

   Keep the package's local terminal commit in `decide()` (sign-failure already restores `.pending`);
   treat a **non-`resolved` ack as a correction** and reconcile (a `GET /inbox` is the simplest
   authoritative re-sync). Don't gate the local commit on the round-trip.

3. **WebSocket lifecycle.** Model: a persistent socket **while foregrounded**; in the background, the
   APNs wake → `GET /inbox` (no socket needed). Verdict submission is WS-only, but approving requires
   biometric (⇒ foreground), so the socket is naturally live at verdict time — **no background verdict
   submission is expected.** The relay sends no server pings and requires none (it ignores unknown
   message types). Use a protocol-level WS **ping ~30 s** to survive idle-connection drops by
   intermediaries; on drop, **reconnect with exponential backoff + jitter** (e.g. 1→2→4→…→cap 30 s).
   On every (re)connect the relay auto-flushes the offline queue; also `GET /inbox` to reconcile.

4. **`surface_id` = a stable per-install UUID** (persist it), **not** the `device_id`. The socket is
   already tagged `device:{device_id}`; `surface_id` is a finer "visible screen" key so the relay fans
   out **one push per surface** (dedup across a Mac + a Mirrored iPhone on the same screen). For v1, one
   UUID per app install is correct (each install = its own surface). Cross-device same-screen dedup is a
   post-v1 refinement.

5. **Inbound `request` vs `sync()`.** Endorsed approach: keep an authoritative in-memory envelope set;
   on (re)connect treat `GET /inbox` as the **full truth**; apply WS `request` (union) / `retract`
   (remove) as deltas; call `ApprovalInboxStore.sync(fullSet)` with the maintained set. WS-delivered
   envelopes may be rendered **directly** — security comes from on-device `prepare()` (decrypt+verify,
   fail-closed), not from the transport — so no per-message `/inbox` round-trip is needed; reconcile
   with `/inbox` on connect and periodically.

6. **Pairing & `device_cert` (read carefully — the relay is a single-key surface).**
   - `POST /pairing/complete` registers **exactly one `pubkey` = the device X25519 _encryption_ key**
     (used by integrators to JWE-encrypt to the device). The Ed25519 **signing** key is **not** sent to
     the relay — by design, so the relay is never the carrier of the verdict-key binding. It is certified
     out of band instead (`enrollment.md` §Pairing Flow step 3 documents this single-key surface).
   - The device also needs a **`device_cert`** — an account-root-signed JWS binding its Ed25519 signing
     pubkey (`issue_device_cert`). **The relay does NOT issue or validate it.** Verdicts without a valid
     `device_cert` are denied by integrators (`enrollment.md` §Device Certificate Validation).
   - Who calls `/pairing/start`: the **account owner** (the root-seed holder), or the reference
     `allw-approver pair` CLI drives `start` itself when `--code` is omitted. The new device calls only
     `/pairing/complete` with the `pairing_auth_token` shown out-of-band.
   - **Cross-device issuance (resolved, #175):** the walking-skeleton CLI holds the account-root seed and
     self-mints its own cert; the phone and the web approver are **not** root holders. They generate their
     keys on-device (signing key never exported), complete relay pairing with the encryption pubkey, then
     deposit a **MAC-authenticated CSR** in the enrollment courier (§3). The root holder verifies the MAC
     under a secret carried only in the out-of-band enrollment bundle (QR or pasted link), confirms a
     six-digit code shown on both screens, issues the cert, and deposits it for collection. Full spec:
     `docs/enrollment.md` §Cross-Device `device_cert` Issuance Ceremony. A dev-only provisioning bundle
     with a pre-issued `device_cert` remains acceptable **in development builds only** and must never
     carry the device _signing seed_.
   - **Onboarding UX:** a **single QR / `allw://enroll#…` link** carries the whole enrollment bundle
     (`relay_url`, `account_id`, `account_root_pubkey`, pairing `code`, `pairing_auth_token`,
     `enrollment_id`, `enrollment_secret`) — do **not** make the user hand-type a ~43-char token. The
     payload rides in the URL **fragment** so a bundle pasted into a browser never reaches a server; that
     paste is the web approver's first-class path, not a fallback.

## References

`docs/contract.md` (wire types: envelope, Verdict, ApprovalContext, WYSIWYS), `docs/enrollment.md`
(pairing, account state, revocation), `docs/relay-deploy.md` (operator deploy), `docs/apple-approver-app.md`
(the app spec). Relay source: `packages/relay/src/index.ts`; reference client: `packages/approver`.
