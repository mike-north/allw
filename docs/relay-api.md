# Relay HTTP + WebSocket API contract

Status: **active** · Owner: PM · The wire contract between client surfaces (the Apple approver app,
the web approver, integrators) and the zero-knowledge relay (`packages/relay`). Extracted from the
relay source + tests; this doc is the source of truth for client implementations.

> **Zero-knowledge.** The relay routes ciphertext (`context_ciphertext` JWE) and opaque signed
> verdicts (JWS). It never parses them and never sees plaintext, private keys, or push payloads with
> content. Honor `docs/contract.md` / `docs/threat-model.md` — clients decrypt/verify/sign **on
> device** via the core; the relay is a dumb router.
>
> **Not yet zero-knowledge against the relay itself:** integrators encrypt to the device list the relay
> serves (`GET /{acct}/devices`, unauthenticated, not root-vouched), so a malicious relay can add a
> recipient key it holds. Fix: encrypt only to root-vouched devices (#243) from verified account state
> (#242). See `docs/threat-model.md` §Residual Risks.

---

## 0. Base URL & environments

The relay is a Cloudflare Worker. A production deploy is live at `https://allw-relay.mnorth.workers.dev`
(the hosted relay `docs/quickstart.md` defaults new users to); operators may also deploy their own
per `docs/relay-deploy.md`. Point the app at a **configurable base URL**, never a hardcoded host.

| Environment          | Base URL                                                                                             | How                                                   |
| -------------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| **Local dev**        | `http://127.0.0.1:8787` (WS: `ws://127.0.0.1:8787`)                                                  | `cd packages/relay && node_modules/.bin/wrangler dev` |
| **Hosted (default)** | `https://allw-relay.mnorth.workers.dev`                                                              | Already deployed — no operator step needed            |
| **Self-hosted prod** | custom domain (e.g. `https://relay.example.com`) **or** `https://allw-relay.<subdomain>.workers.dev` | `wrangler deploy --env production` (operator)         |

WebSocket endpoints use `ws://` / `wss://` matching the base scheme.

---

## 1. Conventions

- **Account prefix.** Every path is `/{account_id}/<subpath>`. `account_id` selects the per-account
  Durable Object. Account ids are **self-certifying**:
  `base64url-unpadded(SHA-256("allw/account-id/v1" || 0x00 || account_root_pub))` — 43 characters, derived from
  the account-root public key (`docs/enrollment.md` §Self-Certifying Account Id). Root-signed calls present the
  root key and the relay rejects an id it cannot re-derive from it.
- **Relay-level namespace.** The one exception to the account prefix is `/.well-known/allw/…` (RFC 8615,
  §3). The router claims the whole `/.well-known` segment before account routing, so it never reaches an
  account; a leading `.` is outside the base64url alphabet account ids use, so it cannot collide with one.
  Every relay-level route, present or future, lives there.
- **Auth.** `Authorization: Bearer <token>` (token = base64url, `^[A-Za-z0-9_-]+$`, ~43 chars). For
  **WebSocket** upgrades (which can't easily set headers), pass `?auth=<token>` as a query param.
  The relay stores only `SHA-256(token)`; the plaintext is returned **once** at issuance — cache it.
  Missing token ⇒ **401**; wrong/expired/cross-scope token ⇒ **403**.
- **Public keys.** Every key field the relay accepts (`root_pubkey`, a device or actor `pubkey`) is
  the **canonical** base64url-unpadded encoding of 32 bytes: 43 characters, with the 2 unused low bits
  of the last one zero, so re-encoding the bytes gives back the same string. Anything else is a **400**,
  never stored. A stray-bit key such as `…AAAB` decodes leniently, but the core rejects it.
- **Token scopes** (three implemented; `enrollment_auth_token` is specified only):

  | Token                   | Issued by                     | Used for                                                            | Lifetime                  |
  | ----------------------- | ----------------------------- | ------------------------------------------------------------------- | ------------------------- |
  | `pairing_auth_token`    | `POST /pairing/start`         | `POST /pairing/complete`                                            | 10 min (`PAIRING_TTL_MS`) |
  | `enrollment_auth_token` | `POST /enrollments/start`     | **specified, not implemented (#199)** — the enrollment courier (§3) | 10 min (specified)        |
  | `device_auth_token`     | `POST /pairing/complete`      | all `devices/{id}/…`, `actors`                                      | until revoked             |
  | `request_auth_token`    | `POST /requests` (integrator) | `requests/{id}` polling/wait, `requests/{id}/retract`               | 7 days post-terminal      |

- **CORS (browser clients).** A browser page may call the relay only from an allowlisted origin
  (`CORS_ALLOWED_ORIGINS`, `docs/relay-deploy.md` §2; the hosted relay allows
  `https://allw-web-approver.pages.dev`). The policy covers every route, account and relay-level
  (`/.well-known/allw/…`, e.g. the VAPID public key) alike. Preflights (`OPTIONS` with `Access-Control-Request-Method`)
  from an allowed origin get **204** with `Access-Control-Allow-Methods: GET, POST, PUT`,
  `Access-Control-Allow-Headers: Authorization, Content-Type` and `Access-Control-Max-Age: 600`.
  Responses to an allowed origin echo it in `Access-Control-Allow-Origin`. A disallowed origin,
  method or header gets a **403** preflight with no CORS headers. Every response except a WebSocket
  upgrade (101, returned untouched) carries `Vary: Origin`, including a 500 when a handler fails. There is no credentials mode (`Access-Control-Allow-Credentials` is never sent):
  auth is the bearer header, never a cookie. CORS does not apply to WebSocket upgrades, and the relay
  does not check `Origin` there, since the socket authenticates with `?auth=`. Non-browser clients
  send no `Origin` and are unaffected.
- **Errors** are plain bodies with the status code; `400` covers malformed JSON / bad fields /
  unexpected envelope keys (zero-knowledge guard).
- **Abuse limits (#248).** `413` = body or `context_ciphertext` too large. Treat it as "not
  submitted": an integrator fails closed (deny), never retries into an approval.
- **Pairing body cap.** `POST /pairing/start` and `POST /pairing/complete` bodies above
  `MAX_PAIRING_BODY_BYTES` (16 KiB) are refused with **413** before parsing.
- **Exact paths.** An account route answers only on its exact path, compared segment by segment as the URL
  parser yields them (percent-encoding preserved, `.` and `..` segments resolved): the same number of segments, every literal equal, and every `{param}` non-empty
  (#302). Anything else is **404** `{ "error": "not found" }`, whatever the method: an extra segment
  (`…/revoke/extra`), a trailing slash (`/devices/`), an empty segment (`/devices//revoke`) or a missing
  one. A path that is exactly a route's, reached with a method the route doesn't serve, is **405**
  `{ "error": "method not allowed" }`. Dropping or adding a segment can still land exactly on _another_
  route: `/requests/r1` is `GET /requests/{request_id}`, and `/requests/extra` is the same route with
  `request_id = extra`. The route table is `packages/relay/src/routes.ts`.

---

## 2. Approver-device client flow (what the Apple app does)

```
PAIR (once)
  POST /{acct}/pairing/start            (account-root holder only; root-signed)
     body: { root_pubkey, authorization, label? }
                                        → { code, expires_at, pairing_auth_token }
     (code reaches the device out-of-band — QR/deep-link/manual; UX layer, not relay)
  POST /{acct}/pairing/complete         (Bearer pairing_auth_token)
     body: { code, pubkey, label?, push_tokens? }   ← APNs token goes HERE
                                        → { device_id, device_auth_token }   (cache both)

GET A device_cert (once, right after pairing — you cannot approve without one)
  ⚠ SPECIFIED, NOT IMPLEMENTED (#199): the relay has no /enrollments/* routes today (they 404).
  Today the account-root holder mints the cert off-relay (issue_device_cert) and provisions it.
  Specified flow:
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
        ← { type:"retract", request_id }             (resolved/expired elsewhere, or the integrator cancelled it — #195)

DECRYPT / VERIFY / RENDER  (on device, via AllwIOSApprover → UniFFI → core; NOT the relay)

SUBMIT VERDICT   ⚠ WebSocket ONLY — there is no HTTP verdict endpoint
  → { type:"verdict", request_id, verdict }   (verdict = JWS signed by the device key)
  ← { type:"ack", request_id, status:"resolved" | "already_resolved" | "expired" | "retracted" }

SUBSCRIBE / ROTATE PUSH  (any time after pairing; e.g. a browser's Web Push subscription)
  PUT /{acct}/devices/{device_id}/push-tokens   (Bearer device_auth_token; self only)
     body: { push_tokens: [{ transport, token }] }   ← REPLACES this device's set; [] clears
                                        → { push_tokens }   (the stored set)
     Re-send whenever the platform token or subscription changes (rotation, re-subscribe after a
     VAPID key rotation, permission revoked → []). Repeating the same body is a no-op.

REFRESH TRUST  (periodically, to verify actor attestation / feed AccountStateResolver)
  GET /{acct}/account-states            (no auth — public, relay-verified, root-signed)
     → { account_states: [ <compact JWS> … ], max_sequence }
```

**Mapping to the `AllwIOSApprover` package seams:**

| Need                                     | Endpoint                                                       | Package seam                                                                                                                                                                                                                                                        |
| ---------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pair + store creds                       | `pairing/start` + `pairing/complete`                           | persist via `NativeCredentialStore` (`device_id`, `device_auth_token`, account-root pubkey)                                                                                                                                                                         |
| Obtain the `device_cert`                 | `enrollments/{id}/csr` + `…/cert`                              | **specified, not implemented (#199).** Scan the enrollment QR, generate keys on-device, deposit the MAC'd CSR, poll for the cert, verify against the pinned root, persist via `NativeCredentialStore` — no cert ⇒ no inbox                                          |
| Register APNs token                      | `push_tokens` in `pairing/complete`, later `PUT …/push-tokens` | `PushTokenRegistering` / `HexApnsTokenRegistrar` `send` closure posts it here                                                                                                                                                                                       |
| Poll inbox                               | `GET …/inbox`                                                  | `RelayInboxFetching` / `UrlSessionRelayInboxClient.fetchPendingEnvelopes()`                                                                                                                                                                                         |
| Live push + **verdict submit + retract** | `…/connect` WebSocket                                          | **NOT in the package yet — the app builds this WS client.** Feed `{type:"request"}` into `ApprovalInboxStore.sync`; on resolve, send the `SignedVerdict.signedVerdictJson` as `{type:"verdict"}`; on `{type:"retract"}` clear via `PushInboxCoordinator.didResolve` |
| Verify origins (VERIFIED badge)          | `GET …/account-states`                                         | the `AccountStateResolver` feed (#155); verify root sig on device, keep a highest-sequence floor                                                                                                                                                                    |

> ⚠ **Build note for the Xcode agent:** the package fetches the inbox but does **not** implement the
> `/connect` WebSocket or verdict submission. The app must implement the WS client (URLSessionWebSocketTask):
> send `{type:"verdict", request_id, verdict}` with the `SignedVerdict` JSON the core produced, handle
> the `ack` (`already_resolved`/`expired` are fail-closed terminal states), and handle inbound
> `request`/`retract`. Inbox-poll is the fallback when the socket is down (fail-closed: never show an
> approvable item you couldn't fetch/verify).

---

## 3. Endpoint reference

### Pairing

**`POST /{acct}/pairing/start`** — account-root authorization. Body:

```json
{
  "root_pubkey": "base64url 32-byte Ed25519 account-root public key, 43 chars",
  "authorization": "compact JWS, typ allw-pairing-start+jws, signed by the account root",
  "label": "string (optional)"
}
```

`authorization` is an EdDSA compact JWS with protected header
`{ "alg": "EdDSA", "typ": "allw-pairing-start+jws", "kid": "<account_id>" }` and payload
`{ "v": 1, "account_id": "<account_id>", "issued_at": <ms>, "expires_at": <ms>, "jti": "<16–128 base64url chars>" }`.
`expires_at - issued_at` must be in `(0, 5 min]`; `issued_at` may be at most 60 s in the relay's future; the
authorization is rejected at or after `expires_at`. Sign it with the core
(`sign_pairing_start_authorization`), which always binds the id derived from the signing root.

→ **201** `{ code: string (8-char Crockford base32), expires_at: number(ms), pairing_auth_token: string }`.
Code is single-use, 10-min TTL. The first success binds `root_pubkey` to the account — but only into an account
with no device, pairing or actor rows; otherwise the bind is refused (409), never purged
(`docs/enrollment.md` §Self-Certifying Account Id). A used `jti` is remembered until 60 s past its `expires_at`.

| Status | When                                                                                                                                                                                                                                                        |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 400    | body is not a JSON object; `root_pubkey` missing, malformed, or not an Ed25519 key; `{acct}` does not derive from `root_pubkey`                                                                                                                             |
| 401    | `authorization` missing (or not a string)                                                                                                                                                                                                                   |
| 403    | bad signature, wrong `typ`, wrong `kid`/`account_id`, unsupported `v`, malformed `jti`, invalid/overlong window, not yet valid, expired, a `jti` already accepted for this account, or a `root_pubkey` different from the root already bound to the account |
| 409    | no root is bound yet but the account already holds devices, pairing codes or actors from before root binding                                                                                                                                                |
| 500    | the relay's verification core failed to initialize (logged; the request is not judged)                                                                                                                                                                      |

Every rejection leaves the account unchanged (no root bound, no code issued, nothing purged).

**`POST /{acct}/pairing/complete`** — Bearer `pairing_auth_token`. Body:

```json
{
  "code": "string",
  "pubkey": "base64url 32-byte key, 43 chars",
  "label": "string (optional)",
  "push_tokens": [{ "transport": "apns" | "fcm" | "webpush", "token": "string" }]
}
```

→ **201** `{ device_id: string, device_auth_token: string }`. APNs `token` = 64-char hex, in either
case; hex is case-insensitive, so it is stored lowercase and two spellings of one device token are one
token (#304). Rows stored before that are lowercased in place, keeping one row per device token. An
`fcm` token is an opaque, case-sensitive string and is stored as sent. A `webpush` `token` is the
browser subscription's `endpoint` URL, which must be `https:` on a push-service host allowlist (§5);
it is stored in normalized form (`URL.href`), so two spellings of one subscription are one token.
**Budgets:** at most **4** `push_tokens` entries per registration and **2** distinct tokens per
transport (duplicates collapse first); over budget is a **400**, never a silent truncation. An account
holds at most **32** push tokens across all devices; a registration that would exceed that is a
**409** and the pairing code is not consumed (retry without tokens, or free some).

**Small-order keys:** `pubkey` is the device's X25519 encryption key, so a small-order point is a **400**
`{ "error": "'pubkey' is a small-order X25519 key, which can never be an encryption target" }`. The
pairing code is not consumed (#248). Every ECDH with such a key gives a publicly known shared secret, so
`encrypt_context` would refuse every request to the account. The list is the core's
(`X25519_SMALL_ORDER_POINTS`, libsodium's `has_small_order` seven points, matched with bit 255 masked),
called through the relay's WASM binding, not a copy.

Errors:

- 403 when no root is bound to the account (a code on an unbound account predates root binding and is
  never honored);
- 400 (bad body, a pubkey that isn't the canonical encoding of 32 bytes (§1), small-order pubkey,
  push_token, unexpected key, or over budget);
- 401/403 (token);
- 404 (code unknown);
- 409 (code already used, or account push-token budget full);
- 410 (code expired);
- 500 only when the relay's verification core failed to initialize (logged). A key the core rejects
  is the 400 above, never a 500.

Atomic — no half-enrollment.

### Relay-level (`/.well-known/allw/`, not per-account)

**`GET /.well-known/allw/vapid-public-key`** (also `HEAD`): no auth. → **200**
`{ "vapid_public_key": "<base64url>" }` with `Cache-Control: public, max-age=3600`: the relay's
VAPID public key (an uncompressed P-256 point, 65 bytes), which a browser passes as
`applicationServerKey` to `PushManager.subscribe()`. **404** when the relay has no VAPID keypair
configured, or the configured pair fails validation (Web Push disabled); **405** for any other
method. Any other `/.well-known/…` path is **404**.

### Enrollment courier (cross-device `device_cert` issuance, #175) — specified, not implemented (#199)

> ⚠ **Not implemented.** None of the `/enrollments/*` routes below exist in `packages/relay/src/index.ts`; the
> relay answers them `404`. This section is the specification the relay will implement under #199. Until then a
> device's `device_cert` is minted by the account-root holder outside the relay and provisioned directly.

Two write-once mailboxes that carry a **certificate signing request** from a new device to the account-root
holder, and the issued **`device_cert`** back. Full ceremony, derivations, and failure semantics:
`docs/enrollment.md` §Cross-Device `device_cert` Issuance Ceremony.

> **The relay is a courier, not a validator.** It stores an opaque CSR object and an opaque compact JWS. It
> **never** checks `mac` (it holds no key that could), **never** parses or validates `device_cert`, and is never
> a trust anchor for either. Its shape/ownership checks below are anti-abuse only. The `enrollment_secret` that
> keys the CSR MAC travels **only** out of band (QR / pasted link) and must never appear in any request to the
> relay.

**`POST /{acct}/enrollments/start`** — no auth (it only opens a mailbox pair; nothing is certified until the root
holder authenticates the CSR with the out-of-band MAC). Body `{ label?: string }`. → **201**
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

**`PUT /{acct}/devices/{device_id}/push-tokens`** — Bearer the device's own token (self only). Body `{
"push_tokens": [{ "transport": "apns" | "fcm" | "webpush", "token": "string" }] }` (required; `[]`
clears). **Replaces** the device's push-token set, so it covers add, rotate, and clear after pairing.
→ **200** `{ push_tokens: [{ transport, token }] }`, the stored set (normalized: APNs tokens
lowercased, Web Push endpoints as `URL.href`; duplicates collapsed). Validation and per-registration
budgets are exactly those of `push_tokens` in `pairing/complete` (§Pairing): 400 for a malformed body,
a missing `push_tokens`, an unsupported transport, an invalid or over-long token, or over budget. The
account budget (32) counts every other device's tokens plus this set (the device's own current tokens
don't count, so a full account can still rotate); a set that grows past it is a **409** and nothing
changes. A set that stays the same size or shrinks is never refused, so a device can always clear its
tokens. The replace is one transaction and only touches tokens that change, so repeating a body is a
no-op. Auth, in the revoke order: 401 (no bearer), 403 (not a device token, including a revoked
device's own), 404 (device not enrolled or revoked), 403 (another device's token). Revoking a device
deletes its push tokens.

**`GET /{acct}/devices`** — no auth. → **200**
`{ devices: [{ device_id, pubkey, label|null, created_at }] }`. No secrets / no push tokens.

### Actors (requester attestation) — Bearer `device_auth_token` for POST

**`POST /{acct}/actors`** body `{ actor_id, pubkey (Ed25519, 43 chars), label? }` → **201**
`{ actor_id }`. 409 if `actor_id` already enrolled. **`GET /{acct}/actors`** (no auth) → **200**
`{ actors: [{ actor_id, pubkey, label|null, created_at }] }`.

### Account state (trust distribution) — authorized by the account root, not a token

**`POST /{acct}/account-states`** (no auth header) body
`{ account_states: string[] (1–16 compact JWS, ≤32 KiB each), max_sequence?: number }`.
Authority is the root's signature: the relay verifies **every** document with the core's
`verify_account_state` against the root bound to `{acct}` (by a root-signed `pairing/start`) and the
path's account id. All-or-nothing — any rejection leaves the stored state unchanged. On success the
relay replaces its stored set with the submitted documents at the **highest verified sequence**
(lower-sequence documents in the same publish are dropped) and returns them:
→ **200** `{ account_states: string[], max_sequence: number }` (`max_sequence` = that highest verified
sequence). `max_sequence` in the body is optional and never trusted; when present it must equal the
highest verified sequence.

| Status | When                                                                                                                                                                                                        |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 400    | body is not JSON; `account_states` missing, empty, over 16, or not all compact JWS; `max_sequence` not a non-negative safe integer or not equal to the highest verified; a verified `sequence` above 2^53-1 |
| 403    | any document fails verification: another signer, wrong `account_id`/`kid`, a `current_root` other than the bound root, wrong `typ`, unsupported `v`, or junk                                                |
| 409    | no root is bound yet; or the highest verified sequence is not strictly above the stored one (an idempotent republish of the current document is a 409 too)                                                  |
| 500    | the relay's verification core failed to initialize (logged; no document is judged)                                                                                                                          |

**`GET /{acct}/account-states`** (no auth — the documents are public and root-signed; integrators hold
no device token) → **200** `{ account_states: [ "<compact JWS>" … ], max_sequence: number }`: only
relay-verified documents, `max_sequence` = their sequence (`0` when none). The relay is still not the
trust anchor — **verify the account-root signature on device** and reject rollbacks below your
highest-verified sequence floor. Rows from the pre-verification cache are dropped, never served.

### Integrator endpoints (the app does NOT call these — listed for completeness)

**`POST /{acct}/requests`** — no auth; submits the `ApprovalRequest` envelope (only keys `v`, `id`,
`created_at`, `expires_at`, `approver`, `context_ciphertext`; any other key ⇒ 400, including the
specified-but-unimplemented `action_structure` / `privacy_preference` (#216); `expires_at ≤ now` ⇒ 400). → **202**
`{ request_id, status:"pending", delivered_to, push_wakeups, request_auth_token }`. 409 on dup `id`.

**Unknown account.** `POST /{acct}/requests` on an account with no bound root (no root-signed
`pairing/start` has ever succeeded, so no device can have paired since #264) ⇒ **404**
`{ "error": "unknown account" }`, checked before the body is read. This includes accounts that
enrolled devices before root binding existed (#264's pre-binding state): they now get 404 on
submit and must move to a new account root, as #264 already requires (their first bind is refused
with 409, see §3 Pairing).

**Request id.** The envelope `id` must be a canonical UUID — 8-4-4-4-12 hex digits, either case
(contract §Transport requires UUIDv4 or later) — otherwise **400**. This bounds the id, which is
part of every retained row.

**`created_at` sanity bound.** The envelope's `created_at` must be an integer (i64 ms), no later
than `expires_at`, no further back than the request horizon (`now − MAX_REQUEST_TTL_MS`), and no
further ahead than `MAX_CREATED_AT_SKEW_MS` (**60 s**, for clock skew) — otherwise **400**. Each
bound is inclusive. This closes no attack, since the window is the submitter's own: it turns a
request the device could never verify into a 400 at submit, instead of a provenance error on the
device after the human taps.

Limits on `POST /{acct}/requests` (#248; constants in `packages/relay/src/constants.ts`):

| Limit                        | Value                                                               | Over the limit |
| ---------------------------- | ------------------------------------------------------------------- | -------------- |
| Request body                 | `MAX_REQUEST_BODY_BYTES` = 128 KiB, checked **before** JSON parsing | **413**        |
| `context_ciphertext`         | `MAX_CONTEXT_CIPHERTEXT_BYTES` = 64 KiB (UTF-8 bytes of the string) | **413**        |
| Horizon (`expires_at − now`) | `MAX_REQUEST_TTL_MS`, default **15 min** (Worker var override)      | **400**        |

Each value is inclusive (exactly the limit is accepted). The 15-minute horizon covers the hooks'
420 s maximum timeout; an operator who lowers it below that makes hook requests fail closed. A
pending request older than the horizon (only possible for one stored before the horizon existed) is
expired by the alarm; like every terminal request it is deleted 7 days after it ends. When a request
ends (expired, retracted or resolved) the relay blanks its stored envelope: status and verdict reads
keep working, but the ciphertext is gone. Stored bytes are therefore bounded by submit rate ×
retention × that small per-row residue. Submission is not yet rate-limited, nor is the number of
pending requests per account bounded — see `docs/threat-model.md` "Relay denial of service".

**`GET /{acct}/requests/{id}`** and **`GET /{acct}/requests/{id}/wait`** (WS) — Bearer
`request_auth_token`; poll/await `{ status, verdict? }`. `status` is `pending`, terminal `expired`,
terminal `retracted` (see below), or `resolved` (+ `verdict`).

**`POST /{acct}/requests/{id}/retract`** — Bearer `request_auth_token`, scoped to exactly the
request that token was issued for (issue #195). Cancels the integrator's own still-`pending`
request — **NOT a verdict**; it never appears in the audit chain as a decision. No body. → **200**
`{ request_id, status:"retracted" }`. Fans out `{type:"retract", request_id}` to connected devices
(the same message a resolve/expiry already sends) and pushes `{type:"retracted", request_id}` to
any live `…/wait` socket, then closes it. **409** if the request already reached a real terminal
state (`resolved` — a device decided, the verdict stands; or `expired`) — a retract can never
discard a decision or override the fail-closed timeout. Idempotent on an already-`retracted`
request (200). `404` unknown request; `401`/`403` missing/wrong/cross-request token.

---

## 4. WebSocket protocol — `/{acct}/devices/{device_id}/connect`

Upgrade with `?auth=<device_auth_token>` (or Bearer header). On connect the relay flushes the
offline queue (still-pending, non-expired) as `request` messages. Hibernatable.

**relay → device**

- `{ "type": "request", "request_id": string, "envelope": ApprovalEnvelope }`
- `{ "type": "retract", "request_id": string }` — resolved elsewhere, expired, or the submitting
  integrator cancelled it (`POST …/requests/{id}/retract`, #195); clear the notification either way.
- `{ "type": "error", "error": string }` — your last message was malformed.

**device → relay**

- `{ "type": "verdict", "request_id": string, "verdict": <Verdict object> }` — the JWS-signed
  decision (the `SignedVerdict.signedVerdictJson` the core produced; see `docs/contract.md` Verdict).
- relay replies
  `{ "type": "ack", "request_id": string, "status": "resolved" | "already_resolved" | "expired" | "retracted" }`.
  Idempotent: a second verdict is `already_resolved` (not overwritten); a verdict past `expires_at`
  is `expired` (rejected, fail-closed); a verdict for a request the integrator already cancelled is
  `retracted` (rejected — a retract is never overridable, #195).

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
  "context_ciphertext": "string (JWE — decrypt on device)"
}
```

(The Swift `ApprovalEnvelope` mirrors this in camelCase: `createdAt`, `expiresAt`,
`contextCiphertext`.) The structure-not-data `action_structure` view (#131 — never carries args/values) is
**specified, not implemented (#216)**: the relay's envelope key allow-list rejects it with `400` today.

---

## 5. Push wakeups

Integrator submission fans out **request-id-only** wakeups (no context, not E2EE) to registered
tokens. APNs payload: `{ "aps": { "content-available": 1 }, "request_id": "…" }`. The device wakes,
then fetches the full envelope via the socket or `/inbox`.

**Fan-out is off the response path.** The submit returns as soon as the request is stored; wakeups
are sent afterwards (at most 4 in flight, each push-service request bounded by a 5 s timeout), so a
slow, hung, or failing push service can never delay or fail a submit. Consequently `push_wakeups` in
the submit response is the number of wakeups **scheduled** (tokens with a configured transport, up to
the 32-token account budget, newest registrations first, minus coalesced Web Push wakeups), not the
number delivered.

**Pruning, APNs and FCM.** A token is deleted only when its push service says it is no longer valid:
**APNs 410** (`Unregistered`: the app was uninstalled or the token rotated), and **FCM 404 whose
body carries the `UNREGISTERED` error code** (`error.details[].errorCode`; read from at most 4 KiB
of the body, then released). Every other answer keeps the token (#260). In particular APNs `400
BadDeviceToken` never prunes: APNs also returns it for a token sent to the wrong APNs environment
(sandbox or production), so a misconfigured `APNS_ENDPOINT` would otherwise unregister every device.
A bare FCM 404, one with another error code, or one whose body cannot be read is likewise kept. Any
4xx that does not prune is logged once (`console.warn`) with the transport, the push-service host
and the status, never the token (#326); that includes a 429, which keeps the token. 5xx answers
and timeouts are transient and not logged.

**Web Push** (RFC 8030, browser approvers):

- **Token format.** The `webpush` token is the `PushSubscription.endpoint` URL. It must be `https:`,
  carry no credentials, explicit port, or fragment, and name a known push-service host:
  `fcm.googleapis.com` (Chrome), `updates.push.services.mozilla.com` (Firefox), `web.push.apple.com`
  (Safari), or a single-label subdomain of `notify.windows.com` such as `wns2-by3p.notify.windows.com`
  (Edge/WNS). Anything else is a **400** at registration. The relay
  POSTs to this URL, so the allowlist is its SSRF guard; it is re-checked before every send, and
  redirects are not followed.
- **Payload-less wakeup.** The push request has an **empty body** — not even the request id — with
  `TTL` set to the remaining lifetime of the account's **longest-lived pending request** (not just
  the one that triggered it), rounded **up** to one of 60 s, 5 min, 1 h, 1 d, or 28 days (so the
  push service learns that deadline only coarsely), `Urgency: high`, and
  VAPID auth `Authorization: vapid t=<ES256 JWT>, k=<vapid_public_key>` (RFC 8292; the JWT's `aud`
  is the endpoint's origin, `exp` one hour out, `sub` the operator contact). The subscription's
  `p256dh`/`auth` keys are not needed and not sent to the relay. On a `push` event the service worker
  fetches pending envelopes itself via `GET /{acct}/devices/{device_id}/inbox`.
  The TTL covers every pending request because one wakeup leads to an inbox fetch that returns all
  of them. With `Topic` (below), a later wakeup also replaces a queued earlier one along with its
  TTL (RFC 8030 §5.4), so a short-lived request must not cut short the wakeup a longer-lived one
  still needs (#261).
- **`Topic` (collapsing queued wakeups).** Where the push service documents support for it, each
  wakeup carries the fixed RFC 8030 §5.4 header `Topic: allw-wakeup`, the same for every account
  and subscription. A browser that is offline while several requests arrive then has one queued
  wakeup instead of one per request, and loses nothing, since one inbox fetch returns every pending
  request. `Topic` is sent per push-service host:

  | Push service (host)                                    | `Topic` sent | Why                                                                                                                                                                                                                                                                                                                                                                                                                                   |
  | ------------------------------------------------------ | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | Mozilla autopush (`updates.push.services.mozilla.com`) | Yes          | Documented: a newer message with the same topic replaces an unread one; at most 32 characters of `[A-Za-z0-9_-]` ([autopush HTTP API](https://autopush.readthedocs.io/en/latest/http.html)).                                                                                                                                                                                                                                          |
  | Apple (`web.push.apple.com`)                           | **No**       | Since about September 2026 Apple answers any request carrying `Topic` with `400 {"reason":"BadWebPushTopic"}`, whatever the value. Apple has published nothing on this; it is reported independently by many projects, e.g. [1](https://github.com/swimmesberger/Elarion/pull/166), [2](https://github.com/saiday/kukuroo/pull/9), [3](https://github.com/docchi-app/which/pull/69). Sending it would fail every Safari / iOS wakeup. |
  | FCM (`fcm.googleapis.com`)                             | No           | We found no documentation of `Topic` support for Web Push. Not sent until verified.                                                                                                                                                                                                                                                                                                                                                   |
  | WNS (`*.notify.windows.com`)                           | No           | Microsoft documents only its own `X-WNS-*` headers. Not sent until verified.                                                                                                                                                                                                                                                                                                                                                          |

  A host is added only with evidence that it accepts and honours `Topic`, never by probing
  production. On iOS / iPadOS, where every push must show a notification, repeated notifications
  are collapsed on the device instead: the web approver's service worker shows them under one
  fixed notification `tag` (#237).

- **Coalescing.** At most one wakeup per subscription (device id + endpoint) is sent per **30 s**
  (`WEB_PUSH_COALESCE_MS`): a submit that finds a wakeup to that subscription in flight, or sent
  within the window, skips it. This bounds push volume per subscription however fast unauthenticated
  submits arrive (#248). The time of each subscription's last wakeup is stored on its token row, so
  the bound also holds when the Durable Object hibernates or is evicted inside the window (#319).
  Removing the subscription removes its claim too. A stored claim dated in the future (a clock
  anomaly on the host that wrote it) counts as made now, so it blocks the subscription for one
  window at most.
- **Trailing wakeup.** A skipped submit may have landed after the service worker already fetched its
  inbox for the earlier wakeup, so the skip alone could leave that request with no push at all
  (#313). The relay therefore records the subscription as owed a wakeup. A request whose submit was
  skipped keeps its owed wakeup until a later wakeup is accepted: a wakeup claimed after the window
  clears it once the push service answers 2xx, unless another submit was skipped while that wakeup
  was in flight. If none is accepted by the end of the window, the subscription gets **one**
  trailing send, however many submits were skipped, and that trailing send is not retried. A failed
  wakeup for the submit that claimed it is not retried (#333). The trailing wakeup is held to the
  same one-per-window bound, so it still respects an in-flight wakeup. Its own due time is stored,
  so it is never sent less than one window after the claim it trails, even across eviction. It is
  dropped when no request is pending by then or the subscription is gone. Like every wakeup, its
  `TTL` covers the longest-lived pending request. Because the window starts at dispatch, every
  request gets a wakeup **attempt** after it was stored, within about 30 s (a slow fan-out can
  stretch that by its send timeouts). The owed wakeups are stored durably and sent from the
  account's alarm, so they survive the Durable Object hibernating or being evicted.
- **VAPID public key.** Clients subscribe with the key from `GET /.well-known/allw/vapid-public-key`
  (§3).
- **Pruning.** When the push service answers **404 or 410** (the subscription is gone), the relay
  deletes that token row. That is the only pruning. Every other failure (401/403, other 4xx, 5xx,
  3xx, a timeout, a network error) leaves the token in place; in particular an auth error is a
  relay-side VAPID problem, not a dead device, and never unregisters anyone. A stored row that fails
  the endpoint allowlist at send time (e.g. one registered before validation existed, or after the
  allowlist narrows) is refused, logged, and kept, never requested. A 4xx other than 404/410 is
  logged once per answer (`console.warn`): the transport, the push-service host, the status and, for
  Web Push, a JSON body's `reason` when it is an identifier of at most 32 characters (Apple:
  `BadWebPushTopic`) that does not occur anywhere in the subscription endpoint, so an echoed path
  token is dropped. The body is read only up to 1 KiB and 1 s, then released without waiting for
  the release to finish. The token, the endpoint path, credentials and request ids are never logged
  (#326).
- **Enablement.** Web Push is active only when the relay has a complete VAPID configuration whose
  keypair actually matches (`docs/relay-deploy.md` §3d); otherwise `webpush` tokens are stored but no
  wakeup is sent, and the public-key endpoint is 404.

---

## 6. Known gaps / client-owned concerns

1. **Pairing-code delivery** (QR / deep-link / manual entry) is a UX layer — not defined by the relay.
2. **`device_cert`** (binds the device signing key to the account root) is signed by the **account-root
   holder** and persisted **on device**; the relay never issues or validates it. A device that is not the root
   holder will obtain one through the enrollment courier (§3, specified, not implemented — #199) — the relay
   will store the CSR and the cert as opaque bytes and can neither forge nor authenticate either. Include the cert in verdicts per the Verdict schema.
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
   - `retracted` — the submitting integrator cancelled the request before your verdict landed (#195);
     **refused — a retract is never overridable.** Treat like `already_resolved`: clear the row (it
     will also arrive as a `retract`), but there is no winning decision to reconcile against.

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
     (used by integrators to JWE-encrypt to the device). A small-order key is refused (400, §3 Pairing).
     The Ed25519 **signing** key is **not** sent to the relay — by design, so the relay is never the
     carrier of the verdict-key binding. It is certified out of band instead (`enrollment.md` §Pairing Flow step 3 documents this single-key surface).
   - The device also needs a **`device_cert`** — an account-root-signed JWS binding its Ed25519 signing
     pubkey (`issue_device_cert`). **The relay does NOT issue or validate it.** Verdicts without a valid
     `device_cert` are denied by integrators (`enrollment.md` §Device Certificate Validation).
   - Who calls `/pairing/start`: only the **account owner** (the root-seed holder) — the call carries a
     root-signed authorization (§3 Pairing). The reference `allw-approver pair` CLI holds the root and drives
     `start` itself when `--code` is omitted. The new device calls only
     `/pairing/complete` with the `pairing_auth_token` shown out-of-band.
   - **Cross-device issuance (specified #175; relay courier not implemented, #199):** the walking-skeleton CLI holds the account-root seed and
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
