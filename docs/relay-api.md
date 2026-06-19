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
- **Three token scopes:**

  | Token                | Issued by                     | Used for                                         | Lifetime                  |
  | -------------------- | ----------------------------- | ------------------------------------------------ | ------------------------- |
  | `pairing_auth_token` | `POST /pairing/start`         | `POST /pairing/complete`                         | 10 min (`PAIRING_TTL_MS`) |
  | `device_auth_token`  | `POST /pairing/complete`      | all `devices/{id}/…`, `actors`, `account-states` | until revoked             |
  | `request_auth_token` | `POST /requests` (integrator) | `requests/{id}` polling/wait                     | 7 days post-terminal      |

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
2. **`device_cert`** (binds the device signing key to the account root) is produced at enrollment and
   persisted **on device**; the relay never stores/validates it. Include it in verdicts per the Verdict
   schema.
3. **Verdict submission is WS-only** (§2 build note) — there is no HTTP fallback today. If the app
   needs an HTTP verdict path (e.g. background-task constraints), that's a relay change — file an issue.
4. **Account-state signing/publishing** (who holds the root, how docs are produced) is out of relay
   scope; the relay is a distribution cache. Verify on device.
5. **Number-match challenge** is derived + verified on device (`docs/contract.md`); the relay never
   sees it.

## References

`docs/contract.md` (wire types: envelope, Verdict, ApprovalContext, WYSIWYS), `docs/enrollment.md`
(pairing, account state, revocation), `docs/relay-deploy.md` (operator deploy), `docs/apple-approver-app.md`
(the app spec). Relay source: `packages/relay/src/index.ts`.
