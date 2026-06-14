# allw — Approval Primitive Contract (v0.1 draft)

**The keystone.** A request/response protocol:

```
requestApproval(ActionRecord) → verifiable Verdict + AuditRecord     [over an E2EE channel]
```

Thin in surface, rich in contract. Companion to [architecture.md](./architecture.md) (stack),
[policy-seam.md](./policy-seam.md) (the `ActionRecord` and the policy layer that sits in front of this primitive),
and [enrollment.md](./enrollment.md) (account/device enrollment, rotation, revocation, and recovery).

---

## Invariants (the whole design serves these)

1. **E2EE** — the relay never sees plaintext context or rationale. Context is encrypted to the approver's device
   key(s); the verdict is signed by a device key.
2. **Structure-not-data** — the relay (and anything off-device) may see action **structure** — the surface kind,
   program name (commands) / server + tool name (MCP calls), and session label — but **never** action **data**:
   arguments, parameter values, environment variable names or values, or any content the agent is operating on.
   Shorthand: "know the function, not the arguments." For MCP calls the function identity is the (server, tool)
   pair, parallel to a command's program name; both are structure. This is enforced on-device (in the WASM/native
   client) before any bytes reach the relay, and it tightens the E2EE invariant — it does not loosen it. Full
   `ActionRecord` data travels only inside the JWE (`context_ciphertext`), visible exclusively to enrolled
   approver devices. A RESERVED `privacy_preference` wire field (null = default in v1) controls how much
   structure the relay sees; see §Messages for the three tiers.
3. **Verifiable verdict** — a signed artifact any party can verify _without trusting the relay_, cryptographically
   **bound to the exact request** (no replay, no swap).
4. **WYSIWYS (what you see is what you sign)** — the verdict binds to a single `request_hash` over the _entire_
   human-shown payload — the canonical `ApprovalContext` **plus** the shown `expires_at`, as one flat object (the
   _request-hash input_; see §Wire encoding) — computed device-side after decryption. One hash, complete binding
   (no separate `context_digest`). Closes the context/action TOCTOU gap. The structure-not-data boundary does not
   affect WYSIWYS: full data remains inside the JWE and `request_hash` is computed post-decrypt on-device.
5. **Requester attestation** — every request carries an attestable actor identity (v1: **actor-key**), so the
   approver sees a cryptographically-verified origin.
6. **Chain-composable & monotonic** — the primitive **never returns "allow."** It returns _"the human verifiably
   decided X on this exact request."_ Consumers compute `allow = ∧(all gates)`, so a verdict can only **tighten**.
7. **Fail-closed** — timeout / no-response / unverifiable ⇒ **deny** by default.

---

## Roles

- **Actor / Subject** — the automation needing approval (a coding agent on a machine, a web agent via a gateway). Attested.
- **Integrator / Relying Party** — the code calling `requestApproval` (a hook, the proxy, a gateway). Verifies and enforces.
- **Approver** — the human; owns an account with one or more enrolled **devices** (the "inbox").
- **Relay** — zero-knowledge router (Cloudflare Workers + Durable Objects). At the default (structure-visible)
  tier it sees: routing metadata, opaque `context_ciphertext`, and action structure (surface / program name or
  server+tool name / session-label). It never sees action data (arguments, values, env). At the
  paranoid/enterprise tier (reserved; not built in v1) it sees routing metadata only.

---

## What is approved: the `ActionRecord`

The payload being approved is an **`ActionRecord`** — defined in [policy-seam.md](./policy-seam.md). v1 carries the
**syntactic substrate** (`surface` + tokenized command / MCP call); the semantic `capabilities`/`scope` fields are
reserved and null. The contract is **action-agnostic**: it transports and binds whatever `ActionRecord` it's given.

---

## Lifecycle

1. Integrator builds an **ApprovalContext** (actor identity + `ActionRecord` + `summary` + `risk` + `reversible` +
   constraints) and computes `request_hash` over the canonical _request-hash input_ — the `ApprovalContext` fields
   **plus** the shown `expires_at`, as one flat object (see §Wire encoding).
2. Encrypts the `ApprovalContext` to the approver's device key(s) → `context_ciphertext` (JWE), and wraps it in an
   **ApprovalRequest** envelope (routing + lifecycle only).
3. Submits to relay → push **wakeup (request id only)** → device fetches the envelope's ciphertext.
4. Device decrypts the `ApprovalContext`, verifies the actor `attestation`, **renders** (WYSIWYS), recomputes
   `request_hash`, human decides; destructive ops may require a **number-match** challenge.
5. Device emits a **Verdict** signed (JWS/COSE) over `(request_id, request_hash, decision, decided_at, nonce)`;
   if an approval requires number-match, the signed `challenge_response` must be the derived challenge for that
   `request_hash`. Denials do not need to satisfy the approval challenge.
6. Integrator **verifies** (checklist below), composes with its own + upstream policy, appends an **AuditRecord**.

---

## Messages

The human-shown payload and the wire envelope are **separate** (resolved in
[#28](https://github.com/mike-north/allw/issues/28)): everything human-facing is encrypted into an
**`ApprovalContext`**; the **`ApprovalRequest`** the relay sees is a minimal routing/lifecycle envelope wrapping the
ciphertext. **The relay never sees the `ActionRecord` or any rendered content.**

### ApprovalRequest — _envelope (plaintext; relay-visible)_

`v` · `id` · `created_at` · `expires_at` · `approver` (routing id) · `context_ciphertext` (JWE to device key[s]) ·
`action_structure`? · `privacy_preference`? (RESERVED).

`action_structure` is the **structure-not-data** surface (Invariant 2): when present, it carries only structure
fields — `surface` kind, function identity (`program` name for commands; `server` + `tool` name for MCP calls),
`session_label` — never data (arguments, parameter values, env). For MCP calls the (server, tool) pair is the
function identity, parallel to a command's program name; both are structure. In the default (structure-visible)
tier the integrator SHOULD populate this field so the relay can use structure for routing intelligence. In the
paranoid/enterprise tier (reserved; not built in v1) this field is omitted.

`privacy_preference` is a **RESERVED** field: `null` (or absent) in v1 is equivalent to `"default"`.
The three tiers — and what each allows the relay to observe — are:

| Value                        | Relay sees in plaintext                                | v1 status               |
| ---------------------------- | ------------------------------------------------------ | ----------------------- |
| `"default"` (or null/absent) | `action_structure` (structure only) + routing metadata | **implemented**         |
| `"paranoid"`                 | routing metadata only; `action_structure` omitted      | **reserved; not built** |
| `"ai-summary"`               | future tier                                            | **reserved; not built** |

Routing + lifecycle + the opaque ciphertext, and at most action structure — nothing more. `request_hash` is
**not** an envelope field — it is computed over the `ApprovalContext` (below) by the integrator (locally,
pre-send) and recomputed by the device (post-decryption), and travels only inside the **Verdict**. (A separate
transport signature over the envelope proves the sender is an enrolled actor; that is a relay concern and needs
no visibility into content.)

### ApprovalContext — _inside the JWE; the approver's devices only_

`action`: **`ActionRecord`** · `summary` · `actor` { `id`, `kind`, `attestation`: actor-key signature } ·
`risk`(low|med|high|critical) · `reversible` · `constraints` { allowed verdicts, challenge policy } ·
`chain`? (upstream-gate ids, audit correlation only).

This is the **complete human-shown payload**; `request_hash` is computed over the canonical _request-hash input_ —
these `ApprovalContext` fields **plus** the shown `expires_at`, as one flat object (see §Wire encoding) — so that
one hash is the complete WYSIWYS binding. The actor's `attestation` is verified by the **device** after decryption
(the relay never sees it); the integrator still holds the plaintext `ApprovalContext`
locally (it builds it and runs its policy engine before escalating), so this split only changes what crosses the
wire to the relay.

### Verdict — _one-shot and scope-free_

`v` · `request_id` · `request_hash`(echoed/bound) · `decision`(approved|denied|expired|aborted) · `decided_at` ·
`approver` { account_id, device_id } · `note`? (optional freeform) · `challenge_response`? ·
`sig` (device key) · `device_cert`? (chains device key → account root, so verifiers need only the root).

> No `scope`/reuse field — standing autonomy lives in the policy layer ([policy-seam.md](./policy-seam.md)), not the verdict.

### AuditRecord — _append-only, hash-chained_

`seq` · `prev_hash` · `record_hash` · `request_id` · `request_hash` · `actor` · `approver` · `decision` ·
`decided_at` · `action`(ActionRecord) ·
`policy` { decision, rule_id?, tier, schema_version } (reserved; v1 writes `escalate`) · `note`? ·
verdict `sig` (+ optional integrator counter-sign). Periodically anchor the head hash for non-repudiation.

> No `context_digest` — `request_hash` (the hash of the canonical `ApprovalContext`) **is** the
> "prove-what-was-shown-without-storing-plaintext" proof, so a second digest is redundant
> ([#28](https://github.com/mike-north/allw/issues/28)).

---

## Verification checklist (integrator MUST)

1. Signature valid against the approver's device/account root key.
   Multi-account verifiers that already know the account namespace they intended to verify SHOULD also pass that
   `expected_account_id`; verification fails closed if the verdict's certified account does not match it, which
   prevents accidentally accepting a verdict under the wrong trusted root.
2. Bound to the **exact request** (no swap): the verdict's `request_id` equals the request's `id`, **and** its
   `request_hash` equals the integrator's locally-computed hash of the canonical `ApprovalContext`. Both are
   required — `request_hash` excludes `id`, so two content-identical requests share a hash; the `id` check
   distinguishes them.
3. `decision == approved`.
4. Not expired; `decided_at` within window; nonce unseen (anti-replay).
5. If the verdict is approved and destructive challenge is required: `challenge_response` equals the derived
   number-match challenge. Authenticated denials stay denials without a challenge response.
6. **Then** `effective_allow = approved ∧ verified ∧ local_policy ∧ (other gates)`. The primitive contributes a
   verified human decision; it never authorizes by itself.

---

## Identity & keys

- **Actor (v1: actor-key pairing):** each machine/agent enrolls a keypair; requests are signed, so the inbox shows
  a verified origin ("Claude Code · macbook-pro"). No IdP dependency. (OAuth 2.1 / MCP-token interop deferred.)
- **Approver:** an account with enrolled **devices**; each device holds a keypair in **Secure Enclave / StrongBox**,
  with **biometric-gated signing** (the verdict key is released by Face ID / Touch ID and never leaves hardware).
  A `device_cert` chains each device key to an account root so verifiers need only the root; see
  [enrollment.md](./enrollment.md) for pairing, rotation, revocation, and recovery.
- **Crypto:** **JOSE** — JWE (X25519 ECDH) for context, JWS (Ed25519) for verdicts/rules — reusing vaultkeeper's
  substrate. Verdict and policy-rule JWS verification both chain the signing device key through `device_cert` to the
  account root and reject account / `kid` confusion. Static ECDH for v1; forward secrecy later.

---

## Cross-device coordination

A pending approval may surface on several devices, and the same iOS request can appear twice on a Mac (native +
iPhone-Mirrored). The per-account **Durable Object** coordinates: targeted **fan-out**, **retraction** on the
device(s) once any surface resolves, and **dedupe** across transports. See [architecture.md](./architecture.md).

---

## Transport

Relay routes only — it sees the **ApprovalRequest envelope** (routing + lifecycle + the opaque
`context_ciphertext`) and never the `ApprovalContext` (the `ActionRecord`, `summary`, `actor`, constraints, …).
Push (APNs / FCM; **Web Push later**) carries a wakeup + request id — **never context** (push isn't E2EE / is
size-limited). The envelope's ciphertext is fetched as JWE and decrypted on-device.

Push tokens are registered during pairing by including `push_tokens` on authenticated
`POST /pairing/complete`. Each token has `transport` (`apns`, `fcm`, or future `webpush`) plus the
opaque vendor token. APNs tokens are 64-character hex strings; FCM tokens are restricted to the
provider token alphabet the relay accepts (`A-Z`, `a-z`, `0-9`, `_`, `-`, `:`). Tokens are relay
routing metadata: they are stored only to wake an enrolled device and are not exposed by
`GET /devices`. `POST /requests` fans a request-id-only wakeup through the configured transport
registry and still queues the ciphertext envelope for polling / WebSocket delivery.

### Relay routing API (v1)

The per-account Durable Object exposes routing under `/{account_id}/…`. It persists **only** the opaque envelope
and the signed verdict — never plaintext, never a key it could sign with.

| Method / path                                  | Who        | Purpose                                                                                                                                                                   |
| ---------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /requests`                               | integrator | Submit an ApprovalRequest envelope; fans out to online devices.                                                                                                           |
| `GET  /requests/{id}`                          | integrator | Poll status → `pending` / terminal `expired` / `resolved` + verdict.                                                                                                      |
| `GET  /requests/{id}/wait` (WS)                | integrator | Block for the verdict; it is pushed the instant a device decides.                                                                                                         |
| `GET  /devices/{id}/connect?surface_id=…` (WS) | device     | Presence socket (hibernatable); flushes the offline queue on open. `surface_id` is optional visible-screen topology for deduping mirrored/native notification transports. |
| `POST /account-states`                         | device     | Replace the relay-distributed set of root-signed account-state JWS documents for the account.                                                                             |
| `GET  /account-states`                         | device     | Fetch root-signed account-state JWS documents before local actor-origin verification.                                                                                     |

`POST /pairing/start` returns `{ code, expires_at, pairing_auth_token }`; `POST /pairing/complete`
must present that token as `Authorization: Bearer …` and returns `{ device_id, device_auth_token }`.
Device-scoped endpoints such as `GET /devices/{id}/connect` and
`POST /devices/{id}/revoke` require that device token (header or `auth` query for WebSocket
upgrades). `POST /requests` returns `request_auth_token`; `GET /requests/{id}` and
`GET /requests/{id}/wait` require it. `POST /account-states` and `GET /account-states`
also require an enrolled device token: the relay distributes only opaque compact JWS account-state
documents and cannot make a substituted actor key trusted. The relay stores only SHA-256 hashes of
these bearer tokens.

**Device socket messages** (JSON): relay → device `{ type: "request", request_id, envelope }` and
`{ type: "retract", request_id }` (another surface resolved it); device → relay
`{ type: "verdict", request_id, verdict }` (the signed [`Verdict`](#verdict--one-shot-and-scope-free)), answered
with `{ type: "ack", request_id, status }`. **First verdict wins** — a later verdict for a resolved request is
acked as `already_resolved` and does not overwrite. A device that was offline when a request arrived receives it
on its next `connect` (the queue), so delivery survives reconnect. If a device connection supplies `surface_id`,
the relay fans out and flushes queued requests to at most one live socket per `surface_id`, preventing a single
visible screen from showing both a native prompt and a mirrored prompt. Retractions still go to all live device
sockets so stale surfaces clear.
`surface_id` is caller-asserted, account-global topology metadata; it is trusted only from a
connection authenticated with that enrolled device's relay bearer token (#89).

**Fail-closed expiry** (§Invariants #6): once a request is past `expires_at` it can never become approvable. A
verdict for an expired request is refused (acked `expired`, not stored); the offline-queue flush skips expired
requests (no dead request is re-pushed); and a read after the deadline **lazy-expires** the row — poll returns the
terminal `expired` status and `…/wait` is pushed `{ type: "expired", request_id }`. (A proactive `alarm()` sweep
that retracts expired requests from devices without waiting for a read is tracked in
[#44](https://github.com/mike-north/allw/issues/44).) Verdicts are accepted **only** from a socket whose device is
still enrolled — a revoked device cannot drive a request to `resolved`. `GET /requests/{id}` no longer treats
`request_id` alone as sufficient authority; callers must also present the request token returned by
`POST /requests` (#89).

---

## v1 scope

- **Ship:** one-shot scope-free verdicts · actor-key attestation · **syntactic** `ActionRecord` (policy-seam T1) ·
  number-match challenge for destructive/critical · optional human `note` · E2EE + verifiable verdict + audit chain ·
  **structure-not-data boundary** (default / structure-visible tier only; `privacy_preference` reserved as null).
- **Defer:** reuse/standing autonomy & conditions (→ policy layer), semantic `ActionRecord` fields (→ T3),
  predicate rules, paranoid/enterprise and ai-summary privacy tiers.

## Wire encoding

- **Binary fields** (`request_hash`, `prev_hash`, `record_hash`, `attestation`) serialize as
  **base64url-unpadded JSON strings** (JOSE-consistent); enables byte-identical output across the Rust core and the
  WASM/TS surface. (`sig` and `device_cert` are **not** binary fields — they are compact-**JWS** strings (see
  §verdict signature); `context_ciphertext` is a compact-**JWE** string.)
- **Timestamps** (`created_at`, `expires_at`, `decided_at`) are `i64` Unix milliseconds (UTC) — deterministic
  for the WYSIWYS canonical hash and trivially identical Rust↔TS.

### request_hash (WYSIWYS canonicalization)

`request_hash` binds a [`Verdict`] to the exact content the human was shown, and is the **complete** WYSIWYS
binding — there is no separate `context_digest` ([#28](https://github.com/mike-north/allw/issues/28)). Both the
integrator (pre-send) and the device (post-decrypt) compute it independently and **must produce identical bytes**
(the WASM binding too), so the hashed structure is pinned exactly below.

**Hashed input — the `request-hash input`: a single flat JSON object** containing every `ApprovalContext` field
**plus** `expires_at` as a **sibling top-level key** (NOT nested under another key). Exactly these keys, no others:

```
{
  action,        // full ActionRecord
  summary,       // string
  actor,         // { id, kind } ONLY — attestation excluded
  risk,          // "low" | "medium" | "high" | "critical"
  reversible,    // bool
  constraints,   // { allowed_decisions, challenge_required }
  chain,         // string[] — key omitted entirely when absent
  expires_at     // i64 ms — read from the envelope (relay needs it for lifecycle), bound here
                 //          so a tampered deadline fails verification
}
```

So `expires_at` sits at the same level as `action`/`summary`/… — implementations must NOT wrap the
`ApprovalContext` under a sub-key (e.g. `{ context: {...}, expires_at }` is wrong). The device reads `expires_at`
from the plaintext envelope and the rest from the decrypted `ApprovalContext`, then assembles this one object.

Excluded: `actor.attestation` (a verification artifact the device checks separately, not shown content), the
envelope's other routing/lifecycle fields (`id`, `created_at`, `approver`, `v`), and `context_ciphertext` itself.

**Recipe:**

```
request_hash = SHA-256( b"allw/request-hash/v2" || 0x00 || JCS(request-hash input) )
```

where `JCS(...)` is the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JSON Canonicalization Scheme encoding of
the single flat object above (object keys lexicographically sorted by JCS; `expires_at` canonicalizes as a sibling
of `action`/`summary`/…). The `0x00` byte separates the domain tag from the payload.

**Versioning:** the broadened input is a breaking change from the four-field v1, so the domain tag bumps to
`b"allw/request-hash/v2"`; the frozen cross-platform vector is re-pinned when this lands in code.

### audit record_hash

`record_hash = SHA-256( b"allw/audit-record/v1" || 0x00 || JCS(record_without_record_hash) )`

Every field of the `AuditRecord` is covered **except `record_hash` itself** (circular). Critically
`prev_hash` is included, so each record commits to its predecessor → tamper-evident chain.
Domain tag `b"allw/audit-record/v1"` is distinct from the request-hash tag; the `/v1` suffix is the
version knob.

### verdict signature (EdDSA JWS)

The verdict signature is a literal **EdDSA compact JWS** ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) +
[RFC 8037](https://www.rfc-editor.org/rfc/rfc8037)): `b64url(header) . b64url(payload) . b64url(sig)`, where the
Ed25519 signature covers the ASCII signing input `b64url(header) . b64url(payload)` (sign-what-you-send — the
transmitted bytes are authoritative, so no JCS is applied to the JWS payload). Pure-Rust on `ed25519-dalek`, so it
compiles to `wasm32` (josekit/jsonwebtoken are OpenSSL/ring-based and cannot — see [architecture.md](./architecture.md)).

Two JWS types, domain-separated by the `typ` header:

- **Verdict JWS** — `typ: "allw-verdict+jws"`, `kid: <device_id>`, signed by the **device** key. Payload claims:
  `request_id`, `request_hash` (b64url), `decision`, `decided_at`, `nonce` (b64url), and `challenge_response`?
  (signed only when present). These signed claims are authoritative; the outer `Verdict` plaintext fields are a
  decoded convenience and are cross-checked against the claims on verify.
- **Device-cert JWS** — `typ: "allw-device-cert+jws"`, `kid: <account_id>`, signed by the **account root** key.
  Payload: `account_id`, `device_id`, `device_pubkey` (b64url Ed25519 verifying key), `issued_at`, `expires_at`?.
  Binds a device key to the account so verifiers need only the root.

The `Verdict.sig` and `AuditRecord.sig` wire fields are therefore the **compact JWS string** (not raw bytes); the
audit record carries the verdict's JWS verbatim for non-repudiation.

### number-match challenge derivation

When `constraints.challenge_required` is true, the challenge displayed by the approver device and echoed in the
signed `Verdict.challenge_response` is derived from the WYSIWYS `request_hash`:

```
challenge = zero_pad_4_decimal(
  uint32_be(SHA-256( b"allw/number-match/v1" || 0x00 || request_hash )[0..4]) mod 10000
)
```

The result is exactly four decimal digits (`0000` through `9999`). Domain-separating the derivation from
`request_hash` keeps the human-facing code from being a raw prefix of any protocol hash while preserving a single
source of authority: the same `request_hash` the device signs and the verifier recomputes.

### context_ciphertext (JWE)

`context_ciphertext` is a multi-recipient **JWE in General JSON Serialization**
([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) §7.2.1) encrypting the `ApprovalContext` (JSON) to the
approver's device key(s). The `ApprovalContext` is encrypted **once** under a random content-encryption key (CEK)
with `enc = "A256GCM"` ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) §5.3; 96-bit IV; AAD =
`ASCII(BASE64URL(protected_header))`). For **each** recipient device the CEK is wrapped independently with
`alg = "ECDH-ES+A256KW"` (§4.6 + §4.4): an ephemeral X25519 keypair per recipient, `Z = ECDH(ephemeral, device)`
([RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) OKP/X25519), a 256-bit KEK via **Concat KDF** (§4.6.2,
SHA-256), then AES-256 Key Wrap ([RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)) of the CEK. The ephemeral
public key is the recipient header's `epk` (`{kty:"OKP",crv:"X25519",x:<b64url>}`); the shared `protected` header
carries only `enc`, while `alg`/`kid`/`epk` are per-recipient. So one ciphertext is shared and the CEK is wrapped
once per device — a multi-device inbox decrypts the same context with each device's own key. Pure-Rust
(`x25519-dalek` + RustCrypto `aes-gcm`/`aes-kw`/`concat-kdf`), so it compiles to `wasm32`. **Static ECDH for v1**
(the device key is long-term); per-message forward secrecy is deferred. All base64url is unpadded (JOSE-consistent).

## Open decisions

- **JOSE vs COSE** on mobile (default JOSE for substrate consistency).
- **Anti-replay** nonce store on the integrator side — v1: integrator-side `NonceStore` trait + in-memory impl;
  persistence/expiry deferred.
