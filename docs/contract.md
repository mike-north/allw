# allw — Approval Primitive Contract (v0.1 draft)

**The keystone.** A request/response protocol:

```
requestApproval(ActionRecord) → verifiable Verdict + AuditRecord     [over an E2EE channel]
```

Thin in surface, rich in contract. Companion to [architecture.md](./architecture.md) (stack) and
[policy-seam.md](./policy-seam.md) (the `ActionRecord` and the policy layer that sits in front of this primitive).

---

## Invariants (the whole design serves these)

1. **E2EE** — the relay never sees plaintext context or rationale. Context is encrypted to the approver's device
   key(s); the verdict is signed by a device key.
2. **Verifiable verdict** — a signed artifact any party can verify _without trusting the relay_, cryptographically
   **bound to the exact request** (no replay, no swap).
3. **WYSIWYS (what you see is what you sign)** — the verdict binds to a hash of the _plaintext the human was
   shown_, computed device-side after decryption. Closes the context/action TOCTOU gap.
4. **Requester attestation** — every request carries an attestable actor identity (v1: **actor-key**), so the
   approver sees a cryptographically-verified origin.
5. **Chain-composable & monotonic** — the primitive **never returns "allow."** It returns _"the human verifiably
   decided X on this exact request."_ Consumers compute `allow = ∧(all gates)`, so a verdict can only **tighten**.
6. **Fail-closed** — timeout / no-response / unverifiable ⇒ **deny** by default.

---

## Roles

- **Actor / Subject** — the automation needing approval (a coding agent on a machine, a web agent via a gateway). Attested.
- **Integrator / Relying Party** — the code calling `requestApproval` (a hook, the proxy, a gateway). Verifies and enforces.
- **Approver** — the human; owns an account with one or more enrolled **devices** (the "inbox").
- **Relay** — zero-knowledge router (Cloudflare Workers + Durable Objects). Sees ciphertext + routing metadata + unforgeable signatures only.

---

## What is approved: the `ActionRecord`

The payload being approved is an **`ActionRecord`** — defined in [policy-seam.md](./policy-seam.md). v1 carries the
**syntactic substrate** (`surface` + tokenized command / MCP call); the semantic `capabilities`/`scope` fields are
reserved and null. The contract is **action-agnostic**: it transports and binds whatever `ActionRecord` it's given.

---

## Lifecycle

1. Integrator builds an **ApprovalRequest** (actor identity + `ActionRecord` + constraints).
2. Encrypts the sensitive context to the approver's device key(s) → `context_ciphertext` (JWE). Computes
   `request_hash` over the canonical plaintext.
3. Submits to relay → push **wakeup (request id only)** → device fetches ciphertext.
4. Device decrypts, **renders** (WYSIWYS), human decides; destructive ops may require a **number-match** challenge.
5. Device emits a **Verdict** signed (JWS/COSE) over `(request_id, request_hash, decision, decided_at, nonce)`.
6. Integrator **verifies** (checklist below), composes with its own + upstream policy, appends an **AuditRecord**.

---

## Messages

### ApprovalRequest

`v` · `id` · `created_at` · `expires_at` · `approver` (routing id) ·
`actor` { `id`, `kind`, `attestation`: actor-key signature } ·
`action`: **`ActionRecord`** · `summary` · `risk`(low|med|high|critical) · `reversible` ·
`context_ciphertext` (JWE to device key[s]) · `request_hash` ·
`constraints` { allowed verdicts, challenge policy } · `chain`? (upstream-gate ids, audit correlation only).

### Verdict — _one-shot and scope-free_

`v` · `request_id` · `request_hash`(echoed/bound) · `decision`(approved|denied|expired|aborted) · `decided_at` ·
`approver` { account_id, device_id } · `note`? (optional freeform) · `challenge_response`? ·
`sig` (device key) · `device_cert`? (chains device key → account root, so verifiers need only the root).

> No `scope`/reuse field — standing autonomy lives in the policy layer ([policy-seam.md](./policy-seam.md)), not the verdict.

### AuditRecord — _append-only, hash-chained_

`seq` · `prev_hash` · `record_hash` · `request_id` · `request_hash` · `actor` · `approver` · `decision` ·
`decided_at` · `action`(ActionRecord) · `context_digest` (proves what was shown without storing plaintext) ·
`policy` { decision, rule_id?, tier, schema_version } (reserved; v1 writes `escalate`) · `note`? ·
verdict `sig` (+ optional integrator counter-sign). Periodically anchor the head hash for non-repudiation.

---

## Verification checklist (integrator MUST)

1. Signature valid against the approver's device/account root key.
2. `request_hash` matches the request the integrator issued (binds verdict ↔ exact context).
3. `decision == approved`.
4. Not expired; `decided_at` within window; nonce unseen (anti-replay).
5. If destructive & challenge required: `challenge_response` correct.
6. **Then** `effective_allow = approved ∧ verified ∧ local_policy ∧ (other gates)`. The primitive contributes a
   verified human decision; it never authorizes by itself.

---

## Identity & keys

- **Actor (v1: actor-key pairing):** each machine/agent enrolls a keypair; requests are signed, so the inbox shows
  a verified origin ("Claude Code · macbook-pro"). No IdP dependency. (OAuth 2.1 / MCP-token interop deferred.)
- **Approver:** an account with enrolled **devices**; each device holds a keypair in **Secure Enclave / StrongBox**,
  with **biometric-gated signing** (the verdict key is released by Face ID / Touch ID and never leaves hardware).
  A `device_cert` chains each device key to an account root so verifiers need only the root.
- **Crypto:** **JOSE** — JWE (X25519 ECDH) for context, JWS (Ed25519) for verdicts/rules — reusing vaultkeeper's
  substrate. Static ECDH for v1; forward secrecy later.

---

## Cross-device coordination

A pending approval may surface on several devices, and the same iOS request can appear twice on a Mac (native +
iPhone-Mirrored). The per-account **Durable Object** coordinates: targeted **fan-out**, **retraction** on the
device(s) once any surface resolves, and **dedupe** across transports. See [architecture.md](./architecture.md).

---

## Transport

Relay routes only. Push (APNs / FCM; **Web Push later**) carries a wakeup + request id — **never context** (push
isn't E2EE / is size-limited). Context is fetched as JWE and decrypted on-device.

---

## v1 scope

- **Ship:** one-shot scope-free verdicts · actor-key attestation · **syntactic** `ActionRecord` (policy-seam T1) ·
  number-match challenge for destructive/critical · optional human `note` · E2EE + verifiable verdict + audit chain.
- **Defer:** reuse/standing autonomy & conditions (→ policy layer), semantic `ActionRecord` fields (→ T3),
  predicate rules.

## Wire encoding

- **Binary fields** (`request_hash`, `prev_hash`, `record_hash`, `context_digest`, `sig`,
  `attestation`) serialize as **base64url-unpadded JSON strings** (JOSE-consistent); enables byte-identical
  output across the Rust core and the WASM/TS surface. (`device_cert` is **not** a binary field — it is a
  certificate string; once verdicts are signed it carries a compact JWS. See §Identity & keys.)
- **Timestamps** (`created_at`, `expires_at`, `decided_at`) are `i64` Unix milliseconds (UTC) — deterministic
  for the WYSIWYS canonical hash and trivially identical Rust↔TS.

### request_hash (WYSIWYS canonicalization)

`request_hash` binds a [`Verdict`] to the exact content the human was shown. Both the integrator
(pre-send) and the device (post-decrypt) compute the value independently from the same plaintext;
the WASM binding must reproduce the same bytes.

**Hashed subset** — exactly four fields:

| Field                          | Rationale                                                                                           |
| ------------------------------ | --------------------------------------------------------------------------------------------------- |
| `action` (full `ActionRecord`) | What the human approved                                                                             |
| `summary`                      | Human-readable description shown in the inbox                                                       |
| `actor.id`, `actor.kind`       | Actor identity as displayed — `attestation` is excluded (used for crypto verification, not display) |
| `expires_at`                   | The deadline shown to the human                                                                     |

Everything else is excluded: `request_hash` itself (circular), `context_ciphertext` (ciphertext; plaintext
is captured above), `actor.attestation`, `constraints`, `chain`, `id`/`created_at`, `approver` routing id,
top-level `risk`/`reversible` (echoed from `action`), `v`.

**Recipe:**

```
request_hash = SHA-256( b"allw/request-hash/v1" || 0x00 || JCS(subset) )
```

where `JCS(subset)` is the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JSON Canonicalization
Scheme encoding of `{ action, actor: { id, kind }, expires_at, summary }` (keys in JCS-sorted order).
The `0x00` byte separates the domain tag from the payload.

**Versioning:** `b"allw/request-hash/v1"` is the domain separation tag and the version knob. Any change
to the hashed subset, encoding, or recipe requires bumping `v1` → `v2`.

### audit record_hash

`record_hash = SHA-256( b"allw/audit-record/v1" || 0x00 || JCS(record_without_record_hash) )`

Every field of the `AuditRecord` is covered **except `record_hash` itself** (circular). Critically
`prev_hash` is included, so each record commits to its predecessor → tamper-evident chain.
Domain tag `b"allw/audit-record/v1"` is distinct from the request-hash tag; the `/v1` suffix is the
version knob.

## Open decisions

- **Account / device enrollment, key rotation & revocation** — needs its own mini-spec.
- **JOSE vs COSE** on mobile (default JOSE for substrate consistency).
- **Anti-replay** nonce store on the integrator side.
