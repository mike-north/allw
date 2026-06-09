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
3. **WYSIWYS (what you see is what you sign)** — the verdict binds to a single `request_hash` over the _entire_
   human-shown payload (the canonical `ApprovalContext`), computed device-side after decryption. One hash, complete
   binding (no separate `context_digest`). Closes the context/action TOCTOU gap.
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

1. Integrator builds an **ApprovalContext** (actor identity + `ActionRecord` + `summary` + `risk` + `reversible` +
   constraints) and computes `request_hash` over its canonical form (the complete human-shown payload).
2. Encrypts the `ApprovalContext` to the approver's device key(s) → `context_ciphertext` (JWE), and wraps it in an
   **ApprovalRequest** envelope (routing + lifecycle only).
3. Submits to relay → push **wakeup (request id only)** → device fetches the envelope's ciphertext.
4. Device decrypts the `ApprovalContext`, verifies the actor `attestation`, **renders** (WYSIWYS), recomputes
   `request_hash`, human decides; destructive ops may require a **number-match** challenge.
5. Device emits a **Verdict** signed (JWS/COSE) over `(request_id, request_hash, decision, decided_at, nonce)`.
6. Integrator **verifies** (checklist below), composes with its own + upstream policy, appends an **AuditRecord**.

---

## Messages

> **Implementation status.** This section reflects the model resolved in
> [#28](https://github.com/mike-north/allw/issues/28). The merged v1 core (`crates/allw-core`) still implements the
> pre-#28 shape — a flat `ApprovalRequest` with top-level `action`/`summary`/…, a four-field `request_hash`
> (`request-hash/v1`), and a `context_digest` on `AuditRecord`. Bringing the code to the shape below (the
> `ApprovalContext` split, the broadened `request-hash/v2`, and removing `context_digest`) is done in **#5** and a
> small core refactor; this PR locks the contract first.

The human-shown payload and the wire envelope are **separate** (resolved in
[#28](https://github.com/mike-north/allw/issues/28)): everything human-facing is encrypted into an
**`ApprovalContext`**; the **`ApprovalRequest`** the relay sees is a minimal routing/lifecycle envelope wrapping the
ciphertext. **The relay never sees the `ActionRecord` or any rendered content.**

### ApprovalRequest — _envelope (plaintext; relay-visible)_

`v` · `id` · `created_at` · `expires_at` · `approver` (routing id) · `context_ciphertext` (JWE to device key[s]).

Routing + lifecycle + the opaque ciphertext, nothing more. `request_hash` is **not** an envelope field — it is
computed over the `ApprovalContext` (below) by the integrator (locally, pre-send) and recomputed by the device
(post-decryption), and travels only inside the **Verdict**. (A separate transport signature over the envelope
proves the sender is an enrolled actor; that is a relay concern and needs no visibility into content.)

### ApprovalContext — _inside the JWE; the approver's devices only_

`action`: **`ActionRecord`** · `summary` · `actor` { `id`, `kind`, `attestation`: actor-key signature } ·
`risk`(low|med|high|critical) · `reversible` · `constraints` { allowed verdicts, challenge policy } ·
`chain`? (upstream-gate ids, audit correlation only).

This is the **complete human-shown payload**, and `request_hash` is computed over its canonical form (see §Wire
encoding) — so that one hash is the complete WYSIWYS binding. The actor's `attestation` is verified by the
**device** after decryption (the relay never sees it); the integrator still holds the plaintext `ApprovalContext`
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
2. Bound to the **exact request** (no swap): the verdict's `request_id` equals the request's `id`, **and** its
   `request_hash` equals the integrator's locally-computed hash of the canonical `ApprovalContext`. Both are
   required — `request_hash` excludes `id`, so two content-identical requests share a hash; the `id` check
   distinguishes them.
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

Relay routes only — it sees the **ApprovalRequest envelope** (routing + lifecycle + the opaque
`context_ciphertext`) and never the `ApprovalContext` (the `ActionRecord`, `summary`, `actor`, constraints, …).
Push (APNs / FCM; **Web Push later**) carries a wakeup + request id — **never context** (push isn't E2EE / is
size-limited). The envelope's ciphertext is fetched as JWE and decrypted on-device.

---

## v1 scope

- **Ship:** one-shot scope-free verdicts · actor-key attestation · **syntactic** `ActionRecord` (policy-seam T1) ·
  number-match challenge for destructive/critical · optional human `note` · E2EE + verifiable verdict + audit chain.
- **Defer:** reuse/standing autonomy & conditions (→ policy layer), semantic `ActionRecord` fields (→ T3),
  predicate rules.

## Wire encoding

- **Binary fields** (`request_hash`, `prev_hash`, `record_hash`, `sig`,
  `attestation`) serialize as **base64url-unpadded JSON strings** (JOSE-consistent); enables byte-identical
  output across the Rust core and the WASM/TS surface. (`device_cert` is **not** a binary field — it is a
  certificate string; once verdicts are signed it carries a compact JWS. See §Identity & keys.)
- **Timestamps** (`created_at`, `expires_at`, `decided_at`) are `i64` Unix milliseconds (UTC) — deterministic
  for the WYSIWYS canonical hash and trivially identical Rust↔TS.

### request_hash (WYSIWYS canonicalization)

`request_hash` binds a [`Verdict`] to the exact content the human was shown, and is the **complete** WYSIWYS
binding — there is no separate `context_digest` ([#28](https://github.com/mike-north/allw/issues/28)). Both the
integrator (pre-send) and the device (post-decrypt) compute it independently from the same `ApprovalContext`; the
WASM binding must reproduce the same bytes.

**Hashed input — the full canonical `ApprovalContext`** (the entire human-shown payload), plus the `expires_at`
deadline the human is shown:

| Field                          | Rationale                                                    |
| ------------------------------ | ------------------------------------------------------------ |
| `action` (full `ActionRecord`) | What the human approved                                      |
| `summary`                      | Human-readable description shown in the inbox                |
| `actor.id`, `actor.kind`       | Actor identity as displayed                                  |
| `risk`, `reversible`           | Shown to and weighed by the approver                         |
| `constraints`                  | Allowed verdicts + challenge policy that govern the decision |
| `chain`?                       | Upstream-gate correlation, when present                      |
| `expires_at`                   | The deadline shown to the human (carried in the envelope)    |

Excluded: `actor.attestation` (a verification artifact the device checks separately, not shown content), the
envelope's routing/lifecycle fields (`id`, `created_at`, `approver`, `v`), and `context_ciphertext` itself.

**Recipe:**

```
request_hash = SHA-256( b"allw/request-hash/v2" || 0x00 || JCS(canonical ApprovalContext + expires_at) )
```

where the payload is the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JSON Canonicalization Scheme encoding
of the hashed input above (keys in JCS-sorted order). The `0x00` byte separates the domain tag from the payload.

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

## Open decisions

- **Account / device enrollment, key rotation & revocation** — needs its own mini-spec.
- **JOSE vs COSE** on mobile (default JOSE for substrate consistency).
- **Anti-replay** nonce store on the integrator side — v1: integrator-side `NonceStore` trait + in-memory impl;
  persistence/expiry deferred.
