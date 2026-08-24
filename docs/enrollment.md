# allw — Enrollment, Rotation & Revocation

Companion to [contract.md](./contract.md). This mini-spec closes the account/device enrollment open decision and
pins how verifiers decide whether a device, actor, or account root is trusted.

## Scope

This document covers:

- account identity and the account-root trust anchor;
- approver device enrollment and `device_cert` validation;
- the cross-device `device_cert` issuance ceremony for devices that do not hold the account root (#175);
- actor-key enrollment for requester attestation;
- work-stream attestation: the work-stream label, the machine Secure-Enclave keypair (the cryptographic trust
  root), and the asserted-not-verified harness session-ID (Decisions 4 + 5, #133);
- device-key and account-root rotation;
- revocation propagation through the relay and offline verifiers;
- lost/replaced-device recovery.

It informs relay pairing/authn work (#89), actor-key attestation work (#16), and work-stream attestation
(#133, which extends the actor-key model into a machine key + work-stream label — see §Work-Stream Attestation).

Out of scope:

- the native app UX for pairing and recovery;
- IdP/OAuth/MCP-token federation;
- org policy distribution and rule sync;
- hardware-keystore APIs for each platform.

## Model

An **account** is the user's approval inbox and trust domain. It is identified by `account_id` and anchored by an
Ed25519 **account root**. The relay routes by `account_id`, but the relay is not a trust anchor: it stores public
keys and routing metadata only.

```
account_id
  current account root key  ──signs──▶ device_cert(device_id, device signing key)

relay account object
  device registry: device_id -> X25519 encryption public key + metadata
  actor registry:  actor_id  -> actor attestation public key + metadata
  request/verdict routing state
```

The relay device registry and the signed account-state document are deliberately separate. The registry is the
online routing/encryption view the relay enforces; signed account state is the verifier/device trust view that
includes revocation, device signing keys, actor keys, and root rotation state. The relay may store the latest
account state, but it cannot author it.

The approval primitive has two independent device keys:

| Key                   | Algorithm | Purpose                                        | Relay-visible?                        |
| --------------------- | --------- | ---------------------------------------------- | ------------------------------------- |
| Device encryption key | X25519    | JWE recipient for `ApprovalContext` ciphertext | public key only, in `GET /devices`    |
| Device signing key    | Ed25519   | Signs verdicts and policy rules                | public key only through `device_cert` |

These two keys are derived from **two independently-drawn 32-byte random seeds** — enrollment MUST NOT derive both
from one seed. The cross-platform smoke tests (`crates/allw-uniffi/tests/*`, and the WASM vectors) reuse a single
seed for both purely for fixture brevity; that shortcut is a test convenience only and must never be carried into
real enrollment. (See the `derive_device_keys_json` doc comment in `crates/allw-uniffi/src/lib.rs`.)

The account root signs `device_cert` objects for device signing keys. Integrators verify verdicts with only the
configured account-root public key plus the `device_cert` carried in the verdict.

## Requirements

1. Private keys and seeds must never cross the relay boundary.
2. A device may receive encrypted requests only while it is enrolled in the relay device registry.
3. A device may resolve a request only while it is still enrolled.
4. A verifier must accept a verdict only if its `device_cert` chains to an acceptable account root and the verdict
   itself verifies under the certified device signing key.
5. A requester origin is accepted as verified only if its actor attestation verifies under an actor key that is
   `active` in root-signed account state (#16); a relay-supplied key never drives a verified origin.
6. Rotation must have an explicit grace period; after the grace period, old keys fail closed.
7. Revocation must propagate to online relay state immediately and to offline verifiers through signed
   account-state material.
8. Recovery must preserve the user's account identity when possible; when impossible, recovery creates a new
   trust anchor and requires relying parties to reconfigure trust.
9. A device that does not hold the account root must obtain its `device_cert` through a ceremony whose
   enrollee→root leg is authenticated by out-of-band key material the relay never receives. The relay may carry
   ceremony bytes; it must never be able to cause a key it chose to be certified.

## Device Enrollment

Device enrollment binds an approver device to an account in two places:

1. **Relay device registry:** `device_id -> device_encryption_pubkey`, used by integrators to encrypt
   `ApprovalContext` JWE recipients and by the relay to route presence sockets.
2. **Device certificate:** `device_cert`, an EdDSA compact JWS signed by the account root, binding
   `device_id -> device_signing_pubkey` for verdict verification.

### Pairing Flow

The v1 pairing flow is:

1. Account owner starts a short-lived pairing: `POST /{account_id}/pairing/start`.
2. Relay returns `{ code, expires_at, pairing_auth_token }`; the code and bearer token are shown
   out-of-band to the device or delivered through the account-owner pairing ceremony.
3. Device completes pairing with `{ code, pubkey, label?, push_tokens? }`, where `pubkey` is its **X25519
   encryption public key** — the single key the relay registers. The Ed25519 **signing** key is deliberately
   **not** sent to the relay: it is certified out of band through the `device_cert`, and routing the signing key
   through the relay would make the relay the carrier of the verdict-key binding. (An earlier draft of this doc
   listed `encryption_pubkey` + `signing_pubkey` here; the implemented relay contract is single-key, and that is
   the intended design, not a shortfall — see §Cross-Device `device_cert` Issuance Ceremony.)
4. Relay validates the pairing bearer token, consumes the code exactly once, creates `device_id`,
   returns `device_auth_token`, and stores only public key material plus relay-token hashes.
5. Account root signs a `device_cert` for the device signing key. When the device _is_ the root holder it signs
   its own cert locally; when it is not — the phone, a browser, a second Mac — the signing key travels no
   further than its own hardware and the cert is obtained through the ceremony in
   §Cross-Device `device_cert` Issuance Ceremony:

   ```jsonc
   // compact JWS payload, typ = "allw-device-cert+jws"
   {
     "account_id": "acct_123",
     "device_id": "dev_abc",
     "device_pubkey": "<base64url Ed25519 public key>",
     "issued_at": 1760000000000,
     "expires_at": 1791536000000, // optional
   }
   ```

6. Device stores its local secrets, relay coordinates, `device_id`, and `device_cert`.
7. The account-root public key is the integrator trust anchor.

Design note: the current walking-skeleton approver stores the account-root seed and device seeds in a local
software keyfile so the loop can run end to end. Production custody moves account-root signing and device signing
into hardware-backed or recovery-protected stores without changing the wire protocol.

### Device Certificate Validation

Given a verdict and configured account-root public key, a verifier must:

1. Require `verdict.device_cert`; missing cert is deny.
2. Parse it as compact JWS with `typ: "allw-device-cert+jws"` and `kid == account_id`. In this protocol `kid`
   names the account trust domain, not an arbitrary key-record identifier, so verifiers select the configured
   account-root trust anchor before checking claims.
3. Verify the cert signature against an acceptable account root for `account_id`.
4. Require cert claims `account_id == verdict.approver.account_id`.
5. Require cert claims `device_id == verdict.approver.device_id`.
6. Require `now <= cert.expires_at` when `expires_at` is present.
7. Extract the certified `device_pubkey`.
8. Verify the verdict JWS with that certified device key.

What this proves: the relay cannot cause an arbitrary device key to be trusted by listing it in `/devices`; only a
root-signed `device_cert` can make a verdict key trusted.

## Cross-Device `device_cert` Issuance Ceremony

> **Status:** decided (#175). This section owns the path by which a device that is **not** the account-root
> holder — an iPhone, a Mac, a browser — obtains a root-signed `device_cert` without its signing key ever
> leaving the hardware that generated it. Wire detail for the relay endpoints lives in
> [relay-api.md](./relay-api.md) §Enrollment courier; the adversary analysis lives in
> [threat-model.md](./threat-model.md) §R8.

### The gap this closes

The walking-skeleton `allw-approver pair` holds the account-root seed and the device seeds in one keyfile, so it
self-mints its own `device_cert`. Every other approver surface is in a different position: the **phone is not the
root holder**. Its signing key is generated in the Secure Enclave and can never be exported, the relay neither
issues nor stores `device_cert`, and a verdict without a valid root-signed cert is denied by integrators
(§Device Certificate Validation). Without a built ceremony there is simply no path from "the phone paired with
the relay" to "the phone can produce a verdict anyone will accept."

### What actually has to move — and why the problem is asymmetric

Only two artifacts cross between the enrollee and the root holder, and **both are public**:

| Direction                       | Artifact                                                                   | Confidentiality | Integrity                                                     |
| ------------------------------- | -------------------------------------------------------------------------- | --------------- | ------------------------------------------------------------- |
| enrollee → root holder ("out")  | a **CSR**: `device_id` + Ed25519 signing pubkey + X25519 encryption pubkey | not required    | **critical** — this is what the root is about to bless        |
| root holder → enrollee ("back") | the issued `device_cert` (compact JWS)                                     | not required    | **self-verifying** — it is signed by the root the device pins |

The asymmetry is the whole design:

- The **back** leg needs no protection at all. A `device_cert` is worthless to anyone who does not hold the
  matching signing key, and the enrollee verifies the JWS against the account-root public key it already pinned.
  A hostile carrier can withhold or corrupt it — which fails closed (no cert, no accepted verdicts) — but cannot
  forge or substitute one.
- The **out** leg is the entire attack surface. If a carrier can swap the CSR's `signing_pubkey`, the account
  root will mint a valid cert over an attacker-held key, and the attacker can sign verdicts that every integrator
  accepts. That is full account compromise. So the CSR — and only the CSR — must be authenticated by something
  the carrier does not know.

### Options considered

| Option                                                                                                                           | Relay trust required                                                    | Works for the real consumer pairs?                                                                                                                                                                                           |
| -------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A. Two-QR ceremony** — enrollee displays the CSR as a QR, root holder scans it; root displays the cert QR, enrollee scans back | none                                                                    | **No.** The root holder in v1 is a **terminal CLI**, which can _display_ a QR but cannot _scan_ one. The enrollee→root leg would degrade to hand-typing a 43-char pubkey plus a UUID. The web approver has no camera either. |
| **B. Relay store-and-forward courier + MAC-authenticated CSR** _(chosen)_                                                        | **none for trust** — the relay carries opaque bytes it cannot forge     | **Yes**, for every pair: CLI↔phone, CLI↔browser, Mac↔phone. Needs exactly one out-of-band channel, in the direction every consumer already supports.                                                                         |
| C. Relay courier with a human-compared code only (no MAC)                                                                        | **yes** — a substituting relay only has to beat a short comparison code | Yes, but the phishing-resistance control would be a ~20-bit code an adversary who sees the genuine CSR can grind. Rejected as the _primary_ control; kept as defense-in-depth (below).                                       |
| D. Ship a pre-issued `device_cert` in a provisioning bundle                                                                      | n/a                                                                     | Dev-only. Requires the root holder to know the device key before the device exists, so it cannot honor the Secure-Enclave invariant for a real device. See §Dev stub.                                                        |

**Decision: option B.** The ceremony needs exactly **one** out-of-band channel, and it runs in the _easy_
direction — root holder → enrollee — where every consumer already has an affordance: the CLI prints a QR that the
phone's camera reads, or prints a link the browser pastes. The hard direction (enrollee → root holder, which would
demand a camera on the root side) is replaced by a relay mailbox whose contents the root holder authenticates
cryptographically. The relay gains no trust: it carries a MAC it cannot forge and a JWS it cannot sign.

### The enrollment bundle (the one out-of-band payload)

The root holder mints a fresh **enrollment secret** (32 random bytes) locally. **It is never sent to the relay.**
The bundle carries everything the enrollee needs to bootstrap, as compact JSON:

```jsonc
{
  "v": 1,
  "relay_url": "https://relay.example.com",
  "account_id": "acct_123",
  "account_root_pubkey": "<base64url Ed25519 public key>", // the trust anchor the enrollee pins
  "pairing_code": "ABCD2345",
  "pairing_auth_token": "<base64url>",
  "enrollment_id": "<base64url 16 bytes>", // relay mailbox id (public)
  "enrollment_secret": "<base64url 32 bytes>", // NEVER leaves this channel
  "expires_at": 1760000600000,
  "label": "Mike's iPhone", // optional suggestion from the root holder
}
```

Serialized as `base64url(JCS(bundle))` and presented **two ways from the same bytes**:

- **QR code** (phone camera) and
- **a link the human can copy**: `allw://enroll#<b64url>` for the native app, or
  `https://<web-approver-host>/#<b64url>` for the web approver.

The payload rides in the URL **fragment**, never the query string, so a bundle pasted into a browser address bar
is never transmitted to a server. Treat the whole bundle as secret material: it is single-use, expires with the
pairing code (10 minutes), and is invalidated by the abort path below.

### Derived key material and the confirmation code

Every derivation is domain-separated, matching the conventions in [contract.md](./contract.md) §Wire encoding:

```
K_csr     = HKDF-SHA256(ikm = enrollment_secret, salt = "", info = b"allw/enroll-csr-key/v1",     L = 32)
K_confirm = HKDF-SHA256(ikm = enrollment_secret, salt = "", info = b"allw/enroll-confirm-key/v1", L = 32)

csr_mac      = HMAC-SHA256(K_csr,     b"allw/enroll-csr/v1"     || 0x00 || JCS(csr))          // base64url-unpadded
confirm_code = zero_pad_6_decimal(
                 uint32_be( HMAC-SHA256(K_confirm, b"allw/enroll-confirm/v1" || 0x00 || JCS(csr))[0..4] ) mod 1_000_000
               )
```

`csr_mac` is the load-bearing control: it proves the CSR was authored by whoever received the out-of-band bundle.
`confirm_code` is a six-digit human cross-check, computed **independently on both sides from the CSR bytes each
side holds**. It is never transmitted — a relay that carried the code could substitute a CSR and replay the
genuine code, so a wire-supplied confirmation code would be worse than none. Both sides display it; the human
compares.

> **Honest ceiling.** `confirm_code` is ~20 bits. An adversary who _already holds the enrollment secret_ and has
> seen the genuine CSR can grind a colliding code offline. It is therefore defense-in-depth for the
> secret-leak / race case and a guard against accidental mismatch — **not** the phishing-resistance control.
> The MAC is that control (threat-model.md §R8).

### The certificate signing request

```jsonc
// the MACed object; `mac` travels beside it in the request body, never inside it
{
  "v": 1,
  "enrollment_id": "<base64url 16 bytes>", // binds the CSR to this ceremony instance
  "account_id": "acct_123",
  "device_id": "dev_abc", // relay-assigned by POST /pairing/complete
  "signing_pubkey": "<base64url Ed25519 public key>", // what the root is asked to certify
  "encryption_pubkey": "<base64url X25519 public key>", // for the account-state devices[] entry
  "label": "Mike's iPhone",
  "purpose": "enroll", // "enroll" | "rotate"
  "created_at": 1760000000000,
}
```

`encryption_pubkey` is included **deliberately**: the root holder must build the account-state `devices[]` entry
from MAC-authenticated material, not from the relay's `GET /devices` response. Reading it from the relay would
let the relay choose which X25519 key the root vouches for.

### Ceremony sequence

`A` = the **account-root holder** (v1: `allw-approver`; later a root-holding Mac app).
`B` = the **enrollee** (iPhone/iPad/Mac app, or the web approver).

1. **A** `POST /{acct}/pairing/start` → `{ code, expires_at, pairing_auth_token }`.
2. **A** `POST /{acct}/enrollments/start` → `{ enrollment_id, expires_at, enrollment_auth_token }`, and
   generates `enrollment_secret` locally. The relay never sees the secret.
3. **A** renders the enrollment bundle (QR + copyable link) and waits, polling the CSR mailbox.
4. **B** scans or pastes the bundle, **pins** `relay_url` / `account_id` / `account_root_pubkey`, and generates
   its two independent seeds on-device (signing key in Secure Enclave / StrongBox where available).
5. **B** `POST /{acct}/pairing/complete` with `pubkey` = its X25519 encryption key (+ `label`, `push_tokens`)
   → `{ device_id, device_auth_token }`.
6. **B** builds the CSR, computes `csr_mac`, `POST /{acct}/enrollments/{id}/csr` (Bearer `device_auth_token`),
   and displays its locally-derived `confirm_code`.
7. **A** `GET /{acct}/enrollments/{id}/csr` (Bearer `enrollment_auth_token`) and checks, in order, failing
   closed at the first failure: `v == 1`; `enrollment_id` matches this ceremony; `account_id` matches; both
   pubkeys are 32-byte base64url; `created_at` inside the enrollment window; **`csr_mac` verifies under
   `K_csr`**; `device_id` is not revoked in the account's highest-sequence account state.
8. **A** displays the CSR's `label` and its own derived `confirm_code`; the human compares it with **B**'s screen
   and gives an explicit confirmation (a `y` at the CLI, biometric in an app). No confirmation ⇒ abort.
9. **A** `issue_device_cert(root, account_id, device_id, signing_pubkey, now, expires_at)` — an explicit
   `expires_at` (default 180 days) is **recommended**, so a forgotten device eventually fails closed even if it
   is never revoked.
10. **A** `POST /{acct}/enrollments/{id}/cert` with the compact JWS, and **publishes updated account state**
    (`sequence + 1`, a `devices[]` entry carrying both pubkeys from the CSR plus `cert_expires_at`) via
    `POST /{acct}/account-states`. Verdict verification chains through the cert alone, so this step is not
    required for the device to work — but it is what gives offline verifiers and the inbox a complete trust view.
11. **B** polls `GET /{acct}/enrollments/{id}/cert` (Bearer `device_auth_token`) and, before persisting
    anything, verifies the cert against the **pinned** root: compact JWS with `typ = "allw-device-cert+jws"` and
    `alg = EdDSA`, `kid == account_id`, signature under the pinned `account_root_pubkey`, claims
    `account_id` == pinned, `device_id` == its own, **`device_pubkey` == its own signing pubkey**, and
    `expires_at` (when present) in the future.
12. Only on full success does **B** persist `{ account_id, device_id, device_auth_token, device_cert,
account_root_pubkey }` and unlock its inbox. The enrollment is consumed; the relay may drop the row at TTL.

### Failure and abort paths — all fail-closed

| #   | Situation                                                   | Behavior                                                                                                                                                                                                                                |
| --- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Bundle expired / enrollment TTL elapsed                     | Every courier call answers `410`. **B** shows "enrollment expired — start again"; no cert exists, nothing is persisted.                                                                                                                 |
| 2   | CSR mailbox already claimed (first write wins)              | Second poster gets `409`. **B** aborts visibly and the human restarts with a **fresh** secret. A squatted mailbox must never be silently reused.                                                                                        |
| 3   | `csr_mac` fails at **A**                                    | **A** never signs. It calls `POST …/abort`, prints what failed, and the enrollment is dead. This is the relay-substitution case.                                                                                                        |
| 4   | `confirm_code` mismatch, or the human declines              | Same as 3 — explicit abort, no signature.                                                                                                                                                                                               |
| 5   | `device_id` appears in the highest-sequence revocation list | **A** refuses to issue and aborts. A revoked device id is never re-certified (§Revocation and rotation interaction).                                                                                                                    |
| 6   | Abort called                                                | The enrollment row is terminal. Both mailboxes answer `409`; **B** stops polling and reports the abort instead of timing out silently.                                                                                                  |
| 7   | Relay withholds, corrupts, or never delivers the cert       | **B** times out with no cert. It stays **uncertified**, which is indistinguishable from unpaired at the UI layer: the inbox is unreachable.                                                                                             |
| 8   | Cert fails any device-side check in step 11                 | **B** discards it (never persists), reports the failure, and **self-revokes** its relay registration (`POST /devices/{id}/revoke`) so it does not linger in `GET /devices` as a recipient that can never produce an acceptable verdict. |
| 9   | **B** crashes between pairing and cert receipt              | Its seeds are already persisted (a device that lost its seeds could never use a cert). On restart it may re-poll the cert mailbox with the same `enrollment_id`; if the enrollment is gone it self-revokes and restarts the ceremony.   |

**The structural UI invariant:** a surface has no approvable inbox until a **root-verified** `device_cert` is
persisted. "Paired but uncertified" is not a usable state and must not be rendered as one — the approve path is
unreachable, not merely disabled (mirrors `docs/apple-approver-app.md` §6.7).

### Revocation and rotation interaction

- **Revocation is unchanged.** The ceremony issues certs; it never revokes. Revoking a device remains: relay
  device revocation plus a `revocations` entry in the next account-state document (§Revocation).
- **A revoked `device_id` is never re-certified.** Step 7 makes that a hard precondition. A replaced device
  re-runs the whole ceremony and receives a **new** relay-assigned `device_id`; the old id stays revoked
  forever, so an old cert can never be resurrected.
- **Rotation reuses this ceremony as its transport.** A device rotating its signing key generates a new key,
  submits a CSR with `purpose: "rotate"` and its **existing** `device_id`, and the root issues a fresh cert.
  The grace-period rules in §Device-Key Rotation apply unchanged: both certs may verify during the grace window,
  and a device suspected compromised is revoked rather than rotated.
- **Encryption-key rotation** still goes through re-pairing (the relay registry is the encryption-key source of
  truth); a `purpose: "rotate"` CSR carrying a changed `encryption_pubkey` tells the root to publish the updated
  `devices[]` entry in the same account-state bump.
- **Known gap (not solved here):** the relay's `POST /devices/{id}/revoke` is **self-revoke only**, so the root
  holder cannot evict a lost phone from the relay registry — it can only publish account-state revocation, which
  is what verifiers actually enforce. An account-root-authorized revoke endpoint is a separate change; see
  §Deferred Decisions.

### What a hostile relay can and cannot do

| Relay behavior                        | Outcome                                                                                                                    |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Substitute the CSR's `signing_pubkey` | **Blocked.** `csr_mac` is keyed by a secret the relay never receives; **A** aborts.                                        |
| Forge or substitute a `device_cert`   | **Blocked.** The cert is a JWS under the account root; **B** verifies against the pinned root and its own pubkey.          |
| Replay an old CSR or cert             | **Blocked.** Both are bound to a single-use `enrollment_id` with a 10-minute TTL; both mailboxes are write-once.           |
| Read the CSR / cert                   | Allowed and harmless — both are public key material, the same class of data as `GET /devices` and `GET /actors`.           |
| Withhold, delay, or drop either leg   | Denial of service only ⇒ no cert ⇒ fail-closed. Availability is an accepted residual (threat-model.md).                    |
| Enumerate or squat enrollments        | Mitigated by 128-bit random `enrollment_id`, bearer-token auth on every courier call, short TTL, and write-once mailboxes. |

The relay stores only an opaque CSR object and an opaque compact JWS. It **must not** validate the MAC (it has no
key) or the certificate (it is not a trust anchor). Its shape/ownership checks are anti-abuse, never trust.

### Consumer notes

- **Apple approver app** (`docs/apple-approver-app.md` §3.3): camera QR scan is the primary path; the
  `allw://enroll#…` deep link covers AirDrop/Messages hand-off and macOS, where the bundle is pasted. Seeds are
  generated on-device; the signing seed goes to Keychain/Secure Enclave and is never part of the CSR.
- **Web approver**: no camera required — the human pastes the `https://<host>/#<b64url>` link, and the fragment
  never reaches the server. Everything else is identical.
- **`allw-approver` CLI** plays **A** (`enroll` verb: start, render QR + link, poll, verify MAC, prompt with the
  confirmation code, issue, publish, post). It can also play **B** for a second CLI install, which makes the
  ceremony testable end-to-end without a phone.

### Dev stub (superseded, dev-only)

A provisioning bundle carrying relay coordinates, `account_id`, the account-root pubkey, and a **pre-issued**
`device_cert` remains acceptable in **development builds only**, and **must never** carry the device signing
seed. It exists so surfaces could be exercised before this ceremony shipped; once the ceremony lands, production
builds must use it, and any stub path must be compiled out or refuse to run against a non-local relay.

### UAT checklist

Drive these through the real surfaces (CLI subprocess + app/browser), not in-process helpers:

1. **Happy path, phone:** CLI `enroll` → QR scanned by the app → cert issued → the app signs a verdict an
   integrator accepts against the account-root pubkey alone.
2. **Happy path, browser:** same bundle pasted as a link into the web approver → cert issued → verdict accepted.
3. **Confirmation codes match** on both screens in the happy path, and the CLI refuses to proceed without an
   explicit confirmation.
4. **Tampered CSR:** flip one byte of `signing_pubkey` in flight → CLI reports a MAC failure, issues nothing,
   and the enrollment is terminal.
5. **Wrong secret:** enrollee uses a bundle from a different ceremony → MAC failure → no cert.
6. **Expired bundle:** wait past the TTL → `410` on both legs → enrollee reports expiry, nothing persisted.
7. **Squatted mailbox:** post a second CSR → `409` → the genuine enrollee aborts visibly.
8. **Abort:** operator declines at the confirmation prompt → enrollee's poll reports abort (not a timeout) and
   the enrollee holds no cert.
9. **Forged cert:** relay returns a cert signed by a different root, or one whose `device_pubkey` is not the
   enrollee's → the enrollee discards it, persists nothing, self-revokes, and its inbox stays unreachable.
10. **Revoked-device refusal:** revoke a device, then re-run the ceremony reusing its `device_id` → the root
    holder refuses to certify.
11. **Rotation:** `purpose: "rotate"` with an existing `device_id` → a fresh cert; verdicts under both keys
    verify during the grace window and the old key fails after it.
12. **Relay silence:** kill the relay mid-ceremony → both sides time out fail-closed; the enrollee's inbox is
    unreachable.

## Actor-Key Enrollment

Actor keys attest the requester origin shown to the human. An actor has:

```jsonc
{
  "actor_id": "machine:macbook-pro",
  "kind": "claude-code",
  "pubkey": "<base64url Ed25519 public key>",
  "label": "MacBook Pro",
}
```

Target v1 rule: an `ApprovalContext.actor.attestation` is a base64url signature over a domain-separated actor
attestation payload:

```jsonc
{
  "v": 1,
  "account_id": "acct_123",
  "actor_id": "machine:macbook-pro",
  "actor_kind": "claude-code",
  "request_id": "uuid-v4",
  "request_hash": "<base64url>",
}
```

The payload is a domain-separated EdDSA compact JWS (`typ = "allw-actor-attest+jws"`, `alg = EdDSA`,
`kid = actor_id`) over these v1 claims. It binds the attestation to **both** the `request_id` and the WYSIWYS
`request_hash`: because `request_hash` excludes `request_id`, two content-identical requests with different ids
share one hash, so binding `request_id` too closes the cross-request "no swap" gap (mirroring the verdict path's
id+hash binding). The `account_id` claim binds the attestation to a single account trust domain.

**The trust anchor is root-signed account state, not the relay (#16, resolved).** Actor keys are anchored in the
root-signed account-state document (§Account State below): each `actors` entry carries `actor_id → pubkey` and a
`status`, and the document is signed by the account root. The approver device resolves the actor's verifying key
from the **highest valid-sequence account-state document the configured account root signed**, then verifies the
attestation against that key. A relay-distributed `GET /actors` registry key is **never** trusted to drive a
verified origin — a malicious or compromised relay can list its own key for an actor id, but it cannot author
account state, so it can never forge a `✓ VERIFIED` render. When no root-signed account state is available, or the
actor is absent/revoked/inactive, or any binding check fails, the origin is shown `⚠ UNVERIFIED` (fail-closed); it
is never shown as verified.

Enrollment requirements:

- Duplicate `actor_id` values are rejected unless the existing actor is explicitly rotated.
- Actor enrollment stores only public key material and metadata.
- Actor revocation prevents future requests from being shown as verified for that actor. A `revocations` entry
  (`kind: "actor"`) or a non-`active` `status` at the highest sequence fails closed — the actor is not verifiable
  even if an older state document still lists it active.
- The relay may help distribute actor public keys, but the device must treat actor trust as account-state data,
  not as a relay assertion.

**Resolved (#16):** actor enrollment is represented as **entries in signed account-state** (`actors`), reusing the
same root-signed document and highest-sequence revocation semantics as device trust — not a separate root-signed
`actor_cert` artifact. This follows the established pattern: device keys, policy-rule signing keys, and verdict
verification all resolve trust through the same account-state document. A standalone `actor_cert` remains an
option for future flows that need the trust material to ride inside the request envelope, but v1 anchors through
account state.

## Work-Stream Attestation

> **Status:** design spec (CEO roadmap Decisions 4 + 5, 2026-06-13; tracked in #133, post-v1). This section
> _extends_ the actor-key model above; it does not replace it. Where it refines a term, it says so explicitly.

The actor-key model above answers **"which machine signed this request?"** Work-stream attestation answers the
question the human actually reads in the inbox: **"which _stream of work_ is asking?"** — e.g. _"Codex on
devbox-1 / refactor-auth"_. The two compose: the machine key is the cryptographic trust root, and the
work-stream label is the human-meaningful unit that trust is anchored _to_. The design's whole job is to keep the
boundary between **cryptographically verified** and **merely asserted** honest, so the inbox never overstates what
it knows.

### Decision 4 — the attested unit is the work-stream LABEL

The unit of attested identity shown in the inbox is the **work-stream label**, not the agent binary. A human
reasoning about "should I approve this?" reasons about a _stream of work_ ("the refactor-auth run Codex is doing
on devbox-1"), not about which executable emitted the call. The label is therefore a first-class, structured
field — not free-form display text.

A work-stream label has three components:

```jsonc
{
  "machine": "devbox-1", // human name of the machine (mirrors the machine actor's label)
  "harness": "codex", // the tool harness / agent kind running the stream (e.g. "codex", "claude-code")
  "stream": "refactor-auth", // the human-meaningful stream/session name (free text the harness emits)
}
```

The inbox renders these as **"{harness} on {machine} / {stream}"** (e.g. _"Codex on devbox-1 / refactor-auth"_).
Each component carries a **different trust weight** (see Decision 5), and the renderer MUST reflect that — the
label is not uniformly trusted just because it is one string on screen.

**Relationship to `session_label`.** The contract already carries a `session_label` at the `ApprovalRequest`
envelope level as a **structure** field (`docs/contract.md` §Messages; `docs/policy-seam.md` §Structure vs.
data). The work-stream label is the **structured, trust-tiered refinement** of that field: `session_label`
remains the relay-visible structure string (the `"{harness} on {machine} / {stream}"` rendering, or a compatible
opaque token), while the components above and their per-component trust live inside the JWE `ApprovalContext` and
the machine attestation (below), never widening what the relay sees. The structure-not-data boundary is
unchanged: the relay may see the label string as structure; it never sees action data, and it is never the trust
anchor for the label.

### Decision 5 — the two-part origin signal

A request's origin is asserted by **two independent signals with different trust weights**:

| Signal                               | What it proves                                          | Trust weight                   |
| ------------------------------------ | ------------------------------------------------------- | ------------------------------ |
| **Machine Secure-Enclave keypair**   | _which machine_ produced the request                    | **cryptographically verified** |
| **Deterministic harness session-ID** | _which stream/session_ on that machine (asserted by it) | **asserted, NOT verified**     |

#### Part 1 — the machine Secure-Enclave keypair (cryptographic trust root)

The cryptographic trust root for "which machine" is a **machine-level keypair held in the Secure Enclave /
StrongBox** of the requesting machine. **This is the actor key of #16, sharpened:** what the existing model calls
the _actor_ is, in the work-stream model, precisely the **machine**. The composition with #16 is explicit and
reuses the existing machinery rather than forking it:

- The machine keypair is enrolled **exactly as an actor key is** — as an `actors` entry in **root-signed
  account state** (§Account State, §Actor-Key Enrollment). It is **not** a new, separate key class and **not** a
  separately-rooted trust anchor. The `actor_id` is the machine identity (e.g. `machine:devbox-1`); the
  `kind`/`label` metadata names the machine. Anchoring, rotation, and revocation are the actor-key rules already
  specified above — nothing new is invented for the machine key.
- Each request carries a **machine attestation** — the actor-key attestation of #16
  (`crates/allw-core/src/attestation.rs`, `typ = "allw-actor-attest+jws"`), signed by the machine's
  Secure-Enclave key, bound to `(account_id, actor_id, actor_kind, request_id, request_hash)`. Verification is
  unchanged: the approver device resolves the machine key from the highest valid-sequence root-signed
  account-state document and verifies the attestation against it. A relay-supplied key never drives a verified
  machine identity.
- "Secure Enclave" is the **custody** of that key on the requesting machine (hardware-backed, non-exportable),
  matching how approver _device_ signing keys are custodied (`docs/architecture.md`). It does not change the wire
  format or the account-state anchoring — it strengthens the residual risk (a stolen machine key cannot be
  exfiltrated as bytes), which the threat model notes.

> **No design fork with #16/#71.** The machine key is the account-state-anchored actor key; the only change is
> conceptual sharpening (actor → machine) plus naming the custody. The contract's `Actor` type, the
> account-state `actors` schema, and the attestation verification path are all unchanged.

#### Part 2 — the deterministic harness session-ID (asserted, NOT verified)

The stream component of the label is anchored to a **deterministic session-ID emitted by the tool harness's
hook** (e.g. a Claude Code or Codex hook that emits a stable id for the duration of one agent session). This id
lets the inbox group, de-duplicate, and name a stream of work coherently.

**This signal is asserted, not cryptographically verified — and the spec is deliberately precise about that:**

- **The hook is a dumb emitter and holds no key** (`docs/architecture.md` §"Local execution: WASM, not native
  binaries"; the hard constraint below). It emits a session-ID string; it does **not** sign anything.
- The session-ID therefore reaches the allw client as **plaintext the harness asserted**. The client may include
  it inside the machine attestation's signed payload (so the _machine_ vouches "I emitted a request carrying
  session-ID X for stream Y"), but a machine-key signature over an asserted string only proves **the machine
  forwarded that string** — it does **not** prove the harness authenticated the session, that the session-ID is
  unforgeable, or that the stream name is truthful. There is no harness key, so there is no harness-level
  cryptographic guarantee to be had.
- Concretely: a compromised or misbehaving harness on an _enrolled, verified machine_ can assert any
  `harness`/`stream`/session-ID it likes. The machine attestation will still verify (the machine is real); the
  **stream identity is only as trustworthy as the machine's own software stack.** That is the honest ceiling, and
  the inbox must present it as such.

### The cryptographically-guaranteed vs. merely-asserted boundary

This is the most important part of the spec. The inbox MUST present each component of a work-stream label at its
true trust weight and **fail closed** on the asserted parts — never rendering an asserted-only signal as if it
were cryptographically verified.

| Label component              | Backed by                                       | Inbox trust marker                                                                             |
| ---------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `machine` (which machine)    | machine Secure-Enclave key, root-anchored (#16) | **`✓ VERIFIED`** when, and only when, the machine attestation verifies (§Actor-Key Enrollment) |
| `harness` (which agent kind) | asserted by the machine; no harness key         | **asserted** — shown as machine-asserted, never `✓ VERIFIED`                                   |
| `stream` / session-ID        | asserted by the harness via a keyless hook      | **asserted** — shown as machine-asserted, never `✓ VERIFIED`                                   |

Presentation rules (extend the existing `✓ VERIFIED` / `⚠ UNVERIFIED` discipline in
`packages/approver/src/lib/render.ts` and `crates/allw-core/src/attestation.rs`):

1. **Machine identity** uses the existing two-state origin discipline unchanged: `✓ VERIFIED` only when the
   machine attestation verifies against the root-anchored machine key bound to this `request_id` + `request_hash`;
   otherwise `⚠ UNVERIFIED` (fail-closed — absent / not-root-anchored / revoked / mismatched all render
   unverified, never verified).
2. **The stream/harness components are NEVER shown with the `✓ VERIFIED` marker.** They are rendered as
   **asserted** — visibly distinct from a cryptographically verified origin (e.g. an `≈ ASSERTED` / "machine
   asserts" treatment), so a human cannot mistake "the machine says this is the refactor-auth stream" for "this
   stream is cryptographically proven."
3. **Fail-closed composition.** A `✓ VERIFIED` machine with an asserted stream renders as _verified machine,
   asserted stream_ — the verified marker does **not** bleed onto the stream. If the machine itself is
   `⚠ UNVERIFIED`, the entire label (including the stream) is unverified; an asserted stream on an unverified
   machine carries no independent trust and MUST NOT be elevated.
4. **Never silently upgrade.** Absence of a session-ID, an unrecognized harness, or any parse failure degrades to
   the asserted/unverified presentation — never to a more-trusted state.

The one-line mental model: **the inbox can cryptographically trust _which machine_; it can only repeat what the
machine _asserts_ about _which stream_.**

### Hard constraint — crypto lives in the client, never in the hook

All signing and verification for work-stream attestation happens in the **allw client downstream of the hook**
(the WASM-under-`node` SDK/integrator, or a native client), **never in the hook itself.** The hook stays a **dumb
emitter**: it produces a session-ID (and the raw action), and forwards them; it holds no key and performs no
crypto. This is the same WASM-local + thin-surface constraint that governs the rest of the system
(`docs/architecture.md` §"Local execution: WASM, not native binaries"): the machine Secure-Enclave key is used by
the client, which is the audited core, so the keyless hook adds nothing to allowlist and cannot hold or leak a
key. It is _because_ the hook is keyless that Part 2's session-ID is asserted-not-verified — the two facts are the
same fact.

### Reconciliation with #16 / #71 (actor-key attestation)

Work-stream attestation **composes with, and does not duplicate or contradict,** the actor-key model:

- **Machine key = actor key.** The "machine Secure-Enclave keypair" is the #16 actor key, anchored as an
  `actors` entry in root-signed account state (#16 resolved; #104 wired relay distribution). Enrollment,
  rotation, revocation, and the highest-sequence/fail-closed semantics are unchanged.
- **Per-request binding is unchanged.** The machine attestation is the existing
  `allw-actor-attest+jws`, bound to `(account_id, actor_id, actor_kind, request_id, request_hash)`, with the same
  no-swap / no-lift protections.
- **The label is additive.** The work-stream label (machine + harness + stream) is a refinement of the
  envelope-level `session_label` structure field plus the machine-asserted components inside the
  `ApprovalContext`. It introduces **no new root**, no new key class, and no new trust anchor — only a structured
  label and an explicit per-component trust tiering on top of the verified machine identity.
- **The verified-origin render extends, it doesn't override.** `verified_origin_string` /
  `verify_actor_attestation_with_account_states` continue to govern the **machine** marker; the stream/harness
  markers are new, weaker presentations that ride alongside and are never allowed to reach `✓ VERIFIED`.

> **Open contract/type follow-ups (NOT implemented here — noted for arbitration/scheduling).** Realizing this
> spec in code would imply: (a) a structured work-stream-label type (machine/harness/stream) layered over the
> existing `session_label` string; and (b) a renderer change distinguishing `✓ VERIFIED` (machine) from an
> `≈ ASSERTED` stream treatment. Both are forward-compatible (the machine attestation and account-state schemas
> are untouched) and are deferred to implementation issues under #133 — this is a docs-only spec.

### Open question (carried)

**Session-ID harness coverage.** Which agent harnesses (Claude Code via #13, Codex via #97, …) can emit a
_deterministic_ session-ID, and what the fallback is when a harness cannot. When no deterministic session-ID is
available, the stream component degrades to the asserted/unknown presentation (fail-closed — never fabricated,
never elevated); the machine identity is unaffected and still verifies. Tracked in the roadmap epic (#136) and
this issue (#133). See also `docs/threat-model.md` §"Work-stream origin: machine verified, stream asserted".

## Account State

To support offline verifiers, revocation, and rotation without trusting the relay, account trust state is modeled
as a signed account-state document. The relay may store and serve the latest copy, but cannot author it.

```jsonc
{
  "v": 1,
  "account_id": "acct_123",
  "sequence": 42,
  "current_root": "<base64url Ed25519 public key>",
  "previous_roots": [
    {
      "root": "<base64url Ed25519 public key>",
      "valid_until": 1761000000000,
    },
  ],
  "devices": [
    {
      "device_id": "dev_abc",
      "encryption_pubkey": "<base64url X25519 public key>",
      "signing_pubkey": "<base64url Ed25519 public key>",
      "status": "active",
      "cert_expires_at": 1791536000000,
    },
  ],
  "actors": [
    {
      "actor_id": "machine:macbook-pro",
      "kind": "claude-code",
      "pubkey": "<base64url Ed25519 public key>",
      "status": "active",
    },
  ],
  "revocations": [
    {
      "kind": "device",
      "id": "dev_lost",
      "revoked_at": 1760500000000,
      "reason": "lost",
    },
  ],
}
```

The account-state document is signed by the current account root. A root-rotation account state is additionally
cross-signed by the previous root so verifiers that still trust the old root can learn the new root during the
grace period.

Authoring and distribution flow:

1. A root-authorized account-state author builds the next document with a monotonic `sequence`.
2. The account root signs it as a compact JWS (`typ = "allw-account-state+jws"`).
3. An enrolled device publishes the signed document set to `POST /{account_id}/account-states` with its
   `device_auth_token` and the highest sequence in the set as `max_sequence`. The relay treats the
   compact JWS docs as opaque, but stores that asserted max sequence as monotonic metadata and rejects
   lower-sequence republishes with `409`.
4. Approver devices fetch `GET /{account_id}/account-states` with their `device_auth_token` before rendering a
   request origin. The relay returns opaque compact JWS strings plus the stored `max_sequence` metadata and does
   not inspect or author the docs.
5. The device verifies the account-root signature and highest valid sequence locally, persists the highest
   root-verified sequence it has accepted, and downgrades the origin to `⚠ UNVERIFIED` if the relay's
   `max_sequence` is not backed by a root-verified document at least that new or if fetched state is below the
   persisted floor. Missing, tampered, relay-substituted, or relay-rolled-back state renders `⚠ UNVERIFIED`;
   relay-side monotonic publish metadata prevents enrolled devices from rolling the cache back to a lower
   asserted sequence, while the device-side floor covers a compromised relay that lies about metadata.

Validation:

- `sequence` must be monotonic per `account_id`; a lower sequence is stale.
- `current_root` must match the configured trust anchor or be learned through a valid root-rotation chain.
- Revoked devices and actors are not active even if older relay lists still contain them.
- The relay cannot make a revoked key active by omitting the revocation from an older state document; approver
  devices keep the highest valid sequence they have seen and reject lower-sequence rollbacks.

SDK callers that use the revocation-aware `*_with_account_states` verification APIs must supply all known
account-state JWS documents, or must first enforce a durably stored highest sequence for the account. The SDK and
WASM core reject stale lower-sequence rollback within one supplied set, but monotonic persistence across calls is
integrator-owned when using the SDK directly. The `allw-approver watch` CLI persists that floor in its keyfile.
The plain `requestApproval` / `Verdict.verify` SDK path enforces account-state revocation only when
`ClientConfig.accountStates` or `Verdict.verify(..., { accountStates })` is supplied.

## Key Rotation

### Device-Key Rotation

Device-key rotation replaces a device signing key, encryption key, or both while preserving `device_id` when the
same physical device remains trusted.

Rules:

- A rotated encryption key updates the relay device registry; new requests must encrypt only to the new key.
- A rotated signing key requires a fresh `device_cert` signed by the account root.
- During a grace period, verifiers may accept both old and new device signing certs for the same `device_id`.
- After the grace period, the old cert is invalid even if it has not reached its embedded `expires_at`.
- A device whose signing key is suspected compromised must be revoked, not gracefully rotated.

Validation example:

- A verdict signed with the old device key verifies during `valid_until`.
- The same verdict fails after `valid_until`.
- A newly submitted request after encryption-key rotation contains only the new X25519 recipient.

### Account-Root Rotation

Account-root rotation changes the account trust anchor. It is the highest-risk operation because every verifier
ultimately trusts the root.

Rules:

- The old root signs a root-transition statement naming the new root, `account_id`, `issued_at`, and
  `valid_until`.
- The new root signs the new account-state document.
- Verifiers that know the old root may learn the new root only if the old-root transition signature is valid and
  the current time is before `valid_until`.
- After `valid_until`, certs signed only by the old root are rejected.
- If the old root is believed compromised, rotation is not enough; the account must publish a revocation state and
  relying parties must manually confirm the new trust anchor out of band.

Minimal transition payload:

```jsonc
{
  "v": 1,
  "account_id": "acct_123",
  "old_root": "<base64url Ed25519 public key>",
  "new_root": "<base64url Ed25519 public key>",
  "issued_at": 1760000000000,
  "valid_until": 1760604800000,
  "reason": "scheduled_rotation",
}
```

## Revocation

Revocation is fail-closed. A revoked device or actor may not regain trust by replaying old relay state, old
certificates, or old account-state documents.

### Device Revocation

When a device is revoked:

1. The relay deletes or marks inactive the device registry row.
2. Any live device WebSocket for that device is closed.
3. Future `GET /devices` responses omit the revoked device so new requests are not encrypted to it.
4. Future verdict submissions from that device are rejected.
5. Account state records a revocation entry with `revoked_at`.
6. Offline verifiers reject verdicts whose device id appears in the highest-sequence revocation state they have
   seen, even if the verdict's `device_cert` cryptographically chains to an old root.

Pending requests:

- If a revoked device already holds a ciphertext, it may still be able to decrypt that old context.
- It must not be able to resolve the request after revocation because the relay rejects its verdict and the
  integrator checks account-state revocation before accepting a verdict.

### Actor Revocation

When an actor is revoked:

- New requests from that actor must not be shown as verified.
- Existing pending requests from that actor should be retracted or downgraded before approval.
- Any policy rule scoped to that actor remains subject to policy precedence, but the actor can no longer produce a
  valid requester attestation.

## Recovery

### Lost Non-Root Device

If at least one trusted device or recovery authority remains:

1. Revoke the lost device immediately.
2. Publish account state with the revocation.
3. Pair the replacement device — it receives a **new** `device_id`; the lost one stays revoked forever.
4. Issue a fresh `device_cert` (via §Cross-Device `device_cert` Issuance Ceremony when the replacement is not
   the root holder).
5. Reconfigure or refresh integrators that cache device/account state.

This preserves `account_id` and account-root trust.

### Lost Account Root

If the account root is lost but not suspected compromised:

- If a recovery authority or hardware escrow can sign a root-transition statement, rotate to a new root.
- If no recovery authority exists, the account cannot prove continuity. Create a new account/root and require
  relying parties to configure the new trust anchor.

### Compromised Account Root

If the account root is suspected compromised:

- Treat all device certs and actor certs under that root as suspect.
- Stop accepting new approvals until relying parties explicitly install a new trust anchor.
- Publish a final revocation/advisory state if possible, but do not rely on the compromised root alone to prove
  the new root.

## Relay API Implications

Current relay mechanics cover the registry subset and #89 adds relay-scoped endpoint tokens:

| Endpoint                           | Enrollment meaning                                                                      |
| ---------------------------------- | --------------------------------------------------------------------------------------- |
| `POST /pairing/start`              | Create a short-lived single-use device enrollment code.                                 |
| `POST /pairing/complete`           | Redeem the code with its pairing bearer token and store a device encryption public key. |
| `POST /enrollments/start`          | Open a single-use cert-issuance mailbox pair for the ceremony (#175).                   |
| `POST /enrollments/{id}/csr`       | Enrollee deposits its MAC-authenticated CSR (write-once).                               |
| `GET /enrollments/{id}/csr`        | Root holder collects the CSR to verify and certify.                                     |
| `POST /enrollments/{id}/cert`      | Root holder deposits the issued `device_cert` (write-once, opaque to the relay).        |
| `GET /enrollments/{id}/cert`       | Enrollee collects its `device_cert` and verifies it against the pinned root.            |
| `POST /enrollments/{id}/abort`     | Root holder terminates a ceremony fail-closed and visibly.                              |
| `GET /devices`                     | Return active device encryption public keys for JWE recipients.                         |
| `POST /devices/{device_id}/revoke` | Remove an active device and close its live socket.                                      |
| `POST /actors`                     | Enroll an actor public key.                                                             |
| `GET /actors`                      | List enrolled actor public keys.                                                        |
| `POST /account-states`             | Publish the root-signed account-state document set with monotonic `max_sequence`.       |
| `GET /account-states`              | Fetch relay-distributed account-state docs plus `max_sequence` metadata.                |

Endpoint authentication and authorization rules:

- `POST /pairing/start`, `POST /enrollments/start`, and `POST /requests` are deliberately unauthenticated token
  issuers: pairing start and enrollment start are account-owner ceremony boundaries that only mint a capability
  scoped to the object they create, while request submit returns a per-request read capability that can only
  tighten the caller's authority;
- completing pairing requires the code plus the `pairing_auth_token`;
- depositing a CSR and collecting a cert require the enrollee's `device_auth_token`, and the relay additionally
  requires the CSR's `device_id` to be the authenticated device — a device may only ever request a certificate
  for itself;
- collecting a CSR, depositing a cert, and aborting require the `enrollment_auth_token` returned by
  `POST /enrollments/start`, which is scoped to that one enrollment;
- actor enrollment requires an enrolled device token;
- device revocation requires the target device token;
- device presence requires the target device token, passed as a bearer header or `auth` query on WebSocket upgrade;
- request polling and wait sockets require the `request_auth_token` returned by `POST /requests`;
- legacy rows without a stored relay auth-token hash fail closed with `401`; devices must re-pair and pending
  requests must be re-submitted rather than becoming unauthenticated;
- publishing and fetching account state require an enrolled device token. Account state contains public keys and
  metadata, so confidentiality is not required, but authentication prevents open account enumeration and keeps the
  relay cache scoped to paired devices.

## Test Implications

Implementation PRs for this spec should add fixtures or tests for:

- `device_cert` verification under the trusted account root;
- rejection under the wrong root, wrong account id, wrong device id, expired cert, and revoked device id;
- device-key rotation grace-period acceptance and post-grace rejection;
- account-root rotation via old-root cross-signature and post-grace old-root rejection;
- actor attestation verification and revoked-actor downgrade;
- relay revocation closing live device sockets and preventing revoked-device verdict resolution;
- offline verifier keeping the highest valid account-state sequence and rejecting stale state rollback;
- cross-device ceremony (#175): CSR MAC verification, and a direct negative test for **every** rejection branch —
  wrong enrollment secret, tampered `signing_pubkey`, tampered `encryption_pubkey`, wrong `enrollment_id`,
  wrong `account_id`, `device_id` not matching the authenticated device, malformed/oversized bodies, expired
  enrollment, second CSR (`409`), second cert (`409`), post-abort operations, and a cert whose `device_pubkey`,
  `device_id`, `account_id`, `typ`, `kid`, signing root, or `expires_at` does not satisfy the enrollee's checks;
- ceremony confirmation-code derivation agreeing byte-for-byte across the Rust core and the WASM/TS surface, and
  never appearing on the wire.

## Deferred Decisions

- Exact recovery-authority custody model: second device quorum, printed recovery key, platform account recovery, or
  hardware security key.
- Account-state transport format: compact JWS payload versus JSON document plus detached signature.
- Root-transition grace-period defaults.
- **Account-root-authorized device revocation at the relay.** `POST /devices/{id}/revoke` is self-revoke only, so
  the root holder cannot evict a lost device from the relay registry (account-state revocation, which is what
  verifiers enforce, still works). A root-signed revoke request would close that gap.
- **A push/WebSocket wakeup for the ceremony.** v1 polls both mailboxes; a socket would shorten the ceremony but
  changes no trust property.

Resolved (was deferred):

- Cross-device `device_cert` issuance for a device that is not the account-root holder: **#175 chose a relay
  store-and-forward courier with a MAC-authenticated CSR** over a two-QR ceremony, because the ceremony then
  needs only one out-of-band channel in the direction every consumer supports, while the relay gains no trust.
  See §Cross-Device `device_cert` Issuance Ceremony.

- Whether actor keys are anchored via a root-signed `actor_cert` or via signed account-state: **#16 chose signed
  account-state** (`actors` entries), reusing the device-trust/revocation machinery.
- Relay distribution of root-signed account state to devices: **#104 added authenticated
  `POST /account-states` and `GET /account-states`**. The relay serves opaque signed documents and stores only an
  asserted `max_sequence` guard for rollback resistance; verified-origin trust still comes only from local
  account-root signature verification.
