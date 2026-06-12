# allw — Enrollment, Rotation & Revocation

Companion to [contract.md](./contract.md). This mini-spec closes the account/device enrollment open decision and
pins how verifiers decide whether a device, actor, or account root is trusted.

## Scope

This document covers:

- account identity and the account-root trust anchor;
- approver device enrollment and `device_cert` validation;
- actor-key enrollment for requester attestation;
- device-key and account-root rotation;
- revocation propagation through the relay and offline verifiers;
- lost/replaced-device recovery.

It informs relay pairing/authn work (#10) and actor-key attestation work (#16).

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

The account root signs `device_cert` objects for device signing keys. Integrators verify verdicts with only the
configured account-root public key plus the `device_cert` carried in the verdict.

## Requirements

1. Private keys and seeds must never cross the relay boundary.
2. A device may receive encrypted requests only while it is enrolled in the relay device registry.
3. A device may resolve a request only while it is still enrolled.
4. A verifier must accept a verdict only if its `device_cert` chains to an acceptable account root and the verdict
   itself verifies under the certified device signing key.
5. A requester origin must eventually be accepted only if its actor attestation chains to an enrolled actor key.
6. Rotation must have an explicit grace period; after the grace period, old keys fail closed.
7. Revocation must propagate to online relay state immediately and to offline verifiers through signed
   account-state material.
8. Recovery must preserve the user's account identity when possible; when impossible, recovery creates a new
   trust anchor and requires relying parties to reconfigure trust.

## Device Enrollment

Device enrollment binds an approver device to an account in two places:

1. **Relay device registry:** `device_id -> device_encryption_pubkey`, used by integrators to encrypt
   `ApprovalContext` JWE recipients and by the relay to route presence sockets.
2. **Device certificate:** `device_cert`, an EdDSA compact JWS signed by the account root, binding
   `device_id -> device_signing_pubkey` for verdict verification.

### Pairing Flow

The v1 pairing flow is:

1. Account owner starts a short-lived pairing: `POST /{account_id}/pairing/start`.
2. Relay returns `{ code, expires_at }`; the code is shown out-of-band to the device.
3. Device completes pairing with `{ code, encryption_pubkey, signing_pubkey, label? }`, where
   `encryption_pubkey` is its X25519 encryption public key and `signing_pubkey` is the Ed25519 public key to
   certify for verdict and policy-rule signatures.
4. Relay consumes the code exactly once, creates `device_id`, and stores only public key material.
5. Account root signs a `device_cert` for the device signing key:

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
  "issued_at": 1760000000000,
}
```

The approver device verifies this signature against the enrolled actor key before presenting the origin as
verified. Until actor-key verification lands (#16), UIs must visibly treat actor identity as asserted, not
verified.

Enrollment requirements:

- Duplicate `actor_id` values are rejected unless the existing actor is explicitly rotated.
- Actor enrollment stores only public key material and metadata.
- Actor revocation prevents future requests from being shown as verified for that actor.
- The relay may help distribute actor public keys, but the device must treat actor trust as account-state data,
  not as a relay assertion.

Whether actor enrollment is represented as a root-signed `actor_cert` artifact, only as entries in signed
account-state, or both is deferred to #16. This document requires the actor public key to be account-root trusted
before an origin is displayed as verified, but does not pin the final wire artifact.

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

Validation:

- `sequence` must be monotonic per `account_id`; a lower sequence is stale.
- `current_root` must match the configured trust anchor or be learned through a valid root-rotation chain.
- Revoked devices and actors are not active even if older relay lists still contain them.
- The relay cannot make a revoked key active by omitting the revocation from an older state document; verifiers
  keep the highest valid sequence they have seen.

SDK callers that use the revocation-aware `*_with_account_states` verification APIs must supply all known
account-state JWS documents, or must first enforce a durably stored highest sequence for the account. The SDK and
WASM core reject stale lower-sequence rollback within one supplied set, but monotonic persistence across calls is
integrator-owned in v1.

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
3. Pair the replacement device.
4. Issue a fresh `device_cert`.
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

Current relay mechanics (#10) already cover the registry subset:

| Endpoint                           | Enrollment meaning                                              |
| ---------------------------------- | --------------------------------------------------------------- |
| `POST /pairing/start`              | Create a short-lived single-use device enrollment code.         |
| `POST /pairing/complete`           | Redeem the code and store a device encryption public key.       |
| `GET /devices`                     | Return active device encryption public keys for JWE recipients. |
| `POST /devices/{device_id}/revoke` | Remove an active device and close its live socket.              |
| `POST /actors`                     | Enroll an actor public key.                                     |
| `GET /actors`                      | List enrolled actor public keys.                                |

Endpoint authentication and authorization must be added before production use:

- starting pairing requires account-owner authorization;
- completing pairing requires the code and account-owner approval;
- actor enrollment requires an account-authorized device or owner flow;
- device/actor revocation requires account-owner authorization;
- serving account state requires integrity but not confidentiality, because it contains public keys and metadata.

## Test Implications

Implementation PRs for this spec should add fixtures or tests for:

- `device_cert` verification under the trusted account root;
- rejection under the wrong root, wrong account id, wrong device id, expired cert, and revoked device id;
- device-key rotation grace-period acceptance and post-grace rejection;
- account-root rotation via old-root cross-signature and post-grace old-root rejection;
- actor attestation verification and revoked-actor downgrade;
- relay revocation closing live device sockets and preventing revoked-device verdict resolution;
- offline verifier keeping the highest valid account-state sequence and rejecting stale state rollback.

## Deferred Decisions

- Exact recovery-authority custody model: second device quorum, printed recovery key, platform account recovery, or
  hardware security key.
- Account-state transport format: compact JWS payload versus JSON document plus detached signature.
- Root-transition grace-period defaults.
- Whether actor certs are root-signed like device certs or represented only in signed account state.
