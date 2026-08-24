# allw — Threat Model & Security Review Checklist

Companion to [contract.md](./contract.md), [policy-seam.md](./policy-seam.md), and
[architecture.md](./architecture.md). This document names what the approval primitive is defending,
what its invariants are expected to prove, and what reviewers should check before merging security-relevant
changes.

## Scope

This model covers the v1 approval primitive and the policy seam around it:

- `ActionRecord` capture by an integrator.
- `ApprovalContext` construction, encryption, rendering, and WYSIWYS hashing.
- Relay routing over opaque `ApprovalRequest` envelopes.
- Device-side approval signing and `device_cert` validation.
- The cross-device `device_cert` issuance ceremony (#175) — how a non-root-holding device gets certified without
  the relay being able to inject a device key.
- Integrator-side verdict verification, nonce tracking, policy composition, and audit records.

Out of scope:

- Preventing an agent from leaking non-secret working data it legitimately needs to read.
- Full semantic policy inference (the T3 capability engine in [policy-seam.md](./policy-seam.md)).
- Endpoint authentication details that are deferred to the enrollment mini-spec.
- Mobile OS compromise, kernel compromise, or a compromised hardware-backed keystore.

## Security Goals

1. A relay, network observer, or unrelated device must not learn the plaintext approval context.
2. A verdict must be accepted only when it was signed by an enrolled approver device for this exact request.
3. The human must be shown the exact action material that is later authorized or denied.
4. A requester origin must be attestable to the approver before approval.
5. The primitive must compose monotonically with local policy and upstream gates; it must not grant authority by
   itself.
6. Every ambiguous, expired, missing, unverifiable, or transport-failed path must block the gated action.
7. Auditors must be able to reconstruct the decision artifact and the policy state without trusting the relay.
8. The relay must never observe action **data** (arguments, values, env) — only action **structure** (program /
   server+tool / session-label / surface). "Know the function, not the arguments." This holds at every privacy
   tier.

## Assets

| Asset                       | Owner                                  | Why it matters                                                                                                                                             |
| --------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ApprovalContext` plaintext | Integrator and approver device         | Contains the action, actor, summary, risk, constraints, and chain shown to the human.                                                                      |
| Device signing key          | Approver device                        | Signs verdicts and policy rules; compromise lets an attacker approve as that device.                                                                       |
| Account root key            | Approver account                       | Trust anchor for enrolled devices; compromise lets an attacker mint trusted device certs.                                                                  |
| Actor key                   | Actor machine / agent identity         | Lets the approver distinguish the real requester from an impersonator.                                                                                     |
| `request_hash`              | Integrator and approver device         | Binds the verdict to the complete human-shown payload and `expires_at`.                                                                                    |
| Verdict JWS                 | Approver device, integrator, audit log | Non-repudiable human decision artifact.                                                                                                                    |
| Integrator nonce store      | Integrator                             | Rejects replayed approved verdict nonces across requests.                                                                                                  |
| Audit chain head            | Integrator / auditor                   | Tamper evidence for decision history and policy state.                                                                                                     |
| Relay routing state         | Relay Durable Object                   | Stores opaque pending envelopes, device presence, and signed verdicts.                                                                                     |
| Policy rules                | Approver device / policy store         | Standing user grants or denials; signed and precedence-ordered.                                                                                            |
| `enrollment_secret`         | Account-root holder + enrollee only    | Authenticates the CSR the account root is about to certify; whoever holds it during the ceremony can get a key certified as an approver device (#175, R8). |

## Trust Boundaries

```
actor/integrator process
  builds ApprovalContext, encrypts, verifies verdict, enforces policy
  applies privacy-preference: strips data fields from envelope before submit
  (default tier: relay sees structure only; paranoid/enterprise tier: relay sees routing metadata only)
  |
  | opaque ApprovalRequest envelope + ciphertext
  | envelope plaintext carries at most: structure (surface / program / server+tool / session-label), never data
  v
zero-knowledge relay
  routes by account/request/device ids, stores opaque envelopes and signed verdicts
  sees structure at most (surface / program / server+tool / session-label) at default tier; routing metadata only (paranoid/enterprise tier)
  |
  | ciphertext only
  v
approver device
  decrypts, verifies actor attestation, renders WYSIWYS, signs verdict
  full ActionRecord (structure + data) visible only here
```

The relay is intentionally outside the plaintext and signing trust boundary. It may route, delay, drop, replay,
or mutate relay-visible fields, but it must not be trusted to preserve confidentiality or authorize decisions.

**Structure vs. data boundary:** the relay (and anything off-device) may observe action **structure** — the
program name (commands) / server + tool name (MCP calls), session label, and surface kind — but never action
**data**: arguments, parameter values, environment variables, or any content the agent is operating on. For
MCP calls the (server, tool) pair is the function identity, parallel to a command's program name; both are
structure. Structure is what routing metadata legitimately needs; data belongs exclusively inside the JWE
ciphertext, visible only to the approver's enrolled devices. This boundary is enforced on-device (in the
WASM/native client) before anything reaches the relay.

**Privacy preference tiers (v1: default only):**

| Tier                                         | Relay sees                                                        | v1 status           |
| -------------------------------------------- | ----------------------------------------------------------------- | ------------------- |
| **default** (structure-visible)              | program / server+tool / session-label / surface kind — never data | **shipped**         |
| **paranoid / enterprise** (structure-hidden) | routing metadata only (account id, request id, device ids)        | reserved; not built |
| **ai-summary**                               | future tier — reserved; do not build                              | reserved; not built |

The preference is a RESERVED field on the wire contract (null = default in v1); see `docs/contract.md`.
Paranoid/enterprise tier — how an org enforces structure-hidden mode on its members — is an open question
tracked in the roadmap epic.

### Work-stream origin: machine verified, stream asserted

The origin shown in the inbox is a **work-stream label** with two trust weights (Decisions 4 + 5, #133; full
model in `docs/enrollment.md` §Work-Stream Attestation):

- **Which machine** is **cryptographically verified.** The machine's Secure-Enclave keypair _is_ the actor key
  of #16, anchored as an `actors` entry in root-signed account state. The per-request machine attestation
  (`allw-actor-attest+jws`, bound to `request_id` + `request_hash`) is verified on the approver device; a
  relay-supplied key never drives a verified machine identity. This sits inside the same trust boundary as the
  actor-key attestation — nothing new is trusted.
- **Which stream** is **asserted, not verified.** The harness/stream components are anchored to a deterministic
  session-ID from a **keyless** harness hook. The hook holds no key (it is a dumb emitter; crypto lives in the
  client downstream, never the hook — Security Goal 6 / fail-closed and `docs/architecture.md`). A signature by
  the verified machine over the session-ID proves only that the machine forwarded the string, not that the
  harness authenticated the session. The honest ceiling: the stream is only as trustworthy as the verified
  machine's own software stack.

**Presentation boundary (fail-closed).** The inbox MUST render the machine component with the existing
`✓ VERIFIED` / `⚠ UNVERIFIED` discipline and MUST render the harness/stream components as **asserted** — a
visibly weaker marker that is never `✓ VERIFIED`. A verified machine does not elevate an asserted stream; an
unverified machine makes the whole label unverified. This mirrors the actor-key `✓ VERIFIED` vs `⚠ UNVERIFIED`
rule (`crates/allw-core/src/attestation.rs`, `packages/approver/src/lib/render.ts`) and never renders an
asserted-only signal as cryptographically verified.

## Adversary / Asset Matrix

| Adversary                                             | Target assets                                                                                       | Expected defenses                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Residuals / owner                                                                                                                                                                                                                                                                                                                                                             |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Malicious or escaped agent                            | Local files, ambient credentials, gated tool execution                                              | Policy layer evaluates before approval; human gate verifies exact `ActionRecord`; vaultkeeper keeps secrets out of the agent read-set.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Non-secret working data the agent can read is a DLP problem, not solved by allw; owner: sandboxing, egress controls, data minimization.                                                                                                                                                                                                                                       |
| Compromised relay                                     | `ApprovalContext` plaintext, action data (args/values/env), verdict integrity, routing availability | E2EE JWE keeps context opaque; structure-not-data boundary (Security Goal 8) strips data from the relay-visible envelope before submission; verdict JWS verifies without relay trust; fail-closed expiry/no-response; integrator checks request id and hash.                                                                                                                                                                                                                                                                                                                                                                          | Relay can deny service, delay approvals, or drop wakeups; owner: retry/availability design and audit monitoring.                                                                                                                                                                                                                                                              |
| Network MITM                                          | Context confidentiality, action data, envelope integrity, verdict integrity                         | TLS plus application-layer JWE/JWS; structure-not-data boundary prevents data from appearing in the plaintext envelope; request hash includes `expires_at`; integrator verifies device/account root.                                                                                                                                                                                                                                                                                                                                                                                                                                  | Traffic metadata and action structure remain visible to network layers at the default tier; owner: paranoid/enterprise tier (reserved) if structure visibility becomes a requirement.                                                                                                                                                                                         |
| Lost or stolen approver device                        | Device signing key, pending approvals                                                               | Hardware-backed key storage and biometric-gated signing; root-signed account state makes offline verifiers reject future verdicts/rules from revoked devices.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Revocation publication latency and recovery UX are deferred to `docs/enrollment.md` (#19); owner: enrollment spec and app UX.                                                                                                                                                                                                                                                 |
| Malicious integrator                                  | Honest rendering, enforcement, audit completeness                                                   | Approver device recomputes request hash from decrypted context; verdict is not authorization; audit chain can expose what was requested.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | A relying party that ignores verification or lies about local execution can still misbehave; owner: integrator conformance tests, signed/auditable hooks, and deployment policy.                                                                                                                                                                                              |
| Device-injection attacker (relay or ceremony phisher) | Account trust set — the ability to get a key the attacker holds certified as an approver device     | The enrollment CSR is authenticated by a MAC keyed from an `enrollment_secret` carried **only** out of band (QR / pasted link), which the relay never receives, so a substituted `signing_pubkey` is rejected before the root signs (R8). A six-digit confirmation code derived independently on both sides, plus an explicit human confirmation, guards the secret-leak/race case. The issued cert is verified by the enrollee against the **pinned** account-root pubkey and its own signing key, so a relay-forged cert is discarded. Every mailbox is write-once with a 10-minute TTL, and every failure path aborts fail-closed. | An attacker who observes the enrollment bundle (shoulder-surf, screen share, a photo of the QR) within its TTL can impersonate the enrollee; and a user tricked into scanning an **attacker's** bundle enrolls into the attacker's account. Owner: ceremony UX — treat the bundle as secret, keep the TTL short, show the account label + root fingerprint before completing. |
| Requester impersonator                                | Actor identity shown to human                                                                       | Actor-key attestation is verified on device before the human approves; the actor key is resolved from root-signed account state (#16), so a relay-substituted key cannot forge a verified origin. Relay account-state publish stores monotonic `max_sequence` metadata, approvers require that metadata to be backed by a root-verified document at least that new, and both the approver keyfile and the web approver's browser storage persist a highest-sequence floor to reject compromised-relay rollback.                                                                                                                       | A fully malicious relay can still omit or delay state, causing ⚠ UNVERIFIED; availability/audit monitoring is follow-up work.                                                                                                                                                                                                                                                 |
| Replay attacker                                       | Approved verdict, old ciphertext, old request ids                                                   | Verdict binds `request_id` + `request_hash`; nonce store rejects reused approved verdict nonces; expiry windows are enforced.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Persistent nonce storage/retention policy remains integrator-owned; owner: SDK/integrator configuration.                                                                                                                                                                                                                                                                      |
| Policy-rule attacker                                  | Standing `allow` rule or suppressed prompts                                                         | Rules are signed by device keys; precedence is `deny > ask > allow`; no match means ask.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Rule sync/storage conflicts are deferred; owner: policy storage and management UI.                                                                                                                                                                                                                                                                                            |
| Audit tamperer                                        | Decision history and policy evidence                                                                | `AuditRecord` hash chain covers prior head and records the verdict JWS.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Anchoring cadence and retention are deployment choices; owner: integrator/auditor.                                                                                                                                                                                                                                                                                            |

## Invariant-To-Threat Mapping

| Contract invariant             | Defends against                                                                | Required checks / evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E2EE                           | Compromised relay, network MITM, plaintext leakage through push/relay state    | Relay stores only routing metadata, opaque `context_ciphertext`, public keys, and signed verdicts; tests reject unexpected envelope keys and secret material.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Structure-not-data             | Compromised relay or network MITM inferring argument values / env / content    | On-device enforcement (WASM/native client) strips data fields from the relay-visible `ApprovalRequest` envelope before transmission; envelope plaintext carries only structure (surface / program / server+tool / session-label), never data; relay-field acceptance tests assert no argument/value/env keys appear in the envelope.                                                                                                                                                                                                                                                                                                                                |
| Verifiable verdict             | Compromised relay, forged verdicts, malicious network, malicious device ids    | Verify verdict JWS against enrolled device cert and account root; reject revoked device ids from the highest-sequence root-signed account state; reject claim/outer mismatches; do not trust relay status alone. Upstream of verification, the cross-device issuance ceremony keeps the relay from getting a key of its choosing certified (R8).                                                                                                                                                                                                                                                                                                                    |
| WYSIWYS                        | Context/action TOCTOU, summary-only deception, swapped ciphertext or deadline  | Device recomputes `request_hash` over the canonical request-hash input (`ActionRecord`, summary, actor id/kind, risk, reversible, constraints, chain, and shown `expires_at`; `actor.attestation` is verified separately); renderer must show the bound syntactic substrate needed for the decision. The structure-not-data boundary does not affect WYSIWYS — full `ActionRecord` data remains inside the JWE; `request_hash` is computed post-decrypt on-device.                                                                                                                                                                                                  |
| Requester attestation          | Requester impersonation, misleading origin text                                | Device verifies the actor-key attestation before approval, resolving the actor key from root-signed account state (#16) and binding it to `request_id` + `request_hash`; a relay-supplied key never drives a verified origin, and any non-root-anchored / revoked / unbound origin is visibly downgraded to ⚠ UNVERIFIED. **Work-stream refinement (#133):** the verified key attests _which machine_ (the machine Secure-Enclave key = the actor key); the work-stream label's _stream/harness_ components are asserted via a keyless harness hook and are rendered **asserted**, never ✓ VERIFIED (see §"Work-stream origin: machine verified, stream asserted"). |
| Chain-composable and monotonic | Verdict reuse as authorization, policy bypass, upstream gate weakening         | Consumers compute `effective_allow = approved && verified && local_policy && other_gates`; the primitive never emits or stores reusable scope.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Fail-closed                    | Hung relay, no devices, expired request, malformed input, unverifiable verdict | Timeout/no-response/unverified/non-approved paths return `deny`/`expired`; hook exits 0 with explicit deny before external timeouts.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

## Security Requirements

### R1. Context confidentiality

`ApprovalContext` plaintext must cross the relay boundary only as JWE ciphertext encrypted to enrolled approver
device keys. Push payloads may carry a wakeup and request id, never action context. See also R7
(structure-not-data) which further constrains what the plaintext `ApprovalRequest` envelope may reveal.

Validation:

- Relay tests assert accepted envelopes contain only contract routing fields plus `context_ciphertext`.
- Pairing and relay-client tests assert no seeds or private key material are sent to the relay.
- Manual review checks any new relay field for plaintext context leakage.
- The SDK filters the relay-listed device set against the caller's verified account-state revocations
  (`revoked_device_ids`, core/WASM) before building the JWE recipient set, so a revoked device is never
  added as a recipient regardless of whether the relay's own registry has converged (`docs/enrollment.md`
  §Device Revocation, issue #204 fix 1). Tests assert a revoked device receives no recipient entry, that a
  stale lower-sequence account state cannot resurrect a revocation, and that an all-revoked account fails
  closed rather than submitting to nobody.

### R2. Verdict authenticity and binding

An integrator must accept an approval only when the verdict signature chains to the configured account root, the
verdict `request_id` equals the envelope id, the verdict `request_hash` equals the locally computed WYSIWYS hash,
the decision is `approved`, the decision is fresh, and the verdict nonce is unseen.

Validation:

- Core/WASM tests cover tampered JWS claims, mismatched request hashes, expired windows, and replayed nonces.
- SDK tests cover `verify()` returning true only for fully verified approvals.
- Integrator tests cover fail-closed behavior when verification throws or resolves non-approved.

### R3. WYSIWYS completeness

The approver UI must render all material fields that are included in the request hash and relevant to the human
decision. A summary may help readability, but it is not a substitute for rendering the action substrate.

Validation:

- Approver render tests cover command `argv`, flags, cwd, env refs, MCP server/tool/params, divergent raw/parsed
  forms, risk, actor, expiry, and challenge state.
- Any new `ActionRecord` syntactic field must either render directly or be explicitly marked non-decision-making.

### R4. Fail-closed execution

Every integration boundary must deny on parse errors, missing config, network timeout, network refusal, malformed
relay responses, expired requests, non-approved verdicts, and unexpected internal errors.

Validation:

- Hook subprocess UATs spawn the real `allw-hook` process, feed gated stdin, and assert bounded `deny`.
- SDK fetch-timeout tests prove hung `fetchDevices`, `submit`, and polling resolve non-approved.
- Relay tests prove expired requests cannot become approved.

### R5. Monotonic policy composition

Policy may reduce prompts, but it must not turn a failed primitive verification into an allow. A signed
`PolicyRule` can auto-allow only before the primitive is invoked; a one-shot verdict never carries reusable scope.

Validation:

- Policy tests must pin precedence: `deny > ask > allow`; no match means ask.
- A `from_approval` rule test must prove future matching actions use a signed rule, not a reused verdict.
- Policy-rule verification tests must reject cross-account certs, signing keys that do not chain to the account root,
  missing certs, and `kid` values that do not name the certified device.

### R6. Auditability

Security-relevant decisions must leave enough evidence to verify the original request, the verdict, the policy
decision, and the previous audit chain head without trusting the relay.

Validation:

- Audit hash tests cover `prev_hash`, verdict JWS inclusion, policy block inclusion, and deterministic encoding.
- Manual review checks new decision paths append or preserve the audit evidence needed to reconstruct the gate.

### R7. Structure-not-data (relay data boundary)

The plaintext `ApprovalRequest` envelope submitted to the relay must carry **at most** action structure — the
surface kind, program name (commands) / server + tool name (MCP calls), and session label — and **never**
action data: arguments, parameter values, environment variable names or values, or any content the agent is
operating on. Full `ActionRecord` data travels exclusively inside the JWE ciphertext (`context_ciphertext`),
visible only to enrolled approver devices.

This is enforced on-device (in the WASM/native client) before any bytes reach the relay. The preferred privacy
tier is carried as a RESERVED wire field (null = default / structure-visible in v1). The three tiers are defined
in the Trust Boundaries section above; only the default tier is implemented in v1.

Validation:

- Relay envelope acceptance tests assert that no argument, parameter value, environment variable, or action-data
  key appears in the plaintext `ApprovalRequest` fields accepted by the relay.
- SDK/hook integration tests assert that the constructed envelope contains only structure fields in plaintext.
- Manual review checks every new `ActionRecord` syntactic field addition: data fields must land only inside the
  JWE; structure fields (surface, program name / server+tool name, session-label) may appear in the plaintext
  envelope.
- Any code path that serializes an `ActionRecord` toward the relay is audited for argument/value/env leakage.

### R8. Enrollment-ceremony integrity (cross-device `device_cert` issuance)

The account root must sign a `device_cert` **only** over a signing key that reached it through a channel the
relay cannot influence. Full ceremony: `docs/enrollment.md` §Cross-Device `device_cert` Issuance Ceremony.

Rules:

- The `enrollment_secret` that keys the CSR MAC travels **only** out of band (QR or pasted link) and must never
  appear in any request to the relay, any log, or any persisted record after the ceremony ends.
- The root holder MUST verify `csr_mac` before reading any CSR field as trustworthy, and MUST abort — never
  degrade to a weaker check — when it fails. Everything the root vouches for (`signing_pubkey`,
  `encryption_pubkey`, `device_id`) must come from the MAC-authenticated CSR, never from `GET /devices`.
- The confirmation code is derived independently on both sides and is **never transmitted**; a relay-supplied
  code would let a substituting relay replay the genuine value. It is defense-in-depth, not the primary control
  — its ~20-bit space is grindable by an adversary who already holds the secret and has seen the CSR.
- The enrollee MUST verify the returned cert against the **pinned** account-root pubkey (signature, `typ`,
  `kid`, `account_id`, `device_id`, `device_pubkey` == its own signing key, `expires_at`) **before** persisting
  it, and MUST discard-and-self-revoke on any failure.
- A device signing key is generated on-device and never exported; a provisioning bundle carrying a device
  signing seed is prohibited in all builds.
- The relay never validates the MAC or the cert; its shape/ownership checks are anti-abuse only, and a device
  may deposit a CSR only for the `device_id` its own bearer token authenticates.
- Every mailbox is write-once and TTL-bounded; abort is terminal and visible to the enrollee so a killed
  ceremony never degrades into an ambiguous timeout.

Validation:

- Core/WASM tests cover MAC verification, cross-surface byte-identical confirmation-code derivation, and every
  rejection branch (tampered pubkeys, wrong secret, wrong enrollment/account id, expired window).
- Relay tests cover write-once mailboxes (`409`), TTL expiry (`410`), cross-device CSR deposit (`403`), post-abort
  operations, and assert that no request body carrying an `enrollment_secret` is ever accepted or stored.
- Approver-surface UATs prove the inbox is unreachable without a root-verified cert, and that a forged or
  mismatched cert is discarded rather than persisted.

## Residual Risks

| Residual                                                                    | Why it remains                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Owner / next step                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent-readable non-secret sensitive data can be exfiltrated                 | If the agent must read data to work, approval cannot prevent it from copying that data elsewhere.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Sandbox/egress controls and data minimization; keep secrets in vaultkeeper.                                                                                                                                                                                                                                                                                                                                               |
| Relay denial of service                                                     | Zero-knowledge routing does not make the relay available or honest about delivery timing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Availability engineering, retries, alternate transports, and audit visibility.                                                                                                                                                                                                                                                                                                                                            |
| Endpoint authentication is incomplete                                       | Current routing relies on high-entropy ids and enrollment work still in progress.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Enrollment spec (#19) and endpoint authn implementation.                                                                                                                                                                                                                                                                                                                                                                  |
| Actor identity unverified without distributed account state                 | Actor-key attestation now anchors on root-signed account state (#16); until the relay distributes that state to devices, a device without it cannot root-anchor an actor key.                                                                                                                                                                                                                                                                                                                                                                                                                             | Wire relay distribution of root-signed account state (#104); meanwhile origins render ⚠ UNVERIFIED (fail-closed).                                                                                                                                                                                                                                                                                                         |
| Device loss and recovery UX is underspecified                               | Root-signed account state gives offline verifier semantics, but publication latency and recovery flows still need product design.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Enrollment/revocation UX (#19).                                                                                                                                                                                                                                                                                                                                                                                           |
| No root-authorized relay-side eviction for a revoked device                 | The SDK now independently drops a revoked device from the JWE recipient set before encrypting a new request (`docs/enrollment.md` §Device Revocation, issue #204 fix 1), which closes the plaintext-confidentiality gap against an untrusted relay. The relay registry itself, however, still only supports **self-revoke** (`POST /devices/{id}/revoke`) — the account-root holder cannot yet evict a _different_ (e.g. lost/stolen) device's registry row, so a stale/misbehaving relay can keep pushing wakeups to it and keep listing it to any caller that skips the sender-side check.              | Root-authorized relay eviction, verified against the pinned account-root pubkey rather than a bearer token (issue #204 fix 2, tracked separately).                                                                                                                                                                                                                                                                        |
| Enrollment bundle exposure during the ceremony                              | The out-of-band bundle (QR / pasted link) carries the `enrollment_secret` that authenticates the CSR. Anyone who photographs the QR, sees it over a screen share, or reads the pasted link within its 10-minute TTL can author a CSR the root holder will accept as genuine. The six-digit confirmation code and the explicit human confirmation are the only remaining guards, and their ~20-bit space is grindable by an adversary who has also seen the genuine CSR.                                                                                                                                   | Accepted for v1: short TTL, single-use write-once mailboxes, explicit abort. Ceremony UX must treat the bundle as secret material (no screenshots into chat, no long-lived display) and show the account label + root fingerprint before completion. `docs/enrollment.md` §Cross-Device `device_cert` Issuance Ceremony, R8.                                                                                              |
| A user can be induced to enroll into an attacker's account                  | The enrollee pins whatever `account_root_pubkey` arrives in the bundle it scans — trust-on-first-use over the out-of-band channel. Scanning an attacker's QR enrolls the device into the attacker's account (it does not compromise the user's own account, but the user may then approve actions they believe are theirs).                                                                                                                                                                                                                                                                               | Ceremony UX shows the account label and root-key fingerprint before completing, and enrollment is an explicit, deliberate act. A stronger account-identity binding (verified account naming) is post-v1. Owner: approver-app / web-approver onboarding.                                                                                                                                                                   |
| Persistent nonce retention is integrator-owned                              | In-memory nonce stores only protect one process lifetime.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | SDK/integrator persistent `NonceStore` configuration and retention tests.                                                                                                                                                                                                                                                                                                                                                 |
| Semantic capability mistakes are deferred                                   | v1 is syntactic; it does not infer generalized capabilities or data meaning.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | T3 policy engine; until then, use conservative syntactic rules and human escalation.                                                                                                                                                                                                                                                                                                                                      |
| Action structure visible to relay at default tier                           | The default (structure-visible) tier lets the relay observe the program name (commands) / server + tool name (MCP calls), session label, and surface kind. This is by design — routing benefits from it — but it means the relay knows _what function_ the agent is invoking, not _what arguments_ were given.                                                                                                                                                                                                                                                                                            | Paranoid/enterprise (structure-hidden) tier is reserved and not yet built. Org enforcement of structure-hidden mode is an open question tracked in the roadmap epic.                                                                                                                                                                                                                                                      |
| Work-stream **stream** identity is asserted, not verified                   | The work-stream label's machine component is cryptographically verified (machine Secure-Enclave key, root-anchored — #16), but the **harness/stream** components ride on a deterministic session-ID emitted by a **keyless** tool-harness hook (the hook is a dumb emitter; crypto lives in the client, never the hook — `docs/architecture.md`). A machine-key signature over an asserted session-ID proves only that the (verified) machine _forwarded_ that string, not that the harness authenticated the session. A compromised harness on a verified machine can assert any stream name/session-ID. | By design — there is no harness key, so no harness-level guarantee exists. The inbox fails closed by presentation: the stream/harness components are shown **asserted** (never `✓ VERIFIED`); only the machine is verified. Spec: `docs/enrollment.md` §Work-Stream Attestation (#133). Harness session-ID coverage/fallback is an open question (#133, #136).                                                            |
| Recognized-tool tally egress is the only sanctioned data leaving the device | Decision 8 (#135) sanctions exactly one egress: **aggregate-only, recognized-only** tallies — a histogram of recognized tool function-identities (structure) + counts, never action data, never unrecognized-tool existence. This is strictly less than the per-request function identity the relay already sees at the default tier, collapsed to frequency. The risk is that a future implementation widens it (per-event records, an `"other"` bucket leaking unrecognized cardinality, or default-on egress).                                                                                         | By design the three gates (aggregate-only / recognized-only / explicit fail-closed consent) are enforced **on-device before transport**, and the v1 `is_recognized` stub returns `false` so tallies are empty and egress is inert until the deferred T3 registry lands. Transport + consent is an open product/CEO decision (#136) carrying a fail-closed default of "nothing leaves." Spec: `docs/decision-flywheel.md`. |

## Security Review Checklist

Use this checklist for PRs that touch crypto, key material, relay routing, approval rendering, policy rules,
attestation, audit records, hook/SDK fail-closed behavior, or enrollment.

### Crypto and Encoding

- [ ] New signed or hashed bytes have a domain tag and version.
- [ ] JSON that participates in hashes uses the documented canonicalization.
- [ ] Binary fields are base64url-unpadded unless the contract explicitly says compact JWS/JWE.
- [ ] JWS payload claims are cross-checked against any decoded outer convenience fields.
- [ ] Randomness is fresh per verdict/request where required; nonces are never reused.
- [ ] Low-order/invalid key material and malformed JOSE inputs fail closed.

### Key Handling and Enrollment

- [ ] Private keys, seeds, and plaintext secrets never cross the relay boundary.
- [ ] Device keys chain to the configured account root before their verdicts/rules are trusted.
- [ ] Revoked or unenrolled devices cannot resolve pending requests.
- [ ] Lost-device, rotation, and recovery behavior is either implemented or explicitly deferred to the enrollment spec.
- [ ] Test fixtures do not normalize unsafe key handling into production code.
- [ ] Cross-device cert issuance (R8): the `enrollment_secret` never reaches the relay, a log, or persistent
      storage; the root holder verifies `csr_mac` before trusting any CSR field and aborts on failure; the
      enrollee verifies the returned cert against its **pinned** root and its **own** signing pubkey before
      persisting; mailboxes are write-once and TTL-bounded; abort is terminal and visible.
- [ ] No code path ships a device **signing seed** off-device (a pre-issued `device_cert` is dev-only; a
      pre-issued seed is never acceptable).

### Relay and Transport

- [ ] Relay-visible request fields are limited to the envelope contract; no plaintext action context is added.
- [ ] The plaintext envelope carries **at most** action structure (surface / program name / session label); no
      argument, parameter value, environment variable, or other action data appears in plaintext relay-visible fields
      (R7 / structure-not-data boundary).
- [ ] Any new `ActionRecord` syntactic field is classified: structure fields may appear in the plaintext envelope;
      data fields must land exclusively inside the JWE `context_ciphertext`.
- [ ] Push/wakeup payloads carry request ids only, never human-shown context.
- [ ] Pending requests expire fail-closed; expired requests cannot later resolve approved.
- [ ] Network failures, hung reads, refused connections, and malformed relay responses deny or expire, never allow.
- [ ] Any new endpoint states who may call it and what authentication/authorization is required.

### WYSIWYS and Approver UX

- [ ] Every field covered by `request_hash` that matters to the decision is rendered or intentionally explained.
- [ ] Parsed and raw command/MCP forms cannot diverge silently.
- [ ] Expiry, actor identity, risk, reversible status, and challenge requirement are visible before signing.
- [ ] Unverified actor identity is not presented as verified.
- [ ] Work-stream label (#133): the **machine** component is `✓ VERIFIED` only on a verified machine attestation;
      the **harness/stream** components are rendered **asserted**, never `✓ VERIFIED`, and a verified machine does
      not elevate an asserted stream (fail-closed presentation — `docs/enrollment.md` §Work-Stream Attestation).
- [ ] Approve/deny/skip behavior preserves fail-closed semantics.

### Integrator, Policy, and Audit

- [ ] The integrator computes `allow` only after verified approval plus local policy plus other gates.
- [ ] A non-approved, expired, unverifiable, replayed, or transport-synthesized verdict cannot become allow.
- [ ] Policy precedence remains `deny > ask > allow`; no match remains ask.
- [ ] `from_approval` emits a signed `PolicyRule`; it does not mutate or reuse the one-shot verdict.
- [ ] Audit records contain the verdict artifact, request hash, actor, action, policy result, and previous hash.
- [ ] New config has fail-closed validation and cannot weaken timeout-ordering or verification guarantees.

## Review Evidence To Include In PRs

Security-relevant PR descriptions should name:

- which invariant(s) the change touches;
- which adversary or residual risk it changes;
- the exact tests or fixtures proving the behavior;
- any remaining deferred behavior and its owning issue/doc.
