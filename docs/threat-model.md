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

## Assets

| Asset                       | Owner                                  | Why it matters                                                                            |
| --------------------------- | -------------------------------------- | ----------------------------------------------------------------------------------------- |
| `ApprovalContext` plaintext | Integrator and approver device         | Contains the action, actor, summary, risk, constraints, and chain shown to the human.     |
| Device signing key          | Approver device                        | Signs verdicts and policy rules; compromise lets an attacker approve as that device.      |
| Account root key            | Approver account                       | Trust anchor for enrolled devices; compromise lets an attacker mint trusted device certs. |
| Actor key                   | Actor machine / agent identity         | Lets the approver distinguish the real requester from an impersonator.                    |
| `request_hash`              | Integrator and approver device         | Binds the verdict to the complete human-shown payload and `expires_at`.                   |
| Verdict JWS                 | Approver device, integrator, audit log | Non-repudiable human decision artifact.                                                   |
| Integrator nonce store      | Integrator                             | Rejects replayed approved verdict nonces across requests.                                 |
| Audit chain head            | Integrator / auditor                   | Tamper evidence for decision history and policy state.                                    |
| Relay routing state         | Relay Durable Object                   | Stores opaque pending envelopes, device presence, and signed verdicts.                    |
| Policy rules                | Approver device / policy store         | Standing user grants or denials; signed and precedence-ordered.                           |

## Trust Boundaries

```
actor/integrator process
  builds ApprovalContext, encrypts, verifies verdict, enforces policy
  |
  | opaque ApprovalRequest envelope + ciphertext
  v
zero-knowledge relay
  routes by account/request/device ids, stores opaque envelopes and signed verdicts
  |
  | ciphertext only
  v
approver device
  decrypts, verifies actor attestation, renders WYSIWYS, signs verdict
```

The relay is intentionally outside the plaintext and signing trust boundary. It may route, delay, drop, replay,
or mutate relay-visible fields, but it must not be trusted to preserve confidentiality or authorize decisions.

## Adversary / Asset Matrix

| Adversary                      | Target assets                                                        | Expected defenses                                                                                                                                             | Residuals / owner                                                                                                                                                                |
| ------------------------------ | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Malicious or escaped agent     | Local files, ambient credentials, gated tool execution               | Policy layer evaluates before approval; human gate verifies exact `ActionRecord`; vaultkeeper keeps secrets out of the agent read-set.                        | Non-secret working data the agent can read is a DLP problem, not solved by allw; owner: sandboxing, egress controls, data minimization.                                          |
| Compromised relay              | `ApprovalContext` plaintext, verdict integrity, routing availability | E2EE JWE keeps context opaque; verdict JWS verifies without relay trust; fail-closed expiry/no-response; integrator checks request id and hash.               | Relay can deny service, delay approvals, or drop wakeups; owner: retry/availability design and audit monitoring.                                                                 |
| Network MITM                   | Context confidentiality, envelope integrity, verdict integrity       | TLS plus application-layer JWE/JWS; request hash includes `expires_at`; integrator verifies device/account root.                                              | Traffic metadata remains visible to network layers; owner: transport hardening if metadata sensitivity becomes a requirement.                                                    |
| Lost or stolen approver device | Device signing key, pending approvals                                | Hardware-backed key storage and biometric-gated signing; root-signed account state makes offline verifiers reject future verdicts/rules from revoked devices. | Revocation publication latency and recovery UX are deferred to `docs/enrollment.md` (#19); owner: enrollment spec and app UX.                                                    |
| Malicious integrator           | Honest rendering, enforcement, audit completeness                    | Approver device recomputes request hash from decrypted context; verdict is not authorization; audit chain can expose what was requested.                      | A relying party that ignores verification or lies about local execution can still misbehave; owner: integrator conformance tests, signed/auditable hooks, and deployment policy. |
| Requester impersonator         | Actor identity shown to human                                        | Actor-key attestation is verified on device before the human approves.                                                                                        | v0 surfaces may show asserted-but-unverified actor identity until #16 hardens attestation; owner: actor-key implementation and warning UX.                                       |
| Replay attacker                | Approved verdict, old ciphertext, old request ids                    | Verdict binds `request_id` + `request_hash`; nonce store rejects reused approved verdict nonces; expiry windows are enforced.                                 | Persistent nonce storage/retention policy remains integrator-owned; owner: SDK/integrator configuration.                                                                         |
| Policy-rule attacker           | Standing `allow` rule or suppressed prompts                          | Rules are signed by device keys; precedence is `deny > ask > allow`; no match means ask.                                                                      | Rule sync/storage conflicts are deferred; owner: policy storage and management UI.                                                                                               |
| Audit tamperer                 | Decision history and policy evidence                                 | `AuditRecord` hash chain covers prior head and records the verdict JWS.                                                                                       | Anchoring cadence and retention are deployment choices; owner: integrator/auditor.                                                                                               |

## Invariant-To-Threat Mapping

| Contract invariant             | Defends against                                                                | Required checks / evidence                                                                                                                                                                                                                                                                           |
| ------------------------------ | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E2EE                           | Compromised relay, network MITM, plaintext leakage through push/relay state    | Relay stores only routing metadata, opaque `context_ciphertext`, public keys, and signed verdicts; tests reject unexpected envelope keys and secret material.                                                                                                                                        |
| Verifiable verdict             | Compromised relay, forged verdicts, malicious network, malicious device ids    | Verify verdict JWS against enrolled device cert and account root; reject revoked device ids from the highest-sequence root-signed account state; reject claim/outer mismatches; do not trust relay status alone.                                                                                     |
| WYSIWYS                        | Context/action TOCTOU, summary-only deception, swapped ciphertext or deadline  | Device recomputes `request_hash` over the canonical request-hash input (`ActionRecord`, summary, actor id/kind, risk, reversible, constraints, chain, and shown `expires_at`; `actor.attestation` is verified separately); renderer must show the bound syntactic substrate needed for the decision. |
| Requester attestation          | Requester impersonation, misleading origin text                                | Device verifies actor-key attestation before approval; unverified origins must be visibly downgraded until #16 is complete.                                                                                                                                                                          |
| Chain-composable and monotonic | Verdict reuse as authorization, policy bypass, upstream gate weakening         | Consumers compute `effective_allow = approved && verified && local_policy && other_gates`; the primitive never emits or stores reusable scope.                                                                                                                                                       |
| Fail-closed                    | Hung relay, no devices, expired request, malformed input, unverifiable verdict | Timeout/no-response/unverified/non-approved paths return `deny`/`expired`; hook exits 0 with explicit deny before external timeouts.                                                                                                                                                                 |

## Security Requirements

### R1. Context confidentiality

`ApprovalContext` plaintext must cross the relay boundary only as JWE ciphertext encrypted to enrolled approver
device keys. Push payloads may carry a wakeup and request id, never action context.

Validation:

- Relay tests assert accepted envelopes contain only contract routing fields plus `context_ciphertext`.
- Pairing and relay-client tests assert no seeds or private key material are sent to the relay.
- Manual review checks any new relay field for plaintext context leakage.

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

## Residual Risks

| Residual                                                    | Why it remains                                                                                                                    | Owner / next step                                                                    |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Agent-readable non-secret sensitive data can be exfiltrated | If the agent must read data to work, approval cannot prevent it from copying that data elsewhere.                                 | Sandbox/egress controls and data minimization; keep secrets in vaultkeeper.          |
| Relay denial of service                                     | Zero-knowledge routing does not make the relay available or honest about delivery timing.                                         | Availability engineering, retries, alternate transports, and audit visibility.       |
| Endpoint authentication is incomplete                       | Current routing relies on high-entropy ids and enrollment work still in progress.                                                 | Enrollment spec (#19) and endpoint authn implementation.                             |
| Actor identity may be asserted before #16                   | The contract requires actor-key attestation, but early surfaces may not verify it yet.                                            | Actor attestation implementation and unverified-origin UX.                           |
| Device loss and recovery UX is underspecified               | Root-signed account state gives offline verifier semantics, but publication latency and recovery flows still need product design. | Enrollment/revocation UX (#19).                                                      |
| Persistent nonce retention is integrator-owned              | In-memory nonce stores only protect one process lifetime.                                                                         | SDK/integrator persistent `NonceStore` configuration and retention tests.            |
| Semantic capability mistakes are deferred                   | v1 is syntactic; it does not infer generalized capabilities or data meaning.                                                      | T3 policy engine; until then, use conservative syntactic rules and human escalation. |

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

### Relay and Transport

- [ ] Relay-visible request fields are limited to the envelope contract; no plaintext action context is added.
- [ ] Push/wakeup payloads carry request ids only, never human-shown context.
- [ ] Pending requests expire fail-closed; expired requests cannot later resolve approved.
- [ ] Network failures, hung reads, refused connections, and malformed relay responses deny or expire, never allow.
- [ ] Any new endpoint states who may call it and what authentication/authorization is required.

### WYSIWYS and Approver UX

- [ ] Every field covered by `request_hash` that matters to the decision is rendered or intentionally explained.
- [ ] Parsed and raw command/MCP forms cannot diverge silently.
- [ ] Expiry, actor identity, risk, reversible status, and challenge requirement are visible before signing.
- [ ] Unverified actor identity is not presented as verified.
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
