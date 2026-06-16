# allw iOS approver

This package is the first native iOS foundation slice for issue #23. It is intentionally small:
the Swift code owns inbox lifecycle state and render-ready models, while cryptographic preparation
and verdict signing stay behind `ApproverCoreRuntime` so production code can call the shared Rust
core through UniFFI.

## What this slice proves

- Fail-closed rendering: undecryptable or unverifiable requests become `.unverified` and cannot
  sign.
- Device-side expiry uses `PreparedApproval.expiresAt`, the core-prepared deadline, rather than the
  relay-visible envelope timestamp.
- Number-match approvals require the exact challenge response before the app asks the core to sign.
- Deny remains available for prepared requests without satisfying number-match.
- A signing failure restores `.pending` so a transient Keychain/Secure Enclave problem does not lose
  the request.
- Paired device credentials and the root-verified account-state sequence floor persist behind a
  Keychain-ready storage seam; rollback or relay-advertised-but-unverified account state fails
  closed before it can drive verified actor rendering.
- `acceptVerifiedAccountState`'s `verifiedSequence` must come from core JWS verification, never from
  relay `max_sequence` metadata.

## Local test

Swift Package Manager is the intended package shape, but this repo's lightweight local validation
uses `swiftc` directly so it can run in Command Line Tools environments without Xcode:

```sh
bash apps/ios-approver/scripts/test-ios-approver.sh
```

## `prepare(envelope:)` is backed by the core

`UniFfiApproverRuntime.prepare(envelope:)` now composes the shared Rust core via the UniFFI
`prepare_approval_json` call: it decrypts the envelope JWE with the device X25519 encryption seed,
recomputes the WYSIWYS `request_hash` device-side, and verifies the actor attestation against
root-signed account state. The runtime never hashes, decrypts, or interprets crypto itself — it only
marshals inputs, decodes the canonical core `ApprovalContext` JSON into the render model, and maps
the core-reported `attestation_verified` onto the inbox's verified/unverified display state.

Fail-closed split:

- A **decrypt/hash failure** (forged/tampered JWE, wrong key, malformed input) throws → the store
  renders the request `.unverified` with no plaintext.
- An **unverifiable origin** (attestation not root-anchored) is not an error: the context still
  decrypts and renders, but the row is `.unverified` and deny-only.

The `apps/ios-approver` package compiles standalone (its local `swiftc` validation does not link the
generated bindings), so the runtime depends on the narrow `UniFfiCoreBinding` seam. The Xcode target
wires that seam to the generated `prepareApprovalJson`; tests inject a fake.

## APNs wakeup → fetch envelope → inbox refresh

`PushInboxCoordinator` drives the push-delivered inbox lifecycle (issue #142):

1. An **APNs wakeup** carries a **request id only** — never human-shown context
   (`docs/contract.md` §Push). The coordinator does not trust the payload for rendering; it is only a
   signal to refresh.
2. The coordinator **fetches the relay-visible envelopes** through the `RelayInboxFetching` seam
   (`GET /{account}/devices/{device}/inbox`, the HTTP polling counterpart to the presence socket).
   The relay is zero-knowledge: the response is opaque `context_ciphertext`.
3. The envelopes go to `ApprovalInboxStore.sync`, which runs each through the core `prepare()`
   (decrypt + WYSIWYS hash + attestation verification in `allw-core`).
4. The coordinator **reconciles notifications**: it presents a notification for every still-pending
   request and clears notifications for request ids that resolved, expired, or became unverifiable.

Fail-closed behaviour proved by tests:

- A relay **fetch error** throws and leaves the existing inbox and notifications untouched — a
  network blip never wipes a real pending approval or renders an approved-looking row.
- A **tampered/malformed** relay response (e.g. an envelope missing its ciphertext) fails the whole
  batch closed in `RelayInboxDecoder` rather than smuggling a half-formed request in.
- An **unverifiable origin** decrypts to a deny-only `.unverified` row and is never presented as a
  fresh actionable approval.

Device push-token registration: `HexApnsTokenRegistrar` hex-encodes the raw APNs token (the relay
accepts 64-char hex APNs tokens) and forwards it to the relay's pairing-complete `push_tokens`
registration; the concrete HTTP call lives in the pairing flow, so the registrar is parameterized
over an async sender to keep the package's standalone `swiftc` validation free of networking.

CI-only validation: the real `UNUserNotificationCenter` notification surface, the `URLSession`-backed
`UrlSessionRelayInboxClient`, and APNs delivery validate only in CI's macOS `native-bindings` job.
The local `swiftc` run exercises the coordinator, the decoder, and the reconciliation logic against
injected fakes.

## Deferred production wiring

`signDecision(_:)` still fails closed: native Secure-Enclave verdict signing is the next #23 child
(#141). It will call UniFFI `sign_verdict_json` with the device signing seed and a random nonce after
`prepare` has produced core-decrypted context. Pairing helpers (populating
`NativeDeviceCredentials`, including the device encryption seed) and the wiring of the generated
binding into the Xcode target also remain.
