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

## Deferred production wiring

The current UniFFI crate exposes request hashing and verdict signing/verification smoke tests, but
does not yet expose native context decryption, pairing helpers, or a wired native signing path.
`UniFfiApproverRuntime` therefore fails closed until those calls exist. The next slice should add
the missing UniFFI decrypt/pairing operations, then back `prepare(envelope:)` and
`signDecision(_:)` with real core calls and the persisted Keychain device credentials.
