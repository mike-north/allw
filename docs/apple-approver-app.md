# Apple approver app — universal SwiftUI spec

Status: **active design** · Owner: PM · Tracks: #23 (universal app, v1 perimeter), #132 (deeper
surfaces, post-v1), epic #136. Authored for the **Xcode-with-Claude** build environment
(`docs/architecture.md`).

This is the spec for the **hero approval surface**: one universal SwiftUI app that lets a human
approve/deny an agent's gated action from any Apple device. It is built **on top of the existing
`apps/ios-approver` Swift package** (`AllwIOSApprover`) — the audited, tested, platform-neutral
inbox logic — which in turn consumes the one Rust core (`crates/allw-core`) via **UniFFI**. The app
and all its extensions are **thin surfaces**: they render and route, they never do crypto.

> Read first: `docs/contract.md` (the invariants), `docs/threat-model.md` (Security Goal 8 /
> structure-not-data, R-series), `docs/enrollment.md` (pairing, account state, revocation),
> `docs/architecture.md` (platform mapping). This spec must not contradict them.

---

## 1. Scope & platform matrix

One SwiftUI codebase, native per platform (**Mac Catalyst is rejected** — true multiplatform
SwiftUI with native AppKit/UIKit behaviors). Decision 1 + Decision 2 (see
`scratch/allw-roadmap-decisions.md`).

| Surface                               | v1 perimeter                                                          | Post-v1 (#132)                      |
| ------------------------------------- | --------------------------------------------------------------------- | ----------------------------------- |
| **iPhone** (iOS 17+)                  | ✅ full inbox + detail (WYSIWYS) + number-match + Secure-Enclave sign | richer Dynamic Island               |
| **iPad** (iPadOS 17+)                 | ✅ same, adaptive layout                                              | —                                   |
| **macOS** (14+, native)               | ✅ same, window app                                                   | menu-bar extra item, richer widgets |
| **Lock screen / Live Activity** (iOS) | ✅ pending state + **approve-from-lock-screen**                       | rich interactive Live Activity      |
| **Notifications** (all)               | ✅ wakeup + actionable approve/deny (App Intents)                     | —                                   |
| **Widgets** (WidgetKit)               | pending count + expiry (read-only, tap-to-open) — stretch             | full widget suite                   |
| **Apple Watch** (watchOS)             | —                                                                     | ✅ glance + approve/deny            |
| **CarPlay**                           | —                                                                     | ✅ (feasibility-gated; see §7)      |

**v1 acceptance is iPhone + iPad + macOS + lock-screen approve.** Watch, CarPlay, and the full
widget/menu-bar suite are post-v1 (#132) — but **architect for them now** (shared core logic, shared
view models, per-surface presentation) so adding a target is additive.

---

## 2. Architecture: one core, many surfaces

```
crates/allw-core (Rust; crypto, contract, verdict sign/verify, hash, attestation)
        │  UniFFI  (generate Swift bindings → XCFramework)
        ▼
AllwIOSApprover  (apps/ios-approver — SwiftPM package; PLATFORM-NEUTRAL logic + models)
   ApprovalInboxStore · ApprovalModels · ApproverCoreRuntime seam · PushInboxCoordinator ·
   NativeCredentialStore · SecureEnclaveSigning seams · (basic) ApprovalInboxView
        │  consumed as a local package dependency
        ▼
Apple approver app  (NEW — the Xcode project this spec kicks off)
   app target(s) + extensions, each providing PRODUCTION implementations of the package seams
   and per-platform SwiftUI presentation. NO crypto here.
```

**Thin-shell is a hard invariant.** The app and every extension/target call the package; the package
calls the core. No hashing, JWE/JWS, signing, attestation, or policy logic in app/extension code.

### The package is the shared foundation (consume, don't fork)

The package already provides (all `Sendable`, injectable seams, fail-closed, tested):

- `ApprovalInboxStore` — lifecycle: `sync(envelopes)`, `inbox`, `history`, `detail(id)`,
  `canApprove(id, challengeResponse:)`, `decide(...)`. Core-verified expiry; number-match gating;
  sign-failure restores `.pending`.
- `ApprovalModels` — `ApprovalEnvelope`, `ApprovalContext`, `ApprovalAction` (`CommandAction` /
  `McpCallAction`), `ApprovalActor` + `ActorAttestationState`, `ApprovalRisk`, `NumberMatchChallenge`,
  `PreparedApproval` (carries the **core-computed `requestHash`** + `expiresAt`), `SignDecisionInput`,
  `SignedVerdict`, `ApprovalListItem` (with `countdownMs`).
- `ApproverCoreRuntime` / `UniFfiApproverRuntime` + `UniFfiCoreBinding` / `UniFfiSignBinding` — the
  prepare()/signDecision() boundary to the core.
- `NativeCredentialStore` + `KeychainNativeCredentialStorage` — paired-device credentials + the
  root-verified account-state **sequence floor** (anti-rollback).
- `SecureEnclaveSigning`: `BiometricGate` / `LocalAuthenticationBiometricGate`, `SigningSeedProvider`
  / `KeychainSigningSeedProvider`, `VerdictNonceSource` / `SystemVerdictNonceSource`.
- `PushInboxCoordinator` + `RelayInboxFetching` / `UrlSessionRelayInboxClient`,
  `InboxNotificationSurface`, `PushTokenRegistering` / `HexApnsTokenRegistrar`.

**Package changes the agent should make:** add `.watchOS(.v10)` (and any CarPlay-relevant) to
`Package.swift` platforms; keep the package pure logic+models (move/keep platform-specific UI in the
app, not the package); consider renaming the product to `AllwAppleApprover` (optional, low priority).

---

## 3. What the Xcode agent builds (the gaps)

1. **The Xcode project** in/beside the monorepo: a multiplatform SwiftUI **app target** (iPhone/iPad/
   macOS destinations) + extension targets (Live Activity widget, Notification, WidgetKit; later
   Watch app, CarPlay scene). Add the local SwiftPM dependency on `AllwIOSApprover`.
2. **The UniFFI binding wiring (production `UniFfiCoreBinding` / `UniFfiSignBinding`).** Generate the
   Swift bindings from `crates/allw-core` (UniFFI), build an **XCFramework**, and implement the
   package's binding protocols against it. Document the generate→XCFramework build step (Makefile /
   build phase / script). This is the single most important production gap.
3. **Pairing / onboarding UI** (enrollment ceremony per `docs/enrollment.md`): establish account +
   device, persist via `KeychainNativeCredentialStorage`, register the APNs token via
   `PushInboxCoordinator.registerApnsToken`. The app is **not** the account-root holder, so it also runs the
   **cross-device `device_cert` ceremony** (`docs/enrollment.md` §Cross-Device `device_cert` Issuance
   Ceremony, #175): scan the enrollment QR (or open the `allw://enroll#…` deep link), generate both seeds
   on-device with the signing key in the Secure Enclave, deposit the MAC-authenticated CSR, show the six-digit
   confirmation code for the human to compare against the root holder's screen, then poll for the cert and
   verify it against the pinned account-root pubkey before persisting. Inbox is unreachable until a
   **root-verified `device_cert`** is stored — "paired but uncertified" is not a usable state.
4. **Inbox + detail (WYSIWYS) UI** per surface, driven by `ApprovalInboxStore` / `ApprovalListItem` /
   `ApprovalDetail`. Detail must render the **exact** bound plaintext (command argv/raw or MCP
   server+tool+params-summary), actor + attestation badge, risk/reversibility, expiry countdown, and
   the number-match challenge. Approve disabled structurally until `canApprove` is true.
5. **Secure-Enclave signing path**: wire `LocalAuthenticationBiometricGate` + `KeychainSigningSeedProvider`
   (real Keychain, `biometryCurrentSet`, passcode-set, non-synchronizable) into `decide(...)`.
6. **Push + notifications**: `UNUserNotificationCenterDelegate` → `PushInboxCoordinator.handleWakeup`;
   actionable notification (approve/deny via **App Intents**); `InboxNotificationSurface`
   implementation that adds/clears notifications.
7. **Live Activity / Dynamic Island** (ActivityKit): pending count + expiry countdown;
   **approve-from-lock-screen** affordance (App Intent) that still routes through biometric + Secure
   Enclave + WYSIWYS (see §6 reduced-surface rule).
8. **Relay client**: `UrlSessionRelayInboxClient` against the deployed relay; bearer-token auth
   (`docs/enrollment.md` / relay).
9. **Entitlements & capabilities** (§5).

---

## 4. Core approval flow (every surface)

1. APNs **wakeup** arrives (payload = **request id only**, never context).
2. `PushInboxCoordinator.handleWakeup` → `RelayInboxFetching.fetchPendingEnvelopes` → ciphertext
   envelopes.
3. `ApprovalInboxStore.sync` → `ApproverCoreRuntime.prepare` (**core** decrypts the JWE with the
   device key, recomputes the **WYSIWYS `request_hash`** device-side, verifies actor attestation
   against root-signed account state). Failure ⇒ `.unverified` (deny-only), never approvable.
4. Human opens the request; UI renders **WYSIWYS** from the decrypted `ApprovalContext`.
5. Approve requires `canApprove` (not expired, decision allowed, number-match satisfied). Approve →
   `decide(.approved)` → biometric gate → Secure-Enclave sign via core `sign_verdict_json` over the
   **core `requestHash`** → `SignedVerdict`.
6. Verdict returned to the relay. Notifications clear on resolve. Deny/timeout enforce fail-closed.

---

## 5. Entitlements & capabilities

- **Push** (APNs, background `content-available`); App Groups (share inbox state/credentials with
  Live Activity, widgets, Watch).
- **Keychain** (access group; Secure-Enclave biometric items: `biometryCurrentSet`,
  `WhenPasscodeSetThisDeviceOnly`, non-synchronizable); **Face ID** usage description string.
- **ActivityKit** (Live Activities); **WidgetKit**; **App Intents** (notification + Live Activity
  actions); **CarPlay** entitlement (post-v1, requires Apple approval — gate behind feasibility);
  **WatchConnectivity** (post-v1).
- Sign with the team's profile; document the signing/provisioning needs.

---

## 6. Invariants — every surface, including reduced ones (HARD)

1. **Thin-shell** — no crypto in app/extension code; all via the package → UniFFI → `allw-core`.
2. **Fail-closed** — any decrypt/verify/attestation/expiry/biometric/relay failure ⇒ deny-only or
   unverified; never an approve-looking or trusted state. A surface that can't reach the core shows
   "open to approve", never a local approve.
3. **WYSIWYS** — the signature binds the **core-computed `request_hash`** over the exact plaintext
   the human saw. **Reduced-surface rule:** Watch / CarPlay / Live Activity may present an approve
   affordance **only** if they faithfully render the bound substrate the decision needs; otherwise
   they must defer to the full app ("open iPhone to review & approve"). Never approve over content a
   surface can't show.
4. **Secure Enclave + biometric per signature** — signing seed never leaves hardware; Face ID/Touch ID
   required each sign; key never logged/exported.
5. **Push = request-id only** — wakeup payloads carry a request id, never human-shown context.
6. **Structure-not-data (#131)** — the device sends no decrypted arguments/values/env to the relay;
   no sensitive data in URLs/query params.
7. **Unsafe states unreachable, not styled** — approve is structurally disabled (not just greyed)
   until `canApprove`.

---

## 7. Open questions (resolve during build; surface to PM)

- **Live Activities feasibility** for a true lock-screen _approve_ (vs. deep-link to app) under the
  biometric + WYSIWYS constraints.
- **CarPlay** feasibility for an approval surface at all (entitlement + HIG); default to "open phone
  to approve" if it can't satisfy WYSIWYS.
- **Watch** WYSIWYS fidelity: which requests are approvable on-wrist vs. defer-to-phone.
- UniFFI XCFramework build + CI integration (the native-bindings job).

---

## 8. Acceptance criteria (v1 perimeter)

- A real Claude Code (and/or Codex) gated action approved **and** denied **and** timed-out
  end-to-end against the deployed relay from **iPhone, iPad, and macOS**.
- Signing key never leaves the Secure Enclave; each signature requires biometric auth.
- **Lock-screen approve** works on iPhone and still satisfies biometric + Secure Enclave + WYSIWYS.
- WYSIWYS detail renders the exact bound plaintext; tampered context (hash mismatch) ⇒ blocked;
  revoked/unknown actor ⇒ ⚠ UNVERIFIED, deny-only; expired ⇒ deny.
- Number-match required for destructive/critical approvals.
- Thin-shell verified (no crypto in app/extension targets); the package's Swift tests stay green;
  the UniFFI XCFramework builds in CI.

## 9. Non-goals (this effort)

Watch/CarPlay/full-widget/menu-bar **implementation** (architect-for, build later under #132);
AI-summary privacy tier; the policy/semantic tier; relay-side work. Keep those as seams, not code.
