# allw — Architecture & Tech Stack

Decisions for the approval primitive and its surrounding system. The guiding principle: **one audited Rust
core; thin native shells.** Everything security-critical is implemented once; per-platform code is UI,
notifications, and key storage only.

**Product identity:** allw is a **deep OS-integrated client, not a SaaS web shell.** OS integration —
notifications, widgets, Siri / Shortcuts, hardware-backed keys, the Watch — is core value, not chrome, and a
deliberate moat over web / Electron / push-only competitors.

## Decisions at a glance

| Component                   | Choice                                                                                                   | Why                                                                                                                                                                                                                                                          |
| --------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Shared core**             | Rust crate                                                                                               | One audited implementation of JOSE crypto, the approval contract, verdict signing/verification, and audit chaining. The verifiable-verdict invariant demands a single trusted impl. Mirrors `vaultkeeper`.                                                   |
| **Core → app bindings**     | UniFFI (Swift, Kotlin); direct crate (Linux `gtk4-rs`); C ABI via cbindgen + P/Invoke (Windows, C#/.NET) | Every app calls the same Rust logic; no crypto reimplementation per platform.                                                                                                                                                                                |
| **Core → TS bindings**      | **WASM only** (napi avoided)                                                                             | WASM runs under the already-approved `node` — no new native binary, so enterprise binary-allowlisting (Santa) and MDM can't block it. napi is itself a native binary; only consider it for a controlled server that needs the perf, never the local surface. |
| **Inbox apps**              | Fully native (no Tauri)                                                                                  | iOS+macOS Swift/SwiftUI; Android Kotlin/Compose; **Windows** native WinUI 3 + C#/.NET; **Linux** Rust + `gtk4-rs`. Driver: the richest _native_ notification experience on every platform; the Rust core keeps duplication to UI/notifications/keystore.     |
| **Relay**                   | Cloudflare Workers + Durable Objects                                                                     | Per-device/account DO with WebSocket hibernation is a near-perfect presence/routing relay: global, cheap, generous free tier. Zero-knowledge — routes ciphertext, never decrypts. **Push transport pluggable: APNs / FCM now, Web Push later.**              |
| **Integrator SDK**          | TypeScript (npm)                                                                                         | The MCP / Claude Code / CI ecosystem is TS-native. Wraps the Rust core via WASM.                                                                                                                                                                             |
| **Hook / local integrator** | Node + WASM (not a native binary)                                                                        | The Claude Code hook and any on-machine integrator run the Rust core as **WASM under `node`** — nothing new to allowlist (avoids Santa/MDM). Optional native binary only for unrestricted environments.                                                      |
| **Crypto**                  | JOSE — JWE + JWS, X25519 + Ed25519                                                                       | Reuse `vaultkeeper`'s choices so the crypto layer is shared, not re-derived.                                                                                                                                                                                 |
| **Monorepo**                | Cargo workspace + pnpm (polyglot)                                                                        | Same pattern as `vaultkeeper` (Rust + TS) and `macts` (pnpm).                                                                                                                                                                                                |

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │           allw-core  (Rust crate)         │
                    │  JOSE crypto · contract types · verdict   │
                    │  sign/verify · audit hash-chain           │
                    └───┬───────────┬───────────┬───────────┬───┘
            UniFFI ─────┘           │   WASM    │           └───── (direct crate dep)
        ┌───────────────┐   ┌───────┴───────┐   ┌───────┴───────┐   ┌──────────────┐
        │ iOS + macOS   │   │  TS SDK (npm) │   │  Hook (Node   │   │ Windows /    │
        │ Swift/SwiftUI │   │  + relay code │   │  + WASM)      │   │ Linux native │
        └───────────────┘   └───────────────┘   └───────────────┘   └──────────────┘
        ┌───────────────┐
        │ Android        │  Kotlin/Compose (UniFFI)
        └───────────────┘

   Relay (Cloudflare Workers + Durable Objects): zero-knowledge routing + pairing + push fan-out.
   Push transport: APNs (token-based HTTP/2) + FCM — wakeup + request id only; never context.
   Device key storage: Secure Enclave / Android StrongBox (mobile, biometric-gated signing); Keychain /
   DPAPI / libsecret (desktop — reuse vaultkeeper's backend abstraction). Signing keys never leave hardware.
```

## Local execution: WASM, not native binaries

On-machine code (the Claude Code hook, the integrator SDK, anything running the core _locally_) ships as **WASM
run under `node`**, never a standalone native binary. Corporate Macs commonly run binary allowlisting (Google
**Santa**) and MDM that block unapproved native executables — but `node` is already approved and a `.wasm` is
just data it loads, so there's nothing new to allowlist. A hard constraint, not a preference:

- **TS binding = WASM only.** `napi` is a native Node addon — itself a native binary — so it re-creates the Santa
  problem and is avoided on the local surface.
- **Native binaries stay in signed, store-distributed apps.** The native apps are notarized/store-signed and
  allowlisted by publisher cert; the risk is ad-hoc CLI binaries, which we don't ship.
- **The same WASM build is browser/worker-compatible** — which also unlocks the web fallback (below).

## Why native: deep OS integration is the product

For an approval primitive the notification interaction is not chrome — it's the product. Time-to-decision and
glanceability decide whether the tool feels effortless or annoying, and that's exactly where native frameworks
beat any cross-platform layer. **This is the primary reason for native-hybrid over Flutter/Tauri-everywhere.**
Going native buys:

- **Ambient, glanceable pending state** — an iOS **Live Activity / Dynamic Island** showing "N approvals
  pending" + an **expiry countdown**; the Android analog is an **ongoing/foreground-service notification**; on
  macOS, a **menu-bar item**. No competitor (Clawvisor, ntfy, HumanLayer) does more than fire a push.
- **Decide from the notification** — Approve/Deny (and number-match for destructive ops) inline from the lock
  screen / **Apple Watch**, with rich in-notification context (the command, the diff, the record).
- **Urgency control** — Time-Sensitive / Critical (iOS) and heads-up (Android) to pierce Focus/DND when an
  approval is genuinely blocking, plus per-risk **notification channels** so the user tunes each tier's loudness.
- **Beyond notifications** — desktop/lock-screen **widgets** (WidgetKit), **Siri Shortcuts / App Intents**
  (voice, Action Button, interactive widgets, Spotlight, automations), **hardware-backed keys** (Secure Enclave /
  StrongBox) with **biometric-gated approval signing** (the verdict key never leaves hardware, released by
  Face ID / Touch ID), **Apple Watch** & Wear OS, Focus filters, Control Center. Core experience, not chrome.

Reframed, "one inbox" becomes _an ambient approval presence on every device_ — a real differentiator, not polish.

## Cross-device notification coordination

A pending approval may surface on several of a user's devices at once — and on macOS the **same** iOS request can
appear _twice_ on one screen (a native macOS notification **and** the iPhone notification mirrored via iPhone
Mirroring). Getting this right is a coordination problem, and another reason native wins:

- **Fan-out then retract.** Raising an approval lights up the enrolled devices; the instant any surface resolves
  it, every other device must **remove the delivered notification** (and clear the Live Activity / menu-bar /
  ongoing notification / tray badge). Native APIs expose exactly this (managed notifications, stable ids,
  programmatic removal); web push does not.
- **Dedupe across transports.** Avoid double-surfacing one logical request on a single screen (native macOS app
  vs iPhone-mirrored iOS notification) via **device-aware routing** — light up one surface per screen, not all.
- **Owner: the relay.** The per-account **Durable Object** knows the device topology and live presence, so it
  drives targeted fan-out, retraction, and dedupe. First-class requirement on the relay + apps, not an afterthought.

Relay device presence sockets expose the topology hook with an optional `surface_id` on
`GET /devices/{id}/connect`: transports visible on the same physical screen use the same `surface_id`, and the
Durable Object fans out/flushes a request to only one live socket per surface. Clients that omit `surface_id` keep
independent delivery, and retractions still broadcast to every live socket so stale notifications clear.

## Platform mapping (native)

Core access: **UniFFI** (Swift/Kotlin); **direct crate** (Linux `gtk4-rs`); **C ABI / P-Invoke** (Windows, C#/.NET).

| Platform | UI stack                                 | Native surfaces we exploit                                                                                                                                                                                                                       | Keystore                   |
| -------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- |
| iOS      | Swift / SwiftUI                          | Interactive notifications (Approve/Deny on lock screen) · **Live Activity + Dynamic Island** (pending + expiry) · **widgets** (WidgetKit) · **App Intents / Siri** (voice, Action Button, Spotlight) · Time-Sensitive/Critical · **Apple Watch** | Secure Enclave + Keychain  |
| macOS    | Swift / SwiftUI (shares iOS)             | Notification Center actions · **menu-bar item** (persistent "N pending") · **desktop widgets** · App Intents · Focus filters (Live Activities are iOS-only; mirror to Mac via Continuity)                                                        | Secure Enclave + Keychain  |
| Android  | Kotlin / Compose                         | Notification actions · heads-up · **ongoing/foreground-service** persistent pending · **home-screen widgets** · per-risk channels · **Wear OS**                                                                                                  | StrongBox / Keystore       |
| Windows  | **Native** — WinUI 3 + C#/.NET           | **Updatable adaptive toasts** (WinRT) w/ buttons & inputs · Action Center persistence · **tray icon** ambient presence · Win11 widgets                                                                                                           | DPAPI / Credential Manager |
| Linux    | **Native** — Rust + `gtk4-rs`/libadwaita | D-Bus notification **actions** · **StatusNotifierItem tray** persistence (platform-capped: no Live-Activity equivalent regardless of toolkit)                                                                                                    | libsecret                  |

> All desktop targets are native (Tauri dropped): macOS shares the iOS Swift app; Windows is native; Linux is
> `gtk4-rs`. The only remaining desktop fork is the Windows app _language_ (see open sub-decisions).

## Surfaces: native first-class; a web fallback (later, second-class)

Native apps are the product. But some users face real install friction — MDM that forbids native installs, or
locked-down machines. Keep a **future second-class web client** possible _by design now, without building it yet_:

- **Service worker / web worker runs the same WASM core** (decrypt context, sign verdicts in-browser).
- **Web Push** as a pluggable relay transport alongside APNs/FCM.
- **WebAuthn / passkeys (platform authenticator)** as the in-browser analog to Secure Enclave for hardware-backed,
  biometric-gated signing.
- **Explicitly second-class:** no Live Activities, limited notification actions, weaker ambient presence. Don't
  invest until pulled — but the two cheap constraints above (browser-compatible WASM core, pluggable push) keep
  the door open.

## v1 sequencing (don't build five apps before validating)

Native hybrid is the _target_, not the v1 deliverable. Build order for the locked v1 (coding agent +
multi-machine inbox, phone-hero):

1. **`allw-core`** (Rust): contract types, JOSE crypto, verdict sign/verify, audit chain — contract-first.
2. **Hook CLI + TS SDK**: the first callers (`requestApproval`), so a Claude Code hook can fire requests.
3. **Relay** (Workers + DO): pairing, routing, push fan-out.
4. **First inbox app — iOS** (the hero surface), then **macOS** (shares the iOS Swift app) for same-machine approvals.
5. Expand to Android, then Windows and Linux, once the loop is validated.

> **Build environments:** author the iOS/macOS Swift app in **Xcode with Claude embedded** (the best agentic
> authoring experience for Apple platforms); it lives as an Xcode project in/beside the Cargo+pnpm monorepo,
> consuming the core via UniFFI. Android in Android Studio (Kotlin); **Windows in Visual Studio (C#/WinUI 3,
> core via P/Invoke)**; Linux `gtk4-rs` and the WASM/TS surfaces in the main workspace.

## Open sub-decisions (not blocking)

- **Relay language:** Workers + DO in TS (most mature DO ergonomics) vs Rust (`workers-rs`). Default TS;
  pull the Rust core in as WASM only where shared verification is needed.
- **TS core binding — RESOLVED: WASM only.** napi is a native binary and would re-trigger Santa/MDM blocking on
  the local surface; WASM under `node` is the constraint. (napi only ever for a controlled server, never local.)
- **Windows app language — RESOLVED: C#/.NET + WinUI 3** (richest, most ergonomic adaptive-toast / Action-Center
  tooling; adds C# as the one extra app language). Core accessed via a C ABI (cbindgen) + P/Invoke. Linux settled
  on **Rust + `gtk4-rs`**; macOS shares the iOS Swift app. (Linux notification richness is platform-capped — no
  Live-Activity equivalent — regardless of toolkit.)
