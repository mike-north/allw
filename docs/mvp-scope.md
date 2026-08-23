# allw — MVP Scope

**What this is.** The committed source of truth for v1 scope: which integrations the MVP must serve, the
journeys that prove it works, the capability milestones that sequence the work, and the decisions that are
locked. It sits _above_ the design docs — this doc says **what we are shipping and in what order**;
[contract.md](./contract.md), [policy-seam.md](./policy-seam.md), [architecture.md](./architecture.md), and
[enrollment.md](./enrollment.md) say **how**. If this doc and a design doc appear to disagree, the design doc
owns the mechanism and this doc is the one that needs fixing.

**Where the work is tracked.** Milestones **M1–M7** on this repo carry the same capability statements as the
table in §(c) — [repo milestones](https://github.com/mike-north/allw/milestones); the cross-repo sequencing
board (allw + macts) is the [MVP project board](https://github.com/users/mike-north/projects/8). Keep the
milestone descriptions and this table in sync; they are two views of one decision.

---

## (a) The three integration goals

The MVP is proven by three callers, deliberately chosen to be unlike each other. Together they show that allw
is a **primitive you embed**, not a destination you adopt ([positioning.md](./positioning.md)).
[OpenClaw](https://github.com/openclaw/openclaw) and [macts](https://github.com/mike-north/macts) live in their
own repos; the coding-agent hooks live here.

| Integration goal                                   | What it means concretely                                                                                                                                                                        | Why it is in the MVP                                                                                                                                                                                 |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OpenClaw** — native approval client              | allw runs as a gateway client holding the `operator.approvals` scope, mirroring exec and plugin approval requests into the allw inbox and resolving them with signed verdicts.                  | Proves allw inside a personal-agent runtime that _already_ has an approval subsystem and a documented external-approver seam. allw plugs into that seam as a client; it does not fork or replace it. |
| **Claude Code + Codex** — coding-agent hook parity | Both coding agents gated identically through the same hook shape, npm-installable, with quickstart parity between them.                                                                         | The wedge audience: developers running parallel agents on their own machines. **Parity is the deliverable** — one inbox, and a request from either agent behaves the same way.                       |
| **macts** — host policy and API-key policy         | A macts confirm-first operation holds the call and resolves through macts's HITL-provider interface, with allw as the first provider plugin; then per-API-key policy composed with host policy. | Proves allw outside the coding-agent surface, and forces the caller-side interface to be **provider-agnostic rather than allw-shaped** — the test of whether the primitive is genuinely embeddable.  |

---

## (b) Four steel threads — representative journeys

> **These are illustrative, not exhaustive.** Each steel thread is a representative journey that becomes
> _possible_ at a given milestone, and a demo that proves the capability end to end. It is **not** the full
> acceptance bar for that milestone — a milestone's issues define what must ship, and a thread typically
> exercises one slice of it. Read a thread as "here is what you can now do," never as "here is everything M*n*
> owes."

### ST-1 — "Leave the desk" _(exercises M1–M3)_

Claude Code and Codex are running in tmux on a dev box. You close the laptop and leave. An agent reaches a
deploy command; the hook holds it and raises an approval request. The request lands in your inbox, you open it
in the **phone browser**, read exactly what the agent proposed to run, and confirm with a number-match
challenge. The held command resumes. Had you never answered, it would have expired to a deny.

_Exercises:_ the hosted relay across a real network (M1), identical gating from either coding agent (M2), a
web approver good enough to use one-handed on a phone (M3), and number-match derived from the WYSIWYS
`request_hash`.

### ST-2 — "Personal agent, guarded hands" _(exercises M4)_

An OpenClaw agent wants to run a shell exec. Its approval request arrives in the **same inbox** as ST-1's
coding-agent requests — the only difference the human sees is the attested actor identity. Approve and the
agent proceeds; deny and it does not. Let it sit: allw's approval window is budgeted to expire strictly
_inside_ OpenClaw's own approval timeout, so neither layer times the other out and **both sides land on deny**.

_Exercises:_ one inbox spanning unrelated agent runtimes, actor-identity conventions that make origin legible,
and fail-closed timeout budgeting across two independently timing systems.

### ST-3 — "One mac, many keys" _(exercises M5–M6)_

A macts host has issued two API keys: one broad, one strict. The strict key attempts a `send` — an operation the
host permits but the key does not auto-allow — and it is **held for approval**, resolving through the
HITL-provider interface. Then the same key attempts an operation the **host** forbids, and it is refused
outright by macts; **it never reaches the inbox at all**.

That negative half is the point, not a footnote: asking a human about something already forbidden creates a
path to accidentally widening a boundary. A key may only tighten.

_Exercises:_ host ∧ key composition by intersection inside macts, provider-interface routing, and
deny-without-escalation.

### ST-4 — "Lock-screen approval" _(exercises M7 — parallel hero track, not gating)_

A pending approval surfaces as a Live Activity with its expiry counting down. You approve from the lock screen;
Face ID releases the Secure-Enclave signing key and the verdict is signed on-device without the app ever coming
to the foreground. The phone's signing key is trusted because it was certified through the cross-device
`device_cert` ceremony ([enrollment.md](./enrollment.md)) — the phone is not the account-root holder.

_Exercises:_ ambient presence, hardware-backed biometric signing, and cross-device certificate issuance. This
is what makes the product feel inevitable — and the MVP still does not wait on it.

---

## (c) Capability milestones (M1–M7)

Each milestone is named for the **capability it unlocks**, not the components it touches. Where a steel thread
exercises that capability end to end, the thread's demo _is_ the exit criterion.

| Milestone                                | Capability it unlocks                                                                                                                                                                     | Exit criterion                                                                                                                                                                   |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **M1 — Approvals cross the internet**    | Any approval works across networks, not just on localhost: a hosted relay on a real Cloudflare account that the quickstart points at by default.                                          | Walking-skeleton end-to-end green against the live hosted URL, and the quickstart defaulting `ALLW_RELAY_URL` to it. **Unblocks every other milestone.**                         |
| **M2 — Codex parity**                    | Both major coding agents (Claude Code + Codex) gated identically and npm-installable, with quickstart parity.                                                                             | `@allw/codex-hook` published; the Claude Code integration contract documented in one place; the 2026 Codex hook surface re-verified; Codex gating UAT green on the hosted relay. |
| **M3 — Approve from your phone browser** | The web approver is hosted, reachable, and polished enough to live on from a mobile browser — deploy target, dark mode, onboarding, live retraction, rollback floor.                      | **ST-1 "Leave the desk"** runs end to end.                                                                                                                                       |
| **M4 — OpenClaw approver**               | allw is a native OpenClaw approval client: a gateway client holding `operator.approvals` mirrors exec and plugin approval requests into the inbox and resolves them with signed verdicts. | **ST-2 "Personal agent, guarded hands"** — approve, deny, and timeout, fail-closed on both sides.                                                                                |
| **M5 — macts asks a human**              | A macts confirm-first operation holds the call and resolves through the HITL-provider interface, with allw as the first provider plugin (the host-policy angle).                          | The provider interface and its held-call seam land on the macts side; allw ships the provider plugin plus its integration doc. **Spans two repos.**                              |
| **M6 — Keys tighter than hosts**         | Per-API-key policy in macts composed with host policy by intersection (a key may only tighten), with host-level and key-level approvals routable to distinct allw accounts.               | **ST-3 "One mac, many keys"**, including the negative case — a host-forbidden operation never asks.                                                                              |
| **M7 — Pocket approvals**                | Approve from the iPhone lock screen: the cross-device `device_cert` ceremony, the universal Apple approver app, and Live Activity + Face ID signing.                                      | **ST-4 "Lock-screen approval"**. **Parallel hero track — non-gating for the MVP.**                                                                                               |

**MVP = M1–M6.** Those six are the gate: when they are done, the three integration goals in §(a) are real and
demonstrable. **M7 runs in parallel and does not gate the MVP** — it is the hero surface that makes the story
land, and it is sequenced so that slipping it delays nothing else.

**M1 status.** The relay's first production deployment is live at
[allw-relay.mnorth.workers.dev](https://allw-relay.mnorth.workers.dev) and has been verified end to end on all
three paths: **approve**, **deny**, and **timeout ⇒ deny (fail-closed)**. Note what "approve" means here — the
verdict does not return "allow"; the walking-skeleton _integrator_ composed
`allow = approved ∧ verified ∧ (other gates)` and let the command through ([contract.md](./contract.md)
Invariant 6). The remaining M1 work is pointing the quickstart at that hosted URL by default.

---

## (d) Locked decisions

These are settled. They are stated plainly here so a later PR can be checked against them.

### 1. The web approver gates the MVP — not a native app

The MVP's approval surface is the **hosted web approver** (M3). The universal Apple app is M7: a parallel hero
track whose slipping must not slip the MVP. This is a scope decision about the _gate_, not a reversal of
[architecture.md](./architecture.md)'s "native apps are the product" position — the native surface is still
where the deep OS integration lives, and M7 is where it lands.

### 2. macts stays HITL-provider-agnostic

**macts defines an interface for seeking HITL approval signals; allw ships as a plugin implementing it.** macts
must not grow an allw-shaped dependency — another approval provider must be able to implement the same
interface without the interface changing. The interface **reserves room** for two things it does **not**
implement in v1:

- **Policy-editing as part of approval** — the ability for a human's answer to also adjust standing policy.
  Reserved, not built. And when it is built it can never become a field on a verdict: verdicts stay
  **one-shot and scope-free** ([contract.md](./contract.md) §Verdict), and any standing rule is a separately
  signed `PolicyRule` ([policy-seam.md](./policy-seam.md) §The approval → rule bridge).
- **Routing host-level vs. key-level approvals to different allw accounts** — the seam must exist from the
  start so it can be split later without a breaking change. Initially **both route to the same user's
  account**.

### 3. Host ∧ key policy composition lives in macts

A macts API key may **only tighten** host policy, never widen it: composition is **intersection**, matching the
cross-gate monotonicity rule in [policy-seam.md](./policy-seam.md) §Composition & monotonicity. This
composition is macts's job, not allw's — allw has no policy engine in v1 and simply receives whatever
escalations macts decides to raise. The observable consequence is ST-3's negative half: a host-forbidden
operation is refused by macts and never becomes an approval request.

---

## What this scope does not change

Every invariant below is unchanged by anything in this document. A PR that appears to need one of them relaxed
is a PR with a design problem.

- **The primitive never returns "allow."** It returns a verified human decision bound to an exact request;
  callers compute `allow = approved ∧ verified ∧ policy ∧ (other gates)`. A verdict can only ever _tighten_.
  ([contract.md](./contract.md) Invariant 6.)
- **Fail-closed.** Timeout, no response, or an unverifiable artifact resolves to **deny** — in every caller,
  including across two nested timeout budgets (ST-2).
- **One-shot and scope-free verdicts.** No reuse, no "don't ask again," no scope field. Standing autonomy is
  the policy layer's job and arrives as a signed `PolicyRule`. ([contract.md](./contract.md) §Verdict.)
- **WYSIWYS.** The verdict binds to `request_hash` over the exact plaintext the human was shown, computed
  device-side after decryption.
- **Zero-knowledge relay.** The relay routes ciphertext and signed verdicts — never plaintext. At the default
  privacy tier it may additionally see action _structure_ (surface kind, function identity, session label),
  never action _data_. ([contract.md](./contract.md) Invariant 2.)
- **WASM-local, no native binary on the local surface.** Every on-machine caller added by this scope — the
  hooks, the OpenClaw bridge, the macts provider — ships as WASM under `node`.
  ([architecture.md](./architecture.md) §Local execution: WASM, not native binaries.)

---

## Explicitly out of scope for the MVP

- **The semantic / T3 capability-inference tier** — capability taxonomies, per-command schema DB, doc
  extraction, capability-scoped rules. Deferred exactly as [policy-seam.md](./policy-seam.md) describes.
  Adding macts as a _caller_ does not pull this forward; see [positioning.md](./positioning.md) §Where it
  starts, where it goes.
- **A policy engine inside allw.** v1 has none. Every escalation the MVP handles is decided by the _caller's_
  policy (the hook's, OpenClaw's, macts's) before allw is invoked.
- **The paranoid/enterprise and ai-summary privacy tiers.** `privacy_preference` stays reserved and null;
  only the default structure-visible tier is built.
- **Standing autonomy / reuse affordances** ("approve and don't ask again"), and the decision-history
  suggestion loop that would feed them.
- **The native Apple app as a gating deliverable.** It is M7, in parallel, by decision (d)(1).
