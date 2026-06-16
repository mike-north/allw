# allw — On-Device Decision History (post-v1)

**CEO roadmap Decision 7.** The first half of the decision-history flywheel: a learning loop that turns the
user's own past approvals into better future governance — without anything sensitive ever leaving the device.

This document is the **design** for that store. It is post-v1 (issue #134, under epic #136) and intentionally
**design-first**: the reflection engine, the retention UI, and the egress half (tallies, #135 / Decision 8) are
scoped as follow-ups (§Follow-ups). What lands here is the shape of the store, its lifecycle, the reflection
contract, and the privacy boundary — pinned in `docs/` before code, as the repo requires.

Companion to [contract.md](./contract.md) (the verdict/audit artifacts this consumes),
[policy-seam.md](./policy-seam.md) (the `ActionRecord` structure/data split this inherits),
[threat-model.md](./threat-model.md) (the structure-not-data invariant, Security Goal 8 / R7), and
[architecture.md](./architecture.md) (the one-audited-core / WASM-local constraints the store must honor).

---

## Why this exists (the flywheel)

A static gate that just forwards each permission request never improves — the user answers the same prompt
forever. The product thesis ([positioning.md](./positioning.md)) is the opposite: an envelope of autonomy that
**widens over time by your own decisions**. That requires a memory of what you decided and a pass that learns
from it.

The decision-history flywheel has two halves:

| Half                         | What it is                                                                        | Owner              |
| ---------------------------- | --------------------------------------------------------------------------------- | ------------------ |
| **Raw history + reflection** | The on-device ephemeral store of recent decisions, consumed by a learning pass.   | **this doc, #134** |
| **Tallies**                  | The aggregate, recognized-only counts that may leave the device (the only egress) | #135 / Decision 8  |

The raw history **never leaves the device.** Tallies are the only sanctioned aggregate egress, and even those are
recognized-only (#135). This doc owns everything before that boundary; it hands the reflection pass's aggregate
output to the tallies mechanism and stops there.

---

## Invariants (what this store must never violate)

These are not new invariants — they are the existing contract invariants applied to a local store.

1. **Structure-not-data (hard floor).** A decision-history entry records the **structure** the human acted on —
   the surface kind, the function identity (program name for commands; server + tool for MCP calls), the session
   label, the decision, the risk, the timestamp — and the cryptographic binding (`request_hash`). It **never**
   records action **data**: arguments, parameter values, environment variable values, file contents, diffs, or
   raw command text. This is the same boundary the relay sees (Invariant 2 / threat-model R7), applied locally:
   _"remember the function, not the arguments."_ The single nuance versus the relay (§The structure-not-data
   boundary, applied locally) is the one place a product decision is needed.
2. **On-device only.** The raw store lives only on the approver device(s). It is never synced to the relay, never
   pushed off-device, never included in any envelope. The relay remains zero-knowledge; this store does not change
   that.
3. **Encrypted at rest.** The store is encrypted with the **existing `allw-core` JOSE substrate** — do not invent
   a new scheme (§Encrypted store). Plaintext entries exist only transiently in memory during reflection.
4. **Ephemeral by default; consume-and-destroy.** Entries are written when a decision resolves, consumed by the
   reflection pass, then **destroyed**. Persistence beyond reflection is **opt-in only** (§Opt-in retention).
5. **Fail-safe.** Reflection is best-effort and non-authority: it can only ever **propose** (signed policy rules
   the user accepts, anti-fatigue signals). A reflection failure, a corrupt store, or a missing key must **degrade
   to forgetting** — drop the unreadable entries, never block an approval, never silently weaken policy
   (Security Goal 6 / fail-closed). Reflection never auto-grants.

---

## What a decision-history entry is

An entry is captured when a decision **resolves** (the integrator has a verified `Verdict`, or the request hit a
fail-closed terminal state — `expired` / `aborted`). It is the smallest record that lets the reflection pass learn
"this kind of action, from this work-stream, got this decision."

```
DecisionHistoryEntry {
  record_schema_version: int          // forward-compat stamp (mirrors ActionRecord / AuditRecord)
  recorded_at:           i64          // Unix ms (UTC), device clock — when the entry was stored

  // ── identity / correlation (binding, not content) ──
  request_id:            string       // correlates to the AuditRecord; NOT a secret
  request_hash:          bytes        // b64url; the WYSIWYS binding (hash.rs). Opaque — reveals no data.

  // ── STRUCTURE ONLY (never data — see §boundary) ──
  surface:               "command" | "mcp_tool_call" | "file_edit" | …
  function_identity: {                // the structure-tier function name, parallel to action_structure
    bin?:     string                  //   command surface: program name only (e.g. "git")
    server?:  string                  //   mcp surface: server name
    tool?:    string                  //   mcp surface: tool name
    operation?: string                //   file_edit surface: op kind only (e.g. "write") — NOT paths
  }
  session_label?:        string       // the work-stream label (#133); structure, asserted-not-verified
  risk:                  "low" | "medium" | "high" | "critical"  // as shown to the human

  // ── the decision (the learning signal) ──
  decision:              "approved" | "denied" | "expired" | "aborted"
  challenge_required:    bool         // was number-match demanded? (anti-fatigue weight; no challenge value stored)

  // ── reserved (do not populate in the first cut) ──
  capabilities?:         CapabilityAction[]   // T3 semantic enrichment; null until the semantic tier exists
}
```

**Deliberately excluded** (these are **data**, and a regression that included any of them would be a privacy bug
the structure-not-data tests must catch): `argv`, `flags`, `positionals`, `cwd`, `host`, `env_refs` values,
`params` values, `paths`, `diff_summary`, `diff_hash`, `raw`, the human `note`, and the `challenge_response`
value. The reflection pass learns from _shape and outcome_, not from arguments.

> The entry stores `request_hash` (opaque) and `request_id` (a routing id), not the `ApprovalContext`. So the
> store holds **less** than the `AuditRecord` already does — the `AuditRecord` carries the full `ActionRecord`
> (with data) for the integrator's own audit trail, but that is the integrator's tamper-evident log, written and
> owned by the calling process. The decision-history store is the **approver-device** learning store and is
> strictly structure-only. (One open question, §Product decisions, is whether the two ever share storage; the
> default answer is **no** — different owners, different lifetimes, different privacy classes.)

---

## The structure-not-data boundary, applied locally

The relay's structure-not-data boundary already defines exactly which `ActionRecord` fields are **structure** and
which are **data** ([policy-seam.md](./policy-seam.md) §Structure vs. data). The decision-history store reuses
that classification verbatim: only the fields the relay is allowed to see at the default tier are eligible for an
entry, minus the ciphertext.

There is **one** place where local history could, in principle, see slightly more than the relay, and it is the
only product decision the boundary forces:

> **The device legitimately decrypts the full `ActionRecord`** to render WYSIWYS. So the device _could_ persist
> richer detail than the relay ever sees. The default position of this design is that it **must not** — the local
> store stays structure-only, identical to the relay-visible classification — because (a) the device is the
> highest-value exfiltration target if compromised/stolen (threat-model §"Lost or stolen approver device"), and a
> structure-only store has nothing argument-shaped to steal; and (b) it keeps a single, testable boundary
> definition across the whole system. The phrase in #134 — _"never raw data beyond what the device already
> holds"_ — is satisfied conservatively: the device holds the full context only transiently to render it, and the
> **persisted** history keeps none of the data.

**Product decision required** (marked clearly): a future tier could let the **paranoid/enterprise** vs **default**
privacy preference also govern local history richness (e.g. an opt-in "remember which paths I approved, locally
and encrypted, to make reflection smarter"). This design does **not** build that. If product wants
richer-than-structure local history later, it must be (1) opt-in, (2) gated by the privacy preference, (3) still
encrypted at rest, and (4) covered by an explicit boundary test. Until that decision is made, **structure-only is
the floor.** See §Product decisions.

---

## Encrypted store (reuse core crypto — do not invent)

The store reuses the **existing `allw-core` JOSE substrate** (`crates/allw-core/src/jwe.rs`,
`crates/allw-core/src/crypto.rs`) — the same JWE/X25519 + JWS/Ed25519 layer shared with vaultkeeper. No new
cipher, no new KDF, no new key.

- **Encryption.** Each entry (or a small batch) is serialized to canonical JSON and encrypted as a **JWE**
  (`enc = "A256GCM"`, CEK wrapped with `ECDH-ES+A256KW` to the device's X25519 key) — exactly the
  `encrypt_context` / `decrypt_context` path already used for `ApprovalContext` ciphertext. The recipient is the
  **device's own** key (single-recipient): the store is encrypted to the device, decryptable only on the device,
  using hardware-backed key release where available (Secure Enclave / StrongBox, [architecture.md](./architecture.md)).
- **Why JWE and not a bespoke "local DB encryption."** One audited crypto implementation is a hard architecture
  rule. The store inherits the same authenticated-encryption guarantees, the same key handling, and the same
  cross-surface (WASM/UniFFI) availability as the rest of the core, with zero new crypto to review.
- **Storage medium is a surface concern.** Where the encrypted blob(s) live — a file under the app's container, a
  platform secure-storage row, IndexedDB for the web/PWA surface — is per-platform and out of scope for this core
  design. The contract is: **only JWE ciphertext is ever written to durable storage; plaintext exists only in
  memory during a reflection pass and is zeroized after.**
- **Key rotation / device revocation.** Because the store is encrypted to the device key, a rotated or revoked
  device's old store is simply unreadable and is discarded — consistent with fail-safe (forget on unreadable) and
  with enrollment's revocation semantics ([enrollment.md](./enrollment.md)). No cross-device store migration is in
  scope.

---

## Ephemerality & consume-and-destroy

The store is a **short bounded queue**, not a log:

1. **Write on resolve.** When a decision resolves, the integrator/app appends a structure-only
   `DecisionHistoryEntry` (encrypted) to the device's pending-reflection queue.
2. **Consume on reflect.** The reflection pass reads the pending entries, derives learning signal (§Reflection),
   and emits its outputs (proposed signed rules / anti-fatigue signal / the aggregate handed to tallies).
3. **Destroy after consume.** Once an entry has been incorporated into reflection output, it is **deleted** —
   the ciphertext is removed from storage. Consume-and-destroy is the default: the raw history is transient
   working material for the learning pass, not a durable record.
4. **Bound the queue.** Independent of reflection cadence, the pending queue has a hard cap (count and/or age,
   §Product decisions) so an unreflected backlog can never grow without bound. Overflow drops **oldest-first**
   (fail-safe: losing old history weakens future learning slightly; it never weakens a gate).

The durable record of _what was decided_ remains the integrator's `AuditRecord` chain (contract.md) — that is the
tamper-evident audit log and is unaffected. Decision history is explicitly **not** that log; it is ephemeral
learning fuel.

---

## The reflection pass

Reflection is the on-device learning step that **consumes** pending history and **produces** governance signal.
It runs entirely on-device (no data leaves; threat-model §"The reflection pass runs on-device").

### What it consumes

The pending `DecisionHistoryEntry` queue (structure-only, decrypted transiently).

### What it produces

Reflection only ever **proposes** — it never changes authority on its own (fail-safe, Invariant 5):

1. **Proposed policy rules** for the user to accept — e.g. "you approved `git status` from this work-stream 20
   times with no challenge; create an `allow` rule?" The rule, if accepted, is a **signed `PolicyRule`**
   ([policy-seam.md](./policy-seam.md) §approval→rule bridge), exactly as the existing "approve & don't ask again"
   affordance produces — reflection just surfaces the candidate. It never mints a rule unilaterally.
2. **Anti-fatigue signal** — surfaces where the human is rubber-stamping (high approve rate, low dwell, repeated
   challenges) so the UX can adapt (batch, reorder, or escalate visibility). This is local UX state, not authority.
3. **The aggregate handed to tallies (#135).** Reflection computes per-recognized-tool counts; the **tallies**
   mechanism (Decision 8) owns whether/how those leave the device (recognized-only, aggregate-only, with consent).
   This doc produces the aggregate; #135 owns the egress and the recognized-tool registry. **No raw entry crosses
   that hand-off** — only counts of recognized surfaces.

After producing these, reflection **destroys** the consumed entries (§Ephemerality).

### When it runs — the carried open question, with a proposed default

The carried open question (#134, epic #136) is _when_ consume-and-destroy reflection runs. The candidates raised
were: **on resolve** (per-decision), **batched** (periodic), or **on app foreground**. Proposed default:

> **Reflect on app foreground (with a short debounce), plus a hard backstop on queue pressure.** Concretely:
> when the approver app comes to the foreground, if there are pending entries and at least _D_ has elapsed since
> the last reflection (debounce, e.g. 5 min — tunable), run reflection on the pending queue. Independently, if the
> pending queue reaches its cap (count/age, §Product decisions), reflect immediately regardless of foreground
> state (the backstop that keeps the queue bounded).

**Why this default (and why it is fail-safe):**

- **On-resolve is too eager.** Decisions resolve in bursts (an agent fires several gated actions in a row);
  reflecting per-resolve would run a learning pass on a sample of one and could surface a rule proposal mid-flow,
  which is exactly the wrong moment (the user is busy approving, not curating policy). It also does the most work
  on the hot path.
- **Pure background batching is fragile on mobile.** The hero surface is a mobile app ([architecture.md](./architecture.md));
  iOS/Android background execution is throttled and unreliable, so a timer-only design would reflect erratically.
- **Foreground is the natural, fail-safe trigger.** The user is present, the device is unlocked (so the
  hardware-backed key needed to decrypt the store is releasable — Secure Enclave/StrongBox biometric gating), and
  surfacing a rule proposal "next time you open the app" is the right UX moment. If the app is never opened,
  nothing reflects and nothing is destroyed — the queue simply stays encrypted at rest until the cap backstop
  fires or the app is opened. That is fail-safe: the failure mode is _more remembering, not less governance_, and
  never an auto-grant.
- **The cap backstop bounds memory** independent of user behavior, so "never opens the app" cannot grow the queue
  unbounded.

This is a **proposed default, not a locked decision** — it is the carried open question and is presented as a
product/CEO decision in §Product decisions, with the alternatives (on-resolve / pure-batched) and their trade-offs
recorded above so the decision can be made without re-deriving them. The design does not depend on which trigger
is chosen: all three produce the same structure-only consume-and-destroy semantics; only the cadence differs.

---

## Opt-in retention (the only persistence)

By default the raw history is consume-and-destroy (§Ephemerality). The **only** way it persists is an explicit,
user-controlled **opt-in retention** setting:

- **Default = off.** With retention off, entries are destroyed after reflection. Nothing accumulates.
- **When on,** consumed entries are kept (still encrypted, still on-device, still structure-only) up to a
  user-chosen bound (e.g. "keep 30 days" / "keep last N"). Retention extends how long the _raw_ structure-only
  history lives locally; it does **not** change the structure-not-data boundary, does **not** enable any egress,
  and does **not** make retained history leave the device. Tallies (#135) remain the only egress regardless of
  this setting.
- **User-erasable.** The user can clear retained history at any time (a "forget" control). Clearing deletes the
  ciphertext.

Retention is a convenience for users who want a longer local history to browse or to give reflection a larger
window; it is never a default and never an egress path.

---

## Threat-model fit

The store sits **inside** the approver-device trust boundary (threat-model §Trust Boundaries) and adds no new
relay or network surface. Mapped to the existing model:

- **Lost/stolen device** — the highest-value risk for any on-device store. Mitigated by (a) JWE-at-rest encrypted
  to the hardware-backed device key, and (b) the structure-only floor: even a fully decrypted store reveals
  _which functions were approved_, never _with what arguments_. There is nothing argument-shaped to exfiltrate.
- **Compromised relay / network** — unaffected: the raw history never crosses the relay boundary; only #135
  tallies (recognized-only, aggregate-only, with consent) ever leave, and that egress is #135's to harden.
- **Malicious/compromised app on a verified machine** — reflection only proposes; it cannot auto-grant. A bad
  reflection output is a _proposed_ rule the human must still accept and sign, so it cannot silently widen policy.
- **Corrupt/unreadable store** — fail-safe: drop and forget, never block an approval.

A short structure-not-data review note should be added to [threat-model.md](./threat-model.md) when the store is
implemented (the R7 boundary now has a second enforcement site: the local history writer, not just the envelope
builder). That doc update is part of the implementation follow-up, not this design PR, so the two land together
with the code.

---

## Optional core scaffolding in this PR

The primary deliverable is this design. The implementation (the store, the reflection engine, the UI, the
retention setting) is **explicitly out of scope** here. If a small, self-contained typed record shape is included
alongside this doc, it is **only** the forward-compat scaffolding — the `DecisionHistoryEntry` shape and its
structure-only serialization — mirroring how `policy-seam.md`'s "cheap now, painful later" fields were reserved in
`allw-core` v1. No reflection logic, no storage, no crypto wiring, no surface bindings are built here.

---

## Follow-ups (scoped out of this design PR)

- **Reflection engine** — the actual consume → derive → propose → destroy implementation (post-doc; gated on the
  reflection-timing product decision below).
- **Encrypted store + storage medium** — wiring the JWE-at-rest store and the per-platform durable storage.
- **Retention setting + "forget" UI** — the opt-in retention control and history-clearing affordance.
- **Tallies hand-off (#135 / Decision 8)** — the aggregate egress and recognized-tool registry; reflection
  produces the aggregate, #135 owns the boundary.
- **threat-model.md R7 update** — record the local history writer as a second structure-not-data enforcement site
  (lands with the store implementation).

## Product decisions (need PM/CEO sign-off)

1. **Reflection-timing trigger** _(the carried open question)_ — proposed default: **foreground + debounce, with a
   queue-cap backstop** (§Reflection §When it runs). Alternatives recorded: on-resolve (too eager / hot-path),
   pure-batched (fragile on mobile). **Decision needed:** accept the proposed default or pick an alternative.
2. **Local history richness vs. the privacy preference** — proposed default: **structure-only floor, always**
   (§The structure-not-data boundary, applied locally). **Decision needed:** confirm structure-only is the
   permanent floor, or greenlight a future opt-in, preference-gated, encrypted "richer local history" tier (which
   would still never egress).
3. **Queue cap + retention defaults** — the concrete numbers (pending-queue count/age cap; default retention
   window when opt-in is on; debounce interval _D_). Proposed starting points: debounce 5 min; pending cap a small
   bounded count or 24–48h age; retention default 30 days when enabled. **Decision needed:** confirm or adjust;
   these are tunable and not load-bearing on the design.
4. **Shared vs. separate storage with the `AuditRecord` chain** — proposed default: **separate** (different owner,
   lifetime, and privacy class; §What a decision-history entry is). **Decision needed:** confirm separation.
