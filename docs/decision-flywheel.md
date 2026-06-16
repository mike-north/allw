# allw — Decision-History Flywheel: Recognized-Tool Tallies

**Scope:** the design of **recognized-tool tallies** — the **only sanctioned data egress** from a user's device
(CEO roadmap Decision 8). This document defines, precisely, what _aggregate-only, recognized-only_ means; how
tallies are aggregated on-device; where the **recognized-tool registry** boundary sits (deferred to the semantic
policy tier — we design the _seam_, not the engine); and the **transport + consent** model that governs whether
anything leaves at all.

Companion to [policy-seam.md](./policy-seam.md) (the semantic / capability tier that owns "recognized"),
[contract.md](./contract.md) (Invariant 2, structure-not-data), [threat-model.md](./threat-model.md)
(Security Goal 8, R7), and [positioning.md](./positioning.md) (the convergence-on-autonomy thesis the flywheel
serves).

> **Status: design-first.** This document is the design. It does **not** authorize building an egress mechanism,
> a tally uploader, or the recognized-tool registry engine. The transport + consent model below is presented as a
> **recommendation plus options for sign-off** — it is a privacy/product decision, not an engineering default. The
> default until sign-off is the fail-closed one: **nothing leaves the device.**

---

## The flywheel (and the two halves)

allw's moat is convergence: a new tool starts at a safe coarse default, and the autonomy boundary **widens from
the user's own real decisions** ([positioning.md](./positioning.md) §"you converge on autonomy"). That requires a
**decision-history flywheel**, split across two issues so the privacy line is unambiguous:

| Half                                     | What it is                                                                                                       | Where it lives                                  | Issue                                                 |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ----------------------------------------------------- |
| **Decision history** (Decision 7)        | On-device, encrypted, **ephemeral** record of recent approvals; consumed by a reflection pass, then destroyed.   | **Never leaves the device.**                    | [#134](https://github.com/mike-north/allw/issues/134) |
| **Recognized-tool tallies** (Decision 8) | **Aggregate counts of recognized tools** — the durable aggregate that **may** leave the device, recognized-only. | The **only** sanctioned egress (this document). | [#135](https://github.com/mike-north/allw/issues/135) |

This document owns the **tallies** half only. The raw on-device history, the reflection/consume-and-destroy
engine, and its timing are owned by [#134](https://github.com/mike-north/allw/issues/134); this design treats that
history as an upstream source it reads from, and does not redefine it.

The hard rule between the halves: **the raw history never leaves; tallies are the only thing that can, and even
those are recognized-only.** A tally is the _residue_ of a reflection pass — a count, not a record.

---

## The egress floor (what `aggregate-only, recognized-only` means, precisely)

Three independent gates compose. **All three must hold** for any byte to be eligible to leave. Each is
fail-closed: when in doubt, the datum stays on the device.

### Gate 1 — Aggregate-only (no per-event records)

What may leave is a **count over a window**, never an individual decision. A tally entry is at most:

```
{ tool_identity, decision_class, count }   // e.g. { "git", "approved", 42 }
```

- **`tool_identity`** is **structure only** — the function identity already defined by the structure-not-data
  invariant: a command's **program name** (`syntactic.bin`), or an MCP call's **(server, tool)** pair
  ([policy-seam.md](./policy-seam.md) §"Structure vs. data", [contract.md](./contract.md) Invariant 2). It is
  **never** arguments, parameter values, flags, paths, env, cwd, or `raw`. Tallies are counts of _recognized
  surfaces_, not data ([#135](https://github.com/mike-north/allw/issues/135) constraint; Decision 6 floor #131).
- **`decision_class`** is a coarse outcome bucket — `approved` / `denied` / `expired` — derived from the verdict
  `decision` ([contract.md](./contract.md) §Verdict). It carries no `note`, no timestamps, no `request_hash`, no
  challenge state.
- **`count`** is an integer over the aggregation window.

Explicitly **never** in a tally: any per-decision identifier, timestamp, ordering, session label, actor identity,
or anything from which an individual decision could be reconstructed or correlated. A tally is a histogram, not a
log.

> **Why aggregate, not events:** an event stream — even structure-only — leaks _timing and sequence_, which is
> behavioural data ("they approved a deploy at 2am, then three deletes"). A histogram over a window collapses that
> to frequency, which is the only signal the flywheel needs. The aggregate boundary is the privacy boundary, not
> an optimization.

### Gate 2 — Recognized-only (the unrecognized never appears, not even as "other")

A tally entry exists **only for a recognized tool**. Counts of **unrecognized** tools are **excluded entirely** —
they are not bucketed, not summed into an `"other"` total, not reported as a residual, and their **cardinality is
not reported**.

This is stricter than "anonymize the unrecognized" on purpose. An `"other": N` bucket would leak:

- that the user runs tools outside the recognized set (existence),
- how many distinct such tools / how often (cardinality and volume),

both of which are exactly the private "what unusual things does this person run" signal the recognized-only rule
exists to keep on-device. So:

> **The unrecognized are invisible to egress — including the fact that they exist.** A device that only ever ran
> unrecognized tools emits a tally indistinguishable from a device that ran nothing.

The recognized set is defined by the **recognized-tool registry** (next section). Until a tool is recognized by
that registry, it contributes to nothing that can leave.

### Gate 3 — Consent (nothing leaves without explicit, fail-closed consent)

Even a perfectly aggregate, recognized-only tally **does not leave** unless the user has explicitly consented to
tally egress. Absent consent, tallies are computed-and-kept-local (or not computed at all — see Transport &
Consent below). **Default = nothing leaves.** This gate is detailed in §"Transport & consent".

---

## On-device tally aggregation

Aggregation runs **entirely on-device**, in the same audited core that enforces the structure-not-data boundary
(WASM/native client) — never on the relay, never in a surface that could forward raw data
([architecture.md](./architecture.md) §"Structure-not-data boundary").

The pipeline reads from the ephemeral decision history (#134) and produces a tally:

```
ephemeral decision history (#134, on-device, encrypted)
        │  reflection pass consumes recent decisions (#134 owns timing)
        ▼
  for each consumed decision:
        tool_identity ← structure-only function identity (bin | server+tool)
        recognized?   ← registry.is_recognized(tool_identity)        // SEAM — see below
        if not recognized: DROP  (contributes to nothing; Gate 2)
        else: bucket[(tool_identity, decision_class)] += 1
        ▼
  tally = { entries: [ {tool_identity, decision_class, count}, … ], window }
        ▼
  (consent gate) ──► egress  | local-only  | discard      // Gate 3 — see Transport & Consent
```

Properties this pipeline must hold (all fail-closed):

1. **Structure-only input.** The aggregator only ever reads the function-identity (structure) fields of an
   `ActionRecord`. It must not read `argv`, `flags`, `positionals`, `params`, `paths`, `env_refs`, `cwd`, or
   `raw`. (Same data/structure split the envelope construction already enforces — reuse it, don't re-derive it.)
2. **Recognized filter before bucketing.** Unrecognized identities are dropped _before_ they reach any counter,
   so there is no in-memory `"other"` accumulator that a bug could later emit (Gate 2 is enforced structurally,
   not by remembering to redact at the end).
3. **No cross-window correlation.** A tally is a single window's histogram. The design does not maintain a
   per-tool durable timeline that could be diffed across windows to reconstruct timing.
4. **Idempotent w.r.t. consume-and-destroy.** Because #134's history is consume-and-destroy, a decision is tallied
   exactly once; the tally is the durable residue and the raw decision is then destroyed (#134). Tallies must not
   require re-reading destroyed history.

The tally's **window** is a coarse period (e.g. a release-train week), not a timestamp range tied to specific
events — it exists to make counts comparable, not to localize behaviour in time. Exact window granularity is a
follow-up tuning question; it must be coarse enough that the window itself is not a timing signal.

---

## The recognized-tool registry boundary (the seam — deferred to the semantic tier)

**"Recognized" is a semantic notion, and the semantic tier is deferred.** This design must therefore _use_ a
recognized-tool concept without _building_ it.

### Where "recognized" belongs

The recognized-tool registry is part of the **semantic / capability (T3) tier** in
[policy-seam.md](./policy-seam.md) §"The three tiers" — the deferred north star that reuses the **AgentRC / Arc
Flow** capability model rather than inventing its own. Knowing that `git` / `kubectl` / a given MCP `(server,
tool)` is a _recognized, classifiable_ tool is the same knowledge that capability inference needs; it rides on the
same per-command schema DB / capability catalog. Per CLAUDE.md and policy-seam.md, **capability inference and the
schema DB are not built in v1 and not built here.**

> **Hard bound (do not cross):** this document defines the tally model _assuming a recognized-tool predicate
> exists_, and defines the **seam** the predicate plugs into. It does **not** implement the registry, capability
> inference, a schema DB, or any doc-extraction/classification pipeline. Those remain the deferred T3 engine
> ([policy-seam.md](./policy-seam.md) §"Explicitly out of scope"). Building any of them is out of scope for #135.

### The seam (design the interface, stub the engine)

The aggregator depends on a single, narrow predicate over **structure only**:

```
is_recognized(tool_identity) -> bool
        // tool_identity = command program name | MCP (server, tool) pair  — structure only
        // returns true iff this tool is in the recognized-tool registry (T3-owned)
```

This is the entire surface the tally feature needs from the semantic tier. It is deliberately:

- **Structure-only in / boolean out.** It takes function identity (the same structure the relay may already see),
  never data; it returns a yes/no, never a capability, scope, or classification. The tally feature learns _whether_
  a tool is recognized, never _what it means_ — so adopting it does not pull capability inference forward.
- **Defaulting to `false` (fail-closed for privacy).** Until the T3 registry exists, the **v1 stub returns
  `false` for everything.** Consequence, by construction: with the stub, **every** tool is unrecognized, so
  **every** tally is empty, so **nothing is ever eligible to leave** — regardless of the consent gate. The egress
  path is inert until both (a) the registry lands in the semantic tier and (b) consent is granted. This is the
  desired safe state: the privacy-critical egress cannot accidentally turn on before the thing that defines
  "recognized" exists.
- **A strict-superset upgrade.** When T3 lands, `is_recognized` is backed by the real registry with **no change to
  the tally model or wire shape** — exactly the forward-compat discipline the policy seam already uses for the
  reserved `capabilities`/`scope` fields ([policy-seam.md](./policy-seam.md) §"Forward-compat requirements").

What the seam must **not** become: a back door for capability data. `is_recognized` returns a boolean and nothing
else; it must never be widened to return capabilities, scope, or any classification that would constitute building
the T3 engine under another name.

---

## Transport & consent (the carried open question — recommendation + options for sign-off)

> **This is the privacy/CEO decision** carried open in the roadmap epic
> ([#136](https://github.com/mike-north/allw/issues/136): "Tally transport & consent — how recognized-tool
> tallies leave the device"). It is presented here for **sign-off**, not baked in. **No egress mechanism is
> authorized by this document.** The fail-closed default stands until a decision is signed off: **nothing leaves
> the device.**

### Non-negotiable invariants (independent of which option is chosen)

Whatever transport is chosen MUST satisfy all of these — they are derived from the contract, not up for debate:

1. **Fail-closed default.** Egress is **off** unless the user has explicitly opted in. No silent default-on, no
   pre-checked box, no "telemetry on by default." Absent a signed consent decision, tallies do not leave.
2. **Recognized-only + aggregate-only at the source.** The three gates above are applied **on-device before
   transport**, so the transport never has the opportunity to carry data or unrecognized counts even if it is
   compromised — the same on-device-enforcement principle as the structure-not-data boundary
   ([threat-model.md](./threat-model.md) §R7).
3. **Consistent with structure-not-data.** A tally is structure (function identity) + a count. It contains no
   action data, so it does not loosen Invariant 2; it is a strictly smaller disclosure than what the relay already
   sees at the default tier (function identity per request), collapsed to frequency.
4. **Inspectable before it leaves.** The user can see exactly what a tally contains (it is a short histogram of
   recognized tool names + counts) — consent is meaningful only if the payload is legible.
5. **Revocable.** Consent can be withdrawn; withdrawal stops future egress. (Already-sent aggregates cannot be
   recalled — consent copy must say so.)
6. **Off by the same kill-switch as the registry stub.** Because the v1 `is_recognized` stub yields empty tallies,
   egress is inert regardless; the consent gate is the _second_ independent lock, not the only one.

### Recommendation

**Recommended: Option A — explicit opt-in, user-inspectable, via the existing zero-knowledge relay as an
_aggregate_ channel distinct from approval routing; built only after the T3 registry exists.**

Rationale:

- The relay is already the device's trusted-but-zero-knowledge egress point; adding an **aggregate tally channel**
  (separate endpoint, clearly not approval traffic) avoids introducing a _new_ network destination the user must
  trust, and keeps the "one relay" mental model.
- Crucially, a tally is **less** than the relay already sees: at the default tier the relay observes per-request
  function identity ([contract.md](./contract.md) §Roles); a consented tally is that same structure collapsed to
  counts over a window — strictly less granular. So Option A discloses nothing the relay couldn't already infer
  from routing, only in a form the _product_ (not just the relay operator) can use for the flywheel.
- It inherits the relay's existing auth/enrollment and the audited on-device enforcement point.
- It is the smallest new surface that still enables the flywheel.

**Sequencing (firm):** even under Option A, **do not build the channel until the recognized-tool registry exists**
(the stub makes it inert anyway) **and** consent UX is signed off. #135 ships the _design_; implementation is
gated on T3 + this sign-off.

### Options for sign-off (the CEO/privacy decision space)

| Option                                               | Transport                                                                                                                                      | Consent model                                                                    | Trade-off                                                                                                                                                          |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **A — relay aggregate channel** _(recommended)_      | Aggregate tallies sent over the existing zero-knowledge relay on a **distinct, non-approval** endpoint.                                        | Explicit per-account opt-in; inspectable payload; revocable.                     | Reuses trusted relay & enrollment; smallest new surface. Relay operator sees aggregate structure (≤ what routing already shows).                                   |
| **B — local-only, never egress (most conservative)** | **No egress at all.** Tallies are computed on-device and feed only the local flywheel/reflection.                                              | No egress consent needed — there is no egress.                                   | Maximally private; forecloses any network-level / cross-user product learning from tallies. Decision 8's "only sanctioned egress" becomes "no egress in practice." |
| **C — dedicated aggregate-telemetry endpoint**       | A separate, purpose-built telemetry service (not the relay), receiving only aggregate recognized-only tallies.                                 | Explicit opt-in; inspectable; revocable; separate trust decision from the relay. | Cleanest separation of "approval routing" from "product telemetry"; but introduces a _new_ destination the user must trust and a new service to operate/secure.    |
| **D — user-exported, user-pushed**                   | The device produces a signed aggregate the **user** chooses to share (e.g. export, or attach to a support/feedback flow). No automatic egress. | Consent is the act of sharing itself.                                            | Strongest user agency; lowest product yield (sporadic, self-selected); good fallback / complement to A.                                                            |

A defensible default if the CEO wants the conservative posture now and optionality later: **ship B (local-only)**
and treat A as the opt-in upgrade once the flywheel proves it needs network-level signal — both are reachable from
this same design without changing the tally model. The choice does not affect any code in #135 (which builds
neither), only what a future implementation issue targets.

---

## What this design does **not** authorize (scope fence)

- **No egress mechanism / uploader / telemetry channel** is built by #135. The transport options above are for
  sign-off; the default is "nothing leaves."
- **No recognized-tool registry, capability inference, schema DB, or classification pipeline.** Those are the
  deferred T3 engine ([policy-seam.md](./policy-seam.md)); #135 designs only the `is_recognized` **seam** and
  ships a `false`-returning stub.
- **No new wire/contract types are added to `allw-core` here.** When implementation is greenlit, the tally type
  and (if Option A/C) the aggregate channel get their own issue; this document is the spec they implement against.

---

## Open questions (carried to the roadmap epic, [#136](https://github.com/mike-north/allw/issues/136))

- **Transport + consent decision (the big one):** which of Options A–D, and the exact consent copy/UX. Blocks any
  implementation issue. _(This is the sign-off ask.)_
- **Aggregation window granularity:** how coarse the tally window is (week? release train?) — must stay coarse
  enough to not be a timing signal.
- **Reflection-engine timing** (owned by [#134](https://github.com/mike-north/allw/issues/134)): when
  consume-and-destroy runs determines when tallies are produced; cross-referenced, not decided here.
- **Registry residence** (owned by the T3 tier, [policy-seam.md](./policy-seam.md) §"Open questions"): where the
  recognized-tool registry lives and how it is distributed — out of scope for #135.
