# HITL seam: a layered policy and human-decision contract

**Status:** proposed public contract, version 0.1. This document is the design deliverable for
[#218](https://github.com/mike-north/allw/issues/218); no package implementation is authorized by
this specification PR.

This document specifies a provider-agnostic TypeScript boundary for programs that evaluate policy,
seek a human decision, or offer a standing-policy change alongside that decision. It extracts the
working contract in macts rather than making allw's wire format universal. allw is one provider of
the boundary, not a dependency of it.

The key design property is **layered adoptability**. A caller can adopt human decisions without a
policy engine, or policy evaluation without an approver. Later layers compose those two leaves; the
leaves never depend on the composition.

Companion reading:

- [contract.md](./contract.md) defines allw's one-shot, fail-closed approval primitive.
- [policy-seam.md](./policy-seam.md) defines allw's syntactic-first policy layer.
- [hitl-seam-decisions.md](./hitl-seam-decisions.md) records the choices and rejected alternatives
  behind this contract.

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative in the sense of
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 1. Scope and safety model

The seam standardizes four **contract roles**. They are roles, not modules: a host adopts one, some,
or all of them by choosing which optional adapters it passes to a single `createGate(...)` (§2.1).

| Role                | Standalone use case                                           | Vocabulary                                       | Adopted by                      |
| ------------------- | ------------------------------------------------------------- | ------------------------------------------------ | ------------------------------- |
| **L0 — decision**   | Ask a human about an operation, with no policy engine         | `approved \| rejected \| timeout`                | `hitl` alone                    |
| **L1 — policy**     | Evaluate policy without ever asking a human                   | `allow \| deny` (terminal), `ask`                | `policy` alone                  |
| **L2 — escalation** | Invoke a provider when, and only when, policy asks            | the gate's `satisfied \| unsatisfied` + failure  | `policy` + `hitl`               |
| **L3 — change**     | Negotiate a host-authored standing-policy change with a human | host-authored options and drafts; choice or edit | `policyChanges`, with the above |

The contract is an **enforcement input**, never an ambient-authority grant. A caller still owns the
final conjunction:

```text
L0 only: effective_allow = ambient_authority ∧ human_approved ∧ evidence_accepted ∧ other_gates

L1 only: effective_allow = ambient_authority ∧ policy_allows ∧ other_gates

L2:      policy_gate = policy_allows
                        ∨ (policy_asks ∧ all_requirements_approved_and_evidence_accepted)
         effective_allow = ambient_authority ∧ policy_gate ∧ other_gates
```

`evidence_accepted` is `true` when the host does not require provider evidence. If it does require
evidence, the provider adapter or host verifier MUST validate it before treating an `approved`
decision as a satisfied human gate.

For L2, `all_requirements_approved_and_evidence_accepted` is true only when every distinct
conjunctive approval requirement has an `approved` decision and any evidence required for that
specific result has been accepted. Approving one authority never substitutes for the remaining ones.

A satisfied `GateResult` computes the `policy_gate` term above and nothing else. It is not
`effective_allow`: the host still owns `ambient_authority` and every other gate.

An L3 change is absent from all three formulas. It can affect only a later evaluation, after the
host has independently prepared and applied it through its normal policy path.

### 1.1 Non-goals

This package does not define:

- an allw, macts, Claude Code, Codex, OpenClaw, OPA, Cedar, or XACML wire format;
- a universal action, risk, identity, policy, selector, or capability language;
- semantic capability inference or allw's deferred T3 tier;
- cryptography, evidence verification, transport, storage, audit persistence, or UI;
- a durable approval token or a way to reuse a one-shot human decision; or
- a policy mutation API that bypasses a host's own parser, validator, store, and audit path.

The package MUST have zero runtime dependencies, MUST use plain TypeScript/JavaScript values, and
MUST contain no native binary or Node-only filesystem, network, or crypto dependency. An allw
adapter keeps signed verdicts and signed policy rules behind the opaque `evidence` field.

---

## 2. Package and dependency layout

**Decided (2026-08-25):** the package is the unscoped **`hitl-policy`**, published from the
standalone repo [github.com/mike-north/hitl-policy](https://github.com/mike-north/hitl-policy).
allw [#218](https://github.com/mike-north/allw/issues/218) remains the allw-side tracking anchor;
the contract itself does not live in this repo.

The earlier recommendation was a scoped `@allw/hitl-seam`, on the argument that an owned scope gives
clear provenance and forecloses namespace squatting on a bare name. That consideration was
**noted and overruled**: the contract is provider-neutral and is meant to be adopted by hosts with
no allw relationship, and an `@allw`-scoped name reads as an allw artifact regardless of what the
exports say. Neutrality of the dependency graph is necessary but was judged not sufficient — the
name is the first thing an adopting host sees. The standalone repo, rather than a scope, is what
carries provenance and release authority.

Operational consequence of an unscoped name: **the bare name must be claimable — or already
claimed by the owner — on npm before first publish.** Checked 2026-08-27: `hitl-policy` is
published at `0.0.0` under the maintainer `northm <michael.l.north@gmail.com>`, so the name is held
by the owner and the squatting exposure is closed for this name. Re-verify before the first real
release; if the placeholder is ever unpublished, the name becomes re-registrable by anyone.

### 2.1 Entrypoints

The package exposes **one root barrel plus a conformance subpath**:

```text
hitl-policy               the whole contract: createGate, invokeDecision, guards, types
hitl-policy/conformance   fixtures and requirement ids for adapter authors
```

Layering is **behavioral, not structural**. A host adopts layers by choosing which optional adapters
it passes to `createGate`:

```text
createGate({ policy })                      policy without ask
createGate({ hitl })                        human decision without policy
createGate({ policy, hitl })                escalation: policy asks, human answers
createGate({ policy, hitl, policyChanges }) + interactive policy modification
```

Every adapter slot is optional and independently omittable, so the adopt-in-layers requirement is
satisfied by the shape of the configuration object rather than by the shape of the module graph.

**Considered and overruled: structural entrypoints.** The earlier design split the package into five
subpaths (`/decision`, `/policy`, `/escalation`, `/suggestions`, `/conformance`) with no root barrel,
and required declaration/import-graph tests proving no upward dependency between them. The argument
was that the easiest import should not pull every layer into a consumer, and that a physical
boundary makes an accidental upward dependency a build failure rather than a review finding.

That was overruled for three reasons:

1. **Adapter optionality achieves the same adoptability with less ceremony.** A consumer that passes
   only `policy` has, observably, no HITL behavior — which is the property the split existed to
   guarantee. Enforcing it twice, once in the module graph and once in the runtime configuration,
   buys nothing the conformance requirements below do not already prove.
2. **The root-barrel cost is largely notional for a dependency-free types package.** Most of the
   surface is type-only, so it is erased entirely at build time; the runtime surface is a handful of
   guards and two functions, and tree-shaking removes what a consumer does not reference. There is
   no transitive dependency weight to keep out of a consumer's bundle, because the package has zero
   runtime dependencies.
3. **The layers are not separable in the ruled design.** Escalation is not a module that imports
   policy and decision — it is what the single gate does when both adapters are present. There is no
   longer a `/escalation` unit to give its own entrypoint.

The cost accepted with this ruling is real and worth naming: an upward dependency between contract
roles can no longer be caught by a build-time graph assertion, so role separation now rests on
review and on the adapter-optionality conformance requirements.

### 2.2 Adapter-optionality conformance requirements

Replacing the import-graph assertions, the conformance suite MUST prove that:

- **Policy-only is constructible and fully functional.** A gate configured with `policy` and no
  `hitl` reaches both terminal outcomes — a satisfied `allow` and an unsatisfied `deny` — and no
  HITL code path is exercised. The negative half MUST be asserted against a real configured
  provider spy, not against a provider that was never wired to the gate.
- **HITL-only is constructible and fully functional.** A gate configured with `hitl` and no `policy`
  reaches a satisfied result through the implicit ask path, and a gate with neither adapter fails
  closed with `hitl-unavailable` rather than defaulting open.
- **Mixed composes.** With both adapters present, a terminal policy result does not invoke HITL, and
  an `ask` does — and the resulting approval is reported as a satisfied gate, never as a policy
  `allow`.

Repo status (checked 2026-08-27): the behavior is covered by
[`test/gate.test.ts`](https://github.com/mike-north/hitl-policy/blob/main/test/gate.test.ts) —
`GATE-001`/`GATE-002` (policy-only allow/deny), `GATE-003`/`GATE-004` (HITL-only and
neither-adapter fail-closed), `GATE-005` (mixed terminal does not invoke HITL), `GATE-006` (mixed
ask invokes HITL and is not authorization) — and the entrypoint shape is asserted by
[`test/package-boundary.test.ts`](https://github.com/mike-north/hitl-policy/blob/main/test/package-boundary.test.ts),
which pins `exports` to `.` + `./conformance` and asserts the four old subpaths are absent.

Three gaps remain against the requirements above, tracked under
[#220](https://github.com/mike-north/allw/issues/220):

1. `./conformance` ships **fixtures only** — builders plus a `CONFORMANCE_REQUIREMENTS` id list. The
   assertions live in `test/`, which is not exported, so an adapter author cannot execute the
   conformance cases against their own adapter.
2. `CONFORMANCE_REQUIREMENTS` is stale relative to the suite: it lists 24 ids, while the tests also
   implement `GATE-007`–`GATE-010`, `RELOAD-007`/`008`, `RECHECK-005`–`007`, `CHANGE-009`–`014`,
   `FAIL-001`, and `ASSURE-001`/`002`.
3. `GATE-001` and `GATE-002` assert non-invocation against a `vi.fn()` that is never passed to the
   gate, so those two assertions are vacuous. `GATE-005` carries the real non-invocation proof.

---

## 3. L0 — the human-decision role

L0 is a **contract role, not a package layer.** It answers one question: **what did a human decide
about this exact request?** It is realized by `DecisionProvider`, `DecisionRequest`, and
`DecisionResult`, and a host adopts it alone by passing `hitl` to `createGate` with no `policy`
adapter.

The role carries no rule, policy-layer, policy-scope, or standing-reuse field. It does carry the one
approval obligation the gate selected — see the note on `ApprovalDecisionRequest` below.

### 3.1 Types

```ts
/** JSON-safe data accepted across Node, browser, plugin, and WASM boundaries. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/** A neutral caller identity. */
export interface CallerIdentity {
  readonly kind: string;
  readonly id: string;
  readonly displayName?: string;
}

/**
 * The request a provider presents to a human. TOperation is deliberately host-owned:
 * this package does not define a common command, MCP, capability, or selector model.
 */
export interface DecisionRequest<TOperation extends JsonValue = JsonValue> {
  readonly schemaVersion: 1;
  readonly id: string;
  readonly operationId: string;
  readonly operation: TOperation;
  readonly caller: CallerIdentity;
  /** A host-owned display label; there is no shared risk taxonomy. */
  readonly riskClass?: string;
  readonly summary: string;
  readonly requestedAtMs: number;
  readonly timeoutMs: number;
}

/** What a provider actually receives: the request plus the selected obligation. */
export interface ApprovalDecisionRequest<
  TOperation extends JsonValue = JsonValue,
> extends DecisionRequest<TOperation> {
  readonly approval: ApprovalRequirement;
  readonly policyChange?: PolicyChangeRequest;
}

export type DecisionFailure =
  | "invalid-request"
  | "provider-error"
  | "provider-unavailable"
  | "malformed-result"
  | "caller-aborted"
  | "deadline-exceeded";

export type DecisionOutcome =
  | { readonly state: "approved"; readonly reason?: string; readonly failure?: never }
  | { readonly state: "rejected"; readonly reason?: string; readonly failure?: DecisionFailure }
  | {
      readonly state: "timeout";
      readonly reason?: string;
      readonly failure?: "invalid-request" | "deadline-exceeded";
    };

export interface DecisionResult {
  readonly schemaVersion: 1;
  readonly decision: DecisionOutcome;
  /** Provider-specific proof. The seam preserves it but never interprets it. */
  readonly evidence?: unknown;
  /** L3 material, validated independently of the one-shot decision (§6). */
  readonly policyChanges?: readonly PolicyChangeResponse[];
}

export interface DecisionProvider<TOperation extends JsonValue = JsonValue> {
  readonly apiVersion: 1;
  readonly providerId: string;
  request(
    request: ApprovalDecisionRequest<TOperation>,
    context: { readonly signal: AbortSignal },
  ): Promise<DecisionResult>;
}
```

The `number` member of `JsonValue` means a finite JSON number; guards reject `NaN` and infinities.
Recursive JSON values are subject to the documented depth and size bounds in §7.

`operationId` names the operation in the host's namespace; it is not a shared policy selector.
`operation` is the provider-facing exact JSON-safe description and MAY be specialized by a host.
`riskClass` is display metadata, not a common severity ordering. An allw adapter can carry its
`ActionRecord` inside `operation`; that shape never leaks into the base package. `unknown` is
reserved for evidence the common package must not interpret.

**On `approval` in the provider request.** Every provider request carries exactly one
`ApprovalRequirement`, including in HITL-only mode: when no policy adapter is configured, the gate
synthesizes an implicit requirement (`hitl.implicitRequirement`, or
`{ authorityId: "implicit-human", approvalKey: operationId }`). This is deliberate — it gives the
provider a stable obligation identity to render and lets the post-decision recheck in §5 compare
obligations rather than re-prompting. It is an obligation identifier, not a policy rule: it carries
no effect, no scope, and no reuse semantics.

There are no provider capability flags. Routing capability is expressed by whether
`HitlAdapter.route` is supplied (§5); policy-change capability is expressed by whether a
`policyChanges` adapter is configured (§6).

### 3.2 Provider invocation contract

The implementation package MUST expose one safe invocation helper — in the repo, the exported
`invokeDecision` ([`src/callbacks.ts`](https://github.com/mike-north/hitl-policy/blob/main/src/callbacks.ts)).
Its behavior is normative:

1. Validate the standard request fields before invoking the provider.
2. Compute the absolute deadline as `requestedAtMs + timeoutMs`, reject future/unsafe timestamps,
   unsafe-integer overflow, or a timeout beyond the documented maximum, subtract elapsed time
   before invocation, and pass a child `AbortSignal` to the provider. An already-expired request
   returns `timeout` without invocation. Implementations MUST safely bound platform timer values
   rather than allowing numeric coercion to extend a deadline.
3. Treat the provider response as untrusted and validate every standard field.
4. Resolve exactly once. Abort on deadline, ignore a late result, and clear the timer after an early
   result.
5. For every execution path the helper controls, never reject to the caller. Provider
   throws/rejections become `rejected`; deadline expiry becomes `timeout`. Process termination and
   host-runtime failure remain outside an in-process JavaScript contract and MUST be documented by
   adapters at that boundary.
6. Keep provider exceptions in an operator-only diagnostic channel. They MUST NOT be copied into a
   client-safe `reason` by default.
7. Preserve `evidence` opaquely, including object identity or bytes. Generic guards MUST NOT parse,
   normalize, stringify, redact, or attest it.

Returning `approved` asserts that the provider completed the human-presence and exact-request
assurance it advertises. The generic seam cannot derive that assurance by interpreting opaque
evidence. An adapter that promises independently verifiable evidence MUST perform verification
before returning `approved`, or the host MUST place an explicit evidence-verification gate after
L0. Absence, malformation, expiry, signature failure, identity mismatch, or request-binding
mismatch in required evidence MUST NOT satisfy the human gate.

### 3.3 Normative failure table

| Input/provider condition                                                                                      | Normalized L0 state                            | May satisfy the human gate?                                        |
| ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------ |
| Well-formed explicit `approved`                                                                               | `approved`                                     | Yes, only after any required evidence verification and other gates |
| Well-formed explicit `rejected`                                                                               | `rejected`                                     | No                                                                 |
| Well-formed explicit `timeout`                                                                                | `timeout`                                      | No                                                                 |
| Provider hangs beyond the request deadline                                                                    | `timeout`; signal aborted; late result ignored | No                                                                 |
| Provider throws synchronously or rejects                                                                      | `rejected`                                     | No                                                                 |
| Provider is absent, unavailable, or cannot load                                                               | `rejected`                                     | No                                                                 |
| Response is null, primitive, missing a field, has an unknown state/version, or has a malformed standard field | `rejected`                                     | No                                                                 |
| Request has any malformed standard field other than its deadline                                              | `rejected`; provider is not invoked            | No                                                                 |
| `timeoutMs` is non-positive, non-finite, unsafe, not an integer, or exceeds the documented maximum            | `timeout`; provider is not invoked             | No                                                                 |
| `requestedAtMs` is future, non-finite, unsafe, or produces an overflowing deadline                            | `timeout`; provider is not invoked             | No                                                                 |
| Caller cancels before a terminal provider result                                                              | `rejected`; signal aborted                     | No                                                                 |
| Required evidence is absent, malformed, unverifiable, stale, for another caller/request, or revoked           | Gate `evidence-failed`                         | No                                                                 |
| Required durable audit/persistence fails after approval                                                       | Gate `audit-failed`                            | No                                                                 |

The last two rows are enforced by the gate rather than by the host: `HitlAdapter.verify` runs over
every decision record before the gate can be satisfied, and `GateConfig.audit` must return `true`.
Both failures are terminal (`gate.ts` `#verifyEvidence` / `#audit`).

The safe helper sets the corresponding negative-only `failure` category for failures it
normalizes. A provider's well-formed explicit human `rejected` or `timeout` response need not carry
one. The guard rejects `failure` on `approved`, so audit can distinguish a person's “no” from a
provider/channel failure without adding a fourth decision state.

> **Open divergence (for ruling, tracked under [#220](https://github.com/mike-north/allw/issues/220)).**
> The table's "malformed standard field other than its deadline ⇒ `rejected`" row is not what the
> repo does. `invokeDecision` first tests whether the value merely _has_ `requestedAtMs` and
> `timeoutMs` keys; if it does, any other malformed field normalizes to `timeout`/`invalid-request`
> rather than `rejected`/`invalid-request`. Both fail closed, so this is a normalization and
> audit-legibility difference, not a safety one — but it currently makes a malformed `summary`
> indistinguishable from a bad deadline. The row above remains normative pending a ruling.

Silence is never consent. A local UI provider that produces no cryptographic artifact MAY omit
`evidence`; that is an explicit host assurance choice, not a reason for the common guard to invent
proof.

### 3.4 L0 conformance cases

The shared conformance harness MUST cover explicit approval/rejection/timeout; a hung provider and
abort signal; late results; synchronous throw and rejected promise; every malformed standard field;
elapsed/expired/overflowing deadlines; timer cleanup; negative-only failure categories; exception
redaction; evidence pass-through; JSON-safe operation values; unknown additive object properties;
unknown discriminants; and unknown `schemaVersion`/`apiVersion`.

Unknown additive properties are ignored for forward compatibility. Unknown discriminants or
versions fail closed.

Repo status: covered by `test/decision-lifecycle.test.ts` and `test/guards.test.ts`, plus the
`FAIL-001` normalization case in `test/gate.test.ts`. The fixtures an adapter author needs —
`createDecisionRequestFixture`, `createApprovedDecisionFixture`, `createRejectedDecisionFixture`,
`createHungProviderFixture` — are exported from `hitl-policy/conformance`; the assertions that use
them are not (§2.2 gap 1).

---

## 4. L1 — the policy-evaluation role

L1 is a **contract role**, realized by `PolicyAdapter` and `PolicyEvaluation`. It evaluates
host-owned policy state and returns policy data. It never prompts and never suspends for a person: a
host adopts it alone by passing `policy` to `createGate` with no `hitl` adapter, and in that
configuration only the terminal `allow`/`deny` results can satisfy or refuse the gate.

### 4.1 Types

```ts
/** A terminal allow or deny returned by a host policy adapter. */
export interface TerminalPolicyEvaluation {
  readonly decision: "allow" | "deny";
  /** Whether a rule matched (`directive`) or the adapter's default applied. */
  readonly source: "directive" | "default";
  readonly reason?: string;
  /** Opaque host-local provenance which is never inspected or serialized. */
  readonly details?: unknown;
}

/** A terminal ask; the escalation role in §5 consumes it. */
export interface AskPolicyEvaluation {
  readonly decision: "ask";
  readonly requirements: readonly [ApprovalRequirement, ...ApprovalRequirement[]];
  readonly reason?: string;
  readonly details?: unknown;
}

export type PolicyEvaluation = TerminalPolicyEvaluation | AskPolicyEvaluation;

/** A validated, host-owned policy snapshot with an opaque host-issued revision. */
export interface PolicyState<TPolicy = unknown> {
  readonly revision: string;
  readonly state: TPolicy;
}

/** A successful load that intentionally removes the active policy. */
export interface AbsentPolicyState {
  readonly revision: string;
  readonly state?: undefined;
}

export type LoadedPolicyState<TPolicy = unknown> = PolicyState<TPolicy> | AbsentPolicyState;

export interface PolicyAdapter<TInput = unknown, TPolicy = unknown> {
  readonly apiVersion?: 1;
  readonly initial?: LoadedPolicyState<TPolicy>;
  load?(context: {
    readonly signal: AbortSignal;
    readonly generation: number;
  }): Promise<LoadedPolicyState<TPolicy>>;
  evaluate(
    input: TInput,
    context: {
      readonly signal: AbortSignal;
      readonly generation: number;
      readonly revision?: string;
      readonly state: TPolicy;
    },
  ): PolicyEvaluation | Promise<PolicyEvaluation>;
}
```

**There is no `no-match`.** The earlier design surfaced `no-match` as a third successful decision
that the enforcement point resolved through an explicit configured fallback. In the ruled design the
adapter resolves its own no-match internally and reports _how_ it resolved it through
`source: "directive" | "default"`. The safety property the fallback existed to guarantee — never
infer allow from the absence of a match — is preserved by construction, because an adapter that has
no applicable rule must return an explicit `allow` or `deny` and label it `default`. What is lost is
the seam's ability to enforce that the default was configured rather than assumed; that
responsibility now sits with the adapter. `source` is also what makes the distinction auditable
after the fact.

**Policy state is reloadable and versioned.** This has no counterpart in the earlier design and is
load-bearing for §5's recheck. The gate holds one immutable snapshot at a time, identified by a
monotonic `generation` and the host's opaque `revision`:

- `initial` seeds the first snapshot without I/O, so `createGate` is synchronous.
- `reload()` calls `load`, and advances `generation` only when the host's `revision` changes.
  Opaque state is never compared — the host MUST issue a new revision whenever the meaning of
  `state` changes, or the gate will treat the reload as `unchanged`.
- Snapshot replacement is a single synchronous assignment: a reader observes the complete old or the
  complete new snapshot, never a mixed revision/state pair.
- Concurrent `reload()` calls coalesce onto one in-flight operation.
- A failed reload retains the last good snapshot and returns a `failed` status; it never leaves the
  gate policy-less.

**Configured-but-broken is not the same as absent.** A gate with no `policy` adapter has no policy
and falls through to the implicit ask (§5). A gate whose configured adapter fails validation — a
bad `apiVersion`, an accessor-backed registration, a missing `evaluate` — fails with `policy-error`
rather than degrading into implicit ask. Otherwise HITL could silently replace a broken host policy
boundary.

### 4.2 Normative failure table

| Adapter condition                                                                                                  | Normalized evaluation         | Notes                                         |
| ------------------------------------------------------------------------------------------------------------------ | ----------------------------- | --------------------------------------------- |
| Well-formed `allow`                                                                                                | `allow`                       | A policy signal only; other gates still apply |
| Well-formed `deny`                                                                                                 | `deny` ⇒ gate `policy-denied` | Terminal refusal                              |
| Well-formed `ask`                                                                                                  | `ask`                         | Consumed by the escalation role (§5)          |
| Adapter absent (no `policy` configured)                                                                            | Implicit `ask`                | Absence is not allow; see §5                  |
| Configured adapter fails registration validation                                                                   | Gate `policy-error`           | Never degrades to implicit ask                |
| Throw, rejected promise, callback timeout, caller abort, transport error, or missing policy expected to load       | Gate `policy-error`           | Failure is never a successful evaluation      |
| Null, primitive, missing field, unknown decision, `allow`/`deny` without a valid `source`, or empty `requirements` | Gate `policy-error`           | Fail closed                                   |
| Policy generation changes under an in-flight evaluation more than three times                                      | Gate `policy-unstable`        | Bounded restart; see §5                       |

Evaluation never rejects to the caller, sanitizes implementation exceptions into an operator-only
diagnostic channel, and preserves host-native `details` by reference without inspecting or
serializing it.

### 4.3 L1 conformance cases

The harness MUST accept exactly `allow`, `deny`, and `ask`; require a valid `source` on the terminal
pair; reject an `ask` with an empty or malformed `requirements` array; distinguish a configured-but-
broken adapter (`policy-error`) from an absent one (implicit ask); normalize sync/async errors,
callback timeouts, and malformed output to `policy-error`; and cover the snapshot lifecycle —
generation advancing only on a revision change, a failed reload retaining the last good snapshot,
coalesced concurrent reloads, and a successful load of absent state returning the gate to implicit
ask.

Repo status: `RELOAD-001`–`RELOAD-008` in `test/gate.test.ts` and
`test/policy-state-machine.test.ts` cover the snapshot lifecycle; `GATE-010` covers a class-based
adapter with prototype-defined methods; `test/guards.test.ts` covers evaluation-shape rejection.

---

## 5. L2 — the escalation role

L2 is a **contract role**, not a module: it is what the gate does when a policy evaluation returns
`ask`. It normalizes the ask's approval obligations, invokes one L0 provider per obligation, and
re-checks policy before reporting a satisfied gate. It never turns a human decision into ambient
authorization, and it never synthesizes a policy `allow` from an approval.

### 5.1 Types

```ts
/**
 * One stable human-approval obligation emitted by a policy adapter.
 *
 * `approvalKey` identifies the exact obligation that may reuse an in-flight approval
 * after policy re-evaluation. `authorityId` keeps independent authorities conjunctive
 * even when their keys happen to match.
 */
export interface ApprovalRequirement {
  readonly authorityId: string;
  readonly approvalKey: string;
  readonly routeId?: string;
}

/** A provider route selected for one approval requirement. */
export type DecisionRoute<TOperation extends JsonValue = JsonValue> =
  | DecisionProvider<TOperation>
  | {
      readonly providerId?: string;
      request(
        request: ApprovalDecisionRequest<TOperation>,
        context: { readonly signal: AbortSignal },
      ): Promise<DecisionResult>;
    };

/** Host-owned HITL configuration. Supplying this alone is HITL-without-policy. */
export interface HitlAdapter<TOperation extends JsonValue = JsonValue> {
  /** Used when no policy adapter is configured and the gate asks implicitly. */
  readonly implicitRequirement: ApprovalRequirement;
  readonly providerId?: string;
  request(
    request: ApprovalDecisionRequest<TOperation>,
    context: { readonly signal: AbortSignal },
  ): Promise<DecisionResult>;
  route?(requirement: ApprovalRequirement): DecisionRoute<TOperation> | undefined;
  verify?(result: DecisionResult, request: ApprovalDecisionRequest): boolean | Promise<boolean>;
}

/** Policy provenance retained by a gate result. */
export type PolicyResolution =
  | (TerminalPolicyEvaluation & { readonly generation: number; readonly revision?: string })
  | (AskPolicyEvaluation & {
      /** `implicit` marks an ask the gate synthesized because no policy was configured. */
      readonly source: "directive" | "implicit";
      readonly generation: number;
      readonly revision?: string;
    });

export type GateFailure =
  | "invalid-input"
  | "policy-denied"
  | "policy-error"
  | "hitl-unavailable"
  | "route-conflict"
  | "route-unavailable"
  | "decision-rejected"
  | "decision-timeout"
  | "decision-error"
  | "malformed-decision"
  | "caller-aborted"
  | "evidence-failed"
  | "audit-failed"
  | "policy-changed"
  | "policy-unstable";

export interface SatisfiedGateResult<TOperation extends JsonValue = JsonValue> {
  readonly state: "satisfied";
  /** The detached immutable input that was actually evaluated and approved. */
  readonly input: GateInput<TOperation>;
  readonly generation: number;
  readonly revision?: string;
  readonly policy: PolicyResolution;
  readonly human?: HumanResolution;
}
```

`authorityId` is the host's canonical identity for an approval obligation; `approvalKey` identifies
the exact obligation. Two requirements coalesce only when **both** match. `routeId` is a host-owned
provider-routing label, not a closed enum. A required route with no capable provider fails closed
with `route-unavailable`; it MUST NOT silently fall back to the default provider.

Host-native `details` on a policy evaluation are retained in the gate result for audit and
explanation. They MUST NOT be copied into a provider request.

> **Removed in the ruled design: sanitized display context.** The earlier design let a host attach
> an explicitly constructed, JSON-guarded `displayContext` to the one request for a selected
> requirement. The repo has no such field: a provider sees `operation`, `summary`, `riskClass`, and
> the `approval` obligation, and nothing else. Anything a reviewer must see has to be inside
> `operation`, which is already bounded by the same JSON guard. This is a narrowing, so it is safe
> by default — but hosts that were relying on a separate presentational channel no longer have one.
> Listed for ruling under [#220](https://github.com/mike-north/allw/issues/220).

### 5.2 Requirement normalization

The earlier design specified a **multi-layer composer**: layers supplied broadest-to-narrowest, an
`allow < ask < deny` strictest-wins lattice, an exhaustive 3×3 matrix, `governingLayerId`
attribution, and full per-layer provenance retained for audit.

**That composer is not part of the ruled design.** A gate has exactly one `PolicyAdapter`, which
returns one `PolicyEvaluation`. Composing nested restriction layers — a host policy plus a per-key
policy, in the macts case — is now entirely the adapter's job, inside host-owned code, using
host-owned types. The seam composes nothing.

What survives at the seam is narrower: normalizing the requirement list carried by a single `ask`.

- The list MUST be non-empty and every element MUST be a valid `ApprovalRequirement`; otherwise
  `policy-error`.
- Two requirements coalesce only when `authorityId` **and** `approvalKey` are equal. Distinct
  authorities remain separate conjunctive obligations and MUST NOT be collapsed into one prompt.
- Within a coalescing pair, an unspecified `routeId` is compatible with one explicit `routeId`, and
  the explicit one wins. Two different explicit routes are a `route-conflict` and fail closed.
- Every surviving requirement is conjunctive: all must be approved.

The reasoning that made the old composer refuse to rank pre-evaluation declarations still holds and
now applies inside the adapter: in macts, `read-only` and `confirm-first` are incomparable before
the operation's risk is known, so an adapter MUST evaluate first and compose only terminal results.
The macts regressions that §5.5 used to require of the seam are now adapter-owned tests.

### 5.3 Escalation algorithm

Given a policy resolution:

1. `deny` ⇒ `policy-denied`. No provider is invoked.
2. `allow` ⇒ audit, then satisfied. No provider is invoked.
3. Absent policy adapter ⇒ the gate synthesizes an **implicit ask** carrying
   `hitl.implicitRequirement` (or `{ authorityId: "implicit-human", approvalKey: operationId }`),
   marked `source: "implicit"` so audit can distinguish it from a policy directive.
4. `ask` with no `hitl` adapter configured ⇒ `hitl-unavailable`. Fail closed; never allow.
5. `ask` with `hitl` ⇒ normalize requirements (§5.2), build one bounded request per requirement, and
   invoke the routed provider for each. Requests are issued concurrently and each provider is called
   at most once per requirement per `evaluate()` call.
6. Any `rejected`, `timeout`, provider failure, malformed response, or unavailable route fails the
   gate. A late approval cannot revive it.
7. If `hitl.verify` is configured, it MUST return `true` for **every** decision record; otherwise
   `evidence-failed`.
8. **Re-check policy.** The gate re-evaluates current policy after the human answers. A `deny`, or
   an `ask` whose normalized requirements are not covered by the approvals just collected, is
   `policy-changed`. Coverage requires a matching `authorityId` and `approvalKey`, plus a matching
   `routeId` when the latest requirement names one.
9. Audit (`GateConfig.audit`) MUST return `true`, or `audit-failed`.
10. Re-check the generation once more after audit; a policy reload that landed during the audit
    callback is `policy-changed`.
11. Only then is the result satisfied — and it is a satisfied **gate**, not an authorization. The
    result retains the original `ask` and the human records; it never reports a policy `allow`.

Policy evaluation is retried on a bounded loop when the snapshot generation changes underneath it:
at most three restarts, after which the gate fails `policy-unstable` rather than spinning or
evaluating against a torn snapshot.

Two things the earlier design assigned to the host are now enforced by the gate itself: the
pre-execution policy re-check (step 8) and the durable audit gate (step 9). This is a strengthening
— a host can no longer forget them — but hosts MUST still intersect ambient authority and every
other application gate before acting on a satisfied result. `Gate.isCurrent(result)` reports whether
the policy generation that produced a result is still current, using the gate-issued generation
rather than caller-mutable result fields.

### 5.4 Normative failure table

| Condition                                                                 | Result                            | Provider invoked?            |
| ------------------------------------------------------------------------- | --------------------------------- | ---------------------------- |
| Policy `allow` and audit succeeds                                         | Satisfied                         | No                           |
| Policy `deny`                                                             | `policy-denied`                   | No                           |
| Policy `ask`, no `hitl` configured                                        | `hitl-unavailable`                | No                           |
| No policy adapter, no `hitl` configured                                   | `hitl-unavailable`                | No                           |
| Invalid input, or a clock returning an unsafe value                       | `invalid-input`                   | No                           |
| Empty/malformed `requirements`, or a configured-but-broken policy adapter | `policy-error`                    | No                           |
| One authority/key pair mapped to two different explicit routes            | `route-conflict`                  | No                           |
| A requirement's route resolves to no provider, or `route` throws          | `route-unavailable`               | No for that requirement      |
| Provider returns `rejected` without a failure category                    | `decision-rejected`               | Once per requirement         |
| Provider returns `timeout`, or the deadline expires                       | `decision-timeout`                | Once per requirement         |
| Provider throws, rejects, is unavailable, or reports a failure category   | `decision-error`                  | At most once per requirement |
| Provider returns a malformed result                                       | `malformed-decision`              | Once per requirement         |
| Caller aborts before a terminal result                                    | `caller-aborted`                  | At most once per requirement |
| `hitl.verify` returns false, throws, or times out for any record          | `evidence-failed`                 | Once per requirement         |
| Re-check yields `deny`, or an `ask` the approvals do not cover            | `policy-changed`                  | Once per requirement         |
| Audit returns false, throws, or times out                                 | `audit-failed`                    | Once per requirement         |
| Generation changes during audit                                           | `policy-changed`                  | Once per requirement         |
| Generation changes under evaluation more than three times                 | `policy-unstable`                 | No                           |
| Every provider approves, verification and re-check pass, audit succeeds   | Satisfied; never an ambient grant | Once per requirement         |

`evaluate()` never rejects. Every path above resolves to a `GateResult`, and every unsatisfied
result still carries the detached input and the policy provenance that produced it.

### 5.5 L2 conformance cases

The harness MUST cover: no provider call for a terminal policy result; one call per distinct
authority/key pair; same authority/key coalescing; distinct-authority conjunction; unspecified-route
compatibility and two-explicit-route conflict; an unavailable route; the implicit-ask path and its
`source: "implicit"` marking; `hitl-unavailable` fail-closed with no adapter; every failure row
above; the post-decision re-check reaching `policy-changed` on a changed approval key without
automatically re-prompting; the bounded restart limit; and proof that host-native evaluation
`details` never cross the provider boundary.

Repo status: `GATE-001`–`GATE-010`, `FAIL-001`, `ASSURE-001`/`002`, and `RECHECK-001`–`RECHECK-007`
in `test/gate.test.ts`, plus `test/routing.test.ts` for normalization and coverage.

Two gaps against the list above, tracked under [#220](https://github.com/mike-north/allw/issues/220):

1. **Idempotency across invocations is unspecified and unimplemented.** The earlier design required
   each requirement be invoked "idempotently". The repo generates a fresh request id per
   `evaluate()` call from an internal counter, so a retried evaluation re-prompts the human for the
   same obligation. Whether cross-invocation dedupe belongs in the seam or in the host adapter needs
   a ruling.
2. No test asserts that `details` from a policy evaluation are absent from the provider request.
   The property holds by construction — `buildDecisionRequest` copies named fields only — but it is
   a stated invariant with no regression guard.

---

## 6. L3 — the policy-modification role

L3 carries a **policy change negotiation**, not a rule and not a decision. It adds no reuse field to
`DecisionOutcome`. A change can be accepted, rejected, or malformed independently of the one-shot
decision that accompanied it.

**The direction is inverted from the earlier design, and this is the most consequential part of the
ruling.** Previously the _provider_ proposed a `PolicySuggestion` — effect, target, scope, bounds —
attached to its result, and the host validated, mapped, and applied it. In the ruled design the
**host offers** the change material and the human picks or edits it:

```text
host  → PolicyChangeOffer   { options?: PolicyChangeOption[], draft?: PolicyDraft }
       ↓ carried on the request as PolicyChangeRequest
human → PolicyChangeResponse { type: "choice", optionId } | { type: "edit", draft }
       ↓ returned on DecisionResult.policyChanges
host  → prepare(response) → TModification → apply(modifications[])
```

This makes the **host-applied-only** invariant structural rather than merely normative: a provider
cannot propose a rule the host did not author, because every option and the draft's namespace and
kind originate with the host. The provider's contribution is a selection or an edit within material
the host already validated.

### 6.1 Types

```ts
/** One host-authored standing-policy choice displayed by a provider. */
export interface PolicyChangeOption {
  readonly id: string;
  readonly label: string;
  readonly description?: string;
}

/** A host-authored, namespaced editable JSON draft. */
export interface PolicyDraft {
  readonly namespace: string;
  readonly kind: string;
  readonly value: JsonValue;
  /** Human-facing only; hosts MUST NOT enforce from this string. */
  readonly display?: string;
}

/** Host-authored offer returned before a human request. */
export interface PolicyChangeOffer {
  readonly options?: readonly PolicyChangeOption[];
  readonly draft?: PolicyDraft;
}

/** Versioned change material carried to the provider on the request. */
export interface PolicyChangeRequest {
  readonly schemaVersion: 1;
  /** The policy generation this offer was authored against. */
  readonly generation: number;
  readonly options?: readonly PolicyChangeOption[];
  readonly draft?: PolicyDraft;
}

export interface PolicyChoiceResponse {
  readonly schemaVersion: 1;
  readonly type: "choice";
  readonly optionId: string;
}

export interface PolicyEditResponse {
  readonly schemaVersion: 1;
  readonly type: "edit";
  readonly draft: PolicyDraft;
}

export type PolicyChangeResponse = PolicyChoiceResponse | PolicyEditResponse;

/**
 * Host integration which validates and atomically applies policy changes.
 * TModification is deliberately opaque: the gate never interprets or persists it.
 */
export interface PolicyChangeAdapter<TInput = unknown, TModification = unknown> {
  readonly apiVersion?: 1;
  offers?(
    context: PolicyChangeContext<TInput>,
  ):
    | PolicyChangeOffer
    | readonly PolicyChangeOption[]
    | Promise<PolicyChangeOffer | readonly PolicyChangeOption[]>;
  prepare(
    change: PolicyChangeResponse,
    context: PolicyChangeContext<TInput>,
  ): TModification | Promise<TModification>;
  apply(
    modifications: readonly TModification[],
    context: PolicyChangeContext<TInput>,
  ): boolean | void | Promise<boolean | void>;
}
```

`namespace` and `kind` have meaning only inside the named host namespace; there is no universal
selector language and no common capability taxonomy. `display` is an untrusted hint and the host
SHOULD render the mapped native candidate for confirmation. The runtime guard rejects cyclic,
non-JSON, excessively deep, or excessively large draft values using the documented bounds in §7,
and caps an offer at `LIMITS.maxPolicyChangeOptions` and a response batch at
`LIMITS.maxPolicyChangeResponses` (100 each). An oversized option array is rejected on its length
alone, before any element is read.

The package provides no `applyChange` helper that installs policy itself: `prepare` and `apply` are
**host callbacks over a host-opaque modification type**. The gate orchestrates their invocation,
bounds them, and serializes `apply` against snapshot replacement, but it never inspects, persists,
or interprets a modification.

### 6.2 Non-negotiable invariants

These are unchanged in force and re-expressed against the offer model. Where the repo does not yet
enforce one, the invariant remains normative and the gap is called out.

1. **A change negotiation outcome is not a decision.** Parsing, support, mapping, persistence,
   audit, or application failure for a change MUST NOT alter the sibling one-shot result, and MUST
   NOT affect the operation currently awaiting a decision.
   _Enforced._ The provider result is validated in two passes: the decision alone, then the change
   batch. A malformed batch is discarded while the valid decision and its opaque evidence are
   retained (`callbacks.ts` `normalizeProviderResult`, `guards.ts` `hasValidDecision`). Changes are
   applied only **after** the gate result has been constructed, and a failed apply or a failed
   post-apply reload does not alter it (`gate.ts`; `CHANGE-006`, `CHANGE-008`).
2. **Host-applied only.** A change takes effect exclusively after the host recognizes its
   namespace/kind, maps it to native policy, validates it, persists and audits it, and makes it
   visible to the ordinary evaluation path. Providers do not install policy.
   _Structural._ The host authors every option and the draft envelope; the provider can only select
   or edit. `prepare` and `apply` are host code, and only an approved decision reaches them
   (`CHANGE-003`).
3. **No implicit widening.** The host, not the provider, determines whether the native before/after
   change is widening, tightening, mixed, or unknown at the target layer over the changed scope,
   even when a broader deny currently masks it. **Mixed or unknown impact MUST be handled as
   widening.**
   _Not enforced; gap._ The ruled types carry no `effect` and no impact classification, so nothing
   in the contract represents or requires this determination. A host may do it inside `prepare`,
   but the seam neither demands nor records it.
4. **Provenance may be asymmetric.** Every change requires baseline source authentication, request
   binding, and auditability. A host MAY require stronger identity, evidence, presence, or
   signatures for widening than for tightening.
   _Not enforced; gap._ `PolicyChangeResponse` carries no evidence field, so there is no place for
   change-specific provenance. The only artifact available is `DecisionResult.evidence`, which is
   the one-shot verdict — and this spec's own rule is that a one-shot verdict cannot authorize a
   standing rule. allw's separately signed `policy_rule_from_approval` artifact currently has no
   carrier.
5. **Bounds only tighten.** TTL, use caps, and time windows are conjunctive. A host that cannot
   enforce a supplied bound MUST reject the change or replace it with a strictly tighter bound; it
   MUST NOT silently discard the bound.
   _Not enforced; gap._ There is no `PolicyBounds` type. Bounds, if any, are whatever a host encodes
   inside its own `draft.value` under its own `kind`, and the seam cannot tell that a bound was
   dropped. The normative rules still stand for hosts: TTL and use caps MUST be positive safe
   integers; a TTL expires from issuance, never from a replay or retry; a time window is the
   absolute half-open interval `[startsAtMs, endsAtMs)` with `endsAtMs > startsAtMs`; recurring
   local-time/DST semantics are out of scope; a use cap MUST be consumed atomically with the native
   authorization that uses it.
6. **Future evaluation is authoritative.** Accepted policy is re-evaluated for each later operation
   through the host's native path. No one-shot result becomes a reusable bearer grant.
   _Enforced._ An applied change triggers exactly one coalesced `reload()`, and the comment on that
   path states the consequence directly: the change is visible only to future evaluations, and the
   current result retains its old policy (`gate.ts`; `CHANGE-006`).

**Closed-world guards.** `PolicyChangeOption`, `PolicyDraft`, `PolicyChangeRequest`, and
`PolicyChangeResponse` are policy-affecting records. Their guards MUST reject unknown properties, so
that an older consumer can never ignore a field that would have made the proposed change narrower. A
future constraint requires a new `schemaVersion` and a major release.
_Not enforced; gap._ The repo's guards validate the known keys and require plain data properties,
but do not reject additional ones — `{ schemaVersion: 1, type: "choice", optionId: "x", extra: 1 }`
passes `isPolicyChangeResponse`.

**Idempotency and binding.** The earlier design keyed idempotency on
`(providerId, PolicySuggestion.id)` and required a replay to return the existing state without
resetting TTL, use count, provenance, or audit history; it also required the suggestion to name its
sibling request id.
_Replaced by a different mechanism, with a residual gap._ The repo binds a change to the policy
`generation` it was offered against, and discards the batch if the generation moved before `prepare`
or `apply` (`CHANGE-005`). Request binding is positional — a response arrives on the record of the
request that carried the offer. There is no response id and therefore no replay dedupe: a provider
that returns the same response twice produces two prepared modifications. Generation staleness
prevents applying against changed policy; it does not make application idempotent.

### 6.3 Host application protocol

For a change the host chooses to consider:

1. Author the offer in `offers()` — options and/or a namespaced draft — bounded by the documented
   limits, against the current generation.
2. Validate the returned response envelope without changing the normalized decision fields.
3. Confirm the response is a selection of an option the host actually offered, or an edit within the
   namespace and kind the host authored. A response naming an unknown option MUST be rejected.
4. Map the response to a candidate native rule in `prepare`.
5. Determine the candidate's widening/tightening impact at that target, treating mixed or unknown as
   widening (invariant 3).
6. Verify the provenance required for that impact (invariant 4).
7. Apply host-local caps by intersection; never loosen a bound (invariant 5).
8. In `apply`, use the ordinary native validation, idempotent durable write, audit, atomic
   use-count, expiry, and revocation path — atomically over the whole batch.
9. Re-evaluate only later operations against the installed rule.

Steps 5–7 are host obligations the seam cannot currently check; see the gaps in §6.2.

### 6.4 Normative failure table

| Change condition                                                    | Current one-shot result | Standing policy                                       |
| ------------------------------------------------------------------- | ----------------------- | ----------------------------------------------------- |
| No `policyChanges` adapter configured, or it supplies no `offers`   | Unchanged               | No offer is made; unchanged                           |
| Adapter fails registration validation, or `offers` throws/times out | Unchanged               | No offer is made; unchanged                           |
| Host offer is malformed, oversized, or non-JSON                     | Unchanged               | No offer is made; unchanged                           |
| Provider returns no change responses                                | Unchanged               | Unchanged                                             |
| Any response in the batch is malformed                              | Unchanged               | **Whole batch** discarded                             |
| Batch exceeds the response limit                                    | Unchanged               | Whole batch discarded                                 |
| Any decision in the gate is not `approved`                          | Unchanged               | No change is prepared or applied                      |
| Generation moved between offer and prepare/apply                    | Unchanged               | Batch discarded as stale                              |
| Any `prepare` fails, throws, or times out                           | Unchanged               | Whole batch discarded; nothing applied                |
| `apply` returns `false`                                             | Unchanged               | Not applied; no reload                                |
| `apply` throws, times out, or settles late after being invoked      | Unchanged               | Treated as possibly persisted; reconciled by a reload |
| `apply` succeeds                                                    | Unchanged               | One coalesced reload; affects only later evaluations  |
| Post-apply reload fails                                             | Unchanged               | Last good snapshot retained                           |
| Caller aborts before apply                                          | Unchanged               | Nothing applied                                       |

The whole-batch discard on any malformed member is deliberate and stronger than per-item filtering:
it prevents a provider from getting a partial policy change applied by attaching one valid response
to several invalid ones. It also differs from the macts #111 local SPI, where a malformed suggestion
made the entire provider response malformed — structural separation is stronger, because malformed
optional policy material cannot erase or manufacture what the human decided.

The "possibly persisted" row is worth stating explicitly: once `apply` has been invoked, the gate
assumes an external write may have landed even if the callback later rejects or exceeds its
deadline, and reconciles by reloading rather than retaining state it can no longer trust. That
reload is deliberately independent of caller cancellation.

### 6.5 L3 conformance cases

The harness MUST prove that the one-shot result is identical whether change material is absent,
valid, malformed, or rejected; that a malformed member discards the whole batch; that nothing is
prepared or applied unless every decision is approved; that a stale generation discards the batch;
that `apply` is invoked once and atomically over the batch; that a successful apply triggers exactly
one reload and does not alter the current result; that a failed reload after apply leaves the result
unchanged; that a timed-out late apply stays inside the snapshot mutation barrier; that oversized
offers are rejected before their elements are read; and that the aggregate JSON budget is enforced.

Repo status: `CHANGE-001`–`CHANGE-014` in `test/policy-changes.test.ts` cover all of the above.

Not yet covered, tracked under [#220](https://github.com/mike-north/allw/issues/220): unknown-property
rejection on policy-affecting records; rejection of a `choice` naming an option the host never
offered; change-specific provenance; bound expression and tightening; widening/mixed impact
classification; and replay idempotency.

---

## 7. Runtime guards and diagnostics

The implementation should be small enough to audit. It needs guards and normalizers for standard
fields, requirement normalization, and optional conformance fixtures—not a framework.

The rules below apply to every value crossing a boundary, regardless of which contract role it
belongs to:

- Treat values crossing a provider/plugin/process boundary as `unknown` at runtime.
- The decision, policy, and escalation roles accept unknown additive object properties but reject
  unknown discriminants and versions.
  Policy-modification records are closed-world and reject unknown properties as well as unknown
  discriminants and versions (see the §6.2 gap: not yet enforced in the repo).
- Validate finite/safe integer time values and non-empty identifiers before invoking side effects.
- Bound recursive validation work and reject accessors/prototypes that make validation effectful.
- Never deserialize code, execute host-supplied policy, or inspect opaque evidence.
- Return client-safe reasons and send raw failures only to an explicit operator diagnostic sink.
- A guard exception is itself a malformed input and fails closed.

The package MUST NOT define a universal audit schema. It SHOULD expose stable reason categories to
the conformance harness once implementation begins, while leaving provider exceptions and
host-native traces out of the portable result.

---

## 8. Versioning and stability

The npm package and runtime schemas have distinct version axes:

- npm uses Semantic Versioning.
- `apiVersion` versions the provider invocation contract.
- `schemaVersion` versions each runtime value family.

The package remains `0.x` through the first conforming macts migration and allw adapter. `1.0.0`
requires those two independent consumers, frozen conformance fixtures covering every contract role,
the adapter-optionality requirements in §2.2, and the complete fail-closed conformance suites.

During `0.x`, patch releases preserve the current minor contract; a new minor MAY make a breaking
design correction called out in release notes. Consumers SHOULD pin a compatible minor with `~`
until 1.0. Provider registration MUST compare `apiVersion` explicitly rather than assuming that an
installed npm version implies runtime compatibility.

After 1.0:

| Change                                                                                                                                                             | SemVer treatment                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------- |
| Bug fix that preserves valid accepted values and public types                                                                                                      | patch                                    |
| New explicitly non-authoritative optional metadata field, guard/helper, conformance fixture, or optional adapter slot                                              | minor                                    |
| New union/discriminant member, new required field, changed default/failure behavior, moved symbol, removed/renamed field, or newly rejected previously valid value | major                                    |
| New policy-modification constraint, bound, or other policy-affecting field                                                                                         | major plus a new runtime `schemaVersion` |

Adding a union member is major because exhaustive consumers would otherwise compile against an
incomplete decision set. Unknown additive object fields remain accepted on decision, policy, and
escalation values so compatible producers can deploy non-authoritative optional fields before
consumers. Policy-modification records remain closed-world. Unknown versions and discriminants
remain fail-closed everywhere.

Deprecations SHOULD remain for at least one minor release before a major removal. A security patch
MAY reject a value that was never valid under the documented schema, but MUST NOT silently change
the meaning of a valid decision. Every supported major line publishes its own conformance fixtures.

---

## 9. Migration and rollout

Live state checked 2026-08-25:

- macts [#111](https://github.com/mike-north/macts/pull/111) contains the proven local approval SPI.
- macts [#112](https://github.com/mike-north/macts/pull/112) contains terminal host/key policy
  composition.
- macts [#114](https://github.com/mike-north/macts/issues/114) tracks migration to this package.
- allw [#220](https://github.com/mike-north/allw/issues/220) tracks the common package
  implementation and conformance harness.
- allw [#219](https://github.com/mike-north/allw/issues/219) tracks the generic allw adapter and L3
  bridge.
- allw [#183](https://github.com/mike-north/allw/issues/183) tracks the macts-specific provider.

Recommended sequence:

1. Merge macts #111 with its reviewed local SPI; do not block it on this package.
2. Merge/reconcile macts #112 so terminal composition and governing-layer attribution are settled.
3. Close the §10 gap list in
   [github.com/mike-north/hitl-policy](https://github.com/mike-north/hitl-policy) — the repo already
   implements this spec — then publish and stabilize it, tracked under
   [#220](https://github.com/mike-north/allw/issues/220).
4. Migrate macts under #114 **after #112**, in one mechanical change:
   - neutralize permission/API-key names through adapter types;
   - keep macts's multi-layer composition of `allowed | confirm-first | denied` **inside its own
     `PolicyAdapter`**, emitting one terminal `allow`/`deny`/`ask` per evaluation. The seam no
     longer composes layers (§5.2), so `layer` attribution stays host-native;
   - express routing through `HitlAdapter.route` rather than a `supportsDistinctRouting` capability
     flag, which no longer exists;
   - re-express `policySuggestion` as host-authored `offers()` material, since the provider no
     longer proposes rules (§6);
   - retain macts's native risk classes, dispositions, rules, restrictions, and audit schema; and
   - preserve request ids, sanitized failures, and durable-audit-before-execute while keeping the
     #111 fail-closed/audit regression suite green. If downstream compatibility exists by then,
     retain deprecated macts-local aliases for one release.
5. Implement the allw adapter under #219. It maps only a fully verified allw approval to
   `approved`; `denied` and signed `aborted` map to `rejected`; `expired` maps to `timeout`; SDK
   errors map to `rejected`; the signed verdict remains opaque decision evidence. Note the
   dependency: allw's separately signed `policy_rule_from_approval` artifact has **no carrier** in
   the current change-negotiation types (§6.2, invariant 4), so #219 either lands without it or
   waits on that gap being closed under #220.
6. Make #183 a thin macts specialization of #219. If it ships first against local macts types,
   migrate both in the same compatibility window.

Migrating macts before #112 would move the local SPI once and immediately move the policy-layer
attribution again. Waiting makes the boundary change mechanical. Claude Code, Codex, OpenClaw, and
MCP keep their native external contracts; their allw integrations are adapters, not migration
targets.

---

## 10. Package implementation acceptance criteria

**The repo implements this spec.** [github.com/mike-north/hitl-policy](https://github.com/mike-north/hitl-policy)
is the design of record; this document describes it. The criteria below are therefore a gap list,
not a greenfield checklist — the delivered items say what is already true, and the remaining items
are tracked under [#220](https://github.com/mike-north/allw/issues/220).

Delivered:

- a root barrel plus `./conformance`, with the four superseded subpaths asserted absent;
- zero runtime dependencies and no allw/core/crypto/native imports, verified against the built
  declarations and runtime entrypoints;
- documented types corresponding to §§3–6, with an API report under `api-report/`;
- bounded runtime guards, the safe `invokeDecision` helper, and bounded host-callback invocation;
- adapter optionality: policy-only, HITL-only, and mixed gates, with terminal policy results never
  invoking a provider;
- provider-facing requests carrying one approval obligation and no host-native evaluation details;
- reloadable host-owned policy snapshots with opaque revisions, coalesced reloads, last-good
  retention, and bounded restart on an unstable generation;
- gate-enforced post-decision policy re-check, evidence verification, and durable audit;
- the interactive change-negotiation model — host-authored offers, provider choice/edit responses,
  whole-batch discard on any malformed member, generation-staleness rejection, atomic apply
  serialized against snapshot replacement, and exactly one coalesced reload afterward; and
- a portable-import smoke test proving the built entrypoints carry no `node:`, `require(`, `.node`,
  or `.wasm` references.

Remaining, tracked under #220:

- an **executable** conformance suite exported from `./conformance`, not fixtures alone, so an
  adapter author can run the cases against their own adapter;
- a `CONFORMANCE_REQUIREMENTS` list that matches the implemented suite;
- non-vacuous adapter-optionality assertions (§2.2 gap 3);
- closed-world guards that reject unknown properties on policy-affecting records;
- rejection of a `choice` response naming an option the host never offered;
- a carrier for change-specific provenance, and the widening/tightening impact and bounds
  expression that invariants 3–5 require;
- replay idempotency for change responses, and a ruling on cross-invocation decision idempotency;
- a regression guard proving policy `details` never reach a provider request; and
- package documentation that states the effective-allow conjunction and the
  one-shot/change-negotiation invariants before any quickstart example.

---

## 11. Prior art, checked 2026-08-25

The following matrices report current upstream contracts rather than projecting this design onto
them. Primary specifications, vendor documentation, and pinned source are linked inline. A product
callout or callback is not called a verified human approval unless its contract actually provides
that property.

### 11.1 Agent ecosystem

| System                                       | Exact decisions and policy shape                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Ask and failure behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Reuse, composition, revocation, and expiry                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Claude Code / Agent SDK**                  | Rules are `Tool` or `Tool(specifier)` under `permissions.allow`, `.ask`, and `.deny`; modes are `default \| acceptEdits \| plan \| auto \| dontAsk \| bypassPermissions`. `PreToolUse.permissionDecision` is `allow \| deny \| ask \| defer`. The SDK callback returns allow (optionally updated input/permissions) or deny. ([permissions](https://code.claude.com/docs/en/permissions), [hooks](https://code.claude.com/docs/en/hooks), [SDK permissions](https://code.claude.com/docs/en/agent-sdk/permissions))                                                                                                                                                                                                                                                                                         | Unresolved default-mode calls reach the native UI. An explicit deny or exit 2 blocks. A command hook crash/cannot-start, non-0/2 exit, or invalid/absent output is a non-blocking error and the action proceeds: unconditional hook-gate fail-open. A command-hook timeout instead yields no decision and falls through to the normal permission flow, which may still ask/deny but can proceed under a permissive mode/rule. Agent SDK callback-hook timeouts block—the documented opposite—and query cancellation cancels rather than approves. ([timeouts](https://code.claude.com/docs/en/hooks#timeouts), [other exits](https://code.claude.com/docs/en/hooks#other-exit-codes), [SDK user input](https://code.claude.com/docs/en/agent-sdk/user-input))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | “Yes, and don't ask again” writes Bash prefixes/Web domains to project-local settings; edit grants last for the session. SDK `updatedPermissions` can persist local settings. Native order is hooks, deny, ask, mode, allow, callback; native deny/ask still applies after hook allow, while hook deny survives bypass mode. Hook folding is deny > defer > ask > allow. Persisted rules remain until removed through settings or `/permissions`; there is no approval TTL.                                                                                                                                                                                                              |
| **Codex CLI**                                | `approval_policy` is `untrusted \| on-request \| never \| { granular = { sandbox_approval, rules, mcp_elicitations, request_permissions, skill_approval } }`; a false granular category auto-rejects it. Execpolicy `.rules` are side-effect-free Starlark `prefix_rule` declarations with `allow \| prompt \| forbidden`; strictest wins. `PreToolUse` can explicitly deny (or exit 2); `PermissionRequest` returns allow/deny or abstains. MCP modes are `auto \| prompt \| writes \| approve`; elicitation returns `accept \| decline \| cancel`. ([configuration](https://learn.chatgpt.com/docs/config-file/config-reference#configtoml), [rules](https://learn.chatgpt.com/docs/agent-configuration/rules), [MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli#other-configuration-options)) | `PermissionRequest` runs only when Codex was already going to ask; deny wins, allow suppresses that prompt, and failure/abstention preserves normal approval flow. `PreToolUse` runs on supported tool calls, but crash, timeout, invalid/unsupported output, or MCP-hook error sets `should_block=false` and continues the normal tool path; only a valid deny/exit 2 blocks. Auto-review prompt-build, reviewer, parse, and timeout failures fail closed. Specialized tool paths can bypass hooks, which Codex documents as guardrails rather than complete enforcement. ([PreToolUse](https://learn.chatgpt.com/docs/hooks#pretooluse), [PermissionRequest](https://learn.chatgpt.com/docs/hooks#permissionrequest), [pinned implementation](https://github.com/openai/codex/blob/731d969d0387e768a7c35aff430c6d9d376bd951/codex-rs/hooks/src/events/pre_tool_use.rs), [auto-review](https://learn.chatgpt.com/docs/agent-approvals-security#automatic-approval-reviews))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | TUI “always allow” and smart suggestions write durable `~/.codex/rules/default.rules`; MCP modes persist in config. Sandbox, approval policy, granular categories, execpolicy, hooks, and the actual prompt compose as separate gates; execpolicy uses `forbidden > prompt > allow`. `.rules` load at startup and have no TTL; edit/remove and restart to revoke. A one-shot approval is not documented as a durable artifact.                                                                                                                                                                                                                                                           |
| **OpenClaw 2026.8.1**, pinned at `1d526c5c…` | Reviewer decisions are exactly `allow-once \| allow-always \| deny`; durable statuses are `pending \| allowed \| denied \| expired \| cancelled`. `allowedDecisions` is request-local, unique/nonempty, and includes deny. Five canonical `tools.exec.mode` values reduce as: `deny` → deny/off; `allowlist` → allowlist/off; `ask` → allowlist/on-miss human; `auto` → allowlist/on-miss native reviewer then human; `full` → full/off. Configuration layers global → agent → session `/exec` → call, then host SQLite policy constrains the result. ([exec config](https://docs.openclaw.ai/tools/exec#config), [pinned schema](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/packages/gateway-protocol/src/schema/approvals.ts))                                    | `askFallback = deny \| allowlist \| full` handles no route/timeout; default deny. Durable CAS is fail-closed for exact deadline, malformed/no-route/storage-corrupt, abort/restart, first-answer-wins, and one-consumption `allow-once`. The exec caller can nevertheless re-admit a null/expired decision through `askFallback`; `full` is an explicit fail-open hazard. Plugin timeout/cancel/no-route/malformed/mismatch blocks and deprecated `timeoutBehavior:"allow"` is ignored. Node approval requests require a canonical `systemRunPlan`; the gateway ignores caller-supplied command/raw-command/cwd/agent/session changes and forwards the stored plan, while the node host rejects an approved run whose supplied plan does not match its final argv/command text/cwd/agent/session. ([exec approvals](https://docs.openclaw.ai/tools/exec-approvals#settings-and-storage), [plugin decisions](https://docs.openclaw.ai/plugins/plugin-permission-requests#decision-behavior), [protocol](https://docs.openclaw.ai/gateway/protocol#exec-approvals), [request validation](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/exec-approval.ts#L231-L245), [gateway canonicalization](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/node-invoke-system-run-approval.ts#L417-L450), [node-host enforcement](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/node-host/invoke-system-run.ts#L386-L451)) | SQLite row `exec_approvals_config` is CAS-authoritative. Exec allow-always adds an argv-bound allowlist entry; `ask=always` still asks. Plugin allow-always persistence is plugin-defined. Host policy constrains requested policy monotonically; plugin approval can still be blocked by a later hook. Exec defaults to 30 minutes; plugin defaults to 120 seconds and caps at 600 seconds; terminal records remain 30 days; restart cancels parked runs. Allow-always has no TTL/use cap and is revoked by editing/removing the allowlist. ([pinned store](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/operator-approval-store.ts)) |
| **macts PRs #111/#112**                      | Declarations are `allowed \| read-only \| confirm-first \| forbidden`; risk classes are `read \| write \| delete \| send \| execute \| system-change`; evaluated terminals are `allowed \| denied \| confirm-first`. The provider returns `approved \| rejected \| timeout`, optional reason/evidence/suggestion, and capability flags. ([approval SPI](https://github.com/mike-north/macts/blob/1615db965e6a963a60b73795886850dc9f2bb600/packages/core/src/governance/approval.ts), [evaluator](https://github.com/mike-north/macts/blob/7f76b3f55f2c77bd09f9d820cc47e25279a965bd/packages/core/src/governance/evaluator.ts))                                                                                                                                                                              | Only `confirm-first` invokes the provider. Explicit reject/timeout, hang, invalid timeout, throw/rejection, malformed response, provider load failure, or missing durable audit denies/withholds execution. The wrapper aborts a hung provider, never rejects, sanitizes client text, and leaves evidence opaque. No provider preserves a legacy pending response but does not release the handler. ([PR #111](https://github.com/mike-north/macts/pull/111), [tests](https://github.com/mike-north/macts/blob/1615db965e6a963a60b73795886850dc9f2bb600/packages/core/src/governance/approval.test.ts))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Policy suggestions are reserved, not standing-grant behavior. Host and key evaluate independently; only terminals compose as `allowed < confirm-first < denied`, broad-to-narrow with broad tie attribution. Path denies union and allowlists remain separate conjunctive groups. Request timeout is per-call; policy lifecycle is host-owned. ([composition](https://github.com/mike-north/macts/blob/49ea41d1d720f3665bb6bc059228e663afad45dd/packages/core/src/governance/composition.ts), [rationale](https://github.com/mike-north/macts/issues/108#issuecomment-5402917066))                                                                                                       |
| **allw**                                     | The wire verdict is `approved \| denied \| expired \| aborted`; the policy seam evaluates `allow \| deny \| escalate`. The primitive returns a verified human decision, never authorization. T1 rules match syntactic `ActionRecord` data and `ActorMatcher`; semantic capability fields are reserved/null. ([contract](./contract.md), [policy seam](./policy-seam.md))                                                                                                                                                                                                                                                                                                                                                                                                                                    | Timeout, no response, malformed/unverifiable artifact, identity/request/hash mismatch, stale/replayed verdict, and failed challenge all deny. An approved verdict satisfies only the human term in the host conjunction. WYSIWYS binds the exact shown plaintext and expiry.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Verdicts are one-shot and scope-free. Standing autonomy is a separately signed, host-evaluated `policy_rule_from_approval` artifact. Rules are actor-scoped and syntactic-first; policy gates compose by intersection. Bounds exist structurally, but the current core rejects bounded rules until use/expiry enforcement exists. Device/account state supports key revocation; request/verdict expiry is verified per operation. ([policy implementation](https://github.com/mike-north/allw/blob/213c7c05e44326ddf5b057c3a4a06ad9d01cbfb8/crates/allw-core/src/policy.rs))                                                                                                             |
| **MCP stable 2026-07-28 (GA)**               | MCP has no authorization verdict or policy DSL. Elicitation returns exactly `accept \| decline \| cancel`; a tool returns a `complete` result with optional `isError`. The four behavioral tool annotations are optional `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`, and clients MUST treat them as untrusted unless the server is trusted. ([GA release](https://blog.modelcontextprotocol.io/posts/2026-07-28/), [spec](https://modelcontextprotocol.io/specification/2026-07-28), [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools))                                                                                                                                                                                                          | The stateless core uses multi-round tool results (MRTR): a server returns `input_required` with requests/state, and the client fulfills elicitation/other input then retries the original call. Elicitation is interaction transport, not an approval-enforcement contract. Invalid MRTR yields another input requirement or JSON-RPC error, never implied allow. Timeout/no-support policy is host-owned. Deprecated sampling still says there SHOULD always be a human able to deny, with UI to review/edit prompts and review responses, but MCP does not mandate the interaction model or define an approval verdict. Sampling, roots, and logging are formally deprecated for new implementations with a support window. ([MRTR](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr), [elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation#response-actions), [deprecations](https://modelcontextprotocol.io/specification/2026-07-28/deprecated), [sampling](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling#user-interaction-model))                                                                                                                                                                                                                                                                                                                                                                                                                                  | No standing tool-approval grant is standardized. MRTR state is request-local and SHOULD be integrity-protected with short TTL/principal/request binding; that is continuation/replay protection, not reusable approval. MCP separately specifies an optional OAuth authorization flow and normative access-token handling; authorization-server token issuance/lifetime/revocation policy, host tool policy, approval UI/composition/timeouts, and approval revocation remain application-owned. ([authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization))                                                                                         |

#### OpenClaw external-client access model

Verified against the pinned tree on 2026-08-26. OpenClaw's external-client approval seam is
**filtered, not scope-only** — and that filtering is a least-privilege gap, not a blocker on the
bridge described in [openclaw-integration.md](./openclaw-integration.md).

`operator.approvals` is necessary but not sufficient. Delivery is two-stage: an event-level scope
guard, then a targeted recipient set (`canDeliverApprovals` — admin or approvals scope, **and** an
internal approval runtime, a known first-party client id, or the public self-declared handshake
capability `caps: ["approvals"]`), then a per-record visibility check. That per-record check returns
true unconditionally for `operator.admin`; otherwise it admits only the internal approval runtime, a
device listed in the record's `approvalReviewerDeviceIds`, the recording requester
connection/device, or **any** `operator.approvals` client when the record carries no binding at all.
`approvalReviewerDeviceIds` only ever _narrows_ access, is bound solely by the server-trusted
internal runtime, and has no config, CLI, or documented client surface — it is not an enablement
path.

Two corrections to the earlier reading of this seam:

- **"An external client cannot list or resolve pending approvals" is too strong.** An
  `operator.approvals` client with a device id can `approval.get` / `approval.resolve` **any unbound
  pending record**, and an admin-scoped client sees every record through the ordinary list methods.
  The real gap is narrower and exact: a generic paired bridge cannot see the records that _are_
  bound to a requester, which is the population it exists to gate.
- **The `approval.get` sanitization is accurate but not binding.** The unified projection does omit
  `systemRunPlan`. That does not deprive the bridge of the exact-request substrate, because the
  `*.approval.requested` events and `exec.approval.list` / `plugin.approval.list` return the **raw
  stored request verbatim** — for exec including `systemRunPlan`, `systemRunBinding`, `commandArgv`,
  `cwd`, and `envKeys`. The adapter binds from that carrier; it must simply never try to rehydrate
  request identity from the sanitized projection.

**Resolution: dual mode.** In **trusted-deployment (admin) mode** the bridge pairs with the default
handoff profile (which includes `operator.admin`; `--limited` omits it), declares
`caps: ["approvals"]`, subscribes and backfills, renders from the event/list `request`, and resolves
via `*.approval.resolve`. This is upstream's own operator-CLI pattern and works against the pinned
tree today — with upstream's caveat that a restricted third-party client should not request admin
merely to emulate that command, so allw treats it as an explicit, audited, opt-in posture with a
named risk. In **least-privilege mode** (`operator.approvals` alone — allw's preferred default
posture) the bridge is inert for discovery and MUST fail closed and report itself unavailable rather
than run connected-but-blind; it becomes active unchanged once upstream ships reviewer designation.
The gap is an upstream least-privilege ask, not a reason to weaken L0.

([broadcast scope guard](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-broadcast.ts#L53-L60), [admin bypass](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-broadcast.ts#L197-L199), [`canDeliverApprovals`](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-request-context.ts#L135-L161), [record visibility](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/approval-record-lookup.ts#L72-L120), [verbatim list](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/approval-record-lookup.ts#L122-L149), [unbound-record resolve authority](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/operator-approval-authorization.ts#L69-L79), [reviewer bind guard](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/exec-approval.ts#L416-L423), [stored request shape](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/exec-approval.ts#L328-L379), [event payload](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/approval-shared.ts#L146-L160), [sanitized presentation](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/infra/approval-presentation.ts#L46-L72), [`caps` registry](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/packages/gateway-protocol/src/client-info.ts#L82-L95), [pairing profiles](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/docs/channels/pairing.md#L182-L184), [operator CLI](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/cli/exec-approvals-cli.ts#L517-L534), [CLI caveat](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/docs/cli/approvals.md#L79))

### 11.2 Classic policy and permission systems

| System                   | Decision and policy shape                                                                                                                                                                                                                                                                                                                                                                                                               | Ask and failure behavior                                                                                                                                                                                                                                                                                                                                                                                 | Reuse, composition, revocation, and expiry                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **XACML 3.0**            | PDP decisions are `Permit \| Deny \| NotApplicable \| Indeterminate`; rules/policies/policy sets select explicit combining algorithms and may return obligations/advice. ([OASIS standard](https://docs.oasis-open.org/xacml/3.0/errata01/os/xacml-3.0-core-spec-errata01-os-complete.html))                                                                                                                                            | No human ask. Errors/missing attributes can be `Indeterminate`. Base PEP behavior for it and `NotApplicable` is undefined; a deny-biased PEP denies every non-dischargeable `Permit`. Core XACML is not universally fail-closed.                                                                                                                                                                         | Reusable policies target subject/resource/action/environment attributes. Core has no remembered human grant or decision TTL/revocation. It offers deny-overrides, permit-overrides, ordered, first/only-applicable, deny-unless-permit, and permit-unless-deny, so monotonic denial is a chosen profile, not an invariant.                                                                                        |
| **OPA / Rego**           | A query returns arbitrary JSON or `undefined`; boolean allow and structured reason sets are application conventions. Rego modules produce virtual documents from `input` and `data`. ([language](https://www.openpolicyagent.org/docs/policy-language), [REST API](https://www.openpolicyagent.org/docs/rest-api))                                                                                                                      | No native ask or suspended decision. `default allow := false` implements policy-level default deny, but undefined, compile/evaluation error, server unavailability, and readiness are distinct; callers choose fail-open/closed operational behavior. ([default](https://www.openpolicyagent.org/docs/policy-reference/keywords/default), [operations](https://www.openpolicyagent.org/docs/operations)) | Modules/data/bundles are reusable; decisions are not bearer grants. Composition is authored in Rego, with no fixed deny precedence. Bundles replace owned roots and carry opaque revision; failed verification/activation retains the old bundle. Decision expiry/revocation is application policy. ([bundles](https://www.openpolicyagent.org/docs/management-bundles))                                          |
| **Cedar**                | Requests are principal/action/resource/context; `permit` and `forbid` policies produce final `Allow \| Deny` plus diagnostics. Any satisfied forbid wins; otherwise any permit allows; otherwise default deny. ([authorization](https://docs.cedarpolicy.com/auth/authorization.html), [syntax](https://docs.cedarpolicy.com/policies/syntax-policy.html))                                                                              | No ask; the language is terminating/effect-free and has no I/O. A policy evaluation error is skipped and reported, so an erroneous forbid can be skipped while another permit allows. A fail-closed host must inspect diagnostics. ([security](https://docs.cedarpolicy.com/other/security.html))                                                                                                        | Static and template-linked policies are reusable; the result is per-request. Composition is fixed and order-independent forbid-overrides. Policy-store lifecycle, deletion/archival, and time conditions govern future decisions; no verdict expiry/revocation artifact exists. ([templates](https://docs.cedarpolicy.com/policies/templates.html))                                                               |
| **Kubernetes admission** | Webhooks return `allowed: true \| false`; mutating webhooks may patch before validating controllers. A nonmatching webhook/policy is skipped, not returned as no-match. ([admission](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/), [webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/))                                                            | No pending human ask; webhook timeout is 1–30 seconds. Explicit false rejects. Call/timeout/serialization/malformed failures follow `failurePolicy`: default `Fail` rejects, `Ignore` skips. ([failure policy](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy))                                                                                | Per-request admission has no remembered approval. Mutators run before validators; all matching validators must pass, making validation a strong terminal tightening analogy. Policy/config changes affect future admission, not already persisted objects; no generic approval expiry exists. ([ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)) |
| **Web Permissions API**  | Permission state is `granted \| denied \| prompt`, scoped by descriptor plus permission key (normally origin). Permissions Policy can force denied before a prompt. ([W3C Permissions](https://www.w3.org/TR/permissions/))                                                                                                                                                                                                             | `prompt` lets the user agent ask; timeout may return denied. The interaction is browser authorization, not an exact agent-action verdict.                                                                                                                                                                                                                                                                | The permission store remembers descriptor+key. Feature/UA policy sets lifetime; expiry returns to default and revocation removes the entry. This is the clearest precedent for keeping state, scope, expiry, and revocation outside a one-shot prompt response.                                                                                                                                                   |
| **macOS TCC/privacy**    | Resource-specific authorization, not one grammar. Media states include `authorized \| notDetermined \| denied \| restricted`; managed privacy profiles resolve conflicts most-restrictively. ([media authorization](https://developer.apple.com/documentation/bundleresources/requesting-authorization-for-media-capture-on-macos), [PPPC](https://developer.apple.com/documentation/devicemanagement/privacypreferencespolicycontrol)) | First access may prompt with a purpose string; deny/restricted prevents use, and missing mandatory purpose metadata can terminate the app. Some services require Settings rather than an in-context prompt.                                                                                                                                                                                              | The system remembers grant/deny. The person can change it in Privacy & Security; `tccutil reset` clears access, including per bundle id. Scope and lifecycle are OS-owned, not a reusable action verdict. ([general contract](https://developer.apple.com/documentation/uikit/requesting-access-to-protected-resources))                                                                                          |
| **polkit**               | Actions have XML defaults and ordered JavaScript rules. Results expose authorized/challenge; implicit outcomes include `no`, `yes`, `auth_self`, `auth_admin`, and `_keep` variants. ([polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), [authority API](https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html))                                                    | `is_challenge` requests authentication, not approval of exact displayed action data. A session authentication agent handles it; dismissal/error fails the command. ([agents](https://polkit.pages.freedesktop.org/polkit/polkit-agents.html), [`pkcheck`](https://polkit.pages.freedesktop.org/polkit/pkcheck.1.html))                                                                                   | `_KEEP` creates brief temporary authorization by action+subject. The docs warn it ignores varying details supplied under the same action, a direct precedent against loose reuse for agent actions. Temporary authorizations expose action, subject, expiry, and revoke APIs.                                                                                                                                     |
| **sudo / sudoers**       | User specifications and aliases define who may run what; matching entries apply in order and the last match wins. Authentication is a credential gate, not a human action-approval protocol. ([sudoers manual](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in))                                                                                                                                                     | Unauthorized command or failed authentication does not execute and is logged. There is no `ask` policy result distinct from the authentication workflow.                                                                                                                                                                                                                                                 | Timestamp records cache authentication. Default scope is terminal/session; `timestamp_type` changes it and `timestamp_timeout` expires it. `sudo -k` invalidates a record. This is reuse of authentication within explicit scope/time, not reuse of a one-shot action verdict.                                                                                                                                    |

### 11.3 Convergences

The surveyed systems converge on several useful boundaries:

1. **Decision and durable policy are different objects.** Claude Code, Codex, OpenClaw, browser
   permissions, polkit, and sudo may offer “remember” UX, but it writes or caches standing state;
   the one-shot response is not itself a reusable capability.
2. **Deny must remain available and dominant.** macts terminal composition, Cedar forbids,
   Kubernetes validators, Claude/Codex hook folding, OpenClaw request decisions, and deny-biased
   XACML profiles all support a restrictive final layer.
3. **No-match and failure are not the same.** XACML `NotApplicable`/`Indeterminate` and OPA
   undefined/error demonstrate why L1 preserves explicit no-match but normalizes execution failure
   separately.
4. **Scope, lifetime, use count, and revocation belong to policy state.** Browser permissions,
   polkit, sudo, and OpenClaw show both the value of these dimensions and the danger of under-scoped
   persistence.
5. **Exact execution binding is stronger than prose approval.** OpenClaw's canonical
   `systemRunPlan` mutation check and allw WYSIWYS are the strongest native examples.
6. **Tool metadata is not authority.** MCP annotations are expressly untrusted hints; semantic
   classification cannot substitute for policy or verified human evidence.

### 11.4 Conflicts and extracted design consequences

| Prior-art conflict                                                                                                                            | Consequence for this contract                                                                                                                                                                                                                                                      |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Claude Code and Codex command `PreToolUse` processes can fail open at the host boundary                                                       | L0 specifies a safe in-process/provider boundary, and adapters MUST document when a host hook cannot uphold it. A hook is not declared conforming merely because its own code returns deny on errors.                                                                              |
| OpenClaw `askFallback: full`, Kubernetes `failurePolicy: Ignore`, permit-biased XACML, and caller-selected OPA readiness can admit on failure | Common helper defaults are fail-closed. A host MAY expose a deliberate native fail-open mode, but an adapter running in that mode is not conforming to the enforcement profile.                                                                                                    |
| Cedar skips erroneous policies                                                                                                                | L1 evaluator/guard errors normalize to deny even if the underlying engine reports diagnostics and continues.                                                                                                                                                                       |
| Native “always allow” often has no TTL and may match only action+subject                                                                      | L3 expresses bounds and a host-owned full scope; omitted or unenforceable bounds are never silently widened, and the current verdict remains one-shot.                                                                                                                             |
| A single declaration ordering is unsound for macts `read-only` versus `confirm-first`                                                         | L2 accepts only post-evaluation terminal decisions.                                                                                                                                                                                                                                |
| MCP elicitation `accept` and Claude/Codex/OpenClaw auto-review are not necessarily verified human decisions                                   | L0 adapters return `approved` only after the provider assurance promised to the host is met; model review or generic elicitation is not silently relabeled human approval.                                                                                                         |
| Provider-supplied policy direction cannot know host-native before/after semantics                                                             | L3 carries an effect and scope, but the host computes widening/tightening; unknown/mixed is widening.                                                                                                                                                                              |
| OpenClaw's sanitized `approval.get` projection omits the canonical execution plan, while its events and legacy list carry the raw request     | An adapter sources request identity from the carrier that actually holds the substrate and MUST NOT fall back to a sanitized projection to reconstruct it. Where only a lossy projection is reachable, the adapter remains unavailable rather than weakening its request identity. |
