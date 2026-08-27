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

The seam standardizes four independent layers:

| Layer                | Standalone use case                                                         | Vocabulary                                                     | May depend on                 |
| -------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------- | ----------------------------- |
| **L0 — decision**    | Ask a human about an operation, with no policy engine                       | `approved \| rejected \| timeout`                              | nothing above L0              |
| **L1 — policy**      | Evaluate policy without ever asking a human                                 | `allow \| deny \| no-match`                                    | nothing above L1; no L0 types |
| **L2 — escalation**  | Add `ask`, compose tightening policy layers, and invoke L0 only when needed | `allow \| ask \| deny \| no-match`                             | L0 and L1                     |
| **L3 — suggestions** | Carry a prospective host-policy change alongside an L0 result               | `allow \| ask \| deny` effect plus host-owned scope and bounds | L0 and L2                     |

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
conjunctive approval requirement has an `approved` L0 result and any evidence required for that
specific result has been accepted. A primary/governing explanation never substitutes for the
remaining authorities.

An L3 suggestion is absent from all three formulas. It can affect only a later evaluation after the
host has independently accepted and installed it through its normal policy path.

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

The package exposes subpaths, not a root barrel:

```text
hitl-policy/decision       L0 leaf
hitl-policy/policy         L1 leaf
hitl-policy/escalation     L2; imports L0 + L1
hitl-policy/suggestions    L3; imports L0 + L2
hitl-policy/conformance    optional adapter test harnesses
```

The `hitl-policy/policy` subpath is L1 — the host's own policy evaluation — and is deliberately
_not_ the whole package under a package of the same name. `hitl-policy` names the problem domain
(policy around human-in-the-loop decisions); `/policy` names one layer within it.

```text
 decision (L0)       policy (L1)
       \               /
        \             /
         escalation (L2)
          /          \
   decision            suggestions (L3)

 decision + policy + escalation + suggestions ---> conformance
```

There is deliberately no `hitl-policy` root export in v1. A root barrel would make the easiest
import pull every layer into a consumer and would hide accidental upward dependencies. Declaration
and import-graph tests MUST prove that:

- `/decision` exports no policy, escalation, or suggestion symbol;
- `/policy` exports no provider, human-decision, evidence, or suggestion symbol;
- `/escalation` has no L3 dependency; and
- `/suggestions` is the only production entrypoint that mentions `PolicySuggestion`.

---

## 3. L0 — human decision, without policy

L0 answers one question: **what did a human decide about this exact request?** It contains no
`allow`, `deny`, `ask`, rule, policy-layer, policy-scope, or standing-reuse field.

### 3.1 Type sketch

```ts
/** JSON-safe data accepted across Node, browser, plugin, and WASM boundaries. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/** A neutral caller identity. Host-specific identity fields stay on a subtype. */
export interface CallerIdentity {
  readonly kind: string;
  readonly id: string;
  readonly displayName?: string;
}

/**
 * The request a provider presents to a human. TOperation is deliberately host-owned:
 * this package does not define a common command, MCP, capability, or selector model.
 */
export interface DecisionRequest<
  TOperation extends JsonValue = JsonValue,
  TCaller extends CallerIdentity = CallerIdentity,
> {
  readonly schemaVersion: 1;
  readonly id: string;
  readonly operationId: string;
  readonly operation: TOperation;
  readonly caller: TCaller;
  /** A non-empty, host-owned display label; there is no shared risk taxonomy. */
  readonly riskClass: string;
  readonly summary: string;
  readonly requestedAtMs: number;
  readonly timeoutMs: number;
}

export type DecisionFailure =
  | "provider-error"
  | "provider-unavailable"
  | "malformed-result"
  | "invalid-request"
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
  /** Provider-specific proof. L0 preserves it but never interprets it. */
  readonly evidence?: unknown;
}

export interface DecisionProvider<
  TRequest extends DecisionRequest = DecisionRequest,
  TResult extends DecisionResult = DecisionResult,
> {
  readonly apiVersion: 1;
  readonly providerId: string;
  requestDecision(request: TRequest, context: { readonly signal: AbortSignal }): Promise<TResult>;
}
```

The `number` member of `JsonValue` means a finite JSON number; guards reject `NaN` and infinities.
Recursive JSON values are subject to the documented depth and size bounds in §7.

`operationId` names the operation in the host's namespace; it is not a shared policy selector.
`operation` is the provider-facing exact JSON-safe description and MAY be specialized by a host.
Caller extensions crossing a process/plugin/WASM boundary MUST also be JSON-safe. `riskClass` is
display metadata, not a common severity ordering. A macts adapter can carry its permission and
API-key identity; an allw adapter can carry its `ActionRecord`; neither shape leaks into the base
package. `unknown` is reserved for evidence the common package must not interpret.

The base provider has no policy-related capability flags. `supportsDistinctRouting` belongs to L2,
and `supportsPolicySuggestions` belongs to L3.

### 3.2 Provider invocation contract

The implementation package MUST expose one safe invocation helper. Its exact function name is an
implementation detail; its behavior is not:

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
| Required evidence is absent, malformed, unverifiable, stale, for another caller/request, or revoked           | Host evidence gate fails                       | No                                                                 |
| Required durable audit/persistence fails after approval                                                       | Host audit gate fails                          | No                                                                 |

The safe helper sets the corresponding negative-only `failure` category for failures it
normalizes. A provider's well-formed explicit human `rejected` or `timeout` response need not carry
one. The guard rejects `failure` on `approved`, so audit can distinguish a person's “no” from a
provider/channel failure without adding a fourth decision state.

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

---

## 4. L1 — policy evaluation, without a human

L1 is a pure decision contract: it evaluates host-owned policy input and returns policy data. It
MUST NOT prompt, suspend for a person, import L0, or mention an approval provider.

### 4.1 Type sketch

```ts
export type PolicyDecision = "allow" | "deny" | "no-match";

export interface PolicyEvaluation<TDetails = unknown> {
  readonly schemaVersion: 1;
  readonly decision: PolicyDecision;
  readonly reason?: string;
  /** Host-native rule ids, obligations, traces, or other diagnostics. */
  readonly details?: TDetails;
}

export interface PolicyEvaluator<TInput = unknown, TDetails = unknown> {
  evaluate(
    input: TInput,
    context: { readonly signal: AbortSignal },
  ): PolicyEvaluation<TDetails> | Promise<PolicyEvaluation<TDetails>>;
}
```

`no-match` is a successful, explicit result: the evaluator ran and found no applicable rule. It is
not an alias for an evaluator error, missing policy, unavailable PDP, malformed response, or
`undefined`.

The enforcement point MUST resolve `no-match` with an explicit `allow` or `deny` default before it
uses the evaluation as a gate. An explicit `allow` default is permitted for a policy layer intended
to be neutral on no match; it MUST NOT be inferred from an omitted default. Missing or malformed
fallback configuration fails to `deny`.

The safe evaluator helper takes a positive, bounded evaluation deadline independently of policy
input, composes its abort signal with caller cancellation, and never lets an async evaluator wait
indefinitely. Synchronous evaluators may ignore the signal. An optional layer that is not configured
is omitted entirely: absence is neither `no-match` nor an error. An empty configured layer set fails
closed at the enforcement point.

### 4.2 Normative failure table

| Evaluator condition                                                                                                                 | Normalized evaluation | Notes                                               |
| ----------------------------------------------------------------------------------------------------------------------------------- | --------------------- | --------------------------------------------------- |
| Well-formed `allow`                                                                                                                 | `allow`               | A policy signal only; other gates still apply       |
| Well-formed `deny`                                                                                                                  | `deny`                | Terminal refusal                                    |
| Well-formed `no-match`                                                                                                              | `no-match`            | Resolve only through the caller's explicit fallback |
| Throw, rejected promise, timeout, caller abort, transport error, unavailable evaluator, or missing policy that was expected to load | `deny`                | Failure is not `no-match`                           |
| Null, primitive, missing field, unknown decision/version, or malformed standard field                                               | `deny`                | Fail closed                                         |
| `no-match` with no valid fallback                                                                                                   | `deny`                | Never infer allow                                   |

The safe evaluation helper MUST never reject, MUST sanitize implementation exceptions, and MUST
preserve host-native `details` only for a response that passes the standard guard.

### 4.3 L1 conformance cases

The harness MUST accept exactly the three decisions, reject L2's `ask`, distinguish no-match from
errors, exercise both explicit no-match fallbacks, normalize sync/async errors and malformed output
to deny, and prove the `/policy` declaration graph has no L0 dependency.

---

## 5. L2 — escalation and tightening composition

L2 adds `ask` to the policy vocabulary, composes nested restriction layers, and invokes an L0
provider only when the composed policy asks. It does not turn the human decision into ambient
authorization.

### 5.1 Type sketch

```ts
import type {
  DecisionProvider,
  DecisionRequest,
  DecisionResult,
  JsonValue,
} from "hitl-policy/decision";
import type { PolicyEvaluation } from "hitl-policy/policy";

export type EscalationPolicyDecision = "allow" | "deny" | "ask" | "no-match";

export type TerminalPolicyDecision = Exclude<EscalationPolicyDecision, "no-match">;

export interface EscalationPolicyEvaluation<TDetails = unknown> extends Omit<
  PolicyEvaluation<TDetails>,
  "decision"
> {
  readonly decision: EscalationPolicyDecision;
}

/** A layer after no-match has been explicitly terminalized. */
export interface TerminalLayerEvaluation<TDetails = unknown> {
  readonly layerId: string;
  /** Required for ask: equal ids explicitly mean one decision may satisfy both layers. */
  readonly approvalAuthorityId?: string;
  readonly routeId?: string;
  readonly evaluation: EscalationPolicyEvaluation<TDetails> & {
    readonly decision: TerminalPolicyDecision;
  };
}

export interface ApprovalRequirement {
  readonly authorityId: string;
  readonly routeId?: string;
  readonly layerIds: readonly string[];
}

export interface ComposedPolicyEvaluation<TDetails = unknown> {
  readonly decision: TerminalPolicyDecision;
  readonly governingLayerId: string;
  readonly governingRouteId?: string;
  readonly layers: readonly TerminalLayerEvaluation<TDetails>[];
  /** Empty for allow/deny; all entries are conjunctive when decision is ask. */
  readonly approvalRequirements: readonly ApprovalRequirement[];
}

export interface EscalationDecisionRequest<
  TOperation extends JsonValue = JsonValue,
  TDisplayContext extends JsonValue = JsonValue,
> extends DecisionRequest<TOperation> {
  readonly escalation: {
    readonly requirement: ApprovalRequirement;
    /** Optional sanitized display data; never policy input or authoritative provenance. */
    readonly displayContext?: TDisplayContext;
  };
}

export interface EscalationProviderCapabilities {
  readonly supportsDistinctRouting: boolean;
}

export interface EscalationProvider<
  TRequest extends EscalationDecisionRequest = EscalationDecisionRequest,
  TResult extends DecisionResult = DecisionResult,
> extends DecisionProvider<TRequest, TResult> {
  readonly capabilities: EscalationProviderCapabilities;
}
```

Each raw layer couples its `no-match` evaluation with an explicit fallback of `allow`, `ask`, or
`deny`. Terminalization happens before composition. An omitted/invalid fallback or an evaluator
failure terminalizes to `deny`, not to the configured no-match fallback.

`approvalAuthorityId` is the host's canonical identity for an approval obligation. Equal ids are an
explicit assertion that one human decision may satisfy the asks from those layers. Different ids
remain separate conjunctive obligations. `routeId` is a host-owned provider-routing label, not a
closed `host | key` enum. These fields move the macts `layer` concern out of L0. A required
non-default route with no capable router/provider fails closed; it MUST NOT silently use the
default route.

The complete `ComposedPolicyEvaluation`, including host-native `details`, remains inside the host
for audit, explanation, re-evaluation, and final enforcement. It MUST NOT be copied into a provider
request. A host MAY add an explicitly constructed JSON-safe `displayContext` to the one request for
a selected requirement. That context is presentational only, is bounded by the same JSON guard as
`operation`, and cannot be used to reconstruct or enforce native policy.

### 5.2 Composition algorithm

Layers are supplied from broader to narrower, such as macts host policy followed by per-key policy.
The input MUST be non-empty and terminal. The composer chooses the strictest decision:

```text
allow < ask < deny
```

| Broader \\ narrower | `allow`           | `ask`                                         | `deny`            |
| ------------------- | ----------------- | --------------------------------------------- | ----------------- |
| `allow`             | `allow` (broader) | `ask` (narrower requirement)                  | `deny` (narrower) |
| `ask`               | `ask` (broader)   | `ask` (broader explanation; retain both asks) | `deny` (narrower) |
| `deny`              | `deny` (broader)  | `deny` (broader)                              | `deny` (broader)  |

Earlier/broader input wins a tie only for the primary explanation. A narrower layer is named as
governing only when it actually tightens the accumulated scalar decision. The composed result
retains every terminal layer for audit and explanation. When the final decision is `ask`, it groups
every ask into `approvalRequirements` by canonical `approvalAuthorityId`. Two ask layers with
different authority ids require two approvals. Two asks with the same authority id coalesce into
one requirement only because the host explicitly declared their equivalence. When the final
decision is `allow` or `deny`, `approvalRequirements` is empty; any raw ask remains visible in
`layers` but is not actionable. A missing authority id on ask, or one authority id mapped to
conflicting routes, is malformed and fails closed even when another layer denies.

Composition MUST NOT compare pre-evaluation policy declarations. In macts, `read-only` and
`confirm-first` are incomparable before the operation risk is known: `read-only` allows a read but
denies a mutation, while `confirm-first` asks for both. Ranking declarations would either erase the
key's ask on reads or resurrect the host's deny on writes. Evaluate first; compose only the terminal
result.

Path restrictions, argument globs, allowlist intersections, risk classification, and other native
policy algebra remain inside each host evaluator. The common composer combines only terminal
decisions and attribution.

This algorithm supports both nested refinement and independent authorities. A single approval may
satisfy several nested asks only when their canonical authority ids match. Independent authorities
remain separate approval requirements and are conjoined; the composer MUST NOT tie-collapse them
into one prompt.

### 5.3 Escalation algorithm

After terminalization and composition:

1. `deny`: refuse. Do not invoke L0.
2. `allow`: satisfy this policy gate. Do not invoke L0.
3. `ask`: create one uniquely identified L0 request per distinct approval requirement, route it to
   that authority, and invoke each idempotently. Every requirement is conjunctive.
4. Any L0 `rejected`, `timeout`, provider failure, malformed response, missing route, or failed
   required evidence makes the policy gate fail. A late approval cannot revive it.
5. Accepted `approved` results satisfy only the corresponding asks. The L2 helper MUST return the
   original `ask` evaluation and the L0 results; it MUST NOT synthesize a policy `allow` from them.
6. Immediately before execution, the host MUST re-evaluate current policy, confirm the same
   approval requirements remain applicable, durably record its audit event, and intersect ambient
   authority and all other gates. A policy change to deny while a human was deciding is terminal;
   an approval never grandfathers the earlier ask.

### 5.4 Normative failure table

| L2 condition                                                                                                                   | Result                                                | Provider invoked?             |
| ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- | ----------------------------- |
| All layers terminalize to `allow`                                                                                              | `allow`                                               | No                            |
| Any layer terminalizes to `deny` and none is stricter                                                                          | `deny`                                                | No                            |
| Strictest result is `ask`                                                                                                      | Seek one L0 decision per distinct requirement         | Once per requirement          |
| Empty layer list, unresolved `no-match`, unknown decision, invalid/missing ask authority, route conflict, or composition error | `deny`                                                | No                            |
| Policy evaluator throws/rejects or returns malformed output                                                                    | That layer terminalizes to `deny`                     | No if composed result is deny |
| Any required route is unavailable, ambiguous, or unsupported                                                                   | Human gate fails                                      | No or aborted                 |
| Provider missing/cannot load/throws/returns malformed                                                                          | Human gate fails                                      | At most once per requirement  |
| Any provider returns `rejected` or `timeout`                                                                                   | Human gate fails                                      | Once for that requirement     |
| Provider returns `approved`, but required evidence/audit fails                                                                 | Human gate fails                                      | Once for that requirement     |
| Every provider returns accepted `approved` and current policy re-evaluates compatibly                                          | Ask obligations are satisfied; never an ambient grant | Once per requirement          |

### 5.5 L2 conformance cases

The harness MUST cover the exhaustive 3×3 terminal matrix; broad-layer primary explanation while
retaining all provenance; every explicit no-match fallback; rejected unresolved no-match; no
provider call for allow/deny; one idempotent call per distinct approval authority; same-authority
coalescing; different-authority conjunction; missing/conflicting authority routing; current-policy
re-evaluation after a wait; routing capability failure; rejection of unsanitized/non-JSON display
context; proof that host-native evaluation details never cross the provider boundary; and these
macts regressions:

- host `read-only` on a read → allow, key `confirm-first` → ask governed by key;
- host `read-only` on a mutation → deny, key `confirm-first` → deny governed by host, never ask;
- host forbid + key allow → deny, never ask.

---

## 6. L3 — policy modification via human decision

L3 carries a **suggestion**, not a rule and not a decision. It adds no reuse field to
`DecisionOutcome`. A suggestion can be accepted, rejected, or malformed independently of the one-shot
L0 result.

### 6.1 Type sketch

```ts
import type {
  DecisionProvider,
  DecisionRequest,
  DecisionResult,
  JsonValue,
} from "hitl-policy/decision";
import type { TerminalPolicyDecision } from "hitl-policy/escalation";

export interface HostPolicyDescriptor<TValue extends JsonValue = JsonValue> {
  /** Host/vendor namespace that owns this descriptor's semantics. */
  readonly namespace: string;
  readonly schemaVersion: number;
  readonly kind: string;
  readonly value: TValue;
  /** Human-facing only; hosts MUST NOT enforce from this string. */
  readonly display?: string;
}

export type PolicyTargetDescriptor<TValue extends JsonValue = JsonValue> =
  HostPolicyDescriptor<TValue>;

export type PolicyScopeDescriptor<TValue extends JsonValue = JsonValue> =
  HostPolicyDescriptor<TValue>;

export interface PolicyTimeWindow {
  readonly startsAtMs: number;
  readonly endsAtMs: number;
}

export interface PolicyBounds {
  /** Maximum lifetime measured from PolicySuggestion.issuedAtMs. */
  readonly ttlMs?: number;
  readonly maxUses?: number;
  readonly timeWindow?: PolicyTimeWindow;
}

export interface PolicySuggestion {
  readonly schemaVersion: 1;
  /** Idempotency key within the provider namespace. */
  readonly id: string;
  /** Exact sibling L0 DecisionRequest.id this suggestion accompanied. */
  readonly requestId: string;
  readonly issuedAtMs: number;
  readonly effect: TerminalPolicyDecision;
  /** Which native policy store/layer/subject may receive the candidate rule. */
  readonly target: PolicyTargetDescriptor;
  /** Which future operations the candidate rule would cover. */
  readonly scope: PolicyScopeDescriptor;
  readonly bounds?: PolicyBounds;
  readonly rationale?: string;
  /** Suggestion-specific proof; never borrowed from the one-shot decision artifact. */
  readonly evidence?: unknown;
}

export interface PolicySuggestionProviderCapabilities {
  readonly supportsPolicySuggestions: true;
}

/** The suggestion is a sibling of the complete L0 result, never part of its decision. */
export type DecisionWithPolicySuggestion<TResult extends DecisionResult = DecisionResult> =
  TResult & {
    readonly policySuggestion?: PolicySuggestion;
  };

export interface PolicySuggestionProvider<
  TRequest extends DecisionRequest = DecisionRequest,
  TResult extends DecisionResult = DecisionResult,
> extends DecisionProvider<TRequest, DecisionWithPolicySuggestion<TResult>> {
  readonly capabilities: PolicySuggestionProviderCapabilities;
}
```

This is a deliberately minimal common target/scope shape:

- It is more structured than `unknown`: a host can guard, namespace, version, display, log, and
  reject the target and scope deterministically.
- It is not a universal selector language: `kind` and `value` have meaning only inside the named
  host/vendor namespace.
- It does not contain a common capability taxonomy. Hosts map the descriptor to their own
  syntactic or semantic policy language.

The common package MUST NOT provide `applySuggestion`. Applying policy is a host authority. The L3
invocation helper MUST validate and normalize the L0 result exactly as the L0 helper does, then
validate `policySuggestion` independently. A malformed suggestion is omitted/rejected without
changing the normalized result. A plain L0 consumer can safely ignore the additive sibling field;
an L3 consumer must use the L3 guard before considering it.

### 6.2 Non-negotiable invariants

1. **Suggestion is not decision.** Parsing, support, evidence, mapping, persistence, audit, or
   activation failure for the suggestion MUST NOT alter the sibling L0 result. The suggestion MUST
   NOT affect the operation currently awaiting a decision.
2. **Host-applied only.** A suggestion takes effect exclusively after the host recognizes its
   namespace/version/kind, maps it to native policy, validates it, persists/audits it, and makes it
   visible to the ordinary evaluation path. Providers do not install policy.
3. **No implicit widening.** The host, not the provider, determines whether the native before/after
   policy change is widening, tightening, mixed, or unknown at the **target layer** over the
   suggested scope, even when a broader deny currently masks it. Mixed or unknown impact MUST be
   handled as widening.
4. **Provenance may be asymmetric.** Every suggestion requires baseline source authentication,
   request binding, idempotency, and auditability. A host MAY require stronger identity, evidence,
   user presence, or signatures for widening than tightening. Required widening evidence that is
   missing or invalid rejects only the suggestion. allw's separately signed
   `policy_rule_from_approval` artifact is the reference case and remains inside the suggestion's
   opaque `evidence`; the one-shot verdict remains in `DecisionResult.evidence` and cannot authorize
   a standing rule.
5. **Bounds only tighten.** `ttlMs`, `maxUses`, and `timeWindow` are conjunctive. A host that cannot
   enforce a supplied bound MUST reject the suggestion or replace it with a strictly tighter bound;
   it MUST NOT silently discard the bound.
6. **Future evaluation is authoritative.** Accepted policy is re-evaluated for each later operation
   through the host's native path. No L0 result becomes a reusable bearer grant.

`ttlMs` and `maxUses` MUST be positive safe integers. `ttlMs` expires at
`issuedAtMs + ttlMs`, never at a replay or retry time. Time values MUST be finite safe-integer Unix
milliseconds. A time window is the absolute half-open interval `[startsAtMs, endsAtMs)` and MUST
satisfy `endsAtMs > startsAtMs`; recurring local-time/DST semantics are out of scope. `maxUses`
MUST be consumed atomically with the native authorization that uses it. `namespace`, `kind`, and
`display` are data, never code; `display` is an untrusted hint and the host SHOULD render the
mapped native candidate for confirmation. The runtime guard MUST reject cyclic, non-JSON,
excessively deep, or excessively large target/scope values using documented bounds.

`PolicySuggestion`, `HostPolicyDescriptor`, `PolicyBounds`, and `PolicyTimeWindow` are
**closed-world policy-affecting records**. Their guards MUST reject unknown properties. A future
constraint or bound requires a new `schemaVersion` and a package release whose major-version policy
forces consumers to opt into its semantics; an older consumer must never ignore a field that could
make the proposed rule narrower. Only fields explicitly documented as non-authoritative metadata
may be added compatibly.

The tuple `(providerId, PolicySuggestion.id)` is the idempotency key. A replay MUST return the
existing accept/reject state and MUST NOT reset TTL, use count, provenance, or audit history.
`requestId` MUST equal the sibling L0 request id. A host MUST reject a target it cannot prove is the
intended native policy layer/subject; a key-scoped decision, for example, cannot silently target a
host-wide policy store.

### 6.3 Host application protocol

For a suggestion the host chooses to consider:

1. Validate the envelope, idempotency key, `requestId`, issuance time, and baseline source
   authentication without changing the normalized L0 fields.
2. Confirm the provider declared `supportsPolicySuggestions`.
3. Recognize and parse target and scope namespaces/versions/kinds with host-owned parsers.
4. Prove the target policy layer/subject is authorized by the bound request and source.
5. Map effect, scope, and every bound to a candidate native rule.
6. Determine the candidate's widening/tightening impact at that target itself.
7. Verify the suggestion-specific provenance required for that impact.
8. Apply host-local caps by intersection; never loosen a suggested bound.
9. Use the ordinary native validation, idempotent durable write, audit, atomic use-count, expiry,
   and revocation path.
10. Re-evaluate only later operations against the installed rule.

### 6.4 Normative failure table

| Suggestion condition                                                                                                                             | Current L0 result | Standing policy                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------- | ----------------------------------------------------------- |
| Absent                                                                                                                                           | Unchanged         | Unchanged                                                   |
| Valid but provider did not declare support                                                                                                       | Unchanged         | Suggestion ignored/rejected                                 |
| Malformed, cyclic/oversized, unknown property/version/discriminant, request mismatch, stale issuance, or unsupported target/scope namespace/kind | Unchanged         | Suggestion rejected                                         |
| Bound is invalid or cannot be enforced                                                                                                           | Unchanged         | Suggestion rejected or tightened; never installed unbounded |
| Baseline source authentication fails, or widening/mixed/unknown impact lacks stronger required provenance                                        | Unchanged         | Suggestion rejected                                         |
| Native parse, validation, persistence, or audit fails                                                                                            | Unchanged         | No rule becomes active                                      |
| Same idempotency key is replayed                                                                                                                 | Unchanged         | Prior state returned; TTL/uses not reset                    |
| Valid and accepted                                                                                                                               | Unchanged         | Native rule affects only later evaluations                  |
| Installed rule expires, exhausts uses, or is revoked                                                                                             | Unchanged         | Host-native lifecycle removes/disables it                   |

This independent validation deliberately differs from the current macts #111 local SPI, where a
malformed suggestion makes the whole provider response malformed. Structural separation is
stronger: malformed optional policy advice cannot erase or manufacture what the human decided.

### 6.5 L3 conformance cases

The harness MUST prove that the L0 result is byte/reference-identical whether the suggestion is
absent, valid, malformed, unsupported, or rejected; validate namespace/version/kind and bounded
JSON; compile a suggestion-capable provider through the L0 provider constraint; reject unknown
policy-affecting properties; bind suggestion/request/target; preserve separate decision and
suggestion evidence; exercise every bound; reject silent bound dropping; make replay idempotent
without resetting TTL/uses; require host-native application; classify unknown/mixed impact as
widening at the target; reject
missing baseline or widening provenance; and verify atomic use count, expiry, and revocation through
adapter-owned tests.

---

## 7. Runtime guards and diagnostics

The implementation should be small enough to audit. It needs guards and normalizers for standard
fields, terminal composition, and optional conformance fixtures—not a framework.

All entrypoints follow these rules:

- Treat values crossing a provider/plugin/process boundary as `unknown` at runtime.
- L0–L2 accept unknown additive object properties but reject unknown discriminants and versions.
  L3 policy-affecting records are closed-world and reject unknown properties as well as unknown
  discriminants and versions.
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
requires those two independent consumers, frozen L0–L3 fixtures, declaration-graph tests, and the
complete fail-closed conformance suites.

During `0.x`, patch releases preserve the current minor contract; a new minor MAY make a breaking
design correction called out in release notes. Consumers SHOULD pin a compatible minor with `~`
until 1.0. Provider registration MUST compare `apiVersion` explicitly rather than assuming that an
installed npm version implies runtime compatibility.

After 1.0:

| Change                                                                                                                                                             | SemVer treatment                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------- |
| Bug fix that preserves valid accepted values and public types                                                                                                      | patch                                    |
| New explicitly non-authoritative optional metadata field, guard/helper, conformance fixture, or independent subpath                                                | minor                                    |
| New union/discriminant member, new required field, changed default/failure behavior, moved symbol, removed/renamed field, or newly rejected previously valid value | major                                    |
| New L3 policy constraint, bound, or other policy-affecting field                                                                                                   | major plus a new runtime `schemaVersion` |

Adding a union member is major because exhaustive consumers would otherwise compile against an
incomplete decision set. Unknown additive object fields remain accepted in L0–L2 so compatible
producers can deploy non-authoritative optional fields before consumers. L3 policy-affecting
records remain closed-world. Unknown versions and discriminants remain fail-closed everywhere.

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
3. Implement, publish, and stabilize `hitl-policy` in
   [github.com/mike-north/hitl-policy](https://github.com/mike-north/hitl-policy), tracked under
   [#220](https://github.com/mike-north/allw/issues/220), after this spec is approved.
4. Migrate macts under #114 **after #112**, in one mechanical change:
   - neutralize L0 permission/API-key names through adapter types;
   - map macts's already-contextualized `allowed | confirm-first | denied` directly into L2 rather
     than forcing its native evaluator through L1;
   - move `layer` and `supportsDistinctRouting` to L2;
   - move `policySuggestion` and `supportsPolicySuggestions` to L3;
   - retain macts's native risk classes, dispositions, rules, restrictions, and audit schema; and
   - preserve request ids, sanitized failures, and durable-audit-before-execute while keeping the
     #111 fail-closed/audit regression suite green. If downstream compatibility exists by then,
     retain deprecated macts-local aliases for one release.
5. Implement the allw adapter under #219. It maps only a fully verified allw approval to L0
   `approved`; `denied` and signed `aborted` map to `rejected`; `expired` maps to `timeout`; SDK
   errors map to `rejected`; the signed verdict remains opaque decision evidence and a separately
   signed policy rule remains opaque suggestion evidence.
6. Make #183 a thin macts specialization of #219. If it ships first against local macts types,
   migrate both in the same compatibility window.

Migrating macts before #112 would move the local SPI once and immediately move the policy-layer
attribution again. Waiting makes the boundary change mechanical. Claude Code, Codex, OpenClaw, and
MCP keep their native external contracts; their allw integrations are adapters, not migration
targets.

---

## 10. Package implementation acceptance criteria

The follow-on package issue is complete only when it delivers:

- the five subpath exports and no root barrel;
- zero runtime dependencies and no allw/core/crypto/native imports;
- fully documented types corresponding to the sketches above;
- bounded runtime guards and safe L0/L1 invocation helpers;
- terminal-only L2 composition, full layer provenance, distinct approval requirements, and primary
  governing-layer attribution;
- provider-facing L2 requests that carry only one requirement plus sanitized JSON display context,
  never arbitrary host-native evaluation details;
- a type-compatible L3 provider/envelope and independent invocation guard;
- closed-world, independently guarded/idempotent L3 suggestions with explicit request/target
  binding, separate suggestion evidence, and no policy-application helper;
- type/declaration tests proving the dependency graph;
- L0–L3 conformance fixtures and every failure case in this document;
- a WASM-under-node/browser import smoke test; and
- package documentation that states the effective-allow conjunction and one-shot/suggestion
  invariants before any quickstart example.

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
