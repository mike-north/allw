# HITL seam decision log

**Status:** proposed with [the HITL-seam specification](./hitl-seam.md), tracked by
[#218](https://github.com/mike-north/allw/issues/218). Prior-art behavior was checked against the
primary sources linked in the spec on 2026-08-25.

This log records why the common contract differs from its source systems. It is intentionally
separate from the normative specification: a future change can replace a decision here only if it
updates the owning section of [hitl-seam.md](./hitl-seam.md) in the same change.

---

## D1 — Four structurally independent layers

> **Superseded 2026-08-27 by the repo architecture ruling.** Layering is now **behavioral**: one
> `createGate(...)` surface with optional `policy`, `hitl`, and `policyChanges` adapters, exported
> from a root barrel plus `./conformance`. The adoptability requirement below is unchanged and is
> met by adapter optionality; what is lost is the build-time enforceability the declaration-graph
> tests provided, replaced by the adapter-optionality conformance requirements in
> `hitl-seam.md` §2.2. The rest of this entry records the original reasoning.

**Chosen:** L0 decision and L1 policy are leaf entrypoints; L2 imports both; L3 imports L0/L2. The
package has no root barrel.

**Rejected:** one `ApprovalProvider` request/result containing policy layer, policy suggestion, and
every capability flag as optional fields.

**Why:** macts #111's combined SPI is a successful local seam, but it makes a human-decision-only
consumer import policy vocabulary and makes a policy-only consumer import provider types. Claude
Code, Codex, OpenClaw, MCP, XACML, OPA, Cedar, and Kubernetes also show that policy evaluation,
prompt transport, and durable grants are separate mechanisms. Declaration-graph tests make the
independence enforceable rather than aspirational.

**Consequence:** migrating macts deliberately moves `layer`/distinct routing to L2 and suggestions
to L3. L0 remains a complete, useful HITL interface on its own.

---

## D2 — `hitl-policy`, standalone and unscoped, with provider-neutral exports

**Chosen (2026-08-25):** publish as the unscoped **`hitl-policy`** from the standalone repo
[github.com/mike-north/hitl-policy](https://github.com/mike-north/hitl-policy). allw #218 remains
the allw-side tracking anchor only; the contract does not live in the allw repo.

**Rejected:** an `@allw`-scoped name (`@allw/hitl-seam`, `@allw/hitl-contract`), an unowned
`@hitl/*` scope, or pretending the package has independent governance before it does.
`@allw/hitl-contract` was separately rejected because “contract” is easily confused with allw's
cryptographic wire contract.

**Why:** the contract is meant to be adopted by hosts with no allw relationship, and an
`@allw`-scoped name reads as an allw artifact whatever the exports say. Provenance and release
authority come from the standalone repo rather than from a vendor scope. `policy` names the problem
domain more directly than `seam`, which described the boundary from allw's side.

**Noted and overruled:** an owned scope forecloses namespace squatting on a bare name and signals
supply-chain ownership. Real, but outweighed — the name is the first thing an adopting host sees,
and the squatting exposure is addressable by holding the bare name (see Consequence).

**Consequence:** all exported types avoid allw branding. The bare npm name must be claimable, or
already claimed by the owner, before first publish — checked 2026-08-27, `hitl-policy` is published
at `0.0.0` under maintainer `northm <michael.l.north@gmail.com>`, so it is held; re-verify before
the first real release, since unpublishing the placeholder would make it re-registrable by anyone.
A later transfer to independent governance requires an explicit migration rather than an ambiguous
parallel package.

---

## D3 — L0 contains a human decision, never `allow`

**Chosen:** `approved | rejected | timeout`, nested under `DecisionResult.decision`, with
negative-only failure categories and opaque optional evidence.

**Rejected:** `allow | deny`, an `approved` boolean beside a state discriminant, or a reusable scope
on the decision.

**Why:** allw's central invariant is that the primitive reports what the human decided and callers
compute the final conjunction. macts #111's hardened discriminated outcome removed contradictory
boolean/state representations. Browser, polkit, sudo, Claude Code, Codex, and OpenClaw “remember”
flows all persist separate state rather than making the immediate answer a sound bearer grant.

**Consequence:** provider adapters cannot accidentally claim ambient authorization. allw maps only a
fully verified verdict to `approved`; the contract leaves provider-specific proof opaque. Provider
failure can normalize to `rejected` without being misreported in audit as an explicit human “no.”

---

## D4 — Provider failures normalize inside a safe helper

**Chosen:** a host-owned deadline and abort signal; the helper never rejects; throw/malformed/load
failure becomes rejected and deadline becomes timeout.

**Rejected:** requiring every caller to race its own timer, trusting TypeScript types at a plugin
boundary, copying exception text to clients, or treating silence as consent.

**Why:** macts #111 already tests this complete behavior. Claude Code and Codex command hooks show
the danger of a host boundary that treats a failed gating process as nonblocking. OpenClaw's default
deny, deny-biased XACML, Cedar default deny, and Kubernetes `failurePolicy: Fail` are useful
restrictive precedents, while their documented fail-open modes show why the common default must be
normative.

**Consequence:** an adapter can be internally conforming while its external host hook is not. It
must disclose that residual rather than claim end-to-end fail-closed coverage.

---

## D5 — L1 preserves `no-match`; failures are `deny`

> **Superseded 2026-08-27.** There is no `no-match` in the ruled design. An adapter resolves its own
> no-match and reports how it resolved it through `source: "directive" | "default"`, which keeps the
> distinction auditable. The safety half — never infer allow from an absent match — is preserved by
> construction, since an adapter with no applicable rule must return an explicit `allow` or `deny`.
> What moves to the adapter is the guarantee that the default was _configured_ rather than assumed.
> Failures still never present as a successful evaluation; they surface as `policy-error`.

**Chosen:** `allow | deny | no-match`; a successful no-match needs an explicit caller fallback,
while evaluation/transport/malformed failures normalize to deny.

**Rejected:** collapsing no-match into deny inside every evaluator, equating OPA `undefined` with
no-match, or letting an absent fallback imply allow.

**Why:** XACML distinguishes `NotApplicable` from `Indeterminate`; OPA distinguishes undefined from
errors; Cedar's diagnostics can expose “no determining policy” even though its final result is deny.
An explicit no-match is necessary for policy overlays, but it is not evidence that a policy loaded
and failed safely.

**Consequence:** L1 allows either explicit allow or deny as a no-match default. L2 additionally
allows explicit ask. Invalid or missing defaults deny.

---

## D6 — L2 composes only terminal evaluations

> **Superseded 2026-08-27.** The seam no longer composes layers at all. A gate has one
> `PolicyAdapter` returning one evaluation; multi-layer composition — the `allow < ask < deny`
> lattice, governing-layer attribution, per-layer provenance — is now host-internal. The seam
> retains only requirement normalization within a single `ask` (`hitl-seam.md` §5.2): coalescing on
> matching `authorityId` **and** `approvalKey`, conjunction across distinct authorities, and
> `route-conflict` on two explicit routes. The macts counterexample below is why an adapter must
> still evaluate before composing, so the reasoning survives the move.

**Chosen:** terminalize each layer, then take the strictest `allow < ask < deny`; broader layers
come first and win a tie only as the primary explanation. Every raw ask remains in the retained
layer provenance; approval requirements are actionable only when the composed result is `ask`.

**Rejected:** ordering source dispositions, merging rule sets/globs across host boundaries, or
letting a narrower allow replace a broader deny.

**Why:** macts #112 demonstrates the counterexample. `read-only` permits a read and denies a write;
`confirm-first` asks for both. No fixed declaration ordering preserves both outcomes. Cedar
forbid-overrides and Kubernetes terminal validation support restrictive composition, but the
actual extracted algorithm and attribution come from macts terminal results.

**Consequence:** a narrower layer can only tighten. The host retains its native risk, scope, glob,
and restriction algebra. Ask layers coalesce only when the host gives them the same canonical
approval-authority id; different authorities remain separate conjoined L0 gates. Human answers do
not rewrite the composed evaluation to allow, and current policy is re-evaluated before execution.

---

## D7 — Policy routing is L2, not caller identity

> **Amended 2026-08-27.** The principle holds; two mechanisms changed. There are no provider
> capability flags — routing capability is expressed by whether `HitlAdapter.route` is supplied —
> and there is no sanitized `displayContext` channel, so a routed request carries `operation`,
> `summary`, `riskClass`, and its one `ApprovalRequirement` and nothing else. Fail-closed on an
> unroutable requirement is unchanged (`route-unavailable`).

**Chosen:** host-owned `approvalAuthorityId` and `routeId` on terminal layer evaluations and
`supportsDistinctRouting` in the L2 capability surface.

**Rejected:** macts's closed `host | key` `layer` field and routing capability on every L0 request
and provider.

**Why:** a caller identity is useful to every L0 provider; a policy layer that selects a distinct
approver is an escalation concern. Other hosts have different nesting and routing vocabularies.

**Consequence:** a plain L0 provider is valid. Different authorities never tie-collapse into one
approval. A required/mismatched route with no capable router fails closed rather than silently
reaching the wrong approver. Full host-native evaluation details remain host-side; each routed
provider request carries only its approval requirement and explicitly sanitized JSON display data.

---

## D8 — L3 is a companion envelope, validated independently

> **Superseded 2026-08-27 — direction inverted.** The provider no longer proposes a rule. The host
> authors a `PolicyChangeOffer` (options and/or a namespaced draft); the human picks or edits; the
> provider returns `PolicyChangeResponse` values on `DecisionResult.policyChanges`; the host's
> `prepare`/`apply` install it. This makes **host-applied-only structural** rather than merely
> normative — a provider cannot name a rule the host did not author.
>
> The core invariant below survives intact and is enforced: the decision is validated independently
> of the change batch, and a malformed batch is discarded whole while the valid one-shot decision is
> retained. Three properties this entry claimed do **not** yet exist in the ruled types and are
> tracked as gaps: change-specific evidence (so allw's separately signed rule artifact currently has
> no carrier), an explicit request/target binding beyond positional association, and replay
> idempotency. Generation staleness replaces the last of these only partially — it blocks applying
> against changed policy, but does not dedupe a repeated response.

**Chosen:** `DecisionWithPolicySuggestion` holds a complete L0 result and an optional sibling
suggestion. The suggestion has its own id, request/target binding, issuance time, evidence, and
guard.

**Rejected:** putting suggestion fields inside `DecisionOutcome`, invalidating the decision when an
optional suggestion is malformed, or letting a provider apply policy directly.

**Why:** the current macts #111 response invalidates the whole provider response for a malformed
suggestion. That is safe but contradicts the stronger invariant “suggestion is not decision.”
allw's verdict and separately signed policy rule, browser permission-store entries, Codex/Claude
settings rules, and OpenClaw allowlists all demonstrate separate lifecycle objects.

**Consequence:** suggestion failure never manufactures an approval and never erases a genuine
rejection/timeout/approval. The one-shot verdict cannot be reused as standing-rule authority; allw
places its separately signed rule artifact in suggestion evidence. Replay is idempotent and cannot
reset TTL or uses. The L3 envelope structurally extends a valid L0 result, so a suggestion-capable
provider satisfies the L0 provider constraint while the L3 helper validates the sibling field
independently.

---

## D9 — Minimal namespaced scope envelope, host-owned semantics

> **Partly superseded 2026-08-27.** The namespaced envelope survives as `PolicyDraft`
> (`{ namespace, kind, value, display? }`) — still host-owned semantics, still not a universal
> selector language. Removed: the separate target/scope split, the per-descriptor `schemaVersion`,
> and the common `PolicyBounds` (`ttlMs`, `maxUses`, time window). Bounds are now whatever a host
> encodes inside its own `draft.value`, which means the seam cannot detect a dropped bound — the
> "never dropped" rule remains normative for hosts and is listed as a gap. Closed-world guarding of
> policy-affecting records also remains normative but is not yet enforced.

**Chosen:** separate target and scope descriptors shaped as
`{ namespace, schemaVersion, kind, value: JsonValue, display? }`, plus common conjunctive `ttlMs`,
`maxUses`, and an absolute half-open time window.

**Rejected:** bare `unknown`; a universal selector/capability language; or common command/MCP/path
matching semantics.

**Why:** bare `unknown` cannot be versioned, guarded, routed, or rejected deterministically. A
universal policy language would import macts/allw-specific semantics and prematurely build allw's
explicitly deferred capability-inference tier. Browser permissions and polkit show that scope and
lifetime must be explicit; polkit `_KEEP` shows how an under-scoped action+subject cache becomes a
security footgun.

**Consequence:** the package standardizes the envelope and bounds, not the selector. Each host owns
the target/scope parsers and native rule mapping. A key-scoped request cannot silently target host
policy. Unsupported bounds reject or tighten; they are never dropped. Policy-affecting L3 records
are closed-world so an older host cannot silently ignore a newer narrowing constraint.

---

## D10 — The host classifies widening and owns provenance

> **Amended 2026-08-27 — principle retained, mechanism absent.** "The host classifies widening, and
> mixed or unknown counts as widening" is unchanged and remains normative. But the ruled types carry
> no `effect` and no impact classification, and `PolicyChangeResponse` has no evidence slot, so the
> contract neither requires nor records the determination and there is nowhere to put
> widening-specific provenance. The offer model reduces the exposure — a provider can only pick
> among host-authored options — without removing it, since an `edit` response can still widen. Both
> are tracked as gaps against `hitl-seam.md` §6.2 invariants 3 and 4.

**Chosen:** the suggestion carries the desired effect/scope/bounds, but the host computes whether
the native before/after change is widening, tightening, mixed, or unknown. Mixed/unknown is
widening. Hosts may demand stronger provenance for widening.

**Rejected:** a provider-declared `direction: widening | tightening`, treating `deny` as always
tightening, or a common evidence schema.

**Why:** direction depends on current native policy and the full affected scope. `ask` can tighten
allow or widen deny; a narrower allow can be effectively masked by a broader deny but is still
widening at its own target layer. Providers cannot know every host policy state. allw's signed
policy rule is useful evidence but must not force crypto types onto non-allw providers.

**Consequence:** decision evidence and suggestion evidence are separate `unknown` slots; hosts
define assurance policy. Every suggestion needs baseline source authentication; failure of stronger
widening provenance rejects the suggestion only.

---

## D11 — Plain values, Unix milliseconds, bounded guards

**Chosen:** dependency-free JSON-safe operation/scope values, numeric Unix milliseconds, standard
`AbortSignal`, opaque evidence, and bounded runtime guards.

**Rejected:** JavaScript `Date` in the portable request, Node-only APIs, native addons, unbounded
recursive JSON validation, or allw-core/WASM types in the public declaration graph.

**Why:** macts's local `Date` is convenient in-process but not stable across JSON/WASM/plugin
boundaries. The package must work under Node and browser/WASM-local consumers with no binary
allowlisting consequence.

**Consequence:** host adapters translate native time/identity/action representations at their own
edge. Evidence can still be bytes or provider-native objects because the common package preserves
it opaquely.

---

## D12 — One package version, explicit runtime schemas

**Chosen:** Semantic Versioning for npm plus `apiVersion`/`schemaVersion` on boundary values; remain
0.x through macts and allw conformance, then publish 1.0.

**Rejected:** declaring 1.0 before two real consumers, relying only on TypeScript package versions,
or adding union members in a minor release.

**Why:** plugin/process boundaries can outlive one dependency graph. Unknown discriminants must
fail closed, and adding a discriminant breaks exhaustive consumers even when its producer sees it
as additive.

**Consequence:** explicitly non-authoritative optional metadata and new optional adapter slots are
minor; decision-union members, required fields, failure-default changes, removals, and new
policy-modification constraints are major after 1.0. Those constraints also require a new runtime
schema version so an older host can never ignore a narrowing field. Conformance fixtures are versioned with each supported major.
During 0.x, consumers pin `~`; patch preserves a minor, while a documented new minor may correct
the pre-1.0 design.

---

## D13 — Migrate macts after #112; allw implements the generic adapter first

**Chosen:** #111 lands with local types, #112 settles terminal composition, allw #220 publishes the
common package, then macts #114 migrates. allw #219 implements a generic adapter; #183 is a thin
macts specialization.

**Rejected:** blocking #111 on this package, migrating before #112, or making #183 the only allw
adapter.

**Why:** no external macts consumers require premature compatibility. Migrating before #112 would
rewrite the local SPI once for L0 and again to move layer attribution into L2. A generic allw
adapter proves allw is a provider of the seam rather than making the seam macts-shaped.

**Consequence:** existing #111 fail-closed/audit tests remain the migration regression bar. macts
maps its already-contextualized terminals directly at L2 and does not replace its native
restriction composition. Claude Code, Codex, OpenClaw, and MCP preserve their native surfaces and
use adapters only.

---

## D14 — Do not weaken exact binding for a lossy host seam

**Chosen:** an adapter that cannot obtain the exact operation a host will execute remains
unavailable or fails closed.

**Rejected:** approving a sanitized summary and calling it WYSIWYS, reconstructing omitted runtime
fields, or treating reviewer eligibility as access to a record.

**Why:** current OpenClaw record visibility means a generic external client cannot receive or
rehydrate the canonical `systemRunPlan`; the sanitized lookup omits it. That invalidates the
existing bridge's scope-only subscription premise. The correct response is an upstream reviewer
binding/projection change, not a weaker common request identity.

**Consequence:** the prior-art appendix records this drift. It does not change the L0 contract or
turn the package implementation into an OpenClaw repair project.
