# OpenClaw Integration — allw as a Native Approval Client

**Status:** design spec. No implementation lands from this document; the bridge package is tracked
separately and is decomposed in §Implementation slices below.

[OpenClaw](https://github.com/openclaw/openclaw) is a self-hosted gateway that connects chat
channels to AI coding agents. It already has a mature approval subsystem with a first-class seam for
external approvers: a dedicated `operator.approvals` auth scope, kind-agnostic durable approval RPCs,
and broadcast events for every pending approval. This document specifies how allw sits in that seam
— as a **gateway operator client** that turns each pending OpenClaw approval into a verified human
decision from the allw inbox.

Companion reading: [contract.md](./contract.md) (the invariants this must honor),
[policy-seam.md](./policy-seam.md) (the `ActionRecord`), [architecture.md](./architecture.md) (the
WASM-under-node constraint), and [codex-integration.md](./codex-integration.md) (the sibling
integration whose actor-identity and timeout-ordering discipline this follows).

---

## 1. Verified upstream contract

Every claim below was checked against OpenClaw's published documentation, its generated protocol
schema, and its source on **2026-08-23**. Anything this spec depends on that is _not_ in this table
is a fact the implementation must re-verify before relying on it.

| Fact                                                                                                                                                                               | Source                                                                                                                                                                                 |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `operator.approvals` is a closed-set operator scope meaning "Exec and plugin approval APIs". `operator.write` does **not** subsume it.                                             | [operator-scopes](https://docs.openclaw.ai/gateway/operator-scopes), [`src/gateway/operator-scopes.ts`](https://github.com/openclaw/openclaw/blob/main/src/gateway/operator-scopes.ts) |
| Approval RPCs: `exec.approval.request` / `get` / `list` / `waitDecision` / `resolve`; `plugin.approval.request` / `list` / `waitDecision` / `resolve`.                             | [gateway protocol](https://docs.openclaw.ai/gateway/protocol)                                                                                                                          |
| Kind-agnostic durable RPCs: `approval.get { id }`, `approval.resolve { id, kind, decision }`, `approval.history`. The legacy per-kind methods are adapters over the same registry. | [gateway protocol](https://docs.openclaw.ai/gateway/protocol), [multi-surface operator approvals](https://docs.openclaw.ai/refactor/operator-approvals)                                |
| Broadcasts: `exec.approval.requested` / `resolved`, `plugin.approval.requested` / `resolved`, scope-gated to `operator.approvals`.                                                 | [gateway protocol](https://docs.openclaw.ai/gateway/protocol)                                                                                                                          |
| `ApprovalKind` is **three** values: `exec`, `plugin`, **`system-agent`**.                                                                                                          | [`protocol.schema.json`](https://unpkg.com/@openclaw/gateway-protocol@beta/protocol.schema.json)                                                                                       |
| `ApprovalDecision` is `allow-once` \| `allow-always` \| `deny`. `deny` is always present in `allowedDecisions` ("so malformed or unsafe input can fail closed").                   | [`protocol.schema.json`](https://unpkg.com/@openclaw/gateway-protocol@beta/protocol.schema.json)                                                                                       |
| The gateway **rejects a resolve for any decision the request did not offer**.                                                                                                      | [plugin permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests)                                                                                              |
| Resolution is **first-answer-wins** compare-and-set; a losing resolve returns `applied: false` plus the recorded canonical winner.                                                 | [multi-surface operator approvals](https://docs.openclaw.ai/refactor/operator-approvals)                                                                                               |
| For `host=node`, `exec.approval.request` **must** include a canonical `systemRunPlan`; the forwarded `system.run` reuses that stored plan.                                         | [gateway protocol](https://docs.openclaw.ai/gateway/protocol), [exec approvals](https://docs.openclaw.ai/tools/exec-approvals)                                                         |
| A caller that mutates `command`, `rawCommand`, `cwd`, `agentId`, or `sessionKey` after the approval was requested has the run **rejected** as an approval mismatch.                | [exec approvals](https://docs.openclaw.ai/tools/exec-approvals)                                                                                                                        |
| `askFallback` defaults to `deny`; a required prompt with no reachable UI resolves by that fallback. Approval timeout is a terminal host-command denial.                            | [exec approvals](https://docs.openclaw.ai/tools/exec-approvals), [exec approvals — advanced](https://docs.openclaw.ai/tools/exec-approvals-advanced)                                   |
| Pending exec approvals expire after **30 minutes** by default (`DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 1_800_000`).                                                                    | [`src/infra/exec-approvals-core.ts`](https://github.com/openclaw/openclaw/blob/main/src/infra/exec-approvals-core.ts)                                                                  |
| Plugin approvals default to **120 000 ms**, capped at **600 000 ms**.                                                                                                              | [`src/infra/plugin-approvals.ts`](https://github.com/openclaw/openclaw/blob/main/src/infra/plugin-approvals.ts)                                                                        |
| Third-party clients pair with an Ed25519 device identity + `connect.challenge`, then persist `hello-ok.auth.deviceToken`. Current wire protocol is **4**.                          | [building a gateway client](https://docs.openclaw.ai/gateway/clients)                                                                                                                  |
| The established "native approval client" pattern for Slack/Discord/Telegram/Matrix lives in `src/plugin-sdk/approval-client-helpers.ts` with `channels.<channel>.execApprovals.*`. | [`approval-client-helpers.ts`](https://github.com/openclaw/openclaw/blob/main/src/plugin-sdk/approval-client-helpers.ts)                                                               |

Two premises that the original scoping got wrong, and which this spec corrects:

1. **There are three approval kinds, not two.** `system-agent` exists and carries its own
   presentation (`title`, `description`, `proposalHash`, `allowedDecisions: ["allow-once", "deny"]`).
   §5.3 handles it explicitly so an unknown kind can never pass silently.
2. **The reviewer projection is sanitized.** `ApprovalPresentation` for exec deliberately omits
   "runtime cwd, environment, system-run binding, and execution plan". The full runtime request —
   including `systemRunPlan` — travels only on the legacy `*.approval.requested` event payload,
   whose shape is **not** pinned in the generated protocol schema. §6 defines the WYSIWYS plaintext
   accordingly and fails closed when the two sources disagree.

---

## 2. Integration shape: an external operator client

**Decision: allw connects as its own OpenClaw gateway operator client** — a separate `node` process
holding exactly `operator.approvals` — not as an in-gateway OpenClaw plugin.

```
 OpenClaw agent ── exec / plugin tool call
        │
        ▼
 OpenClaw Gateway ──── exec.approval.requested ─────▶ allw-openclaw-bridge  (operator.approvals)
   (enforcement)  ◀─── approval.resolve ────────────       │  node + WASM
                                                            ▼
                                                     @allw/sdk ── E2EE relay ── approver device
```

Why this shape and not an OpenClaw plugin (the Slack/Discord path):

- **Trust-domain separation.** A plugin runs inside the gateway process. allw's actor key, relay
  device token, and account trust anchor would then live in the same address space as the runtime
  whose actions they gate — an agent that compromises the gateway would hold the approval
  credentials too. An external client keeps the approval path outside the gated blast radius.
- **The plugin SDK's helper is a channel-delivery helper.** `createChannelExecApprovalProfile`
  resolves per-channel enablement, approver identity, and prompt suppression for chat transports. It
  is the right abstraction for "post the prompt into Slack"; it is not an approval-verification
  seam. allw's approval path is a signed verdict, not a chat message.
- **The external path is the documented, supported contract.** OpenClaw publishes
  `@openclaw/gateway-client` + `@openclaw/gateway-protocol`, a generated `protocol.schema.json`, a
  wire-version policy, and a "minimal scopes for third-party clients" section that names
  `operator.approvals` for exactly this use. Plugin internals carry no such compatibility promise.
- **It works against a remote gateway.** A plugin can only gate the gateway it is installed in; an
  operator client can serve a gateway on another host over the same authenticated WebSocket.

The cost of this choice is that allw is a **reviewer surface, not an interception point** — see §3.

## 3. Coverage boundary: what allw can and cannot gate

OpenClaw's gateway remains the enforcement point. allw contributes a verified human decision to an
approval OpenClaw had already decided to raise. **allw cannot gate an action OpenClaw never asks
about.** That is a property of the seam, not a defect, and it is the same composition the contract
describes: `effective_allow = openclaw_policy ∧ human_decision ∧ verified` ([contract.md](./contract.md)
§Invariants #6).

Operator configuration prerequisites for the bridge to be a meaningful gate:

| Setting                                              | Required value          | Why                                                                                                                                                                |
| ---------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tools.exec.mode`                                    | `ask`                   | `full`/`allowlist`/`deny` never prompt. **`auto` is not acceptable**: it routes misses through OpenClaw's native auto-reviewer, which can approve without a human. |
| host approvals `ask`                                 | `always` (or `on-miss`) | `always` also defeats pre-existing `allow-always` durable trust, so every command reaches a human.                                                                 |
| host approvals `askFallback`                         | `deny` (the default)    | If the bridge is down, unroutable prompts must still fail closed.                                                                                                  |
| `autoAllowSkills`                                    | `false`                 | Skill-referenced executables are otherwise implicitly allowlisted on nodes and never prompt.                                                                       |
| `tools.exec.strictInlineEval`                        | `true`                  | Forces `python -c` / `node -e` style inline-eval carriers to an explicit approval instead of riding an allowlisted interpreter.                                    |
| `approvals.exec.enabled`, `approvals.plugin.enabled` | `false` (recommended)   | See the first-answer-wins note below.                                                                                                                              |
| `channels.<channel>.execApprovals.enabled`           | `false` (recommended)   | Same.                                                                                                                                                              |

**First-answer-wins interacts with fail-closed.** OpenClaw resolves an approval with a
compare-and-set: the first surface to answer is the canonical winner and no later answer mutates it.
The bridge fails closed on its own deadline (§8), so a bridge `deny` can pre-empt a slower human at
the Control UI or in Slack. This is correct — a deny can only tighten — but it makes the deployment
rule explicit: **when the bridge is the intended gate, disable competing approval surfaces.** If
they stay enabled, the operator has accepted a race whose worst case is a denial.

Conversely, when another surface wins first, the bridge's `approval.resolve` returns
`applied: false` with the recorded winner. The bridge **always** honors the returned canonical
record and never re-submits (§7.4).

---

## 4. Gateway client: scopes, pairing, and subscription

### 4.1 Scopes — `operator.approvals` and nothing else

The bridge requests `role: "operator"` with exactly `["operator.approvals"]`.

- It must **never** request `operator.admin`. Admin satisfies every `operator.*` scope, is required
  for config mutation and native hooks, and would let a compromised bridge rewrite the very exec
  policy it exists to enforce.
- It must **not** request `operator.read`. Read scope is what gates chat, agent, and tool-result
  broadcast frames; omitting it means the bridge never receives session content it has no business
  seeing. The four approval broadcasts are registered under `operator.approvals` directly.
- `operator.approvals` is remote-execution-grade authority in OpenClaw's own words. It is granted
  deliberately, to one paired device identity, and is revocable from the gateway host.

### 4.2 Pairing and credential handling

1. The bridge generates and persists an **Ed25519 device identity**.
2. It connects, waits for `connect.challenge`, uses the challenge's `ts` as the device proof's
   `signedAt`, and sends `connect` with the requested role, scopes, and the operator's shared
   bootstrap credential. A challenge without a non-negative integer `ts` is invalid — reject it
   rather than falling back to local time.
3. A structured `PAIRING_REQUIRED` response surfaces the request id; the operator approves it on the
   gateway host with `openclaw devices approve <requestId>`.
4. The bridge reconnects and persists `hello-ok.auth.deviceToken`, then authenticates with that
   device token from then on.

Rules that follow from OpenClaw's auth model:

- **Do not run the bridge on shared-secret auth.** Shared gateway token/password auth is treated as
  trusted operator access and restores the full default operator scope set on several surfaces even
  when the caller declares narrower scopes. The shared secret is a bootstrap step only; the
  long-lived credential is the paired device token.
- **Do not hand-edit `openclaw.json` to mint a token.** Pairing is the supported path.
- The device private key and device token are **secrets at rest**: they live in the same custody
  backend the allw approver uses, never a config file the operator edits, never an environment
  variable in a process list, never a log line. They are exactly the class of value
  [policy-seam.md](./policy-seam.md) §Network egress says belongs in a credential vault. Concretely,
  that backend is today an owner-only (`0600`) file under the bridge's state directory, matching
  `packages/approver/src/lib/keyfile.ts`'s v0 custody; swapping it for a real OS keystore is a
  follow-up that replaces one module and touches no gateway or protocol code.

### 4.3 Protocol version, capabilities, subscription

- **Pin the wire version.** Send `minProtocol: 4, maxProtocol: 4`. Operator clients must negotiate
  the exact current version; the N-1 acceptance window is for node clients and probes only. A
  version mismatch is a **startup failure**, not a degraded mode — a bridge that cannot parse
  approval frames must not appear to be gating.
- **Advertise only what is implemented**: the `approvals`, `exec-approvals`, and `plugin-approvals`
  client capabilities. Do **not** advertise `tool-events` — it opts the connection into live
  tool-execution streaming the bridge has no use for and should not receive.
- **Install the event listener before backfilling.** On every successful `hello-ok`, register the
  handlers for `exec.approval.requested` / `resolved` and `plugin.approval.requested` / `resolved`
  first, then call `exec.approval.list` and `plugin.approval.list` to pick up approvals that predate
  the connection. Reconcile the list against live events **by approval id** so a transition racing
  the backfill is neither lost nor resurrected.
  - **Consume the full record each list entry carries — never reduce it to a bare id.**
    `exec.approval.list` / `plugin.approval.list` are legacy methods (`since: "<=2026.7"` in the
    installed `@openclaw/gateway-protocol` schema) predating the kind-agnostic RPC redesign, so the
    schema does not pin a typed `Result` for them the way it does their successor,
    `approval.history` (`ApprovalHistoryResult.items[]` — full `…ApprovalSnapshot`-shaped records,
    structurally identical to `approval.get`'s own `ApprovalGetResult.approval`). That is the
    demonstrated convention for every other "list approvals" surface in this protocol version. When
    a list entry already carries a full record, use it directly and skip the otherwise-redundant
    `approval.get` round trip for that id; fall back to `approval.get` only for a bare-id entry.
- **Treat every reconnect as a fresh projection**, not a delta: re-backfill, re-reconcile, and drop
  any in-memory pending entry whose id the gateway no longer reports as pending.
- A dropped gateway connection while an allw request is in flight is a **fail-closed** condition:
  the bridge keeps the allw request open only until its deadline, and on reconnect re-reads the
  approval's canonical status before attempting any resolve (§9).

---

## 5. Request families and the `ActionRecord` mapping

### 5.1 Family 1 — exec approvals → `surface: "command"`

The canonical execution input is the event payload's `systemRunPlan`
(`{ argv, cwd, commandText, commandPreview?, agentId, sessionKey, policySnapshot?, mutableFileOperand? }`),
which the gateway stores at request time and reuses verbatim when forwarding the approved
`system.run`. That plan is therefore what the human must be shown.

| `ActionRecord` field    | Source                                                                              | Notes                                                                                                                       |
| ----------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `surface`               | constant `"command"`                                                                |                                                                                                                             |
| `syntactic.argv`        | `systemRunPlan.argv` → else `request.commandArgv` → else tokenize `request.command` | **Never re-tokenize when a canonical `argv` exists.** Re-parsing risks binding a different token vector than what executes. |
| `syntactic.bin`         | derived by the core from `argv[0]`                                                  | Core-derived; the bridge does not compute it.                                                                               |
| `syntactic.flags`       | derived by the core                                                                 | Same.                                                                                                                       |
| `syntactic.positionals` | derived by the core                                                                 | Same.                                                                                                                       |
| `syntactic.cwd`         | `systemRunPlan.cwd` → else `request.cwd` → else absent                              | Absent is rendered explicitly as "working directory not bound" (§6.3), never silently omitted.                              |
| `syntactic.raw`         | `systemRunPlan.commandText` → else `request.command`                                | The exact string OpenClaw shows its other reviewers; also what the core derives `env_refs` from.                            |
| `syntactic.host`        | core-derived from the command (ssh/scp target)                                      | **Not** OpenClaw's `host` field — see the name-collision note below.                                                        |
| `syntactic.env_refs`    | core-derived from `raw`                                                             | Names only; values are never captured.                                                                                      |
| `risk`                  | core `classify_risk`, floored at `high` when `request.warningText` is non-empty     | §6.4.                                                                                                                       |

**Name collision, called out so nobody wires it wrong:** OpenClaw's `host` on an exec approval is the
_execution locus_ (`gateway` \| `node` \| `sandbox`). allw's `syntactic.host` is the _remote host a
command targets_ (an ssh/scp destination). They are unrelated. OpenClaw's execution locus and
`nodeId` are decision-relevant and are carried in the hashed `summary` (§6.2), not in
`syntactic.host`.

### 5.2 Family 2 — plugin permission requests → `surface: "agent_tool_call"`

A plugin permission request carries `{ pluginId?, title, description, detail?, severity?, toolName?,
toolCallId?, allowedDecisions?, agentId?, sessionKey? }` on the untyped event. Its function identity
is the `(pluginId, toolName)` pair — structurally parallel to an MCP call's `(server, tool)` and to a
command's program name.

**The pinned `approval.get` presentation (`PluginApprovalPresentation`) is the canonical source**,
not the event (§6.1) — verified against the installed `@openclaw/gateway-protocol` schema: `title`,
`description`, `severity`, and `allowedDecisions` are schema-**required**; `detail`, `pluginId`,
`toolName`, `agentId` are schema-optional. Every field below is read from the snapshot first, the
event only when the snapshot omits it, and a value present on **both** that disagrees is a
`presentation-divergence` deny (§6.1, §9) — extended beyond `title`/`description` to every field the
two sources both carry, including `severity` (the sharpest case: a lower event severity must never
silently suppress a higher, canonical snapshot severity and its number-match challenge).

| `ActionRecord` field | Source                                                                     | Notes                                                                                   |
| -------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `surface`            | constant `"agent_tool_call"`                                               | New surface; see the decision below.                                                    |
| `syntactic.server`   | pinned `pluginId` → else event `pluginId` → else `"openclaw"`              | The gating provider identity — the function-identity slot, shared with `mcp_tool_call`. |
| `syntactic.tool`     | pinned `toolName` → else event `toolName` → else a slug of `title`         | Fail closed if neither yields a non-empty token.                                        |
| `syntactic.params`   | **absent**                                                                 | OpenClaw exposes no structured parameters to a reviewer. Do not synthesize one.         |
| `syntactic.raw`      | pinned `description`, plus pinned `detail` when present                    | The prose the plugin author wrote for the approver; display + fallback matching.        |
| `risk`               | pinned `severity`: `info`→`low`, `warning`→`medium`, `critical`→`critical` | `severity` defaults to `warning` upstream when genuinely absent from both sources.      |

**Decision: a new `agent_tool_call` surface, not `mcp_tool_call`.** `surface` is a permanent,
relay-visible (`action_structure`), policy-matchable namespace — the single most expensive kind of
name to get wrong. Most plugin permission requests are not MCP tool calls at all (OpenClaw's own
worked example gates a plugin-owned "deploy service" operation), and the bridge cannot isolate the
genuinely-MCP subset: Codex marks those with `_meta.codex_approval_kind: "mcp_tool_call"` inside the
harness runtime, and that marker never reaches an operator client. Filing the whole family under
`mcp_tool_call` would mean a future "allow any `mcp_tool_call` on server X" policy rule, the relay's
structure-based routing, and the T3 recognized-tool registry all sweep in things that are not MCP
calls — the category-wide-change failure mode `agent_tool_call` exists to avoid.
[policy-seam.md](./policy-seam.md) already reserves the name (`// interception paradigm (more added
as needed: agent_tool_call, delegated_fetch …)`), so this spends the reservation rather than
inventing a concept.

The new surface **reuses the existing `(server, tool)` function-identity fields** rather than adding
parallel `provider`/`tool` fields. That is a mild naming stretch — `server` holds a plugin id — but
it keeps one function-identity slot for the structure/data boundary to classify, keeps the relay's
`action_structure` shape unchanged, and adds no syntactic field that would need a new
structure-vs-data ruling ([policy-seam.md](./policy-seam.md) forward-compat requirement #5).

**Backfilled instances are driven faithfully — the pinned snapshot IS the canonical source.**
§4.3's backfill (`exec.approval.list` / `plugin.approval.list`) discovers approvals that predate the
connection with no untyped `*.approval.requested` event to read from. For a plugin approval, the
pinned `PluginApprovalPresentation` returned by `approval.get` (and by these list methods
themselves — see §4.3's `readApprovalList` note) is **not** limited to `title`/`description`: per
the installed `@openclaw/gateway-protocol` schema, `title`, `description`, `severity`, and
`allowedDecisions` are schema-**required** on this presentation, and `detail`, `pluginId`,
`toolName`, `agentId` are schema-optional. That is the same real data a live event's reconcile
cross-checks against — it is simply the _only_ source during backfill, so it is used directly as
canonical rather than merely as a cross-check. There is nothing to fabricate: `pluginId`/`toolName`
fall back to `"openclaw"`/`slug(title)` only when the _pinned presentation itself_ omits them (the
same fallback a live event gets when its own untyped payload omits them), and `severity` drives risk
exactly as it does for a live event.

A backfilled plugin approval therefore drives through the identical path a live event does,
including the identical fail-closed outcomes: `build-error` when the pinned presentation itself
carries neither a usable `toolName` nor a `title` that reduces to a usable slug (the substrate is
genuinely absent, not merely unobserved), and `presentation-divergence` when `approval.get` itself
is unreadable or reports the wrong kind. There is no longer a backfill-specific "leave it open"
case — denying or approving a backfilled plugin approval is exactly as informed as denying or
approving a live one.

This differs from a common but wrong intuition: a _synthesized_ event object built purely from the
snapshot (no live payload ever existed) might look like it is "missing" fields the live event
normally supplies (`toolCallId`, `sessionKey`) — but those are correlation-only (`chain`), never
required substrate, so their absence during backfill is a minor audit-correlation gap, not a
fail-closed condition.

### 5.3 Family 3 — `system-agent` approvals: out of scope, fail closed

`ApprovalKind` also admits `system-agent`, whose presentation is `{ title, description,
proposalHash, allowedDecisions: ["allow-once", "deny"] }` — an OpenClaw-internal proposal gate with
no syntactic substrate to reduce. v1 does **not** map it.

The bridge must handle it, and every future unknown kind, explicitly:

- Do not raise an allw request (there is nothing faithful to show).
- Do not resolve it either — silently denying another surface's approval would make the bridge a
  denial-of-service on approval families it does not understand.
- Log it as `unsupported-approval-kind` and leave it for the Control UI or another surface. If no
  surface answers, OpenClaw's own deadline and `askFallback: deny` still fail it closed.

Anything that is neither `exec`, `plugin`, nor a recognized future kind is treated the same way: the
kind is read from the **event family** (`exec.approval.requested` vs `plugin.approval.requested`) and
cross-checked against `approvalKind` on the payload — never inferred from an id prefix, which
OpenClaw explicitly forbids.

---

## 6. WYSIWYS: exactly what the human sees and signs

[contract.md](./contract.md) Invariant 4 binds the verdict to a single `request_hash` over the whole
human-shown payload. So "what the human sees" is not a UI question here — it is the definition of the
`ApprovalContext`, field by field.

### 6.1 Sourcing rule and the two-source reconcile

The bridge reads each approval from **two** places, and they are not interchangeable:

| Source                                                        | Contains                                                                                            | Schema-pinned?                                          |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `exec.approval.requested` / `plugin.approval.requested` event | `{ id, request, createdAtMs, expiresAtMs }` — the **full** runtime request incl. `systemRunPlan`    | **No** (`payload` is untyped in `protocol.schema.json`) |
| `approval.get { id }`                                         | The sanitized `ApprovalSnapshot`: `{ id, urlPath, createdAtMs, expiresAtMs, presentation, status }` | **Yes**                                                 |

Rule:

1. The event is the **carrier of record for the execution substrate** — `systemRunPlan`, `argv`,
   `cwd` — because the sanitized projection deliberately withholds them.
2. `approval.get` is the **authority for lifecycle and reviewer contract** — `status`,
   `expiresAtMs`, `allowedDecisions`, and the canonical id.
3. The bridge calls `approval.get` for every approval it intends to act on, **before** building the
   context, and reconciles: for every field **both** sources carry (exec: `commandText`; plugin:
   `title`, `description`), the event's value must equal the snapshot's, and `presentation.kind`
   must match the event family. A snapshot that **omits** a field is not a divergence — the
   sanitized projection is allowed to withhold — only a genuinely _different_ value is. A mismatch
   is a fail-closed `presentation-divergence` deny (§9) — it means the untyped event payload and
   the pinned projection disagree about what is being approved, and neither can be trusted to be
   what runs.
4. If `approval.get` reports a non-`pending` status, the bridge does not raise an allw request.

### 6.2 The `ApprovalContext`, per family

| `ApprovalContext` field | Exec approvals                                                                                      | Plugin permission requests                                                                 |
| ----------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `action`                | §5.1                                                                                                | §5.2                                                                                       |
| `summary`               | `OpenClaw <gateway-id> · <host>[/<nodeId>] · agent <agentId> · <commandText>[ · bound file <path>]` | `OpenClaw <gateway-id> · agent <agentId> · <pluginId>/<toolName>: <title> — <description>` |
| `actor.id`              | `openclaw:<gateway-id>` (§7)                                                                        | same                                                                                       |
| `actor.kind`            | `"openclaw"`                                                                                        | same                                                                                       |
| `risk`                  | §6.4                                                                                                | §6.4                                                                                       |
| `reversible`            | `risk ∈ {low, medium}`                                                                              | same                                                                                       |
| `constraints`           | `{ allowed_decisions: ["approved", "denied"], challenge_required: risk === "critical" }`            | same                                                                                       |
| `chain`                 | `["openclaw:<gateway-id>:approval:<approval_id>", "openclaw:session:<sessionKey>"]`                 | same, plus `"openclaw:tool_call:<toolCallId>"` when present                                |

Notes on the non-obvious choices:

- **`summary` carries the execution context.** `summary` is a first-class, hashed, human-shown field
  ([contract.md](./contract.md) §request_hash), so the execution locus (`host`, `nodeId`), the
  originating agent, and the gateway label are bound by the verdict without inventing a syntactic
  field for each. Unknown components render as the literal `unknown` rather than being dropped — a
  missing field must be visible, not invisible.
- **`chain` is the right home for the OpenClaw approval id.** The contract defines `chain` as
  "upstream-gate ids, audit correlation only", and an OpenClaw approval is precisely an upstream
  gate that allw is composing with. This mirrors the Codex hook's `chain: ["codex:tool_use_id:<id>"]`.
  It is included in `request_hash`, so a verdict cannot be replayed against a different approval id.
- **`allowed_decisions` is always `["approved", "denied"]`.** The allw verdict vocabulary is fixed;
  OpenClaw's `allowedDecisions` constrains what the _bridge_ may submit downstream (§7.3), not what
  the human may choose upstream.

### 6.3 What is deliberately not bound, and why that is safe

- **`mutableFileOperand.sha256` and `systemRunBinding.envHash`.** OpenClaw binds these itself and
  denies a run whose bound file or env drifted after approval. allw does not re-implement that check;
  the two gates compose (`effective_allow = ∧(all gates)`), and neither weakens the other. The
  bridge does surface the operand's `path` in the summary when present, so the human knows a
  concrete file is bound.
- **`policySnapshot`.** The allowlist rules in effect at request time are gateway policy state, not
  the action. Binding them would put an unbounded, frequently-changing blob inside the WYSIWYS hash
  for no decision value.
- **`commandSpans`, `commandAnalysis`, `commandPreview`.** Presentation hints for OpenClaw's own
  renderers. allw renders from the substrate it binds; consuming a second, unbound rendering would
  create exactly the context/action gap `request_hash` closes.
- **An absent `cwd`.** Rendered as an explicit "working directory not bound" line rather than
  omitted, so a weaker binding is visible to the human instead of looking like a normal request.

### 6.4 Risk, challenge, and reversibility

| Family | Risk                                                                                        |
| ------ | ------------------------------------------------------------------------------------------- |
| exec   | the core's `classify_risk` over the bound argv, floored at `high` when `warningText` is set |
| plugin | `severity`: `info` → `low`, `warning` → `medium`, `critical` → `critical`                   |

`challenge_required = (risk === "critical")`, which routes genuinely destructive actions through the
number-match challenge ([contract.md](./contract.md) §number-match challenge derivation).
`reversible = risk ∈ {low, medium}`, matching the Codex hook's `reversibleForRisk` helper — this is
deliberate cross-surface consistency, not an independent judgement.

### 6.5 Structure-not-data

The relay may see, at the default privacy tier, only the `action_structure` fields: `surface`, and
the function identity (`bin` for exec; `server` + `tool` for plugin approvals). Everything else —
`argv`, `cwd`, `env_refs`, `raw`, the summary, the OpenClaw approval id — is data and travels only
inside the JWE. Concretely, the relay learns "an `openclaw` actor is running `kubectl`", never which
cluster, which namespace, or in which directory. The split is enforced in the WASM core when the
envelope is constructed, not by the bridge ([architecture.md](./architecture.md)
§Structure-not-data boundary).

---

## 7. Actor identity and decision mapping

### 7.1 `openclaw:<gateway-id>`

Requests carry `actor.kind = "openclaw"` and `actor.id = "openclaw:<gateway-id>"`, so one allw inbox
distinguishes "OpenClaw on home-mini" from "Claude Code on devbox-1" and "Codex on devbox-1"
([codex-integration.md](./codex-integration.md) §Decision Mapping).

`<gateway-id>` is **operator-configured**, because the protocol offers no stable gateway identity:
`hello-ok.server` exposes `{ version, buildId?, connId }`, and `connId` is per-connection. The
bridge therefore requires an explicit label:

- Syntax: `[a-z0-9][a-z0-9._-]{0,62}`, matched after lowercasing and trimming.
- Missing, blank, or malformed ⇒ **the bridge refuses to start.** A silently-defaulted actor id
  would let two gateways collide in one inbox, which is an integrity problem, not a cosmetic one.
- The value is re-validated per request; a request that cannot produce a valid actor id is denied
  (`config-error`).

Like `codex:<hostname>`, this identity is **asserted, not yet cryptographically verified** — the
actor-key `attestation` slot is reserved and its enrollment is deferred
([contract.md](./contract.md) §Identity & keys). The inbox must present it as an asserted origin.

### 7.2 Verdict → OpenClaw decision

| allw outcome                                | OpenClaw decision | `terminal_reason` observed upstream |
| ------------------------------------------- | ----------------- | ----------------------------------- |
| verified verdict, `decision === "approved"` | `allow-once`      | `user`                              |
| verified verdict, `decision === "denied"`   | `deny`            | `user`                              |
| verified verdict, `decision === "expired"`  | `deny`            | `user`                              |
| verified verdict, `decision === "aborted"`  | `deny`            | `user`                              |
| any unverifiable / malformed / errored path | `deny`            | `user`                              |

`allow-once` is submitted **only** for a verdict that is approved **and** passed full verification
(signature chains to the configured account root, bound to this exact `request_id` and
`request_hash`, unexpired, nonce unseen, challenge satisfied when required). Verification failure is
a deny, never a skipped check.

### 7.3 `allow-always` maps to nothing — this is load-bearing

**The bridge never submits `allow-always`, under any circumstance.**

An allw verdict is one-shot and scope-free by construction ([contract.md](./contract.md) §Verdict:
"No `scope`/reuse field — standing autonomy lives in the policy layer, not the verdict"). OpenClaw's
`allow-always`, by contrast, writes durable standing trust: for exec it persists an argv-bound
allowlist entry (`source: "allow-always"` with a generated `argPattern`) into the host approvals
document, and for plugins it hands the plugin a decision it may persist however it chooses. Turning
a one-shot verdict into either would mean a single human tap silently authorizing an unbounded set
of _future, never-approved_ executions — a direct violation of the monotonicity invariant that a
verdict can only ever tighten (Invariant 6).

There is also no field to carry it. The allw device never offers a "don't ask again" affordance for
an OpenClaw request in v1, because `constraints.allowed_decisions` is `["approved", "denied"]` and
the `Verdict` type has nowhere to put a scope. The mapping is not "unsupported"; it is structurally
absent.

**Reserved future path (do not build here).** The only artifact allowed to widen standing autonomy
is a **signed `PolicyRule`** ([policy-seam.md](./policy-seam.md) §The approval → rule bridge),
produced by `policy_rule_from_approval` and verified the same way a verdict is. A later slice could
translate a verified rule (`effect: "allow"`, `tier: "syntactic"`, `provenance: "from_approval"`)
into an OpenClaw allowlist entry via the exec-approvals policy management RPCs — a separate,
explicit, signed, revocable artifact, submitted through `exec.approvals.set`, **never** through
`approval.resolve`. Two problems must be solved before that is built, and neither is solved here:
allw's `bounds` (`ttl`, `max_uses`, `time_window`) have no OpenClaw allowlist equivalent, so the
translation is lossy in the dangerous direction; and rule revocation would need to propagate to the
gateway's durable document.

### 7.4 Submitting the resolve

- Call `approval.resolve { id, kind, decision }` — the kind-agnostic method — passing the **exact
  canonical id** and the kind derived in §5.3. Never truncate an id, resolve a hash prefix, or infer
  kind from an id prefix.
- Before submitting `allow-once`, check it is present in the approval's `allowedDecisions`. If it is
  not (the schema permits `["deny"]` alone, and `["allow-always", "deny"]` is expressible), an
  approved verdict **cannot be faithfully expressed**: submit `deny` with reason
  `no-expressible-allow` and log loudly. Fabricating `allow-always` in its place is forbidden by
  §7.3; submitting nothing would leave the run hanging until OpenClaw's own fallback.
- `deny` is always available, so the fail-closed path is always expressible.
- Read the response: `applied: false` means another surface won. Honor the returned canonical record
  as authoritative, do not retry, and reconcile local state from it. A lost acknowledgement is
  resolved by re-reading with `approval.get`, never by re-submitting a decision.

---

## 8. Timeout budgeting: the nesting rule

The ordering invariant is the same one pinned for the Codex hook in
[#52](https://github.com/mike-north/allw/issues/52): **allw's deadline must fire strictly inside
OpenClaw's, with enough margin left for the verdict to travel and the resolve to land.** If OpenClaw
times out first, the human's decision is discarded and the outcome is OpenClaw's fallback rather
than a verified verdict.

OpenClaw's deadline is not a constant to hardcode — every approval carries an authoritative
`expiresAtMs` (defaults: 1 800 000 ms exec, 120 000 ms plugin, plugin capped at 600 000 ms). Derive
from it:

```
budget_ms  = expiresAtMs − now_ms − ALLW_DEADLINE_MARGIN_MS
timeout_ms = min(budget_ms, ALLW_OPENCLAW_MAX_TIMEOUT_MS)

if budget_ms < ALLW_OPENCLAW_MIN_TIMEOUT_MS  ⇒  resolve `deny` (`insufficient-budget`), raise no allw request
```

| Constant                       | Default   | Constraint                                                                                                                                                                                                                                        |
| ------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLW_DEADLINE_MARGIN_MS`      | `60_000`  | **Must exceed the SDK per-relay-fetch timeout** (`DEFAULT_FETCH_TIMEOUT_MS = 30_000`), so the final verdict fetch _and_ the `approval.resolve` round trip both complete inside it. Same 2× headroom the hook uses (`480_000 − 420_000 = 60_000`). |
| `ALLW_OPENCLAW_MIN_TIMEOUT_MS` | `15_000`  | Below this there is no realistic chance of a human decision; raising a prompt that is doomed to expire is worse than an immediate, explainable deny.                                                                                              |
| `ALLW_OPENCLAW_MAX_TIMEOUT_MS` | `420_000` | Operator-configurable cap, mirroring the hook's `MAX_TIMEOUT_MS`. Only ever lowers `budget_ms`.                                                                                                                                                   |
| `ALLW_FETCH_TIMEOUT_MS`        | `30_000`  | May only lower the SDK default, and must stay `< ALLW_DEADLINE_MARGIN_MS`. A configured value at or above the margin is rejected at startup.                                                                                                      |

Additional rules:

- The bridge **never extends** an OpenClaw deadline. It is not the requester and must not call
  `exec.approval.request` / `plugin.approval.request` with a larger `timeoutMs`.
- A configuration that would place allw's deadline at or after `expiresAtMs` is a **startup
  failure**, not a runtime warning.
- On an allw `expired` verdict, the bridge resolves `deny` immediately rather than waiting for
  OpenClaw's own expiry — a deterministic denial beats a fallback, and the margin exists precisely so
  that resolve lands in time.
- Timeout comparison uses the gateway's clock as authoritative for `expiresAtMs`
  (`now == expires_at_ms` is expired upstream); the bridge must not assume its own clock agrees, and
  should treat significant skew as a startup failure.

---

## 9. Fail-closed matrix

Every path either resolves to `deny` or leaves the approval for OpenClaw's own `askFallback` — never
to `allow-once`, and never to silence when the bridge could have denied. Reason codes are
machine-readable and mirror the Codex hook's `denyReason` categories so operators can triage without
parsing prose.

| Condition                                                                                                                             | OpenClaw decision | Reason code                           |
| ------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ------------------------------------- |
| Verified verdict `denied` / `expired` / `aborted`                                                                                     | `deny`            | `no-approval` / `timeout` / `aborted` |
| Verdict signature invalid, wrong account root, or revoked device                                                                      | `deny`            | `verify-error`                        |
| Verdict bound to a different `request_id` / `request_hash`                                                                            | `deny`            | `binding-error`                       |
| Verdict nonce already seen (replay)                                                                                                   | `deny`            | `replay`                              |
| Required number-match challenge response missing or wrong                                                                             | `deny`            | `challenge-error`                     |
| Event payload and `approval.get` snapshot disagree on `commandText`, `kind`, `title`, or `description` (whichever both sources carry) | `deny`            | `presentation-divergence`             |
| `commandText` empty, or no usable argv for an exec approval                                                                           | `deny`            | `build-error`                         |
| Plugin approval with neither `toolName` nor a usable title slug, or an unrecognized `severity`                                        | `deny`            | `build-error`                         |
| Remaining budget below `ALLW_OPENCLAW_MIN_TIMEOUT_MS`                                                                                 | `deny`            | `insufficient-budget`                 |
| `allow-once` not in `allowedDecisions` for an approved verdict                                                                        | `deny`            | `no-expressible-allow`                |
| Relay / network / SDK transport failure                                                                                               | `deny`            | `transport-error`                     |
| Gateway connection lost, not restored before the allw deadline                                                                        | _cannot resolve_  | `transport-error`                     |
| Invalid or missing `<gateway-id>`, relay config, or account root                                                                      | `deny`            | `config-error`                        |
| Unknown or unsupported `ApprovalKind` (incl. `system-agent`)                                                                          | _no resolve_      | `unsupported-approval-kind`           |

The two **non**-deny rows are deliberate:

- **Unknown kind** (§5.3): an unrecognized approval family is left for a surface that understands it.
  Denying another surface's approval family would make the bridge a denial-of-service on approvals it
  cannot even render. This applies identically whether the approval was discovered live or by
  backfill (§4.3) — a backfilled plugin approval otherwise drives through the exact same path a live
  one does (§5.2), so there is no separate "cannot render a backfilled instance" case.
- **Lost connection**: the bridge has no channel on which to submit anything. OpenClaw's own deadline
  plus `askFallback: deny` closes it, which is why §3 requires that fallback stay `deny`.

A connection lost and **restored while the approval is still `pending`** is _not_ a deny. The bridge
re-reads `approval.get`, and if the status is still `pending` and a verified approved verdict arrives
inside the remaining budget, `allow-once` is submitted normally. If `approval.get` reports any
terminal status, the recorded record is authoritative and nothing is submitted. Failing closed means
never inventing an allow — not discarding a human decision that is still valid.

Two residual fail-open risks the bridge cannot close, stated so nobody assumes otherwise:

1. **Coverage.** allw only sees approvals OpenClaw raises. A gateway configured with
   `tools.exec.mode: full`, `ask: off`, or `askFallback: full` executes without ever asking (§3).
2. **Bridge absence.** If the bridge is not connected at all, OpenClaw resolves by `askFallback`.
   That default is `deny`, which is correct — but an operator who set it to `full` has opted out of
   the gate entirely.

---

## 10. Packaging: WASM under `node`

The bridge is an **on-machine local surface** and inherits the hard constraint from
[architecture.md](./architecture.md) §Local execution: it runs the Rust core as **WASM under
`node`**, never as a standalone native binary.

- **No `napi`.** A napi addon is itself a native binary and re-creates the Santa/MDM
  binary-allowlisting problem the constraint exists to avoid. `node` is already approved on managed
  machines and a `.wasm` is just data it loads.
- **No packaged native executable** — no `pkg`, no single-file binary, no bundled `openclaw`
  companion binary. The bridge is `node dist/cli.js`, exactly like the Claude Code and Codex hooks.
- **Thin shell only.** All hashing, JWE/JWS, verdict verification, `ActionRecord` construction, and
  policy evaluation stay in `crates/allw-core` behind the WASM boundary. The bridge maps OpenClaw
  wire shapes to core inputs and back; it implements no crypto and no parsing the core already owns.
- `@openclaw/gateway-client`'s Node entry owns its own WebSocket transport, which is pure JS and
  adds no native dependency — verify this at slice time, and reject any transitive native addon.
- Native binaries remain confined to signed, store-distributed approver apps.

---

## 11. UAT checklist

The real-gateway UAT is **operator-run**, for the same reason the Codex UAT is: automating a live
agent runtime has already proven unreliable (a macOS malware-detection false positive on the Codex
binary), and the same caution applies to driving a real OpenClaw gateway. Repository automation
prepares the environment; the human drives OpenClaw.

Prepare with `scripts/uat-openclaw.sh` (built in the final slice, mirroring `scripts/uat-codex.sh`):
it builds the WASM + TS packages, starts a local relay, pairs a temporary `allw-approver` keyfile,
writes a throwaway OpenClaw config with `tools.exec.mode: ask` / `ask: always` / `askFallback: deny`
into a temp state directory, prints the pairing command for the operator to approve, and then runs
`allw-approver watch` in the foreground. It never starts the gateway itself.

Run these against a live gateway and record the result on the implementation issue:

1. **Approve path (exec).** Ask the agent to run a harmless gated command, approve on the second
   device, confirm the command runs and the gateway records `allow-once` with `terminal_reason: user`.
2. **Deny path (exec).** Ask for another gated command, deny on the device, confirm the command does
   not run and the agent's session receives the denial followup.
3. **Timeout path.** Lower `ALLW_OPENCLAW_MAX_TIMEOUT_MS`, leave the approval unanswered, confirm the
   bridge resolves `deny` **before** the gateway's own `expiresAtMs`, and that the recorded reason is
   the bridge's decision rather than an upstream timeout.
4. **Actor identity.** Confirm the inbox shows `openclaw:<gateway-id>`, distinct from a
   `codex:<hostname>` or Claude Code request raised on the same machine.
5. **Plan-divergence rejection.** After approving an exec request, mutate the command/cwd before the
   forwarded `system.run` and confirm the **gateway** rejects it as an approval mismatch — this
   proves the two bindings compose rather than overlap.
6. **Plugin permission request.** Trigger a plugin `requireApproval` hook, confirm the inbox renders
   `<pluginId>/<toolName>` with the plugin's title and description, and that approving lets exactly
   that one call proceed.
7. **`allow-once`-unavailable path.** Trigger a plugin request declaring
   `allowedDecisions: ["deny"]`, approve it in allw, and confirm the bridge resolves `deny` with
   `no-expressible-allow` rather than escalating to `allow-always`.
8. **Race with another surface.** With the Control UI also connected, resolve there first and confirm
   the bridge observes `applied: false`, adopts the recorded winner, and does not re-submit.

Comment template:

```md
Approve (exec): PASS/FAIL - command ran only after approval
Deny (exec): PASS/FAIL - command was blocked after denial
Timeout: PASS/FAIL - bridge denied before the gateway deadline
Actor identity: PASS/FAIL - inbox showed openclaw:<gateway-id>
Plan divergence: PASS/FAIL - gateway rejected the mutated run
Plugin approval: PASS/FAIL - plugin/tool identity and prose rendered; single call proceeded
allow-once unavailable: PASS/FAIL - denied with no-expressible-allow
Surface race: PASS/FAIL - applied:false honored, no re-submit
Notes:
```

Automated tests cover the same mapping and verification paths against a fake gateway speaking the
real frame shapes; this checklist is the remaining product proof that a live OpenClaw gateway
actually routes to allw and honors the result.

---

## 12. Implementation slices

The bridge is decomposed into six slices, each independently reviewable and each roughly ≤1000
changed lines. Slices 1 and 2 are core work that the bridge depends on; they can land in parallel
with each other but must precede slice 4.

**Landed:** slice 1 (`action_from_argv` carrying the original command text, exported to WASM and
UniFFI), slice 2 (the `agent_tool_call` surface in the core, plus an `action_from_agent_tool_call_with_raw`
builder so a plugin's reviewer prose can bind verbatim as `syntactic.raw` instead of a synthesized
display, and the SDK `Surface` union widening), and slices 3–6 for **both** the exec and the plugin
permission-request families, including the §11 UAT checklist's plugin rows.

The `action_structure` envelope field ([contract.md](./contract.md) §Messages) — the relay-visible
plaintext structure summary — is **not yet implemented in any surface** (the wire `ApprovalRequest`
envelope carries only `{ v, id, created_at, expires_at, approver, context_ciphertext }`). Building it
is a separate, materially larger slice than either family's mapping and is not required for either
family's fail-closed correctness: an unrecognized `Surface` string already fails to deserialize in the
Rust core rather than being silently accepted. Tracked separately from this document.

| #   | Scope                                                                                                                                                                                                                                                                                                                              | Deliverable                                                                                                                                                         | Tests                                                                                                                                                                                                                                                    |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Core: argv-with-raw command records.** `allw-core` already has `action_from_argv`, but it is not exposed to WASM and cannot carry the original command text (it sets `raw: None`, which also suppresses `env_refs` extraction).                                                                                                  | A core builder taking `(argv, raw, ctx)`; a WASM export `action_from_argv`; UniFFI parity per the return-type suffix convention; SDK/hook `wasm.ts` type additions. | Rust unit tests for argv+raw (incl. empty argv, `env_refs` from `raw`); a cross-platform vector proving Rust and WASM produce byte-identical records.                                                                                                    |
| 2   | **Core: the `agent_tool_call` surface.** Adds the `Surface` variant reserved in `policy-seam.md`, a builder over `(server, tool)` function identity, relay `action_structure` acceptance, and SDK `Surface` union widening.                                                                                                        | Core enum + builder, WASM + UniFFI exports, SDK types, relay validation, `docs/policy-seam.md` classification note.                                                 | Structure/data split test (server+tool are structure; `raw` is data); a negative test that an unknown surface string fails closed rather than defaulting.                                                                                                |
| 3   | **Bridge skeleton: gateway client.** New `packages/openclaw-bridge`; Ed25519 device identity, `connect.challenge` proof, `PAIRING_REQUIRED` handling, device-token persistence in the OS keystore, protocol pin, capability advertisement, subscription + `*.approval.list` backfill + reconnect re-projection. No allw calls yet. | A connectable, scope-minimal operator client that logs pending approvals.                                                                                           | Integration tests against a fake gateway WebSocket speaking real `RequestFrame`/`ResponseFrame`/`EventFrame` shapes; negatives for challenge without `ts`, wrong protocol version, scope downgrade, reconnect double-delivery.                           |
| 4   | **Mapping.** Event → `approval.get` reconcile → `ApprovalContext` construction for both families; deterministic summary templates; actor-id validation; risk/reversible/constraints derivation; `chain` correlation.                                                                                                               | Pure, I/O-free mapping module (the `decide.ts` analogue).                                                                                                           | Field-by-field assertions derived from §5/§6 of this spec (never from captured output); negatives for `presentation-divergence`, empty `commandText`, missing tool identity, malformed gateway id.                                                       |
| 5   | **Decision + resolution.** `requestApproval` wiring, full verdict verification, `approval.resolve` submission, `applied: false` reconcile, timeout budgeting, the complete §9 matrix.                                                                                                                                              | End-to-end fail-closed behavior.                                                                                                                                    | One direct negative test per §9 row, plus: `allow-always` is never submitted under any input; `no-expressible-allow`; `insufficient-budget`; gateway loss both not-restored and restored-while-pending; unsupported kind is neither approved nor denied. |
| 6   | **Operability + UAT.** `scripts/uat-openclaw.sh`, package README, structured logging that never emits plaintext context, and the operator-prerequisite checks from §3 surfaced as startup diagnostics.                                                                                                                             | Operator-runnable UAT and a bridge that refuses to start misconfigured.                                                                                             | Script test in the style of `scripts/uat-codex.test.mjs`; a startup-diagnostic test asserting refusal on `tools.exec.mode: auto` and on a margin below the fetch timeout.                                                                                |

Explicitly out of scope for all six slices: the `allow-always` → `PolicyRule` bridge (§7.3),
`system-agent` mapping (§5.3), and anything requiring `operator.admin`.

---

## 13. Open decisions

- **No integrator-side cancellation.** `@allw/sdk` has no `AbortSignal` in v0 — `aborted` originates
  only from a signed device verdict. So when OpenClaw resolves an approval at another surface first,
  the bridge cannot retract the pending allw prompt, and the human may decide a request that is
  already terminal. That is safe (the resolve returns `applied: false` and the recorded winner
  stands) but it is bad UX and it wastes a decision. Closing it needs an SDK cancellation path plus
  an integrator-initiated relay retract; both are outside this spec and should be filed separately.
- **Which gateway identity to standardize on.** `<gateway-id>` is operator-asserted today because the
  protocol exposes no stable gateway identity. If OpenClaw later surfaces one (or once work-stream
  attestation lands per [enrollment.md](./enrollment.md)), the asserted label should become a
  verified component rather than a second identity.
- **Whether the bridge should also consume `session.approval`.** The sanitized per-session projection
  requires a paired device plus `operator.approvals` and would give cleaner lifecycle tombstones than
  the legacy events. It is not needed for v1 and adds a subscription-authorization surface; revisit if
  event reconciliation proves fragile in practice.
- **Multi-gateway.** One bridge process serves one gateway. Fan-in (several gateways, one inbox,
  distinct `<gateway-id>` actors) is a deployment pattern, not a code feature, until proven otherwise.
