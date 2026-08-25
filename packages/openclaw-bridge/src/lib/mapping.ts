/**
 * Pure, I/O-free mapping: an OpenClaw exec approval → the allw `ApprovalRequest` the human decides.
 *
 * Nothing here touches the network, the clock, or the filesystem, so every assertion in
 * `test/mapping.test.mjs` is derived field-by-field from the spec rather than from captured output.
 *
 * The two load-bearing rules this module enforces:
 *
 * 1. **Never re-tokenize when a canonical `argv` exists** (spec §5.1). `systemRunPlan.argv` is the
 *    exact vector the gateway will reuse when it forwards the approved `system.run`; re-parsing the
 *    command text could bind a *different* vector than the one that executes.
 * 2. **Two-source reconcile** (spec §6.1). The untyped event payload carries the execution
 *    substrate; the pinned `approval.get` snapshot carries lifecycle and the reviewer contract. If
 *    they disagree about the command text or the kind, neither can be trusted and the approval is
 *    denied `presentation-divergence`.
 *
 * @see ../../../../docs/openclaw-integration.md §5.1, §6.1–6.4, §7.1
 * @see ../../../../docs/contract.md §request_hash (why `summary` is load-bearing)
 */

import type { HookWasm } from "@allw/hook";

import { actorIdForGateway, normalizeGatewayId } from "./config.js";
import { isExecPresentation, isPluginPresentation } from "./protocol.js";
import type {
  ApprovalSnapshot,
  ExecApprovalRequestedEvent,
  PluginApprovalRequestedEvent,
} from "./protocol.js";

/** Coarse risk tiers, in ascending order (the core's `Risk`). */
export type Risk = "low" | "medium" | "high" | "critical";

const RISK_ORDER: readonly Risk[] = ["low", "medium", "high", "critical"];

/**
 * Machine-readable fail-closed reason codes (spec §9). They mirror the Codex hook's `denyReason`
 * categories so operators triage both surfaces the same way.
 */
export type DenyReason =
  | "no-approval"
  | "timeout"
  | "aborted"
  | "verify-error"
  | "binding-error"
  | "replay"
  | "challenge-error"
  | "presentation-divergence"
  | "build-error"
  | "insufficient-budget"
  | "no-expressible-allow"
  | "transport-error"
  | "config-error";

/** The allw approval request the bridge submits (the `@allw/sdk` `ApprovalRequest` shape). */
export interface BridgeApprovalRequest {
  readonly action: {
    readonly recordSchemaVersion: number;
    /**
     * `command` for the exec family, `agent_tool_call` for the plugin family — asserted, not
     * assumed (spec §5.1, §5.2).
     */
    readonly surface: "command" | "agent_tool_call";
    readonly syntactic: unknown;
    readonly risk: Risk;
  };
  readonly summary: string;
  readonly actor: { readonly id: string; readonly kind: "openclaw" };
  readonly risk: Risk;
  readonly reversible: boolean;
  readonly constraints: {
    readonly allowedDecisions: readonly ["approved", "denied"];
    readonly challengeRequired: boolean;
  };
  readonly chain: readonly string[];
  readonly timeoutMs: number;
  /**
   * Integrator-initiated cancellation (issue #195, issue #222). `OpenClawBridge` arms an
   * `AbortController` per in-flight approval id and aborts it the moment it learns — via a
   * `*.approval.resolved` broadcast — that the SAME id was decided on another OpenClaw surface
   * first. Aborting tells `@allw/sdk` to retract the pending relay request so connected approver
   * devices drop the stale prompt live, instead of riding out the full timeout
   * (`docs/openclaw-integration.md` §7.5). This is inbox hygiene only: first-answer-wins (§9) has
   * already decided the outcome, and a retract never enters the audit chain as a decision.
   */
  readonly signal?: AbortSignal;
}

/** Outcome of mapping one approval. */
export type MappingOutcome =
  | { readonly kind: "request"; readonly request: BridgeApprovalRequest }
  | { readonly kind: "deny"; readonly reason: DenyReason; readonly detail: string }
  /** `approval.get` reports a terminal status: raise nothing, submit nothing (spec §6.1 rule 4). */
  | { readonly kind: "not-pending"; readonly status: string };

/** Inputs to {@link buildExecApprovalRequest}. */
export interface ExecMappingInput {
  readonly event: ExecApprovalRequestedEvent;
  readonly snapshot: ApprovalSnapshot;
  /** Operator-configured gateway label; re-validated per request (spec §7.1). */
  readonly gatewayId: string;
  /** The derived allw deadline, already budgeted against `expiresAtMs` (spec §8). */
  readonly timeoutMs: number;
}

/** Inputs to {@link buildPluginApprovalRequest}. */
export interface PluginMappingInput {
  readonly event: PluginApprovalRequestedEvent;
  readonly snapshot: ApprovalSnapshot;
  /** Operator-configured gateway label; re-validated per request (spec §7.1). */
  readonly gatewayId: string;
  /** The derived allw deadline, already budgeted against `expiresAtMs` (spec §8). */
  readonly timeoutMs: number;
}

/** The literal rendered for a decision-relevant component OpenClaw did not supply (spec §6.2). */
const UNKNOWN = "unknown";

/** Low/medium actions are reversible — the same rule the Codex hook applies (spec §6.4). */
export function reversibleForRisk(risk: Risk): boolean {
  return risk === "low" || risk === "medium";
}

/** Raise `risk` to at least `floor` (used for the `warningText` floor of `high`, spec §5.1). */
export function floorRisk(risk: Risk, floor: Risk): Risk {
  return RISK_ORDER.indexOf(risk) >= RISK_ORDER.indexOf(floor) ? risk : floor;
}

interface CoreActionRecord {
  readonly record_schema_version: number;
  readonly surface: string;
  readonly syntactic: unknown;
  readonly risk: Risk;
}

function isCoreActionRecord(value: unknown): value is CoreActionRecord {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.record_schema_version === "number" &&
    typeof v.surface === "string" &&
    "syntactic" in v &&
    (v.risk === "low" || v.risk === "medium" || v.risk === "high" || v.risk === "critical")
  );
}

/**
 * The exec `summary` (spec §6.2). It is a first-class, hashed, human-shown field, so the execution
 * locus (`host`/`nodeId`), the originating agent, and the gateway label are bound by the verdict
 * without inventing a syntactic field for each. Components OpenClaw did not supply render as the
 * literal `unknown` rather than being dropped — a missing field must be *visible*.
 *
 * An unbound working directory appends an explicit `working directory not bound` component
 * (spec §6.3), so a weaker binding never looks like a normal request.
 */
export function execSummary(input: {
  readonly gatewayId: string;
  readonly host?: string | undefined;
  readonly nodeId?: string | undefined;
  readonly agentId?: string | undefined;
  readonly commandText: string;
  readonly cwd?: string | undefined;
  readonly boundFilePath?: string | undefined;
}): string {
  const locus =
    input.nodeId !== undefined && input.nodeId.length > 0
      ? `${input.host ?? UNKNOWN}/${input.nodeId}`
      : (input.host ?? UNKNOWN);
  const parts = [
    `OpenClaw ${input.gatewayId}`,
    locus,
    `agent ${input.agentId ?? UNKNOWN}`,
    input.commandText,
  ];
  if (input.boundFilePath !== undefined && input.boundFilePath.length > 0) {
    parts.push(`bound file ${input.boundFilePath}`);
  }
  if (input.cwd === undefined || input.cwd.length === 0) {
    parts.push("working directory not bound");
  }
  return parts.join(" · ");
}

/**
 * Build the allw request for one exec approval, or the fail-closed reason it cannot be built.
 *
 * Order matters: the reconcile (§6.1) runs **before** any record is constructed, so a divergent
 * pair is never rendered to a human at all.
 */
export function buildExecApprovalRequest(wasm: HookWasm, input: ExecMappingInput): MappingOutcome {
  const { event, snapshot } = input;

  const gatewayId = normalizeGatewayId(input.gatewayId);
  if (gatewayId === null) {
    return {
      kind: "deny",
      reason: "config-error",
      detail: `gateway id '${input.gatewayId}' is not a valid <gateway-id>`,
    };
  }

  if (snapshot.id !== event.id) {
    return {
      kind: "deny",
      reason: "presentation-divergence",
      detail: `approval.get returned id '${snapshot.id}' for event id '${event.id}'`,
    };
  }

  // §5.3: the kind comes from the event family and is cross-checked against the pinned snapshot.
  if (!isExecPresentation(snapshot.presentation)) {
    return {
      kind: "deny",
      reason: "presentation-divergence",
      detail: `exec.approval.requested carried a snapshot of kind '${snapshot.presentation.kind}'`,
    };
  }
  const execPresentation = snapshot.presentation;

  const plan = event.request.systemRunPlan;
  const commandText = plan?.commandText ?? event.request.command;
  if (commandText === undefined || commandText.trim().length === 0) {
    return {
      kind: "deny",
      reason: "build-error",
      detail:
        "exec approval carried no command text (neither systemRunPlan.commandText nor request.command)",
    };
  }

  // §6.1 rule 3: the sanitized projection and the untyped event must agree about what is approved.
  // A snapshot that omits `commandText` is not a divergence — the projection is allowed to sanitize
  // — but a *different* value is, and neither source can then be trusted to be what runs.
  if (execPresentation.commandText !== undefined && execPresentation.commandText !== commandText) {
    return {
      kind: "deny",
      reason: "presentation-divergence",
      detail: "approval.get presentation.commandText does not equal the event's command text",
    };
  }

  // §6.1 rule 4: a terminal approval gets no allw request and no resolve.
  if (snapshot.status !== "pending") {
    return { kind: "not-pending", status: snapshot.status };
  }

  const cwd = plan?.cwd ?? event.request.cwd;
  const canonicalArgv = plan?.argv ?? event.request.commandArgv;

  let recordJson: string;
  try {
    recordJson =
      canonicalArgv !== undefined
        ? // §5.1: bind the canonical vector verbatim; `commandText` rides along as `raw` only.
          wasm.action_from_argv(JSON.stringify(canonicalArgv), commandText, cwd ?? null)
        : // No canonical argv exists anywhere — the core tokenizes the command text itself. This is
          // the documented last resort, not a shortcut past the rule above.
          wasm.action_from_command(commandText, cwd ?? null);
  } catch (err) {
    return {
      kind: "deny",
      reason: "build-error",
      detail: `core rejected the exec substrate: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(recordJson);
  } catch {
    return {
      kind: "deny",
      reason: "build-error",
      detail: "core returned unparseable ActionRecord",
    };
  }
  if (!isCoreActionRecord(parsed)) {
    return {
      kind: "deny",
      reason: "build-error",
      detail: "core ActionRecord was not in the expected shape",
    };
  }
  if (parsed.syntactic === null || typeof parsed.syntactic !== "object") {
    return {
      kind: "deny",
      reason: "build-error",
      detail: "core ActionRecord carried no syntactic substrate",
    };
  }
  if (parsed.surface !== "command") {
    // An exec approval must reduce to the `command` surface. Anything else means the core builder
    // and this mapping disagree about the family, which must never reach a human as an approval.
    return {
      kind: "deny",
      reason: "build-error",
      detail: `exec approval reduced to surface '${parsed.surface}', expected 'command'`,
    };
  }

  // §5.1/§6.4: `warningText` floors the risk at `high` — OpenClaw already decided this run warrants
  // a warning, so allw must not present it as routine even when the argv looks benign.
  const hasWarning =
    event.request.warningText !== undefined && event.request.warningText.trim().length > 0;
  const risk = hasWarning ? floorRisk(parsed.risk, "high") : parsed.risk;

  const summary = execSummary({
    gatewayId,
    host: event.request.host,
    nodeId: event.request.nodeId,
    agentId: plan?.agentId ?? event.request.agentId,
    commandText,
    cwd,
    boundFilePath: plan?.mutableFileOperand?.path,
  });

  // §6.2: `chain` is the contract's home for upstream-gate ids, and it is inside `request_hash`, so
  // a verdict cannot be replayed against a different OpenClaw approval.
  const sessionKey = plan?.sessionKey ?? event.request.sessionKey;
  const chain = [`openclaw:${gatewayId}:approval:${event.id}`];
  if (sessionKey !== undefined && sessionKey.length > 0) {
    chain.push(`openclaw:session:${sessionKey}`);
  }

  return {
    kind: "request",
    request: {
      action: {
        recordSchemaVersion: parsed.record_schema_version,
        surface: "command",
        syntactic: parsed.syntactic,
        risk,
      },
      summary,
      actor: { id: actorIdForGateway(gatewayId), kind: "openclaw" },
      risk,
      reversible: reversibleForRisk(risk),
      // §6.2: the allw verdict vocabulary is fixed. OpenClaw's `allowedDecisions` constrains what
      // the *bridge* may submit downstream (§7.4), never what the human may choose upstream.
      constraints: {
        allowedDecisions: ["approved", "denied"],
        challengeRequired: risk === "critical",
      },
      chain,
      timeoutMs: input.timeoutMs,
    },
  };
}

// ── §5.2 plugin permission requests ─────────────────────────────────────────────

/** `severity` → `risk` (spec §5.2, §6.4). Absent `severity` defaults upstream to `warning`. */
const SEVERITY_RISK: Readonly<Record<string, Risk>> = {
  info: "low",
  warning: "medium",
  critical: "critical",
};

/** The risk for the upstream default `severity: "warning"` when a plugin request omits it. */
const DEFAULT_SEVERITY_RISK: Risk = "medium";

/** The outcome of reconciling one field the pinned snapshot and the untyped event both carry. */
interface ReconciledField {
  /** The canonical value — the snapshot's, falling back to the event's only when the snapshot
   * omits the field (§6.1: the pinned presentation is authoritative). */
  readonly value: string | undefined;
  /** Set when both sources supplied a value and it differs; the caller must deny
   * `presentation-divergence` and never proceed to build a record. */
  readonly divergence: string | undefined;
}

/**
 * Reconcile one named field between the pinned `approval.get` presentation (canonical) and the
 * untyped event (cross-check only). A value present on only one side is not a divergence — the
 * sanitized projection is allowed to omit fields (mirrors exec's `commandText` rule, §6.1); a value
 * present on **both** sides that disagrees is.
 */
function reconcileString(
  fieldName: string,
  snapshotValue: string | undefined,
  eventValue: string | undefined,
): ReconciledField {
  if (snapshotValue !== undefined && eventValue !== undefined && snapshotValue !== eventValue) {
    return {
      value: snapshotValue,
      divergence: `approval.get presentation.${fieldName} does not equal the event's ${fieldName}`,
    };
  }
  return { value: snapshotValue ?? eventValue, divergence: undefined };
}

/** Order-independent divergence check for two `allowedDecisions` sets (the schema declares the
 * field a set: `uniqueItems: true`). `undefined` on either side means nothing to compare. */
function decisionsDiverge(
  a: readonly string[] | undefined,
  b: readonly string[] | undefined,
): boolean {
  if (a === undefined || b === undefined) return false;
  if (a.length !== b.length) return true;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.some((value, index) => value !== sortedB[index]);
}

/**
 * Normalize a plugin's `title` into a slug usable as `syntactic.tool` when `toolName` is absent
 * (spec §5.2: "else a normalized slug of `title`"). Returns `undefined` when `title` is absent or
 * reduces to an empty slug (e.g. a title with no alphanumeric characters), so the caller can fail
 * closed with `build-error` rather than binding an empty tool identity.
 */
export function slugifyTitle(title: string | undefined): string | undefined {
  if (title === undefined) return undefined;
  const slug = title
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug.length > 0 ? slug : undefined;
}

/**
 * The plugin `summary` (spec §6.2): `OpenClaw <gateway-id> · agent <agentId> ·
 * <server>/<tool>: <title> — <description>`. `server`/`tool` are the already-resolved function
 * identity (i.e. after the `pluginId → "openclaw"` / `toolName → title slug` fallbacks in
 * {@link buildPluginApprovalRequest} have run), so this only ever renders a non-empty pair.
 * `agentId`/`title`/`description` render as the literal `unknown` when OpenClaw did not supply
 * them — a missing field must be visible, not invisible (spec §6.2 notes).
 */
export function pluginSummary(input: {
  readonly gatewayId: string;
  readonly agentId?: string | undefined;
  readonly server: string;
  readonly tool: string;
  readonly title?: string | undefined;
  readonly description?: string | undefined;
}): string {
  const title = input.title !== undefined && input.title.length > 0 ? input.title : UNKNOWN;
  const description =
    input.description !== undefined && input.description.length > 0 ? input.description : UNKNOWN;
  return (
    `OpenClaw ${input.gatewayId} · agent ${input.agentId ?? UNKNOWN} · ` +
    `${input.server}/${input.tool}: ${title} — ${description}`
  );
}

/**
 * Build the allw request for one plugin permission request, or the fail-closed reason it cannot
 * be built.
 *
 * Order matters, mirroring {@link buildExecApprovalRequest}: the reconcile (§6.1) runs **before**
 * any record is constructed, so a divergent pair is never rendered to a human at all.
 */
export function buildPluginApprovalRequest(
  wasm: HookWasm,
  input: PluginMappingInput,
): MappingOutcome {
  const { event, snapshot } = input;

  const gatewayId = normalizeGatewayId(input.gatewayId);
  if (gatewayId === null) {
    return {
      kind: "deny",
      reason: "config-error",
      detail: `gateway id '${input.gatewayId}' is not a valid <gateway-id>`,
    };
  }

  if (snapshot.id !== event.id) {
    return {
      kind: "deny",
      reason: "presentation-divergence",
      detail: `approval.get returned id '${snapshot.id}' for event id '${event.id}'`,
    };
  }

  // §5.3: the kind comes from the event family and is cross-checked against the pinned snapshot.
  if (!isPluginPresentation(snapshot.presentation)) {
    return {
      kind: "deny",
      reason: "presentation-divergence",
      detail: `plugin.approval.requested carried a snapshot of kind '${snapshot.presentation.kind}'`,
    };
  }
  const presentation = snapshot.presentation;

  // §6.1 rule 3, extended to every field BOTH sources carry (not only `commandText`/prose): the
  // pinned `PluginApprovalPresentation` is the **canonical** source for function identity
  // (`pluginId`, `toolName`), risk (`severity`), reviewer prose (`title`, `description`, `detail`),
  // and actor context (`agentId`) — @openclaw/gateway-protocol's schema marks `title`,
  // `description`, `severity`, and `allowedDecisions` schema-**required** on this presentation, and
  // `detail`/`pluginId`/`toolName`/`agentId` schema-optional. The untyped event is only a
  // cross-check: a sanitized snapshot may omit a field (that is not divergence, mirroring exec's
  // `commandText` rule), but when BOTH sources supply a value they must agree, or neither can be
  // trusted to be what the human is actually being asked to approve.
  const pluginId = reconcileString("pluginId", presentation.pluginId, event.request.pluginId);
  if (pluginId.divergence !== undefined) {
    return { kind: "deny", reason: "presentation-divergence", detail: pluginId.divergence };
  }
  const toolName = reconcileString("toolName", presentation.toolName, event.request.toolName);
  if (toolName.divergence !== undefined) {
    return { kind: "deny", reason: "presentation-divergence", detail: toolName.divergence };
  }
  const title = reconcileString("title", presentation.title, event.request.title);
  if (title.divergence !== undefined) {
    return { kind: "deny", reason: "presentation-divergence", detail: title.divergence };
  }
  const descriptionField = reconcileString(
    "description",
    presentation.description,
    event.request.description,
  );
  if (descriptionField.divergence !== undefined) {
    return { kind: "deny", reason: "presentation-divergence", detail: descriptionField.divergence };
  }
  const detailField = reconcileString("detail", presentation.detail, event.request.detail);
  if (detailField.divergence !== undefined) {
    return { kind: "deny", reason: "presentation-divergence", detail: detailField.divergence };
  }
  const severityField = reconcileString("severity", presentation.severity, event.request.severity);
  if (severityField.divergence !== undefined) {
    return { kind: "deny", reason: "presentation-divergence", detail: severityField.divergence };
  }
  const agentId = reconcileString("agentId", presentation.agentId, event.request.agentId);
  if (agentId.divergence !== undefined) {
    return { kind: "deny", reason: "presentation-divergence", detail: agentId.divergence };
  }
  // `allowedDecisions` is present on both sources' schemas; the sharpest divergence case (a
  // severity of `medium` on the event vs. `critical` on the snapshot silently skipping the
  // number-match challenge) is caught above, but a decision-set mismatch is checked too for the
  // same reason — an unchecked disagreement here would leave the two sources' reviewer contracts
  // silently inconsistent. Order-independent: the schema declares `allowedDecisions` a set.
  if (decisionsDiverge(presentation.allowedDecisions, event.request.allowedDecisions)) {
    return {
      kind: "deny",
      reason: "presentation-divergence",
      detail:
        "approval.get presentation.allowedDecisions does not equal the event's allowedDecisions",
    };
  }

  // §6.1 rule 4: a terminal approval gets no allw request and no resolve.
  if (snapshot.status !== "pending") {
    return { kind: "not-pending", status: snapshot.status };
  }

  // §5.2: function identity is (pluginId, toolName); pluginId falls back to "openclaw", toolName
  // falls back to a normalized slug of title. Fail closed if neither yields a non-empty token.
  const server = pluginId.value ?? "openclaw";
  const tool = toolName.value ?? slugifyTitle(title.value);
  if (tool === undefined) {
    return {
      kind: "deny",
      reason: "build-error",
      detail: "plugin approval carried neither toolName nor a usable title slug",
    };
  }

  // §5.2/§6.4: an unrecognized severity is rejected rather than guessed at — silently defaulting
  // an out-of-band value would misclassify risk for a condition OpenClaw's own schema never
  // documented. Absent severity uses the upstream default (`warning` → medium).
  let risk: Risk;
  if (severityField.value === undefined) {
    risk = DEFAULT_SEVERITY_RISK;
  } else {
    const mapped = SEVERITY_RISK[severityField.value];
    if (mapped === undefined) {
      return {
        kind: "deny",
        reason: "build-error",
        detail: `plugin approval declared an unrecognized severity '${severityField.value}'`,
      };
    }
    risk = mapped;
  }

  // §5.2: syntactic.raw = description, plus detail when present — the prose the plugin author
  // wrote for the approver. syntactic.params stays absent: OpenClaw exposes no structured
  // parameters to a reviewer, so none is synthesized.
  const description =
    descriptionField.value !== undefined && descriptionField.value.length > 0
      ? descriptionField.value
      : UNKNOWN;
  const raw =
    detailField.value !== undefined && detailField.value.length > 0
      ? `${description}\n\n${detailField.value}`
      : description;

  let recordJson: string;
  try {
    recordJson = wasm.action_from_agent_tool_call_with_raw(server, tool, raw, null);
  } catch (err) {
    return {
      kind: "deny",
      reason: "build-error",
      detail: `core rejected the plugin substrate: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(recordJson);
  } catch {
    return {
      kind: "deny",
      reason: "build-error",
      detail: "core returned unparseable ActionRecord",
    };
  }
  if (!isCoreActionRecord(parsed)) {
    return {
      kind: "deny",
      reason: "build-error",
      detail: "core ActionRecord was not in the expected shape",
    };
  }
  if (parsed.syntactic === null || typeof parsed.syntactic !== "object") {
    return {
      kind: "deny",
      reason: "build-error",
      detail: "core ActionRecord carried no syntactic substrate",
    };
  }
  if (parsed.surface !== "agent_tool_call") {
    // A plugin approval must reduce to the `agent_tool_call` surface. Anything else means the
    // core builder and this mapping disagree about the family, which must never reach a human as
    // an approval.
    return {
      kind: "deny",
      reason: "build-error",
      detail: `plugin approval reduced to surface '${parsed.surface}', expected 'agent_tool_call'`,
    };
  }

  const summary = pluginSummary({
    gatewayId,
    agentId: agentId.value,
    server,
    tool,
    title: title.value,
    description: descriptionField.value,
  });

  // §6.2: `chain` is the contract's home for upstream-gate ids. Plugin approvals additionally
  // carry `openclaw:tool_call:<toolCallId>` when OpenClaw supplied one.
  const chain = [`openclaw:${gatewayId}:approval:${event.id}`];
  if (event.request.sessionKey !== undefined && event.request.sessionKey.length > 0) {
    chain.push(`openclaw:session:${event.request.sessionKey}`);
  }
  if (event.request.toolCallId !== undefined && event.request.toolCallId.length > 0) {
    chain.push(`openclaw:tool_call:${event.request.toolCallId}`);
  }

  return {
    kind: "request",
    request: {
      action: {
        recordSchemaVersion: parsed.record_schema_version,
        surface: "agent_tool_call",
        syntactic: parsed.syntactic,
        risk,
      },
      summary,
      actor: { id: actorIdForGateway(gatewayId), kind: "openclaw" },
      risk,
      reversible: reversibleForRisk(risk),
      // §6.2: the allw verdict vocabulary is fixed. OpenClaw's `allowedDecisions` constrains what
      // the *bridge* may submit downstream (§7.4), never what the human may choose upstream.
      constraints: {
        allowedDecisions: ["approved", "denied"],
        challengeRequired: risk === "critical",
      },
      chain,
      timeoutMs: input.timeoutMs,
    },
  };
}
