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
import type { ApprovalSnapshot, ExecApprovalRequestedEvent } from "./protocol.js";

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
    /** Always `command` for the exec family — asserted, not assumed (spec §5.1). */
    readonly surface: "command";
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
  if (snapshot.presentation.kind !== "exec") {
    return {
      kind: "deny",
      reason: "presentation-divergence",
      detail: `exec.approval.requested carried a snapshot of kind '${snapshot.presentation.kind}'`,
    };
  }

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
  if (
    snapshot.presentation.commandText !== undefined &&
    snapshot.presentation.commandText !== commandText
  ) {
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
