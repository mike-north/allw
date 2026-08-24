/**
 * The OpenClaw approval wire shapes the bridge consumes, plus **validating** readers for them.
 *
 * Two sources, deliberately not interchangeable (`docs/openclaw-integration.md` §6.1):
 *
 * | Source                           | Contains                                                        | Schema-pinned |
 * | -------------------------------- | --------------------------------------------------------------- | ------------- |
 * | `exec.approval.requested` event  | the **full** runtime request incl. `systemRunPlan`               | **no**        |
 * | `approval.get { id }`            | the sanitized `ApprovalSnapshot` (lifecycle + reviewer contract) | yes           |
 *
 * Because the event payload is untyped in OpenClaw's generated `protocol.schema.json`, everything
 * read from it goes through a reader here that returns `null` rather than casting. A `null` is
 * always a fail-closed condition upstream, never a defaulted value.
 *
 * @see ../../../../docs/openclaw-integration.md §5.1, §6.1, §7.4
 * @see https://docs.openclaw.ai/gateway/protocol
 * @see https://unpkg.com/@openclaw/gateway-protocol@beta/protocol.schema.json
 */

/**
 * `ApprovalKind` as OpenClaw's schema defines it — **three** values. `system-agent` is out of scope
 * for v1 and must be neither approved nor denied (spec §5.3).
 */
export type ApprovalKind = "exec" | "plugin" | "system-agent";

/** OpenClaw's decision vocabulary. The bridge only ever submits `allow-once` or `deny` (spec §7.3). */
export type ApprovalDecision = "allow-once" | "allow-always" | "deny";

/** The four broadcast events the bridge subscribes to, scope-gated to `operator.approvals`. */
export const APPROVAL_EVENTS = [
  "exec.approval.requested",
  "exec.approval.resolved",
  "plugin.approval.requested",
  "plugin.approval.resolved",
] as const;

/** The kind-agnostic durable RPCs (spec §7.4 — never the per-kind adapters, never an id prefix). */
export const APPROVAL_GET_METHOD = "approval.get";
export const APPROVAL_RESOLVE_METHOD = "approval.resolve";
export const EXEC_APPROVAL_LIST_METHOD = "exec.approval.list";
export const PLUGIN_APPROVAL_LIST_METHOD = "plugin.approval.list";

/** The client capabilities the bridge advertises. `tool-events` is deliberately absent (spec §4.3). */
export const BRIDGE_CAPABILITIES = ["approvals", "exec-approvals", "plugin-approvals"] as const;

/** The one scope the bridge requests. Never `operator.admin`, never `operator.read` (spec §4.1). */
export const BRIDGE_SCOPES = ["operator.approvals"] as const;

/** Operator clients must negotiate the exact current wire version (spec §4.3). */
export const PINNED_PROTOCOL_VERSION = 4;

/**
 * The canonical execution plan the gateway stores at request time and reuses verbatim when
 * forwarding the approved `system.run`. This — not a re-parse of the command text — is what the
 * human must be shown and what the verdict binds to (spec §5.1).
 */
export interface SystemRunPlan {
  readonly argv: readonly string[];
  readonly cwd?: string | undefined;
  readonly commandText: string;
  readonly agentId?: string | undefined;
  readonly sessionKey?: string | undefined;
  readonly mutableFileOperand?: { readonly path: string } | undefined;
}

/** The exec runtime request carried on the (untyped) `exec.approval.requested` event payload. */
export interface ExecApprovalRequest {
  readonly command?: string | undefined;
  readonly commandArgv?: readonly string[] | undefined;
  readonly cwd?: string | undefined;
  readonly agentId?: string | undefined;
  readonly sessionKey?: string | undefined;
  /** OpenClaw's *execution locus* (`gateway` | `node` | `sandbox`) — **not** allw's `syntactic.host`. */
  readonly host?: string | undefined;
  readonly nodeId?: string | undefined;
  readonly warningText?: string | undefined;
  readonly systemRunPlan?: SystemRunPlan | undefined;
}

/** The `exec.approval.requested` event payload. */
export interface ExecApprovalRequestedEvent {
  readonly id: string;
  readonly approvalKind?: string | undefined;
  readonly createdAtMs?: number | undefined;
  readonly expiresAtMs: number;
  readonly request: ExecApprovalRequest;
}

/**
 * The plugin runtime request carried on the (untyped) `plugin.approval.requested` event payload
 * (spec §5.2). Its function identity is the `(pluginId, toolName)` pair — structurally parallel to
 * an MCP call's `(server, tool)` and to a command's program name.
 */
export interface PluginApprovalRequest {
  readonly pluginId?: string | undefined;
  readonly title?: string | undefined;
  readonly description?: string | undefined;
  readonly detail?: string | undefined;
  readonly severity?: string | undefined;
  readonly toolName?: string | undefined;
  readonly toolCallId?: string | undefined;
  readonly agentId?: string | undefined;
  readonly sessionKey?: string | undefined;
}

/** The `plugin.approval.requested` event payload. */
export interface PluginApprovalRequestedEvent {
  readonly id: string;
  readonly approvalKind?: string | undefined;
  readonly createdAtMs?: number | undefined;
  readonly expiresAtMs: number;
  readonly request: PluginApprovalRequest;
}

/** The sanitized reviewer projection returned by `approval.get` (spec §6.1). */
export interface ApprovalPresentation {
  readonly kind: string;
  readonly title?: string | undefined;
  readonly description?: string | undefined;
  readonly commandText?: string | undefined;
  readonly allowedDecisions: readonly ApprovalDecision[];
}

/** The pinned `ApprovalSnapshot` — authority for lifecycle and the reviewer contract (spec §6.1). */
export interface ApprovalSnapshot {
  readonly id: string;
  readonly createdAtMs?: number | undefined;
  readonly expiresAtMs: number;
  readonly status: string;
  readonly presentation: ApprovalPresentation;
}

/** The `approval.resolve` response. `applied: false` means another surface won (spec §7.4). */
export interface ApprovalResolveResult {
  readonly applied: boolean;
  readonly record?:
    | { readonly status?: string | undefined; readonly decision?: string | undefined }
    | undefined;
}

// ── Readers ──────────────────────────────────────────────────────────────────────

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function readNonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function readSafeInt(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : undefined;
}

function readStringArray(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.every((entry) => typeof entry === "string") ? value : undefined;
}

/**
 * Map a broadcast event name to the approval kind it carries. The kind is read from the **event
 * family**, never inferred from an id prefix (which OpenClaw explicitly forbids), and is
 * cross-checked against the payload's `approvalKind` by {@link readExecApprovalRequestedEvent}
 * (spec §5.3).
 */
export function kindForEvent(event: string): ApprovalKind | null {
  if (event === "exec.approval.requested" || event === "exec.approval.resolved") return "exec";
  if (event === "plugin.approval.requested" || event === "plugin.approval.resolved") {
    return "plugin";
  }
  return null;
}

/**
 * Parse an `exec.approval.requested` payload. Returns `null` when the payload is not an object,
 * lacks a non-empty `id` or a safe-integer `expiresAtMs`, carries no `request` object, or declares
 * an `approvalKind` other than `exec` (the family/payload cross-check from spec §5.3).
 */
export function readExecApprovalRequestedEvent(
  payload: unknown,
): ExecApprovalRequestedEvent | null {
  const root = asRecord(payload);
  if (root === null) return null;

  const id = readNonEmptyString(root.id);
  const expiresAtMs = readSafeInt(root.expiresAtMs);
  const request = asRecord(root.request);
  if (id === undefined || expiresAtMs === undefined || request === null) return null;

  const declaredKind = readNonEmptyString(root.approvalKind);
  if (declaredKind !== undefined && declaredKind !== "exec") return null;

  return {
    id,
    expiresAtMs,
    approvalKind: declaredKind,
    createdAtMs: readSafeInt(root.createdAtMs),
    request: readExecApprovalRequest(request),
  };
}

function readSystemRunPlan(value: unknown): SystemRunPlan | undefined {
  const plan = asRecord(value);
  if (plan === null) return undefined;
  const argv = readStringArray(plan.argv);
  const commandText = readNonEmptyString(plan.commandText);
  if (argv === undefined || commandText === undefined) return undefined;

  const operandPath = readNonEmptyString(asRecord(plan.mutableFileOperand)?.path);

  return {
    argv,
    commandText,
    cwd: readNonEmptyString(plan.cwd),
    agentId: readNonEmptyString(plan.agentId),
    sessionKey: readNonEmptyString(plan.sessionKey),
    mutableFileOperand: operandPath === undefined ? undefined : { path: operandPath },
  };
}

function readExecApprovalRequest(request: Record<string, unknown>): ExecApprovalRequest {
  return {
    command: readNonEmptyString(request.command),
    commandArgv: readStringArray(request.commandArgv),
    cwd: readNonEmptyString(request.cwd),
    agentId: readNonEmptyString(request.agentId),
    sessionKey: readNonEmptyString(request.sessionKey),
    host: readNonEmptyString(request.host),
    nodeId: readNonEmptyString(request.nodeId),
    warningText: readNonEmptyString(request.warningText),
    systemRunPlan: readSystemRunPlan(request.systemRunPlan),
  };
}

/**
 * Parse a `plugin.approval.requested` payload. Returns `null` when the payload is not an object,
 * lacks a non-empty `id` or a safe-integer `expiresAtMs`, carries no `request` object, or declares
 * an `approvalKind` other than `plugin` (the family/payload cross-check from spec §5.3).
 */
export function readPluginApprovalRequestedEvent(
  payload: unknown,
): PluginApprovalRequestedEvent | null {
  const root = asRecord(payload);
  if (root === null) return null;

  const id = readNonEmptyString(root.id);
  const expiresAtMs = readSafeInt(root.expiresAtMs);
  const request = asRecord(root.request);
  if (id === undefined || expiresAtMs === undefined || request === null) return null;

  const declaredKind = readNonEmptyString(root.approvalKind);
  if (declaredKind !== undefined && declaredKind !== "plugin") return null;

  return {
    id,
    expiresAtMs,
    approvalKind: declaredKind,
    createdAtMs: readSafeInt(root.createdAtMs),
    request: readPluginApprovalRequest(request),
  };
}

function readPluginApprovalRequest(request: Record<string, unknown>): PluginApprovalRequest {
  return {
    pluginId: readNonEmptyString(request.pluginId),
    title: readNonEmptyString(request.title),
    description: readNonEmptyString(request.description),
    detail: readNonEmptyString(request.detail),
    severity: readNonEmptyString(request.severity),
    toolName: readNonEmptyString(request.toolName),
    toolCallId: readNonEmptyString(request.toolCallId),
    agentId: readNonEmptyString(request.agentId),
    sessionKey: readNonEmptyString(request.sessionKey),
  };
}

function readAllowedDecisions(value: unknown): readonly ApprovalDecision[] | null {
  const raw = readStringArray(value);
  if (raw === undefined) return null;
  const allowed = raw.filter(
    (entry): entry is ApprovalDecision =>
      entry === "allow-once" || entry === "allow-always" || entry === "deny",
  );
  // An unrecognized decision string is dropped rather than passed through: the bridge may only
  // submit a decision the request actually offered, so an unknown token must never widen the set.
  return allowed;
}

/**
 * Parse an `approval.get` response into an {@link ApprovalSnapshot}, or `null` when any field the
 * bridge relies on is missing or the wrong type. `presentation.allowedDecisions` is required — the
 * bridge cannot check "is `allow-once` offered?" (spec §7.4) without it, and guessing would risk
 * submitting a decision the gateway will reject.
 */
export function readApprovalSnapshot(payload: unknown): ApprovalSnapshot | null {
  const root = asRecord(payload);
  if (root === null) return null;

  const id = readNonEmptyString(root.id);
  const expiresAtMs = readSafeInt(root.expiresAtMs);
  const status = readNonEmptyString(root.status);
  const presentation = asRecord(root.presentation);
  if (
    id === undefined ||
    expiresAtMs === undefined ||
    status === undefined ||
    presentation === null
  ) {
    return null;
  }

  const kind = readNonEmptyString(presentation.kind);
  const allowedDecisions = readAllowedDecisions(presentation.allowedDecisions);
  if (kind === undefined || allowedDecisions === null) return null;

  return {
    id,
    expiresAtMs,
    status,
    createdAtMs: readSafeInt(root.createdAtMs),
    presentation: {
      kind,
      allowedDecisions,
      title: readNonEmptyString(presentation.title),
      description: readNonEmptyString(presentation.description),
      commandText: readNonEmptyString(presentation.commandText),
    },
  };
}

/**
 * Parse an `approval.resolve` response. A response the bridge cannot read is treated as
 * `applied: false` with no canonical record: the bridge never retries a resolve, and a lost
 * acknowledgement is reconciled by re-reading `approval.get` (spec §7.4).
 */
export function readApprovalResolveResult(payload: unknown): ApprovalResolveResult {
  const root = asRecord(payload);
  if (root === null) return { applied: false };
  const record = asRecord(root.record);
  return {
    applied: root.applied === true,
    record:
      record === null
        ? undefined
        : {
            status: readNonEmptyString(record.status),
            decision: readNonEmptyString(record.decision),
          },
  };
}

/**
 * Parse an `*.approval.list` response into the pending approval ids it reports. Accepts either a
 * bare array or `{ approvals: [...] }`; entries without a readable `id` are skipped rather than
 * defaulted.
 */
export function readApprovalListIds(payload: unknown): readonly string[] {
  const entries = Array.isArray(payload)
    ? payload
    : (asRecord(payload)?.approvals ?? asRecord(payload)?.items);
  if (!Array.isArray(entries)) return [];
  const ids: string[] = [];
  for (const entry of entries) {
    const id = typeof entry === "string" ? entry : readNonEmptyString(asRecord(entry)?.id);
    if (id !== undefined && id.length > 0) ids.push(id);
  }
  return ids;
}
