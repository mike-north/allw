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
  /** Present on `PluginApprovalRequestParams` per the pinned schema; used only to cross-check
   * against the snapshot's `presentation.allowedDecisions` (§6.1) — never as the value the bridge
   * submits (that is always sourced fresh from `approval.get` at resolve time, §7.4). */
  readonly allowedDecisions?: readonly ApprovalDecision[] | undefined;
}

/** The `plugin.approval.requested` event payload. */
export interface PluginApprovalRequestedEvent {
  readonly id: string;
  readonly approvalKind?: string | undefined;
  readonly createdAtMs?: number | undefined;
  readonly expiresAtMs: number;
  readonly request: PluginApprovalRequest;
}

/**
 * The sanitized reviewer projection returned by `approval.get` (spec §6.1) — a discriminated union
 * on `kind`, matching `@openclaw/gateway-protocol`'s `ExecApprovalPresentation` /
 * `PluginApprovalPresentation` schema definitions exactly (verified against the installed
 * `protocol.schema.json`, `since: "2026.7"`). Every field below is still read **defensively**
 * (optional at this boundary) even where the pinned schema marks it `required` — the bridge does
 * not trust a wire response to honor its own schema, mirroring the existing `commandText`
 * precedent (§6.1: a sanitized snapshot may omit a field; only a genuinely different value is a
 * divergence).
 */
export interface ExecApprovalPresentation {
  readonly kind: "exec";
  readonly commandText?: string | undefined;
  /** Schema-present but not yet consumed by the mapping; kept for completeness/future use. */
  readonly warningText?: string | undefined;
  readonly host?: string | undefined;
  readonly nodeId?: string | undefined;
  readonly agentId?: string | undefined;
  readonly allowedDecisions: readonly ApprovalDecision[];
}

/**
 * `PluginApprovalPresentation` per the pinned schema: `kind`, `title`, `description`, `severity`,
 * and `allowedDecisions` are schema-**required**; `detail`, `pluginId`, `toolName`, `agentId` are
 * schema-optional (and nullable on the wire — `readNonEmptyString` folds `null` to `undefined`).
 * This is the **canonical** source for plugin function identity, risk, and reviewer prose
 * (`docs/openclaw-integration.md` §5.2, §6.1) — the untyped event is only a cross-check.
 */
export interface PluginApprovalPresentation {
  readonly kind: "plugin";
  readonly title?: string | undefined;
  readonly description?: string | undefined;
  readonly detail?: string | undefined;
  /** Schema enum `"info" | "warning" | "critical"`; kept as a raw string so an out-of-enum value
   * reaches the mapping's own validation (`build-error`) rather than being silently normalized
   * away here. */
  readonly severity?: string | undefined;
  readonly pluginId?: string | undefined;
  readonly toolName?: string | undefined;
  readonly agentId?: string | undefined;
  readonly allowedDecisions: readonly ApprovalDecision[];
}

/** Any other kind (`system-agent`, or a future one) — out of scope for v1 mapping (spec §5.3); only
 * `kind` and `allowedDecisions` are modeled since nothing else is consumed. */
export interface OtherApprovalPresentation {
  readonly kind: string;
  readonly allowedDecisions: readonly ApprovalDecision[];
}

export type ApprovalPresentation =
  | ExecApprovalPresentation
  | PluginApprovalPresentation
  | OtherApprovalPresentation;

/**
 * Type predicates for {@link ApprovalPresentation}. Plain `kind !== "exec"` narrowing does not
 * eliminate {@link OtherApprovalPresentation} on its own — its `kind` is a general `string`, not a
 * literal, so TS cannot prove it excludes `"exec"`/`"plugin"` from that comparison alone. These
 * predicates make the narrowing explicit instead.
 */
export function isExecPresentation(p: ApprovalPresentation): p is ExecApprovalPresentation {
  return p.kind === "exec";
}
export function isPluginPresentation(p: ApprovalPresentation): p is PluginApprovalPresentation {
  return p.kind === "plugin";
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
    allowedDecisions: readAllowedDecisions(request.allowedDecisions) ?? undefined,
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
 * Parse an `approval.get` response's `presentation` into the discriminated
 * {@link ApprovalPresentation}, given the already-read `kind` and `allowedDecisions` (common to
 * every variant). `exec` and `plugin` each pick up their kind-specific fields per the pinned
 * schema (`ExecApprovalPresentation` / `PluginApprovalPresentation`); any other kind (`system-agent`,
 * or a future one) keeps only the common fields (spec §5.3 — v1 does not map it).
 */
function readApprovalPresentation(
  presentation: Record<string, unknown>,
  kind: string,
  allowedDecisions: readonly ApprovalDecision[],
): ApprovalPresentation {
  if (kind === "exec") {
    return {
      kind: "exec",
      allowedDecisions,
      commandText: readNonEmptyString(presentation.commandText),
      warningText: readNonEmptyString(presentation.warningText),
      host: readNonEmptyString(presentation.host),
      nodeId: readNonEmptyString(presentation.nodeId),
      agentId: readNonEmptyString(presentation.agentId),
    };
  }
  if (kind === "plugin") {
    return {
      kind: "plugin",
      allowedDecisions,
      title: readNonEmptyString(presentation.title),
      description: readNonEmptyString(presentation.description),
      detail: readNonEmptyString(presentation.detail),
      severity: readNonEmptyString(presentation.severity),
      pluginId: readNonEmptyString(presentation.pluginId),
      toolName: readNonEmptyString(presentation.toolName),
      agentId: readNonEmptyString(presentation.agentId),
    };
  }
  return { kind, allowedDecisions };
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
    presentation: readApprovalPresentation(presentation, kind, allowedDecisions),
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

/** One entry from an `*.approval.list` response: an id, plus the full snapshot when the entry
 * itself carried one. */
export interface ApprovalListEntry {
  readonly id: string;
  /** `null` when the entry was a bare id (or an object with an id but no readable snapshot) —
   * the caller must fall back to a fresh `approval.get` for it. */
  readonly snapshot: ApprovalSnapshot | null;
}

/**
 * Parse an `*.approval.list` response into its entries, preserving each one's **full record**
 * when the entry itself carries one — never reducing to bare ids.
 *
 * `exec.approval.list` / `plugin.approval.list` are legacy methods (`since: "<=2026.7"` in the
 * installed `@openclaw/gateway-protocol` schema) predating the 2026.7 kind-agnostic RPC redesign,
 * so the schema does not pin a typed `Result` for them the way it does for their successor,
 * `approval.history` (`ApprovalHistoryResult.items[]`) — whose items are full
 * `PendingApprovalSnapshot`/`…ApprovalSnapshot`-shaped records, matching `approval.get`'s own
 * `ApprovalGetResult.approval` shape exactly. That is the demonstrated convention for every
 * *other* "list approvals" surface in this protocol version, and it is why the entries here are
 * parsed as full records first: reducing an already-full record to its `id` would silently discard
 * data the bridge needs (`docs/openclaw-integration.md` §5.2, §6.1) and force a wasted extra
 * `approval.get` round trip per approval.
 *
 * Each entry is parsed with the **same** {@link readApprovalSnapshot} used for `approval.get`
 * responses — the two are structurally identical `ApprovalSnapshot` shapes. An entry that does not
 * parse as a full record falls back to reading a bare `id` (a bare string, or an object exposing
 * only `id`) so the caller can still discover it and fetch its snapshot separately; this fallback
 * is defensive/backward-compatible, never the expected shape.
 */
export function readApprovalList(payload: unknown): readonly ApprovalListEntry[] {
  const entries = Array.isArray(payload)
    ? payload
    : (asRecord(payload)?.approvals ?? asRecord(payload)?.items);
  if (!Array.isArray(entries)) return [];
  const result: ApprovalListEntry[] = [];
  for (const entry of entries) {
    const snapshot = readApprovalSnapshot(entry);
    if (snapshot !== null) {
      result.push({ id: snapshot.id, snapshot });
      continue;
    }
    const id = typeof entry === "string" ? entry : readNonEmptyString(asRecord(entry)?.id);
    if (id !== undefined && id.length > 0) result.push({ id, snapshot: null });
  }
  return result;
}
