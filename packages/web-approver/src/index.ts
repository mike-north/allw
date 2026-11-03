import { quoteToken, reconstructCommand, renderArgv, renderList } from "./command-line.js";

export type { AllwWasm, WasmModuleSource } from "./wasm.js";
export { initWasm, initWasmSync, resetWasmForTests } from "./wasm.js";

export type {
  PairedIdentity,
  PairingStore,
  PairingGateOptions,
  RejectedRelayPin,
  DisplayEscape,
  RelayRepairGateOptions,
  StoredPairing,
  StoredSnapshot,
} from "./pairing.js";
export { WITHHELD_UNTRUSTED_TEXT, displayUntrusted } from "./display-escape.js";
export {
  WITHHELD_PIN_TEXT,
  createLocalPairingStore,
  mountPairingGate,
  mountRelayRepairGate,
} from "./pairing.js";

export type { OnboardingWalkthroughOptions, OnboardingGateOptions } from "./onboarding.js";
export {
  isOnboardingComplete,
  mountOnboardingWalkthrough,
  mountOnboardingGate,
} from "./onboarding.js";

export type {
  FetchImpl as RelayFetchImpl,
  IntervalScheduler,
  IntervalCanceller,
  OnPollResult,
  PollResult,
  RelayPollerOptions,
  RelayPoller,
} from "./relay-poll.js";
export { createRelayPoller } from "./relay-poll.js";

export type {
  ApproverIdentity,
  AccountStateResolver,
  AccountStateResolution,
  WasmRuntimeOptions,
  BrowserRuntimeOptions,
} from "./runtime.js";
export { createWasmRuntime, createBrowserRuntime } from "./runtime.js";

export type { RelayAccountStateResolverOptions } from "./account-state.js";
export {
  ACCOUNT_STATE_FETCH_TIMEOUT_MS,
  createRelayAccountStateResolver,
} from "./account-state.js";

export type { AccountStateFloorStore } from "./sequence-floor.js";
export {
  ACCOUNT_STATE_FLOOR_STORAGE_KEY,
  createLocalAccountStateFloorStore,
  createInMemoryAccountStateFloorStore,
} from "./sequence-floor.js";

export type { SurfaceIdStore } from "./surface-id.js";
export {
  SURFACE_ID_STORAGE_KEY,
  createLocalSurfaceIdStore,
  resolveSurfaceId,
} from "./surface-id.js";

export type {
  LiveSocket,
  ConnectImpl,
  ReconnectScheduler,
  ReconnectCanceller,
  RetractListenerOptions,
  RetractListener,
} from "./retract-listener.js";
export { createRetractListener } from "./retract-listener.js";

export { mountAuditHistory } from "./audit-history.js";

export type {
  IgnoredRelayNoticeOptions,
  RelayConfigGateOptions,
  RelayUrlCheck,
  RelayUrlResolution,
  RelayUrlSource,
} from "./relay-config.js";
export {
  INSECURE_RELAY_URL_REASON,
  PENDING_IGNORED_RELAY_TEXT,
  RELAY_URL_EXTRAS_REASON,
  RELAY_URL_QUERY_PARAM,
  RELAY_URL_STORAGE_KEY,
  checkRelayUrl,
  describeIgnoredRelayOverride,
  mountIgnoredRelayNotice,
  mountRelayConfigGate,
  readStoredRelayUrl,
  relayOrigin,
  resolveRelayUrl,
} from "./relay-config.js";

export type ApprovalDecision = "approved" | "denied";

export type ApprovalStatus = "pending" | "deciding" | "expired" | "unverified" | ApprovalDecision;

export interface ApprovalEnvelope {
  readonly v: number;
  readonly id: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly approver: string;
  readonly context_ciphertext: string;
  readonly resolved_at?: number;
}

export interface ApprovalActor {
  readonly id: string;
  readonly display: string;
  readonly attestation: "verified" | "unverified" | "pending";
}

export interface ApprovalRisk {
  readonly level: "low" | "medium" | "high" | "critical";
  readonly reversible: boolean;
  /** The context `summary`: the integrator's description of the action, escaped by the core. */
  readonly summary: string;
}

/**
 * The action's complete syntactic substrate as the core displays it (Rust
 * `allw_core::DisplaySubstrate`, from `display_model`, #246): every field the core binds into
 * `request_hash`, each already escaped (`\x1b`, `⟨U+202E⟩`, …). Renderers lay these out but never
 * escape anything themselves, and must never be handed raw decrypted strings.
 *
 * The substrate is one generic record for every surface, so the view keeps it whole rather than a
 * per-surface subset: a renderer that shows every present field can never omit a hash-bound one,
 * and whenever the hidden-character warning shows, the escaped character is somewhere on screen.
 */
export interface SubstrateView {
  readonly bin?: string;
  readonly argv?: readonly string[];
  readonly flags?: readonly string[];
  readonly positionals?: readonly string[];
  readonly cwd?: string;
  readonly host?: string;
  readonly envRefs?: readonly string[];
  /** MCP server name, or the gating provider (plugin) id for an `agent_tool_call`. */
  readonly server?: string;
  readonly tool?: string;
  /** The call's `params` as compact one-line JSON (the headline of a record with nothing else). */
  readonly paramsJson?: string;
  /** The call's `params` as indented JSON, one entry per line. */
  readonly paramsLines?: readonly string[];
  /** File-edit operation (e.g. `patch`, `write`). */
  readonly operation?: string;
  readonly paths?: readonly string[];
  readonly diffSummary?: string;
  readonly diffHash?: string;
  /** `raw` as one line (TAB, LF and CR show as `\t`, `\n`, `\r`) — for one-line headlines. */
  readonly raw?: string;
  /**
   * `raw` as multi-line content, one entry per line: a heredoc command, or a file edit's content.
   * TAB, and a CR before LF in a file edit, are shown as structure markers and do not raise the
   * warning.
   */
  readonly rawLines?: readonly string[];
}

export interface NumberMatchChallenge {
  readonly kind: "number-match";
  readonly code: string;
  readonly prompt: string;
}

export interface ApprovalContext {
  /**
   * The action's surface. `agent_tool_call` (an agent-runtime/plugin-owned tool call,
   * `docs/openclaw-integration.md` §5.2) shares the `(server, tool)` shape with `mcp` but is its own
   * kind, so a plugin-owned call is never labelled as an MCP call it never was.
   */
  readonly kind: "command" | "mcp" | "agent_tool_call" | "file_edit";
  /** Every hash-bound action field, escaped by the core. */
  readonly substrate: SubstrateView;
  /**
   * Set only when the hash-bound `bin`/`argv` describes a different command than `raw` (decided on
   * the unescaped bytes): the escaped command line `bin`/`argv` reconstruct to. Renderers show it
   * as the headline with a warning, so a benign `raw` can never be the only half on screen.
   */
  readonly divergentArgv?: string;
  /** Escaped ids of the upstream gates this request passed through. */
  readonly chain?: readonly string[];
  readonly actor: ApprovalActor;
  readonly risk: ApprovalRisk;
  readonly allowed_decisions: readonly ApprovalDecision[];
  readonly challenge?: NumberMatchChallenge;
  /**
   * The core found (and escaped) hidden or control characters somewhere in the request (#246).
   * Renderers must show a prominent warning when this is true.
   */
  readonly hasHiddenOrControlChars: boolean;
}

export interface PreparedApproval {
  readonly requestHash: string;
  /** Core-verified request expiry; lifecycle state must not trust the relay-visible envelope timestamp. */
  readonly expiresAt: number;
  readonly context: ApprovalContext;
  /** MUST be set only from a core-verified terminal Verdict. */
  readonly resolvedDecision?: ApprovalDecision;
}

export interface SignDecisionInput {
  readonly envelope: ApprovalEnvelope;
  readonly prepared: PreparedApproval;
  readonly decision: ApprovalDecision;
  readonly challengeResponse?: string;
}

export interface SignedVerdict {
  readonly requestId: string;
  readonly decision: ApprovalDecision;
  readonly signedVerdictJson: string;
}

export interface WebApproverRuntime {
  /**
   * Decrypts the relay envelope, recomputes the WYSIWYS request hash, and returns the
   * exact plaintext model to render. Implementations must call the WASM/core-backed
   * allw surfaces; the web shell treats failures as deny-by-default.
   */
  prepare(envelope: ApprovalEnvelope): Promise<PreparedApproval>;

  /**
   * Signs a human decision with the device/account key material held by the runtime.
   * The controller validates UI state first, but signing remains delegated to core.
   */
  signDecision(input: SignDecisionInput): Promise<SignedVerdict>;

  /**
   * Renders untrusted text (an error message that can embed a relay-supplied id or HTTP body) for
   * display through the core's escape (`escape_for_display`). Optional: when a runtime has no
   * core, the controller withholds such text rather than showing it unescaped.
   */
  escapeForDisplay?(text: string): string;
}

/**
 * Shown with a request whose raw and hash-bound argv describe different commands. The heading then
 * shows the argv form, and the plaintext block shows both, so neither half is hidden (#295).
 */
export const RAW_ARGV_DIVERGENCE_WARNING =
  "⚠ raw and argv differ — the heading shows the hash-bound argv; the raw line below is what the agent wrote. Review both.";

/** Label for the context summary: the integrator's own description, not the action itself (#262). */
export const CONTEXT_SUMMARY_LABEL = "Agent's description";

/** Shown in place of untrusted error text when no core escape is available to render it safely. */
export const WITHHELD_ERROR_TEXT = "details withheld (no display escaper available)";

export interface WebApproverControllerOptions {
  readonly runtime: WebApproverRuntime;
  readonly nowMs?: () => number;
}

export interface ApprovalListItem {
  readonly id: string;
  readonly status: ApprovalStatus;
  readonly actor: string;
  readonly riskLevel: ApprovalRisk["level"] | "unknown";
  readonly summary: string;
  readonly expiresAt: number;
  readonly countdownMs: number;
  readonly denyOnly: boolean;
}

export interface ApprovalDetail extends ApprovalListItem {
  readonly requestHash?: string;
  readonly exactPlaintext: string;
  readonly actorId?: string;
  readonly attestation?: ApprovalActor["attestation"];
  readonly reversible?: boolean;
  readonly verificationError?: string;
  readonly challenge?: NumberMatchChallenge;
  /** True when the core escaped hidden/control characters in this request (#246). */
  readonly hasHiddenOrControlChars: boolean;
  /**
   * The context `summary` (the integrator's description, escaped), absent when the request could
   * not be prepared. It is hash-bound, so it is shown; it is not the action, which stays primary.
   */
  readonly contextSummary?: string;
  /** True when raw and the hash-bound argv describe different commands; see `divergentArgv`. */
  readonly rawArgvDiverges: boolean;
}

/**
 * A resolved audit-history record: an `ApprovalDetail` extended with `decidedAt` and a
 * chain-integrity status derived from what the runtime could verify. This is the type consumed by
 * the audit-history view; it is read-only and never carries an approvable action.
 *
 * `chainStatus` is fail-closed: any record that could not be fully verified by the WASM core during
 * `prepare` renders as `"broken"`, never as `"verified"`. Records the core successfully prepared
 * render as `"verified"` (the chain link was intact at prepare time). The history view must make
 * broken/unverifiable records visually prominent and must never display them as approved-looking.
 *
 * @see docs/contract.md §Audit chain
 */
export interface AuditHistoryItem extends ApprovalDetail {
  /** Unix-ms at which the controller recorded the terminal decision (or `undefined` when resolved
   *  by the relay before this device processed it — the envelope's `resolved_at` covers that). */
  readonly decidedAt?: number;
  /** Chain integrity from the runtime's `prepare` pass.
   *  - `"verified"` — the core processed this record without error.
   *  - `"broken"` — `prepare` threw (tampered/undecryptable/unverifiable); fail-closed. */
  readonly chainStatus: "verified" | "broken";
}

interface ApprovalRecord {
  readonly envelope: ApprovalEnvelope;
  readonly expiresAt: number;
  readonly prepared?: PreparedApproval;
  readonly verificationError?: string;
  status: ApprovalStatus;
  decidedAt?: number;
}

export class WebApproverController {
  readonly #runtime: WebApproverRuntime;
  readonly #nowMs: () => number;
  readonly #records = new Map<string, ApprovalRecord>();

  constructor(options: WebApproverControllerOptions) {
    this.#runtime = options.runtime;
    this.#nowMs = options.nowMs ?? Date.now;
  }
  /**
   * Render untrusted text (an error message, which can embed a relay-supplied id or HTTP body) for
   * the DOM through the runtime's core escape, or withhold it when the runtime has none (#246).
   */
  escapeForDisplay(text: string): string {
    return this.#runtime.escapeForDisplay?.(text) ?? WITHHELD_ERROR_TEXT;
  }

  /**
   * Refreshes the controller from relay-visible envelopes. Each envelope is prepared
   * independently so one tampered/undecryptable request cannot hide the rest of the inbox.
   */
  async sync(envelopes: readonly ApprovalEnvelope[]): Promise<void> {
    const preparedRecords = await Promise.all(envelopes.map((envelope) => this.#prepare(envelope)));
    this.#records.clear();

    for (const record of preparedRecords) {
      this.#records.set(record.envelope.id, record);
    }
  }

  inbox(): readonly ApprovalListItem[] {
    return this.#list(["pending", "deciding", "expired", "unverified"]);
  }

  history(): readonly ApprovalListItem[] {
    return this.#list(["approved", "denied"]);
  }

  /**
   * Returns resolved decisions for the audit-history view, sorted most-recent first.
   * Each item carries the full {@link AuditHistoryItem} including `chainStatus` and `decidedAt`.
   * Read-only: the audit history view must never expose approve/deny controls for these items.
   * Fail-closed: records the core could not prepare render with `chainStatus: "broken"` and
   * `denyOnly: true`, so the UI cannot display them as approved-looking evidence.
   */
  auditHistory(): readonly AuditHistoryItem[] {
    return Array.from(this.#records.values())
      .filter((record) => record.status === "approved" || record.status === "denied")
      .map((record) => this.#toAuditHistoryItem(record))
      .sort((left, right) => {
        // Most-recent decision first; fall back to expiresAt for relay-resolved records.
        const leftAt = left.decidedAt ?? left.expiresAt;
        const rightAt = right.decidedAt ?? right.expiresAt;
        return rightAt - leftAt;
      });
  }

  /**
   * Remove a request resolved on ANOTHER device/surface (relay `{type:"retract"}`, #150;
   * `docs/relay-api.md` §4). Deletes the record outright rather than merely marking it hidden, so
   * the approve/deny path becomes structurally unreachable — `canApprove`/`decide` treat the id as
   * unknown afterward, and it disappears from `inbox()`/`detail()` on the next render. This
   * matches the fleet's UI-unreachable-states convention (`docs/apple-approver-app.md` §6.7,
   * `docs/enrollment.md`): an unsafe state must be impossible to reach, not just unstyled.
   *
   * A record this device has already decided locally (`status` is `"approved"`/`"denied"`) is left
   * untouched: the relay only retracts a request from devices OTHER than the one whose verdict won
   * (`docs/relay-api.md` §4), so a retract should never arrive for our own winning decision — and
   * even if one did (a lost race with another device, before verdict submission is wired up),
   * preserving the locally-recorded decision here avoids silently erasing this device's own audit
   * history entry.
   *
   * @returns `true` when a record was removed, `false` when `id` was unknown or already terminal.
   */
  retract(id: string): boolean {
    const record = this.#records.get(id);
    if (!record) {
      return false;
    }
    if (record.status === "approved" || record.status === "denied") {
      return false;
    }
    this.#records.delete(id);
    return true;
  }

  detail(id: string): ApprovalDetail | undefined {
    const record = this.#records.get(id);
    if (!record) {
      return undefined;
    }
    return this.#toDetail(record);
  }

  canApprove(id: string, options: { readonly challengeResponse?: string } = {}): boolean {
    const record = this.#records.get(id);
    if (
      !record?.prepared ||
      this.#markExpiredIfPastDeadline(record) ||
      record.status !== "pending"
    ) {
      return false;
    }
    if (!record.prepared.context.allowed_decisions.includes("approved")) {
      return false;
    }
    return this.#challengeSatisfied(record.prepared.context, options.challengeResponse);
  }

  async decide(
    id: string,
    decision: ApprovalDecision,
    options: { readonly challengeResponse?: string } = {},
  ): Promise<SignedVerdict> {
    const record = this.#records.get(id);
    if (!record) {
      throw new Error(`unknown request '${id}'`);
    }
    if (this.#markExpiredIfPastDeadline(record)) {
      throw new Error(`request '${id}' is expired`);
    }
    if (record.status === "deciding") {
      throw new Error(`request '${id}' is already being decided`);
    }
    if (!record.prepared || record.status === "unverified") {
      throw new Error(`request '${id}' is not approvable`);
    }
    if (!record.prepared.context.allowed_decisions.includes(decision)) {
      throw new Error(`decision '${decision}' is not allowed for request '${id}'`);
    }
    if (decision === "approved" && !this.canApprove(id, options)) {
      if (record.prepared.context.challenge?.kind === "number-match") {
        throw new Error(`number-match challenge failed for request '${id}'`);
      }
      throw new Error(`request '${id}' is not approvable`);
    }

    const signInput = this.#signInput(record, decision, options.challengeResponse);
    // Claim the request before signing so duplicate submits cannot produce two verdicts.
    record.status = "deciding";
    try {
      const verdict = await this.#runtime.signDecision(signInput);
      record.status = decision;
      record.decidedAt = this.#nowMs();
      return verdict;
    } catch (error) {
      record.status = "pending";
      throw error;
    }
  }

  #markExpiredIfPastDeadline(record: ApprovalRecord): boolean {
    if (record.status === "pending" && record.prepared && record.expiresAt <= this.#nowMs()) {
      record.status = "expired";
    }
    return record.status === "expired";
  }

  async #prepare(envelope: ApprovalEnvelope): Promise<ApprovalRecord> {
    try {
      const prepared = await this.#runtime.prepare(envelope);
      if (!Number.isFinite(prepared.expiresAt)) {
        throw new Error("prepared approval is missing a core-verified expiry");
      }
      const resolvedDecision = prepared.resolvedDecision;
      if (resolvedDecision) {
        return { envelope, expiresAt: prepared.expiresAt, prepared, status: resolvedDecision };
      }
      return {
        envelope,
        expiresAt: prepared.expiresAt,
        prepared,
        status: prepared.expiresAt <= this.#nowMs() ? "expired" : "pending",
      };
    } catch (error) {
      return {
        envelope,
        expiresAt: envelope.expires_at,
        status: "unverified",
        verificationError: this.escapeForDisplay(
          error instanceof Error ? error.message : String(error),
        ),
      };
    }
  }

  #list(statuses: readonly ApprovalStatus[]): readonly ApprovalListItem[] {
    return Array.from(this.#records.values())
      .filter((record) => statuses.includes(record.status))
      .map((record) => this.#toListItem(record))
      .sort((left, right) => {
        if (left.status === "pending" && right.status === "pending") {
          return left.expiresAt - right.expiresAt;
        }
        return right.expiresAt - left.expiresAt;
      });
  }

  #toListItem(record: ApprovalRecord): ApprovalListItem {
    const context = record.prepared?.context;
    return {
      id: record.envelope.id,
      status: record.status,
      actor: context?.actor.display ?? "Unverified request",
      riskLevel: context?.risk.level ?? "unknown",
      summary: context ? actionSummary(context) : "Unable to verify or decrypt this request",
      expiresAt: record.expiresAt,
      countdownMs: Math.max(0, record.expiresAt - this.#nowMs()),
      denyOnly: record.status === "unverified" || record.status === "expired",
    };
  }

  #toDetail(record: ApprovalRecord): ApprovalDetail {
    const item = this.#toListItem(record);
    const prepared = record.prepared;
    const context = prepared?.context;
    const base = {
      ...item,
      exactPlaintext: context ? exactPlaintext(context) : "Context could not be verified.",
      hasHiddenOrControlChars: context?.hasHiddenOrControlChars === true,
      rawArgvDiverges: context?.divergentArgv !== undefined,
    };

    if (!prepared) {
      return {
        ...base,
        verificationError: record.verificationError ?? "unverified request",
      };
    }

    const detail: ApprovalDetail = {
      ...base,
      contextSummary: prepared.context.risk.summary,
      requestHash: prepared.requestHash,
      actorId: prepared.context.actor.id,
      attestation: prepared.context.actor.attestation,
      reversible: prepared.context.risk.reversible,
    };
    if (prepared.context.challenge) {
      return { ...detail, challenge: prepared.context.challenge };
    }
    return detail;
  }

  #challengeSatisfied(context: ApprovalContext, challengeResponse: string | undefined): boolean {
    const challenge = context.challenge;
    if (!challenge) {
      return true;
    }
    return challengeResponse === challenge.code;
  }

  #signInput(
    record: ApprovalRecord,
    decision: ApprovalDecision,
    challengeResponse: string | undefined,
  ): SignDecisionInput {
    if (!record.prepared) {
      throw new Error(`request '${record.envelope.id}' has no prepared plaintext`);
    }
    const input: SignDecisionInput = {
      envelope: record.envelope,
      prepared: record.prepared,
      decision,
    };
    if (challengeResponse !== undefined) {
      return { ...input, challengeResponse };
    }
    return input;
  }

  /**
   * Map a resolved `ApprovalRecord` to an `AuditHistoryItem`. `chainStatus` is derived from
   * whether `prepare` succeeded: records without a `prepared` value had a prepare error ⇒ broken.
   * The audit history view must render broken records with fail-closed language and visual
   * prominence — never as approved-looking evidence (see `docs/contract.md` §Invariants #6).
   */
  #toAuditHistoryItem(record: ApprovalRecord): AuditHistoryItem {
    const detail = this.#toDetail(record);
    const chainStatus: AuditHistoryItem["chainStatus"] = record.prepared ? "verified" : "broken";
    const base: AuditHistoryItem = { ...detail, chainStatus };
    if (record.decidedAt !== undefined) {
      return { ...base, decidedAt: record.decidedAt };
    }
    return base;
  }
}

/** The headline of a record with no command, tool or file-edit fields (the CLI's wording). */
export const NO_ACTION_FIELDS_HEADLINE = "(no command, tool, or file-edit fields)";

/**
 * One-line headline for a list row and a card heading. Uses the CLI's precedence
 * (`renderActionHeadline` in `packages/approver/src/lib/render.ts`), whatever the surface, so a
 * record that mixes substrates (an `mcp_tool_call` also carrying `argv`) heads with the command,
 * not the benign-looking tool name. The shared fixture `test/fixtures/action-headline.json` keeps
 * the two approvers in step.
 *
 * 1. When raw and argv diverge: the hash-bound argv form, never the possibly benign `raw` (the card
 *    then shows a warning and both forms).
 * 2. A file edit: its diff summary, else `operation paths`.
 * 3. `raw`; else the command `bin`/`argv` reconstruct to.
 * 4. A tool call: `server :: tool` (a `.` join would make server `fs.delete` + tool `x` look like
 *    server `fs` + tool `delete.x`), or the tool alone.
 * 5. `operation paths`; else the compact params; else {@link NO_ACTION_FIELDS_HEADLINE}.
 */
export function actionSummary(context: ApprovalContext): string {
  if (context.divergentArgv !== undefined) return context.divergentArgv;
  const s = context.substrate;
  const fileEdit =
    s.operation !== undefined && s.paths !== undefined && s.paths.length > 0
      ? `${s.operation} ${renderList(s.paths)}`
      : undefined;
  if (context.kind === "file_edit") {
    const headline = s.diffSummary ?? fileEdit;
    if (headline !== undefined) return headline;
  }
  if (s.raw !== undefined) return s.raw;
  const reconstructed = reconstructCommand(s);
  if (reconstructed !== undefined) return reconstructed;
  if (s.tool !== undefined) return s.server !== undefined ? `${s.server} :: ${s.tool}` : s.tool;
  return fileEdit ?? s.paramsJson ?? NO_ACTION_FIELDS_HEADLINE;
}

/** Continuation marker for multi-line content, so no later line can pass for a field label. */
const CONTINUATION = "\n   │ ";

/**
 * The full hash-bound action as labelled plain-text lines (the card's and audit receipt's exact
 * plaintext). Every substrate field that is present is shown, whatever the surface, in the order
 * the CLI shows them; the first line names a tool call or file edit. Values come from the core's
 * escaped substrate; this only lays them out (token and list quoting via `command-line.ts`).
 */
export function exactPlaintext(context: ApprovalContext): string {
  const s = context.substrate;
  const lines: string[] = [];
  const toolCallFirst =
    (context.kind === "mcp" || context.kind === "agent_tool_call") &&
    s.server !== undefined &&
    s.tool !== undefined;
  if (toolCallFirst) {
    lines.push(`${context.kind}: ${s.server ?? ""} :: ${s.tool ?? ""}`);
  }
  const operationFirst = context.kind === "file_edit" && s.operation !== undefined;
  if (operationFirst) lines.push(`file_edit: ${s.operation ?? ""}`);

  if (s.cwd !== undefined) lines.push(`cwd: ${s.cwd}`);
  if (s.host !== undefined) lines.push(`host: ${s.host}`);
  if (s.bin !== undefined) lines.push(`bin: ${quoteToken(s.bin)}`);
  if (s.argv !== undefined) lines.push(`argv: ${renderArgv(s.argv)}`);
  if (s.flags !== undefined) lines.push(`flags: ${renderArgv(s.flags)}`);
  if (s.positionals !== undefined) lines.push(`positionals: ${renderArgv(s.positionals)}`);
  if (s.envRefs !== undefined) lines.push(`env_refs: ${renderList(s.envRefs)}`);
  if (!toolCallFirst) {
    if (s.server !== undefined) lines.push(`server: ${s.server}`);
    if (s.tool !== undefined) lines.push(`tool: ${s.tool}`);
  }
  if (s.paramsLines !== undefined) {
    lines.push(`params: ${s.paramsLines.join("\n")}`);
  } else if (toolCallFirst) {
    lines.push("params: (none)");
  }
  if (!operationFirst && s.operation !== undefined) lines.push(`operation: ${s.operation}`);
  if (s.paths !== undefined) lines.push(`paths: ${renderList(s.paths)}`);
  if (s.diffSummary !== undefined) lines.push(`diff_summary: ${s.diffSummary}`);
  if (s.diffHash !== undefined) lines.push(`diff_hash: ${s.diffHash}`);
  const content = s.rawLines ?? (s.raw !== undefined ? [s.raw] : undefined);
  if (content !== undefined) {
    lines.push(
      `${context.kind === "file_edit" ? "content" : "raw"}: ${content.join(CONTINUATION)}`,
    );
  }
  if (context.chain !== undefined) lines.push(`chain: ${renderList(context.chain)}`);
  return lines.length > 0 ? lines.join("\n") : "Unknown action";
}
