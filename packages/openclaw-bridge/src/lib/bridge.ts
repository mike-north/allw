/**
 * The decision + resolution core: one pending OpenClaw exec approval → a verified human decision →
 * `approval.resolve`.
 *
 * This module owns the **fail-closed matrix** (`docs/openclaw-integration.md` §9). Every path either
 * resolves to `deny` or deliberately leaves the approval for OpenClaw's own `askFallback` — never to
 * `allow-once`, and never to silence when the bridge could have denied.
 *
 * Two rows are deliberately *not* denies:
 *
 * - **Unknown / unsupported approval kind** (§5.3). Silently denying an approval family the bridge
 *   cannot even render would make it a denial-of-service on that family. It is logged and left for a
 *   surface that understands it; OpenClaw's own deadline plus `askFallback: deny` still closes it.
 * - **Gateway connection lost.** There is no channel on which to submit anything. A connection lost
 *   and *restored while the approval is still pending* is likewise **not** a deny: the bridge
 *   re-reads `approval.get` and, if the status is still `pending`, submits the verified decision
 *   normally. Failing closed means never inventing an allow — not discarding a human decision that
 *   is still valid.
 *
 * `allow-always` is **never** submitted, under any input (§7.3): an allw verdict is one-shot and
 * scope-free by construction, while OpenClaw's `allow-always` writes durable standing trust. There
 * is no field to carry it and no code path that can emit it — the mapping is structurally absent,
 * not merely unsupported.
 *
 * @see ../../../../docs/openclaw-integration.md §5.3, §6.1, §7.2–7.4, §8, §9
 * @see ../../../../docs/contract.md §Invariants #6 (fail-closed), #5 (a verdict only tightens)
 */

import type { HookWasm } from "@allw/hook";

import { deriveTimeout } from "./budget.js";
import type { BridgeConfig } from "./config.js";
import type { ApprovalGateway, GatewayEvent } from "./gateway.js";
import type { Logger } from "./logging.js";
import {
  buildExecApprovalRequest,
  type BridgeApprovalRequest,
  type DenyReason,
} from "./mapping.js";
import {
  APPROVAL_GET_METHOD,
  APPROVAL_RESOLVE_METHOD,
  EXEC_APPROVAL_LIST_METHOD,
  kindForEvent,
  readApprovalListIds,
  readApprovalResolveResult,
  readApprovalSnapshot,
  readExecApprovalRequestedEvent,
  type ApprovalSnapshot,
  type ExecApprovalRequestedEvent,
} from "./protocol.js";

/** The verdict surface the bridge consumes from `@allw/sdk`. */
export interface BridgeVerdict {
  readonly decision: "approved" | "denied" | "expired" | "aborted";
  /** Re-runs full verification against the account root. Returns `true` only when approved. */
  verify(approverRootKey: string): Promise<boolean>;
}

/** Injectable approval call; production is `client.requestApproval`. */
export type RequestApprovalFn = (req: BridgeApprovalRequest) => Promise<BridgeVerdict>;

/** Everything the decision core needs. All seams are injectable so tests drive them determinstically. */
export interface BridgeDeps {
  readonly gateway: ApprovalGateway;
  readonly wasm: HookWasm;
  readonly requestApproval: RequestApprovalFn;
  readonly config: BridgeConfig;
  readonly logger: Logger;
  /** Local wall clock in ms. Only ever used to measure *elapsed* time (see {@link gatewayNowMs}). */
  readonly now: () => number;
}

/** What the bridge did with one approval — the unit `test/bridge.test.mjs` asserts on. */
export type ApprovalOutcome =
  | {
      readonly kind: "resolved";
      readonly decision: "allow-once" | "deny";
      readonly applied: boolean;
    }
  /** Deliberately left for another surface / OpenClaw's own fallback. */
  | {
      readonly kind: "left-open";
      readonly why: "unsupported-approval-kind" | "not-pending" | "unresolvable";
    }
  /** Already handled (in flight or terminal). */
  | { readonly kind: "ignored" };

const VERDICT_DENY_REASON: Readonly<Record<"denied" | "expired" | "aborted", DenyReason>> = {
  denied: "no-approval",
  expired: "timeout",
  aborted: "aborted",
};

/**
 * Anchor "now" to the **gateway's** clock (§8): `expiresAtMs` and `createdAtMs` come from the
 * gateway, so the budget is computed in the gateway's epoch and the local clock contributes only the
 * elapsed delta since the event was received. The bridge must not assume its own clock agrees with
 * the gateway's.
 */
function gatewayNowMs(
  deps: BridgeDeps,
  createdAtMs: number | undefined,
  receivedAtMs: number,
): number {
  const localNow = deps.now();
  if (createdAtMs === undefined) return localNow;
  return createdAtMs + (localNow - receivedAtMs);
}

/** Synthesize the exec event shape from a sanitized snapshot, for approvals that predate the
 * connection (backfill, §4.3). The snapshot deliberately withholds `systemRunPlan`, so this takes
 * §5.1's documented last-resort branch: the core tokenizes `presentation.commandText`, and the
 * absent `cwd` renders as an explicit "working directory not bound" line (§6.3). */
function execEventFromSnapshot(snapshot: ApprovalSnapshot): ExecApprovalRequestedEvent | null {
  const commandText = snapshot.presentation.commandText;
  if (commandText === undefined) return null;
  return {
    id: snapshot.id,
    expiresAtMs: snapshot.expiresAtMs,
    ...(snapshot.createdAtMs !== undefined ? { createdAtMs: snapshot.createdAtMs } : {}),
    request: { command: commandText },
  };
}

/**
 * The bridge: subscribes to approval broadcasts, projects pending approvals on every connect, and
 * drives each exec approval to a resolve.
 */
export class OpenClawBridge {
  private readonly deps: BridgeDeps;
  /** Approval ids currently being driven, so a backfill racing a live event never double-raises. */
  private readonly inFlight = new Set<string>();
  /** Ids the gateway has reported resolved, so a late backfill cannot resurrect them. */
  private readonly settled = new Set<string>();

  constructor(deps: BridgeDeps) {
    this.deps = deps;
  }

  /** Install the broadcast listener. Must be called **before** {@link project} (§4.3). */
  listen(): () => void {
    return this.deps.gateway.addEventListener((event) => {
      void this.handle(event);
    });
  }

  /**
   * Re-project pending approvals from scratch: backfill the gateway's pending list, drop any
   * in-memory entry the gateway no longer reports as pending, and drive the rest. Treating every
   * reconnect as a fresh projection (not a delta) is what makes a transition that raced the backfill
   * neither lost nor resurrected (§4.3).
   */
  async project(): Promise<void> {
    let ids: readonly string[];
    try {
      ids = readApprovalListIds(await this.deps.gateway.request(EXEC_APPROVAL_LIST_METHOD, {}));
    } catch (err) {
      this.deps.logger.error("backfill.failed", {
        message: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    const pending = new Set(ids);
    // Reconcile by approval id: anything we still hold that the gateway no longer lists as pending
    // was resolved elsewhere; drop it rather than continuing to drive it.
    for (const id of [...this.inFlight]) {
      if (!pending.has(id)) this.inFlight.delete(id);
    }
    this.deps.logger.info("backfill.projected", { pending: pending.size });

    for (const id of pending) {
      if (this.settled.has(id) || this.inFlight.has(id)) continue;
      await this.driveFromBackfill(id);
    }
  }

  /**
   * Route one broadcast frame and drive it to completion. Public (rather than an internal callback)
   * so the fail-closed matrix can be asserted per row without racing an un-awaited promise.
   */
  async handle(event: GatewayEvent): Promise<ApprovalOutcome> {
    if (event.event.endsWith(".approval.resolved")) {
      const id = readResolvedId(event.payload);
      if (id !== null) {
        this.inFlight.delete(id);
        this.settled.add(id);
      }
      return { kind: "ignored" };
    }
    if (!event.event.endsWith(".approval.requested")) return { kind: "ignored" };

    const family = kindForEvent(event.event);
    if (family === null) {
      // §5.3: an approval family the bridge cannot render is neither approved nor denied.
      this.deps.logger.warn("unsupported-approval-kind", { event: event.event });
      return { kind: "left-open", why: "unsupported-approval-kind" };
    }
    if (family === "plugin") {
      // The plugin permission-request family (§5.2, `agent_tool_call`) is not implemented in this
      // slice. It gets the same treatment as an unsupported kind — left for another surface —
      // because denying a family the bridge cannot render would be a denial-of-service on it.
      this.deps.logger.warn("approval-family-not-implemented", { event: event.event });
      return { kind: "left-open", why: "unsupported-approval-kind" };
    }

    const declaredKind = readDeclaredKind(event.payload);
    if (declaredKind !== null && declaredKind !== "exec") {
      // A payload riding the exec event but declaring another kind (e.g. `system-agent`) fails the
      // family/payload cross-check (§5.3). Neither approve nor deny it.
      this.deps.logger.warn("unsupported-approval-kind", {
        event: event.event,
        approvalKind: declaredKind,
      });
      return { kind: "left-open", why: "unsupported-approval-kind" };
    }

    const parsed = readExecApprovalRequestedEvent(event.payload);
    if (parsed === null) {
      const id = readResolvedId(event.payload);
      if (id === null) {
        // No readable id ⇒ nothing can be resolved. OpenClaw's own deadline closes it.
        this.deps.logger.error("event.unreadable", { event: event.event });
        return { kind: "left-open", why: "unresolvable" };
      }
      return await this.resolveDeny(
        id,
        "build-error",
        "exec.approval.requested payload unreadable",
      );
    }

    return await this.driveExec(parsed, this.deps.now());
  }

  /** Drive an approval discovered by backfill rather than by a live event. */
  private async driveFromBackfill(id: string): Promise<ApprovalOutcome> {
    const snapshot = await this.readSnapshot(id);
    if (snapshot === null) {
      return await this.resolveDeny(id, "presentation-divergence", "approval.get unreadable");
    }
    if (snapshot.status !== "pending") {
      this.settled.add(id);
      return { kind: "left-open", why: "not-pending" };
    }
    if (snapshot.presentation.kind !== "exec") {
      this.deps.logger.warn("unsupported-approval-kind", {
        approvalKind: snapshot.presentation.kind,
      });
      return { kind: "left-open", why: "unsupported-approval-kind" };
    }
    const synthesized = execEventFromSnapshot(snapshot);
    if (synthesized === null) {
      return await this.resolveDeny(
        id,
        "build-error",
        "backfilled exec approval carried no command text",
      );
    }
    return await this.driveExec(synthesized, this.deps.now(), snapshot);
  }

  /** The exec end-to-end path: reconcile → budget → request → verify → resolve. */
  private async driveExec(
    event: ExecApprovalRequestedEvent,
    receivedAtMs: number,
    known?: ApprovalSnapshot,
  ): Promise<ApprovalOutcome> {
    if (this.settled.has(event.id) || this.inFlight.has(event.id)) return { kind: "ignored" };
    this.inFlight.add(event.id);
    try {
      // §6.1: `approval.get` is the authority for lifecycle and the reviewer contract, and it is
      // read *before* the context is built so a divergent pair is never shown to a human at all.
      const snapshot = known ?? (await this.readSnapshot(event.id));
      if (snapshot === null) {
        return await this.resolveDeny(
          event.id,
          "presentation-divergence",
          "approval.get returned an unreadable snapshot; the two sources cannot be reconciled",
        );
      }

      const nowMs = gatewayNowMs(
        this.deps,
        event.createdAtMs ?? snapshot.createdAtMs,
        receivedAtMs,
      );
      const budget = deriveTimeout({
        expiresAtMs: snapshot.expiresAtMs,
        nowMs,
        deadlineMarginMs: this.deps.config.deadlineMarginMs,
        minTimeoutMs: this.deps.config.minTimeoutMs,
        maxTimeoutMs: this.deps.config.maxTimeoutMs,
      });
      if (budget.kind === "insufficient") {
        // §8: raising a prompt that is doomed to expire is worse than an immediate, explainable deny.
        return await this.resolveDeny(
          event.id,
          "insufficient-budget",
          `remaining budget ${String(budget.budgetMs)}ms is below the minimum`,
        );
      }

      const mapped = buildExecApprovalRequest(this.deps.wasm, {
        event,
        snapshot,
        gatewayId: this.deps.config.gatewayId,
        timeoutMs: budget.timeoutMs,
      });
      if (mapped.kind === "deny") {
        return await this.resolveDeny(event.id, mapped.reason, mapped.detail);
      }
      if (mapped.kind === "not-pending") {
        // §6.1 rule 4 — the recorded record is authoritative; submit nothing.
        this.settled.add(event.id);
        this.deps.logger.info("approval.already-terminal", {
          approvalId: event.id,
          status: mapped.status,
        });
        return { kind: "left-open", why: "not-pending" };
      }

      let verdict: BridgeVerdict;
      try {
        verdict = await this.deps.requestApproval(mapped.request);
      } catch (err) {
        return await this.resolveDeny(
          event.id,
          "transport-error",
          err instanceof Error ? err.message : String(err),
        );
      }

      if (verdict.decision !== "approved") {
        return await this.resolveDeny(
          event.id,
          VERDICT_DENY_REASON[verdict.decision],
          `verdict decision was '${verdict.decision}'`,
        );
      }

      // §7.2: `allow-once` is submitted **only** for a verdict that is approved *and* passed full
      // verification. Re-running the check here makes "verification failure is a deny, never a
      // skipped check" a property of this code path, not of a caller's discipline.
      let verified: boolean;
      try {
        verified = await verdict.verify(this.deps.config.approverRootKey);
      } catch {
        verified = false;
      }
      if (!verified) {
        return await this.resolveDeny(
          event.id,
          "verify-error",
          "approved verdict failed re-verification",
        );
      }

      return await this.submitApproval(event.id, snapshot);
    } finally {
      this.inFlight.delete(event.id);
    }
  }

  /**
   * Submit `allow-once` for a verified approval — after re-reading the canonical status, because the
   * connection may have dropped and been restored while the human decided (§9).
   */
  private async submitApproval(
    id: string,
    priorSnapshot: ApprovalSnapshot,
  ): Promise<ApprovalOutcome> {
    const current = await this.readSnapshot(id);
    if (current === null) {
      // No channel / unreadable projection ⇒ the bridge cannot submit anything. OpenClaw's own
      // deadline plus `askFallback: deny` closes it (§9).
      this.deps.logger.error("resolve.unavailable", { approvalId: id, reason: "transport-error" });
      return { kind: "left-open", why: "unresolvable" };
    }
    if (current.status !== "pending") {
      // Another surface won first. The recorded record is authoritative; submit nothing (§7.4).
      this.settled.add(id);
      this.deps.logger.info("approval.won-elsewhere", { approvalId: id, status: current.status });
      return { kind: "left-open", why: "not-pending" };
    }

    // §7.4: check `allow-once` is actually offered. The schema permits `["deny"]` alone, and
    // `["allow-always", "deny"]` is expressible — in either case an approved verdict cannot be
    // faithfully expressed. Fabricating `allow-always` is forbidden by §7.3, and submitting nothing
    // would leave the run hanging, so the answer is a loud `deny`.
    const offered =
      current.presentation.allowedDecisions.length > 0
        ? current.presentation.allowedDecisions
        : priorSnapshot.presentation.allowedDecisions;
    if (!offered.includes("allow-once")) {
      return await this.resolveDeny(
        id,
        "no-expressible-allow",
        `approval offered ${JSON.stringify(offered)}; an approved verdict cannot be expressed`,
      );
    }

    return await this.submit(id, "allow-once", null);
  }

  /** Resolve `deny` with a machine-readable reason. `deny` is always in `allowedDecisions` (§7.4). */
  private async resolveDeny(
    id: string,
    reason: DenyReason,
    detail: string,
  ): Promise<ApprovalOutcome> {
    this.deps.logger.warn("approval.denied", { approvalId: id, reason, detail });
    return await this.submit(id, "deny", reason);
  }

  /** Issue the kind-agnostic `approval.resolve` and honour the first-answer-wins response. */
  private async submit(
    id: string,
    decision: "allow-once" | "deny",
    reason: DenyReason | null,
  ): Promise<ApprovalOutcome> {
    let applied: boolean;
    try {
      const result = readApprovalResolveResult(
        // The exact canonical id and the kind derived from the event family — never a truncated id,
        // a hash prefix, or a kind inferred from an id prefix (§7.4).
        await this.deps.gateway.request(APPROVAL_RESOLVE_METHOD, { id, kind: "exec", decision }),
      );
      applied = result.applied;
      if (!applied) {
        // Another surface answered first. Adopt the recorded winner; never re-submit. A lost
        // acknowledgement is reconciled by re-reading `approval.get`, not by resolving again (§7.4).
        this.settled.add(id);
        this.deps.logger.info("approval.not-applied", {
          approvalId: id,
          winner: result.record?.decision ?? null,
        });
      }
    } catch (err) {
      this.deps.logger.error("resolve.failed", {
        approvalId: id,
        decision,
        message: err instanceof Error ? err.message : String(err),
      });
      return { kind: "left-open", why: "unresolvable" };
    }
    this.settled.add(id);
    this.deps.logger.info("approval.resolved", { approvalId: id, decision, applied, reason });
    return { kind: "resolved", decision, applied };
  }

  /** Read the pinned snapshot, returning `null` for both an RPC failure and an unreadable payload. */
  private async readSnapshot(id: string): Promise<ApprovalSnapshot | null> {
    try {
      return readApprovalSnapshot(await this.deps.gateway.request(APPROVAL_GET_METHOD, { id }));
    } catch (err) {
      this.deps.logger.error("approval-get.failed", {
        approvalId: id,
        message: err instanceof Error ? err.message : String(err),
      });
      return null;
    }
  }
}

/** Read an approval id off an arbitrary event payload without trusting its shape. */
function readResolvedId(payload: unknown): string | null {
  if (typeof payload !== "object" || payload === null) return null;
  const id = (payload as { id?: unknown }).id;
  return typeof id === "string" && id.length > 0 ? id : null;
}

/** Read a payload's self-declared `approvalKind`, for the §5.3 family cross-check. */
function readDeclaredKind(payload: unknown): string | null {
  if (typeof payload !== "object" || payload === null) return null;
  const kind = (payload as { approvalKind?: unknown }).approvalKind;
  return typeof kind === "string" && kind.length > 0 ? kind : null;
}
