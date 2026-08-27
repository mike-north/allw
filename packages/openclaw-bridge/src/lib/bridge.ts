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
 * **Integrator-initiated retract (issue #222).** While a request is in flight, `handle()` holds an
 * `AbortController` for its approval id. If a `*.approval.resolved` broadcast for that SAME id
 * arrives before the bridge's own `requestApproval` call settles, the controller is aborted —
 * telling `@allw/sdk` to retract the pending relay request so connected approver devices drop the
 * stale prompt live rather than riding out the full timeout. This is purely inbox hygiene: it never
 * changes the outcome the bridge submits (first-answer-wins, §9, already decided that), and the
 * bridge never issues a second `approval.resolve` for an id it has already learned is `settled`.
 *
 * @see ../../../../docs/openclaw-integration.md §5.3, §6.1, §7.2–7.5, §8, §9
 * @see ../../../../docs/contract.md §Invariants #6 (fail-closed), #5 (a verdict only tightens)
 */

import type { HookWasm } from "@allw/hook";

import { deriveTimeout } from "./budget.js";
import type { BridgeConfig } from "./config.js";
import type { ApprovalGateway, GatewayEvent } from "./gateway.js";
import type { Logger } from "./logging.js";
import {
  buildExecApprovalRequest,
  buildPluginApprovalRequest,
  type BridgeApprovalRequest,
  type DenyReason,
} from "./mapping.js";
import {
  APPROVAL_GET_METHOD,
  APPROVAL_RESOLVE_METHOD,
  EXEC_APPROVAL_LIST_METHOD,
  PLUGIN_APPROVAL_LIST_METHOD,
  isExecPresentation,
  isPluginPresentation,
  kindForEvent,
  readApprovalList,
  readApprovalResolveResult,
  readApprovalSnapshot,
  readExecApprovalRequestedEvent,
  readPluginApprovalRequestedEvent,
  type ApprovalKind,
  type ApprovalSnapshot,
  type ExecApprovalRequestedEvent,
  type PluginApprovalRequestedEvent,
} from "./protocol.js";

/** Either family's requested-event shape, once parsed (spec §5.1, §5.2). */
type RequestedEvent = ExecApprovalRequestedEvent | PluginApprovalRequestedEvent;

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
  if (!isExecPresentation(snapshot.presentation)) return null;
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
 * Synthesize the plugin event shape from a sanitized snapshot, for approvals discovered by
 * backfill (§4.3). Unlike exec, this is a **faithful** binding, not a last resort: the pinned
 * `PluginApprovalPresentation` carries the real `pluginId`, `toolName`, `severity`, `detail`, and
 * `agentId` (verified against the installed `@openclaw/gateway-protocol` schema — `title`,
 * `description`, `severity`, and `allowedDecisions` are schema-required; `detail`/`pluginId`/
 * `toolName`/`agentId` schema-optional). There is no untyped event to reconcile against during
 * backfill, so every overlapping field here is copied straight from the snapshot; downstream
 * reconciliation in `buildPluginApprovalRequest` trivially agrees with itself and the snapshot's
 * values are used as canonical, exactly as they would be for a live event.
 */
function pluginEventFromSnapshot(snapshot: ApprovalSnapshot): PluginApprovalRequestedEvent | null {
  if (!isPluginPresentation(snapshot.presentation)) return null;
  const p = snapshot.presentation;
  return {
    id: snapshot.id,
    expiresAtMs: snapshot.expiresAtMs,
    ...(snapshot.createdAtMs !== undefined ? { createdAtMs: snapshot.createdAtMs } : {}),
    request: {
      pluginId: p.pluginId,
      title: p.title,
      description: p.description,
      detail: p.detail,
      severity: p.severity,
      toolName: p.toolName,
      agentId: p.agentId,
      allowedDecisions: p.allowedDecisions,
      // `toolCallId`/`sessionKey` are not part of the pinned presentation — backfill loses the
      // `openclaw:tool_call:<id>` chain component a live event would have carried. That is a
      // best-effort audit-correlation gap, not missing required substrate.
    },
  };
}

/**
 * The bridge: subscribes to approval broadcasts, projects pending approvals on every connect, and
 * drives each exec approval to a resolve.
 */
export class OpenClawBridge {
  private readonly deps: BridgeDeps;
  /**
   * Approval ids currently being driven, so a backfill racing a live event never double-raises.
   * Keyed to each id's family so {@link project}'s per-family prune never drops an id whose OWN
   * family's list call failed (§4.3) — see the prune-safety note there.
   */
  private readonly inFlight = new Map<string, ApprovalKind>();
  /** Ids the gateway has reported resolved, so a late backfill cannot resurrect them. */
  private readonly settled = new Set<string>();
  /**
   * One `AbortController` per approval id **while its `requestApproval` call is actually
   * outstanding** (issue #222) — armed in {@link driveApproval} and removed the instant that call
   * settles. Because it is removed before the bridge submits its own resolve, a `*.approval.resolved`
   * broadcast for an id the bridge itself just decided finds nothing here to abort.
   */
  private readonly abortControllers = new Map<string, AbortController>();

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
   * Re-project pending approvals from scratch: backfill **both** families' pending lists
   * (`exec.approval.list`, `plugin.approval.list` — §4.3), drop any in-memory entry the gateway no
   * longer reports as pending, and drive the rest. Treating every reconnect as a fresh projection
   * (not a delta) is what makes a transition that raced the backfill neither lost nor resurrected.
   *
   * The two lists are backfilled independently: a failure fetching one family's list (e.g. the
   * gateway drops mid-request) is logged and does not prevent the other family's backfill from
   * running.
   *
   * **Prune safety.** The reconcile prune below MUST only drop an in-flight id when that id's OWN
   * family's list call succeeded. If it pruned by the union of both lists, a failed `plugin`
   * list call would make every in-flight *exec* id — genuinely still pending, just absent from an
   * error rather than absent from a real list — look unreconciled too, but worse: a failed
   * `plugin` list call would incorrectly prune in-flight *plugin* ids (they are silently absent
   * from `kindById` because their list call errored, not because the gateway stopped reporting
   * them pending). A pruned-but-still-pending id then gets re-driven by the next live event or
   * backfill pass, raising a duplicate approval prompt for the same approval. Tracking which
   * families' list calls actually succeeded and gating the prune per id's own family on that
   * closes the hole.
   */
  async project(): Promise<void> {
    const byId = new Map<
      string,
      { readonly kind: ApprovalKind; readonly snapshot: ApprovalSnapshot | null }
    >();
    const succeededFamilies = new Set<ApprovalKind>();
    for (const [kind, method] of [
      ["exec", EXEC_APPROVAL_LIST_METHOD],
      ["plugin", PLUGIN_APPROVAL_LIST_METHOD],
    ] as const) {
      try {
        const entries = readApprovalList(await this.deps.gateway.request(method, {}));
        for (const entry of entries) byId.set(entry.id, { kind, snapshot: entry.snapshot });
        succeededFamilies.add(kind);
      } catch (err) {
        this.deps.logger.error("backfill.failed", {
          family: kind,
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }

    const pending = new Set(byId.keys());
    // Reconcile by approval id, but only within a family whose list call actually succeeded
    // (see the prune-safety note above): anything we still hold in a succeeded family that the
    // gateway no longer lists as pending was resolved elsewhere, so drop it. An id whose family's
    // list call failed is left exactly as-is — neither pruned nor resurrected — until a later
    // successful projection can reconcile it for real.
    for (const [id, trackedKind] of [...this.inFlight]) {
      if (succeededFamilies.has(trackedKind) && !pending.has(id)) this.inFlight.delete(id);
    }
    this.deps.logger.info("backfill.projected", { pending: pending.size });

    for (const [id, { kind, snapshot }] of byId) {
      if (this.settled.has(id) || this.inFlight.has(id)) continue;
      await this.driveFromBackfill(id, kind, snapshot);
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
        // Retract, if we are still waiting on our own `requestApproval` call for this SAME id
        // (issue #222): another OpenClaw surface already won (§9 first-answer-wins), so the
        // pending allw prompt is now dead weight — abort() tells `@allw/sdk` to retract it so
        // connected approver devices drop it live instead of riding out the full timeout. A
        // no-op when the bridge has no live controller for `id` — including when this broadcast
        // is an echo of the bridge's OWN resolve (driveApproval already removed its controller
        // before submitting).
        this.abortControllers.get(id)?.abort();
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

    const declaredKind = readDeclaredKind(event.payload);
    if (declaredKind !== null && declaredKind !== family) {
      // A payload riding one family's event but declaring another kind (e.g. `system-agent` on
      // the exec channel) fails the family/payload cross-check (§5.3). Neither approve nor deny it.
      this.deps.logger.warn("unsupported-approval-kind", {
        event: event.event,
        approvalKind: declaredKind,
      });
      return { kind: "left-open", why: "unsupported-approval-kind" };
    }

    if (family === "exec") {
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
          "exec",
          "build-error",
          "exec.approval.requested payload unreadable",
        );
      }
      return await this.driveApproval("exec", parsed, this.deps.now());
    }

    const parsed = readPluginApprovalRequestedEvent(event.payload);
    if (parsed === null) {
      const id = readResolvedId(event.payload);
      if (id === null) {
        // No readable id ⇒ nothing can be resolved. OpenClaw's own deadline closes it.
        this.deps.logger.error("event.unreadable", { event: event.event });
        return { kind: "left-open", why: "unresolvable" };
      }
      return await this.resolveDeny(
        id,
        "plugin",
        "build-error",
        "plugin.approval.requested payload unreadable",
      );
    }
    return await this.driveApproval("plugin", parsed, this.deps.now());
  }

  /**
   * Drive an approval discovered by backfill rather than by a live event.
   *
   * `known` is the full record when the `*.approval.list` entry itself carried one (§4.3 —
   * `exec.approval.list`/`plugin.approval.list` are legacy pre-2026.7 methods without a schema-
   * pinned `Result`, but every *other* "list approvals" surface in the pinned protocol returns
   * full `ApprovalSnapshot`-shaped records, e.g. `approval.history`'s `items[]`; see
   * `readApprovalList`). When `known` is `null` (a bare-id list entry, or the family's list call
   * failed to enumerate this id), the bridge falls back to a fresh `approval.get` — the same call
   * every live-event drive already makes.
   *
   * Once a snapshot is in hand, plugin backfill is now a **faithful** binding, not a fabrication:
   * the pinned `PluginApprovalPresentation` carries the real `pluginId`, `toolName`, `severity`,
   * `detail`, and `agentId` (`docs/openclaw-integration.md` §5.2), so it drives through the exact
   * same path a live event would, including the exact same `build-error` (no usable tool identity)
   * and `presentation-divergence` (unreadable/mismatched snapshot) fail-closed outcomes.
   */
  private async driveFromBackfill(
    id: string,
    kind: ApprovalKind,
    known: ApprovalSnapshot | null,
  ): Promise<ApprovalOutcome> {
    const snapshot = known ?? (await this.readSnapshot(id));
    if (snapshot === null) {
      return await this.resolveDeny(id, kind, "presentation-divergence", "approval.get unreadable");
    }
    if (snapshot.status !== "pending") {
      this.settled.add(id);
      return { kind: "left-open", why: "not-pending" };
    }
    if (snapshot.presentation.kind !== kind) {
      // The list method that reported `id` is the backfill's stand-in for the "event family" the
      // live path cross-checks against (§5.3); a snapshot declaring a different kind is exactly
      // the unsupported-kind case, not a divergence (there is only one source here, not two).
      this.deps.logger.warn("unsupported-approval-kind", {
        approvalKind: snapshot.presentation.kind,
      });
      return { kind: "left-open", why: "unsupported-approval-kind" };
    }
    if (kind === "exec") {
      const synthesized = execEventFromSnapshot(snapshot);
      if (synthesized === null) {
        return await this.resolveDeny(
          id,
          "exec",
          "build-error",
          "backfilled exec approval carried no command text",
        );
      }
      return await this.driveApproval("exec", synthesized, this.deps.now(), snapshot);
    }

    const synthesized = pluginEventFromSnapshot(snapshot);
    if (synthesized === null) {
      // Unreachable in practice (the kind check above already confirmed `presentation.kind ===
      // "plugin"`), kept only so the narrowing in `pluginEventFromSnapshot` has a defined,
      // fail-closed return for every input rather than an unsafe assertion.
      return await this.resolveDeny(
        id,
        "plugin",
        "build-error",
        "backfilled plugin approval snapshot was not a plugin presentation",
      );
    }
    return await this.driveApproval("plugin", synthesized, this.deps.now(), snapshot);
  }

  /** The end-to-end path for either family: reconcile → budget → request → verify → resolve. */
  private async driveApproval(
    kind: ApprovalKind,
    event: RequestedEvent,
    receivedAtMs: number,
    known?: ApprovalSnapshot,
  ): Promise<ApprovalOutcome> {
    if (this.settled.has(event.id) || this.inFlight.has(event.id)) return { kind: "ignored" };
    this.inFlight.set(event.id, kind);
    try {
      // §6.1: `approval.get` is the authority for lifecycle and the reviewer contract, and it is
      // read *before* the context is built so a divergent pair is never shown to a human at all.
      const snapshot = known ?? (await this.readSnapshot(event.id));
      if (snapshot === null) {
        return await this.resolveDeny(
          event.id,
          kind,
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
          kind,
          "insufficient-budget",
          `remaining budget ${String(budget.budgetMs)}ms is below the minimum`,
        );
      }

      const mapped =
        kind === "exec"
          ? buildExecApprovalRequest(this.deps.wasm, {
              event,
              snapshot,
              gatewayId: this.deps.config.gatewayId,
              timeoutMs: budget.timeoutMs,
            })
          : buildPluginApprovalRequest(this.deps.wasm, {
              event,
              snapshot,
              gatewayId: this.deps.config.gatewayId,
              timeoutMs: budget.timeoutMs,
            });
      if (mapped.kind === "deny") {
        return await this.resolveDeny(event.id, kind, mapped.reason, mapped.detail);
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

      // Armed for the duration of this call only (issue #222): `handle()`'s `*.approval.resolved`
      // branch aborts it if the SAME id resolves on another OpenClaw surface first, which
      // `@allw/sdk` surfaces as a rejection. The checks below key off `controller.signal.aborted`
      // — THIS call's own retraction — rather than the shared `settled` set, so an unrelated
      // concurrent `driveApproval` call for the same id (e.g. one raised after a backfill prune)
      // that happens to finish first is never mistaken for a retraction of this one.
      const controller = new AbortController();
      this.abortControllers.set(event.id, controller);
      let verdict: BridgeVerdict;
      try {
        verdict = await this.deps.requestApproval({ ...mapped.request, signal: controller.signal });
      } catch (err) {
        if (controller.signal.aborted) {
          // Resolved elsewhere while in flight (§7.4, §9): the `*.approval.resolved` handler
          // already recorded the winner and issued the abort() that produced this rejection.
          // Never submit a second `approval.resolve` for an id already settled.
          this.deps.logger.info("approval.retracted", {
            approvalId: event.id,
            message: err instanceof Error ? err.message : String(err),
          });
          return { kind: "ignored" };
        }
        return await this.resolveDeny(
          event.id,
          kind,
          "transport-error",
          err instanceof Error ? err.message : String(err),
        );
      } finally {
        this.abortControllers.delete(event.id);
      }

      if (controller.signal.aborted) {
        // A race between the retract and the verdict itself: this request was retracted and
        // `requestApproval` nonetheless returned a decision (e.g. the retract call failed and the
        // SDK's own deadline produced an `expired` verdict instead — best-effort cancellation,
        // `docs/openclaw-integration.md` §7.5). The winner recorded elsewhere still stands; do not
        // resolve this decision a second time.
        this.deps.logger.info("approval.retracted", { approvalId: event.id });
        return { kind: "ignored" };
      }

      if (verdict.decision !== "approved") {
        return await this.resolveDeny(
          event.id,
          kind,
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
          kind,
          "verify-error",
          "approved verdict failed re-verification",
        );
      }

      return await this.submitApproval(event.id, kind, snapshot);
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
    kind: ApprovalKind,
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
        kind,
        "no-expressible-allow",
        `approval offered ${JSON.stringify(offered)}; an approved verdict cannot be expressed`,
      );
    }

    return await this.submit(id, kind, "allow-once", null);
  }

  /** Resolve `deny` with a machine-readable reason. `deny` is always in `allowedDecisions` (§7.4). */
  private async resolveDeny(
    id: string,
    kind: ApprovalKind,
    reason: DenyReason,
    detail: string,
  ): Promise<ApprovalOutcome> {
    this.deps.logger.warn("approval.denied", { approvalId: id, reason, detail });
    return await this.submit(id, kind, "deny", reason);
  }

  /** Issue the kind-agnostic `approval.resolve` and honour the first-answer-wins response. */
  private async submit(
    id: string,
    kind: ApprovalKind,
    decision: "allow-once" | "deny",
    reason: DenyReason | null,
  ): Promise<ApprovalOutcome> {
    let applied: boolean;
    try {
      const result = readApprovalResolveResult(
        // The exact canonical id and the kind derived from the event family — never a truncated id,
        // a hash prefix, or a kind inferred from an id prefix (§7.4).
        await this.deps.gateway.request(APPROVAL_RESOLVE_METHOD, { id, kind, decision }),
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
