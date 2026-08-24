/**
 * The fail-closed matrix, one direct test per row.
 *
 * Every path either resolves `deny` or deliberately leaves the approval for OpenClaw's own
 * `askFallback` — never `allow-once`, and never silence where the bridge could have denied. Two rows
 * are deliberately non-denies (unknown kind; connection lost), and both are asserted here as
 * *absence of a resolve*, not as a deny.
 *
 * The single most load-bearing assertion in this file is negative: **`allow-always` is never
 * submitted under any input.**
 *
 * @see ../../../docs/openclaw-integration.md §5.3, §7.2, §7.3, §7.4, §8, §9
 * @see ../../../docs/contract.md §Invariants #6 (fail-closed), #5 (a verdict only tightens)
 */

import assert from "node:assert/strict";
import test from "node:test";

import { loadWasm } from "@allw/hook";

import { OpenClawBridge } from "../dist/index.js";
import { FakeGateway, recordingLogger, verdict } from "./support/fake-gateway.mjs";
import {
  APPROVAL_ID,
  CONFIG,
  CREATED_AT_MS,
  EXPIRES_AT_MS,
  PLUGIN_APPROVAL_ID,
  execEvent,
  execSnapshot,
  pluginEvent,
  pluginSnapshot,
} from "./support/fixtures.mjs";

const wasm = await loadWasm();

/** A fixed clock anchored to the fixtures' gateway-clock reference — never `Date.now()`. */
function fixedClock(nowMs = CREATED_AT_MS) {
  return () => nowMs;
}

function makeBridge({
  snapshot = execSnapshot(),
  snapshots,
  resolveResult = { applied: true },
  approval = verdict("approved"),
  requestApproval,
  now = fixedClock(),
  config = CONFIG,
  listIds,
  pluginListIds,
  handlers = {},
} = {}) {
  const queue = snapshots === undefined ? null : [...snapshots];
  const gateway = new FakeGateway({
    "approval.get": () => {
      if (queue === null) {
        if (snapshot instanceof Error) throw snapshot;
        return snapshot;
      }
      const next = queue.length > 1 ? queue.shift() : queue[0];
      if (next instanceof Error) throw next;
      return next;
    },
    "approval.resolve": () => {
      if (resolveResult instanceof Error) throw resolveResult;
      return resolveResult;
    },
    "exec.approval.list": () => ({ approvals: (listIds ?? []).map((id) => ({ id })) }),
    "plugin.approval.list": () => ({ approvals: (pluginListIds ?? []).map((id) => ({ id })) }),
    ...handlers,
  });
  const { logger, records } = recordingLogger();
  const requests = [];
  const bridge = new OpenClawBridge({
    gateway,
    wasm,
    requestApproval:
      requestApproval ??
      ((req) => {
        requests.push(req);
        if (approval instanceof Error) return Promise.reject(approval);
        return Promise.resolve(approval);
      }),
    config,
    logger,
    now,
  });
  return { bridge, gateway, records, requests };
}

function requested(event = execEvent()) {
  return { event: "exec.approval.requested", payload: event };
}

function pluginRequested(event = pluginEvent()) {
  return { event: "plugin.approval.requested", payload: event };
}

// ── the happy path, so the negatives below are meaningful ───────────────────────

test("a verified approved verdict resolves allow-once (§7.2)", async () => {
  const { bridge, gateway, requests } = makeBridge();
  const outcome = await bridge.handle(requested());

  assert.deepEqual(outcome, { kind: "resolved", decision: "allow-once", applied: true });
  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "allow-once" }]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].actor.id, "openclaw:home-mini");
});

test("approval.get is called before the allw request is raised (§6.1)", async () => {
  const order = [];
  const { bridge } = makeBridge({
    requestApproval: () => {
      order.push("requestApproval");
      return Promise.resolve(verdict("approved"));
    },
    handlers: {
      "approval.get": () => {
        order.push("approval.get");
        return execSnapshot();
      },
    },
  });
  await bridge.handle(requested());
  assert.equal(order[0], "approval.get");
  assert.equal(order[1], "requestApproval");
});

// ── §9 rows that deny ───────────────────────────────────────────────────────────

for (const [decision, reason] of [
  ["denied", "no-approval"],
  ["expired", "timeout"],
  ["aborted", "aborted"],
]) {
  test(`a verified '${decision}' verdict resolves deny with reason ${reason} (§9)`, async () => {
    const { bridge, gateway, records } = makeBridge({ approval: verdict(decision) });
    const outcome = await bridge.handle(requested());

    assert.deepEqual(outcome, { kind: "resolved", decision: "deny", applied: true });
    assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "deny" }]);
    assert.ok(records.some((r) => r.event === "approval.denied" && r.fields.reason === reason));
  });
}

test("an approved verdict that fails re-verification denies verify-error (§7.2, §9)", async () => {
  // Verification failure is a deny, never a skipped check.
  const { bridge, gateway, records } = makeBridge({
    approval: verdict("approved", { verifies: false }),
  });
  const outcome = await bridge.handle(requested());

  assert.equal(outcome.decision, "deny");
  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "deny" }]);
  assert.ok(records.some((r) => r.fields.reason === "verify-error"));
});

test("a verification call that throws denies verify-error rather than propagating (§9)", async () => {
  const { bridge, records } = makeBridge({
    approval: verdict("approved", { verifyThrows: true }),
  });
  const outcome = await bridge.handle(requested());
  assert.equal(outcome.decision, "deny");
  assert.ok(records.some((r) => r.fields.reason === "verify-error"));
});

test("an SDK transport failure denies transport-error (§9)", async () => {
  const { bridge, gateway, records } = makeBridge({ approval: new Error("relay unreachable") });
  const outcome = await bridge.handle(requested());

  assert.equal(outcome.decision, "deny");
  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "deny" }]);
  assert.ok(records.some((r) => r.fields.reason === "transport-error"));
});

test("a divergent presentation denies presentation-divergence and raises no allw request (§6.1, §9)", async () => {
  const { bridge, gateway, requests, records } = makeBridge({
    snapshot: execSnapshot({ presentation: { commandText: "git push" } }),
  });
  const outcome = await bridge.handle(requested());

  assert.equal(outcome.decision, "deny");
  assert.equal(requests.length, 0, "a divergent pair is never rendered to a human");
  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "deny" }]);
  assert.ok(records.some((r) => r.fields.reason === "presentation-divergence"));
});

test("an unreadable approval.get snapshot denies rather than proceeding (§6.1, §9)", async () => {
  const { bridge, requests, records } = makeBridge({ snapshot: { nonsense: true } });
  const outcome = await bridge.handle(requested());

  assert.equal(outcome.decision, "deny");
  assert.equal(requests.length, 0);
  assert.ok(records.some((r) => r.fields.reason === "presentation-divergence"));
});

test("an approval.get RPC failure denies rather than proceeding (§9)", async () => {
  const { bridge, requests } = makeBridge({ snapshot: new Error("connection lost") });
  const outcome = await bridge.handle(requested());
  assert.equal(outcome.decision, "deny");
  assert.equal(requests.length, 0);
});

test("an unreadable event payload with a readable id denies build-error (§9)", async () => {
  const { bridge, gateway } = makeBridge();
  const outcome = await bridge.handle({
    event: "exec.approval.requested",
    payload: { id: APPROVAL_ID, request: "not an object" },
  });
  assert.equal(outcome.decision, "deny");
  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "deny" }]);
});

test("an event payload with no readable id cannot be resolved at all (§9)", async () => {
  const { bridge, gateway, records } = makeBridge();
  const outcome = await bridge.handle({ event: "exec.approval.requested", payload: 42 });

  assert.deepEqual(outcome, { kind: "left-open", why: "unresolvable" });
  assert.deepEqual(gateway.resolves, [], "nothing can be submitted without a canonical id");
  assert.ok(records.some((r) => r.event === "event.unreadable"));
});

test("a budget below the minimum denies insufficient-budget and raises nothing (§8, §9)", async () => {
  // 20 s remain against a 60 s margin ⇒ budget −40 s.
  const { bridge, gateway, requests, records } = makeBridge({
    now: fixedClock(CREATED_AT_MS),
    snapshot: execSnapshot({ expiresAtMs: CREATED_AT_MS + 20_000 }),
  });
  const event = execEvent({ expiresAtMs: CREATED_AT_MS + 20_000 });
  const outcome = await bridge.handle(requested(event));

  assert.equal(outcome.decision, "deny");
  assert.equal(requests.length, 0, "raising a prompt doomed to expire is worse than denying");
  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "deny" }]);
  assert.ok(records.some((r) => r.fields.reason === "insufficient-budget"));
});

test("the budget is anchored to the gateway's clock, not the bridge's (§8)", async () => {
  // The local clock is a full hour ahead of the gateway's. Anchoring on the bridge's own clock
  // would compute a negative budget and deny a perfectly fresh approval.
  const { bridge, requests } = makeBridge({ now: fixedClock(CREATED_AT_MS + 3_600_000) });
  const outcome = await bridge.handle(requested());

  assert.equal(outcome.decision, "allow-once");
  assert.equal(requests.length, 1);
  assert.ok(requests[0].timeoutMs > 0);
});

test("an approved verdict with allow-once unavailable denies no-expressible-allow (§7.3, §7.4)", async () => {
  for (const allowedDecisions of [["deny"], ["allow-always", "deny"]]) {
    const { bridge, gateway, records } = makeBridge({
      snapshot: execSnapshot({ presentation: { allowedDecisions } }),
    });
    const outcome = await bridge.handle(requested());

    assert.equal(outcome.decision, "deny", `offered ${JSON.stringify(allowedDecisions)}`);
    assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "deny" }]);
    assert.ok(records.some((r) => r.fields.reason === "no-expressible-allow"));
  }
});

test("a malformed gateway id denies config-error per request (§7.1, §9)", async () => {
  const { bridge, gateway, requests } = makeBridge({
    config: { ...CONFIG, gatewayId: "Not A Valid Id" },
  });
  const outcome = await bridge.handle(requested());

  assert.equal(outcome.decision, "deny");
  assert.equal(requests.length, 0);
  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "deny" }]);
});

// ── §9 rows that deliberately do NOT deny ───────────────────────────────────────

test("a system-agent approval is neither approved nor denied (§5.3)", async () => {
  const { bridge, gateway, requests, records } = makeBridge();
  const outcome = await bridge.handle({
    event: "system-agent.approval.requested",
    payload: { id: "apr_system", approvalKind: "system-agent", expiresAtMs: EXPIRES_AT_MS },
  });

  assert.deepEqual(outcome, { kind: "left-open", why: "unsupported-approval-kind" });
  assert.deepEqual(gateway.resolves, [], "denying a family it cannot render would be a DoS");
  assert.equal(requests.length, 0);
  assert.ok(records.some((r) => r.event === "unsupported-approval-kind"));
});

test("a payload declaring a non-exec kind on the exec event is left alone (§5.3 cross-check)", async () => {
  const { bridge, gateway, records } = makeBridge();
  const event = execEvent({ approvalKind: "system-agent" });
  const outcome = await bridge.handle(requested(event));

  assert.deepEqual(outcome, { kind: "left-open", why: "unsupported-approval-kind" });
  assert.deepEqual(gateway.resolves, []);
  assert.ok(
    records.some(
      (r) => r.event === "unsupported-approval-kind" && r.fields.approvalKind === "system-agent",
    ),
  );
});

test("an unrecognized future approval family is left alone, not denied (§5.3)", async () => {
  const { bridge, gateway } = makeBridge();
  const outcome = await bridge.handle({
    event: "workflow.approval.requested",
    payload: { id: "apr_future", expiresAtMs: EXPIRES_AT_MS },
  });
  assert.deepEqual(outcome, { kind: "left-open", why: "unsupported-approval-kind" });
  assert.deepEqual(gateway.resolves, []);
});

test("a terminal approval raises nothing and submits nothing (§6.1 rule 4)", async () => {
  const { bridge, gateway, requests, records } = makeBridge({
    snapshot: execSnapshot({ status: "resolved" }),
  });
  const outcome = await bridge.handle(requested());

  assert.deepEqual(outcome, { kind: "left-open", why: "not-pending" });
  assert.equal(requests.length, 0);
  assert.deepEqual(gateway.resolves, []);
  assert.ok(records.some((r) => r.event === "approval.already-terminal"));
});

test("a connection lost before the resolve leaves the approval to OpenClaw's fallback (§9)", async () => {
  // The human decided, but the re-read of the canonical status fails: there is no channel on which
  // to submit anything, so the bridge submits nothing and OpenClaw's askFallback closes it.
  const { bridge, gateway, records } = makeBridge({
    snapshots: [execSnapshot(), new Error("socket closed")],
  });
  const outcome = await bridge.handle(requested());

  assert.deepEqual(outcome, { kind: "left-open", why: "unresolvable" });
  assert.deepEqual(gateway.resolves, []);
  assert.ok(records.some((r) => r.event === "resolve.unavailable"));
});

test("a connection restored while the approval is still pending resolves normally (§9)", async () => {
  // Failing closed means never inventing an allow — not discarding a human decision that is still
  // valid. The re-read succeeds and still reports `pending`, so allow-once is submitted.
  const { bridge, gateway } = makeBridge({
    snapshots: [execSnapshot(), execSnapshot()],
  });
  const outcome = await bridge.handle(requested());

  assert.deepEqual(outcome, { kind: "resolved", decision: "allow-once", applied: true });
  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "allow-once" }]);
});

test("a re-read reporting a terminal status after the verdict submits nothing (§9)", async () => {
  const { bridge, gateway, records } = makeBridge({
    snapshots: [execSnapshot(), execSnapshot({ status: "resolved" })],
  });
  const outcome = await bridge.handle(requested());

  assert.deepEqual(outcome, { kind: "left-open", why: "not-pending" });
  assert.deepEqual(gateway.resolves, [], "the recorded record is authoritative");
  assert.ok(records.some((r) => r.event === "approval.won-elsewhere"));
});

test("a failing approval.resolve is not retried (§7.4)", async () => {
  const { bridge, gateway } = makeBridge({ resolveResult: new Error("socket closed") });
  const outcome = await bridge.handle(requested());

  assert.deepEqual(outcome, { kind: "left-open", why: "unresolvable" });
  assert.equal(gateway.resolves.length, 1, "exactly one attempt, never a retry");
});

// ── §7.4 first-answer-wins ──────────────────────────────────────────────────────

test("applied:false is honored: the recorded winner stands and nothing is re-submitted (§7.4)", async () => {
  const { bridge, gateway, records } = makeBridge({
    resolveResult: { applied: false, record: { status: "resolved", decision: "deny" } },
  });
  const outcome = await bridge.handle(requested());

  assert.deepEqual(outcome, { kind: "resolved", decision: "allow-once", applied: false });
  assert.equal(gateway.resolves.length, 1, "a losing resolve is never re-submitted");
  assert.ok(
    records.some((r) => r.event === "approval.not-applied" && r.fields.winner === "deny"),
    "the canonical winner is adopted",
  );
});

test("an approval already settled by a resolved broadcast is not driven again (§7.4)", async () => {
  const { bridge, gateway } = makeBridge();
  await bridge.handle({ event: "exec.approval.resolved", payload: { id: APPROVAL_ID } });
  const outcome = await bridge.handle(requested());

  assert.deepEqual(outcome, { kind: "ignored" });
  assert.deepEqual(gateway.resolves, []);
});

// ── §7.3 the structural absence of allow-always ─────────────────────────────────

test("allow-always is never submitted under any input (§7.3)", async () => {
  const inputs = [
    { approval: verdict("approved") },
    { approval: verdict("denied") },
    { approval: verdict("expired") },
    { approval: verdict("aborted") },
    { approval: verdict("approved", { verifies: false }) },
    { approval: new Error("transport") },
    { snapshot: execSnapshot({ presentation: { allowedDecisions: ["allow-always", "deny"] } }) },
    { snapshot: execSnapshot({ presentation: { allowedDecisions: ["allow-always"] } }) },
    { snapshot: execSnapshot({ presentation: { commandText: "something else" } }) },
  ];
  for (const input of inputs) {
    const { bridge, gateway } = makeBridge(input);
    await bridge.handle(requested());
    for (const params of gateway.resolves) {
      assert.notEqual(
        params.decision,
        "allow-always",
        `allow-always must be structurally unreachable (input: ${JSON.stringify(input.approval?.decision ?? "snapshot")})`,
      );
      assert.ok(["allow-once", "deny"].includes(params.decision));
    }
  }
});

// ── §4.3 backfill + reconcile ───────────────────────────────────────────────────

test("backfill drives pending approvals the connection missed (§4.3)", async () => {
  const { bridge, gateway } = makeBridge({ listIds: [APPROVAL_ID] });
  await bridge.project();

  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "allow-once" }]);
});

test("backfill does not resurrect an approval already reported resolved (§4.3)", async () => {
  const { bridge, gateway } = makeBridge({ listIds: [APPROVAL_ID] });
  await bridge.handle({ event: "exec.approval.resolved", payload: { id: APPROVAL_ID } });
  await bridge.project();

  assert.deepEqual(gateway.resolves, []);
});

test("backfill skips an approval the gateway reports as terminal (§4.3, §6.1)", async () => {
  const { bridge, gateway } = makeBridge({
    listIds: [APPROVAL_ID],
    snapshot: execSnapshot({ status: "expired" }),
  });
  await bridge.project();
  assert.deepEqual(gateway.resolves, []);
});

test("a backfilled approval with no reviewer command text denies build-error (§9)", async () => {
  const { bridge, gateway } = makeBridge({
    listIds: [APPROVAL_ID],
    snapshot: execSnapshot({ presentation: { commandText: undefined } }),
  });
  await bridge.project();
  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "deny" }]);
});

test("a backfilled non-exec approval is left for a surface that understands it (§5.3)", async () => {
  const { bridge, gateway, records } = makeBridge({
    listIds: [APPROVAL_ID],
    snapshot: execSnapshot({ presentation: { kind: "system-agent" } }),
  });
  await bridge.project();

  assert.deepEqual(gateway.resolves, []);
  assert.ok(records.some((r) => r.event === "unsupported-approval-kind"));
});

test("a failing backfill logs and leaves state untouched rather than throwing (§4.3)", async () => {
  const { bridge, gateway, records } = makeBridge({
    handlers: {
      "exec.approval.list": () => {
        throw new Error("connection lost");
      },
    },
  });
  await bridge.project();

  assert.deepEqual(gateway.resolves, []);
  assert.ok(records.some((r) => r.event === "backfill.failed"));
});

// ── operator logging never carries plaintext ────────────────────────────────────

test("no log record carries the approval plaintext (§6.5)", async () => {
  const { bridge, records } = makeBridge();
  await bridge.handle(requested());

  const serialized = JSON.stringify(records);
  for (const secret of ["git push --force", "/srv/app", "OpenClaw home-mini ·"]) {
    assert.ok(!serialized.includes(secret), `log must not contain '${secret}'`);
  }
});

// ── §5.2 the plugin permission-request family ───────────────────────────────────

test("a verified approved plugin verdict resolves allow-once with kind 'plugin' (§5.2, §7.2)", async () => {
  const { bridge, gateway, requests } = makeBridge({ snapshot: pluginSnapshot() });
  const outcome = await bridge.handle(pluginRequested());

  assert.deepEqual(outcome, { kind: "resolved", decision: "allow-once", applied: true });
  assert.deepEqual(gateway.resolves, [
    { id: PLUGIN_APPROVAL_ID, kind: "plugin", decision: "allow-once" },
  ]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].action.surface, "agent_tool_call");
});

test("a plugin verdict resolves deny with kind 'plugin' on the exact same reason codes as exec (§9)", async () => {
  const { bridge, gateway, records } = makeBridge({
    snapshot: pluginSnapshot(),
    approval: verdict("denied"),
  });
  const outcome = await bridge.handle(pluginRequested());

  assert.deepEqual(outcome, { kind: "resolved", decision: "deny", applied: true });
  assert.deepEqual(gateway.resolves, [
    { id: PLUGIN_APPROVAL_ID, kind: "plugin", decision: "deny" },
  ]);
  assert.ok(
    records.some((r) => r.event === "approval.denied" && r.fields.reason === "no-approval"),
  );
});

test("a plugin approval with allow-once unavailable denies no-expressible-allow (§7.3, §7.4)", async () => {
  for (const allowedDecisions of [["deny"], ["allow-always", "deny"]]) {
    const { bridge, gateway, records } = makeBridge({
      snapshot: pluginSnapshot({ presentation: { allowedDecisions } }),
    });
    const outcome = await bridge.handle(pluginRequested());

    assert.equal(outcome.decision, "deny");
    assert.deepEqual(gateway.resolves, [
      { id: PLUGIN_APPROVAL_ID, kind: "plugin", decision: "deny" },
    ]);
    assert.ok(records.some((r) => r.fields.reason === "no-expressible-allow"));
  }
});

test("allow-always is never submitted for a plugin approval under any input (§7.3)", async () => {
  const inputs = [
    { approval: verdict("approved") },
    { approval: verdict("denied") },
    { approval: verdict("approved", { verifies: false }) },
    { snapshot: pluginSnapshot({ presentation: { allowedDecisions: ["allow-always", "deny"] } }) },
    { snapshot: pluginSnapshot({ presentation: { allowedDecisions: ["allow-always"] } }) },
  ];
  for (const input of inputs) {
    const { bridge, gateway } = makeBridge({
      snapshot: pluginSnapshot(),
      ...input,
    });
    await bridge.handle(pluginRequested());
    for (const params of gateway.resolves) {
      assert.notEqual(params.decision, "allow-always");
      assert.ok(["allow-once", "deny"].includes(params.decision));
    }
  }
});

test("a plugin approval carrying an insufficient budget denies immediately, raising nothing (§8, §9)", async () => {
  const { bridge, gateway, requests } = makeBridge({
    snapshot: pluginSnapshot({ expiresAtMs: CREATED_AT_MS + 1_000 }),
  });
  const outcome = await bridge.handle(pluginRequested());

  assert.equal(outcome.decision, "deny");
  assert.equal(requests.length, 0);
  assert.deepEqual(gateway.resolves, [
    { id: PLUGIN_APPROVAL_ID, kind: "plugin", decision: "deny" },
  ]);
});

// ── §4.3 backfill drives both families ──────────────────────────────────────────

test("backfill drives pending plugin approvals from plugin.approval.list (§4.3)", async () => {
  const { bridge, gateway } = makeBridge({
    snapshot: pluginSnapshot(),
    pluginListIds: [PLUGIN_APPROVAL_ID],
  });
  await bridge.project();

  assert.deepEqual(gateway.resolves, [
    { id: PLUGIN_APPROVAL_ID, kind: "plugin", decision: "allow-once" },
  ]);
});

test("a single project() call backfills both exec and plugin lists (§4.3)", async () => {
  const { bridge, gateway } = makeBridge({
    listIds: [APPROVAL_ID],
    pluginListIds: [PLUGIN_APPROVAL_ID],
    handlers: {
      "approval.get": (params) =>
        params.id === PLUGIN_APPROVAL_ID ? pluginSnapshot() : execSnapshot(),
    },
  });
  await bridge.project();

  const resolvedIds = gateway.resolves.map((r) => r.id).sort();
  assert.deepEqual(resolvedIds, [APPROVAL_ID, PLUGIN_APPROVAL_ID].sort());
  assert.ok(
    gateway.resolves.every((r) => r.decision === "allow-once"),
    "both families resolve allow-once on the happy path",
  );
});

test("a backfilled plugin approval reporting a mismatched kind is left for another surface (§5.3)", async () => {
  const { bridge, gateway, records } = makeBridge({
    pluginListIds: [PLUGIN_APPROVAL_ID],
    snapshot: pluginSnapshot({ presentation: { kind: "exec" } }),
  });
  await bridge.project();

  assert.deepEqual(gateway.resolves, []);
  assert.ok(records.some((r) => r.event === "unsupported-approval-kind"));
});

test("a failing plugin.approval.list backfill logs and does not block the exec backfill (§4.3)", async () => {
  const { bridge, gateway, records } = makeBridge({
    listIds: [APPROVAL_ID],
    handlers: {
      "plugin.approval.list": () => {
        throw new Error("connection lost");
      },
    },
  });
  await bridge.project();

  assert.deepEqual(gateway.resolves, [{ id: APPROVAL_ID, kind: "exec", decision: "allow-once" }]);
  assert.ok(records.some((r) => r.event === "backfill.failed" && r.fields.family === "plugin"));
});
