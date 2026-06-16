/**
 * Tests for {@link createRelayPoller} — live inbox refresh (issue #147).
 *
 * Uses fake timers (node:test `mock.timers`) and a stub `fetch` to drive every timing seam
 * deterministically. All fixtures use a fixed clock constant — never `Date.now()` in test data.
 *
 * Coverage:
 *  - Successful poll: envelopes fetched, controller synced, onPollResult called with ok:true.
 *  - Countdown integration: expiry countdowns reflect the relay-returned expiresAt value.
 *  - Expired item: a request past its deadline is not returned by the relay (relay excludes it);
 *    any that slipped through are handled fail-closed by the controller (expired status).
 *  - Fetch error (network): fail-closed — onPollResult ok:false, controller NOT re-synced.
 *  - Non-2xx response: same fail-closed path as network error.
 *  - Malformed response body: fail-closed — onPollResult ok:false, controller NOT re-synced.
 *  - Tampered/unverifiable envelope: onPollResult ok:true but item renders as unverified.
 *  - Multiple items: one tampered, one valid — both present; tampered is deny-only.
 *  - Polling loop stops after stop().
 *
 * @see ../src/relay-poll.ts
 * @see ../../../docs/contract.md §Invariants #6, #7
 */

import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { createRelayPoller } from "../dist/relay-poll.js";
import { WebApproverController } from "../dist/index.js";

// ── Fixed clock (never Date.now() in test data) ───────────────────────────

const NOW = Date.parse("2026-06-12T16:00:00.000Z");
const SOON = NOW + 30_000; // 30 s from now — well within a valid expiry window
const PAST = NOW - 1; // 1 ms before NOW — expired

/**
 * Flush all pending microtasks (Promise.resolve chains) by awaiting a sufficient number of times
 * to allow the full async chain (fetch → json → sync → prepare × N) to settle.
 */
async function flushMicrotasks(n = 20) {
  for (let i = 0; i < n; i++) {
    await Promise.resolve();
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

function envelope(id, overrides = {}) {
  return {
    v: 1,
    id,
    created_at: NOW - 1_000,
    expires_at: SOON,
    approver: "acct-test",
    context_ciphertext: `ciphertext-${id}`,
    ...overrides,
  };
}

function context() {
  return {
    kind: "command",
    command: { cwd: "/repo", argv: ["git", "status"], raw: "git status" },
    actor: { id: "claude-code:local", display: "Claude Code", attestation: "verified" },
    risk: { level: "low", reversible: true, summary: "checks git status" },
    allowed_decisions: ["approved", "denied"],
  };
}

/**
 * Build a fake runtime that resolves envelopes by id from a fixture map.
 * A fixture value of `Error` simulates a tampered/undecryptable envelope → `unverified` status.
 */
function fakeRuntime(fixtures) {
  return {
    async prepare(envelopeInput) {
      const value = fixtures.get(envelopeInput.id);
      if (value instanceof Error) throw value;
      assert.ok(value, `missing fixture for ${envelopeInput.id}`);
      return {
        expiresAt: envelopeInput.expires_at,
        requestHash: `hash-${envelopeInput.id}`,
        ...value,
      };
    },
    async signDecision(input) {
      return {
        requestId: input.envelope.id,
        decision: input.decision,
        signedVerdictJson: JSON.stringify({
          request_id: input.envelope.id,
          decision: input.decision,
        }),
      };
    },
  };
}

/**
 * Build a stub `fetch` that returns the given envelopes array on the first call,
 * then returns an error response on subsequent calls (simulates outage after first poll).
 */
function stubFetch(envelopes, options = {}) {
  const { status = 200, body } = options;
  let callCount = 0;
  const calls = [];
  async function fakeFetch(url, init) {
    calls.push({ url, init });
    callCount++;
    if (status !== 200) {
      return { ok: false, status, json: async () => ({ error: "relay error" }) };
    }
    const responseBody = body !== undefined ? body : { envelopes };
    return { ok: true, status: 200, json: async () => responseBody };
  }
  fakeFetch.calls = calls;
  fakeFetch.callCount = () => callCount;
  return fakeFetch;
}

/**
 * A fake scheduler pair: records scheduled callbacks and lets the test fire them manually.
 */
function fakeScheduler() {
  const scheduled = [];
  let nextId = 1;

  function schedule(fn, ms) {
    const id = nextId++;
    scheduled.push({ fn, ms, id, cancelled: false });
    return id;
  }

  function cancel(id) {
    const entry = scheduled.find((e) => e.id === id);
    if (entry) entry.cancelled = true;
  }

  function tick() {
    for (const entry of scheduled) {
      if (!entry.cancelled) entry.fn();
    }
  }

  return { schedule, cancel, tick, scheduled };
}

// ── Tests ─────────────────────────────────────────────────────────────────

describe("createRelayPoller", () => {
  test("successful poll syncs the controller and calls onPollResult with ok:true", async () => {
    const env1 = envelope("req-1");
    const fixtures = new Map([["req-1", { context: context() }]]);
    const runtime = fakeRuntime(fixtures);
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    const results = [];
    const fetch = stubFetch([env1]);
    const { schedule, cancel } = fakeScheduler();

    createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-1",
      deviceId: "dev-1",
      deviceAuthToken: "token-abc",
      controller,
      onPollResult: (r) => results.push(r),
      fetchImpl: fetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    // The initial poll is async — wait for microtasks to settle.
    await flushMicrotasks();

    assert.equal(results.length, 1);
    assert.equal(results[0].ok, true);
    assert.equal(results[0].envelopes.length, 1);
    assert.equal(results[0].envelopes[0].id, "req-1");

    // Controller should have synced the envelope.
    assert.deepEqual(
      controller.inbox().map((i) => i.id),
      ["req-1"],
      "synced envelope appears in the inbox",
    );
  });

  test("countdown reflects the relay-returned expiresAt", async () => {
    const env1 = envelope("req-countdown", { expires_at: NOW + 45_000 });
    const fixtures = new Map([["req-countdown", { context: context() }]]);
    const runtime = fakeRuntime(fixtures);
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    const fetch = stubFetch([env1]);
    const { schedule, cancel } = fakeScheduler();

    createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-countdown",
      deviceId: "dev-countdown",
      deviceAuthToken: "tok",
      controller,
      onPollResult: () => undefined,
      fetchImpl: fetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    await flushMicrotasks();

    const detail = controller.detail("req-countdown");
    assert.ok(detail, "item should be in the inbox after sync");
    assert.equal(detail.countdownMs, 45_000, "countdown reflects the relay-returned expiresAt");
  });

  test("an already-expired envelope is handled fail-closed (expired status, not approvable)", async () => {
    // The relay excludes expired requests, but test defence-in-depth: if one slips through,
    // the controller marks it expired and it cannot be approved.
    const expiredEnv = envelope("req-expired-slip", { expires_at: PAST });
    const fixtures = new Map([["req-expired-slip", { context: context(), expiresAt: PAST }]]);
    const runtime = fakeRuntime(fixtures);
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    const fetch = stubFetch([expiredEnv]);
    const { schedule, cancel } = fakeScheduler();

    createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-expired-slip",
      deviceId: "dev-e",
      deviceAuthToken: "tok",
      controller,
      onPollResult: () => undefined,
      fetchImpl: fetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    await flushMicrotasks();

    const detail = controller.detail("req-expired-slip");
    assert.ok(detail, "expired item is still rendered (not silently dropped)");
    assert.equal(detail.status, "expired", "expired item renders as expired, never pending");
    assert.equal(
      controller.canApprove("req-expired-slip"),
      false,
      "expired item cannot be approved",
    );
  });

  test("fetch network error is fail-closed: onPollResult ok:false, controller not re-synced", async () => {
    const runtime = fakeRuntime(new Map());
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    // First put something in the inbox so we can verify it is preserved on failure.
    await controller.sync([envelope("req-pre-existing")]);

    const results = [];
    async function failingFetch() {
      throw new Error("Network timeout");
    }
    const { schedule, cancel } = fakeScheduler();

    createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-err",
      deviceId: "dev-err",
      deviceAuthToken: "tok",
      controller,
      onPollResult: (r) => results.push(r),
      fetchImpl: failingFetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    await flushMicrotasks();

    assert.equal(results.length, 1);
    assert.equal(results[0].ok, false, "poll result is not ok on network error");
    assert.match(results[0].error, /Network timeout/, "error message is propagated");

    // The controller must NOT have been re-synced — the pre-existing item should still be there.
    assert.deepEqual(
      controller.inbox().map((i) => i.id),
      ["req-pre-existing"],
      "last-known inbox is preserved on fetch failure",
    );
  });

  test("non-2xx response is fail-closed: onPollResult ok:false", async () => {
    const runtime = fakeRuntime(new Map());
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    const results = [];
    const fetch = stubFetch([], { status: 503 });
    const { schedule, cancel } = fakeScheduler();

    createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-503",
      deviceId: "dev-503",
      deviceAuthToken: "tok",
      controller,
      onPollResult: (r) => results.push(r),
      fetchImpl: fetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    await flushMicrotasks();

    assert.equal(results[0].ok, false, "503 response yields ok:false");
    assert.match(results[0].error, /503/, "HTTP status code is in the error message");
  });

  test("malformed response body is fail-closed: onPollResult ok:false, controller not re-synced", async () => {
    const runtime = fakeRuntime(new Map());
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    await controller.sync([envelope("req-before-malformed")]);

    const results = [];
    // Returns a response body missing the `envelopes` field.
    const fetch = stubFetch([], { body: { wrong_key: [] } });
    const { schedule, cancel } = fakeScheduler();

    createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-malformed",
      deviceId: "dev-malformed",
      deviceAuthToken: "tok",
      controller,
      onPollResult: (r) => results.push(r),
      fetchImpl: fetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    await flushMicrotasks();

    assert.equal(results[0].ok, false, "malformed body yields ok:false");
    assert.match(results[0].error, /unexpected response shape/, "error mentions shape mismatch");

    // Inbox must be preserved.
    assert.deepEqual(
      controller.inbox().map((i) => i.id),
      ["req-before-malformed"],
      "last-known inbox is preserved on malformed response",
    );
  });

  test("tampered/unverifiable envelope renders as unverified (deny-only), poll is ok:true", async () => {
    // The poller itself does not verify envelopes — the controller's sync does.
    // A tampered envelope should not crash the poll; it becomes `unverified` in the inbox.
    const tamperedEnv = envelope("req-tampered");
    const goodEnv = envelope("req-good");
    const fixtures = new Map([
      ["req-tampered", new Error("hash mismatch — tampered context")],
      ["req-good", { context: context() }],
    ]);
    const runtime = fakeRuntime(fixtures);
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    const results = [];
    const fetch = stubFetch([tamperedEnv, goodEnv]);
    const { schedule, cancel } = fakeScheduler();

    createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-tamper",
      deviceId: "dev-tamper",
      deviceAuthToken: "tok",
      controller,
      onPollResult: (r) => results.push(r),
      fetchImpl: fetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    await flushMicrotasks();

    assert.equal(results[0].ok, true, "poll is ok:true even when an envelope is tampered");

    const tamperedDetail = controller.detail("req-tampered");
    assert.ok(tamperedDetail, "tampered item is visible in the inbox");
    assert.equal(tamperedDetail.status, "unverified", "tampered item renders as unverified");
    assert.equal(tamperedDetail.denyOnly, true, "tampered item is deny-only");
    assert.equal(controller.canApprove("req-tampered"), false, "tampered item cannot be approved");

    const goodDetail = controller.detail("req-good");
    assert.ok(goodDetail, "good item is visible alongside the tampered one");
    assert.equal(goodDetail.status, "pending", "good item renders as pending");
  });

  test("stop() cancels the interval so no further polls fire", async () => {
    const runtime = fakeRuntime(new Map([["req-stop", { context: context() }]]));
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    let fetchCallCount = 0;
    async function countingFetch() {
      fetchCallCount++;
      return { ok: true, status: 200, json: async () => ({ envelopes: [envelope("req-stop")] }) };
    }

    const { schedule, cancel, tick } = fakeScheduler();

    const poller = createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-stop",
      deviceId: "dev-stop",
      deviceAuthToken: "tok",
      controller,
      onPollResult: () => undefined,
      fetchImpl: countingFetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    // Wait for the initial poll.
    await flushMicrotasks();
    assert.equal(fetchCallCount, 1, "initial poll fires once");

    poller.stop();

    // Fire the interval — the callback should have been cancelled.
    tick();
    await flushMicrotasks();

    assert.equal(fetchCallCount, 1, "no further poll fires after stop()");
  });

  test("poll() fires an extra tick immediately on demand", async () => {
    const runtime = fakeRuntime(new Map([["req-manual", { context: context() }]]));
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    let fetchCallCount = 0;
    async function countingFetch() {
      fetchCallCount++;
      return {
        ok: true,
        status: 200,
        json: async () => ({ envelopes: [envelope("req-manual")] }),
      };
    }

    const { schedule, cancel } = fakeScheduler();

    const poller = createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-manual",
      deviceId: "dev-manual",
      deviceAuthToken: "tok",
      controller,
      onPollResult: () => undefined,
      fetchImpl: countingFetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    // Initial poll.
    await flushMicrotasks();
    assert.equal(fetchCallCount, 1);

    // Manual extra tick.
    await poller.poll();
    assert.equal(fetchCallCount, 2, "manual poll() fires an extra fetch");
  });

  test("inbox URL is built correctly from relayUrl, accountId, and deviceId", async () => {
    const runtime = fakeRuntime(new Map());
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    const capturedUrls = [];
    async function capturingFetch(url) {
      capturedUrls.push(url);
      return { ok: true, status: 200, json: async () => ({ envelopes: [] }) };
    }

    const { schedule, cancel } = fakeScheduler();

    createRelayPoller({
      relayUrl: "https://relay.example.com/", // trailing slash should be normalized
      accountId: "my-account",
      deviceId: "my-device",
      deviceAuthToken: "tok",
      controller,
      onPollResult: () => undefined,
      fetchImpl: capturingFetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    await flushMicrotasks();

    assert.equal(capturedUrls.length, 1);
    assert.equal(
      capturedUrls[0],
      "https://relay.example.com/my-account/devices/my-device/inbox",
      "inbox URL is built from relayUrl/accountId/devices/deviceId/inbox",
    );
  });

  test("bearer token is sent in the Authorization header", async () => {
    const runtime = fakeRuntime(new Map());
    const controller = new WebApproverController({ runtime, nowMs: () => NOW });

    const capturedInits = [];
    async function capturingFetch(_url, init) {
      capturedInits.push(init);
      return { ok: true, status: 200, json: async () => ({ envelopes: [] }) };
    }

    const { schedule, cancel } = fakeScheduler();

    createRelayPoller({
      relayUrl: "https://relay.test",
      accountId: "acct-auth",
      deviceId: "dev-auth",
      deviceAuthToken: "my-secret-token",
      controller,
      onPollResult: () => undefined,
      fetchImpl: capturingFetch,
      scheduleInterval: schedule,
      cancelInterval: cancel,
    });

    await flushMicrotasks();

    assert.equal(capturedInits.length, 1);
    assert.equal(
      capturedInits[0].headers.Authorization,
      "Bearer my-secret-token",
      "bearer token is sent in the Authorization header",
    );
  });
});
