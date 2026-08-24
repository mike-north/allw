/**
 * Tests for the relay-polling mount path of {@link mountWebApprover} (issue #147).
 *
 * These cover the behaviors surfaced when mounting via `config.relay`:
 *  - the returned `stop()` disposer cancels the poll interval (no further fetches after stop);
 *  - the refresh (↻) button forces a real relay poll (a `poller.poll()` fetch), not just a repaint;
 *  - a `decide()` on a pending item triggers a re-render (the inbox shell is repainted).
 *
 * Mounting drives the real DOM (jsdom) and an injected `fetchImpl` + interval scheduler so every
 * timing seam is deterministic. All fixtures use a fixed clock constant — never `Date.now()`.
 *
 * @see ../src/browser.ts
 * @see ../src/relay-poll.ts
 * @see ../../../docs/contract.md §Invariants #6, #7
 */

import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { JSDOM } from "jsdom";

import { mountWebApprover } from "../dist/browser.js";

// ── Fixed clock (never Date.now() in test data) ───────────────────────────

const NOW = Date.parse("2026-06-12T16:00:00.000Z");
const SOON = NOW + 60_000; // 60 s from now — well within a valid expiry window

/**
 * Flush pending microtasks (Promise.resolve chains) so the async fetch → json → sync → prepare
 * chain settles before assertions.
 */
async function flushMicrotasks(n = 30) {
  for (let i = 0; i < n; i++) {
    await Promise.resolve();
  }
}

function envelope(id, overrides = {}) {
  return {
    v: 1,
    id,
    created_at: NOW - 1_000,
    expires_at: SOON,
    approver: "acct-web",
    context_ciphertext: `ciphertext-${id}`,
    ...overrides,
  };
}

function context(overrides = {}) {
  return {
    kind: "command",
    command: { cwd: "/repo", argv: ["git", "status"], raw: "git status" },
    actor: { id: "claude-code:local", display: "Claude Code", attestation: "verified" },
    risk: { level: "low", reversible: true, summary: "checks git status" },
    allowed_decisions: ["approved", "denied"],
    ...overrides,
  };
}

/**
 * A runtime whose `prepare` resolves a context per envelope id, and whose `signDecision` records
 * calls so `decide()` re-render behavior can be asserted.
 */
function runtime(fixtures) {
  const signCalls = [];
  return {
    signCalls,
    async prepare(envelopeInput) {
      const value = fixtures.get(envelopeInput.id);
      assert.ok(value, `missing fixture for ${envelopeInput.id}`);
      return {
        expiresAt: envelopeInput.expires_at,
        requestHash: `hash-${envelopeInput.id}`,
        ...value,
      };
    },
    async signDecision(input) {
      signCalls.push(input);
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

/** A `fetch` stub that always returns the given envelopes and counts calls. */
function countingFetch(envelopes) {
  let callCount = 0;
  async function fakeFetch() {
    callCount++;
    return { ok: true, status: 200, json: async () => ({ envelopes }) };
  }
  fakeFetch.callCount = () => callCount;
  return fakeFetch;
}

/**
 * A fake scheduler pair: records scheduled callbacks and lets the test fire them manually,
 * honoring cancellation so a stopped interval does not fire.
 */
function fakeScheduler() {
  const scheduled = [];
  let nextId = 1;
  return {
    schedule(fn, ms) {
      const id = nextId++;
      scheduled.push({ fn, ms, id, cancelled: false });
      return id;
    },
    cancel(id) {
      const entry = scheduled.find((e) => e.id === id);
      if (entry) entry.cancelled = true;
    },
    tick() {
      for (const entry of scheduled) {
        if (!entry.cancelled) entry.fn();
      }
    },
  };
}

/**
 * Install a fresh jsdom and the globals `browser.ts` reads (`document`, `window`,
 * `HTMLButtonElement`). Returns the root element and a `restore()` to revert the globals.
 */
function installDom() {
  const dom = new JSDOM('<div id="app"></div>', { url: "https://approver.local/" });
  const root = dom.window.document.getElementById("app");
  const saved = {
    document: globalThis.document,
    window: globalThis.window,
    HTMLButtonElement: globalThis.HTMLButtonElement,
  };
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  globalThis.HTMLButtonElement = dom.window.HTMLButtonElement;
  return {
    dom,
    root,
    restore() {
      globalThis.document = saved.document;
      globalThis.window = saved.window;
      globalThis.HTMLButtonElement = saved.HTMLButtonElement;
    },
  };
}

const RELAY_CONFIG = {
  relayUrl: "https://relay.test",
  accountId: "acct-1",
  deviceId: "dev-1",
  deviceAuthToken: "token-abc",
};

describe("mountWebApprover (relay path)", () => {
  test("returned stop() cancels the poll interval — no further fetches after stop", async () => {
    const { root, restore } = installDom();
    try {
      const fetchImpl = countingFetch([envelope("req-1")]);
      const scheduler = fakeScheduler();
      const fixtures = new Map([["req-1", { context: context() }]]);

      const { stop } = await mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: runtime(fixtures),
        relay: {
          ...RELAY_CONFIG,
          fetchImpl,
          scheduleInterval: scheduler.schedule,
          cancelInterval: scheduler.cancel,
        },
      });

      await flushMicrotasks();
      assert.equal(fetchImpl.callCount(), 1, "initial poll fires exactly once");

      stop();

      // Firing the scheduled interval after stop() must not poll again.
      scheduler.tick();
      await flushMicrotasks();
      assert.equal(fetchImpl.callCount(), 1, "no further fetch after stop()");
    } finally {
      restore();
    }
  });

  test("refresh (↻) button forces a real relay poll (poller.poll fetch), not just a repaint", async () => {
    const { root, restore } = installDom();
    try {
      const fetchImpl = countingFetch([envelope("req-1")]);
      const scheduler = fakeScheduler();
      const fixtures = new Map([["req-1", { context: context() }]]);

      const { stop } = await mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: runtime(fixtures),
        relay: {
          ...RELAY_CONFIG,
          fetchImpl,
          scheduleInterval: scheduler.schedule,
          cancelInterval: scheduler.cancel,
        },
      });

      await flushMicrotasks();
      assert.equal(fetchImpl.callCount(), 1, "initial poll fires once on mount");

      const refreshButton = root.querySelector("button.icon-button");
      assert.ok(refreshButton, "refresh button is rendered");

      refreshButton.click();
      await flushMicrotasks();

      assert.equal(
        fetchImpl.callCount(),
        2,
        "clicking refresh triggers an additional relay fetch (poller.poll), not a local-only repaint",
      );

      stop();
    } finally {
      restore();
    }
  });

  test("decide() on a pending item triggers a re-render", async () => {
    // After a decision is signed, the form's submit handler invokes the refresh callback, which in
    // the relay path forces a poll and repaints. We detect the repaint by capturing the shell
    // element before the decision and confirming it has been replaced by a fresh one afterward
    // (render() calls root.replaceChildren()). We also assert exactly one verdict was signed.
    const { root, restore } = installDom();
    try {
      const fetchImpl = countingFetch([envelope("req-decide")]);
      const scheduler = fakeScheduler();
      const fixtures = new Map([["req-decide", { context: context() }]]);
      const rt = runtime(fixtures);

      const { controller, stop } = await mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: rt,
        relay: {
          ...RELAY_CONFIG,
          fetchImpl,
          scheduleInterval: scheduler.schedule,
          cancelInterval: scheduler.cancel,
        },
      });

      // Let the initial poll sync the pending item and render its decision controls.
      await flushMicrotasks();
      assert.deepEqual(
        controller.inbox().map((i) => i.id),
        ["req-decide"],
        "pending item is in the inbox after the first poll",
      );

      const shellBefore = root.querySelector("main.approver-shell");
      assert.ok(shellBefore, "a shell is rendered before the decision");

      // Submit a decision via the rendered Deny button (drives the form submit → decide path).
      const denyButton = [...root.querySelectorAll("button")].find((b) => b.textContent === "Deny");
      assert.ok(denyButton, "deny button is rendered for the pending item");
      denyButton.click();
      await flushMicrotasks();

      assert.equal(rt.signCalls.length, 1, "decide() called signDecision once");
      assert.equal(rt.signCalls[0].decision, "denied", "the denied decision was signed");

      // The decision's refresh callback repainted the inbox: the old shell node is gone and a new
      // one is in the DOM (replaceChildren replaces the subtree on each render).
      const shellAfter = root.querySelector("main.approver-shell");
      assert.ok(shellAfter, "a shell is still rendered after the decision");
      assert.notEqual(shellAfter, shellBefore, "decide() triggered a re-render (new shell node)");
      assert.equal(
        shellBefore.isConnected,
        false,
        "the pre-decision shell was detached by the re-render",
      );

      stop();
    } finally {
      restore();
    }
  });
});

// ── mountWebApprover — live cross-device retraction listener (#150) ────────
//
// These cover the WS wiring introduced alongside `RelayPollConfig.surfaceId`: when set, mounting
// also opens a `createRetractListener` connection, and a `{type:"retract"}` message removes the
// item from the rendered inbox without waiting for the next poll tick.

/** A stub `LiveSocket` whose listeners the test can fire directly (mirrors retract-listener.test). */
function stubLiveSocket() {
  const listeners = { open: [], message: [], error: [], close: [] };
  let closed = false;
  return {
    closed: () => closed,
    addEventListener(type, listener) {
      listeners[type].push(listener);
    },
    close() {
      closed = true;
    },
    emitMessage(data) {
      for (const l of listeners.message) l({ data });
    },
  };
}

/** A connector that records every URL requested and returns fresh stub sockets. */
function recordingConnector() {
  const sockets = [];
  const urls = [];
  const connect = (url) => {
    urls.push(url);
    const socket = stubLiveSocket();
    sockets.push(socket);
    return socket;
  };
  connect.sockets = sockets;
  connect.urls = urls;
  return connect;
}

describe("mountWebApprover — live retraction listener (#150)", () => {
  test("a {type:'retract'} message removes the item from the rendered inbox immediately", async () => {
    const { root, restore } = installDom();
    try {
      const fetchImpl = countingFetch([envelope("req-1")]);
      const scheduler = fakeScheduler();
      const connect = recordingConnector();
      const fixtures = new Map([["req-1", { context: context() }]]);

      const { controller, stop } = await mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: runtime(fixtures),
        relay: {
          ...RELAY_CONFIG,
          fetchImpl,
          scheduleInterval: scheduler.schedule,
          cancelInterval: scheduler.cancel,
          surfaceId: "surface-abc",
          connectImpl: connect,
        },
      });

      await flushMicrotasks();
      assert.deepEqual(
        controller.inbox().map((i) => i.id),
        ["req-1"],
        "the item is pending after the initial poll",
      );
      assert.ok(root.querySelector("article.approval-card"), "a card is rendered for it");

      connect.sockets[0].emitMessage(JSON.stringify({ type: "retract", request_id: "req-1" }));

      assert.deepEqual(controller.inbox(), [], "the controller drops the retracted item");
      assert.equal(
        root.querySelector("article.approval-card"),
        null,
        "the retracted item's card is removed from the DOM by the immediate re-render",
      );

      stop();
    } finally {
      restore();
    }
  });

  test("connect URL is built from the relay config and includes the surface id", async () => {
    const { root, restore } = installDom();
    try {
      const fetchImpl = countingFetch([]);
      const scheduler = fakeScheduler();
      const connect = recordingConnector();

      const { stop } = await mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: runtime(new Map()),
        relay: {
          ...RELAY_CONFIG,
          fetchImpl,
          scheduleInterval: scheduler.schedule,
          cancelInterval: scheduler.cancel,
          surfaceId: "surface-abc",
          connectImpl: connect,
        },
      });

      await flushMicrotasks();
      const url = new URL(connect.urls[0]);
      assert.equal(url.searchParams.get("surface_id"), "surface-abc");
      assert.equal(url.searchParams.get("auth"), RELAY_CONFIG.deviceAuthToken);

      stop();
    } finally {
      restore();
    }
  });

  test("omitting surfaceId keeps the poll-only path — no WebSocket connect attempted", async () => {
    const { root, restore } = installDom();
    try {
      const fetchImpl = countingFetch([]);
      const scheduler = fakeScheduler();

      // No `connectImpl` is supplied and no `surfaceId` is set — if the retraction listener were
      // mounted unconditionally, this would try to construct a real global `WebSocket` and throw
      // in this Node/jsdom test environment. Not throwing proves the listener stayed opt-in.
      const { stop } = await mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: runtime(new Map()),
        relay: {
          ...RELAY_CONFIG,
          fetchImpl,
          scheduleInterval: scheduler.schedule,
          cancelInterval: scheduler.cancel,
        },
      });

      await flushMicrotasks();
      stop();
    } finally {
      restore();
    }
  });

  test("stop() also tears down the retraction listener (closes its socket)", async () => {
    const { root, restore } = installDom();
    try {
      const fetchImpl = countingFetch([]);
      const scheduler = fakeScheduler();
      const connect = recordingConnector();

      const { stop } = await mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: runtime(new Map()),
        relay: {
          ...RELAY_CONFIG,
          fetchImpl,
          scheduleInterval: scheduler.schedule,
          cancelInterval: scheduler.cancel,
          surfaceId: "surface-abc",
          connectImpl: connect,
        },
      });

      await flushMicrotasks();
      assert.equal(connect.sockets[0].closed(), false);

      stop();

      assert.equal(
        connect.sockets[0].closed(),
        true,
        "stop() closes the retraction listener's socket",
      );
    } finally {
      restore();
    }
  });
});
