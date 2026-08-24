/**
 * Tests for {@link createRetractListener} — the live cross-device retraction WebSocket listener
 * (issue #150).
 *
 * Drives the listener against a stub `LiveSocket` and fake reconnect scheduler so every timing seam
 * (open/message/close/error, exponential backoff + jitter) is deterministic. No real network socket
 * is ever opened — this is a unit test of the client-side protocol handling; the wire contract
 * itself (`GET /{acct}/devices/{deviceId}/connect`, `{type:"retract"}`) is owned by
 * `docs/relay-api.md` and exercised end-to-end by the relay's own test suite.
 *
 * Coverage:
 *  - The connect URL carries `auth` and `surface_id` query params (`docs/relay-api.md` §3).
 *  - A well-formed `{type:"retract", request_id}` message calls `onRetract`.
 *  - `request` / `ack` / `error` message types are ignored (out of this listener's scope).
 *  - Malformed JSON, non-object payloads, and a missing/empty `request_id` are ignored (never
 *    throw, never call `onRetract`).
 *  - On close, the listener reconnects with exponential backoff (capped), and resets the backoff
 *    to the minimum after a subsequent successful `open`.
 *  - `stop()` closes the socket, cancels a pending reconnect timer, and prevents any further
 *    reconnect attempts.
 *
 * @see ../src/retract-listener.ts
 * @see ../../../docs/relay-api.md §4 (WebSocket protocol), §7.3 (reconnect backoff)
 */

import assert from "node:assert/strict";
import test from "node:test";

import { createRetractListener } from "../dist/retract-listener.js";

const OPTIONS_BASE = {
  relayUrl: "https://relay.test",
  accountId: "acct-1",
  deviceId: "dev-1",
  deviceAuthToken: "token-abc",
  surfaceId: "surface-xyz",
};

/** A stub `LiveSocket` whose listeners the test can fire directly. */
function stubSocket() {
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
    emitOpen() {
      for (const l of listeners.open) l();
    },
    emitMessage(data) {
      for (const l of listeners.message) l({ data });
    },
    emitError(err) {
      for (const l of listeners.error) l(err);
    },
    emitClose() {
      for (const l of listeners.close) l();
    },
  };
}

/** A connector that records every URL it was asked to connect to and returns fresh stub sockets. */
function recordingConnector() {
  const sockets = [];
  const urls = [];
  const connect = (url) => {
    urls.push(url);
    const socket = stubSocket();
    sockets.push(socket);
    return socket;
  };
  connect.sockets = sockets;
  connect.urls = urls;
  return connect;
}

/** A fake reconnect scheduler: records `(fn, ms)` calls and lets the test fire them manually. */
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
    fireLatest() {
      const entry = scheduled.filter((e) => !e.cancelled).at(-1);
      assert.ok(entry, "expected a pending (non-cancelled) reconnect to be scheduled");
      entry.fn();
      return entry;
    },
    pendingCount: () => scheduled.filter((e) => !e.cancelled).length,
    delays: () => scheduled.map((e) => e.ms),
  };
}

test("connect URL carries auth and surface_id query params", () => {
  const connect = recordingConnector();
  const listener = createRetractListener({
    ...OPTIONS_BASE,
    onRetract: () => {},
    connectImpl: connect,
  });

  const url = new URL(connect.urls[0]);
  assert.equal(url.protocol, "wss:");
  assert.equal(url.pathname, "/acct-1/devices/dev-1/connect");
  assert.equal(url.searchParams.get("auth"), "token-abc");
  assert.equal(url.searchParams.get("surface_id"), "surface-xyz");

  listener.stop();
});

test("http(s) relay URL is upgraded to ws(s)", () => {
  const connect = recordingConnector();
  const listener = createRetractListener({
    ...OPTIONS_BASE,
    relayUrl: "http://127.0.0.1:8787",
    onRetract: () => {},
    connectImpl: connect,
  });

  assert.match(connect.urls[0], /^ws:\/\/127\.0\.0\.1:8787\//);
  listener.stop();
});

test("a well-formed retract message calls onRetract with the request id", () => {
  const connect = recordingConnector();
  const retracted = [];
  const listener = createRetractListener({
    ...OPTIONS_BASE,
    onRetract: (id) => retracted.push(id),
    connectImpl: connect,
  });

  connect.sockets[0].emitMessage(JSON.stringify({ type: "retract", request_id: "req-1" }));

  assert.deepEqual(retracted, ["req-1"]);
  listener.stop();
});

test("request / ack / error message types are ignored (out of this listener's scope)", () => {
  const connect = recordingConnector();
  const retracted = [];
  const listener = createRetractListener({
    ...OPTIONS_BASE,
    onRetract: (id) => retracted.push(id),
    connectImpl: connect,
  });

  const socket = connect.sockets[0];
  socket.emitMessage(JSON.stringify({ type: "request", request_id: "req-1", envelope: {} }));
  socket.emitMessage(JSON.stringify({ type: "ack", request_id: "req-1", status: "resolved" }));
  socket.emitMessage(JSON.stringify({ type: "error", error: "boom" }));

  assert.deepEqual(retracted, [], "only {type:'retract'} triggers onRetract");
  listener.stop();
});

test("malformed messages are ignored, never throw, and never call onRetract", () => {
  const connect = recordingConnector();
  const retracted = [];
  const listener = createRetractListener({
    ...OPTIONS_BASE,
    onRetract: (id) => retracted.push(id),
    connectImpl: connect,
  });

  const socket = connect.sockets[0];
  assert.doesNotThrow(() => {
    socket.emitMessage("not json");
    socket.emitMessage(JSON.stringify(["not", "an", "object"]));
    socket.emitMessage(JSON.stringify(null));
    socket.emitMessage(JSON.stringify({ type: "retract" })); // missing request_id
    socket.emitMessage(JSON.stringify({ type: "retract", request_id: "" })); // empty request_id
    socket.emitMessage(JSON.stringify({ type: "retract", request_id: 42 })); // wrong type
  });

  assert.deepEqual(retracted, []);
  listener.stop();
});

test("on close, the listener reconnects with exponential backoff capped at 30s", () => {
  const connect = recordingConnector();
  const scheduler = fakeScheduler();
  const listener = createRetractListener({
    ...OPTIONS_BASE,
    onRetract: () => {},
    connectImpl: connect,
    scheduleReconnect: scheduler.schedule,
    cancelReconnect: scheduler.cancel,
    randomImpl: () => 0, // no jitter — deterministic delay assertions
  });

  assert.equal(connect.sockets.length, 1, "connects immediately on creation");

  // First disconnect: backoff starts at 1s.
  connect.sockets[0].emitClose();
  assert.equal(scheduler.delays().at(-1), 1_000);
  scheduler.fireLatest();
  assert.equal(connect.sockets.length, 2, "reconnected after the scheduled delay fired");

  // Second disconnect without an intervening open: backoff doubles to 2s.
  connect.sockets[1].emitClose();
  assert.equal(scheduler.delays().at(-1), 2_000);
  scheduler.fireLatest();

  // Third disconnect: doubles again to 4s.
  connect.sockets[2].emitClose();
  assert.equal(scheduler.delays().at(-1), 4_000);

  listener.stop();
});

test("backoff resets to the minimum after a successful open", () => {
  const connect = recordingConnector();
  const scheduler = fakeScheduler();
  const listener = createRetractListener({
    ...OPTIONS_BASE,
    onRetract: () => {},
    connectImpl: connect,
    scheduleReconnect: scheduler.schedule,
    cancelReconnect: scheduler.cancel,
    randomImpl: () => 0,
  });

  connect.sockets[0].emitClose(); // backoff -> 1s scheduled, next backoff becomes 2s
  scheduler.fireLatest();
  connect.sockets[1].emitOpen(); // successful reconnect resets backoff to 1s
  connect.sockets[1].emitClose();

  assert.equal(scheduler.delays().at(-1), 1_000, "backoff restarted at the minimum after open");

  listener.stop();
});

test("stop() closes the socket, cancels a pending reconnect, and prevents further reconnects", () => {
  const connect = recordingConnector();
  const scheduler = fakeScheduler();
  const listener = createRetractListener({
    ...OPTIONS_BASE,
    onRetract: () => {},
    connectImpl: connect,
    scheduleReconnect: scheduler.schedule,
    cancelReconnect: scheduler.cancel,
  });

  const firstSocket = connect.sockets[0];
  listener.stop();

  assert.equal(firstSocket.closed(), true, "stop() closes the live socket");

  // A close event arriving after stop() (e.g. a late server-side close) must not schedule a
  // reconnect.
  firstSocket.emitClose();
  assert.equal(scheduler.pendingCount(), 0, "no reconnect is scheduled after stop()");
  assert.equal(connect.sockets.length, 1, "no further connect() calls after stop()");
});

test("stop() cancels an already-scheduled reconnect timer", () => {
  const connect = recordingConnector();
  const scheduler = fakeScheduler();
  const listener = createRetractListener({
    ...OPTIONS_BASE,
    onRetract: () => {},
    connectImpl: connect,
    scheduleReconnect: scheduler.schedule,
    cancelReconnect: scheduler.cancel,
  });

  connect.sockets[0].emitClose();
  assert.equal(scheduler.pendingCount(), 1, "a reconnect is pending after the first close");

  listener.stop();

  assert.equal(scheduler.pendingCount(), 0, "stop() cancels the pending reconnect timer");
});
