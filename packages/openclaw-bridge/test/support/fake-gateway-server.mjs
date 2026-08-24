/**
 * A **real WebSocket server** speaking OpenClaw's real frame shapes, for integration-testing the
 * gateway client against the actual wire contract rather than a hand-built approximation.
 *
 * Frames follow `@openclaw/gateway-protocol`'s `RequestFrame` / `ResponseFrame` / `EventFrame`
 * envelopes and the documented `connect.challenge` → `connect` → `hello-ok` handshake.
 *
 * @see https://docs.openclaw.ai/gateway/clients
 * @see https://unpkg.com/@openclaw/gateway-protocol@beta/protocol.schema.json
 */

import { createServer } from "node:http";
import { WebSocketServer } from "ws";

/** A fixed challenge nonce/timestamp — no `Date.now()` in test data. */
export const CHALLENGE_NONCE = "nonce-0123456789abcdef";
export const CHALLENGE_TS = 1_700_000_000_000;

/** Build a `hello-ok` payload with the fields the bridge reads. */
export function helloOk(overrides = {}) {
  return {
    type: "hello-ok",
    protocol: 4,
    server: { version: "test-gateway", connId: "conn-1" },
    features: {
      methods: ["approval.get", "approval.resolve", "exec.approval.list"],
      events: [
        "exec.approval.requested",
        "exec.approval.resolved",
        "plugin.approval.requested",
        "plugin.approval.resolved",
      ],
    },
    snapshot: { presence: [], health: {} },
    policy: { tickIntervalMs: 30_000 },
    ...overrides,
  };
}

/**
 * Start a fake gateway.
 *
 * @param options.onConnect receives the `connect` params and returns either
 *   `{ ok: true, payload }` or `{ ok: false, error }` — so a test can drive PAIRING_REQUIRED or a
 *   protocol mismatch exactly as the gateway would.
 * @param options.methods per-RPC handlers for everything after `connect`.
 * @param options.challenge override the `connect.challenge` payload (e.g. omit `ts`).
 */
export async function startFakeGateway(options = {}) {
  const http = createServer();
  const wss = new WebSocketServer({ server: http });
  /** Every `connect` params object received, in order (one per connection attempt). */
  const connects = [];
  /** Every non-connect `{ method, params }` received, in order. */
  const calls = [];
  const sockets = new Set();

  wss.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.send(
      JSON.stringify({
        type: "event",
        event: "connect.challenge",
        payload: options.challenge ?? { nonce: CHALLENGE_NONCE, ts: CHALLENGE_TS },
      }),
    );

    socket.on("message", (raw) => {
      let frame;
      try {
        frame = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (frame.type !== "req") return;

      if (frame.method === "connect") {
        connects.push(frame.params);
        const outcome = options.onConnect?.(frame.params, connects.length) ?? { ok: true };
        socket.send(
          JSON.stringify(
            outcome.ok
              ? { type: "res", id: frame.id, ok: true, payload: outcome.payload ?? helloOk() }
              : { type: "res", id: frame.id, ok: false, error: outcome.error },
          ),
        );
        return;
      }

      calls.push({ method: frame.method, params: frame.params });
      const handler = options.methods?.[frame.method];
      if (handler === undefined) {
        socket.send(
          JSON.stringify({
            type: "res",
            id: frame.id,
            ok: false,
            error: { code: "METHOD_NOT_FOUND", message: frame.method },
          }),
        );
        return;
      }
      void Promise.resolve(handler(frame.params, { emit })).then(
        (payload) => socket.send(JSON.stringify({ type: "res", id: frame.id, ok: true, payload })),
        (err) =>
          socket.send(
            JSON.stringify({
              type: "res",
              id: frame.id,
              ok: false,
              error: { code: "INTERNAL", message: String(err) },
            }),
          ),
      );
    });
  });

  /** Broadcast an event frame to every open connection. */
  function emit(event, payload) {
    for (const socket of sockets) {
      socket.send(JSON.stringify({ type: "event", event, payload }));
    }
  }

  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  const { port } = http.address();

  return {
    url: `ws://127.0.0.1:${port}`,
    connects,
    calls,
    emit,
    /** Drop every open socket without closing the server (simulates a transport loss). */
    dropConnections() {
      for (const socket of sockets) socket.terminate();
    },
    async close() {
      for (const socket of sockets) socket.terminate();
      await new Promise((resolve) => wss.close(resolve));
      await new Promise((resolve) => http.close(resolve));
    },
  };
}

/** Poll `predicate` until it is true or the budget elapses; throws with `label` on timeout. */
export async function waitFor(predicate, label, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
