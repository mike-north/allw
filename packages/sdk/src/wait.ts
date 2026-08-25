/**
 * Awaiting a verdict, fail-closed (`docs/contract.md` §Invariants #6).
 *
 * Strategy: open the live `…/wait` WebSocket and race it against a deadline tied to the request's
 * `expires_at`. The relay pushes `{ type: "verdict", … }` the instant a device decides,
 * `{ type: "expired", … }` for a past-deadline request, or `{ type: "retracted", … }` if the
 * integrator that submitted the request cancelled it (issue #195). If the socket cannot be used
 * (no global `WebSocket`, or it errors), fall back to polling `GET /:acct/requests/:id` until a
 * terminal status or the deadline. On the deadline elapsing with no terminal signal, resolve to
 * `timeout`.
 *
 * Every path that is not a delivered verdict is a **deny** outcome (`expired`/`timeout`) — the SDK
 * never fabricates an approval. `retracted` is different in kind, not degree: it is not a verdict at
 * all (no device ever decided), so the caller (`requestApproval`) rejects rather than resolves for
 * that outcome — see `index.ts`.
 */

import type { NowImpl, RelayClient, VerdictOutcome } from "./relay.js";

/**
 * A minimal structural type for the WebSocket the SDK uses. Node ≥22 and browsers expose a global
 * `WebSocket` matching this; tests inject a double. Kept narrow so the SDK does not depend on the
 * DOM lib.
 */
export interface MinimalWebSocket {
  addEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
  addEventListener(type: "open" | "error" | "close", listener: () => void): void;
  close(): void;
}

/** Constructs a {@link MinimalWebSocket} for a `ws(s)://` URL. */
export type WebSocketFactory = (url: string) => MinimalWebSocket;

/** Tunables for the wait loop, all injectable for deterministic tests. */
export interface WaitDeps {
  readonly relay: RelayClient;
  readonly now: NowImpl;
  /** Absolute deadline (Unix ms); the wait fails closed once `now() >= deadline`. */
  readonly deadline: number;
  /** Optional WebSocket factory; when absent the wait polls only. */
  readonly webSocketFactory?: WebSocketFactory;
  /** Poll cadence in ms (fallback path). */
  readonly pollIntervalMs: number;
  /** Schedules `fn` after `ms`; injectable so tests can drive a fake clock. Defaults to `setTimeout`. */
  readonly schedule?: (fn: () => void, ms: number) => void;
}

/** Decode a relay WebSocket frame's `data` (string or binary) into a parsed object, or `null`. */
function parseFrame(data: unknown): Record<string, unknown> | null {
  let text: string;
  if (typeof data === "string") {
    text = data;
  } else if (data instanceof ArrayBuffer) {
    text = new TextDecoder().decode(data);
  } else if (ArrayBuffer.isView(data)) {
    // Decode the exact bytes the view covers — passing the view (not `.buffer`) makes TextDecoder
    // honor `byteOffset`/`byteLength`, so a frame carried in a subarray isn't polluted by
    // neighbouring bytes of a shared backing buffer.
    text = new TextDecoder().decode(data);
  } else {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    return null;
  }
  return null;
}

/** Map a relay `…/wait` frame to a terminal outcome, or `null` for a non-terminal/unknown frame. */
function frameToOutcome(frame: Record<string, unknown>): VerdictOutcome | null {
  if (frame.type === "verdict") {
    return { kind: "verdict", value: frame.verdict ?? null };
  }
  if (frame.type === "expired") {
    return { kind: "expired" };
  }
  if (frame.type === "retracted") {
    return { kind: "retracted" };
  }
  return null;
}

const DEFAULT_SCHEDULE = (fn: () => void, ms: number): void => {
  const timer = setTimeout(fn, ms);
  // Don't let a still-pending deadline/poll timer keep a node process alive once the verdict has
  // already resolved the race (no-op in browsers/workers, where `unref` is absent).
  (timer as { unref?: () => void }).unref?.();
};

/**
 * Await a verdict, returning a terminal {@link VerdictOutcome}. Never throws for a verdict that did
 * not arrive — the deadline path resolves to `timeout` (fail-closed). Relay/transport errors during
 * polling propagate; the caller (`requestApproval`) catches them and fails closed to a non-approving
 * verdict (the timeout path → `expired`), never an approval.
 */
export async function awaitVerdict(requestId: string, deps: WaitDeps): Promise<VerdictOutcome> {
  const schedule = deps.schedule ?? DEFAULT_SCHEDULE;

  // The deadline timer is the fail-closed backstop shared by both strategies.
  const deadlinePromise = new Promise<VerdictOutcome>((resolve) => {
    const remaining = Math.max(0, deps.deadline - deps.now());
    schedule(() => {
      resolve({ kind: "timeout" });
    }, remaining);
  });

  if (deps.webSocketFactory) {
    try {
      const wsOutcome = await Promise.race([
        waitOverSocket(requestId, deps, deps.webSocketFactory),
        deadlinePromise,
      ]);
      if (wsOutcome) return wsOutcome;
      // The socket closed without a terminal frame before the deadline — fall through to polling
      // as a robustness backstop.
    } catch {
      // Socket construction/connection failed — degrade to polling.
    }
  }

  return Promise.race([pollUntilTerminal(requestId, deps, schedule), deadlinePromise]);
}

/**
 * Wait for a terminal frame over the `…/wait` WebSocket. Resolves to the outcome, or to `null` if
 * the socket closes without ever delivering one (the caller then falls back to polling).
 */
function waitOverSocket(
  requestId: string,
  deps: WaitDeps,
  factory: WebSocketFactory,
): Promise<VerdictOutcome | null> {
  return new Promise<VerdictOutcome | null>((resolve, reject) => {
    let settled = false;
    let socket: MinimalWebSocket;
    const finish = (outcome: VerdictOutcome | null): void => {
      if (settled) return;
      settled = true;
      try {
        socket.close();
      } catch {
        // already closing — ignore
      }
      resolve(outcome);
    };

    try {
      socket = factory(deps.relay.waitUrl(requestId));
    } catch (cause) {
      reject(cause instanceof Error ? cause : new Error("WebSocket construction failed"));
      return;
    }

    socket.addEventListener("message", (event: { data: unknown }) => {
      const frame = parseFrame(event.data);
      if (!frame) return;
      const outcome = frameToOutcome(frame);
      if (outcome) finish(outcome);
    });
    socket.addEventListener("error", () => {
      // Treat a socket error as "no terminal frame" → poll fallback (not a hard reject, so a
      // transient WS issue still resolves via polling).
      finish(null);
    });
    socket.addEventListener("close", () => {
      finish(null);
    });
  });
}

/** Poll `GET /:acct/requests/:id` on a cadence until a terminal outcome appears. */
async function pollUntilTerminal(
  requestId: string,
  deps: WaitDeps,
  schedule: (fn: () => void, ms: number) => void,
): Promise<VerdictOutcome> {
  for (;;) {
    const outcome = await deps.relay.poll(requestId);
    if (outcome) return outcome;
    if (deps.now() >= deps.deadline) return { kind: "timeout" };
    await new Promise<void>((resolve) => {
      schedule(resolve, deps.pollIntervalMs);
    });
  }
}
