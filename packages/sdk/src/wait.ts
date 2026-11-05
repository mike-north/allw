/**
 * Awaiting a verdict, fail-closed (`docs/contract.md` §Invariants #6).
 *
 * Strategy: open the live `…/wait` WebSocket and race it against a deadline tied to the request's
 * `expires_at`. The relay pushes `{ type: "verdict", … }` the instant a device decides,
 * `{ type: "expired", … }` for a past-deadline request, or `{ type: "retracted", … }` if the
 * integrator that submitted the request cancelled it (issue #195). If the socket cannot be used
 * (no global `WebSocket`, or it errors), fall back to polling `GET /:acct/requests/:id` until a
 * fully verified verdict, another terminal status, or the deadline. Without a fully verified
 * verdict or other terminal signal at the deadline, resolve to `timeout`. Caller abort races the
 * wait too: confirmed retraction is `retracted`, while refusal/failure is local `timeout`. The
 * native deadline keeps Node alive through pending async verification and is cleared on settlement.
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
  /**
   * Integrator-owned full verification through the core. A rejected candidate is not terminal;
   * transport delivery and relay provenance alone cannot decide a human outcome.
   */
  readonly acceptVerdict: (value: unknown) => Promise<boolean>;
  /** Caller cancellation retracts once, then ends the local wait even if the relay refuses it. */
  readonly signal?: AbortSignal;
  /**
   * Schedules `fn` after `ms`; injectable so tests can drive a fake clock. When absent, the wait
   * keeps a referenced deadline timer until the wait settles, then clears it, so async nonce
   * verification cannot let Node exit without a result. Poll sleeps are also referenced and
   * clamped to the deadline. An override replaces both timers and owns their keep-alive/cleanup
   * behavior; unref'ing all active timers can let Node exit mid-wait with no verdict (#254).
   */
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

/**
 * Default scheduler for the **poll sleep**. A referenced timer preserves keep-alive between polls;
 * injected schedulers own the same responsibility. Each sleep is clamped to the time remaining,
 * so it cannot hold the process beyond the deadline, and the loop stops once the wait settles.
 */
const DEFAULT_POLL_SCHEDULE = (fn: () => void, ms: number): void => {
  setTimeout(fn, ms);
};

/**
 * Await a verdict, returning a terminal {@link VerdictOutcome}. Never throws for a verdict that did
 * not arrive — the deadline path resolves to `timeout` (fail-closed). Relay/transport errors during
 * polling propagate; the caller (`requestApproval`) catches them and fails closed to a non-approving
 * verdict (the timeout path → `expired`), never an approval.
 */
export async function awaitVerdict(requestId: string, deps: WaitDeps): Promise<VerdictOutcome> {
  const pollSchedule = deps.schedule ?? DEFAULT_POLL_SCHEDULE;

  // Async verification and cancellation may own no live I/O handle. Keep a native backstop
  // referenced until terminal settlement, then clear it so an early result exits promptly.
  const deadlineTimer: { handle?: ReturnType<typeof setTimeout> } = {};
  const deadlinePromise = new Promise<VerdictOutcome>((resolve) => {
    const remaining = Math.max(0, deps.deadline - deps.now());
    const expire = (): void => {
      resolve({ kind: "timeout" });
    };
    if (deps.schedule) deps.schedule(expire, remaining);
    else deadlineTimer.handle = setTimeout(expire, remaining);
  });

  const lifetime = new AbortController();
  // Cancellation has its own terminal outcome: relay confirmation is a retraction, while refusal
  // or transport failure is only local expiry. Neither trusts an SDK-unverifiable stored verdict.
  const cancellationPromise = new Promise<VerdictOutcome>((resolve) => {
    const signal = deps.signal;
    if (!signal) return;
    const onAbort = (): void => {
      void deps.relay.retract(requestId).then(
        () => {
          resolve({ kind: "retracted" });
        },
        () => {
          resolve({ kind: "timeout" });
        },
      );
    };
    signal.addEventListener("abort", onAbort, { once: true, signal: lifetime.signal });
    // Abort may have happened during submission, before the wait was armed with the request token.
    if (signal.aborted) onAbort();
  });

  const waitForTransport = async (): Promise<VerdictOutcome> => {
    if (deps.webSocketFactory) {
      try {
        const outcome = await waitOverSocket(
          requestId,
          deps,
          deps.webSocketFactory,
          lifetime.signal,
        );
        if (outcome) return outcome;
        // A socket that closes without an accepted frame degrades to polling.
      } catch {
        // Socket construction/connection failed — degrade to polling.
      }
    }
    return pollUntilTerminal(requestId, deps, pollSchedule, () => lifetime.signal.aborted);
  };

  try {
    // A pre-existing abort needs only its retract attempt, not a new socket or poll. Once abort
    // is observed, a concurrent delivery cannot replace cancellation with an approval. The local
    // deadline still bounds a hung retract, just as it bounds transport and nonce verification.
    if (deps.signal?.aborted) return await Promise.race([cancellationPromise, deadlinePromise]);
    const outcome = await Promise.race([waitForTransport(), deadlinePromise, cancellationPromise]);
    return deps.signal?.aborted
      ? await Promise.race([cancellationPromise, deadlinePromise])
      : outcome;
  } catch (cause) {
    if (deps.signal?.aborted) return await Promise.race([cancellationPromise, deadlinePromise]);
    throw cause;
  } finally {
    // Release the owned backstop, cancellation listeners, socket and further polling together.
    if (deadlineTimer.handle !== undefined) clearTimeout(deadlineTimer.handle);
    lifetime.abort();
  }
}

/**
 * Wait for a terminal frame over the `…/wait` WebSocket. Resolves to the outcome, or to `null` if
 * the socket closes without ever delivering one (the caller then falls back to polling).
 */
function waitOverSocket(
  requestId: string,
  deps: WaitDeps,
  factory: WebSocketFactory,
  signal: AbortSignal,
): Promise<VerdictOutcome | null> {
  return new Promise<VerdictOutcome | null>((resolve, reject) => {
    let settled = false;
    // Read through a function across awaits: deadline/close callbacks can settle the socket while
    // async verification is pending, even though TypeScript cannot model those callback writes.
    const isSettled = (): boolean => settled;
    let socket: MinimalWebSocket;
    const finish = (outcome: VerdictOutcome | null): void => {
      if (isSettled()) return;
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

    signal.addEventListener(
      "abort",
      () => {
        finish(null);
      },
      { once: true },
    );
    // Serialize verification: an async nonce store must not let later frames overtake the first
    // fully verified decision. A failed candidate leaves the same socket and deadline in force.
    let candidates = Promise.resolve();
    socket.addEventListener("message", (event: { data: unknown }) => {
      candidates = candidates
        .then(async () => {
          if (isSettled()) return;
          if (deps.now() >= deps.deadline) {
            finish({ kind: "timeout" });
            return;
          }
          const frame = parseFrame(event.data);
          if (!frame) return;
          const outcome = frameToOutcome(frame);
          if (!outcome) return;
          if (outcome.kind === "verdict" && !(await deps.acceptVerdict(outcome.value))) return;
          if (!isSettled()) finish(deps.now() >= deps.deadline ? { kind: "timeout" } : outcome);
        })
        .catch(() => {
          finish(null);
        });
    });
    socket.addEventListener("error", () => {
      // Treat a socket error as "no terminal frame" → poll fallback (not a hard reject, so a
      // transient WS issue still resolves via polling).
      void candidates.then(() => {
        finish(null);
      });
    });
    socket.addEventListener("close", () => {
      // A relay may close immediately after its terminal frame. Drain delivered candidates before
      // falling back, so socket closure cannot discard a valid verdict or race its nonce insert.
      void candidates.then(() => {
        finish(null);
      });
    });
  });
}

/**
 * Poll `GET /:acct/requests/:id` on a cadence until a terminal outcome appears, the deadline passes,
 * or `isSettled()` reports that the surrounding race was already decided.
 *
 * Each sleep is clamped to the time left before the deadline, so the (ref'd) poll timer never holds
 * the process past the deadline even when `pollIntervalMs` exceeds the remaining time.
 */
async function pollUntilTerminal(
  requestId: string,
  deps: WaitDeps,
  schedule: (fn: () => void, ms: number) => void,
  isSettled: () => boolean,
): Promise<VerdictOutcome> {
  for (;;) {
    if (isSettled() || deps.now() >= deps.deadline) return { kind: "timeout" };
    const outcome = await deps.relay.poll(requestId);
    if (outcome && (outcome.kind !== "verdict" || (await deps.acceptVerdict(outcome.value)))) {
      return deps.now() >= deps.deadline ? { kind: "timeout" } : outcome;
    }
    // Resolved relay rows can repeat an SDK-unverifiable verdict forever. Treat them like a
    // pending response and sleep on the normal cadence rather than spinning or trusting status.
    const remaining = deps.deadline - deps.now();
    if (remaining <= 0 || isSettled()) return { kind: "timeout" };
    await new Promise<void>((resolve) => {
      schedule(resolve, Math.min(deps.pollIntervalMs, remaining));
    });
    if (isSettled()) return { kind: "timeout" };
  }
}
