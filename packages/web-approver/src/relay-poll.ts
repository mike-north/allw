/**
 * Live inbox refresh: relay polling + re-render (issue #147).
 *
 * `createRelayPoller` drives the 1–5s poll loop that keeps the web approver inbox up to date
 * without a WebSocket connection. Each tick fetches the authenticated device's pending envelopes
 * from `GET /{accountId}/devices/{deviceId}/inbox`, calls `controller.sync(envelopes)`, and
 * re-renders the UI.
 *
 * # Fail-closed design (`docs/contract.md` §Invariants #6 + #7)
 * - A **fetch failure** (network error, relay outage, non-2xx) keeps the last-known inbox visible
 *   but sets an error banner — never silently drops work or fabricates state.
 * - A **parse failure** (relay returned non-JSON or a missing/non-array `envelopes` field) is
 *   treated identically to a fetch failure: last-known state is preserved with an error flag.
 * - An **envelope that fails `prepare`** (tampered context, wrong key, expired) is handled by
 *   `WebApproverController.sync` which marks that item `unverified` — deny-only, never
 *   approved-looking.
 * - On outage the countdown timers continue draining against the last-known `expiresAt` values,
 *   so expired items correctly transition to `expired` without a new poll.
 *
 * No crypto or verification is performed here — all trust decisions flow through the runtime seam
 * established in #146 (`createWasmRuntime` / the controller's `sync`).
 *
 * @see ../../../docs/contract.md §Invariants #6, #7
 * @see ./index.ts (WebApproverController.sync)
 */

import type { ApprovalEnvelope, WebApproverController } from "./index.js";

/** The minimum polling interval in ms (guards against misconfiguration). */
const MIN_POLL_INTERVAL_MS = 500;

/** An injectable `fetch`-compatible function for tests. */
export type FetchImpl = typeof fetch;

/** An injectable `setInterval` compatible scheduler for tests. */
export type IntervalScheduler = (fn: () => void, ms: number) => ReturnType<typeof setInterval>;

/** An injectable `clearInterval` compatible function for tests. */
export type IntervalCanceller = (id: ReturnType<typeof setInterval>) => void;

/** Called after every successful or failed poll so the caller can update the UI. */
export type OnPollResult = (result: PollResult) => void;

/** The outcome of a single poll tick. */
export type PollResult =
  | {
      /** The poll succeeded and the controller was synced. */
      readonly ok: true;
      /** The envelopes returned by the relay this tick. */
      readonly envelopes: readonly ApprovalEnvelope[];
    }
  | {
      /** The poll failed (network error, relay outage, or malformed response). */
      readonly ok: false;
      /** Human-readable reason for the failure. */
      readonly error: string;
    };

/** Options for {@link createRelayPoller}. */
export interface RelayPollerOptions {
  /** The relay base URL, e.g. `https://relay.allw.app`. Trailing slashes are normalized. */
  readonly relayUrl: string;
  /** The account id (the approver's account). Used to build the per-account endpoint URL. */
  readonly accountId: string;
  /** The device id (this approver device). Used to build the per-device inbox URL. */
  readonly deviceId: string;
  /** Bearer token authorizing this device against the relay's inbox endpoint. */
  readonly deviceAuthToken: string;
  /** The controller whose inbox is refreshed after each successful poll. */
  readonly controller: WebApproverController;
  /** Poll interval in ms. Must be ≥ 500. Defaults to 2000 (2s). */
  readonly pollIntervalMs?: number;
  /**
   * Called after every poll tick with the outcome. Intended for triggering a UI re-render or
   * showing/hiding an outage banner.
   */
  readonly onPollResult: OnPollResult;
  /** Injectable `fetch` for tests. Defaults to the global `fetch`. */
  readonly fetchImpl?: FetchImpl;
  /** Injectable `setInterval` for tests. Defaults to the global `setInterval`. */
  readonly scheduleInterval?: IntervalScheduler;
  /** Injectable `clearInterval` for tests. Defaults to the global `clearInterval`. */
  readonly cancelInterval?: IntervalCanceller;
}

/** Controls a running poll loop. */
export interface RelayPoller {
  /**
   * Fire one poll tick immediately (in addition to the scheduled interval). Useful for triggering
   * a forced refresh after a decision (e.g. after `controller.decide()`).
   */
  readonly poll: () => Promise<void>;
  /** Stop the poll loop and cancel the interval timer. Safe to call multiple times. */
  readonly stop: () => void;
}

/**
 * Build the per-account, per-device inbox URL:
 * `<relayUrl>/<accountId>/devices/<deviceId>/inbox`.
 */
function inboxUrl(relayUrl: string, accountId: string, deviceId: string): string {
  const base = relayUrl.replace(/\/+$/, "");
  return `${base}/${encodeURIComponent(accountId)}/devices/${encodeURIComponent(deviceId)}/inbox`;
}

/**
 * Validate that a parsed response body from the relay inbox endpoint has the expected shape.
 * Returns the typed envelopes array on success, or `null` if the body is malformed.
 *
 * The relay is zero-knowledge and sends opaque ciphertext envelopes; the shape contract here is
 * just the routing/lifecycle fields the web approver needs to schedule and sync. Actual decryption
 * and verification happen in the controller's runtime (`createWasmRuntime.prepare`).
 */
function parseInboxBody(body: unknown): readonly ApprovalEnvelope[] | null {
  if (typeof body !== "object" || body === null) return null;
  const raw = (body as Record<string, unknown>).envelopes;
  if (!Array.isArray(raw)) return null;
  // Accept any envelope-shaped object; the runtime's prepare() is the trust boundary.
  return raw as readonly ApprovalEnvelope[];
}

/**
 * Start a 1–5s poll loop against `GET /{accountId}/devices/{deviceId}/inbox`, keeping the
 * approver's inbox live without a WebSocket connection (issue #147).
 *
 * The first tick runs immediately; subsequent ticks run on `pollIntervalMs`. On every tick:
 *  1. Fetch the inbox from the relay.
 *  2. Call `controller.sync(envelopes)` (fail-closed: a bad envelope is rendered `unverified`).
 *  3. Call `onPollResult` so the caller can re-render.
 *
 * On fetch or parse failure the controller is **not** re-synced (last-known inbox is preserved),
 * and `onPollResult` is called with `{ ok: false, error }` so the UI can show an outage banner.
 *
 * @returns A `RelayPoller` handle with `poll()` (force a tick) and `stop()` (cancel the loop).
 */
export function createRelayPoller(options: RelayPollerOptions): RelayPoller {
  const { relayUrl, accountId, deviceId, deviceAuthToken, controller, onPollResult } = options;

  const pollIntervalMs = Math.max(options.pollIntervalMs ?? 2_000, MIN_POLL_INTERVAL_MS);
  const fetchImpl: FetchImpl = options.fetchImpl ?? fetch;
  const scheduleInterval: IntervalScheduler = options.scheduleInterval ?? setInterval;
  const cancelInterval: IntervalCanceller = options.cancelInterval ?? clearInterval;

  const url = inboxUrl(relayUrl, accountId, deviceId);
  const headers = { Authorization: `Bearer ${deviceAuthToken}` };

  let intervalId: ReturnType<typeof setInterval> | null = null;

  async function poll(): Promise<void> {
    let body: unknown;
    try {
      const resp = await fetchImpl(url, { method: "GET", headers });
      if (!resp.ok) {
        // Non-2xx: relay is degraded or the token is invalid. Preserve last state, show error.
        onPollResult({
          ok: false,
          error: `relay inbox returned HTTP ${String(resp.status)} — showing stale inbox`,
        });
        return;
      }
      body = await resp.json();
    } catch (err) {
      // Network failure, timeout, or JSON parse error — all map to the same outage banner.
      onPollResult({
        ok: false,
        error: `relay inbox unavailable: ${err instanceof Error ? err.message : String(err)}`,
      });
      return;
    }

    const envelopes = parseInboxBody(body);
    if (envelopes === null) {
      // Malformed relay response — keep the last-known state, show an error.
      onPollResult({
        ok: false,
        error: "relay inbox returned an unexpected response shape — showing stale inbox",
      });
      return;
    }

    // Each envelope is prepared independently in the controller; a tampered/undecryptable one
    // becomes `unverified` (deny-only) without hiding the rest of the inbox (fail-closed #6).
    await controller.sync(envelopes);
    onPollResult({ ok: true, envelopes });
  }

  // Fire the first tick immediately, then schedule subsequent ticks.
  void poll();
  intervalId = scheduleInterval(() => {
    void poll();
  }, pollIntervalMs);

  function stop(): void {
    if (intervalId !== null) {
      cancelInterval(intervalId);
      intervalId = null;
    }
  }

  return { poll, stop };
}
