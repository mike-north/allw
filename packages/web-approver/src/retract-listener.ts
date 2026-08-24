/**
 * Cross-device retraction listener (#150): a live `GET …/connect` WebSocket subscription whose
 * only job is to remove a request from the inbox the moment ANOTHER device/surface resolves it,
 * instead of waiting up to `pollIntervalMs` for the next `relay-poll.ts` tick (#147) to notice it
 * has dropped out of `GET /inbox`.
 *
 * # Scope — retract-only, not a duplex verdict channel
 * This module only *listens*. It never sends `{type:"verdict"}` — verdict submission from the web
 * approver is separate, tracked work (`docs/relay-api.md` §2 build note: "the app must implement
 * the WS client" for submission is still open). It also does not treat inbound
 * `{type:"request"}` push messages as authoritative: new/updated requests keep arriving through
 * the existing poll loop, which already re-syncs the full inbox every `pollIntervalMs`. Naming
 * this a "retract listener" rather than a general "live connection" keeps a future duplex
 * verdict-submission channel from silently inheriting this module's much narrower contract
 * (`~/.claude/rules/api-semantics.md` — model by what a thing does, not by what's convenient).
 *
 * # Fail-closed / never fail-open
 * A dropped socket, malformed message, or relay-side `{type:"error"}` never removes anything by
 * itself — only a well-formed `{type:"retract", request_id}` calls `onRetract`. On disconnect the
 * listener reconnects with exponential backoff + jitter (`docs/relay-api.md` §7.3). The poll loop
 * remains the fail-closed backstop: a resolved request also naturally drops out of the next
 * `GET /inbox` poll even if this socket never reconnects, so a lost connection degrades to #147's
 * poll-interval latency rather than to a stuck, double-decidable inbox.
 *
 * @see ../../../docs/relay-api.md §4 (WebSocket protocol), §7.3 (WebSocket lifecycle / reconnect)
 * @see ./relay-poll.ts (the poll-based fallback/reconciliation path)
 * @see ./surface-id.ts (the persisted `surface_id` this listener connects with)
 */

/** The minimum reconnect delay in ms (`docs/relay-api.md` §7.3: "1→2→4→…→cap 30s"). */
const MIN_RECONNECT_DELAY_MS = 1_000;
/** The reconnect delay cap in ms. */
const MAX_RECONNECT_DELAY_MS = 30_000;
/** Jitter fraction applied on top of the current backoff delay, per §7.3 ("backoff + jitter"). */
const JITTER_FRACTION = 0.2;

/** A `WebSocket`-shaped surface (the global browser `WebSocket`, or a stub in tests). */
export interface LiveSocket {
  close(code?: number, reason?: string): void;
  addEventListener(type: "open" | "close", listener: () => void): void;
  addEventListener(type: "message", listener: (ev: { data: unknown }) => void): void;
  addEventListener(type: "error", listener: (ev: unknown) => void): void;
}

/** An injectable connector so tests never open a real network socket. */
export type ConnectImpl = (url: string) => LiveSocket;

/** An injectable `setTimeout`-compatible scheduler for tests. */
export type ReconnectScheduler = (fn: () => void, ms: number) => ReturnType<typeof setTimeout>;

/** An injectable `clearTimeout`-compatible canceller for tests. */
export type ReconnectCanceller = (id: ReturnType<typeof setTimeout>) => void;

/** Options for {@link createRetractListener}. */
export interface RetractListenerOptions {
  /** The relay base URL (`http(s)://…`); upgraded to `ws(s)://` internally. */
  readonly relayUrl: string;
  /** The account id (the approver's account). */
  readonly accountId: string;
  /** The device id (this approver device). */
  readonly deviceId: string;
  /** Bearer token authorizing this device against the relay's connect endpoint. */
  readonly deviceAuthToken: string;
  /** This install's stable surface id (`docs/relay-api.md` §7.4; see `./surface-id.ts`). */
  readonly surfaceId: string;
  /** Called with the `request_id` of every well-formed `{type:"retract"}` message received. */
  readonly onRetract: (requestId: string) => void;
  /** Injectable connector for tests. Defaults to the global browser `WebSocket`. */
  readonly connectImpl?: ConnectImpl;
  /** Injectable reconnect scheduler for tests. Defaults to the global `setTimeout`. */
  readonly scheduleReconnect?: ReconnectScheduler;
  /** Injectable reconnect canceller for tests. Defaults to the global `clearTimeout`. */
  readonly cancelReconnect?: ReconnectCanceller;
  /** Injectable jitter source for deterministic tests. Defaults to `Math.random`. */
  readonly randomImpl?: () => number;
}

/** Controls a running retraction listener. */
export interface RetractListener {
  /** Stop listening, close the socket, and cancel any pending reconnect. Idempotent. */
  readonly stop: () => void;
}

/** Build the `/{accountId}/devices/{deviceId}/connect?auth=…&surface_id=…` WebSocket URL. */
function connectUrl(options: RetractListenerOptions): string {
  const base = options.relayUrl.replace(/\/+$/, "").replace(/^http/, "ws");
  const params = new URLSearchParams({
    auth: options.deviceAuthToken,
    surface_id: options.surfaceId,
  });
  return `${base}/${encodeURIComponent(options.accountId)}/devices/${encodeURIComponent(options.deviceId)}/connect?${params.toString()}`;
}

/**
 * Parse a raw WS message payload into a `retract` request id, or `null` if the message is
 * malformed, unparseable, or a different message type (`request`/`ack`/`error` — all ignored by
 * this listener; see the module doc's Scope section).
 */
function parseRetractRequestId(data: unknown): string | null {
  const text = typeof data === "string" ? data : decodeBinary(data);
  if (text === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  if (obj.type !== "retract") return null;
  return typeof obj.request_id === "string" && obj.request_id.length > 0 ? obj.request_id : null;
}

function decodeBinary(data: unknown): string | null {
  if (data instanceof ArrayBuffer) return new TextDecoder().decode(data);
  return null;
}

/**
 * Start a live `connect` WebSocket subscription that calls `onRetract(requestId)` for every
 * cross-device/-surface `{type:"retract"}` message (#150). Connects immediately; on close/error it
 * reconnects with exponential backoff + jitter capped at {@link MAX_RECONNECT_DELAY_MS}, resetting
 * the backoff to {@link MIN_RECONNECT_DELAY_MS} after a successful `open`.
 *
 * @returns A {@link RetractListener} handle with `stop()` to tear the whole thing down.
 */
export function createRetractListener(options: RetractListenerOptions): RetractListener {
  const connectImpl: ConnectImpl = options.connectImpl ?? ((url) => new WebSocket(url));
  const scheduleReconnect: ReconnectScheduler = options.scheduleReconnect ?? setTimeout;
  const cancelReconnect: ReconnectCanceller = options.cancelReconnect ?? clearTimeout;
  const randomImpl: () => number = options.randomImpl ?? Math.random;

  const url = connectUrl(options);

  let stopped = false;
  let reconnectDelayMs = MIN_RECONNECT_DELAY_MS;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let socket: LiveSocket | null = null;

  function scheduleNextConnect(): void {
    if (stopped) return;
    const jitterMs = randomImpl() * reconnectDelayMs * JITTER_FRACTION;
    const delayMs = reconnectDelayMs + jitterMs;
    reconnectTimer = scheduleReconnect(() => {
      reconnectTimer = null;
      connect();
    }, delayMs);
    // Exponential backoff for the NEXT disconnect, capped so a persistently down relay is polled
    // at a bounded rate rather than growing without limit.
    reconnectDelayMs = Math.min(reconnectDelayMs * 2, MAX_RECONNECT_DELAY_MS);
  }

  function connect(): void {
    if (stopped) return;
    const ws = connectImpl(url);
    socket = ws;

    ws.addEventListener("open", () => {
      // A successful connection proves the relay is reachable again — reset backoff so the next
      // disconnect starts fast rather than inheriting a long-outage delay.
      reconnectDelayMs = MIN_RECONNECT_DELAY_MS;
    });
    ws.addEventListener("message", (ev) => {
      const requestId = parseRetractRequestId(ev.data);
      if (requestId !== null) {
        options.onRetract(requestId);
      }
    });
    ws.addEventListener("error", () => {
      // The following `close` event drives reconnect scheduling; nothing else to do here.
    });
    ws.addEventListener("close", () => {
      socket = null;
      if (!stopped) {
        scheduleNextConnect();
      }
    });
  }

  connect();

  return {
    stop(): void {
      if (stopped) return;
      stopped = true;
      if (reconnectTimer !== null) {
        cancelReconnect(reconnectTimer);
        reconnectTimer = null;
      }
      if (socket !== null) {
        try {
          socket.close(1000, "client stop");
        } catch {
          // already closing — ignore
        }
        socket = null;
      }
    },
  };
}
