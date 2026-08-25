/**
 * Thin client for the zero-knowledge relay's routing API (`docs/contract.md` §Transport →
 * Relay routing API). The SDK submits an opaque `ApprovalRequest` envelope, fetches the approver's
 * enrolled device pubkeys (JWE recipients), and awaits the signed verdict — preferring the live
 * WebSocket push and falling back to polling. The relay sees only ciphertext + routing metadata.
 *
 * @see ../../../docs/contract.md (§Transport → Relay routing API)
 * @see ../../relay/src/index.ts (the endpoints this calls)
 */

/** A `fetch`-compatible function (injectable for tests; defaults to the global `fetch`). */
export type FetchImpl = typeof fetch;

/** One enrolled approver device as returned by `GET /:acct/devices`. */
export interface DeviceRecord {
  readonly device_id: string;
  /** The device's public key, base64url-unpadded 32 bytes (X25519 for JWE recipients). */
  readonly pubkey: string;
  readonly label: string | null;
  readonly created_at: number;
}

/** The relay-visible `ApprovalRequest` envelope — exactly the contract's key set, nothing more. */
export interface ApprovalRequestEnvelope {
  readonly v: number;
  readonly id: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly approver: string;
  readonly context_ciphertext: string;
}

/** A relay error carrying the HTTP status and the relay's error body (when present). */
export class RelayError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "RelayError";
  }
}

/**
 * The terminal outcome of awaiting a verdict from the relay.
 *
 * - `verdict`: a device decided; `value` is the opaque signed `Verdict` JSON (unverified here —
 *   the SDK verifies it through the WASM core before exposing it).
 * - `expired`: the relay reported the request past its deadline (fail-closed terminal state).
 * - `retracted`: the integrator that submitted the request cancelled it before a verdict arrived
 *   (issue #195). NOT a verdict — no device ever decided, so this never carries a `value` and can
 *   never resolve `approved`.
 * - `timeout`: the SDK's own deadline elapsed with no terminal relay signal (fail-closed).
 */
export type VerdictOutcome =
  | { readonly kind: "verdict"; readonly value: unknown }
  | { readonly kind: "expired" }
  | { readonly kind: "retracted" }
  | { readonly kind: "timeout" };

/** A monotonic-ish clock injectable for deterministic tests (defaults to `Date.now`). */
export type NowImpl = () => number;

/**
 * Schedules `fn` after `ms` and returns nothing — the same seam {@link RelayClient} and the wait
 * loop share so a fake clock can drive every fail-closed timer deterministically (no wall-clock in
 * tests). Defaults to `setTimeout`.
 */
export type ScheduleImpl = (fn: () => void, ms: number) => void;

/**
 * Default per-request relay-fetch timeout (ms). Bounded **well under** the SDK's overall deadline
 * (`DEFAULT_TIMEOUT_MS` = 5 min) so a hung connect/read on the pre-deadline `fetchDevices`/`submit`
 * calls — which run *before* the await-verdict deadline timer is even armed — still rejects
 * deterministically and lets `requestApproval` fail closed (issue #52). A poll request is also
 * bounded, so a single hung poll never wedges the loop.
 *
 * @see ../../../docs/contract.md (§Invariants #6 — fail-closed)
 */
export const DEFAULT_FETCH_TIMEOUT_MS = 30_000;

const DEFAULT_SCHEDULE: ScheduleImpl = (fn, ms) => {
  const timer = setTimeout(fn, ms);
  // A still-pending fetch-timeout timer must not keep a node process alive after the fetch settles
  // (no-op in browsers/workers, where `unref` is absent).
  (timer as { unref?: () => void }).unref?.();
};

/**
 * A relay-fetch timeout that fired before its `fetch` settled — i.e. a hung connect/read (no HTTP
 * response was ever received). Callers use `instanceof RelayTimeoutError` to identify it as a
 * transport failure to fail closed on, distinct from a relay {@link RelayError} HTTP status.
 */
export class RelayTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayTimeoutError";
  }
}

/**
 * Build the per-account base URL: `<relayUrl>/<accountId>`. Trailing slashes on `relayUrl` are
 * normalized so a caller passing `https://relay.test/` or `https://relay.test` behaves identically.
 */
function accountBase(relayUrl: string, accountId: string): string {
  const trimmed = relayUrl.replace(/\/+$/, "");
  return `${trimmed}/${encodeURIComponent(accountId)}`;
}

/** Derive the `ws(s)://` origin for a WebSocket upgrade from an `http(s)://` relay URL. */
function toWsUrl(httpUrl: string): string {
  return httpUrl.replace(/^http/, "ws");
}

/** Tunables for {@link RelayClient}'s per-request fetch timeouts (injectable for tests). */
export interface RelayClientOptions {
  /** Per-request fetch timeout in ms. Defaults to {@link DEFAULT_FETCH_TIMEOUT_MS}. */
  readonly fetchTimeoutMs?: number;
  /**
   * Schedules the timeout timer; injectable so a fake clock can fire it deterministically (no
   * wall-clock in tests). Defaults to `setTimeout`.
   */
  readonly schedule?: ScheduleImpl;
}

/** A relay client bound to one account; constructed once and reused per request. */
export class RelayClient {
  private readonly base: string;
  private readonly fetchImpl: FetchImpl;
  private readonly fetchTimeoutMs: number;
  private readonly schedule: ScheduleImpl;
  private readonly requestAuthTokens = new Map<string, string>();

  constructor(
    relayUrl: string,
    accountId: string,
    fetchImpl: FetchImpl,
    options: RelayClientOptions = {},
  ) {
    this.base = accountBase(relayUrl, accountId);
    this.fetchImpl = fetchImpl;
    this.fetchTimeoutMs = options.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
    this.schedule = options.schedule ?? DEFAULT_SCHEDULE;
  }

  /**
   * Issue one `fetch` bounded by {@link fetchTimeoutMs}. A hung connect/read (a relay that accepts
   * the TCP connection but never responds — black-holed host, captive portal) would otherwise leave
   * the await pending **indefinitely**; this races the fetch against a {@link schedule}-driven
   * timeout that both aborts the underlying request (best-effort, via `AbortSignal`) and rejects
   * with a {@link RelayTimeoutError} so the caller fails closed (issue #52, contract §Invariants #6).
   *
   * The timeout is driven by the injected `schedule` (not the global `setTimeout`), so tests using a
   * fake clock fire it deterministically; the same seam the wait loop already uses.
   */
  private async timedFetch(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeoutMessage = `relay request to '${url}' timed out after ${String(
      this.fetchTimeoutMs,
    )}ms (fail-closed)`;

    // The timeout rejects with a RelayTimeoutError and aborts the underlying request (best-effort —
    // the race is what guarantees the caller unblocks even if the runtime/`fetchImpl` ignores the
    // signal). The timer is driven by the injected `schedule`, so a fake clock fires it
    // deterministically; the wrapping settles before any late fire matters.
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      this.schedule(() => {
        try {
          controller.abort();
        } catch {
          // some abort implementations can throw on double-abort — ignore
        }
        reject(new RelayTimeoutError(timeoutMessage));
      }, this.fetchTimeoutMs);
    });

    try {
      return await Promise.race([
        this.fetchImpl(url, { ...init, signal: controller.signal }),
        timeoutPromise,
      ]);
    } catch (err) {
      // A fetch that rejects because *we* aborted it on timeout (an `AbortError`) reads as a timeout,
      // not a bare network error — `controller.signal.aborted` is the genuine runtime signal that the
      // abort came from our timer. Surface the clearer RelayTimeoutError so the caller fails closed.
      if (controller.signal.aborted && !(err instanceof RelayTimeoutError)) {
        throw new RelayTimeoutError(timeoutMessage);
      }
      throw err;
    }
  }

  /**
   * Fetch the approver's enrolled devices (`GET /:acct/devices`) to use as JWE recipients.
   *
   * @throws {RelayError} on a non-2xx response or a malformed body.
   */
  async fetchDevices(): Promise<readonly DeviceRecord[]> {
    const resp = await this.timedFetch(`${this.base}/devices`, { method: "GET" });
    if (!resp.ok) {
      throw new RelayError(`relay device list failed (HTTP ${String(resp.status)})`, resp.status);
    }
    const body: unknown = await resp.json();
    if (typeof body !== "object" || body === null || !("devices" in body)) {
      throw new RelayError("relay device list returned a malformed body", resp.status);
    }
    const devices: unknown = body.devices;
    if (!Array.isArray(devices)) {
      throw new RelayError("relay device list 'devices' is not an array", resp.status);
    }
    return devices as readonly DeviceRecord[];
  }

  /**
   * Submit an `ApprovalRequest` envelope (`POST /:acct/requests`). The relay stores it opaquely and
   * fans the ciphertext out to online devices.
   *
   * @throws {RelayError} on a non-2xx response (e.g. 400 malformed envelope, 409 duplicate id).
   */
  async submit(envelope: ApprovalRequestEnvelope): Promise<void> {
    const resp = await this.timedFetch(`${this.base}/requests`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(envelope),
    });
    if (!resp.ok) {
      let detail = "";
      try {
        const body: unknown = await resp.json();
        if (typeof body === "object" && body !== null && "error" in body) {
          detail = `: ${String(body.error)}`;
        }
      } catch {
        // Non-JSON error body — the status alone is the signal.
      }
      throw new RelayError(
        `relay submit failed (HTTP ${String(resp.status)})${detail}`,
        resp.status,
      );
    }
    const body: unknown = await resp.json();
    if (
      typeof body !== "object" ||
      body === null ||
      typeof (body as { request_auth_token?: unknown }).request_auth_token !== "string"
    ) {
      throw new RelayError("relay submit returned a malformed auth body", resp.status);
    }
    this.requestAuthTokens.set(
      envelope.id,
      (body as { request_auth_token: string }).request_auth_token,
    );
  }

  /**
   * Poll a request's status once (`GET /:acct/requests/:id`).
   *
   * @returns the terminal outcome if the request is `resolved`/`expired`, or `null` while pending.
   * @throws {RelayError} on a non-2xx response (e.g. 404 unknown request).
   */
  async poll(requestId: string): Promise<VerdictOutcome | null> {
    const token = this.requestAuthTokens.get(requestId);
    const resp = await this.timedFetch(`${this.base}/requests/${encodeURIComponent(requestId)}`, {
      method: "GET",
      ...(token === undefined ? {} : { headers: { Authorization: `Bearer ${token}` } }),
    });
    if (!resp.ok) {
      throw new RelayError(`relay poll failed (HTTP ${String(resp.status)})`, resp.status);
    }
    const body: unknown = await resp.json();
    if (typeof body !== "object" || body === null || !("status" in body)) {
      throw new RelayError("relay poll returned a malformed body", resp.status);
    }
    const status: unknown = body.status;
    if (status === "resolved") {
      const verdict: unknown = "verdict" in body ? body.verdict : null;
      return { kind: "verdict", value: verdict ?? null };
    }
    if (status === "expired") {
      return { kind: "expired" };
    }
    if (status === "retracted") {
      return { kind: "retracted" };
    }
    // "pending" (or anything non-terminal) — keep waiting.
    return null;
  }

  /** The WebSocket URL for the live verdict-wait socket (`GET /:acct/requests/:id/wait`). */
  waitUrl(requestId: string): string {
    const path = `${toWsUrl(this.base)}/requests/${encodeURIComponent(requestId)}/wait`;
    const token = this.requestAuthTokens.get(requestId);
    return token === undefined ? path : `${path}?auth=${encodeURIComponent(token)}`;
  }

  /**
   * Cancel a request this client submitted (`POST /:acct/requests/:id/retract`, issue #195).
   * Bearer-authenticated with the `request_auth_token` returned by {@link submit} — the relay
   * scopes the retract to exactly the request that token was issued for, so an integrator can
   * never retract a request it did not submit. Best-effort by design: the caller (`requestApproval`'s
   * abort handling) does not treat a failed retract as fatal — the original deadline still governs,
   * so a failure here can only make cancellation a no-op, never fabricate an approval or discard an
   * already-recorded verdict (the relay itself refuses to retract a `resolved` request).
   *
   * @throws {RelayError} on a non-2xx response (e.g. 404 unknown request, 409 already resolved/expired).
   */
  async retract(requestId: string): Promise<void> {
    const token = this.requestAuthTokens.get(requestId);
    const resp = await this.timedFetch(
      `${this.base}/requests/${encodeURIComponent(requestId)}/retract`,
      {
        method: "POST",
        ...(token === undefined ? {} : { headers: { Authorization: `Bearer ${token}` } }),
      },
    );
    if (!resp.ok) {
      throw new RelayError(`relay retract failed (HTTP ${String(resp.status)})`, resp.status);
    }
  }
}
