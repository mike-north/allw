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
 * - `timeout`: the SDK's own deadline elapsed with no terminal relay signal (fail-closed).
 */
export type VerdictOutcome =
  | { readonly kind: "verdict"; readonly value: unknown }
  | { readonly kind: "expired" }
  | { readonly kind: "timeout" };

/** A monotonic-ish clock injectable for deterministic tests (defaults to `Date.now`). */
export type NowImpl = () => number;

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

/** A relay client bound to one account; constructed once and reused per request. */
export class RelayClient {
  private readonly base: string;
  private readonly fetchImpl: FetchImpl;

  constructor(relayUrl: string, accountId: string, fetchImpl: FetchImpl) {
    this.base = accountBase(relayUrl, accountId);
    this.fetchImpl = fetchImpl;
  }

  /**
   * Fetch the approver's enrolled devices (`GET /:acct/devices`) to use as JWE recipients.
   *
   * @throws {RelayError} on a non-2xx response or a malformed body.
   */
  async fetchDevices(): Promise<readonly DeviceRecord[]> {
    const resp = await this.fetchImpl(`${this.base}/devices`, { method: "GET" });
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
    const resp = await this.fetchImpl(`${this.base}/requests`, {
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
  }

  /**
   * Poll a request's status once (`GET /:acct/requests/:id`).
   *
   * @returns the terminal outcome if the request is `resolved`/`expired`, or `null` while pending.
   * @throws {RelayError} on a non-2xx response (e.g. 404 unknown request).
   */
  async poll(requestId: string): Promise<VerdictOutcome | null> {
    const resp = await this.fetchImpl(`${this.base}/requests/${encodeURIComponent(requestId)}`, {
      method: "GET",
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
    // "pending" (or anything non-terminal) — keep waiting.
    return null;
  }

  /** The WebSocket URL for the live verdict-wait socket (`GET /:acct/requests/:id/wait`). */
  waitUrl(requestId: string): string {
    return `${toWsUrl(this.base)}/requests/${encodeURIComponent(requestId)}/wait`;
  }
}
