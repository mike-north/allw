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

/** The relay's `GET /:acct/account-states` body: relay-verified documents plus their sequence. */
export interface AccountStatesResponse {
  /** Compact root-signed account-state JWS. The SDK still verifies each one in the core. */
  readonly account_states: readonly string[];
  /** The relay-reported highest sequence (`0` when none). Informational; never trusted. */
  readonly max_sequence: number;
}

/** The most account-state documents the SDK accepts from one fetch (the core caps selection at 64). */
const MAX_FETCHED_ACCOUNT_STATES = 64;

/**
 * Read a relay response body as JSON. A body that isn't JSON becomes a {@link RelayError} naming only
 * the call and the status: the parser's own message quotes the start of the body, and relay text
 * must not reach the agent through the hooks' deny reason. Other failures (a network error while
 * reading the body) are rethrown unchanged, so they stay transport failures.
 */
async function readJsonBody(resp: Response, call: string): Promise<unknown> {
  try {
    return (await resp.json()) as unknown;
  } catch (err) {
    if (err instanceof SyntaxError) {
      throw new RelayError(`relay ${call} returned a non-JSON body`, resp.status);
    }
    throw err;
  }
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

/**
 * The relay answered, but not with a usable success: a non-2xx reply (for example 413 when
 * `context_ciphertext` is over the 64 KiB ceiling, `docs/relay-api.md` §3), or a 2xx whose body is not
 * JSON or not the expected shape. Every relay call throws it for such a reply.
 *
 * Through `requestApproval`, it is a rejection only from the steps before waiting. A failed submit
 * rejects with it directly. A failed account-state fetch rejects with a `RecipientSelectionError`
 * (stage `"load"`) whose `cause` is this error. Once the request is submitted, a non-2xx or malformed
 * poll reply (for example 401 or 403) resolves to an `expired` verdict instead, and a failed retract
 * is ignored. Treat a rejection as deny, like every failure (fail-closed), and never retry it into an
 * approval.
 *
 * Narrow with `err instanceof RelayError`. The message names the call and status only: it never
 * quotes the relay's body, which is untrusted. A hung or unreachable relay is not a `RelayError`,
 * because no reply arrived: a direct relay call rejects with a timeout or the fetch's own network
 * error, and `requestApproval` resolves to an `expired` verdict.
 */
export class RelayError extends Error {
  constructor(
    message: string,
    /** The relay reply's HTTP status (the 2xx status itself when the body was malformed). */
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
 * (`DEFAULT_TIMEOUT_MS` = 5 min) so a hung connect/read on the pre-deadline `submit`
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
 * Hosts on which a plaintext `http:` relay is tolerated: a local-development relay
 * (`wrangler dev`) never leaves the machine. The IPv6 loopback `[::1]` is deliberately absent so
 * the rule is identical to the web approver's, where a CSP cannot express an IPv6 literal;
 * `127.0.0.1` is the loopback to use. Mirrors `packages/web-approver/src/relay-config.ts`.
 */
const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(["localhost", "127.0.0.1"]);

/**
 * Reject a relay URL that would carry bearer tokens and ciphertext without TLS, or that carries
 * userinfo, a query, or a fragment (issue #249, `docs/threat-model.md` §Relay and Transport).
 * Accepts `https:`, or `http:` on a loopback host; a path is allowed. Throws an actionable
 * `Error` for anything else — including an unparseable URL — so a misconfigured client fails at
 * construction, before any request is built.
 *
 * Userinfo makes a URL *look* like one host while pointing at another
 * (`https://relay.example.com@evil.example` is `evil.example`); a query or fragment would corrupt
 * the request paths {@link accountBase} appends. The empty forms (`https://host?`, `https://@host`)
 * are rejected too, on the raw text, for the same reason. Mirrors
 * `packages/web-approver/src/relay-config.ts` `checkRelayUrl`; both are pinned by the shared
 * vectors in `test/fixtures/relay-url-vectors.json`.
 */
export function assertRelayUrlTransport(relayUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(relayUrl);
  } catch {
    throw new Error(
      `allw: relayUrl '${relayUrl}' is not an absolute URL; expected e.g. https://relay.example.com`,
    );
  }
  const secure =
    parsed.protocol === "https:" ||
    (parsed.protocol === "http:" && LOOPBACK_HOSTNAMES.has(parsed.hostname));
  if (!secure) {
    throw new Error(
      `allw: relayUrl '${relayUrl}' must use https:// — plain http:// is allowed only for a local ` +
        "relay on localhost or 127.0.0.1 (use 127.0.0.1 rather than [::1])",
    );
  }
  const hasExtras =
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    relayUrl.includes("?") ||
    relayUrl.includes("#") ||
    /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*@/i.test(relayUrl.trim());
  if (hasExtras) {
    throw new Error(
      `allw: relayUrl '${relayUrl}' must not include a username, password, query (?) or ` +
        "fragment (#); expected e.g. https://relay.example.com",
    );
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
  /** Credentials owned by active local requests; completed calls must not accumulate here. */
  private readonly requestAuthTokens = new Map<string, string>();

  constructor(
    relayUrl: string,
    accountId: string,
    fetchImpl: FetchImpl,
    options: RelayClientOptions = {},
  ) {
    assertRelayUrlTransport(relayUrl);
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
   * Fetch the account's root-signed account state (`GET /:acct/account-states`). Unauthenticated:
   * the relay serves only documents it verified against the account's bound root, and the SDK
   * re-verifies every one in the core before it selects a recipient, so this is untrusted transport
   * of signed data (`docs/relay-api.md` §Account state).
   *
   * The body must be `{ account_states: string[], max_sequence: number }` with at most
   * {@link MAX_FETCHED_ACCOUNT_STATES} documents; anything else fails the whole call. Error messages
   * name only the call and status, never relay text.
   *
   * @throws {RelayError} on a non-2xx response or a malformed body.
   */
  async fetchAccountStates(): Promise<AccountStatesResponse> {
    const resp = await this.timedFetch(`${this.base}/account-states`, { method: "GET" });
    if (resp.status === 401) {
      // The endpoint is unauthenticated (account-state documents are public and root-verified), so
      // a relay that demands authorization for it predates that endpoint. Name the fix (a relay
      // redeploy), early and short: hook deny reasons keep only the first 256 characters. Still a
      // throw, so the request fails closed.
      throw new RelayError(
        "relay account-state fetch failed (HTTP 401): this relay is too old (it requires auth " +
          "for GET /account-states); redeploy it from current allw main, see docs/relay-deploy.md",
        resp.status,
      );
    }
    if (!resp.ok) {
      throw new RelayError(
        `relay account-state fetch failed (HTTP ${String(resp.status)})`,
        resp.status,
      );
    }
    const body = await readJsonBody(resp, "account-state fetch");
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      throw new RelayError("relay account-state fetch returned a malformed body", resp.status);
    }
    const { account_states: states, max_sequence: maxSequence } = body as Record<string, unknown>;
    if (
      !Array.isArray(states) ||
      states.length > MAX_FETCHED_ACCOUNT_STATES ||
      !states.every((doc) => typeof doc === "string")
    ) {
      throw new RelayError(
        `relay account-state fetch 'account_states' is not an array of at most ` +
          `${String(MAX_FETCHED_ACCOUNT_STATES)} strings`,
        resp.status,
      );
    }
    if (typeof maxSequence !== "number" || !Number.isSafeInteger(maxSequence) || maxSequence < 0) {
      throw new RelayError(
        "relay account-state fetch 'max_sequence' is not a non-negative safe integer",
        resp.status,
      );
    }
    const accountStates: readonly string[] = states;
    return { account_states: accountStates, max_sequence: maxSequence };
  }

  /**
   * Submit an `ApprovalRequest` envelope (`POST /:acct/requests`). The relay stores it opaquely and
   * fans the ciphertext out to online devices.
   *
   * The relay's error body is not included in the message, only the status: the relay is untrusted,
   * and the message can reach the agent through the hooks' deny reason.
   *
   * @throws {RelayError} on a non-2xx response (e.g. 400 malformed envelope, 409 duplicate id), or a
   *   success body that is not JSON or carries no auth token.
   */
  async submit(envelope: ApprovalRequestEnvelope): Promise<void> {
    const resp = await this.timedFetch(`${this.base}/requests`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(envelope),
    });
    if (!resp.ok) {
      throw new RelayError(`relay submit failed (HTTP ${String(resp.status)})`, resp.status);
    }
    const body = await readJsonBody(resp, "submit");
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
   * Release only this request's credential after its owning local lifecycle settles. Polling a
   * relay-reported verdict does not end that lifecycle until the SDK verifies it; cancellation
   * also needs the credential through its retract attempt (or the bounded local deadline).
   * Returned Verdict verification is local and does not use this transport credential.
   */
  releaseRequest(requestId: string): void {
    this.requestAuthTokens.delete(requestId);
  }

  /**
   * Poll a request's status once (`GET /:acct/requests/:id`).
   *
   * @returns the terminal outcome if the request is `resolved`/`expired`, or `null` while pending.
   * @throws {RelayError} on a non-2xx response (e.g. 401/403: a missing or wrong token, which is
   *   also how the relay answers an unknown request id).
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
    const body = await readJsonBody(resp, "poll");
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
   * @throws {RelayError} on a non-2xx response (e.g. 401/403: a missing or wrong token, which is
   *   also how the relay answers an unknown request id; 409 already resolved/expired).
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
