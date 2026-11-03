/**
 * Push transport seam for request wakeups (#17).
 *
 * Routing code emits only `{ request_id }` plus device routing metadata; vendor-specific classes
 * adapt that minimal wakeup to APNs, FCM, or Web Push (`web-push.ts`). The relay must never send
 * plaintext approval context through push because those payloads are not end-to-end encrypted.
 */

export type PushTransportKind = "apns" | "fcm" | "webpush";

export interface StoredPushToken {
  readonly device_id: string;
  readonly transport: PushTransportKind;
  readonly token: string;
}

export interface PushWakeup {
  readonly accountId: string;
  readonly deviceId: string;
  readonly requestId: string;
  /**
   * How long the wakeup stays useful (epoch ms): the latest deadline among the account's pending
   * requests, not just this one's. A wakeup makes the device fetch every pending request, and with
   * an RFC 8030 `Topic` a later wakeup replaces an earlier queued one, along with its `TTL`.
   * Transports use it to bound how long a wakeup is held.
   */
  readonly expiresAt: number;
  readonly token: string;
}

/**
 * Thrown by a transport when a token is **permanently undeliverable**: the push service itself
 * reports the token gone. Per transport: Web Push 404 or 410; APNs 410; FCM 404 with the
 * `UNREGISTERED` error code. It is the only failure that removes a stored token. Every other failure, including timeouts, auth errors, and a stored token the relay
 * refuses to send to (e.g. a Web Push endpoint outside the current allowlist), is treated as
 * transient, so a provider outage or relay misconfiguration can never silently unregister a device.
 */
export class UndeliverablePushTokenError extends Error {
  override readonly name = "UndeliverablePushTokenError";
}

/**
 * Whether a push-service status is a 4xx. A transport logs every 4xx it does **not** prune as a
 * **rejection worth an operator's attention** ({@link warnPushServiceRejection}). The token is kept
 * as transient, but such a 4xx usually means the relay sent something the push service refuses for
 * *every* device: a bad header such as Apple's `400 BadWebPushTopic`, a VAPID or credential
 * mismatch, a wrong APNs environment or FCM project, a bad payload. That is invisible unless it is
 * logged (#326). A 4xx that prunes (see {@link UndeliverablePushTokenError}) is not logged; 2xx,
 * 5xx, redirects and timeouts are not rejections in this sense.
 */
export function isClientErrorStatus(status: number): boolean {
  return status >= 400 && status < 500;
}

/**
 * The host of a push-service URL, the only part of it the relay logs. For Web Push the path is the
 * subscription itself (a bearer capability); for APNs it carries the device token.
 */
export function pushServiceHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "(invalid endpoint)";
  }
}

/**
 * Log one push-service rejection (a 4xx that did not prune; see {@link isClientErrorStatus}) for
 * `wrangler tail`. Only the
 * transport, the push-service host, the status and an optional short `reason` are logged: never
 * the token, the endpoint path, credentials (VAPID JWT, bearer) or request ids.
 */
export function warnPushServiceRejection(
  transport: PushTransportKind,
  host: string,
  status: number,
  reason?: string,
): void {
  const detail = reason === undefined ? "" : ` (reason ${reason})`;
  console.warn(
    `push: ${transport} push service ${host} rejected a wakeup with HTTP ${String(status)}${detail}; token kept`,
  );
}

/** Reading a push service's error body gives up after this long; a stalled body never holds a send. */
const PUSH_BODY_READ_MS = 1_000;

/**
 * Release a response body without waiting for it. Cancelling is how the relay frees the outbound
 * connection, but a body whose `cancel()` never settles must not hold the send, so the cancel is
 * fired and its outcome ignored.
 */
export function releaseBody(body: ReadableStream | null): void {
  void body?.cancel().catch(() => undefined);
}

/**
 * A push service's JSON error body, parsed from at most `maxBytes` of it, or `undefined` when there
 * is no body or the prefix is not valid JSON. Reads for at most {@link PUSH_BODY_READ_MS}, then
 * always cancels the body without waiting for the cancel, so a large or stalled body can neither hold the send nor leave the
 * connection unreleased. A body cut off at the limit fails to parse, so callers must treat
 * `undefined` as "no information", never as a positive signal.
 */
export async function readBoundedJsonBody(response: Response, maxBytes: number): Promise<unknown> {
  const body = response.body;
  if (!body) return undefined;
  // Response bodies are byte streams; the Workers types leave the chunk type open.
  const reader = (body as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const deadline = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => {
      resolve("timeout");
    }, PUSH_BODY_READ_MS);
  });
  try {
    while (size < maxBytes) {
      const next = await Promise.race([reader.read(), deadline]);
      if (next === "timeout" || next.done) break;
      chunks.push(next.value);
      size += next.value.byteLength;
    }
  } catch {
    // A body that fails mid-read just carries no information.
  } finally {
    clearTimeout(timer);
    void reader.cancel().catch(() => undefined);
  }
  const bytes = new Uint8Array(Math.min(size, maxBytes));
  let offset = 0;
  for (const chunk of chunks) {
    if (offset >= bytes.length) break;
    const part = chunk.subarray(0, bytes.length - offset);
    bytes.set(part, offset);
    offset += part.length;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } catch {
    return undefined;
  }
}

/** Outcome of one fan-out: which tokens' wakeups the push services accepted, and which to prune. */
export interface PushDispatchResult {
  /** Tokens whose wakeup the push service accepted (a 2xx). */
  readonly deliveredTokens: readonly StoredPushToken[];
  readonly undeliverableTokens: readonly StoredPushToken[];
}

// Registration budgets. Every stored token costs an outbound request on every submit, so registration
// is bounded even for the root holder, the only party able to pair devices (root-signed
// pairing/start). Over-budget input is rejected, never truncated.

/** Most `push_tokens` entries one registration may carry. */
export const MAX_PUSH_TOKENS_PER_REGISTRATION = 4;
/** Most distinct tokens one registration may carry for a single transport. */
export const MAX_PUSH_TOKENS_PER_TRANSPORT = 2;
/** Most `device_push_token` rows one account may hold across all its devices. */
export const MAX_PUSH_TOKENS_PER_ACCOUNT = 32;

/**
 * Minimum spacing between Web Push wakeups to one subscription. Submitting a request needs no caller
 * auth, so without this every submit would fan out real, VAPID-signed pushes: notification spam on
 * the user's browser (service workers must show a notification per push) and, because one VAPID key
 * serves every account, push-service throttling of the whole relay.
 *
 * A Web Push wakeup is payload-less ("check your inbox"), but it covers only requests stored
 * before the service worker's inbox fetch. A submit skipped by coalescing may land after that
 * fetch, so the relay sends one **trailing** wakeup when the window ends (see `AccountRelay`'s
 * `webpush_trailing_wakeup`). Every request then gets a wakeup sent after it was stored, still at
 * most one push per subscription per window. The relay keeps last claims in SQLite, so the bound
 * holds across Durable Object eviction (#319).
 */
export const WEB_PUSH_COALESCE_MS = 30_000;

/**
 * How long a due trailing wakeup waits before trying again when its subscription is still blocked
 * by a wakeup in flight. A fan-out can outlast the coalescing window: each send has a 5 s timeout,
 * and at most 4 run at once.
 */
export const WEB_PUSH_TRAILING_RETRY_MS = 1_000;

/** Most wakeups in flight at once; Workers allow about six open outbound connections. */
const DEFAULT_PUSH_CONCURRENCY = 4;

export interface PushTransport {
  readonly kind: PushTransportKind;
  sendWakeup(wakeup: PushWakeup): Promise<void>;
}

/**
 * The transports a relay can actually deliver through. A kind is present only when its credentials
 * are configured; tokens of an absent kind stay stored but are never scheduled or counted.
 */
export type PushTransportRegistry = Partial<Record<PushTransportKind, PushTransport>>;

export type Fetcher = typeof fetch;

export interface PushWakeupPayload {
  readonly request_id: string;
}

/** Build the logical push wakeup payload: request id only, no context or ciphertext envelope. */
export function buildPushWakeupPayload(requestId: string): PushWakeupPayload {
  return { request_id: requestId };
}

export function isPushTransportKind(value: string): value is PushTransportKind {
  return value === "apns" || value === "fcm" || value === "webpush";
}

/** A push token as a device registers it: routing metadata only, never request content. */
export interface PushTokenEntry {
  readonly transport: PushTransportKind;
  readonly token: string;
}

/**
 * The row changes that turn a device's current push-token set into `desired`: rows to delete and
 * entries to insert. Tokens present in both are left untouched (keeping their `created_at`), so
 * replacing a set with itself changes nothing.
 */
export function diffPushTokenSet(
  current: readonly PushTokenEntry[],
  desired: readonly PushTokenEntry[],
): { readonly remove: PushTokenEntry[]; readonly add: PushTokenEntry[] } {
  const key = (entry: PushTokenEntry): string => `${entry.transport}\0${entry.token}`;
  const currentKeys = new Set(current.map(key));
  const desiredKeys = new Set(desired.map(key));
  return {
    remove: current.filter((entry) => !desiredKeys.has(key(entry))),
    add: desired.filter((entry) => !currentKeys.has(key(entry))),
  };
}

/** The tokens a fan-out will actually attempt: those whose transport is registered. */
export function schedulablePushTokens(
  tokens: readonly StoredPushToken[],
  transports: PushTransportRegistry,
): StoredPushToken[] {
  return tokens.filter((token) => transports[token.transport] !== undefined);
}

/**
 * Dispatch every schedulable token through its transport, at most `concurrency` at a time. Never
 * throws: push is a wakeup optimization, so a failed send is counted out rather than propagated.
 * Devices still receive the ciphertext via WebSocket presence or polling.
 */
export async function dispatchPushWakeups(
  tokens: readonly StoredPushToken[],
  options: {
    readonly accountId: string;
    readonly requestId: string;
    readonly expiresAt: number;
    readonly transports: PushTransportRegistry;
    readonly concurrency?: number;
  },
): Promise<PushDispatchResult> {
  const queue = schedulablePushTokens(tokens, options.transports);
  const deliveredTokens: StoredPushToken[] = [];
  const undeliverableTokens: StoredPushToken[] = [];

  const sendOne = async (token: StoredPushToken): Promise<void> => {
    const transport = options.transports[token.transport];
    if (!transport) return;
    try {
      await transport.sendWakeup({
        accountId: options.accountId,
        deviceId: token.device_id,
        requestId: options.requestId,
        expiresAt: options.expiresAt,
        token: token.token,
      });
      deliveredTokens.push(token);
    } catch (error) {
      // Only an explicit "permanently undeliverable" prunes; everything else is transient.
      if (error instanceof UndeliverablePushTokenError) undeliverableTokens.push(token);
    }
  };

  // A small worker pool: each worker drains the shared queue, so at most `concurrency` sends are
  // in flight and one slow push service delays only its own slot.
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < queue.length) {
      const token = queue[next++];
      if (token) await sendOne(token);
    }
  };
  const width = Math.max(
    1,
    Math.min(options.concurrency ?? DEFAULT_PUSH_CONCURRENCY, queue.length),
  );
  await Promise.allSettled(Array.from({ length: width }, worker));
  return { deliveredTokens, undeliverableTokens };
}

/**
 * APNs token-auth transport. Credentials are supplied by Worker environment bindings.
 *
 * Only **410** prunes: APNs's answer for a device token that is no longer active for the topic
 * (the app was uninstalled, or the token rotated). `400 BadDeviceToken` deliberately does **not**
 * prune. APNs also returns it for a token sent to the wrong APNs environment (a sandbox token to
 * production, or the reverse), so a relay configured with the wrong `APNS_ENDPOINT` would otherwise
 * unregister every device. Like every other 4xx it is logged and the token kept.
 *
 * @see https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
 */
export class ApnsPushTransport implements PushTransport {
  readonly kind = "apns" as const;

  private readonly endpoint: string;
  private readonly topic: string;
  private readonly bearerToken: string;
  private readonly fetcher: Fetcher;

  constructor(options: {
    readonly endpoint: string;
    readonly topic: string;
    readonly bearerToken: string;
    readonly fetcher?: Fetcher;
  }) {
    this.endpoint = options.endpoint.replace(/\/+$/, "");
    this.topic = options.topic;
    this.bearerToken = options.bearerToken;
    this.fetcher = options.fetcher ?? fetch;
  }

  async sendWakeup(wakeup: PushWakeup): Promise<void> {
    const payload = buildPushWakeupPayload(wakeup.requestId);
    const response = await this.fetcher(
      `${this.endpoint}/3/device/${encodeURIComponent(wakeup.token)}`,
      {
        method: "POST",
        headers: {
          Authorization: `bearer ${this.bearerToken}`,
          "apns-push-type": "background",
          "apns-topic": this.topic,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          aps: { "content-available": 1 },
          ...payload,
        }),
      },
    );
    // The relay never reads APNs bodies (the status alone decides); release the connection.
    releaseBody(response.body);
    if (response.ok) return;
    if (response.status === 410) {
      throw new UndeliverablePushTokenError("APNs device token is no longer active (HTTP 410)");
    }
    if (isClientErrorStatus(response.status)) {
      warnPushServiceRejection("apns", pushServiceHost(this.endpoint), response.status);
    }
    throw new Error(`APNs wakeup failed with HTTP ${String(response.status)}`);
  }
}

/** At most this much of an FCM 404's body is read, looking for the `UNREGISTERED` error code. */
const FCM_ERROR_MAX_BYTES = 4096;

/**
 * Whether an FCM HTTP v1 error body names the `UNREGISTERED` error code
 * (`error.details[].errorCode`), FCM's answer for a registration token that is no longer valid.
 */
function isFcmUnregistered(body: unknown): boolean {
  if (typeof body !== "object" || body === null) return false;
  const error = (body as Record<string, unknown>).error;
  if (typeof error !== "object" || error === null) return false;
  const details = (error as Record<string, unknown>).details;
  return (
    Array.isArray(details) &&
    details.some(
      (detail: unknown) =>
        typeof detail === "object" &&
        detail !== null &&
        (detail as Record<string, unknown>).errorCode === "UNREGISTERED",
    )
  );
}

/**
 * FCM HTTP v1 transport. Credentials are supplied by Worker environment bindings.
 *
 * Only a **404 whose body carries the `UNREGISTERED` error code** prunes. A bare 404, or one with
 * another code, more likely means a wrong endpoint or project (a relay misconfiguration), so it is
 * logged like any other 4xx and the token kept. So is a body that cannot be read or parsed.
 *
 * @see https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode
 */
export class FcmPushTransport implements PushTransport {
  readonly kind = "fcm" as const;

  private readonly endpoint: string;
  private readonly bearerToken: string;
  private readonly fetcher: Fetcher;

  constructor(options: {
    readonly endpoint: string;
    readonly bearerToken: string;
    readonly fetcher?: Fetcher;
  }) {
    this.endpoint = options.endpoint;
    this.bearerToken = options.bearerToken;
    this.fetcher = options.fetcher ?? fetch;
  }

  async sendWakeup(wakeup: PushWakeup): Promise<void> {
    const response = await this.fetcher(this.endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.bearerToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message: {
          token: wakeup.token,
          data: buildPushWakeupPayload(wakeup.requestId),
        },
      }),
    });
    if (response.status === 404) {
      // Only this answer's body is read; it is bounded and always released.
      if (isFcmUnregistered(await readBoundedJsonBody(response, FCM_ERROR_MAX_BYTES))) {
        throw new UndeliverablePushTokenError("FCM registration token is unregistered (HTTP 404)");
      }
    } else {
      releaseBody(response.body);
    }
    if (response.ok) return;
    if (isClientErrorStatus(response.status)) {
      warnPushServiceRejection("fcm", pushServiceHost(this.endpoint), response.status);
    }
    throw new Error(`FCM wakeup failed with HTTP ${String(response.status)}`);
  }
}

/** The coalescing key of one Web Push subscription: its device plus endpoint. */
export function webPushCoalesceKey(deviceId: string, token: string): string {
  return `${deviceId}\0${token}`;
}

/**
 * The device id and endpoint a {@link webPushCoalesceKey} was built from. Neither contains a NUL:
 * device ids are relay-generated, and an endpoint is a validated URL. Throws on a key with no
 * separator: every key is built by {@link webPushCoalesceKey}, so one without it is a bug, and
 * guessing would read or update the wrong subscription's claim.
 */
export function parseWebPushCoalesceKey(key: string): { deviceId: string; token: string } {
  const split = key.indexOf("\0");
  if (split < 0) throw new Error("not a Web Push coalescing key");
  return { deviceId: key.slice(0, split), token: key.slice(split + 1) };
}

/**
 * Where a {@link WakeupCoalescer} remembers each key's most recent claim.
 *
 * The coalescing bound is only as durable as this store. An in-memory store forgets every claim
 * when its Durable Object is evicted, after which one more wakeup could go out inside the window.
 * The relay therefore keeps claims in SQLite (#319).
 */
export interface WakeupClaimStore {
  /** Epoch ms of `key`'s most recent claim, or `undefined` if none is remembered. */
  lastClaimedAt(key: string): number | undefined;
  /** Remember a claim of `key` at `atMs`. */
  recordClaim(key: string, atMs: number): void;
}

/**
 * A {@link WakeupClaimStore} in memory, forgetting claims once they can no longer coalesce. Used
 * where durability does not matter: unit tests, and any coalescer outside a Durable Object.
 */
export class InMemoryWakeupClaimStore implements WakeupClaimStore {
  private readonly windowMs: number;
  private readonly claims = new Map<string, number>();

  constructor(windowMs: number) {
    this.windowMs = windowMs;
  }

  lastClaimedAt(key: string): number | undefined {
    return this.claims.get(key);
  }

  recordClaim(key: string, atMs: number): void {
    for (const [other, at] of this.claims) {
      if (atMs - at > this.windowMs) this.claims.delete(other);
    }
    this.claims.set(key, atMs);
  }
}

/**
 * Per-subscription wakeup coalescing for one account's Durable Object.
 *
 * A key (e.g. `device_id` + token) may be claimed only when it has no wakeup in flight **and** its
 * last claim is more than `windowMs` old; a claim exactly `windowMs` after the previous one is still
 * coalesced. The window runs from when a wakeup is dispatched, whatever its outcome, so it bounds
 * outbound volume per subscription regardless of how fast submits arrive or how the push service
 * answers.
 *
 * Last claims live in a {@link WakeupClaimStore}, so the bound is as durable as that store. In-flight
 * claims are kept in memory: a running fan-out keeps its Durable Object alive (`waitUntil`), so they
 * cannot be lost mid-flight. Every method is synchronous, and the Durable Object runs one event at
 * a time, so a check-and-claim cannot interleave with another submit (no TOCTOU).
 */
export class WakeupCoalescer {
  private readonly windowMs: number;
  private readonly claims: WakeupClaimStore;
  /** Keys whose claimed wakeup has not finished yet. */
  private readonly inFlight = new Set<string>();

  constructor(windowMs: number, claims: WakeupClaimStore = new InMemoryWakeupClaimStore(windowMs)) {
    this.windowMs = windowMs;
    this.claims = claims;
  }

  /** Claim a wakeup for `key` at `nowMs`: `true` (and recorded as in flight) or `false` if coalesced. */
  tryClaim(key: string, nowMs: number): boolean {
    if (this.inFlight.has(key)) return false;
    const stored = this.claims.lastClaimedAt(key);
    if (stored !== undefined && stored > nowMs) {
      // A claim from the future counts as one made now (see lastClaimAsOf). Store it as now, so
      // the window ends one window from here rather than one window after each later look.
      this.claims.recordClaim(key, nowMs);
      return false;
    }
    if (stored !== undefined && nowMs - stored <= this.windowMs) return false;
    this.claims.recordClaim(key, nowMs);
    this.inFlight.add(key);
    return true;
  }

  /**
   * The earliest epoch ms at which {@link tryClaim} for `key` could next succeed: just past the
   * window of its last claim, or `nowMs` if it has none. While a wakeup is in flight the answer
   * also depends on when it finishes, which is unknown here, so callers treat the result as a lower
   * bound.
   */
  nextClaimableAt(key: string, nowMs: number): number {
    const last = this.lastClaimAsOf(key, nowMs);
    return last === undefined ? nowMs : Math.max(nowMs, last + this.windowMs + 1);
  }

  /**
   * `key`'s last claim as seen at `nowMs`. A stored claim later than `nowMs` counts as `nowMs`. Such
   * a claim can only come from a clock anomaly on whichever host wrote it. Because claims persist,
   * it would otherwise silence the subscription, leading and trailing wakeups alike, until that
   * future time. {@link tryClaim} also stores the clamped value, so the worst case is one normal
   * window.
   */
  private lastClaimAsOf(key: string, nowMs: number): number | undefined {
    const last = this.claims.lastClaimedAt(key);
    return last === undefined ? undefined : Math.min(last, nowMs);
  }

  /** Mark a claimed wakeup finished. The window from its claim still applies. */
  release(key: string): void {
    this.inFlight.delete(key);
  }
}
