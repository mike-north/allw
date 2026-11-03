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
  /** The request's deadline (epoch ms). Transports use it to bound how long a wakeup is held. */
  readonly expiresAt: number;
  readonly token: string;
}

/**
 * Thrown by a transport when a token is **permanently undeliverable**: the push service reports
 * the subscription gone (for Web Push, HTTP 404 or 410), or the stored token can never be a valid
 * target for its transport (e.g. a Web Push endpoint outside the push-service allowlist). It is the
 * only failure that removes a stored token. Every other failure, including timeouts and auth
 * errors, is treated as transient, so a provider outage or relay misconfiguration can never
 * silently unregister a device.
 */
export class UndeliverablePushTokenError extends Error {
  override readonly name = "UndeliverablePushTokenError";
}

/** Outcome of one fan-out: how many wakeups were accepted, and which tokens should be pruned. */
export interface PushDispatchResult {
  readonly delivered: number;
  readonly undeliverableTokens: readonly StoredPushToken[];
}

// Registration budgets. Pairing is unauthenticated, and every stored token costs an outbound request
// on every submit, so registration is bounded. Over-budget input is rejected, never truncated.

/** Most `push_tokens` entries one registration may carry. */
export const MAX_PUSH_TOKENS_PER_REGISTRATION = 4;
/** Most distinct tokens one registration may carry for a single transport. */
export const MAX_PUSH_TOKENS_PER_TRANSPORT = 2;
/** Most `device_push_token` rows one account may hold across all its devices. */
export const MAX_PUSH_TOKENS_PER_ACCOUNT = 32;

/** Most wakeups in flight at once; Workers allow about six open outbound connections. */
const DEFAULT_PUSH_CONCURRENCY = 4;

export interface PushTransport {
  readonly kind: PushTransportKind;
  sendWakeup(wakeup: PushWakeup): Promise<void>;
}

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
  let delivered = 0;
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
      delivered++;
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
  return { delivered, undeliverableTokens };
}

/** APNs token-auth transport. Credentials are supplied by Worker environment bindings. */
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
    if (!response.ok) {
      throw new Error(`APNs wakeup failed with HTTP ${String(response.status)}`);
    }
  }
}

/** FCM HTTP v1 transport. Credentials are supplied by Worker environment bindings. */
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
    if (!response.ok) {
      throw new Error(`FCM wakeup failed with HTTP ${String(response.status)}`);
    }
  }
}

/** Test/local fallback: keeps the relay operational via polling when credentials are not configured. */
export class NoopPushTransport implements PushTransport {
  readonly kind: PushTransportKind;

  constructor(kind: PushTransportKind) {
    this.kind = kind;
  }

  async sendWakeup(_wakeup: PushWakeup): Promise<void> {
    return Promise.resolve();
  }
}
