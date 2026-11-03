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
 * Thrown by a transport when the push service reports that the token no longer exists (for Web
 * Push, HTTP 404 or 410). It is the only failure that removes a stored token: every other failure is
 * treated as transient, so a provider outage can never silently unregister a device.
 */
export class PushTokenGoneError extends Error {
  override readonly name = "PushTokenGoneError";
}

/** Outcome of one fan-out: how many wakeups were accepted, and which tokens should be pruned. */
export interface PushDispatchResult {
  readonly delivered: number;
  readonly goneTokens: readonly StoredPushToken[];
}

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

/**
 * Dispatch all registered tokens through their matching transport. Never throws: push is a wakeup
 * optimization, so a failed send is counted out rather than propagated to the submit path.
 */
export async function dispatchPushWakeups(
  tokens: readonly StoredPushToken[],
  options: {
    readonly accountId: string;
    readonly requestId: string;
    readonly expiresAt: number;
    readonly transports: PushTransportRegistry;
  },
): Promise<PushDispatchResult> {
  let delivered = 0;
  const goneTokens: StoredPushToken[] = [];
  for (const token of tokens) {
    const transport = options.transports[token.transport];
    if (!transport) continue;
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
      // A provider outage must not break the pending request path; devices can still receive the
      // ciphertext via WebSocket presence or polling. Only an explicit "token gone" prunes.
      if (error instanceof PushTokenGoneError) goneTokens.push(token);
    }
  }
  return { delivered, goneTokens };
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
