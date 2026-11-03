/**
 * Web Push transport (RFC 8030) with VAPID sender authentication (RFC 8292), for waking a paired
 * browser approver (the web approver's service worker) when a request is submitted.
 *
 * # Payload-less by design
 * The push request carries **no body at all** — not even the request id. A push payload is not
 * end-to-end encrypted to the user (the push service sees routing and timing), so the relay sends a
 * bare wakeup and the service worker fetches pending envelopes itself through
 * `GET /{acct}/devices/{device_id}/inbox`. Because there is no payload, RFC 8291 message encryption
 * is unnecessary and deliberately not implemented.
 *
 * # Why VAPID signing lives here and not in `allw-core`
 * The VAPID JWT (ES256 over P-256) is a **push-provider transport credential** — the same category as
 * the APNs bearer token. It authenticates the relay to Google/Mozilla/Apple/Microsoft push services;
 * it is not allw contract crypto and never touches a request, verdict, or audit record. The audited
 * Rust core owns contract crypto only, so this signing runs in the Worker through WebCrypto.
 *
 * # SSRF boundary
 * A Web Push token is the browser subscription's `endpoint` URL, and the relay POSTs to it. An
 * unconstrained value would let any paired device make the relay issue requests to arbitrary hosts,
 * so endpoints must be `https:` on an allowlist of known push-service hosts
 * ({@link parseWebPushEndpoint}). The same check runs at registration and again before every send,
 * and redirects are never followed.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8030 (Generic Event Delivery Using HTTP Push)
 * @see https://www.rfc-editor.org/rfc/rfc8292 (VAPID)
 */

import {
  UndeliverablePushTokenError,
  isPushServiceRejection,
  warnPushServiceRejection,
  type Fetcher,
  type PushTransport,
  type PushWakeup,
} from "./push.js";

/** Push-service hosts matched exactly (lowercase, as the WHATWG URL parser normalizes them). */
const WEB_PUSH_EXACT_HOSTS: ReadonlySet<string> = new Set([
  // Chrome / Chromium-based browsers (FCM-backed Web Push).
  "fcm.googleapis.com",
  // Firefox (Mozilla autopush).
  "updates.push.services.mozilla.com",
  // Safari on macOS / iOS / iPadOS.
  "web.push.apple.com",
]);

/**
 * Windows Push Notification Services (Edge on Windows) issues per-region hosts such as
 * `wns2-by3p.notify.windows.com`: exactly **one** label under `notify.windows.com`. Deeper names,
 * empty labels, and dotted (IP-like) prefixes are never real subscription hosts and are refused.
 */
const WNS_HOST_PATTERN = /^[a-z0-9-]+\.notify\.windows\.com$/;

/**
 * The RFC 8030 §5.4 `Topic` on every wakeup sent to a host in {@link WEB_PUSH_TOPIC_HOSTS}. It is
 * one fixed value for every account and subscription. A push service keeps at most one undelivered
 * message per topic per subscription, so an offline browser receives one queued wakeup instead of
 * one per request. Nothing is lost: a wakeup is payload-less, and one inbox fetch returns every
 * pending request. The value is 11 characters from the base64url alphabet, within the RFC's limit
 * of 32.
 */
export const WEB_PUSH_TOPIC = "allw-wakeup";

/**
 * Push-service hosts that get a `Topic` header. Only hosts whose own documentation says they
 * support it are listed. Sending `Topic` where it isn't supported can fail every wakeup, not merely
 * skip collapsing:
 *
 * - Mozilla autopush documents `Topic` (at most 32 characters of `[A-Za-z0-9_-]`). Listed.
 * - Apple (`web.push.apple.com`) has answered any `Topic` with `400 BadWebPushTopic` since about
 *   September 2026, by many independent reports. Not listed.
 * - FCM documents no `Topic` support for Web Push, and WNS documents only its own `X-WNS-*`
 *   headers. Neither is listed until verified.
 *
 * The per-host table, with sources, is in `docs/relay-api.md` §5.
 */
const WEB_PUSH_TOPIC_HOSTS: ReadonlySet<string> = new Set(["updates.push.services.mozilla.com"]);

/** The `Topic` header for a wakeup to `endpoint`, or `undefined` for a host that must not get one. */
export function webPushTopicFor(endpoint: URL): string | undefined {
  return WEB_PUSH_TOPIC_HOSTS.has(endpoint.hostname) ? WEB_PUSH_TOPIC : undefined;
}

/**
 * `TTL` values the relay sends, in seconds: 1 minute, 5 minutes, 1 hour, 1 day, and 28 days (the
 * common push-service ceiling). The TTL is visible to the push service, so it is rounded **up** to
 * one of these buckets rather than sent exactly; the provider learns a request's deadline only to
 * bucket granularity, never the integrator's precise timeout.
 */
const WEB_PUSH_TTL_BUCKETS_SECONDS: readonly number[] = [
  60,
  5 * 60,
  60 * 60,
  24 * 60 * 60,
  28 * 24 * 60 * 60,
];

/** Lifetime of each VAPID JWT. RFC 8292 §2 caps `exp` at 24 hours; one is signed per send. */
const VAPID_JWT_LIFETIME_SECONDS = 60 * 60;

/** Uncompressed P-256 public point: `0x04 || X (32 bytes) || Y (32 bytes)`. */
const P256_UNCOMPRESSED_POINT_LENGTH = 65;
/** P-256 private scalar length. */
const P256_PRIVATE_SCALAR_LENGTH = 32;

/**
 * Parse a Web Push subscription endpoint and admit it only if it targets a known push service.
 *
 * Returns the parsed URL, or `null` when the value is not a URL, is not `https:`, carries
 * credentials, an explicit port, or a fragment, or names a host outside the allowlist. This is the
 * relay's SSRF guard for the only outbound request whose target a client chooses.
 */
export function parseWebPushEndpoint(token: string): URL | null {
  let url: URL;
  try {
    url = new URL(token);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  // An explicit non-default port or embedded credentials never appear in a genuine subscription
  // endpoint; refusing them keeps the allowlist a statement about hosts on the standard port.
  if (url.port !== "" || url.username !== "" || url.password !== "") return null;
  // A fragment is never sent on the wire, so `…/X#a` and `…/X#b` would be two stored tokens for one
  // subscription. Genuine endpoints have none; `href` (not `hash`) also catches an empty `#`.
  if (url.href.includes("#")) return null;
  const host = url.hostname;
  if (WEB_PUSH_EXACT_HOSTS.has(host) || WNS_HOST_PATTERN.test(host)) return url;
  return null;
}

/**
 * The relay's VAPID identity: a P-256 keypair (both halves base64url, unpadded) and the RFC 8292
 * `sub` contact URI. The public key is not secret — browsers need it to subscribe.
 */
export interface VapidConfig {
  /** Uncompressed P-256 public point (65 bytes), base64url. Served at `/.well-known/allw/vapid-public-key`. */
  readonly publicKey: string;
  /** P-256 private scalar (32 bytes), base64url. A Worker secret; never logged or returned. */
  readonly privateKey: string;
  /** Operator contact, a `mailto:` or `https:` URI (RFC 8292 §2.1). */
  readonly subject: string;
}

/** The Worker bindings that configure Web Push. All three must be present and well-formed. */
export interface VapidEnv {
  readonly VAPID_PUBLIC_KEY?: string;
  readonly VAPID_PRIVATE_KEY?: string;
  readonly VAPID_SUBJECT?: string;
}

/**
 * Read the VAPID configuration from Worker bindings. Returns `null` (Web Push disabled) unless every
 * binding is present and syntactically valid. This is the syntactic half of the single enablement
 * switch shared by the `webpush` transport and the public-key endpoint; {@link loadVapidSigningKey}
 * is the cryptographic half (the pair must actually match).
 */
export function vapidConfigFromEnv(env: VapidEnv): VapidConfig | null {
  const publicKey = env.VAPID_PUBLIC_KEY?.trim();
  const privateKey = env.VAPID_PRIVATE_KEY?.trim();
  const subject = env.VAPID_SUBJECT?.trim();
  if (!publicKey || !privateKey || !subject) return null;

  const pub = base64UrlDecode(publicKey);
  if (pub?.length !== P256_UNCOMPRESSED_POINT_LENGTH || pub[0] !== 0x04) return null;
  if (base64UrlDecode(privateKey)?.length !== P256_PRIVATE_SCALAR_LENGTH) return null;
  if (!isVapidSubject(subject)) return null;
  return { publicKey, privateKey, subject };
}

function isVapidSubject(subject: string): boolean {
  if (subject.startsWith("mailto:")) return subject.length > "mailto:".length;
  try {
    return new URL(subject).protocol === "https:";
  } catch {
    return false;
  }
}

/** Default per-request timeout for a push-service POST. A timeout is transient: never a prune. */
const DEFAULT_WEB_PUSH_TIMEOUT_MS = 5_000;

/**
 * Validated VAPID signing keys, memoized per keypair for the isolate's lifetime. Bindings are fixed
 * for a deployment, so a pair that fails validation keeps failing until a redeploy, and there is
 * nothing to retry. Keyed by the configured key material, which is already in this isolate's memory.
 */
const vapidSigningKeys = new Map<string, Promise<CryptoKey | null>>();

/**
 * Import and **validate** the configured VAPID keypair, once per keypair. Resolves to the signing
 * key, or `null` when the pair is unusable: an off-curve public point, a private scalar that does
 * not belong to the public point, or a key the runtime refuses. Validation signs a probe message and
 * verifies it against the configured public key, so success means push services will accept the
 * relay's signatures under exactly the key that browsers subscribe with.
 *
 * Shared by {@link WebPushTransport} and the public-key endpoint, so a broken pair disables both:
 * browsers are never handed a key the relay cannot sign for.
 */
export function loadVapidSigningKey(vapid: VapidConfig): Promise<CryptoKey | null> {
  const cacheKey = `${vapid.publicKey}\0${vapid.privateKey}`;
  let loaded = vapidSigningKeys.get(cacheKey);
  if (!loaded) {
    loaded = validateVapidKeypair(vapid).catch(() => null);
    vapidSigningKeys.set(cacheKey, loaded);
  }
  return loaded;
}

async function validateVapidKeypair(vapid: VapidConfig): Promise<CryptoKey | null> {
  const pub = base64UrlDecode(vapid.publicKey);
  if (pub?.length !== P256_UNCOMPRESSED_POINT_LENGTH) return null;
  const algorithm = { name: "ECDSA", namedCurve: "P-256" };
  // Importing the raw point rejects an off-curve public key.
  const verifyKey = await crypto.subtle.importKey("raw", pub, algorithm, false, ["verify"]);
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: base64UrlEncode(pub.subarray(1, 33)),
      y: base64UrlEncode(pub.subarray(33, 65)),
      d: vapid.privateKey,
      ext: false,
    },
    algorithm,
    false,
    ["sign"],
  );
  // Prove the private scalar belongs to the public point, independent of whether the runtime's JWK
  // import checks consistency.
  const probe = new TextEncoder().encode("allw vapid keypair check");
  const ecdsa = { name: "ECDSA", hash: "SHA-256" };
  const signature = await crypto.subtle.sign(ecdsa, signingKey, probe);
  return (await crypto.subtle.verify(ecdsa, verifyKey, signature, probe)) ? signingKey : null;
}

/**
 * Web Push transport: one empty-body POST per subscription endpoint, authenticated with VAPID.
 *
 * Status handling follows RFC 8030 §§5–7: any 2xx (push services answer 201) is delivered; 404 or
 * 410 means the subscription no longer exists and surfaces as {@link UndeliverablePushTokenError}
 * so the caller prunes the token. Every other outcome is transient and leaves the token in place,
 * including a timeout, a 401/403 (a VAPID mismatch is a relay-side problem, not a dead device), and
 * a stored endpoint the allowlist refuses at send time.
 */
export class WebPushTransport implements PushTransport {
  readonly kind = "webpush" as const;

  private readonly vapid: VapidConfig;
  private readonly fetcher: Fetcher;
  private readonly now: () => number;
  private readonly timeoutMs: number;

  constructor(options: {
    readonly vapid: VapidConfig;
    readonly fetcher?: Fetcher;
    /** Clock in epoch milliseconds; injectable so TTL and JWT `exp` are deterministic in tests. */
    readonly now?: () => number;
    /** Per-request timeout for the push-service POST (default 5 s). */
    readonly timeoutMs?: number;
  }) {
    this.vapid = options.vapid;
    // Wrapped rather than stored bare so the runtime's `fetch` is never invoked as a method.
    this.fetcher = options.fetcher ?? ((input, init) => fetch(input, init));
    this.now = options.now ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_WEB_PUSH_TIMEOUT_MS;
  }

  async sendWakeup(wakeup: PushWakeup): Promise<void> {
    // Re-validate at send time: a stored value must never steer the relay at an arbitrary host.
    // Refusing is a relay-side decision (an older row, or a narrowed allowlist), not the push
    // service reporting the subscription gone, so it is transient: the row is kept, never pruned.
    const endpoint = parseWebPushEndpoint(wakeup.token);
    if (!endpoint) {
      console.warn(
        `webpush: refusing a stored endpoint outside the allowlist (device ${wakeup.deviceId}); token kept`,
      );
      throw new Error("stored Web Push endpoint is not on the allowlist");
    }
    const signingKey = await loadVapidSigningKey(this.vapid);
    if (!signingKey) throw new Error("VAPID keypair is invalid; Web Push is disabled");

    const nowMs = this.now();
    const jwt = await signVapidJwt(signingKey, endpoint.origin, this.vapid.subject, nowMs);
    const headers: Record<string, string> = {
      Authorization: `vapid t=${jwt}, k=${this.vapid.publicKey}`,
      TTL: String(webPushTtlSeconds(wakeup.expiresAt, nowMs)),
      Urgency: "high",
    };
    const topic = webPushTopicFor(endpoint);
    if (topic !== undefined) headers.Topic = topic;
    const response = await this.fetcher(endpoint.href, {
      method: "POST",
      headers,
      // Payload-less wakeup: an empty body (sent as `Content-Length: 0`), never request data.
      body: "",
      // A redirect would let an allowlisted host bounce the relay to an arbitrary target.
      redirect: "manual",
      // Bound each push: a slow or hung push service must not hold a fan-out slot indefinitely.
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (isPushServiceRejection(response.status)) {
      // A rejection is logged with its reason, read from a bounded prefix of the body (which is
      // then released). Every other body is never read.
      warnPushServiceRejection(
        "webpush",
        endpoint.host,
        response.status,
        await readPushServiceReason(response),
      );
    } else {
      // Release the connection rather than leaving an unconsumed body holding one of the Worker's
      // few outbound connection slots.
      await response.body?.cancel();
    }
    if (response.ok) return;
    if (response.status === 404 || response.status === 410) {
      throw new UndeliverablePushTokenError(
        `Web Push subscription is gone (HTTP ${String(response.status)})`,
      );
    }
    throw new Error(`Web Push wakeup failed with HTTP ${String(response.status)}`);
  }
}

/** At most this much of a rejection's body is read, looking for its `reason`. */
const PUSH_REASON_MAX_BYTES = 1024;
/** Reading a rejection's body gives up after this long; a stalled body never holds a send. */
const PUSH_REASON_READ_MS = 1_000;
/**
 * A logged reason must look like an identifier (Apple's are `BadWebPushTopic`, `BadJwtToken`, …),
 * so a push service cannot put arbitrary text, or anything echoed from the request, in the log.
 */
const PUSH_REASON_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;

/**
 * The `reason` of a push service's JSON error body (Apple: `{"reason":"BadWebPushTopic"}`), or
 * `undefined` when there is none. Reads at most {@link PUSH_REASON_MAX_BYTES} for at most
 * {@link PUSH_REASON_READ_MS}, then always cancels the body, so a large or stalled body can neither
 * hold the send nor leave the connection unreleased.
 */
async function readPushServiceReason(response: Response): Promise<string | undefined> {
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
    }, PUSH_REASON_READ_MS);
  });
  try {
    while (size < PUSH_REASON_MAX_BYTES) {
      const next = await Promise.race([reader.read(), deadline]);
      if (next === "timeout" || next.done) break;
      chunks.push(next.value);
      size += next.value.byteLength;
    }
  } catch {
    // A body that fails mid-read just has no reason to report.
  } finally {
    clearTimeout(timer);
    await reader.cancel().catch(() => undefined);
  }
  const bytes = new Uint8Array(Math.min(size, PUSH_REASON_MAX_BYTES));
  let offset = 0;
  for (const chunk of chunks) {
    if (offset >= bytes.length) break;
    const part = chunk.subarray(0, bytes.length - offset);
    bytes.set(part, offset);
    offset += part.length;
  }
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
    const reason = (parsed as Record<string, unknown>).reason;
    return typeof reason === "string" && PUSH_REASON_PATTERN.test(reason) ? reason : undefined;
  } catch {
    return undefined;
  }
}

/** Sign an RFC 8292 VAPID JWT for one push-service origin (ES256, raw `r || s` signature). */
async function signVapidJwt(
  signingKey: CryptoKey,
  audience: string,
  subject: string,
  nowMs: number,
): Promise<string> {
  const header = base64UrlEncodeJson({ typ: "JWT", alg: "ES256" });
  const claims = base64UrlEncodeJson({
    aud: audience,
    exp: Math.floor(nowMs / 1000) + VAPID_JWT_LIFETIME_SECONDS,
    sub: subject,
  });
  const signingInput = `${header}.${claims}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signingKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
}

/**
 * `TTL` for a wakeup: the request's remaining lifetime rounded **up** to the next bucket in
 * {@link WEB_PUSH_TTL_BUCKETS_SECONDS} (anything beyond the largest is capped at 28 days), or `0`
 * once the deadline has passed or is not a number. Rounding up never expires a wakeup before its request (which would
 * drop a push); at worst it outlives the request by less than one bucket step.
 */
export function webPushTtlSeconds(expiresAtMs: number, nowMs: number): number {
  const remaining = Math.ceil((expiresAtMs - nowMs) / 1000);
  // Fail toward a short TTL: a non-finite deadline (NaN) must never become the 28-day cap.
  // An infinite one is capped like any other far-future deadline.
  if (Number.isNaN(remaining) || remaining <= 0) return 0;
  const largest =
    WEB_PUSH_TTL_BUCKETS_SECONDS[WEB_PUSH_TTL_BUCKETS_SECONDS.length - 1] ?? remaining;
  return WEB_PUSH_TTL_BUCKETS_SECONDS.find((bucket) => remaining <= bucket) ?? largest;
}

function base64UrlEncodeJson(value: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/** Decode unpadded base64url; `null` for any character outside the base64url alphabet. */
function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return null;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** How long clients and caches may reuse the public key. It changes only on a deliberate rotation. */
const VAPID_PUBLIC_KEY_CACHE_CONTROL = "public, max-age=3600";

/**
 * `GET`/`HEAD /.well-known/allw/vapid-public-key` (routed by `well-known.ts`), unauthenticated.
 * Browsers need the relay's VAPID public key as the `applicationServerKey` to create a subscription
 * this relay can push to, and the key is public by design. → 200 `{ vapid_public_key }`; 404 when
 * Web Push is not configured **or the configured keypair fails validation**; 405 for other methods.
 */
export async function handleVapidPublicKey(request: Request, env: VapidEnv): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return Response.json(
      { error: "method not allowed" },
      { status: 405, headers: { Allow: "GET, HEAD" } },
    );
  }
  const vapid = vapidConfigFromEnv(env);
  if (!vapid || !(await loadVapidSigningKey(vapid))) {
    return Response.json({ error: "web push is not configured" }, { status: 404 });
  }
  const headers = { "Cache-Control": VAPID_PUBLIC_KEY_CACHE_CONTROL };
  if (request.method === "HEAD") {
    return new Response(null, { headers: { ...headers, "Content-Type": "application/json" } });
  }
  return Response.json({ vapid_public_key: vapid.publicKey }, { headers });
}
