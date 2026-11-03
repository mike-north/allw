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

import { PushTokenGoneError, type Fetcher, type PushTransport, type PushWakeup } from "./push.js";

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
 * Push-service host suffixes matched as strict subdomains. Windows Push Notification Services
 * (Edge on Windows) issues per-region hosts such as `wns2-by3p.notify.windows.com`.
 */
const WEB_PUSH_HOST_SUFFIXES: readonly string[] = [".notify.windows.com"];

/** Maximum `TTL` sent to a push service: 28 days, the common push-service ceiling. */
const MAX_WEB_PUSH_TTL_SECONDS = 28 * 24 * 60 * 60;

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
 * credentials or an explicit port, or names a host outside the allowlist. This is the relay's SSRF
 * guard for the only outbound request whose target a client chooses.
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
  const host = url.hostname;
  if (WEB_PUSH_EXACT_HOSTS.has(host)) return url;
  for (const suffix of WEB_PUSH_HOST_SUFFIXES) {
    if (host.length > suffix.length && host.endsWith(suffix)) return url;
  }
  return null;
}

/**
 * The relay's VAPID identity: a P-256 keypair (both halves base64url, unpadded) and the RFC 8292
 * `sub` contact URI. The public key is not secret — browsers need it to subscribe.
 */
export interface VapidConfig {
  /** Uncompressed P-256 public point (65 bytes), base64url. Served by `GET /push/vapid-public-key`. */
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
 * Read the VAPID configuration from Worker bindings. Returns `null` — Web Push disabled — unless
 * every binding is present and syntactically valid. This is the single switch for both the
 * `webpush` transport and the public-key endpoint, so they cannot disagree about enablement.
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

/**
 * Web Push transport: one empty-body POST per subscription endpoint, authenticated with VAPID.
 *
 * Status handling follows RFC 8030 §§5–7: any 2xx (push services answer 201) is delivered; 404 or
 * 410 means the subscription no longer exists and surfaces as {@link PushTokenGoneError} so the
 * caller prunes the token; every other outcome is a transient failure that leaves the token alone.
 */
export class WebPushTransport implements PushTransport {
  readonly kind = "webpush" as const;

  private readonly vapid: VapidConfig;
  private readonly fetcher: Fetcher;
  private readonly now: () => number;
  private signingKey: Promise<CryptoKey> | undefined;

  constructor(options: {
    readonly vapid: VapidConfig;
    readonly fetcher?: Fetcher;
    /** Clock in epoch milliseconds; injectable so TTL and JWT `exp` are deterministic in tests. */
    readonly now?: () => number;
  }) {
    this.vapid = options.vapid;
    // Wrapped rather than stored bare so the runtime's `fetch` is never invoked as a method.
    this.fetcher = options.fetcher ?? ((input, init) => fetch(input, init));
    this.now = options.now ?? Date.now;
  }

  async sendWakeup(wakeup: PushWakeup): Promise<void> {
    // Re-validate at send time: rows can predate the allowlist (the earlier stub accepted any
    // string), and a stored value must never steer the relay at an arbitrary host.
    const endpoint = parseWebPushEndpoint(wakeup.token);
    if (!endpoint) throw new Error("Web Push endpoint is not on the push-service allowlist");

    const nowMs = this.now();
    const jwt = await this.signVapidJwt(endpoint.origin, nowMs);
    const response = await this.fetcher(endpoint.href, {
      method: "POST",
      headers: {
        Authorization: `vapid t=${jwt}, k=${this.vapid.publicKey}`,
        TTL: String(webPushTtlSeconds(wakeup.expiresAt, nowMs)),
        Urgency: "high",
      },
      // Payload-less wakeup: an empty body (sent as `Content-Length: 0`), never request data.
      body: "",
      // A redirect would let an allowlisted host bounce the relay to an arbitrary target.
      redirect: "manual",
    });
    if (response.ok) return;
    if (response.status === 404 || response.status === 410) {
      throw new PushTokenGoneError(
        `Web Push subscription is gone (HTTP ${String(response.status)})`,
      );
    }
    throw new Error(`Web Push wakeup failed with HTTP ${String(response.status)}`);
  }

  /** Sign an RFC 8292 VAPID JWT for one push-service origin (ES256, raw `r || s` signature). */
  private async signVapidJwt(audience: string, nowMs: number): Promise<string> {
    const header = base64UrlEncodeJson({ typ: "JWT", alg: "ES256" });
    const claims = base64UrlEncodeJson({
      aud: audience,
      exp: Math.floor(nowMs / 1000) + VAPID_JWT_LIFETIME_SECONDS,
      sub: this.vapid.subject,
    });
    const signingInput = `${header}.${claims}`;
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      await this.loadSigningKey(),
      new TextEncoder().encode(signingInput),
    );
    return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
  }

  private loadSigningKey(): Promise<CryptoKey> {
    this.signingKey ??= importVapidPrivateKey(this.vapid).catch((error: unknown) => {
      // Do not cache a failed import; the next send retries (and fails the same way if misconfigured).
      this.signingKey = undefined;
      throw error;
    });
    return this.signingKey;
  }
}

/**
 * `TTL` for a wakeup: the request's remaining lifetime in whole seconds (rounded up), clamped to
 * `[0, 28 days]`. A wakeup that outlives its request is useless; one that expires early drops a push.
 */
export function webPushTtlSeconds(expiresAtMs: number, nowMs: number): number {
  const remaining = Math.ceil((expiresAtMs - nowMs) / 1000);
  return Math.min(Math.max(remaining, 0), MAX_WEB_PUSH_TTL_SECONDS);
}

async function importVapidPrivateKey(vapid: VapidConfig): Promise<CryptoKey> {
  const pub = base64UrlDecode(vapid.publicKey);
  if (pub?.length !== P256_UNCOMPRESSED_POINT_LENGTH) {
    throw new Error("VAPID public key is not an uncompressed P-256 point");
  }
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: base64UrlEncode(pub.subarray(1, 33)),
    y: base64UrlEncode(pub.subarray(33, 65)),
    d: vapid.privateKey,
    ext: false,
  };
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
  ]);
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
function base64UrlDecode(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return null;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/**
 * Relay-level (not per-account) path serving the VAPID public key. It is matched before account
 * routing, so it never reaches an account's Durable Object.
 */
export const VAPID_PUBLIC_KEY_PATH = "/push/vapid-public-key";

/**
 * `GET /push/vapid-public-key` — unauthenticated. Browsers need the relay's VAPID public key as the
 * `applicationServerKey` to create a subscription this relay can push to; the key is public by
 * design. → 200 `{ vapid_public_key }`, 404 when Web Push is not configured, 405 for other methods.
 */
export function handleVapidPublicKey(request: Request, env: VapidEnv): Response {
  if (request.method !== "GET") {
    return Response.json(
      { error: "method not allowed" },
      { status: 405, headers: { Allow: "GET" } },
    );
  }
  const vapid = vapidConfigFromEnv(env);
  if (!vapid) return Response.json({ error: "web push is not configured" }, { status: 404 });
  return Response.json({ vapid_public_key: vapid.publicKey });
}
