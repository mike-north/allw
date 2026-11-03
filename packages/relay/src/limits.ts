/**
 * Abuse limits for the relay's unauthenticated routes (#248): body-size capping, the request
 * horizon's Worker-var parsing, and the Cloudflare rate-limiting wrapper.
 *
 * These are routing/availability controls, not authorization: a request that passes them is still
 * only ever ciphertext routed to the account's devices. Every limit fails closed — an over-budget
 * input, an unreadable body, a missing limiter binding, or a limiter that throws is refused.
 *
 * @see ../../../docs/relay-api.md §3 Integrator endpoints (limits and status codes)
 * @see ../../../docs/relay-deploy.md (rate-limit bindings and the TTL var)
 */

import { DEFAULT_MAX_REQUEST_TTL_MS } from "./constants.js";
import { accountSubPathSegments, resolveAccountRoute, type AccountRouteName } from "./routes.js";

/** Outcome of reading a body under a byte cap. */
export type CappedBody =
  | { readonly kind: "ok"; readonly text: string }
  | { readonly kind: "too_large" }
  | { readonly kind: "unreadable" };

/**
 * Read `request`'s body as UTF-8 text, refusing it once it exceeds `maxBytes`.
 *
 * A declared `Content-Length` above the cap is refused before any byte is read. Because the header
 * can be absent (chunked) or wrong, the stream is also counted as it is read and abandoned as soon
 * as the running total passes the cap — the body is never buffered beyond `maxBytes` + one chunk.
 */
export async function readBodyCapped(request: Request, maxBytes: number): Promise<CappedBody> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null) {
    const digits = declared.trim();
    if (!/^\d+$/.test(digits)) {
      // Release the unread body rather than leaving the sender's stream dangling.
      await request.body?.cancel().catch(() => undefined);
      return { kind: "unreadable" };
    }
    // A digit-only length beyond the safe-integer range is still a declared size, and over any cap.
    const length = Number(digits);
    if (!Number.isSafeInteger(length) || length > maxBytes) {
      await request.body?.cancel().catch(() => undefined);
      return { kind: "too_large" };
    }
  }
  if (request.body === null) return { kind: "ok", text: "" };

  const stream = request.body as ReadableStream<Uint8Array>;
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const result: ReadableStreamReadResult<Uint8Array> = await reader.read();
      if (result.done) break;
      const value = result.value;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return { kind: "too_large" };
      }
      chunks.push(value);
    }
  } catch {
    return { kind: "unreadable" };
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return {
      kind: "ok",
      text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes),
    };
  } catch {
    return { kind: "unreadable" };
  }
}

/** Outcome of reading and parsing a JSON-object body under a byte cap. */
export type CappedJsonBody =
  | { readonly kind: "ok"; readonly body: Record<string, unknown> }
  | { readonly kind: "too_large" }
  | { readonly kind: "invalid" };

/**
 * {@link readBodyCapped}, then parse the text as a JSON object. Unreadable bytes, invalid JSON, and
 * non-object JSON (arrays, scalars, null) are all `invalid`.
 */
export async function readJsonObjectCapped(
  request: Request,
  maxBytes: number,
): Promise<CappedJsonBody> {
  const raw = await readBodyCapped(request, maxBytes);
  if (raw.kind === "too_large") return raw;
  if (raw.kind === "unreadable") return { kind: "invalid" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.text);
  } catch {
    return { kind: "invalid" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { kind: "invalid" };
  }
  return { kind: "ok", body: parsed as Record<string, unknown> };
}

/** UTF-8 byte length of a string (what the ciphertext cap measures). */
export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

/**
 * Resolve the request horizon from the optional `MAX_REQUEST_TTL_MS` Worker var.
 *
 * Unset → {@link DEFAULT_MAX_REQUEST_TTL_MS}. A set value must be a positive safe integer of
 * milliseconds; anything else is a misconfiguration, logged, and replaced by the default — the
 * horizon is never disabled or widened by a typo. A value below the hooks' 420 s timeout is honored
 * (the operator's choice) and makes such submits fail closed with 400.
 */
export function parseMaxRequestTtlMs(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return DEFAULT_MAX_REQUEST_TTL_MS;
  const trimmed = raw.trim();
  const value = Number(trimmed);
  if (!/^\d+$/.test(trimmed) || !Number.isSafeInteger(value) || value <= 0) {
    console.error(
      `allw relay: ignoring invalid MAX_REQUEST_TTL_MS ${JSON.stringify(raw)}; using the default`,
    );
    return DEFAULT_MAX_REQUEST_TTL_MS;
  }
  return value;
}

/** The relay's unauthenticated routes, each with its own per-account rate-limit binding. */
export type RateLimitedRoute = "pairing" | "requests";

/** The subset of the Cloudflare rate-limiting binding the relay calls (injectable in tests). */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/** The account routes the limiter covers, by dispatch key, and the budget each one draws on. */
const RATE_LIMITED_ROUTES: Partial<Record<AccountRouteName, RateLimitedRoute>> = {
  pairingStart: "pairing",
  pairingComplete: "pairing",
  requestSubmit: "requests",
};

/**
 * Which rate-limited route a request targets, or `null` for routes the limiter does not cover.
 * Covered: `POST /{acct}/pairing/start`, `POST /{acct}/pairing/complete`, `POST /{acct}/requests`.
 *
 * Resolved through the Durable Object's own route table (`resolveAccountRoute`), so the limiter
 * covers exactly the requests that dispatch to those handlers: a path the router answers with 404
 * or 405 (an extra segment, a trailing slash) is neither limited nor handled.
 */
export function rateLimitedRoute(method: string, pathname: string): RateLimitedRoute | null {
  const resolved = resolveAccountRoute(method.toUpperCase(), accountSubPathSegments(pathname));
  return resolved.kind === "route" ? (RATE_LIMITED_ROUTES[resolved.name] ?? null) : null;
}

/**
 * The client's rate-limit identity from `CF-Connecting-IP` (set by the Cloudflare edge):
 * an IPv4 address as-is, an IPv6 address reduced to its /64 (one subscriber typically holds a whole
 * /64, so per-address keys would hand out 2^64 buckets), an IPv4-mapped IPv6 address as its IPv4.
 * A missing or unparseable header shares the single `unknown` bucket.
 */
export function clientIpKey(request: Request): string {
  const raw = (request.headers.get("CF-Connecting-IP") ?? "").trim();
  if (raw === "") return "unknown";
  if (isIpv4(raw)) return raw;
  const prefix = ipv6Slash64(raw);
  return prefix ?? "unknown";
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && String(Number(p)) === p)
  );
}

/** `"2001:db8:1:2::/64"`-style key for an IPv6 address, the IPv4 for a mapped one, else null. */
function ipv6Slash64(value: string): string | null {
  let addr = value.toLowerCase();
  const zone = addr.indexOf("%");
  if (zone !== -1) addr = addr.slice(0, zone);
  if (!/^[0-9a-f:.]+$/.test(addr) || !addr.includes(":")) return null;

  // An embedded dotted IPv4 tail occupies the last two groups.
  let tail: string[] = [];
  const lastColon = addr.lastIndexOf(":");
  const maybeV4 = addr.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    if (!isIpv4(maybeV4)) return null;
    const o = maybeV4.split(".").map(Number) as [number, number, number, number];
    tail = [((o[0] << 8) | o[1]).toString(16), ((o[2] << 8) | o[3]).toString(16)];
    // A placeholder "0" group stands in for the tail; it is swapped for the two groups below.
    addr = addr.slice(0, lastColon + 1) + "0";
  }

  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] === "" ? [] : (halves[0] ?? "").split(":");
  const rest = halves.length === 2 ? (halves[1] === "" ? [] : (halves[1] ?? "").split(":")) : [];
  let groups: string[];
  if (halves.length === 2) {
    const fill = 8 - (tail.length > 0 ? 1 : 0) - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...Array<string>(fill).fill("0"), ...rest];
  } else {
    groups = head;
  }
  if (tail.length > 0) groups = [...groups.slice(0, -1), ...tail];
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;

  const norm = groups.map((g) => parseInt(g, 16));
  // ::ffff:a.b.c.d (IPv4-mapped) → the IPv4 address itself.
  if (norm.slice(0, 5).every((g) => g === 0) && norm[5] === 0xffff) {
    const hi = norm[6] ?? 0;
    const lo = norm[7] ?? 0;
    return `${String(hi >> 8)}.${String(hi & 0xff)}.${String(lo >> 8)}.${String(lo & 0xff)}`;
  }
  return `${norm
    .slice(0, 4)
    .map((g) => g.toString(16))
    .join(":")}::/64`;
}

/**
 * The per-account limiter key: the account id together with the client identity
 * ({@link clientIpKey}). Keying on both means one client flooding an account exhausts only its own
 * budget for that account, never the account owner's.
 */
export function rateLimitKey(accountId: string, request: Request): string {
  return `${accountId}|${clientIpKey(request)}`;
}

/**
 * The per-client limiter key (client identity alone, across every account), so minting random
 * account ids does not buy a client fresh per-account buckets.
 */
export function clientRateLimitKey(request: Request): string {
  return `ip|${clientIpKey(request)}`;
}

/**
 * Apply `limiter` to a covered request. Returns a refusal `Response` (429 over the limit; 503 when
 * the binding is missing or throws — fail-closed), or `null` to let the request through.
 */
export async function enforceRateLimit(
  limiter: RateLimiter | undefined,
  key: string,
): Promise<Response | null> {
  if (limiter === undefined) {
    console.error("allw relay: rate-limit binding missing; refusing unauthenticated route");
    return limitResponse({ error: "rate limiter unavailable" }, 503);
  }
  let outcome: { success: boolean };
  try {
    outcome = await limiter.limit({ key });
  } catch (err) {
    console.error("allw relay: rate limiter failed; refusing", err);
    return limitResponse({ error: "rate limiter unavailable" }, 503);
  }
  if (!outcome.success) {
    return limitResponse({ error: "rate limit exceeded" }, 429);
  }
  return null;
}

function limitResponse(data: unknown, status: number): Response {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (status === 429) headers["Retry-After"] = "60";
  return new Response(JSON.stringify(data), { status, headers });
}
