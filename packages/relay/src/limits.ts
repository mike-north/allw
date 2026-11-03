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
    const length = Number(declared);
    if (!/^\d+$/.test(declared.trim()) || !Number.isSafeInteger(length)) {
      return { kind: "unreadable" };
    }
    if (length > maxBytes) return { kind: "too_large" };
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

/** The relay's unauthenticated routes, each with its own rate-limit binding. */
export type RateLimitedRoute = "pairing" | "requests";

/** The subset of the Cloudflare rate-limiting binding the relay calls (injectable in tests). */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/**
 * Which rate-limited route a request targets, or `null` for routes the limiter does not cover.
 * Covered: `POST /{acct}/pairing/start`, `POST /{acct}/pairing/complete`, `POST /{acct}/requests`.
 */
export function rateLimitedRoute(method: string, pathname: string): RateLimitedRoute | null {
  if (method.toUpperCase() !== "POST") return null;
  const segments = pathname.split("/").filter(Boolean);
  if (segments.length === 3 && segments[1] === "pairing") {
    return segments[2] === "start" || segments[2] === "complete" ? "pairing" : null;
  }
  if (segments.length === 2 && segments[1] === "requests") return "requests";
  return null;
}

/**
 * The limiter key: the account id together with the client IP (`CF-Connecting-IP`, set by the
 * Cloudflare edge). Keying on both means one client flooding an account exhausts only its own
 * budget for that account, never the account owner's.
 */
export function rateLimitKey(accountId: string, request: Request): string {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  return `${accountId}|${ip}`;
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
