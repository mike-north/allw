/**
 * Cross-origin (CORS) policy for browser clients of the relay, applied once at the Worker's
 * top-level `fetch` so no route handler deals with it.
 *
 * # Why the relay needs it
 * The hosted web approver is served from a different origin than the relay. Every relay call it makes
 * either sends `Authorization: Bearer …` or POSTs `application/json`, and both force a preflight.
 * Without CORS headers a browser blocks every response, so the web approver cannot work at all.
 *
 * # Policy
 * - **Origin allowlist.** Only configured origins (`CORS_ALLOWED_ORIGINS`, a non-secret Worker var)
 *   get an `Access-Control-Allow-Origin` echo. Other origins get no CORS headers, so the browser
 *   withholds the response. When the var is absent the allowlist is the hosted web approver alone.
 * - **No credentials mode.** `Access-Control-Allow-Credentials` is never sent. Relay auth is a bearer
 *   capability the page holds explicitly, never an ambient cookie, so allowing an origin grants it
 *   nothing the bearer token does not.
 * - **Preflight** admits only the methods the relay routes (`GET`, `POST`) and the request headers it
 *   reads (`Authorization`, `Content-Type`). Anything else is refused.
 * - **`Vary: Origin`** goes on every response the wrapper handles, because the CORS headers depend
 *   on the request's `Origin`.
 *
 * CORS is a browser read-permission mechanism, not access control. Non-browser clients (the CLI,
 * SDK, hook, native apps) send no `Origin` and are unaffected, and a request from a disallowed
 * origin still reaches its handler and is authorized exactly as before. WebSocket upgrades are not
 * subject to CORS and pass through unchanged; they authenticate with the `?auth=` bearer.
 *
 * @see https://fetch.spec.whatwg.org/#http-cors-protocol
 */

/** The hosted web approver, the allowlist used when `CORS_ALLOWED_ORIGINS` is not set. */
export const DEFAULT_CORS_ALLOWED_ORIGINS = "https://allw-web-approver.pages.dev";

/** HTTP methods the relay routes; the only ones a preflight may request. */
const ALLOWED_METHODS: readonly string[] = ["GET", "POST"];

/** Request headers the relay reads (lowercase); the only ones a preflight may request. */
const ALLOWED_REQUEST_HEADERS: ReadonlySet<string> = new Set(["authorization", "content-type"]);

/** How long a browser may cache a successful preflight, in seconds. */
const PREFLIGHT_MAX_AGE_SECONDS = 600;

/** The Worker binding that configures the allowlist. */
export interface CorsEnv {
  /**
   * Comma-separated origins, e.g. `https://approver.example.com,http://localhost:*`. Each entry is
   * an exact origin (scheme, host and optional port, with no path). A port of `*` matches any port,
   * which is meant for loopback dev servers. An empty value allows no origin.
   */
  readonly CORS_ALLOWED_ORIGINS?: string;
}

/** A parsed allowlist entry: an exact origin, or a scheme + host on any port. */
export type OriginRule =
  | { readonly kind: "exact"; readonly origin: string }
  | { readonly kind: "any-port"; readonly scheme: string; readonly hostname: string };

/**
 * Parse the allowlist. Malformed entries are dropped, never widened: an entry with a path, query,
 * credentials, a non-http(s) scheme, a wildcard host, or the opaque `null` origin matches nothing.
 */
export function parseCorsAllowedOrigins(value: string | undefined): readonly OriginRule[] {
  const raw = value ?? DEFAULT_CORS_ALLOWED_ORIGINS;
  const rules: OriginRule[] = [];
  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (trimmed === "") continue;
    const anyPort = /^(https?):\/\/([^/:@?#*]+):\*$/.exec(trimmed);
    if (anyPort) {
      const [, scheme = "", hostname = ""] = anyPort;
      const probe = parseOrigin(`${scheme}://${hostname}`);
      if (probe) rules.push({ kind: "any-port", scheme: `${scheme}:`, hostname: probe.hostname });
      continue;
    }
    // `*` is only meaningful as a port; a wildcard host or a bare `*` is never a valid entry.
    if (trimmed.includes("*")) continue;
    const exact = parseOrigin(trimmed);
    // Only an entry that is already a bare origin is accepted: `https://a.example/` (trailing slash)
    // or anything with a path is rejected rather than silently trimmed.
    if (exact?.origin === trimmed) rules.push({ kind: "exact", origin: exact.origin });
  }
  return rules;
}

/** Whether a request `Origin` header value is on the allowlist. */
export function isCorsOriginAllowed(origin: string, rules: readonly OriginRule[]): boolean {
  const parsed = parseOrigin(origin);
  // The request's Origin must itself be a serialized origin (no path) to match anything.
  if (parsed?.origin !== origin) return false;
  return rules.some((rule) =>
    rule.kind === "exact"
      ? rule.origin === origin
      : rule.scheme === parsed.protocol && rule.hostname === parsed.hostname,
  );
}

/**
 * Wrap the relay's top-level handler with the CORS policy: answer preflights directly, and decorate
 * every other non-WebSocket response with the allowlisted origin echo and `Vary: Origin`.
 */
export async function withCors(
  request: Request,
  env: CorsEnv,
  handler: (request: Request) => Promise<Response>,
): Promise<Response> {
  const rules = parseCorsAllowedOrigins(env.CORS_ALLOWED_ORIGINS);
  const origin = request.headers.get("Origin");
  const allowedOrigin = origin !== null && isCorsOriginAllowed(origin, rules) ? origin : null;

  if (isPreflight(request)) return preflightResponse(request, allowedOrigin);

  const response = await handler(request);
  // A 101 carries the WebSocket and must be returned as-is; WebSockets are not subject to CORS.
  if (response.status === 101) return response;
  // Handler and Durable Object responses can have immutable headers; copy before decorating.
  const decorated = new Response(response.body, response);
  decorated.headers.append("Vary", "Origin");
  if (allowedOrigin !== null) decorated.headers.set("Access-Control-Allow-Origin", allowedOrigin);
  return decorated;
}

/** A CORS preflight is an `OPTIONS` carrying `Access-Control-Request-Method` (Fetch §3.2.2). */
function isPreflight(request: Request): boolean {
  return (
    request.method === "OPTIONS" && request.headers.get("Access-Control-Request-Method") !== null
  );
}

function preflightResponse(request: Request, allowedOrigin: string | null): Response {
  const requestedMethod = request.headers.get("Access-Control-Request-Method") ?? "";
  const requestedHeaders = (request.headers.get("Access-Control-Request-Headers") ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h !== "");
  const admissible =
    allowedOrigin !== null &&
    ALLOWED_METHODS.includes(requestedMethod) &&
    requestedHeaders.every((h) => ALLOWED_REQUEST_HEADERS.has(h));
  if (!admissible) {
    // Refused: no Access-Control-* headers, so the browser fails the preflight and never sends
    // the actual request.
    return new Response(null, { status: 403, headers: { Vary: "Origin" } });
  }
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": ALLOWED_METHODS.join(", "),
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Max-Age": String(PREFLIGHT_MAX_AGE_SECONDS),
      Vary: "Origin",
    },
  });
}

function parseOrigin(value: string): URL | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (url.username !== "" || url.password !== "") return null;
  return url;
}
