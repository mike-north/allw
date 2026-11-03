/**
 * The `AccountRelay` Durable Object's route table and its exact path matcher (#302).
 *
 * Every account route is declared once, in {@link ACCOUNT_ROUTES}. Dispatch and the
 * 405-vs-404 decision both come from {@link resolveAccountRoute}, so they cannot disagree.
 *
 * # Matching rule
 * A route matches only its **exact** segment sequence, compared as the URL parser yields them
 * (percent-encoding preserved; `.` and `..` segments, `%2e%2e` included, already resolved):
 * - the same number of segments;
 * - every literal segment equal;
 * - every `{param}` segment non-empty.
 *
 * So an extra segment, a trailing slash, an empty segment (`//`) or a missing segment is not that
 * route. Anything layered on exact paths (rate limits, log or WAF rules, CORS) therefore can't be
 * bypassed by appending to a path.
 *
 * The relay-level `/.well-known/allw/…` routes are outside this table: the Worker dispatches them
 * before account routing (`well-known.ts`).
 *
 * @see ../../../docs/relay-api.md §1 Conventions (path matching), §3 Endpoints
 */

/** One account route: its HTTP method and its sub-path below `/{account_id}/`. */
export interface AccountRouteSpec {
  /** Dispatch key; the Durable Object switches on it. */
  readonly name: string;
  /** Upper-case HTTP method. */
  readonly method: string;
  /** Slash-separated segments; `{name}` marks a non-empty path parameter. */
  readonly path: string;
}

/**
 * Every account route the relay serves, as documented in `docs/relay-api.md` §3. Add a route
 * here and the router, the 405 check and the exact-path tests all pick it up.
 */
export const ACCOUNT_ROUTES = [
  { name: "pairingStart", method: "POST", path: "pairing/start" },
  { name: "pairingComplete", method: "POST", path: "pairing/complete" },
  { name: "actorEnroll", method: "POST", path: "actors" },
  { name: "actorList", method: "GET", path: "actors" },
  { name: "accountStatePublish", method: "POST", path: "account-states" },
  { name: "accountStateList", method: "GET", path: "account-states" },
  { name: "deviceList", method: "GET", path: "devices" },
  { name: "deviceRevoke", method: "POST", path: "devices/{device_id}/revoke" },
  { name: "devicePushTokens", method: "PUT", path: "devices/{device_id}/push-tokens" },
  { name: "deviceInbox", method: "GET", path: "devices/{device_id}/inbox" },
  { name: "deviceConnect", method: "GET", path: "devices/{device_id}/connect" },
  { name: "requestSubmit", method: "POST", path: "requests" },
  { name: "requestWait", method: "GET", path: "requests/{request_id}/wait" },
  { name: "requestGet", method: "GET", path: "requests/{request_id}" },
  { name: "requestRetract", method: "POST", path: "requests/{request_id}/retract" },
] as const satisfies readonly AccountRouteSpec[];

/** The dispatch key of an account route. */
export type AccountRouteName = (typeof ACCOUNT_ROUTES)[number]["name"];

/**
 * How a request's path and method resolve against {@link ACCOUNT_ROUTES}:
 * - `route`: an exact match, with its path parameters;
 * - `method-not-allowed`: the path is exactly some route's, but no route has this method (405);
 * - `not-found`: no route has exactly this path (404).
 */
export type AccountRouteResolution =
  | {
      readonly kind: "route";
      readonly name: AccountRouteName;
      readonly params: Readonly<Record<string, string>>;
    }
  | { readonly kind: "method-not-allowed" }
  | { readonly kind: "not-found" };

/**
 * The sub-path segments below the account id, empty segments kept. A trailing slash therefore
 * leaves a final `""`, which no route matches.
 *
 * `pathname` is a URL pathname such as `/acct/devices/d1/inbox`. Its first segment (the account
 * id) is the Worker's routing key, not part of any route.
 */
export function accountSubPathSegments(pathname: string): string[] {
  // "/acct/devices" splits to ["", "acct", "devices"]: drop the empty root and the account id.
  return pathname.split("/").slice(2);
}

/**
 * Match `segments` against one route path exactly. Returns its parameters, or `null` when the
 * segment count, a literal segment, or a parameter's non-emptiness differs.
 */
export function matchRoutePath(
  path: string,
  segments: readonly string[],
): Record<string, string> | null {
  const pattern = path.split("/");
  if (pattern.length !== segments.length) return null;
  const params: Record<string, string> = {};
  for (const [i, part] of pattern.entries()) {
    const segment = segments[i] ?? "";
    const param = /^\{([a-z_]+)\}$/.exec(part)?.[1];
    if (param !== undefined) {
      if (segment === "") return null;
      params[param] = segment;
    } else if (segment !== part) {
      return null;
    }
  }
  return params;
}

/** Resolve a request against {@link ACCOUNT_ROUTES} (see {@link AccountRouteResolution}). */
export function resolveAccountRoute(
  method: string,
  segments: readonly string[],
): AccountRouteResolution {
  let pathKnown = false;
  for (const route of ACCOUNT_ROUTES) {
    const params = matchRoutePath(route.path, segments);
    if (params === null) continue;
    if (route.method === method) return { kind: "route", name: route.name, params };
    pathKnown = true;
  }
  return pathKnown ? { kind: "method-not-allowed" } : { kind: "not-found" };
}

/**
 * The value of path parameter `name` in a resolved route. Every parameter a route declares is
 * non-empty once matched, so a missing one is a mismatch between the route table and its
 * handler, never a client error.
 */
export function routeParam(params: Readonly<Record<string, string>>, name: string): string {
  const value = params[name];
  if (value === undefined) throw new Error(`route has no '${name}' parameter`);
  return value;
}
