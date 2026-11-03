/**
 * Every account route matches its exact path (#302).
 *
 * The relay answers a route only on its exact segment sequence (`docs/relay-api.md` §1
 * Conventions, "Exact paths"). Any other path is a 404 `{ error: "not found" }`, whatever the
 * method: an extra segment, a trailing slash, an empty segment, or a missing segment. The
 * exception is a missing segment that lands exactly on another documented route. A path that is
 * exactly some route's, reached with another method, is a 405 `{ error: "method not allowed" }`.
 *
 * The route list below is written by hand from `docs/relay-api.md` §3. The first test pins the
 * relay's route table to it, and each case's expected status is written here, not derived from the
 * table.
 *
 * @see ../../../docs/relay-api.md §1 Conventions, §3 Endpoints
 * @see https://github.com/mike-north/allw/issues/302
 */

import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { ACCOUNT_ROUTES, matchRoutePath, resolveAccountRoute } from "../src/routes.js";

const ACCOUNT = "acct-exact-route-paths";
const METHODS = ["GET", "POST", "PUT", "DELETE"] as const;
const NOT_FOUND = { error: "not found" };
const METHOD_NOT_ALLOWED = { error: "method not allowed" };

interface DocumentedRoute {
  readonly method: string;
  /** The documented sub-path, with `{param}` placeholders. */
  readonly path: string;
  /** The same route with each parameter filled in. */
  readonly concrete: string;
  /** The response when the last segment is dropped: the router's, or another route's handler. */
  readonly missingLast: Outcome;
  /**
   * Set only where `<route>/extra` is exactly another documented route, so it is not a 404 from
   * the router. The response for each method. Every other route's extra segment is a 404.
   */
  readonly extraSegment?: Readonly<Record<(typeof METHODS)[number], Outcome>>;
}

interface Outcome {
  readonly status: number;
  readonly body: unknown;
}

/** The account routes in `docs/relay-api.md` §3, and what dropping each one's last segment gives. */
const DOCUMENTED_ROUTES: readonly DocumentedRoute[] = [
  {
    method: "POST",
    path: "pairing/start",
    concrete: "pairing/start",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "POST",
    path: "pairing/complete",
    concrete: "pairing/complete",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "POST",
    path: "actors",
    concrete: "actors",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "GET",
    path: "actors",
    concrete: "actors",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "POST",
    path: "account-states",
    concrete: "account-states",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "GET",
    path: "account-states",
    concrete: "account-states",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "GET",
    path: "devices",
    concrete: "devices",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "POST",
    path: "devices/{device_id}/revoke",
    concrete: "devices/d1/revoke",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "PUT",
    path: "devices/{device_id}/push-tokens",
    concrete: "devices/d1/push-tokens",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "GET",
    path: "devices/{device_id}/inbox",
    concrete: "devices/d1/inbox",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  {
    method: "GET",
    path: "devices/{device_id}/connect",
    concrete: "devices/d1/connect",
    missingLast: { status: 404, body: NOT_FOUND },
  },
  // `requests/extra` is exactly `requests/{request_id}`, which only GET serves.
  {
    method: "POST",
    path: "requests",
    concrete: "requests",
    missingLast: { status: 404, body: NOT_FOUND },
    extraSegment: {
      GET: { status: 404, body: { error: "request not found" } },
      POST: { status: 405, body: METHOD_NOT_ALLOWED },
      PUT: { status: 405, body: METHOD_NOT_ALLOWED },
      DELETE: { status: 405, body: METHOD_NOT_ALLOWED },
    },
  },
  // `requests/r1` is exactly `GET /requests/{request_id}`, whose handler 404s an unknown request.
  {
    method: "GET",
    path: "requests/{request_id}/wait",
    concrete: "requests/r1/wait",
    missingLast: { status: 404, body: { error: "request not found" } },
  },
  // `requests` is exactly `POST /requests`; GET is not a method there.
  {
    method: "GET",
    path: "requests/{request_id}",
    concrete: "requests/r1",
    missingLast: { status: 405, body: METHOD_NOT_ALLOWED },
  },
  // `requests/r1` is exactly `GET /requests/{request_id}`; POST is not a method there.
  {
    method: "POST",
    path: "requests/{request_id}/retract",
    concrete: "requests/r1/retract",
    missingLast: { status: 405, body: METHOD_NOT_ALLOWED },
  },
];

async function call(method: string, subPath: string): Promise<{ status: number; body: unknown }> {
  const resp = await SELF.fetch(`https://relay.allw.test/${ACCOUNT}${subPath}`, {
    method,
    ...(method === "GET" ? {} : { headers: { "Content-Type": "application/json" }, body: "{}" }),
  });
  return { status: resp.status, body: await resp.json() };
}

function routeLabel(route: DocumentedRoute): string {
  return `${route.method} /${route.path}`;
}

describe("route table", () => {
  it("is exactly the documented account API", () => {
    const table = ACCOUNT_ROUTES.map((route) => `${route.method} /${route.path}`).sort();
    expect(table).toEqual(DOCUMENTED_ROUTES.map(routeLabel).sort());
  });

  it("has no two routes that one request could match", () => {
    for (const route of DOCUMENTED_ROUTES) {
      const segments = route.concrete.split("/");
      const matching = ACCOUNT_ROUTES.filter(
        (candidate) =>
          candidate.method === route.method && matchRoutePath(candidate.path, segments) !== null,
      );
      expect(matching, routeLabel(route)).toHaveLength(1);
    }
  });
});

describe("matchRoutePath", () => {
  it("binds a non-empty parameter", () => {
    expect(matchRoutePath("devices/{device_id}/inbox", ["devices", "d1", "inbox"])).toEqual({
      device_id: "d1",
    });
  });

  it.each([
    ["an extra segment", ["devices", "d1", "inbox", "extra"]],
    ["a trailing slash", ["devices", "d1", "inbox", ""]],
    ["a missing segment", ["devices", "d1"]],
    ["an empty parameter", ["devices", "", "inbox"]],
    ["a different literal", ["devices", "d1", "outbox"]],
  ])("rejects %s", (_label, segments) => {
    expect(matchRoutePath("devices/{device_id}/inbox", segments)).toBeNull();
  });

  it("treats a lone trailing slash on a one-segment route as not that route", () => {
    expect(resolveAccountRoute("GET", ["devices", ""])).toEqual({ kind: "not-found" });
  });
});

describe.each(DOCUMENTED_ROUTES)("$method /$path", (route) => {
  // Each route's handler behaviour is pinned by its own suite (account-relay, pairing-start-auth,
  // account-state-verified, push-tokens, relay-routing); this only checks the router reaches it.
  it("reaches its handler on the exact path", async () => {
    const { status, body } = await call(route.method, `/${route.concrete}`);
    // The handler decides the status (often 400/401/404 for this junk input); the router's own
    // 404 and 405 bodies must not appear.
    expect(body, `status ${status}`).not.toEqual(NOT_FOUND);
    expect(body, `status ${status}`).not.toEqual(METHOD_NOT_ALLOWED);
  });

  it.each(METHODS)("is not this route with an extra segment, by %s", async (method) => {
    expect(await call(method, `/${route.concrete}/extra`)).toEqual(
      route.extraSegment?.[method] ?? { status: 404, body: NOT_FOUND },
    );
  });

  it.each(METHODS)("is 404 with a trailing slash, by %s", async (method) => {
    expect(await call(method, `/${route.concrete}/`)).toEqual({ status: 404, body: NOT_FOUND });
  });

  it("gives the documented response with its last segment missing", async () => {
    const missing = route.concrete.split("/").slice(0, -1).join("/");
    expect(await call(route.method, missing === "" ? "" : `/${missing}`)).toEqual(
      route.missingLast,
    );
  });
});

describe.each(DOCUMENTED_ROUTES.filter((route) => route.path.includes("{")))(
  "$method /$path",
  (route) => {
    it("is 404 with an empty parameter", async () => {
      const emptied = route.concrete
        .split("/")
        .map((segment, i) => (route.path.split("/")[i]?.startsWith("{") ? "" : segment));
      expect(await call(route.method, `/${emptied.join("/")}`)).toEqual({
        status: 404,
        body: NOT_FOUND,
      });
    });
  },
);

describe("dot segments", () => {
  // The WHATWG URL parser resolves `.` / `..` (and `%2e%2e`) before the router sees the path, so
  // these are the inbox route itself, not an extra or missing segment.
  it.each(["/devices/d1/inbox/../inbox", "/devices/d1/x/%2e%2e/inbox", "/devices/./d1/inbox"])(
    "%s reaches GET /devices/{device_id}/inbox",
    async (subPath) => {
      const direct = await call("GET", "/devices/d1/inbox");
      expect(direct.body).not.toEqual(NOT_FOUND);
      expect(await call("GET", subPath)).toEqual(direct);
    },
  );
});

describe("the account root", () => {
  it.each(["", "/"])("is 404 for '/%s' below the account id", async (suffix) => {
    expect(await call("GET", suffix)).toEqual({ status: 404, body: NOT_FOUND });
  });
});
