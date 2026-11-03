/**
 * Tests for the relay's CORS policy (#258). The Worker runs under the dev `wrangler.jsonc` vars, which
 * allow the hosted web approver plus loopback on any port, so the browser-facing behaviour is tested
 * end to end through `SELF`. Overrides go through the default export with a custom `env`.
 *
 * @see https://fetch.spec.whatwg.org/#http-cors-protocol (preflight, ACAO, credentials mode)
 * @see ../../../docs/relay-api.md (§1 Conventions: CORS)
 */

import { SELF, env } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import worker from "../src/index.js";
import {
  DEFAULT_CORS_ALLOWED_ORIGINS,
  isCorsOriginAllowed,
  parseCorsAllowedOrigins,
  withCors,
} from "../src/cors.js";
import wranglerConfigText from "../wrangler.jsonc?raw";
import { pairingStartBody, testAccount } from "./support/accounts.js";

const HOSTED_APPROVER = "https://allw-web-approver.pages.dev";
/** A 32-byte base64url-unpadded device key (32 × 0x00). */
const DEVICE_PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function url(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

function preflight(
  origin: string,
  method: string,
  requestHeaders = "authorization",
): Promise<Response> {
  return SELF.fetch(url("acct-cors-preflight", "/devices/dev-x/inbox"), {
    method: "OPTIONS",
    headers: {
      Origin: origin,
      "Access-Control-Request-Method": method,
      "Access-Control-Request-Headers": requestHeaders,
    },
  });
}

function expectNoCorsGrant(resp: Response): void {
  expect(resp.headers.get("Access-Control-Allow-Origin")).toBeNull();
  expect(resp.headers.get("Access-Control-Allow-Methods")).toBeNull();
  expect(resp.headers.get("Access-Control-Allow-Headers")).toBeNull();
  expect(resp.headers.get("Access-Control-Allow-Credentials")).toBeNull();
}

describe("CORS preflight", () => {
  it("admits the hosted web approver for an authenticated GET", async () => {
    const resp = await preflight(HOSTED_APPROVER, "GET");

    expect(resp.status).toBe(204);
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(HOSTED_APPROVER);
    expect(resp.headers.get("Access-Control-Allow-Methods")).toBe("GET, POST");
    expect(resp.headers.get("Access-Control-Allow-Headers")).toBe("Authorization, Content-Type");
    expect(resp.headers.get("Access-Control-Max-Age")).toBe("600");
    expect(resp.headers.get("Vary")).toBe("Origin");
    // No credentials mode: auth is a bearer header, never a cookie.
    expect(resp.headers.get("Access-Control-Allow-Credentials")).toBeNull();
  });

  it("admits a JSON POST (Content-Type + Authorization) from an allowed origin", async () => {
    const resp = await preflight(HOSTED_APPROVER, "POST", "content-type, Authorization");

    expect(resp.status).toBe(204);
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(HOSTED_APPROVER);
  });

  it.each(["http://localhost:5173", "http://127.0.0.1:8788"])(
    "admits a loopback dev origin on any port (%s)",
    async (origin) => {
      const resp = await preflight(origin, "GET");

      expect(resp.status).toBe(204);
      expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(origin);
    },
  );

  it.each([
    ["an unrelated origin", "https://evil.example"],
    ["a lookalike suffix", "https://allw-web-approver.pages.dev.evil.example"],
    ["the hosted origin over http", "http://allw-web-approver.pages.dev"],
    ["the opaque null origin", "null"],
    ["https on a loopback host only allowed over http", "https://localhost:5173"],
  ])("rejects %s with no CORS grant", async (_name, origin) => {
    const resp = await preflight(origin, "GET");

    expect(resp.status).toBe(403);
    expectNoCorsGrant(resp);
    expect(resp.headers.get("Vary")).toBe("Origin");
  });

  it.each(["DELETE", "PUT", "PATCH"])(
    "rejects a preflight for a method the relay does not route (%s)",
    async (method) => {
      const resp = await preflight(HOSTED_APPROVER, method);

      expect(resp.status).toBe(403);
      expectNoCorsGrant(resp);
    },
  );

  it("rejects a preflight that carries no Origin, still varying on Origin", async () => {
    const resp = await SELF.fetch(url("acct-cors-preflight-no-origin", "/devices/dev-x/inbox"), {
      method: "OPTIONS",
      headers: {
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
      },
    });

    expect(resp.status).toBe(403);
    expectNoCorsGrant(resp);
    expect(resp.headers.get("Vary")).toBe("Origin");
  });

  it("rejects a preflight requesting a header the relay does not read", async () => {
    const resp = await preflight(HOSTED_APPROVER, "GET", "authorization, x-forwarded-for");

    expect(resp.status).toBe(403);
    expectNoCorsGrant(resp);
  });

  it("leaves a non-preflight OPTIONS (no Access-Control-Request-Method) to the router", async () => {
    const resp = await SELF.fetch(url("acct-cors-plain-options", "/devices/dev-x/inbox"), {
      method: "OPTIONS",
      headers: { Origin: HOSTED_APPROVER },
    });

    expect(resp.status).toBe(405);
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(HOSTED_APPROVER);
  });
});

/** Chrome's request headers on a cross-site CORS preflight (captured shape, values illustrative). */
function chromePreflightHeaders(method: string, requestHeaders: string): Record<string, string> {
  return {
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Access-Control-Request-Headers": requestHeaders,
    "Access-Control-Request-Method": method,
    Origin: HOSTED_APPROVER,
    Referer: `${HOSTED_APPROVER}/`,
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "cross-site",
    "User-Agent":
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
  };
}

/**
 * The browser's CORS check on a preflight (Fetch §4.8 "CORS-preflight fetch") for a request whose
 * credentials mode is not "include": an ok status, ACAO equal to the origin, the method listed, and
 * every requested header listed (case-insensitive). Returns why it fails, or null when it passes.
 */
function browserPreflightFailure(
  resp: Response,
  method: string,
  requestHeaders: readonly string[],
): string | null {
  if (resp.status < 200 || resp.status > 299) return `preflight status ${String(resp.status)}`;
  if (resp.headers.get("Access-Control-Allow-Origin") !== HOSTED_APPROVER) return "ACAO mismatch";
  const methods = (resp.headers.get("Access-Control-Allow-Methods") ?? "")
    .split(",")
    .map((m) => m.trim());
  if (!methods.includes(method)) return `method ${method} not allowed`;
  const allowed = (resp.headers.get("Access-Control-Allow-Headers") ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase());
  const missing = requestHeaders.filter((h) => !allowed.includes(h.toLowerCase()));
  return missing.length > 0 ? `headers not allowed: ${missing.join(",")}` : null;
}

describe("CORS — browser-shaped flow from the hosted web approver", () => {
  it("passes Chrome's preflight + CORS check for the authenticated inbox poll", async () => {
    const acct = testAccount("acct-cors-browser-inbox");
    const start = (await (
      await SELF.fetch(url(acct, "/pairing/start"), {
        method: "POST",
        body: JSON.stringify(pairingStartBody(acct)),
      })
    ).json()) as { code: string; pairing_auth_token: string };
    const device = (await (
      await SELF.fetch(url(acct, "/pairing/complete"), {
        method: "POST",
        headers: { Authorization: `Bearer ${start.pairing_auth_token}` },
        body: JSON.stringify({ code: start.code, pubkey: DEVICE_PUBKEY }),
      })
    ).json()) as { device_id: string; device_auth_token: string };
    const inbox = url(acct, `/devices/${device.device_id}/inbox`);

    // 1. Chrome's preflight for `fetch(inbox, { headers: { Authorization } })` (relay-poll.ts).
    const pre = await SELF.fetch(inbox, {
      method: "OPTIONS",
      headers: chromePreflightHeaders("GET", "authorization"),
    });
    expect(browserPreflightFailure(pre, "GET", ["authorization"])).toBeNull();

    // 2. The actual request, as Chrome sends it after a passing preflight.
    const actual = await SELF.fetch(inbox, {
      headers: {
        Accept: "*/*",
        Authorization: `Bearer ${device.device_auth_token}`,
        Origin: HOSTED_APPROVER,
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
      },
    });
    expect(actual.status).toBe(200);
    // Fetch §4.9 CORS check: ACAO must equal the request origin for the page to read the body.
    expect(actual.headers.get("Access-Control-Allow-Origin")).toBe(HOSTED_APPROVER);
    expect(await actual.json()).toEqual({ envelopes: [] });
  });

  it("passes Chrome's preflight for a JSON POST with a bearer (pairing completion)", async () => {
    const pre = await SELF.fetch(url("acct-cors-browser-post", "/pairing/complete"), {
      method: "OPTIONS",
      // Chrome lowercases and sorts the list, comma-separated without spaces.
      headers: chromePreflightHeaders("POST", "authorization,content-type"),
    });

    expect(browserPreflightFailure(pre, "POST", ["authorization", "content-type"])).toBeNull();
  });
});

describe("CORS on actual responses", () => {
  it("echoes an allowed origin and sets Vary: Origin, preserving the handler's response", async () => {
    const resp = await SELF.fetch(url("acct-cors-get", "/devices/dev-x/inbox"), {
      headers: { Origin: HOSTED_APPROVER },
    });

    expect(resp.status).toBe(404);
    expect(await resp.json()).toEqual({ error: "device not enrolled" });
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(HOSTED_APPROVER);
    expect(resp.headers.get("Vary")).toBe("Origin");
    expect(resp.headers.get("Access-Control-Allow-Credentials")).toBeNull();
  });

  it("decorates a successful JSON POST from an allowed origin", async () => {
    const acct = testAccount("acct-cors-post");
    const resp = await SELF.fetch(url(acct, "/pairing/start"), {
      method: "POST",
      headers: { Origin: HOSTED_APPROVER, "Content-Type": "application/json" },
      body: JSON.stringify(pairingStartBody(acct)),
    });

    expect(resp.status).toBe(201);
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(HOSTED_APPROVER);
  });

  it("gives a disallowed origin no ACAO; the request is otherwise handled as before", async () => {
    const resp = await SELF.fetch(url("acct-cors-get-disallowed", "/devices/dev-x/inbox"), {
      headers: { Origin: "https://evil.example" },
    });

    expect(resp.status).toBe(404);
    expectNoCorsGrant(resp);
    expect(resp.headers.get("Vary")).toBe("Origin");
  });

  it("adds no CORS grant for a non-browser request without Origin", async () => {
    const resp = await SELF.fetch(url("acct-cors-no-origin", "/devices/dev-x/inbox"));

    expect(resp.status).toBe(404);
    expectNoCorsGrant(resp);
  });

  it("passes a WebSocket upgrade from an allowed origin through untouched (101)", async () => {
    const acct = testAccount("acct-cors-websocket");
    const start = (await (
      await SELF.fetch(url(acct, "/pairing/start"), {
        method: "POST",
        body: JSON.stringify(pairingStartBody(acct)),
      })
    ).json()) as { code: string; pairing_auth_token: string };
    const complete = (await (
      await SELF.fetch(url(acct, "/pairing/complete"), {
        method: "POST",
        headers: { Authorization: `Bearer ${start.pairing_auth_token}` },
        body: JSON.stringify({ code: start.code, pubkey: DEVICE_PUBKEY }),
      })
    ).json()) as { device_id: string; device_auth_token: string };

    const resp = await SELF.fetch(
      url(
        acct,
        `/devices/${complete.device_id}/connect?auth=${encodeURIComponent(complete.device_auth_token)}`,
      ),
      { headers: { Upgrade: "websocket", Origin: HOSTED_APPROVER } },
    );

    expect(resp.status).toBe(101);
    expect(resp.webSocket).not.toBeNull();
    resp.webSocket?.accept();
    resp.webSocket?.close();
  });

  it("uses the configured allowlist (a self-hosted approver origin)", async () => {
    const selfHosted = "https://approver.example.com";
    const customEnv = { ...env, CORS_ALLOWED_ORIGINS: selfHosted };

    const allowed = await worker.fetch(
      new Request(url("acct-cors-custom", "/devices/dev-x/inbox"), {
        headers: { Origin: selfHosted },
      }),
      customEnv,
    );
    const hosted = await worker.fetch(
      new Request(url("acct-cors-custom", "/devices/dev-x/inbox"), {
        headers: { Origin: HOSTED_APPROVER },
      }),
      customEnv,
    );

    expect(allowed.headers.get("Access-Control-Allow-Origin")).toBe(selfHosted);
    // Replacing the var replaces the allowlist: the hosted origin is no longer implied.
    expectNoCorsGrant(hosted);
  });
});

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

describe("CORS on relay-level routes (/.well-known/allw/…)", () => {
  it("lets the hosted web approver read the VAPID public key it subscribes with", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const publicKey = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
    const privateKey = (await crypto.subtle.exportKey("jwk", pair.privateKey)).d ?? "";
    const vapidEnv = {
      ...env,
      VAPID_PUBLIC_KEY: publicKey,
      VAPID_PRIVATE_KEY: privateKey,
      VAPID_SUBJECT: "mailto:ops@allw.example",
    };

    const resp = await worker.fetch(
      new Request("https://relay.allw.test/.well-known/allw/vapid-public-key", {
        headers: { Origin: HOSTED_APPROVER },
      }),
      vapidEnv,
    );

    expect(resp.status).toBe(200);
    expect(await resp.json()).toEqual({ vapid_public_key: publicKey });
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(HOSTED_APPROVER);
    expect(resp.headers.get("Vary")).toBe("Origin");
  });

  it("gives a disallowed origin no ACAO on a relay-level route", async () => {
    const resp = await SELF.fetch("https://relay.allw.test/.well-known/allw/vapid-public-key", {
      headers: { Origin: "https://evil.example" },
    });

    // The test Worker has no VAPID bindings (404), but the CORS decision is the same either way.
    expect(resp.status).toBe(404);
    expectNoCorsGrant(resp);
  });
});

describe("withCors — a throwing handler still answers with CORS headers", () => {
  const throwing = (): Promise<Response> => Promise.reject(new Error("durable object reset"));

  it("returns a 500 with ACAO and Vary for an allowed origin", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const resp = await withCors(
        new Request("https://relay.allw.test/acct/devices", {
          headers: { Origin: HOSTED_APPROVER },
        }),
        {},
        throwing,
      );

      expect(resp.status).toBe(500);
      expect(await resp.json()).toEqual({ error: "internal error" });
      expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(HOSTED_APPROVER);
      expect(resp.headers.get("Vary")).toBe("Origin");
      expect(error).toHaveBeenCalled();
    } finally {
      error.mockRestore();
    }
  });

  it("returns a 500 with Vary but no ACAO for a disallowed origin", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const resp = await withCors(
        new Request("https://relay.allw.test/acct/devices", {
          headers: { Origin: "https://evil.example" },
        }),
        {},
        throwing,
      );

      expect(resp.status).toBe(500);
      expectNoCorsGrant(resp);
      expect(resp.headers.get("Vary")).toBe("Origin");
    } finally {
      error.mockRestore();
    }
  });
});

/**
 * Strip `//` and `/* *\/` comments and trailing commas from JSONC, leaving string contents (which
 * hold `http://…` origins) untouched. Enough for the committed `wrangler.jsonc`.
 */
function parseJsonc(text: string): unknown {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] ?? "";
    if (inString) {
      out += c;
      if (c === "\\") out += text[++i] ?? "";
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      i = text.indexOf("*/", i + 2) + 1;
    } else {
      out += c;
    }
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

describe("committed wrangler.jsonc CORS configuration", () => {
  const config = parseJsonc(wranglerConfigText) as {
    vars?: { CORS_ALLOWED_ORIGINS?: string };
    env?: { production?: { vars?: { CORS_ALLOWED_ORIGINS?: string } } };
  };

  it("allows exactly the hosted web approver in production (no loopback)", () => {
    expect(config.env?.production?.vars?.CORS_ALLOWED_ORIGINS).toBe(HOSTED_APPROVER);
  });

  it("admits loopback only in the top-level dev config", () => {
    const dev = parseCorsAllowedOrigins(config.vars?.CORS_ALLOWED_ORIGINS);
    const prod = parseCorsAllowedOrigins(config.env?.production?.vars?.CORS_ALLOWED_ORIGINS);

    expect(isCorsOriginAllowed("http://localhost:5173", dev)).toBe(true);
    expect(isCorsOriginAllowed("http://localhost:5173", prod)).toBe(false);
    expect(isCorsOriginAllowed("http://127.0.0.1:5173", prod)).toBe(false);
  });
});

describe("parseCorsAllowedOrigins / isCorsOriginAllowed", () => {
  it("defaults to the hosted web approver alone when the var is unset", () => {
    const rules = parseCorsAllowedOrigins(undefined);

    expect(DEFAULT_CORS_ALLOWED_ORIGINS).toBe(HOSTED_APPROVER);
    expect(isCorsOriginAllowed(HOSTED_APPROVER, rules)).toBe(true);
    expect(isCorsOriginAllowed("http://localhost:5173", rules)).toBe(false);
  });

  it("allows no origin when the var is set but empty", () => {
    expect(parseCorsAllowedOrigins("")).toEqual([]);
    expect(isCorsOriginAllowed(HOSTED_APPROVER, parseCorsAllowedOrigins(" , "))).toBe(false);
  });

  it.each([
    ["an uppercase host", "https://Approver.Example.com", "https://approver.example.com"],
    ["the default https port", "https://approver.example.com:443", "https://approver.example.com"],
    ["the default http port", "http://approver.example.com:80", "http://approver.example.com"],
    ["a Unicode IDN host", "https://bücher.example", "https://xn--bcher-kva.example"],
  ])("normalizes an exact entry with %s to the origin a browser sends", (_name, entry, origin) => {
    const rules = parseCorsAllowedOrigins(entry);

    expect(rules).toEqual([{ kind: "exact", origin }]);
    expect(isCorsOriginAllowed(origin, rules)).toBe(true);
  });

  it("logs each dropped entry once, not on every request", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      // A value no other test parses, so the per-value memo starts cold.
      const value = "https://ok.example,https://dropped.example/app,https://*.wild.example";
      parseCorsAllowedOrigins(value);
      parseCorsAllowedOrigins(value);

      expect(warn).toHaveBeenCalledTimes(2);
      expect(warn).toHaveBeenCalledWith(expect.stringContaining("https://dropped.example/app"));
      expect(warn).toHaveBeenCalledWith(expect.stringContaining("https://*.wild.example"));
    } finally {
      warn.mockRestore();
    }
  });

  it.each([
    ["the opaque null origin", "null"],
    ["an entry with a path", "https://approver.example.com/app"],
    ["an entry with a trailing slash", "https://approver.example.com/"],
    ["an entry with a query", "https://approver.example.com?x=1"],
    ["an entry with a fragment", "https://approver.example.com#x"],
    ["a non-http scheme", "ftp://approver.example.com"],
    ["embedded credentials", "https://user:pw@approver.example.com"],
    ["a wildcard host", "https://*.example.com"],
    ["a bare wildcard", "*"],
  ])("drops %s rather than widening the allowlist", (_name, entry) => {
    expect(parseCorsAllowedOrigins(entry)).toEqual([]);
  });

  it("matches an any-port entry only on its scheme and host", () => {
    const rules = parseCorsAllowedOrigins("http://localhost:*");

    expect(isCorsOriginAllowed("http://localhost:3000", rules)).toBe(true);
    expect(isCorsOriginAllowed("http://localhost", rules)).toBe(true);
    expect(isCorsOriginAllowed("https://localhost:3000", rules)).toBe(false);
    expect(isCorsOriginAllowed("http://localhost.evil.example:3000", rules)).toBe(false);
  });

  it("does not match a request Origin that is not a serialized origin", () => {
    const rules = parseCorsAllowedOrigins(HOSTED_APPROVER);

    expect(isCorsOriginAllowed(`${HOSTED_APPROVER}/`, rules)).toBe(false);
    expect(isCorsOriginAllowed(`${HOSTED_APPROVER}/path`, rules)).toBe(false);
  });
});
