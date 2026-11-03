/**
 * Tests for the Web Push transport (#235): payload-less VAPID-authenticated wakeups, the
 * push-service endpoint allowlist (SSRF guard), VAPID configuration, and the relay-level public-key
 * endpoint. Runs in the Workers pool, so VAPID signing uses the real workerd WebCrypto.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8030 (Web Push: §5 TTL, §5.3 Urgency, §6–7 404/410)
 * @see https://www.rfc-editor.org/rfc/rfc8292 (VAPID: §2 JWT claims, §3 `vapid t=…, k=…`)
 * @see ../../../docs/relay-api.md (§5 Push wakeups)
 */

import { SELF, env } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import worker from "../src/index.js";
import { PushTokenGoneError } from "../src/push.js";
import {
  WebPushTransport,
  handleVapidPublicKey,
  parseWebPushEndpoint,
  vapidConfigFromEnv,
  webPushTtlSeconds,
  type VapidConfig,
} from "../src/web-push.js";

// ---------------------------------------------------------------------------
// Fixtures (fixed clock; never `Date.now()` in data)
// ---------------------------------------------------------------------------

/** 2023-11-14T22:13:20Z in ms — the injected "now" for every transport under test. */
const NOW_MS = 1_700_000_000_000;
/** A request deadline 5 minutes after `NOW_MS`. */
const EXPIRES_AT_MS = NOW_MS + 5 * 60 * 1000;

const FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send/dGVzdC1zdWJzY3JpcHRpb24";
const SUBJECT = "mailto:ops@allw.example";

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
}

/** A fresh VAPID keypair in the relay's configured shape, plus a key that verifies its JWTs. */
async function makeVapid(): Promise<{ config: VapidConfig; verifyKey: CryptoKey }> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(b64urlDecode(jwk.x ?? ""), 1);
  point.set(b64urlDecode(jwk.y ?? ""), 33);
  return {
    config: { publicKey: b64url(point), privateKey: jwk.d ?? "", subject: SUBJECT },
    verifyKey: pair.publicKey,
  };
}

function capturingFetcher(status: number) {
  return vi.fn<typeof fetch>(async () => new Response(null, { status }));
}

function wakeup(token = FCM_ENDPOINT) {
  return {
    accountId: "acct-web-push",
    deviceId: "dev-web",
    requestId: "req-web-push",
    expiresAt: EXPIRES_AT_MS,
    token,
  };
}

function onlyCall(fetcher: ReturnType<typeof capturingFetcher>): [string, RequestInit] {
  expect(fetcher).toHaveBeenCalledTimes(1);
  const [input, init] = fetcher.mock.calls[0] ?? [];
  return [String(input), init ?? {}];
}

// ---------------------------------------------------------------------------
// Endpoint allowlist (SSRF guard)
// ---------------------------------------------------------------------------

describe("parseWebPushEndpoint — push-service allowlist", () => {
  it.each([
    ["FCM (Chrome)", "https://fcm.googleapis.com/fcm/send/abc"],
    ["Mozilla autopush (Firefox)", "https://updates.push.services.mozilla.com/wpush/v2/abc"],
    ["Apple (Safari)", "https://web.push.apple.com/QGx0abc"],
    ["Windows WNS (Edge)", "https://wns2-by3p.notify.windows.com/w/?token=abc"],
  ])("accepts a %s subscription endpoint", (_name, endpoint) => {
    expect(parseWebPushEndpoint(endpoint)?.href).toBe(new URL(endpoint).href);
  });

  it.each([
    ["plain http", "http://fcm.googleapis.com/fcm/send/abc"],
    ["a non-allowlisted host", "https://push.attacker.example/abc"],
    ["non-URL input", "not a url"],
    ["an internal address", "https://127.0.0.1/abc"],
    ["a lookalike suffix", "https://fcm.googleapis.com.attacker.example/abc"],
    ["a host merely ending in the WNS suffix text", "https://evilnotify.windows.com/w/"],
    ["the bare WNS apex", "https://notify.windows.com/w/"],
    ["an explicit port", "https://fcm.googleapis.com:8443/fcm/send/abc"],
    ["embedded credentials", "https://user:pass@fcm.googleapis.com/fcm/send/abc"],
    ["a non-https scheme", "ftp://fcm.googleapis.com/abc"],
  ])("rejects %s", (_name, endpoint) => {
    expect(parseWebPushEndpoint(endpoint)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// VAPID configuration
// ---------------------------------------------------------------------------

describe("vapidConfigFromEnv — Web Push is enabled only when fully configured", () => {
  it("returns the config when public key, private key, and subject are all valid", async () => {
    const { config } = await makeVapid();
    expect(
      vapidConfigFromEnv({
        VAPID_PUBLIC_KEY: config.publicKey,
        VAPID_PRIVATE_KEY: config.privateKey,
        VAPID_SUBJECT: config.subject,
      }),
    ).toEqual(config);
  });

  it("accepts an https: subject (RFC 8292 §2.1)", async () => {
    const { config } = await makeVapid();
    expect(
      vapidConfigFromEnv({
        VAPID_PUBLIC_KEY: config.publicKey,
        VAPID_PRIVATE_KEY: config.privateKey,
        VAPID_SUBJECT: "https://allw.example/contact",
      })?.subject,
    ).toBe("https://allw.example/contact");
  });

  it.each(["VAPID_PUBLIC_KEY", "VAPID_PRIVATE_KEY", "VAPID_SUBJECT"] as const)(
    "is disabled when %s is missing",
    async (missing) => {
      const { config } = await makeVapid();
      const full = {
        VAPID_PUBLIC_KEY: config.publicKey,
        VAPID_PRIVATE_KEY: config.privateKey,
        VAPID_SUBJECT: config.subject,
      };
      const { [missing]: _omitted, ...partial } = full;
      expect(vapidConfigFromEnv(partial)).toBeNull();
    },
  );

  it("is disabled for a public key that is not a 65-byte uncompressed P-256 point", async () => {
    const { config } = await makeVapid();
    const compressedPrefix = b64urlDecode(config.publicKey);
    compressedPrefix[0] = 0x02;
    for (const publicKey of [b64url(new Uint8Array(33)), b64url(compressedPrefix), "not*b64"]) {
      expect(
        vapidConfigFromEnv({
          VAPID_PUBLIC_KEY: publicKey,
          VAPID_PRIVATE_KEY: config.privateKey,
          VAPID_SUBJECT: SUBJECT,
        }),
      ).toBeNull();
    }
  });

  it("is disabled for a private key that is not a 32-byte scalar", async () => {
    const { config } = await makeVapid();
    expect(
      vapidConfigFromEnv({
        VAPID_PUBLIC_KEY: config.publicKey,
        VAPID_PRIVATE_KEY: b64url(new Uint8Array(31)),
        VAPID_SUBJECT: SUBJECT,
      }),
    ).toBeNull();
  });

  it.each(["ops@allw.example", "mailto:", "http://allw.example/contact"])(
    "is disabled for a subject that is not a mailto:/https: URI (%s)",
    async (subject) => {
      const { config } = await makeVapid();
      expect(
        vapidConfigFromEnv({
          VAPID_PUBLIC_KEY: config.publicKey,
          VAPID_PRIVATE_KEY: config.privateKey,
          VAPID_SUBJECT: subject,
        }),
      ).toBeNull();
    },
  );
});

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

describe("WebPushTransport — payload-less VAPID wakeup", () => {
  it("POSTs an empty body to the subscription endpoint with TTL, Urgency, and VAPID auth", async () => {
    const { config } = await makeVapid();
    const fetcher = capturingFetcher(201);
    const transport = new WebPushTransport({ vapid: config, fetcher, now: () => NOW_MS });

    await transport.sendWakeup(wakeup());

    const [url, init] = onlyCall(fetcher);
    expect(url).toBe(FCM_ENDPOINT);
    expect(init.method).toBe("POST");
    // RFC 8030 §5: the wakeup carries no payload at all — not even the request id.
    const sent = new Request(url, init);
    expect((await sent.arrayBuffer()).byteLength).toBe(0);
    const headers = new Headers(init.headers);
    expect(headers.get("TTL")).toBe("300"); // RFC 8030 §5.2: the request's remaining 5 minutes.
    expect(headers.get("Urgency")).toBe("high"); // RFC 8030 §5.3.
    expect(headers.get("Content-Encoding")).toBeNull(); // no RFC 8291 payload to encode.
    expect(headers.get("Authorization")).toMatch(
      new RegExp(`^vapid t=[\\w-]+\\.[\\w-]+\\.[\\w-]+, k=${config.publicKey}$`),
    );
    // Never follow a redirect off the allowlisted host.
    expect(init.redirect).toBe("manual");
  });

  it("signs an ES256 VAPID JWT bound to the push-service origin (RFC 8292 §2)", async () => {
    const { config, verifyKey } = await makeVapid();
    const fetcher = capturingFetcher(201);
    const transport = new WebPushTransport({ vapid: config, fetcher, now: () => NOW_MS });

    await transport.sendWakeup(wakeup());

    const [, init] = onlyCall(fetcher);
    const jwt = /vapid t=([^,]+),/.exec(new Headers(init.headers).get("Authorization") ?? "")?.[1];
    const [header, claims, signature] = (jwt ?? "").split(".");
    expect(JSON.parse(new TextDecoder().decode(b64urlDecode(header ?? "")))).toEqual({
      typ: "JWT",
      alg: "ES256",
    });
    expect(JSON.parse(new TextDecoder().decode(b64urlDecode(claims ?? "")))).toEqual({
      aud: "https://fcm.googleapis.com", // §2: the push resource's origin.
      exp: NOW_MS / 1000 + 3600, // §2: within 24h; one hour from the injected clock.
      sub: SUBJECT, // §2.1: operator contact.
    });
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verifyKey,
      b64urlDecode(signature ?? ""),
      new TextEncoder().encode(`${header ?? ""}.${claims ?? ""}`),
    );
    expect(valid).toBe(true);
  });

  it.each([404, 410])("reports HTTP %i as a gone subscription (prune signal)", async (status) => {
    const { config } = await makeVapid();
    const transport = new WebPushTransport({
      vapid: config,
      fetcher: capturingFetcher(status),
      now: () => NOW_MS,
    });

    await expect(transport.sendWakeup(wakeup())).rejects.toBeInstanceOf(PushTokenGoneError);
  });

  it.each([400, 403, 413, 429, 500, 503, 301])(
    "treats HTTP %i as a transient failure, not a gone subscription",
    async (status) => {
      const { config } = await makeVapid();
      const transport = new WebPushTransport({
        vapid: config,
        fetcher: capturingFetcher(status),
        now: () => NOW_MS,
      });

      const failure = await transport.sendWakeup(wakeup()).then(
        () => null,
        (error: unknown) => error,
      );
      expect(failure).toBeInstanceOf(Error);
      expect(failure).not.toBeInstanceOf(PushTokenGoneError);
    },
  );

  it("refuses to send to a stored endpoint outside the allowlist without making a request", async () => {
    const { config } = await makeVapid();
    const fetcher = capturingFetcher(201);
    const transport = new WebPushTransport({ vapid: config, fetcher, now: () => NOW_MS });

    await expect(
      transport.sendWakeup(wakeup("https://169.254.169.254/latest/meta-data")),
    ).rejects.toThrow(/allowlist/);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("fails every send when the private key does not import", async () => {
    const { config } = await makeVapid();
    const fetcher = capturingFetcher(201);
    // A 32-byte scalar of all zeros is not a valid P-256 private key.
    const broken = { ...config, privateKey: b64url(new Uint8Array(32)) };
    const transport = new WebPushTransport({ vapid: broken, fetcher, now: () => NOW_MS });

    await expect(transport.sendWakeup(wakeup())).rejects.toBeInstanceOf(Error);
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("webPushTtlSeconds", () => {
  it("rounds the remaining lifetime up to whole seconds", () => {
    expect(webPushTtlSeconds(NOW_MS + 1500, NOW_MS)).toBe(2);
  });

  it("never goes negative for an already-past deadline", () => {
    expect(webPushTtlSeconds(NOW_MS - 10_000, NOW_MS)).toBe(0);
  });

  it("clamps to the 28-day push-service ceiling", () => {
    const ninetyDays = 90 * 24 * 60 * 60 * 1000;
    expect(webPushTtlSeconds(NOW_MS + ninetyDays, NOW_MS)).toBe(28 * 24 * 60 * 60);
  });
});

// ---------------------------------------------------------------------------
// GET /push/vapid-public-key (relay-level, unauthenticated)
// ---------------------------------------------------------------------------

describe("GET /push/vapid-public-key", () => {
  const url = "https://relay.allw.test/push/vapid-public-key";

  it("serves the configured VAPID public key without auth", async () => {
    const { config } = await makeVapid();
    const configuredEnv = {
      ...env,
      VAPID_PUBLIC_KEY: config.publicKey,
      VAPID_PRIVATE_KEY: config.privateKey,
      VAPID_SUBJECT: config.subject,
    };

    const resp = await worker.fetch(new Request(url), configuredEnv);

    expect(resp.status).toBe(200);
    const body: unknown = await resp.json();
    // Only the public key — never the private key or subject.
    expect(body).toEqual({ vapid_public_key: config.publicKey });
  });

  it("is 404 when Web Push is not configured (the test Worker has no VAPID bindings)", async () => {
    const resp = await SELF.fetch(url);

    expect(resp.status).toBe(404);
    expect(await resp.json()).toEqual({ error: "web push is not configured" });
  });

  it("is 405 for a non-GET method", async () => {
    const { config } = await makeVapid();
    const resp = handleVapidPublicKey(new Request(url, { method: "POST" }), {
      VAPID_PUBLIC_KEY: config.publicKey,
      VAPID_PRIVATE_KEY: config.privateKey,
      VAPID_SUBJECT: config.subject,
    });

    expect(resp.status).toBe(405);
  });
});
