/**
 * Tests for the Web Push transport (#235): payload-less VAPID-authenticated wakeups, the
 * push-service endpoint allowlist (SSRF guard), VAPID configuration, and the relay-level public-key
 * endpoint. Runs in the Workers pool, so VAPID signing uses the real workerd WebCrypto.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8030 (Web Push: §5 TTL, §5.3 Urgency, §5.4 Topic, §6–7 404/410)
 * @see https://autopush.readthedocs.io/en/latest/http.html (Mozilla autopush: Topic support)
 * @see https://www.rfc-editor.org/rfc/rfc8292 (VAPID: §2 JWT claims, §3 `vapid t=…, k=…`)
 * @see https://www.rfc-editor.org/rfc/rfc8615 (Well-Known URIs: the relay-level namespace)
 * @see ../../../docs/relay-api.md (§5 Push wakeups)
 */

import { env, exports } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import worker from "../src/index.js";
import { UndeliverablePushTokenError } from "../src/push.js";
import {
  WEB_PUSH_TOPIC,
  WebPushTransport,
  loadVapidSigningKey,
  parseWebPushEndpoint,
  vapidConfigFromEnv,
  webPushTtlSeconds,
  type VapidConfig,
} from "../src/web-push.js";
import { urlOf } from "./support/fetch-input.js";

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
  return vi.fn<typeof fetch>(() => Promise.resolve(new Response(null, { status })));
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
  return [urlOf(input), init ?? {}];
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
    ["a WNS host with digits and hyphens", "https://db5p-1.notify.windows.com/w/?token=abc"],
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
    ["a trailing-dot host", "https://fcm.googleapis.com./fcm/send/abc"],
    // A fragment never reaches the wire, so it would let one subscription be stored twice.
    ["a fragment", "https://fcm.googleapis.com/fcm/send/abc#dup"],
    ["an empty fragment", "https://fcm.googleapis.com/fcm/send/abc#"],
    // WNS: exactly one label under notify.windows.com.
    ["a two-label WNS subdomain", "https://a.b.notify.windows.com/w/"],
    ["an empty WNS label", "https://..notify.windows.com/w/"],
    ["a leading-dot WNS host", "https://.notify.windows.com/w/"],
    ["an IP-like WNS prefix", "https://169.254.169.254.notify.windows.com/w/"],
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
    // RFC 8030 §5.2: 5 minutes remain, which is exactly the 5-minute TTL bucket.
    expect(headers.get("TTL")).toBe("300");
    expect(headers.get("Urgency")).toBe("high"); // RFC 8030 §5.3.
    expect(headers.get("Content-Encoding")).toBeNull(); // no RFC 8291 payload to encode.
    expect(headers.get("Authorization")).toMatch(
      new RegExp(`^vapid t=[\\w-]+\\.[\\w-]+\\.[\\w-]+, k=${config.publicKey}$`),
    );
    // Never follow a redirect off the allowlisted host.
    expect(init.redirect).toBe("manual");
  });

  it.each([
    // Autopush documents Topic: one queued wakeup per subscription instead of one per request.
    ["Mozilla autopush", "https://updates.push.services.mozilla.com/wpush/v2/abc", WEB_PUSH_TOPIC],
    // Apple answers any Topic with 400 BadWebPushTopic, which would fail every Safari/iOS wakeup.
    ["Apple", "https://web.push.apple.com/QGx0abc", null],
    // FCM and WNS document no Topic support for Web Push, so they get none until verified.
    ["FCM", "https://fcm.googleapis.com/fcm/send/abc", null],
    ["WNS", "https://wns2-by3p.notify.windows.com/w/?token=abc", null],
  ])("sends the Topic header to %s only where documented", async (_name, endpoint, expected) => {
    const { config } = await makeVapid();
    const fetcher = capturingFetcher(201);
    const transport = new WebPushTransport({ vapid: config, fetcher, now: () => NOW_MS });

    await transport.sendWakeup(wakeup(endpoint));

    const [, init] = onlyCall(fetcher);
    expect(new Headers(init.headers).get("Topic")).toBe(expected);
  });

  it("uses a Topic that RFC 8030 §5.4 and autopush both accept", () => {
    // §5.4: at most 32 characters from the base64url alphabet. Autopush: `[A-Za-z0-9_-]`, max 32.
    expect(WEB_PUSH_TOPIC).toMatch(/^[A-Za-z0-9_-]{1,32}$/);
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

    await expect(transport.sendWakeup(wakeup())).rejects.toBeInstanceOf(
      UndeliverablePushTokenError,
    );
  });

  it.each([400, 401, 403, 413, 429, 500, 503, 301])(
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
      expect(failure).not.toBeInstanceOf(UndeliverablePushTokenError);
    },
  );

  it("refuses a stored endpoint outside the allowlist as transient (kept, logged), without a request", async () => {
    const { config } = await makeVapid();
    const fetcher = capturingFetcher(201);
    const transport = new WebPushTransport({ vapid: config, fetcher, now: () => NOW_MS });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    try {
      const failure = await transport
        .sendWakeup(wakeup("https://169.254.169.254/latest/meta-data"))
        .then(
          () => null,
          (error: unknown) => error,
        );

      // A relay-side refusal is not the push service saying the subscription is gone: never prune.
      expect(failure).toBeInstanceOf(Error);
      expect(failure).not.toBeInstanceOf(UndeliverablePushTokenError);
      expect(fetcher).not.toHaveBeenCalled();
      expect(warn).toHaveBeenCalledWith(expect.stringMatching(/outside the allowlist/));
    } finally {
      warn.mockRestore();
    }
  });

  it("aborts a hung push service at the timeout, as a transient failure", async () => {
    const { config } = await makeVapid();
    // Never answers; settles only when the transport's AbortSignal fires.
    const hanging = vi.fn<typeof fetch>(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(init.signal?.reason as Error);
          });
        }),
    );
    const transport = new WebPushTransport({
      vapid: config,
      fetcher: hanging,
      now: () => NOW_MS,
      timeoutMs: 20,
    });

    const failure = await transport.sendWakeup(wakeup()).then(
      () => null,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(UndeliverablePushTokenError);
    expect(hanging.mock.calls[0]?.[1]?.signal).toBeInstanceOf(AbortSignal);
  });

  it("cancels the push-service response body instead of leaving it unconsumed", async () => {
    const { config } = await makeVapid();
    const cancelled = vi.fn();
    const fetcher = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        new Response(new ReadableStream({ cancel: cancelled }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    const transport = new WebPushTransport({ vapid: config, fetcher, now: () => NOW_MS });

    await expect(transport.sendWakeup(wakeup())).rejects.toBeInstanceOf(Error);
    expect(cancelled).toHaveBeenCalledTimes(1);
  });

  it("makes no request when the private key is not a valid P-256 scalar", async () => {
    const { config } = await makeVapid();
    const fetcher = capturingFetcher(201);
    // A 32-byte scalar of all zeros is not a valid P-256 private key.
    const broken = { ...config, privateKey: b64url(new Uint8Array(32)) };
    const transport = new WebPushTransport({ vapid: broken, fetcher, now: () => NOW_MS });

    const failure = await transport.sendWakeup(wakeup()).then(
      () => null,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(UndeliverablePushTokenError);
    expect(fetcher).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// VAPID keypair validation (shared by the transport and the endpoint)
// ---------------------------------------------------------------------------

/** A keypair whose public half is valid but belongs to a different private key. */
async function mismatchedVapid(): Promise<VapidConfig> {
  const a = await makeVapid();
  const b = await makeVapid();
  return { ...a.config, privateKey: b.config.privateKey };
}

/** A well-formed 65-byte `0x04…` point that is not on the P-256 curve. */
async function offCurveVapid(): Promise<VapidConfig> {
  const { config } = await makeVapid();
  const point = b64urlDecode(config.publicKey);
  point[64] = (point[64] ?? 0) ^ 0x01; // flip one bit of Y: (X, Y') is not on the curve
  return { ...config, publicKey: b64url(point) };
}

describe("WebPushTransport — a push-service rejection is logged with its reason (#326)", () => {
  const APPLE_ENDPOINT = "https://web.push.apple.com/QGFwcGxlLXN1YnNjcmlwdGlvbi1zZWNyZXQ";
  const APPLE_PATH = "/QGFwcGxlLXN1YnNjcmlwdGlvbi1zZWNyZXQ";

  /** Run one wakeup to `endpoint` answered by `response`; the relay's push-rejection warnings. */
  async function warningsFor(
    response: () => Response,
    endpoint = APPLE_ENDPOINT,
  ): Promise<{ warnings: string[]; failure: unknown; authorization: string }> {
    const { config } = await makeVapid();
    const fetcher = vi.fn<typeof fetch>(() => Promise.resolve(response()));
    const transport = new WebPushTransport({ vapid: config, fetcher, now: () => NOW_MS });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      const failure = await transport.sendWakeup(wakeup(endpoint)).then(
        () => null,
        (error: unknown) => error,
      );
      const init = fetcher.mock.calls[0]?.[1];
      return {
        warnings: warn.mock.calls
          .map((call) => String(call[0]))
          .filter((message) => message.startsWith("push:")),
        failure,
        authorization: new Headers(init?.headers).get("Authorization") ?? "",
      };
    } finally {
      warn.mockRestore();
    }
  }

  it("logs Apple's 400 BadWebPushTopic with host, status and reason, and keeps the token", async () => {
    const { warnings, failure, authorization } = await warningsFor(
      () => new Response(JSON.stringify({ reason: "BadWebPushTopic" }), { status: 400 }),
    );

    expect(warnings).toEqual([
      "push: webpush push service web.push.apple.com rejected a wakeup with HTTP 400 (reason BadWebPushTopic); token kept",
    ]);
    // Transient: the token is not pruned.
    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(UndeliverablePushTokenError);
    // The subscription path is a bearer capability; the JWT and the request id stay out too.
    for (const secret of [APPLE_PATH, APPLE_ENDPOINT, authorization, "req-web-push"]) {
      expect(warnings[0]).not.toContain(secret);
    }
  });

  it("logs a 4xx without a reason when the body has none, or one that is not an identifier", async () => {
    for (const body of [
      "Forbidden",
      JSON.stringify({ error: "x" }),
      JSON.stringify({ reason: 42 }),
      JSON.stringify(["BadJwtToken"]),
      // A reason echoing the endpoint's path token (an identifier-shaped bearer capability) would
      // put the capability in the log; it is dropped because it occurs in the endpoint.
      JSON.stringify({ reason: APPLE_PATH.slice(1) }),
      // So is any piece of the token, and the full endpoint.
      JSON.stringify({ reason: APPLE_PATH.slice(1, 20) }),
      JSON.stringify({ reason: APPLE_ENDPOINT }),
      // Longer than any documented reason: a token-sized identifier is not logged either.
      JSON.stringify({ reason: "A".repeat(33) }),
      JSON.stringify({ reason: "Bad reason\nwith a forged log line" }),
    ]) {
      const { warnings } = await warningsFor(() => new Response(body, { status: 403 }));

      expect(warnings).toEqual([
        "push: webpush push service web.push.apple.com rejected a wakeup with HTTP 403; token kept",
      ]);
    }
  });

  it("logs a reason up to 32 characters, such as Apple's longest", async () => {
    for (const reason of ["TooManyProviderTokenUpdates", "B".repeat(32)]) {
      const { warnings } = await warningsFor(
        () => new Response(JSON.stringify({ reason }), { status: 429 }),
      );

      expect(warnings).toEqual([
        `push: webpush push service web.push.apple.com rejected a wakeup with HTTP 429 (reason ${reason}); token kept`,
      ]);
    }
  });

  it.each([
    [400, "rejection", Error],
    [201, "success", null],
  ] as const)(
    "does not wait for a body cancel that never settles (HTTP %i, %s)",
    async (status, _kind, expected) => {
      const { config } = await makeVapid();
      const cancelled = vi.fn(() => new Promise<void>(() => undefined));
      const fetcher = vi.fn<typeof fetch>(() =>
        Promise.resolve(
          new Response(
            new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new TextEncoder().encode('{"reason":"BadJwtToken"}'));
              },
              cancel: cancelled,
            }),
            { status },
          ),
        ),
      );
      const transport = new WebPushTransport({ vapid: config, fetcher, now: () => NOW_MS });
      const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
      try {
        const outcome = await Promise.race([
          transport.sendWakeup(wakeup(APPLE_ENDPOINT)).then(
            () => null,
            (error: unknown) => error,
          ),
          new Promise((resolve) =>
            setTimeout(() => {
              resolve("hung");
            }, 3_000),
          ),
        ]);

        if (expected === null) expect(outcome).toBeNull();
        else expect(outcome).toBeInstanceOf(expected);
        expect(cancelled).toHaveBeenCalledTimes(1);
      } finally {
        warn.mockRestore();
      }
    },
  );

  it("reads only a bounded prefix of an endless body, then releases it", async () => {
    const cancelled = vi.fn();
    let pulls = 0;
    const chunk = new TextEncoder().encode(" ".repeat(4096));
    const { warnings } = await warningsFor(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            pull(controller) {
              pulls++;
              controller.enqueue(chunk);
            },
            cancel: cancelled,
          }),
          { status: 400 },
        ),
    );

    expect(warnings).toHaveLength(1);
    expect(cancelled).toHaveBeenCalledTimes(1);
    // One 4 KiB chunk already exceeds the 1 KiB cap; the stream's read-ahead may add a pull or two.
    expect(pulls).toBeLessThanOrEqual(3);
  });

  it("gives up on a stalled body after a bounded wait, then releases it", async () => {
    const cancelled = vi.fn();
    const started = Date.now();
    const { warnings } = await warningsFor(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new TextEncoder().encode('{"reason":'));
            },
            cancel: cancelled,
          }),
          { status: 400 },
        ),
    );

    expect(warnings).toEqual([
      "push: webpush push service web.push.apple.com rejected a wakeup with HTTP 400; token kept",
    ]);
    expect(cancelled).toHaveBeenCalledTimes(1);
    expect(Date.now() - started).toBeLessThan(4_000);
  });

  it.each([201, 301, 404, 410, 500, 503])("does not log HTTP %i as a rejection", async (status) => {
    const { warnings } = await warningsFor(
      () => new Response(JSON.stringify({ reason: "Whatever" }), { status }),
    );

    expect(warnings).toEqual([]);
  });

  it("does not log a timeout or network failure as a rejection", async () => {
    const { config } = await makeVapid();
    const transport = new WebPushTransport({
      vapid: config,
      // No response at all, as when the AbortSignal fires or the connection fails.
      fetcher: () => {
        throw new Error("The operation was aborted due to timeout");
      },
      now: () => NOW_MS,
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      await expect(transport.sendWakeup(wakeup(APPLE_ENDPOINT))).rejects.toBeInstanceOf(Error);
      expect(warn.mock.calls.filter((call) => String(call[0]).startsWith("push:"))).toEqual([]);
    } finally {
      warn.mockRestore();
    }
  });
});

describe("loadVapidSigningKey — the keypair must actually match", () => {
  it("accepts a genuine keypair", async () => {
    const { config } = await makeVapid();

    await expect(loadVapidSigningKey(config)).resolves.toBeInstanceOf(CryptoKey);
  });

  it.each([
    ["a mismatched pair (public and private from different keys)", mismatchedVapid],
    ["an off-curve public point", offCurveVapid],
  ])("rejects %s, and the transport then makes no request", async (_name, build) => {
    const vapid = await build();
    // Factsally fine: only the cryptographic check can catch these.
    expect(
      vapidConfigFromEnv({
        VAPID_PUBLIC_KEY: vapid.publicKey,
        VAPID_PRIVATE_KEY: vapid.privateKey,
        VAPID_SUBJECT: vapid.subject,
      }),
    ).not.toBeNull();
    await expect(loadVapidSigningKey(vapid)).resolves.toBeNull();

    const fetcher = capturingFetcher(201);
    const transport = new WebPushTransport({ vapid, fetcher, now: () => NOW_MS });
    await expect(transport.sendWakeup(wakeup())).rejects.toBeInstanceOf(Error);
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("webPushTtlSeconds — remaining lifetime rounded up to a coarse bucket", () => {
  const SECOND = 1000;
  const MINUTE = 60 * SECOND;
  const HOUR = 60 * MINUTE;
  const DAY = 24 * HOUR;

  // Buckets (relay-api.md §5): 60 s, 5 min, 1 h, 1 d, 28 d. Each boundary maps to its own bucket and
  // one second past it to the next, so the push service never learns the exact deadline.
  it.each([
    ["1.5 s", 1500, 60],
    ["exactly 60 s", MINUTE, 60],
    ["60 s + 1 s", MINUTE + SECOND, 5 * 60],
    ["exactly 5 min", 5 * MINUTE, 5 * 60],
    ["5 min + 1 s", 5 * MINUTE + SECOND, 60 * 60],
    ["exactly 1 h", HOUR, 60 * 60],
    ["1 h + 1 s", HOUR + SECOND, 24 * 60 * 60],
    ["exactly 1 d", DAY, 24 * 60 * 60],
    ["1 d + 1 s", DAY + SECOND, 28 * 24 * 60 * 60],
    ["exactly 28 d", 28 * DAY, 28 * 24 * 60 * 60],
  ])("maps %s remaining to the next bucket up", (_name, remainingMs, ttl) => {
    expect(webPushTtlSeconds(NOW_MS + remainingMs, NOW_MS)).toBe(ttl);
  });

  it("is 0 for an already-past deadline", () => {
    expect(webPushTtlSeconds(NOW_MS - 10_000, NOW_MS)).toBe(0);
    expect(webPushTtlSeconds(NOW_MS, NOW_MS)).toBe(0);
  });

  it("caps at the 28-day push-service ceiling", () => {
    expect(webPushTtlSeconds(NOW_MS + 90 * DAY, NOW_MS)).toBe(28 * 24 * 60 * 60);
    expect(webPushTtlSeconds(Infinity, NOW_MS)).toBe(28 * 24 * 60 * 60);
  });

  it("fails toward a short TTL when the deadline or clock is not a number (review-322 N1)", () => {
    // NaN used to fall through every bucket comparison to the 28-day cap.
    expect(webPushTtlSeconds(Number.NaN, NOW_MS)).toBe(0);
    expect(webPushTtlSeconds(NOW_MS + 60_000, Number.NaN)).toBe(0);
    expect(webPushTtlSeconds(-Infinity, NOW_MS)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// GET /.well-known/allw/vapid-public-key (relay-level, unauthenticated)
// ---------------------------------------------------------------------------

function vapidEnv(vapid: VapidConfig) {
  return {
    ...env,
    VAPID_PUBLIC_KEY: vapid.publicKey,
    VAPID_PRIVATE_KEY: vapid.privateKey,
    VAPID_SUBJECT: vapid.subject,
  };
}

describe("GET /.well-known/allw/vapid-public-key", () => {
  const url = "https://relay.allw.test/.well-known/allw/vapid-public-key";

  it("serves the configured VAPID public key without auth, cacheably", async () => {
    const { config } = await makeVapid();

    const resp = await worker.fetch(new Request(url), vapidEnv(config));

    expect(resp.status).toBe(200);
    expect(resp.headers.get("Cache-Control")).toBe("public, max-age=3600");
    const body: unknown = await resp.json();
    // Only the public key — never the private key or subject.
    expect(body).toEqual({ vapid_public_key: config.publicKey });
  });

  it("answers HEAD with the GET headers and no body", async () => {
    const { config } = await makeVapid();

    const resp = await worker.fetch(new Request(url, { method: "HEAD" }), vapidEnv(config));

    expect(resp.status).toBe(200);
    expect(resp.headers.get("Cache-Control")).toBe("public, max-age=3600");
    expect(await resp.text()).toBe("");
  });

  it("is 404 when Web Push is not configured (the test Worker has no VAPID bindings)", async () => {
    const resp = await exports.default.fetch(url);

    expect(resp.status).toBe(404);
    expect(await resp.json()).toEqual({ error: "web push is not configured" });
  });

  it.each([
    ["a mismatched pair", mismatchedVapid],
    ["an off-curve public point", offCurveVapid],
  ])("is 404 for %s, so browsers never subscribe with an unusable key", async (_name, build) => {
    const resp = await worker.fetch(new Request(url), vapidEnv(await build()));

    expect(resp.status).toBe(404);
  });

  it("is 405 for a method other than GET or HEAD", async () => {
    const { config } = await makeVapid();

    const resp = await worker.fetch(new Request(url, { method: "POST" }), vapidEnv(config));

    expect(resp.status).toBe(405);
    expect(resp.headers.get("Allow")).toBe("GET, HEAD");
  });

  it.each(["/.well-known/allw/unknown", "/.well-known/allw/vapid-public-key/", "/.well-known"])(
    "keeps the relay-level namespace closed: %s is 404 and never reaches an account",
    async (path) => {
      const { config } = await makeVapid();

      const resp = await worker.fetch(
        new Request(`https://relay.allw.test${path}`),
        vapidEnv(config),
      );

      expect(resp.status).toBe(404);
      expect(await resp.json()).toEqual({ error: "not found" });
    },
  );

  it("no longer serves the key under the account namespace (/push/…)", async () => {
    const { config } = await makeVapid();

    const resp = await worker.fetch(
      new Request("https://relay.allw.test/push/vapid-public-key"),
      vapidEnv(config),
    );

    // Routed to the account literally named "push", which has no such route.
    expect(resp.status).toBe(404);
    expect(await resp.text()).not.toContain(config.publicKey);
  });
});
