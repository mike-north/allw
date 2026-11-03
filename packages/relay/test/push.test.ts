/**
 * Tests for the relay push fan-out seam (#17).
 *
 * The relay must keep routing independent from vendor-specific push APIs: routing emits a
 * request-id-only wakeup, while APNs/FCM/Web Push transports decide how to deliver it.
 *
 * @see ../../../docs/relay-api.md (§5 Push wakeups)
 */

import { describe, expect, it, vi } from "vitest";
import {
  ApnsPushTransport,
  FcmPushTransport,
  InMemoryWakeupClaimStore,
  UndeliverablePushTokenError,
  WEB_PUSH_COALESCE_MS,
  WakeupCoalescer,
  buildPushWakeupPayload,
  diffPushTokenSet,
  dispatchPushWakeups,
  isClientErrorStatus,
  parseWebPushCoalesceKey,
  webPushCoalesceKey,
  type Fetcher,
  type PushTransport,
  type StoredPushToken,
} from "../src/push.js";

/** A fixed request deadline (2100-01-01Z, ms); never `Date.now()` in test data. */
const EXPIRES_AT = 4102444800000;

describe("push fan-out", () => {
  it("builds a wakeup payload containing only the request id", () => {
    const payload = buildPushWakeupPayload("req-push-only-id");

    expect(payload).toEqual({ request_id: "req-push-only-id" });
    expect(payload).not.toHaveProperty("envelope");
    expect(payload).not.toHaveProperty("context_ciphertext");
    expect(payload).not.toHaveProperty("action");
    expect(payload).not.toHaveProperty("summary");
  });

  it("dispatches through swappable transports without routing knowing vendor details", async () => {
    const sent: Array<{ kind: string; deviceId: string; requestId: string; token: string }> = [];
    const apns: PushTransport = {
      kind: "apns",
      async sendWakeup(wakeup) {
        sent.push({ kind: "apns", ...wakeup });
      },
    };
    const fcm: PushTransport = {
      kind: "fcm",
      async sendWakeup(wakeup) {
        sent.push({ kind: "fcm", ...wakeup });
      },
    };
    const tokens: StoredPushToken[] = [
      { device_id: "dev-a", transport: "apns", token: "apns-token" },
      { device_id: "dev-b", transport: "fcm", token: "fcm-token" },
    ];

    const result = await dispatchPushWakeups(tokens, {
      accountId: "acct-push-swap",
      requestId: "req-push-swap",
      expiresAt: EXPIRES_AT,
      transports: { apns, fcm },
    });

    // Both providers accepted their wakeup, so both tokens are reported delivered.
    expect(result).toEqual({ deliveredTokens: tokens, undeliverableTokens: [] });
    expect(sent).toEqual([
      {
        kind: "apns",
        accountId: "acct-push-swap",
        deviceId: "dev-a",
        requestId: "req-push-swap",
        expiresAt: EXPIRES_AT,
        token: "apns-token",
      },
      {
        kind: "fcm",
        accountId: "acct-push-swap",
        deviceId: "dev-b",
        requestId: "req-push-swap",
        expiresAt: EXPIRES_AT,
        token: "fcm-token",
      },
    ]);
  });

  it("formats APNs and FCM requests while keeping only request_id in the logical wakeup", async () => {
    const fetcher = vi.fn<Fetcher>(async () => new Response(null, { status: 202 }));
    const apns = new ApnsPushTransport({
      endpoint: "https://api.push.apple.test",
      topic: "com.example.allw",
      bearerToken: "apns-bearer",
      fetcher,
    });
    const fcm = new FcmPushTransport({
      endpoint: "https://fcm.googleapis.test/v1/projects/allw/messages:send",
      bearerToken: "fcm-bearer",
      fetcher,
    });

    await apns.sendWakeup({
      accountId: "acct",
      deviceId: "dev-ios",
      requestId: "req-format",
      expiresAt: EXPIRES_AT,
      token: "apns-token",
    });
    await fcm.sendWakeup({
      accountId: "acct",
      deviceId: "dev-android",
      requestId: "req-format",
      expiresAt: EXPIRES_AT,
      token: "fcm-token",
    });

    const apnsBody = JSON.parse(fetcher.mock.calls[0]?.[1]?.body as string) as {
      request_id?: string;
      context_ciphertext?: string;
    };
    expect(apnsBody.request_id).toBe("req-format");
    expect(apnsBody.context_ciphertext).toBeUndefined();

    const fcmBody = JSON.parse(fetcher.mock.calls[1]?.[1]?.body as string) as {
      message?: { data?: Record<string, string> };
    };
    expect(fcmBody.message?.data).toEqual({ request_id: "req-format" });
  });

  it("does not fail the relay dispatch when one push provider rejects a wakeup", async () => {
    const apns: PushTransport = {
      kind: "apns",
      async sendWakeup() {
        throw new Error("provider unavailable");
      },
    };
    const fcm: PushTransport = {
      kind: "fcm",
      async sendWakeup() {
        return Promise.resolve();
      },
    };

    await expect(
      dispatchPushWakeups(
        [
          { device_id: "dev-a", transport: "apns", token: "apns-token" },
          { device_id: "dev-b", transport: "fcm", token: "fcm-token" },
        ],
        {
          accountId: "acct-push-provider-failure",
          requestId: "req-push-provider-failure",
          expiresAt: EXPIRES_AT,
          transports: { apns, fcm },
        },
      ),
    ).resolves.toEqual({
      // Only FCM accepted; the rejected APNs wakeup is neither delivered nor prunable.
      deliveredTokens: [{ device_id: "dev-b", transport: "fcm", token: "fcm-token" }],
      undeliverableTokens: [],
    });
  });

  it("keeps at most `concurrency` wakeups in flight, and a slow one does not block the rest", async () => {
    let inFlight = 0;
    let peak = 0;
    const finished: string[] = [];
    const releases: Array<() => void> = [];
    const webpush: PushTransport = {
      kind: "webpush",
      async sendWakeup(wakeup) {
        inFlight++;
        peak = Math.max(peak, inFlight);
        if (wakeup.token === "slow") {
          // Hangs until released at the end: the other sends must complete around it.
          await new Promise<void>((resolve) => releases.push(resolve));
        }
        inFlight--;
        finished.push(wakeup.token);
      },
    };
    const tokens: StoredPushToken[] = ["slow", "a", "b", "c", "d", "e"].map((token) => ({
      device_id: `dev-${token}`,
      transport: "webpush",
      token,
    }));

    const dispatched = dispatchPushWakeups(tokens, {
      accountId: "acct-push-concurrency",
      requestId: "req-push-concurrency",
      expiresAt: EXPIRES_AT,
      transports: { webpush },
      concurrency: 2,
    });
    await vi.waitFor(() => {
      expect(finished).toEqual(["a", "b", "c", "d", "e"]);
    });
    expect(peak).toBe(2);
    releases.forEach((release) => {
      release();
    });

    // Every send succeeded, the slow one last.
    const result = await dispatched;
    expect(result.deliveredTokens.map((token) => token.token)).toEqual([
      "a",
      "b",
      "c",
      "d",
      "e",
      "slow",
    ]);
    expect(result.undeliverableTokens).toEqual([]);
  });

  it("reports only tokens whose transport signalled UndeliverablePushTokenError for pruning", async () => {
    const gone: StoredPushToken = { device_id: "dev-a", transport: "webpush", token: "gone" };
    const transient: StoredPushToken = { device_id: "dev-b", transport: "webpush", token: "flaky" };
    const webpush: PushTransport = {
      kind: "webpush",
      async sendWakeup(wakeup) {
        if (wakeup.token === "gone") throw new UndeliverablePushTokenError("HTTP 410");
        throw new Error("HTTP 503");
      },
    };

    await expect(
      dispatchPushWakeups([gone, transient], {
        accountId: "acct-push-prune",
        requestId: "req-push-prune",
        expiresAt: EXPIRES_AT,
        transports: { webpush },
      }),
    ).resolves.toEqual({ deliveredTokens: [], undeliverableTokens: [gone] });
  });
});

describe("push-service rejections are logged for operators (#326)", () => {
  const APNS_DEVICE_TOKEN = "f".repeat(64);
  const FCM_REGISTRATION = "fcm-registration-secret";

  function apnsAnswering(status: number): ApnsPushTransport {
    return new ApnsPushTransport({
      endpoint: "https://api.push.apple.test",
      topic: "com.example.allw",
      bearerToken: "apns-bearer-secret",
      fetcher: async () => new Response(JSON.stringify({ reason: "BadDeviceToken" }), { status }),
    });
  }

  function fcmAnswering(status: number): FcmPushTransport {
    return new FcmPushTransport({
      endpoint: "https://fcm.googleapis.test/v1/projects/allw-secret-project/messages:send",
      bearerToken: "fcm-bearer-secret",
      fetcher: async () => new Response(null, { status }),
    });
  }

  function wakeupFor(token: string) {
    return {
      accountId: "acct",
      deviceId: "dev",
      requestId: "req-rejected",
      expiresAt: EXPIRES_AT,
      token,
    };
  }

  /** The relay's push-rejection warnings during `body`, ignoring any other console output. */
  async function rejectionWarnings(body: () => Promise<unknown>): Promise<string[]> {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      await body().catch(() => undefined);
      return warn.mock.calls
        .map((call) => String(call[0]))
        .filter((message) => message.startsWith("push:"));
    } finally {
      warn.mockRestore();
    }
  }

  it("logs an APNs 4xx with transport, host and status only, never the device token", async () => {
    const warnings = await rejectionWarnings(() =>
      apnsAnswering(400).sendWakeup(wakeupFor(APNS_DEVICE_TOKEN)),
    );

    expect(warnings).toEqual([
      "push: apns push service api.push.apple.test rejected a wakeup with HTTP 400; token kept",
    ]);
    for (const secret of [APNS_DEVICE_TOKEN, "apns-bearer-secret", "req-rejected", "/3/device"]) {
      expect(warnings[0]).not.toContain(secret);
    }
  });

  it("logs an FCM 4xx with the host only, never the token or the project path", async () => {
    const warnings = await rejectionWarnings(() =>
      fcmAnswering(403).sendWakeup(wakeupFor(FCM_REGISTRATION)),
    );

    expect(warnings).toEqual([
      "push: fcm push service fcm.googleapis.test rejected a wakeup with HTTP 403; token kept",
    ]);
    for (const secret of [FCM_REGISTRATION, "fcm-bearer-secret", "allw-secret-project"]) {
      expect(warnings[0]).not.toContain(secret);
    }
  });

  it.each([200, 202, 500, 503, 301])(
    "does not log an APNs or FCM response with HTTP %i as a rejection",
    async (status) => {
      expect(
        await rejectionWarnings(() =>
          apnsAnswering(status).sendWakeup(wakeupFor(APNS_DEVICE_TOKEN)),
        ),
      ).toEqual([]);
      expect(
        await rejectionWarnings(() => fcmAnswering(status).sendWakeup(wakeupFor(FCM_REGISTRATION))),
      ).toEqual([]);
    },
  );

  it("classifies exactly the 4xx statuses as client errors", () => {
    expect([400, 401, 403, 404, 410, 429, 499].every((s) => isClientErrorStatus(s))).toBe(true);
    expect([200, 201, 301, 399, 500, 503].some((s) => isClientErrorStatus(s))).toBe(false);
  });
});

/**
 * @see https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
 * @see https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode
 */
describe("APNs and FCM prune only on an unregistered answer (#260)", () => {
  const APNS_TOKEN = "e".repeat(64);
  /** FCM HTTP v1's error body for a registration token that is no longer valid. */
  const FCM_UNREGISTERED = {
    error: {
      code: 404,
      message: "Requested entity was not found.",
      status: "NOT_FOUND",
      details: [
        {
          "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
          errorCode: "UNREGISTERED",
        },
      ],
    },
  };

  function apns(response: () => Response): ApnsPushTransport {
    return new ApnsPushTransport({
      endpoint: "https://api.push.apple.test",
      topic: "com.example.allw",
      bearerToken: "apns-bearer",
      fetcher: async () => response(),
    });
  }

  function fcm(response: () => Response): FcmPushTransport {
    return new FcmPushTransport({
      endpoint: "https://fcm.googleapis.test/v1/projects/allw/messages:send",
      bearerToken: "fcm-bearer",
      fetcher: async () => response(),
    });
  }

  /** Send one wakeup; the error it failed with (or null) and the push-rejection warnings logged. */
  async function outcome(
    transport: PushTransport,
    token: string,
  ): Promise<{ failure: unknown; warnings: string[] }> {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      const failure = await transport
        .sendWakeup({
          accountId: "acct",
          deviceId: "dev",
          requestId: "req",
          expiresAt: EXPIRES_AT,
          token,
        })
        .then(
          () => null,
          (error: unknown) => error,
        );
      return {
        failure,
        warnings: warn.mock.calls
          .map((call) => String(call[0]))
          .filter((message) => message.startsWith("push:")),
      };
    } finally {
      warn.mockRestore();
    }
  }

  it("prunes an APNs token answered 410 (Unregistered), without logging a rejection", async () => {
    const { failure, warnings } = await outcome(
      apns(() => new Response(JSON.stringify({ reason: "Unregistered" }), { status: 410 })),
      APNS_TOKEN,
    );

    expect(failure).toBeInstanceOf(UndeliverablePushTokenError);
    expect(warnings).toEqual([]);
  });

  it("keeps an APNs token answered 400 BadDeviceToken, which a wrong APNs environment also causes", async () => {
    const { failure, warnings } = await outcome(
      apns(() => new Response(JSON.stringify({ reason: "BadDeviceToken" }), { status: 400 })),
      APNS_TOKEN,
    );

    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(UndeliverablePushTokenError);
    expect(warnings).toEqual([
      "push: apns push service api.push.apple.test rejected a wakeup with HTTP 400; token kept",
    ]);
  });

  it.each([403, 404, 429, 500, 503])("keeps an APNs token answered %i", async (status) => {
    const { failure } = await outcome(
      apns(() => new Response(null, { status })),
      APNS_TOKEN,
    );

    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(UndeliverablePushTokenError);
  });

  it("logs an APNs 404 (a wrong request path) as a rejection, since it does not prune", async () => {
    const { warnings } = await outcome(
      apns(() => new Response(null, { status: 404 })),
      APNS_TOKEN,
    );

    expect(warnings).toEqual([
      "push: apns push service api.push.apple.test rejected a wakeup with HTTP 404; token kept",
    ]);
  });

  it("releases every APNs response body unread", async () => {
    for (const status of [200, 400, 410, 500]) {
      const cancelled = vi.fn();
      await outcome(
        apns(() => new Response(new ReadableStream({ cancel: cancelled }), { status })),
        APNS_TOKEN,
      );
      expect(cancelled).toHaveBeenCalledTimes(1);
    }
  });

  it("prunes an FCM token answered 404 with UNREGISTERED, without logging a rejection", async () => {
    const { failure, warnings } = await outcome(
      fcm(() => new Response(JSON.stringify(FCM_UNREGISTERED), { status: 404 })),
      "fcm-token",
    );

    expect(failure).toBeInstanceOf(UndeliverablePushTokenError);
    expect(warnings).toEqual([]);
  });

  it.each([
    ["no body", null],
    ["a non-JSON body", "Not Found"],
    [
      "another error code",
      JSON.stringify({ error: { details: [{ errorCode: "SENDER_ID_MISMATCH" }] } }),
    ],
    ["UNREGISTERED outside error.details", JSON.stringify({ errorCode: "UNREGISTERED" })],
    // Cut off at the read limit, the prefix does not parse: no information, so no prune.
    [
      "UNREGISTERED past the read limit",
      JSON.stringify({ padding: " ".repeat(8192), ...FCM_UNREGISTERED }),
    ],
  ])("keeps an FCM token answered 404 with %s, and logs it", async (_name, body) => {
    const { failure, warnings } = await outcome(
      fcm(() => new Response(body, { status: 404 })),
      "fcm-token",
    );

    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(UndeliverablePushTokenError);
    expect(warnings).toEqual([
      "push: fcm push service fcm.googleapis.test rejected a wakeup with HTTP 404; token kept",
    ]);
  });

  it.each([400, 403, 429, 500, 503])(
    "keeps an FCM token answered %i, even with an UNREGISTERED body",
    async (status) => {
      const { failure } = await outcome(
        fcm(() => new Response(JSON.stringify(FCM_UNREGISTERED), { status })),
        "fcm-token",
      );

      expect(failure).toBeInstanceOf(Error);
      expect(failure).not.toBeInstanceOf(UndeliverablePushTokenError);
    },
  );
});

describe("WakeupCoalescer — at most one wakeup per subscription per window", () => {
  /** 2023-11-14T22:13:20Z in ms: a fixed clock for every claim. */
  const T0 = 1_700_000_000_000;
  const KEY = "dev-a\0https://fcm.googleapis.com/fcm/send/a";
  const OTHER = "dev-b\0https://fcm.googleapis.com/fcm/send/b";

  it("uses a 30-second window", () => {
    expect(WEB_PUSH_COALESCE_MS).toBe(30_000);
  });

  it("coalesces a second claim inside the window, through the boundary, and allows one just past it", () => {
    const coalescer = new WakeupCoalescer(WEB_PUSH_COALESCE_MS);
    expect(coalescer.tryClaim(KEY, T0)).toBe(true);
    coalescer.release(KEY);

    expect(coalescer.tryClaim(KEY, T0 + 1)).toBe(false);
    expect(coalescer.tryClaim(KEY, T0 + WEB_PUSH_COALESCE_MS - 1)).toBe(false);
    // The boundary itself is still inside the window.
    expect(coalescer.tryClaim(KEY, T0 + WEB_PUSH_COALESCE_MS)).toBe(false);
    // Just past it, the subscription may be woken again, and that claim opens a new window.
    expect(coalescer.tryClaim(KEY, T0 + WEB_PUSH_COALESCE_MS + 1)).toBe(true);
    coalescer.release(KEY);
    expect(coalescer.tryClaim(KEY, T0 + WEB_PUSH_COALESCE_MS + 2)).toBe(false);
  });

  it("coalesces while a wakeup is still in flight, even past the window", () => {
    const coalescer = new WakeupCoalescer(WEB_PUSH_COALESCE_MS);
    expect(coalescer.tryClaim(KEY, T0)).toBe(true);

    const pastWindow = T0 + WEB_PUSH_COALESCE_MS + 1;
    expect(coalescer.tryClaim(KEY, pastWindow)).toBe(false);
    coalescer.release(KEY);
    expect(coalescer.tryClaim(KEY, pastWindow)).toBe(true);
  });

  it("reports the first instant a claim can succeed again: just past the window", () => {
    const coalescer = new WakeupCoalescer(WEB_PUSH_COALESCE_MS);
    // Never claimed: claimable now.
    expect(coalescer.nextClaimableAt(KEY, T0)).toBe(T0);

    expect(coalescer.tryClaim(KEY, T0)).toBe(true);
    coalescer.release(KEY);
    const reopensAt = T0 + WEB_PUSH_COALESCE_MS + 1;
    expect(coalescer.nextClaimableAt(KEY, T0 + 1)).toBe(reopensAt);
    // The reported instant agrees with tryClaim at the boundary and just past it.
    expect(coalescer.tryClaim(KEY, reopensAt - 1)).toBe(false);
    expect(coalescer.tryClaim(KEY, reopensAt)).toBe(true);
  });

  it("never reports a time before now, even while a claim is still in flight past its window", () => {
    const coalescer = new WakeupCoalescer(WEB_PUSH_COALESCE_MS);
    expect(coalescer.tryClaim(KEY, T0)).toBe(true);
    const late = T0 + 10 * WEB_PUSH_COALESCE_MS;
    expect(coalescer.nextClaimableAt(KEY, late)).toBe(late);
    // It is a lower bound: the in-flight claim still blocks until released.
    expect(coalescer.tryClaim(KEY, late)).toBe(false);
  });

  it("remembers claims through its store, so a second coalescer on the same store still coalesces (#319)", () => {
    // Models a Durable Object evicted and recreated over the same SQLite: in-flight state is new,
    // but the last claim is read back from the store.
    const store = new InMemoryWakeupClaimStore(WEB_PUSH_COALESCE_MS);
    const before = new WakeupCoalescer(WEB_PUSH_COALESCE_MS, store);
    expect(before.tryClaim(KEY, T0)).toBe(true);
    before.release(KEY);

    const after = new WakeupCoalescer(WEB_PUSH_COALESCE_MS, store);
    expect(after.tryClaim(KEY, T0 + 1)).toBe(false);
    expect(after.nextClaimableAt(KEY, T0 + 1)).toBe(T0 + WEB_PUSH_COALESCE_MS + 1);
    expect(after.tryClaim(KEY, T0 + WEB_PUSH_COALESCE_MS + 1)).toBe(true);
  });

  it("counts a stored claim from the future as now, so it blocks for one window at most (review-330 S1)", () => {
    const store = new InMemoryWakeupClaimStore(WEB_PUSH_COALESCE_MS);
    store.recordClaim(KEY, T0 + 24 * 60 * 60 * 1000);
    const coalescer = new WakeupCoalescer(WEB_PUSH_COALESCE_MS, store);

    expect(coalescer.nextClaimableAt(KEY, T0)).toBe(T0 + WEB_PUSH_COALESCE_MS + 1);
    expect(coalescer.tryClaim(KEY, T0)).toBe(false);
    expect(coalescer.tryClaim(KEY, T0 + WEB_PUSH_COALESCE_MS + 1)).toBe(true);
  });

  it("round-trips a subscription through its coalescing key", () => {
    const key = webPushCoalesceKey("dev-a", "https://fcm.googleapis.com/fcm/send/a?x=1");
    expect(parseWebPushCoalesceKey(key)).toEqual({
      deviceId: "dev-a",
      token: "https://fcm.googleapis.com/fcm/send/a?x=1",
    });
  });

  it("refuses to parse a coalescing key with no separator", () => {
    expect(() => parseWebPushCoalesceKey("dev-a-https://fcm.googleapis.com/fcm/send/a")).toThrow(
      "not a Web Push coalescing key",
    );
  });

  it("keeps subscriptions independent", () => {
    const coalescer = new WakeupCoalescer(WEB_PUSH_COALESCE_MS);
    expect(coalescer.tryClaim(KEY, T0)).toBe(true);
    expect(coalescer.tryClaim(OTHER, T0)).toBe(true);
    expect(coalescer.tryClaim(KEY, T0 + 1)).toBe(false);
  });
});

describe("diffPushTokenSet — replace a device's set with minimal row changes", () => {
  const A = { transport: "webpush", token: "https://fcm.googleapis.com/fcm/send/a" } as const;
  const B = { transport: "webpush", token: "https://fcm.googleapis.com/fcm/send/b" } as const;
  const APNS_SAME_TEXT = { transport: "apns", token: A.token } as const;

  it("changes nothing when the set is unchanged", () => {
    expect(diffPushTokenSet([A, B], [B, A])).toEqual({ remove: [], add: [] });
  });

  it("removes what is gone and adds what is new, keeping the overlap", () => {
    expect(diffPushTokenSet([A], [B])).toEqual({ remove: [A], add: [B] });
    expect(diffPushTokenSet([A], [A, B])).toEqual({ remove: [], add: [B] });
  });

  it("clears everything for an empty desired set", () => {
    expect(diffPushTokenSet([A, B], [])).toEqual({ remove: [A, B], add: [] });
  });

  it("treats the same token text under another transport as a different entry", () => {
    expect(diffPushTokenSet([A], [APNS_SAME_TEXT])).toEqual({ remove: [A], add: [APNS_SAME_TEXT] });
  });
});
