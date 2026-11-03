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
  UndeliverablePushTokenError,
  WEB_PUSH_COALESCE_MS,
  WakeupCoalescer,
  buildPushWakeupPayload,
  dispatchPushWakeups,
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

    expect(result).toEqual({ delivered: 2, undeliverableTokens: [] });
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
    const fetcher = vi.fn(async () => new Response(null, { status: 202 }));
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

    const apnsBody = JSON.parse((fetcher.mock.calls[0]?.[1] as RequestInit).body as string) as {
      request_id?: string;
      context_ciphertext?: string;
    };
    expect(apnsBody.request_id).toBe("req-format");
    expect(apnsBody.context_ciphertext).toBeUndefined();

    const fcmBody = JSON.parse((fetcher.mock.calls[1]?.[1] as RequestInit).body as string) as {
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
    ).resolves.toEqual({ delivered: 1, undeliverableTokens: [] });
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

    await expect(dispatched).resolves.toEqual({ delivered: 6, undeliverableTokens: [] });
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
    ).resolves.toEqual({ delivered: 0, undeliverableTokens: [gone] });
  });
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

  it("keeps subscriptions independent", () => {
    const coalescer = new WakeupCoalescer(WEB_PUSH_COALESCE_MS);
    expect(coalescer.tryClaim(KEY, T0)).toBe(true);
    expect(coalescer.tryClaim(OTHER, T0)).toBe(true);
    expect(coalescer.tryClaim(KEY, T0 + 1)).toBe(false);
  });
});
