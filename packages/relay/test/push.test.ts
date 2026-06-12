/**
 * Tests for the relay push fan-out seam (#17).
 *
 * The relay must keep routing independent from vendor-specific push APIs: routing emits a
 * request-id-only wakeup, while APNs/FCM/Web Push transports decide how to deliver it.
 */

import { describe, expect, it, vi } from "vitest";
import {
  ApnsPushTransport,
  FcmPushTransport,
  WebPushStubTransport,
  buildPushWakeupPayload,
  dispatchPushWakeups,
  type PushTransport,
  type StoredPushToken,
} from "../src/push.js";

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

    const delivered = await dispatchPushWakeups(tokens, {
      accountId: "acct-push-swap",
      requestId: "req-push-swap",
      transports: { apns, fcm },
    });

    expect(delivered).toBe(2);
    expect(sent).toEqual([
      {
        kind: "apns",
        accountId: "acct-push-swap",
        deviceId: "dev-a",
        requestId: "req-push-swap",
        token: "apns-token",
      },
      {
        kind: "fcm",
        accountId: "acct-push-swap",
        deviceId: "dev-b",
        requestId: "req-push-swap",
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
      token: "apns-token",
    });
    await fcm.sendWakeup({
      accountId: "acct",
      deviceId: "dev-android",
      requestId: "req-format",
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
          transports: { apns, fcm },
        },
      ),
    ).resolves.toBe(1);
  });

  it("keeps Web Push behind the same interface as an explicit stub", async () => {
    const webPush = new WebPushStubTransport();

    await expect(
      webPush.sendWakeup({
        accountId: "acct",
        deviceId: "dev-web",
        requestId: "req-web",
        token: "web-token",
      }),
    ).resolves.toBeUndefined();
  });
});
