/**
 * Integration tests for Web Push inside the relay (#235), through the real Worker + `AccountRelay`
 * Durable Object: subscription-endpoint validation at pairing (SSRF allowlist), and pruning a
 * device's token row when the push service reports the subscription gone (404/410) — while a push
 * failure never fails the submit.
 *
 * The `webpush` transport is a real `WebPushTransport` with an injected `fetcher`, installed into
 * the account's DO, so no request leaves the test runtime.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8030 (§6–7: 404/410 mean the subscription is gone)
 * @see ../../../docs/relay-api.md (§3 Pairing `push_tokens`, §5 Push wakeups)
 * @see ../../../docs/threat-model.md (push endpoint SSRF allowlist)
 */

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import type { SqlStorage } from "@cloudflare/workers-types";
import type { AccountRelay } from "../src/index.js";
import type { PushTransportRegistry } from "../src/push.js";
import { WebPushTransport, type VapidConfig } from "../src/web-push.js";

/** A 32-byte base64url-unpadded device key (32 × 0x00). */
const DEVICE_PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/** Far-future expiry (2100-01-01Z, ms) — deterministic and always after the relay's clock. */
const FUTURE_EXPIRES_AT = 4102444800000;
/** A fixed creation timestamp (2023-11-14Z, ms). */
const CREATED_AT = 1700000000000;

const FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send/c3Vic2NyaXB0aW9uLWE";
const MOZILLA_ENDPOINT = "https://updates.push.services.mozilla.com/wpush/v2/c3Vic2NyaXB0aW9uLWI";

function relayUrl(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

async function post<T>(
  accountId: string,
  subPath: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; data: T }> {
  const resp = await SELF.fetch(relayUrl(accountId, subPath), {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: resp.status, data: (await resp.json()) as T };
}

/** Run pairing with the given push tokens; returns the completion status and device id. */
async function pairWithPushTokens(
  accountId: string,
  pushTokens: unknown,
): Promise<{ status: number; deviceId: string | undefined; error: string | undefined }> {
  const start = await post<{ code: string; pairing_auth_token: string }>(
    accountId,
    "/pairing/start",
    {},
  );
  const complete = await post<{ device_id?: string; error?: string }>(
    accountId,
    "/pairing/complete",
    { code: start.data.code, pubkey: DEVICE_PUBKEY, push_tokens: pushTokens },
    { Authorization: `Bearer ${start.data.pairing_auth_token}` },
  );
  return {
    status: complete.status,
    deviceId: complete.data.device_id,
    error: complete.data.error,
  };
}

async function readPushTokens(accountId: string): Promise<Array<{ token: string }>> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    return [
      ...relay.sql.exec<{ token: string }>(
        `SELECT token FROM device_push_token ORDER BY created_at ASC, token ASC`,
      ),
    ];
  });
}

async function installPushTransports(
  accountId: string,
  transports: PushTransportRegistry,
): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    (instance as unknown as { pushTransports: PushTransportRegistry }).pushTransports = transports;
  });
}

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function makeVapid(): Promise<VapidConfig> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return { publicKey: b64url(raw), privateKey: jwk.d ?? "", subject: "mailto:ops@allw.example" };
}

/** Install a real Web Push transport whose push service answers each endpoint with `statusFor`. */
async function installWebPush(
  accountId: string,
  statusFor: (endpoint: string) => number,
): Promise<ReturnType<typeof vi.fn<typeof fetch>>> {
  const fetcher = vi.fn<typeof fetch>(
    async (input) => new Response(null, { status: statusFor(String(input)) }),
  );
  await installPushTransports(accountId, {
    webpush: new WebPushTransport({ vapid: await makeVapid(), fetcher }),
  });
  return fetcher;
}

function envelope(id: string): Record<string, unknown> {
  return {
    v: 1,
    id,
    created_at: CREATED_AT,
    expires_at: FUTURE_EXPIRES_AT,
    approver: "acct-approver-routing-id",
    context_ciphertext: "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE",
  };
}

describe("pairing — webpush token is a validated subscription endpoint", () => {
  it("stores an allowlisted https subscription endpoint as the webpush token", async () => {
    const acct = "acct-webpush-pair-valid";
    const paired = await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);

    expect(paired.status).toBe(201);
    expect(await readPushTokens(acct)).toEqual([{ token: FCM_ENDPOINT }]);
  });

  it.each([
    ["an http endpoint", "http", "http://fcm.googleapis.com/fcm/send/abc"],
    ["a non-allowlisted host", "host", "https://push.attacker.example/abc"],
    ["non-URL input", "non-url", "web-token"],
  ])("rejects %s with 400 and stores nothing", async (_name, slug, token) => {
    const acct = `acct-webpush-pair-bad-${slug}`;
    const paired = await pairWithPushTokens(acct, [{ transport: "webpush", token }]);

    expect(paired.status).toBe(400);
    expect(paired.error).toMatch(/push_tokens/);
    expect(await readPushTokens(acct)).toEqual([]);
  });
});

describe("submit — Web Push wakeups and gone-subscription pruning", () => {
  it.each([404, 410])(
    "prunes only the token the push service answered %i for; submit still succeeds",
    async (goneStatus) => {
      const acct = `acct-webpush-prune-${String(goneStatus)}`;
      const paired = await pairWithPushTokens(acct, [
        { transport: "webpush", token: FCM_ENDPOINT },
        { transport: "webpush", token: MOZILLA_ENDPOINT },
      ]);
      expect(paired.status).toBe(201);
      const fetcher = await installWebPush(acct, (endpoint) =>
        endpoint === FCM_ENDPOINT ? goneStatus : 201,
      );

      const submit = await post<{ status: string; push_wakeups: number }>(
        acct,
        "/requests",
        envelope(`req-webpush-prune-${String(goneStatus)}`),
      );

      expect(submit.status).toBe(202);
      expect(submit.data.status).toBe("pending");
      expect(submit.data.push_wakeups).toBe(1);
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect(await readPushTokens(acct)).toEqual([{ token: MOZILLA_ENDPOINT }]);
    },
  );

  it.each([429, 500, 503])(
    "keeps the token when the push service fails with %i; submit still succeeds",
    async (status) => {
      const acct = `acct-webpush-keep-${String(status)}`;
      const paired = await pairWithPushTokens(acct, [
        { transport: "webpush", token: FCM_ENDPOINT },
      ]);
      expect(paired.status).toBe(201);
      await installWebPush(acct, () => status);

      const submit = await post<{ status: string; push_wakeups: number }>(
        acct,
        "/requests",
        envelope(`req-webpush-keep-${String(status)}`),
      );

      expect(submit.status).toBe(202);
      expect(submit.data.push_wakeups).toBe(0);
      expect(await readPushTokens(acct)).toEqual([{ token: FCM_ENDPOINT }]);
    },
  );

  it("keeps the token when the push service is unreachable (fetch rejects)", async () => {
    const acct = "acct-webpush-keep-network-error";
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    await installPushTransports(acct, {
      webpush: new WebPushTransport({
        vapid: await makeVapid(),
        fetcher: () => Promise.reject(new TypeError("network down")),
      }),
    });

    const submit = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-webpush-network-error"),
    );

    expect(submit.status).toBe(202);
    expect(submit.data.push_wakeups).toBe(0);
    expect(await readPushTokens(acct)).toEqual([{ token: FCM_ENDPOINT }]);
  });

  it("sends a payload-less wakeup whose TTL is bounded by the request deadline", async () => {
    const acct = "acct-webpush-payloadless";
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    const submit = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-webpush-payloadless"),
    );

    expect(submit.data.push_wakeups).toBe(1);
    const [input, init] = fetcher.mock.calls[0] ?? [];
    const sent = new Request(String(input), init);
    expect((await sent.arrayBuffer()).byteLength).toBe(0);
    // The fixture deadline is in 2100, so the TTL is the 28-day push-service ceiling.
    expect(sent.headers.get("TTL")).toBe(String(28 * 24 * 60 * 60));
    expect(sent.headers.get("Urgency")).toBe("high");
  });
});
