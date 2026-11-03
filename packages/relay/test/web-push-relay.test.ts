/**
 * Integration tests for Web Push inside the relay (#235), through the real Worker + `AccountRelay`
 * Durable Object: subscription-endpoint validation at pairing (SSRF allowlist), and pruning a
 * device's token row when the push service reports the subscription gone (404/410), registration
 * budgets, per-subscription coalescing of wakeups from unauthenticated submits (with one trailing
 * wakeup once the window ends, #313), and the fan-out running off the response path, so a push
 * failure or hang never fails or delays the submit.
 *
 * Background delivery is awaited through the DO's `pushFanOut` promise, never a fixed sleep, so a
 * "token kept" assertion runs only after every send and prune has finished.
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
import { AccountRelay, type Env } from "../src/index.js";
import {
  WEB_PUSH_COALESCE_MS,
  WEB_PUSH_TRAILING_RETRY_MS,
  WakeupCoalescer,
  type PushTransport,
  type PushTransportRegistry,
} from "../src/push.js";
import { WebPushTransport, type VapidConfig } from "../src/web-push.js";
import { pairingStartBody, testAccount } from "./support/accounts.js";

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
    pairingStartBody(accountId),
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
    const acct = testAccount("acct-webpush-pair-valid");
    const paired = await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);

    expect(paired.status).toBe(201);
    expect(await readPushTokens(acct)).toEqual([{ token: FCM_ENDPOINT }]);
  });

  it.each([
    ["an http endpoint", "http", "http://fcm.googleapis.com/fcm/send/abc"],
    ["a non-allowlisted host", "host", "https://push.attacker.example/abc"],
    ["non-URL input", "non-url", "web-token"],
  ])("rejects %s with 400 and stores nothing", async (_name, slug, token) => {
    const acct = testAccount(`acct-webpush-pair-bad-${slug}`);
    const paired = await pairWithPushTokens(acct, [{ transport: "webpush", token }]);

    expect(paired.status).toBe(400);
    expect(paired.error).toMatch(/push_tokens/);
    expect(await readPushTokens(acct)).toEqual([]);
  });
});

/** Wait until every push fan-out the account's DO has started has finished, pruning included. */
async function pushFanOutSettled(accountId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(
    stub,
    (instance: AccountRelay) => (instance as unknown as { pushFanOut: Promise<void> }).pushFanOut,
  );
}

async function seedPushTokenRows(
  accountId: string,
  rows: ReadonlyArray<{ device_id: string; transport: string; token: string; created_at?: number }>,
): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    for (const row of rows) {
      relay.sql.exec(
        `INSERT INTO device_push_token (device_id, transport, token, created_at) VALUES (?, ?, ?, ?)`,
        row.device_id,
        row.transport,
        row.token,
        row.created_at ?? CREATED_AT,
      );
    }
  });
}

describe("pairing — push-token budgets (reject, never truncate)", () => {
  it("rejects more than four push_tokens in one registration with 400, storing nothing", async () => {
    const acct = testAccount("acct-webpush-budget-total");
    const paired = await pairWithPushTokens(acct, [
      { transport: "webpush", token: FCM_ENDPOINT },
      { transport: "webpush", token: MOZILLA_ENDPOINT },
      { transport: "apns", token: "a".repeat(64) },
      { transport: "apns", token: "b".repeat(64) },
      { transport: "fcm", token: "fcm-token-1" },
    ]);

    expect(paired.status).toBe(400);
    expect(await readPushTokens(acct)).toEqual([]);
  });

  it("rejects more than two distinct tokens for one transport with 400, storing nothing", async () => {
    const acct = testAccount("acct-webpush-budget-transport");
    const paired = await pairWithPushTokens(acct, [
      { transport: "webpush", token: `${FCM_ENDPOINT}1` },
      { transport: "webpush", token: `${FCM_ENDPOINT}2` },
      { transport: "webpush", token: `${FCM_ENDPOINT}3` },
    ]);

    expect(paired.status).toBe(400);
    expect(await readPushTokens(acct)).toEqual([]);
  });

  it("rejects a registration that would exceed the account's 32-token budget (409), storing nothing", async () => {
    const acct = testAccount("acct-webpush-budget-account");
    // Bind the account root first (pairing/start requires an otherwise empty account), then fill it.
    expect((await pairWithPushTokens(acct, [])).status).toBe(201);
    await seedPushTokenRows(
      acct,
      Array.from({ length: 31 }, (_, n) => ({
        device_id: `dev-seed-${String(n)}`,
        transport: "webpush",
        token: `${FCM_ENDPOINT}-seed-${String(n)}`,
      })),
    );

    const overBudget = await pairWithPushTokens(acct, [
      { transport: "webpush", token: FCM_ENDPOINT },
      { transport: "webpush", token: MOZILLA_ENDPOINT },
    ]);
    expect(overBudget.status).toBe(409);
    expect(await readPushTokens(acct)).toHaveLength(31);

    const fits = await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    expect(fits.status).toBe(201);
    expect(await readPushTokens(acct)).toHaveLength(32);
  });

  it("lets the same pairing code succeed after a budget 409 (the code is not consumed)", async () => {
    const acct = testAccount("acct-webpush-budget-retry");
    expect((await pairWithPushTokens(acct, [])).status).toBe(201);
    await seedPushTokenRows(
      acct,
      Array.from({ length: 31 }, (_, n) => ({
        device_id: `dev-seed-${String(n)}`,
        transport: "webpush",
        token: `${FCM_ENDPOINT}-seed-${String(n)}`,
      })),
    );
    const start = await post<{ code: string; pairing_auth_token: string }>(
      acct,
      "/pairing/start",
      pairingStartBody(acct),
    );
    const complete = (pushTokens: unknown) =>
      post<{ device_id?: string }>(
        acct,
        "/pairing/complete",
        { code: start.data.code, pubkey: DEVICE_PUBKEY, push_tokens: pushTokens },
        { Authorization: `Bearer ${start.data.pairing_auth_token}` },
      );

    const overBudget = await complete([
      { transport: "webpush", token: FCM_ENDPOINT },
      { transport: "webpush", token: MOZILLA_ENDPOINT },
    ]);
    expect(overBudget.status).toBe(409);

    const retry = await complete([]);
    expect(retry.status).toBe(201);
    expect(retry.data.device_id).toEqual(expect.any(String));
    expect(await readPushTokens(acct)).toHaveLength(31);
  });

  it("accepts exactly four push_tokens in one registration (the accept boundary)", async () => {
    const acct = testAccount("acct-webpush-budget-exactly-four");
    const paired = await pairWithPushTokens(acct, [
      { transport: "webpush", token: FCM_ENDPOINT },
      { transport: "webpush", token: MOZILLA_ENDPOINT },
      { transport: "apns", token: "a".repeat(64) },
      { transport: "apns", token: "b".repeat(64) },
    ]);

    expect(paired.status).toBe(201);
    expect(await readPushTokens(acct)).toHaveLength(4);
  });

  it("stores the normalized endpoint, so two spellings of one subscription are one row", async () => {
    const acct = testAccount("acct-webpush-normalized");
    const paired = await pairWithPushTokens(acct, [
      { transport: "webpush", token: "https://FCM.googleapis.com/fcm/send/c3Vic2NyaXB0aW9uLWE" },
      {
        transport: "webpush",
        token: "https://fcm.googleapis.com:443/fcm/send/c3Vic2NyaXB0aW9uLWE",
      },
    ]);

    expect(paired.status).toBe(201);
    expect(await readPushTokens(acct)).toEqual([{ token: FCM_ENDPOINT }]);
  });
});

describe("submit — Web Push wakeups off the response path, with pruning", () => {
  it.each([404, 410])(
    "prunes only the token the push service answered %i for; submit still succeeds",
    async (goneStatus) => {
      const acct = testAccount(`acct-webpush-prune-${String(goneStatus)}`);
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
      // `push_wakeups` counts wakeups scheduled, not delivered (relay-api.md §5).
      expect(submit.data.push_wakeups).toBe(2);
      await pushFanOutSettled(acct);
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect(await readPushTokens(acct)).toEqual([{ token: MOZILLA_ENDPOINT }]);
    },
  );

  it.each([401, 403, 429, 500, 503])(
    "keeps the token when the push service fails with %i; submit still succeeds",
    async (status) => {
      const acct = testAccount(`acct-webpush-keep-${String(status)}`);
      const paired = await pairWithPushTokens(acct, [
        { transport: "webpush", token: FCM_ENDPOINT },
      ]);
      expect(paired.status).toBe(201);
      const fetcher = await installWebPush(acct, () => status);

      const submit = await post<{ status: string; push_wakeups: number }>(
        acct,
        "/requests",
        envelope(`req-webpush-keep-${String(status)}`),
      );

      expect(submit.status).toBe(202);
      expect(submit.data.push_wakeups).toBe(1);
      await pushFanOutSettled(acct);
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(await readPushTokens(acct)).toEqual([{ token: FCM_ENDPOINT }]);
    },
  );

  it("keeps the token when the push service is unreachable (fetch rejects)", async () => {
    const acct = testAccount("acct-webpush-keep-network-error");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = vi.fn<typeof fetch>(() => Promise.reject(new TypeError("network down")));
    await installPushTransports(acct, {
      webpush: new WebPushTransport({ vapid: await makeVapid(), fetcher }),
    });

    const submit = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-webpush-network-error"),
    );

    expect(submit.status).toBe(202);
    await pushFanOutSettled(acct);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(await readPushTokens(acct)).toEqual([{ token: FCM_ENDPOINT }]);
  });

  it("returns 202 while a push service hangs, then times the push out and keeps the token", async () => {
    const acct = testAccount("acct-webpush-hanging");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    let fetchSettled = false;
    const hanging = vi.fn<typeof fetch>(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            fetchSettled = true;
            reject(init.signal?.reason as Error);
          });
        }),
    );
    await installPushTransports(acct, {
      webpush: new WebPushTransport({ vapid: await makeVapid(), fetcher: hanging, timeoutMs: 300 }),
    });

    const submit = await post<{ status: string; push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-webpush-hanging"),
    );

    // The submit answered without waiting on the hung push.
    expect(submit.status).toBe(202);
    expect(submit.data.push_wakeups).toBe(1);
    expect(fetchSettled).toBe(false);
    // The per-request timeout then aborts it; a timeout is transient, so the token stays.
    await pushFanOutSettled(acct);
    expect(fetchSettled).toBe(true);
    expect(await readPushTokens(acct)).toEqual([{ token: FCM_ENDPOINT }]);
  });

  it("refuses, but keeps, a stored row that fails the allowlist, without ever requesting it", async () => {
    const acct = testAccount("acct-webpush-legacy-row");
    // A row the earlier no-op stub accepted (any string) before endpoints were validated.
    await seedPushTokenRows(acct, [
      { device_id: "dev-legacy", transport: "webpush", token: "web-token" },
    ]);
    const fetcher = await installWebPush(acct, () => 201);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    try {
      const submit = await post<{ push_wakeups: number }>(
        acct,
        "/requests",
        envelope("req-webpush-legacy-row"),
      );

      expect(submit.status).toBe(202);
      await pushFanOutSettled(acct);
      // A send-time refusal is transient (relay-api.md §5): only a 404/410 from the push service prunes.
      expect(await readPushTokens(acct)).toEqual([{ token: "web-token" }]);
      expect(fetcher).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("schedules nothing for webpush tokens when the relay has no VAPID configuration", async () => {
    const acct = testAccount("acct-webpush-unconfigured");
    // The test Worker has no VAPID bindings, so no webpush transport is registered.
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);

    const submit = await post<{ status: string; push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-webpush-unconfigured"),
    );

    expect(submit.status).toBe(202);
    // `push_wakeups` counts only tokens with a configured transport (relay-api.md §5).
    expect(submit.data.push_wakeups).toBe(0);
    // The token stays registered for when Web Push is configured.
    expect(await readPushTokens(acct)).toEqual([{ token: FCM_ENDPOINT }]);
  });

  it("wakes the newest registrations first when an account holds more rows than the budget", async () => {
    const acct = testAccount("acct-webpush-newest-first");
    // Only rows from before budgets existed can exceed 32; seed 33 with increasing creation times.
    await seedPushTokenRows(
      acct,
      Array.from({ length: 33 }, (_, n) => ({
        device_id: `dev-seed-${String(n)}`,
        transport: "webpush",
        token: `${FCM_ENDPOINT}-seed-${String(n)}`,
        created_at: CREATED_AT + n,
      })),
    );
    const fetcher = await installWebPush(acct, () => 201);

    const submit = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-webpush-newest-first"),
    );

    expect(submit.data.push_wakeups).toBe(32);
    await pushFanOutSettled(acct);
    const requested = fetcher.mock.calls.map(([input]) => String(input));
    expect(requested).toHaveLength(32);
    expect(requested).not.toContain(`${FCM_ENDPOINT}-seed-0`);
    expect(requested).toContain(`${FCM_ENDPOINT}-seed-32`);
  });

  it("sends a payload-less wakeup whose TTL is bounded by the request deadline", async () => {
    const acct = testAccount("acct-webpush-payloadless");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    const submit = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-webpush-payloadless"),
    );

    expect(submit.data.push_wakeups).toBe(1);
    await pushFanOutSettled(acct);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [input, init] = fetcher.mock.calls[0] ?? [];
    const sent = new Request(String(input), init);
    expect((await sent.arrayBuffer()).byteLength).toBe(0);
    // The fixture deadline is in 2100, so the TTL is the 28-day push-service ceiling.
    expect(sent.headers.get("TTL")).toBe(String(28 * 24 * 60 * 60));
    expect(sent.headers.get("Urgency")).toBe("high");
  });
});

describe("submit — Web Push wakeups are coalesced per subscription", () => {
  it("sends one push per subscription for a burst of unauthenticated submits", async () => {
    const acct = testAccount("acct-webpush-coalesce-burst");
    await pairWithPushTokens(acct, [
      { transport: "webpush", token: FCM_ENDPOINT },
      { transport: "webpush", token: MOZILLA_ENDPOINT },
    ]);
    const fetcher = await installWebPush(acct, () => 201);

    const wakeups: number[] = [];
    for (let n = 0; n < 10; n++) {
      // No Authorization header: submit needs no caller auth, which is why coalescing exists.
      const submit = await post<{ status: string; push_wakeups: number }>(
        acct,
        "/requests",
        envelope(`req-webpush-coalesce-${String(n)}`),
      );
      expect(submit.status).toBe(202);
      wakeups.push(submit.data.push_wakeups);
    }

    // The first submit wakes both subscriptions; every later one finds a wakeup in flight or
    // within WEB_PUSH_COALESCE_MS and schedules nothing.
    expect(wakeups).toEqual([2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    await pushFanOutSettled(acct);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("still coalesces after the earlier wakeup has finished, within the window", async () => {
    const acct = testAccount("acct-webpush-coalesce-after-finish");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    const first = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-webpush-coalesce-finish-1"),
    );
    await pushFanOutSettled(acct);
    const second = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-webpush-coalesce-finish-2"),
    );
    await pushFanOutSettled(acct);

    expect(first.data.push_wakeups).toBe(1);
    expect(second.data.push_wakeups).toBe(0);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("does not coalesce APNs wakeups, which carry the request id", async () => {
    const acct = testAccount("acct-webpush-coalesce-apns");
    await pairWithPushTokens(acct, [
      { transport: "webpush", token: FCM_ENDPOINT },
      { transport: "apns", token: "a".repeat(64) },
    ]);
    const apnsRequestIds: string[] = [];
    const apns: PushTransport = {
      kind: "apns",
      sendWakeup(wakeup) {
        apnsRequestIds.push(wakeup.requestId);
        return Promise.resolve();
      },
    };
    const fetcher = vi.fn<typeof fetch>(async () => new Response(null, { status: 201 }));
    await installPushTransports(acct, {
      apns,
      webpush: new WebPushTransport({ vapid: await makeVapid(), fetcher }),
    });

    const first = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-coalesce-apns-1"),
    );
    const second = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope("req-coalesce-apns-2"),
    );
    await pushFanOutSettled(acct);

    expect(first.data.push_wakeups).toBe(2);
    expect(second.data.push_wakeups).toBe(1);
    expect(apnsRequestIds).toEqual(["req-coalesce-apns-1", "req-coalesce-apns-2"]);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// Trailing wakeups (#313): a submit skipped by coalescing still gets a wakeup when the window ends
// ---------------------------------------------------------------------------

/** The relay internals these tests drive. The alarm and the coalescer are not reachable over HTTP. */
type RelayInternals = {
  sql: SqlStorage;
  ctx: DurableObjectState;
  webPushCoalescer: WakeupCoalescer;
  pushTransports: PushTransportRegistry;
  pushFanOut: Promise<void>;
  alarm(): Promise<void>;
};

type TrailingRow = { device_id: string; token: string; due_at: number };

function relayStub(accountId: string): DurableObjectStub {
  return env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
}

async function readTrailingRows(accountId: string): Promise<TrailingRow[]> {
  return runInDurableObject(relayStub(accountId), (instance: AccountRelay) => {
    const relay = instance as unknown as RelayInternals;
    return [
      ...relay.sql.exec<TrailingRow>(
        `SELECT device_id, token, due_at FROM webpush_trailing_wakeup ORDER BY token ASC`,
      ),
    ];
  });
}

/** The `alarm_due` time of each relay alarm purpose, plus the alarm actually set. */
async function readAlarmSchedule(
  accountId: string,
): Promise<{ purposes: Record<string, number>; alarm: number | null }> {
  return runInDurableObject(relayStub(accountId), async (instance: AccountRelay) => {
    const relay = instance as unknown as RelayInternals;
    const purposes: Record<string, number> = {};
    for (const row of relay.sql.exec<{ purpose: string; due_at: number }>(
      `SELECT purpose, due_at FROM alarm_due`,
    )) {
      purposes[row.purpose] = row.due_at;
    }
    return { purposes, alarm: await relay.ctx.storage.getAlarm() };
  });
}

/**
 * Let the coalescing window end, then fire the alarm and wait for its fan-out.
 *
 * Time is not faked inside the Durable Object, so "the window ends" is modelled directly: every
 * owed trailing wakeup (and its alarm purpose) becomes due now. Unless `keepClaims` is set, the
 * window has also passed for every claim ({@link letWindowPass}).
 */
async function endWindowAndRunAlarm(
  accountId: string,
  options: { keepClaims?: boolean } = {},
): Promise<void> {
  await runInDurableObject(relayStub(accountId), async (instance: AccountRelay) => {
    const relay = instance as unknown as RelayInternals;
    makeTrailingWakeupsDue(relay);
    if (options.keepClaims !== true) letWindowPass(relay);
    await relay.alarm();
    await relay.pushFanOut;
  });
}

/**
 * Move every persisted claim, and every skipped submit, far into the past: the state once the
 * window has passed. Claims live in SQLite (#319), so a fresh instance sees the same.
 */
function letWindowPass(relay: RelayInternals): void {
  relay.sql.exec(
    `UPDATE device_push_token SET last_wakeup_at = 1 WHERE last_wakeup_at IS NOT NULL`,
  );
  relay.sql.exec(`UPDATE webpush_trailing_wakeup SET last_skipped_at = 1`);
}

async function letWindowPassFor(accountId: string): Promise<void> {
  await runInDurableObject(relayStub(accountId), (instance: AccountRelay) => {
    letWindowPass(instance as unknown as RelayInternals);
  });
}

function makeTrailingWakeupsDue(relay: RelayInternals): void {
  relay.sql.exec(`UPDATE webpush_trailing_wakeup SET due_at = 1`);
  relay.sql.exec(`UPDATE alarm_due SET due_at = 1 WHERE purpose = 'webpush-trailing-wakeup'`);
}

/** Submit one request (no caller auth) and return its `push_wakeups` count. */
async function submitRequest(accountId: string, body: Record<string, unknown>): Promise<number> {
  const submit = await post<{ push_wakeups: number }>(accountId, "/requests", body);
  expect(submit.status).toBe(202);
  return submit.data.push_wakeups;
}

function ttlOf(fetcher: ReturnType<typeof vi.fn<typeof fetch>>, call: number): string | null {
  const [input, init] = fetcher.mock.calls[call] ?? [];
  return new Request(String(input), init).headers.get("TTL");
}

describe("submit — a coalesced submit gets a trailing wakeup when the window ends (#313)", () => {
  it("sends one more wakeup after the window to a subscription whose submit was coalesced", async () => {
    // The bug: request 1's wakeup was delivered and the inbox fetched before request 2 existed,
    // and request 2's own wakeup was coalesced away, so it was never pushed at all.
    const acct = testAccount("acct-webpush-trailing-basic");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    const before = Date.now();
    expect(await submitRequest(acct, envelope("req-trailing-basic-1"))).toBe(1);
    await pushFanOutSettled(acct);
    expect(await submitRequest(acct, envelope("req-trailing-basic-2"))).toBe(0);
    await pushFanOutSettled(acct);
    expect(fetcher).toHaveBeenCalledTimes(1);

    // The owed wakeup is due just past the window of the first claim, and the alarm is set for it.
    const [row] = await readTrailingRows(acct);
    expect(row?.token).toBe(FCM_ENDPOINT);
    expect(row?.due_at).toBeGreaterThanOrEqual(before + WEB_PUSH_COALESCE_MS + 1);
    expect(row?.due_at).toBeLessThanOrEqual(Date.now() + WEB_PUSH_COALESCE_MS + 1);
    const scheduled = await readAlarmSchedule(acct);
    expect(scheduled.purposes["webpush-trailing-wakeup"]).toBe(row?.due_at);

    await endWindowAndRunAlarm(acct);

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(await readTrailingRows(acct)).toEqual([]);
    expect((await readAlarmSchedule(acct)).purposes["webpush-trailing-wakeup"]).toBeUndefined();
  });

  it("owes one trailing wakeup per subscription however many submits were coalesced", async () => {
    const acct = testAccount("acct-webpush-trailing-burst");
    await pairWithPushTokens(acct, [
      { transport: "webpush", token: FCM_ENDPOINT },
      { transport: "webpush", token: MOZILLA_ENDPOINT },
    ]);
    const fetcher = await installWebPush(acct, () => 201);

    const wakeups: number[] = [];
    for (let n = 0; n < 6; n++) {
      wakeups.push(await submitRequest(acct, envelope(`req-trailing-burst-${String(n)}`)));
    }
    await pushFanOutSettled(acct);
    expect(wakeups).toEqual([2, 0, 0, 0, 0, 0]);
    expect((await readTrailingRows(acct)).map((row) => row.token)).toEqual([
      FCM_ENDPOINT,
      MOZILLA_ENDPOINT,
    ]);

    await endWindowAndRunAlarm(acct);

    // Two leading wakeups plus exactly one trailing wakeup per subscription.
    expect(fetcher).toHaveBeenCalledTimes(4);
    expect(await readTrailingRows(acct)).toEqual([]);
  });

  it("gives the trailing wakeup the TTL of the longest-lived pending request", async () => {
    const acct = testAccount("acct-webpush-trailing-ttl");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    // A short-lived request is woken first; a long-lived one is coalesced behind it.
    await submitRequest(acct, {
      ...envelope("req-trailing-ttl-short"),
      expires_at: Date.now() + 90_000,
    });
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-trailing-ttl-long"));
    await endWindowAndRunAlarm(acct);

    expect(fetcher).toHaveBeenCalledTimes(2);
    // 90 s rounds up to the 5-minute bucket; the 2100 deadline is the 28-day ceiling.
    expect(ttlOf(fetcher, 0)).toBe(String(5 * 60));
    expect(ttlOf(fetcher, 1)).toBe(String(28 * 24 * 60 * 60));
  });

  it("sends nothing when no request is still pending by the time the window ends", async () => {
    const acct = testAccount("acct-webpush-trailing-none-pending");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    await submitRequest(acct, envelope("req-trailing-resolved-1"));
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-trailing-resolved-2"));
    await runInDurableObject(relayStub(acct), (instance: AccountRelay) => {
      (instance as unknown as RelayInternals).sql.exec(
        `UPDATE request SET status = 'resolved', terminal_at = ?`,
        CREATED_AT,
      );
    });

    await endWindowAndRunAlarm(acct);

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(await readTrailingRows(acct)).toEqual([]);
    expect((await readAlarmSchedule(acct)).purposes["webpush-trailing-wakeup"]).toBeUndefined();
  });

  it("sends nothing to a subscription that was removed before the window ended", async () => {
    const acct = testAccount("acct-webpush-trailing-removed");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    await submitRequest(acct, envelope("req-trailing-removed-1"));
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-trailing-removed-2"));
    await runInDurableObject(relayStub(acct), (instance: AccountRelay) => {
      (instance as unknown as RelayInternals).sql.exec(`DELETE FROM device_push_token`);
    });

    await endWindowAndRunAlarm(acct);

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(await readTrailingRows(acct)).toEqual([]);
  });

  it("retries later, without sending, while the subscription is still blocked", async () => {
    const acct = testAccount("acct-webpush-trailing-blocked");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    await submitRequest(acct, envelope("req-trailing-blocked-1"));
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-trailing-blocked-2"));

    // The alarm fires while the coalescer still holds the first claim (as if the alarm ran early):
    // the per-window bound wins, and the owed wakeup moves to the next claimable time.
    const fired = Date.now();
    await endWindowAndRunAlarm(acct, { keepClaims: true });

    expect(fetcher).toHaveBeenCalledTimes(1);
    const [row] = await readTrailingRows(acct);
    expect(row?.due_at).toBeGreaterThanOrEqual(fired + WEB_PUSH_TRAILING_RETRY_MS);
    expect((await readAlarmSchedule(acct)).purposes["webpush-trailing-wakeup"]).toBe(row?.due_at);
  });

  it("waits at least the retry interval while a wakeup is still in flight past its window", async () => {
    // A fan-out can outlast the window (5 s per send, 4 at a time). The owed wakeup must not be
    // re-armed for "now" while the claim is held, which would spin the alarm.
    const acct = testAccount("acct-webpush-trailing-in-flight");
    const { deviceId } = await pairWithPushTokens(acct, [
      { transport: "webpush", token: FCM_ENDPOINT },
    ]);
    const fetcher = await installWebPush(acct, () => 201);
    await submitRequest(acct, envelope("req-trailing-in-flight-1"));
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-trailing-in-flight-2"));

    const fired = Date.now();
    await runInDurableObject(relayStub(acct), async (instance: AccountRelay) => {
      const relay = instance as unknown as RelayInternals;
      // Claimed long ago and never released: in flight, with its window long over.
      const stuck = new WakeupCoalescer(WEB_PUSH_COALESCE_MS);
      stuck.tryClaim(`${String(deviceId)}\0${FCM_ENDPOINT}`, 1);
      relay.webPushCoalescer = stuck;
      makeTrailingWakeupsDue(relay);
      await relay.alarm();
    });

    expect(fetcher).toHaveBeenCalledTimes(1);
    const [row] = await readTrailingRows(acct);
    expect(row?.due_at).toBeGreaterThanOrEqual(fired + WEB_PUSH_TRAILING_RETRY_MS);
  });

  it("clears the owed wakeup when a later submit claims a fresh one after the window", async () => {
    const acct = testAccount("acct-webpush-trailing-superseded");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    await submitRequest(acct, envelope("req-trailing-superseded-1"));
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-trailing-superseded-2"));
    expect(await readTrailingRows(acct)).toHaveLength(1);

    // The window passes and a third submit is woken directly: that wakeup is sent after request 2
    // was stored, so it covers it and nothing more is owed.
    await letWindowPassFor(acct);
    expect(await submitRequest(acct, envelope("req-trailing-superseded-3"))).toBe(1);
    await pushFanOutSettled(acct);
    expect(await readTrailingRows(acct)).toEqual([]);

    await endWindowAndRunAlarm(acct, { keepClaims: true });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("sends the owed wakeup from a fresh instance, after the object was evicted", async () => {
    const acct = testAccount("acct-webpush-trailing-evicted");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    await submitRequest(acct, envelope("req-trailing-evicted-1"));
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-trailing-evicted-2"));

    // A new instance on the same storage: nothing in memory, only what SQLite kept.
    await runInDurableObject(relayStub(acct), async (instance: AccountRelay, state) => {
      const fresh = new AccountRelay(state, env as unknown as Env) as unknown as RelayInternals;
      fresh.pushTransports = (instance as unknown as RelayInternals).pushTransports;
      makeTrailingWakeupsDue(fresh);
      letWindowPass(fresh);
      await fresh.alarm();
      await fresh.pushFanOut;
    });

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(await readTrailingRows(acct)).toEqual([]);
  });

  it("shares the alarm with request expiry: the earlier wins and neither drops the other", async () => {
    const acct = testAccount("acct-webpush-trailing-shared-alarm");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    await installWebPush(acct, () => 201);

    const expiresAt = Date.now() + 10 * 60_000;
    await submitRequest(acct, { ...envelope("req-trailing-shared-1"), expires_at: expiresAt });
    await pushFanOutSettled(acct);
    await submitRequest(acct, { ...envelope("req-trailing-shared-2"), expires_at: expiresAt });

    const both = await readAlarmSchedule(acct);
    const trailingDue = both.purposes["webpush-trailing-wakeup"];
    expect(both.purposes["request-expiry"]).toBe(expiresAt);
    expect(trailingDue).toBeLessThan(expiresAt);
    expect(both.alarm).toBe(trailingDue);

    await endWindowAndRunAlarm(acct);

    const after = await readAlarmSchedule(acct);
    expect(after.purposes).toEqual({ "request-expiry": expiresAt });
    expect(after.alarm).toBe(expiresAt);
  });
});

describe("submit — a wakeup's TTL covers every pending request, not just its own (#261)", () => {
  it("uses the latest pending deadline, and only pending requests count", async () => {
    // With an RFC 8030 Topic, a later wakeup replaces a queued earlier one along with its TTL, so a
    // short-lived request must not cut short the wakeup a long-lived pending one still needs.
    const acct = testAccount("acct-webpush-ttl-latest-pending");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: MOZILLA_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    await submitRequest(acct, envelope("req-ttl-long"));
    await pushFanOutSettled(acct);
    await letWindowPassFor(acct);
    await submitRequest(acct, {
      ...envelope("req-ttl-short-1"),
      expires_at: Date.now() + 90_000,
    });
    await pushFanOutSettled(acct);

    // Once the long-lived request is resolved, only the short-lived ones remain.
    await runInDurableObject(relayStub(acct), (instance: AccountRelay) => {
      (instance as unknown as RelayInternals).sql.exec(
        `UPDATE request SET status = 'resolved', terminal_at = ? WHERE request_id = 'req-ttl-long'`,
        CREATED_AT,
      );
    });
    await letWindowPassFor(acct);
    await submitRequest(acct, {
      ...envelope("req-ttl-short-2"),
      expires_at: Date.now() + 90_000,
    });
    await pushFanOutSettled(acct);

    expect(fetcher).toHaveBeenCalledTimes(3);
    const day28 = String(28 * 24 * 60 * 60);
    expect(ttlOf(fetcher, 0)).toBe(day28);
    // The 90 s request alone would get the 5-minute bucket; the pending 2100 request wins.
    expect(ttlOf(fetcher, 1)).toBe(day28);
    expect(ttlOf(fetcher, 2)).toBe(String(5 * 60));
  });
});

describe("request table — the latest pending deadline is read through an index", () => {
  it("plans latestPendingRequest's query on the partial pending-by-expiry index", async () => {
    // Every unauthenticated submit runs this query, so it must not scan the whole request table.
    const acct = testAccount("acct-request-pending-index");
    const plan = await runInDurableObject(relayStub(acct), (instance: AccountRelay) => [
      ...(instance as unknown as RelayInternals).sql.exec<{ detail: string }>(
        `EXPLAIN QUERY PLAN
         SELECT request_id, expires_at FROM request
         WHERE status = 'pending' AND expires_at > ?
         ORDER BY expires_at DESC LIMIT 1`,
        0,
      ),
    ]);
    const details = plan.map((row) => row.detail).join(" | ");
    expect(details).toContain("request_pending_by_expiry");
    expect(details).not.toContain("USE TEMP B-TREE FOR ORDER BY");
  });
});

describe("submit — the coalescing bound survives eviction (#319)", () => {
  /** Submit through a brand-new `AccountRelay` on the same storage, as after an eviction. */
  async function submitViaFreshInstance(
    accountId: string,
    body: Record<string, unknown>,
  ): Promise<number> {
    return runInDurableObject(relayStub(accountId), async (instance: AccountRelay, state) => {
      const fresh = new AccountRelay(state, env as unknown as Env) as unknown as RelayInternals & {
        fetch(request: Request): Promise<Response>;
      };
      fresh.pushTransports = (instance as unknown as RelayInternals).pushTransports;
      const response = await fresh.fetch(
        new Request(relayUrl(accountId, "/requests"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
      expect(response.status).toBe(202);
      await fresh.pushFanOut;
      return ((await response.json()) as { push_wakeups: number }).push_wakeups;
    });
  }

  it("still coalesces a submit inside the window on a fresh instance, and owes it a trailing wakeup", async () => {
    // Before #319 the last claim lived only in memory: a fresh instance claimed again at once.
    const acct = testAccount("acct-webpush-claims-evicted");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    expect(await submitRequest(acct, envelope("req-claims-evicted-1"))).toBe(1);
    await pushFanOutSettled(acct);
    expect(await submitViaFreshInstance(acct, envelope("req-claims-evicted-2"))).toBe(0);

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(await readTrailingRows(acct)).toHaveLength(1);
  });

  it("lets a fresh instance claim once the window has passed", async () => {
    const acct = testAccount("acct-webpush-claims-evicted-later");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const fetcher = await installWebPush(acct, () => 201);

    await submitRequest(acct, envelope("req-claims-later-1"));
    await pushFanOutSettled(acct);
    await letWindowPassFor(acct);
    expect(await submitViaFreshInstance(acct, envelope("req-claims-later-2"))).toBe(1);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("keeps the claim on the subscription's own token row, so removing the token removes it", async () => {
    const acct = testAccount("acct-webpush-claims-row");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    await installWebPush(acct, () => 201);
    const before = Date.now();
    await submitRequest(acct, envelope("req-claims-row-1"));
    await pushFanOutSettled(acct);

    const rows = await runInDurableObject(relayStub(acct), (instance: AccountRelay) => [
      ...(instance as unknown as RelayInternals).sql.exec<{
        token: string;
        last_wakeup_at: number | null;
      }>(`SELECT token, last_wakeup_at FROM device_push_token`),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.last_wakeup_at).toBeGreaterThanOrEqual(before);
    expect(rows[0]?.last_wakeup_at).toBeLessThanOrEqual(Date.now());
  });
});

describe("submit — an owed trailing wakeup is cleared only by an accepted wakeup (review-317 N2)", () => {
  it("keeps the owed wakeup when the next wakeup fails, and sends it once when that window ends", async () => {
    const acct = testAccount("acct-webpush-n2-retry");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    let status = 201;
    const fetcher = await installWebPush(acct, () => status);

    await submitRequest(acct, envelope("req-n2-retry-1"));
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-n2-retry-2"));
    expect(await readTrailingRows(acct)).toHaveLength(1);

    // The window passes; the next submit is woken directly, but the push service fails it.
    await letWindowPassFor(acct);
    status = 503;
    const claimed = Date.now();
    expect(await submitRequest(acct, envelope("req-n2-retry-3"))).toBe(1);
    await pushFanOutSettled(acct);

    // The owed wakeup is kept, and is not due inside the new window.
    const [row] = await readTrailingRows(acct);
    expect(row?.due_at).toBeGreaterThanOrEqual(claimed + WEB_PUSH_COALESCE_MS + 1);

    status = 201;
    await endWindowAndRunAlarm(acct);
    // Leading 201, the failed 503, then the one retry.
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(await readTrailingRows(acct)).toEqual([]);
  });

  it("retries a failed wakeup only once: a failed trailing send is not owed again", async () => {
    const acct = testAccount("acct-webpush-n2-once");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    let status = 201;
    const fetcher = await installWebPush(acct, () => status);

    await submitRequest(acct, envelope("req-n2-once-1"));
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-n2-once-2"));
    status = 503;
    await endWindowAndRunAlarm(acct);

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(await readTrailingRows(acct)).toEqual([]);
  });

  it("keeps an earlier owed wakeup when another submit is skipped while the accepted wakeup is in flight", async () => {
    // The row predates the claim, but a later skip during the flight must keep it owed: the
    // accepted wakeup covers only submits stored before its claim.
    const acct = testAccount("acct-webpush-n2-in-flight-existing");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    await installWebPush(acct, () => 201);
    await submitRequest(acct, envelope("req-n2-existing-1"));
    await pushFanOutSettled(acct);
    await submitRequest(acct, envelope("req-n2-existing-2"));
    expect(await readTrailingRows(acct)).toHaveLength(1);
    await letWindowPassFor(acct);
    const vapid = await makeVapid();

    const owed = await runInDurableObject(relayStub(acct), async (instance: AccountRelay) => {
      const relay = instance as unknown as RelayInternals & {
        fetch(request: Request): Promise<Response>;
      };
      let release: () => void = () => undefined;
      const blocked = new Promise<void>((resolve) => {
        release = resolve;
      });
      relay.pushTransports = {
        webpush: new WebPushTransport({
          vapid,
          fetcher: async () => {
            await blocked;
            return new Response(null, { status: 201 });
          },
        }),
      };
      for (const id of ["req-n2-existing-3", "req-n2-existing-4"]) {
        await relay.fetch(
          new Request(relayUrl(acct, "/requests"), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(envelope(id)),
          }),
        );
      }
      release();
      await relay.pushFanOut;
      return [...relay.sql.exec<{ token: string }>(`SELECT token FROM webpush_trailing_wakeup`)]
        .length;
    });

    expect(owed).toBe(1);
  });

  it("keeps the owed wakeup for a submit skipped while the accepted wakeup was in flight", async () => {
    // That submit's request may postdate the device's inbox fetch, so the accepted wakeup (claimed
    // before it) does not cover it. The whole race runs inside the Durable Object: workerd forbids
    // resolving the blocked push from another context.
    const acct = testAccount("acct-webpush-n2-in-flight");
    await pairWithPushTokens(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const vapid = await makeVapid();

    const outcome = await runInDurableObject(relayStub(acct), async (instance: AccountRelay) => {
      const relay = instance as unknown as RelayInternals & {
        fetch(request: Request): Promise<Response>;
      };
      let release: () => void = () => undefined;
      const blocked = new Promise<void>((resolve) => {
        release = resolve;
      });
      let calls = 0;
      relay.pushTransports = {
        webpush: new WebPushTransport({
          vapid,
          fetcher: async () => {
            calls++;
            await blocked;
            return new Response(null, { status: 201 });
          },
        }),
      };
      const submit = async (id: string): Promise<number> => {
        const response = await relay.fetch(
          new Request(relayUrl(acct, "/requests"), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(envelope(id)),
          }),
        );
        return ((await response.json()) as { push_wakeups: number }).push_wakeups;
      };

      const first = await submit("req-n2-in-flight-1");
      // Skipped while the first wakeup is still in flight.
      const second = await submit("req-n2-in-flight-2");
      release();
      await relay.pushFanOut;
      const owed = [
        ...relay.sql.exec<{ token: string }>(`SELECT token FROM webpush_trailing_wakeup`),
      ];
      return { first, second, calls, owed: owed.length };
    });

    expect(outcome).toEqual({ first: 1, second: 0, calls: 1, owed: 1 });
  });
});
