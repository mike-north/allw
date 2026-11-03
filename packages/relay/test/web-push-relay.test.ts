/**
 * Integration tests for Web Push inside the relay (#235), through the real Worker + `AccountRelay`
 * Durable Object: subscription-endpoint validation at pairing (SSRF allowlist), and pruning a
 * device's token row when the push service reports the subscription gone (404/410), registration
 * budgets, per-subscription coalescing of wakeups from unauthenticated submits, and the fan-out
 * running off the response path, so a push failure or hang never fails or delays the submit.
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
import type { AccountRelay } from "../src/index.js";
import type { PushTransport, PushTransportRegistry } from "../src/push.js";
import { WebPushTransport, type VapidConfig } from "../src/web-push.js";
import { pairingStartBody, testAccount, testRequestId as rid } from "./support/accounts.js";
import { bindAccountRoot, pinRelayClock } from "./support/relay-state.js";

/** A 32-byte base64url-unpadded device key (32 × 0x00). */
const DEVICE_PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/** Far-future expiry (2100-01-01Z, ms) — deterministic and always after the real clock. */
const FUTURE_EXPIRES_AT = 4102444800000;
/**
 * The relay's injected clock for accounts that submit: two minutes before
 * {@link FUTURE_EXPIRES_AT}, so that fixed expiry is inside the request horizon (#248).
 */
const RELAY_NOW = FUTURE_EXPIRES_AT - 2 * 60 * 1000;
/** Accounts whose root is bound and whose relay clock is pinned to {@link RELAY_NOW}. */
const prepared = new Set<string>();
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
  if (subPath === "/requests" && !prepared.has(accountId)) {
    // Submits need a bound root (#248); accounts seeded without pairing bind the test root directly.
    await bindAccountRoot(accountId);
    await pinRelayClock(accountId, RELAY_NOW);
    prepared.add(accountId);
  }
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
    // Same clock as the relay instance, as `buildPushTransports` wires it in production.
    webpush: new WebPushTransport({ vapid: await makeVapid(), fetcher, now: () => RELAY_NOW }),
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
        envelope(rid(`req-webpush-prune-${String(goneStatus)}`)),
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
        envelope(rid(`req-webpush-keep-${String(status)}`)),
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
      envelope(rid("req-webpush-network-error")),
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
      envelope(rid("req-webpush-hanging")),
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
        envelope(rid("req-webpush-legacy-row")),
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
      envelope(rid("req-webpush-unconfigured")),
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
      envelope(rid("req-webpush-newest-first")),
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
      envelope(rid("req-webpush-payloadless")),
    );

    expect(submit.data.push_wakeups).toBe(1);
    await pushFanOutSettled(acct);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [input, init] = fetcher.mock.calls[0] ?? [];
    const sent = new Request(String(input), init);
    expect((await sent.arrayBuffer()).byteLength).toBe(0);
    // The deadline is 2 minutes after the relay clock, rounded up to the 5-minute TTL bucket.
    expect(sent.headers.get("TTL")).toBe(String(5 * 60));
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
        envelope(rid(`req-webpush-coalesce-${String(n)}`)),
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
      envelope(rid("req-webpush-coalesce-finish-1")),
    );
    await pushFanOutSettled(acct);
    const second = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope(rid("req-webpush-coalesce-finish-2")),
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
      envelope(rid("req-coalesce-apns-1")),
    );
    const second = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      envelope(rid("req-coalesce-apns-2")),
    );
    await pushFanOutSettled(acct);

    expect(first.data.push_wakeups).toBe(2);
    expect(second.data.push_wakeups).toBe(1);
    expect(apnsRequestIds).toEqual([rid("req-coalesce-apns-1"), rid("req-coalesce-apns-2")]);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
