/**
 * Integration tests for `PUT /{acct}/devices/{device_id}/push-tokens` (#236): a paired device
 * replaces its own push-token set (add, rotate, clear), through the real Worker + `AccountRelay`
 * Durable Object. Validation is shared with `/pairing/complete` (`optionalPushTokens`), auth is the
 * device bearer, self only, in the revoke handler's order, and the replace is a diff, so repeating
 * a body changes nothing.
 *
 * @see ../../../docs/relay-api.md (§2 subscribe after pairing, §3 device endpoints, §5 push wakeups)
 * @see https://www.rfc-editor.org/rfc/rfc9110#section-9.3.4 (PUT replaces the target's state)
 */

import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import { AccountRelay } from "../src/index.js";
import { WebPushTransport, type VapidConfig } from "../src/web-push.js";
import { pairingStartBody, testAccount, testRequestId } from "./support/accounts.js";
import { pinRelayClock } from "./support/relay-state.js";
import { DEVICE_X25519_PUBKEY } from "./support/keys.js";
import { urlOf } from "./support/fetch-input.js";

/** A full-order X25519 device key (pairing rejects small-order keys, #248). */
const DEVICE_PUBKEY = DEVICE_X25519_PUBKEY;
/** Far-future expiry (2100-01-01Z, ms) — deterministic and always after the relay's clock. */
const FUTURE_EXPIRES_AT = 4102444800000;
/** The relay's injected clock for the submit test: two minutes before {@link FUTURE_EXPIRES_AT}. */
const RELAY_NOW = FUTURE_EXPIRES_AT - 2 * 60 * 1000;
/** A fixed creation timestamp (2023-11-14Z, ms) for seeded rows. */
const SEEDED_AT = 1700000000000;

const FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send/c3Vic2NyaXB0aW9uLWE";
const ROTATED_FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send/c3Vic2NyaXB0aW9uLXJvdGF0ZWQ";
const MOZILLA_ENDPOINT = "https://updates.push.services.mozilla.com/wpush/v2/c3Vic2NyaXB0aW9uLWI";
const APNS_TOKEN = "a".repeat(64);

interface PairedDevice {
  readonly deviceId: string;
  readonly authToken: string;
}

/** A `device_push_token` row. A type alias (not an interface) so it satisfies `SqlStorage.exec`'s row constraint. */
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions -- a type alias satisfies SqlStorage.exec's row constraint; an interface doesn't.
type StoredRow = {
  device_id: string;
  transport: string;
  token: string;
  created_at: number;
};

function relayUrl(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- T types the parsed body for the caller, as Response.json<T>() does.
async function post<T>(
  accountId: string,
  subPath: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; data: T }> {
  const resp = await exports.default.fetch(relayUrl(accountId, subPath), {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: resp.status, data: (await resp.json()) as T };
}

/** PUT a raw body (a string is sent verbatim, so malformed JSON can be tested). */
async function putPushTokens(
  accountId: string,
  deviceId: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; data: { push_tokens?: unknown; error?: string } }> {
  const resp = await exports.default.fetch(
    relayUrl(accountId, `/devices/${deviceId}/push-tokens`),
    {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...headers },
      body: typeof body === "string" ? body : JSON.stringify(body),
    },
  );
  return {
    status: resp.status,
    data: await resp.json<{ push_tokens?: unknown; error?: string }>(),
  };
}

/** Pair one device on `accountId` (binding the root on first use), optionally with push tokens. */
async function pairDevice(accountId: string, pushTokens: unknown = []): Promise<PairedDevice> {
  const start = await post<{ code: string; pairing_auth_token: string }>(
    accountId,
    "/pairing/start",
    pairingStartBody(accountId),
  );
  const complete = await post<{ device_id: string; device_auth_token: string }>(
    accountId,
    "/pairing/complete",
    { code: start.data.code, pubkey: DEVICE_PUBKEY, push_tokens: pushTokens },
    bearer(start.data.pairing_auth_token),
  );
  expect(complete.status).toBe(201);
  return { deviceId: complete.data.device_id, authToken: complete.data.device_auth_token };
}

function accountStub(accountId: string) {
  return env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
}

async function readRows(accountId: string, deviceId?: string): Promise<StoredRow[]> {
  return runInDurableObject(accountStub(accountId), (instance: AccountRelay) => {
    const sql = instance["sql"];
    const rows =
      deviceId === undefined
        ? sql.exec<StoredRow>(
            `SELECT device_id, transport, token, created_at FROM device_push_token
             ORDER BY transport, token`,
          )
        : sql.exec<StoredRow>(
            `SELECT device_id, transport, token, created_at FROM device_push_token
             WHERE device_id = ? ORDER BY transport, token`,
            deviceId,
          );
    return [...rows];
  });
}

async function seedRows(
  accountId: string,
  rows: readonly { device_id: string; transport: string; token: string; created_at?: number }[],
): Promise<void> {
  await runInDurableObject(accountStub(accountId), (instance: AccountRelay) => {
    const sql = instance["sql"];
    for (const row of rows) {
      sql.exec(
        `INSERT INTO device_push_token (device_id, transport, token, created_at) VALUES (?, ?, ?, ?)`,
        row.device_id,
        row.transport,
        row.token,
        row.created_at ?? SEEDED_AT,
      );
    }
  });
}

function otherDeviceRows(count: number) {
  return Array.from({ length: count }, (_, n) => ({
    device_id: `dev-other-${String(n)}`,
    transport: "webpush",
    token: `${FCM_ENDPOINT}-other-${String(n)}`,
  }));
}

describe("PUT /devices/{id}/push-tokens — replace the device's own set", () => {
  it("adds a token to a device paired without one, returning the stored set", async () => {
    const acct = testAccount("acct-push-tokens-add");
    const device = await pairDevice(acct);

    const put = await putPushTokens(
      acct,
      device.deviceId,
      { push_tokens: [{ transport: "webpush", token: FCM_ENDPOINT }] },
      bearer(device.authToken),
    );

    expect(put.status).toBe(200);
    expect(put.data).toEqual({ push_tokens: [{ transport: "webpush", token: FCM_ENDPOINT }] });
    expect(await readRows(acct, device.deviceId)).toEqual([
      expect.objectContaining({ transport: "webpush", token: FCM_ENDPOINT }),
    ]);
  });

  it("rotates: the new set fully replaces the old one", async () => {
    const acct = testAccount("acct-push-tokens-rotate");
    const device = await pairDevice(acct, [
      { transport: "webpush", token: FCM_ENDPOINT },
      { transport: "apns", token: APNS_TOKEN },
    ]);

    const put = await putPushTokens(
      acct,
      device.deviceId,
      { push_tokens: [{ transport: "webpush", token: ROTATED_FCM_ENDPOINT }] },
      bearer(device.authToken),
    );

    expect(put.status).toBe(200);
    expect((await readRows(acct, device.deviceId)).map((row) => row.token)).toEqual([
      ROTATED_FCM_ENDPOINT,
    ]);
  });

  it("clears every token with an empty array", async () => {
    const acct = testAccount("acct-push-tokens-clear");
    const device = await pairDevice(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);

    const put = await putPushTokens(
      acct,
      device.deviceId,
      { push_tokens: [] },
      bearer(device.authToken),
    );

    expect(put.status).toBe(200);
    expect(put.data).toEqual({ push_tokens: [] });
    expect(await readRows(acct, device.deviceId)).toEqual([]);
  });

  it("leaves other devices' tokens untouched", async () => {
    const acct = testAccount("acct-push-tokens-isolated");
    const a = await pairDevice(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const b = await pairDevice(acct, [{ transport: "webpush", token: MOZILLA_ENDPOINT }]);

    await putPushTokens(acct, a.deviceId, { push_tokens: [] }, bearer(a.authToken));

    expect(await readRows(acct)).toEqual([
      expect.objectContaining({ device_id: b.deviceId, token: MOZILLA_ENDPOINT }),
    ]);
  });

  it("is a no-op on a repeat: unchanged rows keep their original created_at", async () => {
    const acct = testAccount("acct-push-tokens-idempotent");
    const device = await pairDevice(acct);
    // Seeded with a fixed timestamp: a delete + re-insert would replace it with the relay's clock.
    await seedRows(acct, [
      { device_id: device.deviceId, transport: "webpush", token: FCM_ENDPOINT },
    ]);
    const body = { push_tokens: [{ transport: "webpush", token: FCM_ENDPOINT }] };

    const first = await putPushTokens(acct, device.deviceId, body, bearer(device.authToken));
    const afterFirst = await readRows(acct, device.deviceId);
    const second = await putPushTokens(acct, device.deviceId, body, bearer(device.authToken));

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(second.data).toEqual(first.data);
    expect(afterFirst).toEqual([
      {
        device_id: device.deviceId,
        transport: "webpush",
        token: FCM_ENDPOINT,
        created_at: SEEDED_AT,
      },
    ]);
    expect(await readRows(acct, device.deviceId)).toEqual(afterFirst);
  });

  it("keeps an unchanged token's row when another token is added alongside it", async () => {
    const acct = testAccount("acct-push-tokens-add-alongside");
    const device = await pairDevice(acct);
    await seedRows(acct, [
      { device_id: device.deviceId, transport: "webpush", token: FCM_ENDPOINT },
    ]);

    await putPushTokens(
      acct,
      device.deviceId,
      {
        push_tokens: [
          { transport: "webpush", token: FCM_ENDPOINT },
          { transport: "webpush", token: MOZILLA_ENDPOINT },
        ],
      },
      bearer(device.authToken),
    );

    const rows = await readRows(acct, device.deviceId);
    expect(rows.map((row) => row.token)).toEqual([FCM_ENDPOINT, MOZILLA_ENDPOINT]);
    expect(rows.find((row) => row.token === FCM_ENDPOINT)?.created_at).toBe(SEEDED_AT);
  });

  it("collapses duplicates, including two spellings of one Web Push subscription", async () => {
    const acct = testAccount("acct-push-tokens-dedupe");
    const device = await pairDevice(acct);

    const put = await putPushTokens(
      acct,
      device.deviceId,
      {
        push_tokens: [
          { transport: "webpush", token: FCM_ENDPOINT },
          { transport: "webpush", token: FCM_ENDPOINT },
          {
            transport: "webpush",
            token: FCM_ENDPOINT.replace("fcm.googleapis.com", "FCM.googleapis.com:443"),
          },
        ],
      },
      bearer(device.authToken),
    );

    expect(put.status).toBe(200);
    expect(put.data).toEqual({ push_tokens: [{ transport: "webpush", token: FCM_ENDPOINT }] });
    expect(await readRows(acct, device.deviceId)).toHaveLength(1);
  });

  it("routes the next wakeup to the rotated endpoint", async () => {
    const acct = testAccount("acct-push-tokens-wakeup");
    const device = await pairDevice(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    await putPushTokens(
      acct,
      device.deviceId,
      { push_tokens: [{ transport: "webpush", token: ROTATED_FCM_ENDPOINT }] },
      bearer(device.authToken),
    );
    const fetcher = vi.fn<typeof fetch>(() => Promise.resolve(new Response(null, { status: 201 })));
    await runInDurableObject(accountStub(acct), async (instance: AccountRelay) => {
      instance["pushTransports"] = {
        webpush: new WebPushTransport({ vapid: await makeVapid(), fetcher }),
      };
    });

    // Pin the clock so the fixed expiry sits inside the request horizon (#248).
    await pinRelayClock(acct, RELAY_NOW);
    const submit = await post<{ push_wakeups: number }>(acct, "/requests", {
      v: 1,
      id: testRequestId("req-push-tokens-rotated"),
      created_at: RELAY_NOW - 60_000,
      expires_at: FUTURE_EXPIRES_AT,
      approver: "acct-approver-routing-id",
      context_ciphertext: "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE",
    });
    await runInDurableObject(accountStub(acct), (instance: AccountRelay) => instance["pushFanOut"]);

    expect(submit.data.push_wakeups).toBe(1);
    expect(fetcher.mock.calls.map(([input]) => urlOf(input))).toEqual([ROTATED_FCM_ENDPOINT]);
  });

  it("never exposes push tokens through GET /devices", async () => {
    const acct = testAccount("acct-push-tokens-list-hidden");
    const device = await pairDevice(acct);
    await putPushTokens(
      acct,
      device.deviceId,
      { push_tokens: [{ transport: "webpush", token: FCM_ENDPOINT }] },
      bearer(device.authToken),
    );

    const list = await exports.default.fetch(relayUrl(acct, "/devices"));
    const text = await list.text();

    expect(list.status).toBe(200);
    expect(text).not.toContain("push_tokens");
    expect(text).not.toContain("fcm.googleapis.com");
  });
});

describe("APNs tokens are stored in one canonical, lowercase spelling (#304)", () => {
  // An APNs device token is hex, which is case-insensitive: two spellings are one device token.
  const UPPER = APNS_TOKEN.toUpperCase();
  const MIXED = "aA".repeat(32);
  /** FCM registration tokens are case-sensitive opaque strings, so their case is kept. */
  const FCM_TOKEN = "AbC:dEf_123-XyZ";

  it("pairing stores both spellings of one APNs token as one lowercase row", async () => {
    const acct = testAccount("acct-apns-case-pairing");
    const device = await pairDevice(acct, [
      { transport: "apns", token: APNS_TOKEN },
      { transport: "apns", token: UPPER },
      { transport: "fcm", token: FCM_TOKEN },
    ]);

    expect((await readRows(acct, device.deviceId)).map((r) => [r.transport, r.token])).toEqual([
      ["apns", APNS_TOKEN],
      ["fcm", FCM_TOKEN],
    ]);
  });

  it("PUT collapses mixed spellings in one body to one lowercase entry", async () => {
    const acct = testAccount("acct-apns-case-put");
    const device = await pairDevice(acct);

    const put = await putPushTokens(
      acct,
      device.deviceId,
      {
        push_tokens: [
          { transport: "apns", token: UPPER },
          { transport: "apns", token: MIXED },
        ],
      },
      bearer(device.authToken),
    );

    // Both spellings are the token APNS_TOKEN ("a" × 64).
    expect(put.status).toBe(200);
    expect(put.data).toEqual({ push_tokens: [{ transport: "apns", token: APNS_TOKEN }] });
    expect(await readRows(acct, device.deviceId)).toHaveLength(1);
  });

  it("PUT re-sending a stored APNs token in uppercase is a no-op (created_at unchanged)", async () => {
    const acct = testAccount("acct-apns-case-noop");
    const device = await pairDevice(acct);
    // Seeded with a fixed timestamp: a delete + re-insert would replace it with the relay's clock.
    await seedRows(acct, [{ device_id: device.deviceId, transport: "apns", token: APNS_TOKEN }]);

    const put = await putPushTokens(
      acct,
      device.deviceId,
      { push_tokens: [{ transport: "apns", token: UPPER }] },
      bearer(device.authToken),
    );

    expect(put.status).toBe(200);
    expect(put.data).toEqual({ push_tokens: [{ transport: "apns", token: APNS_TOKEN }] });
    expect(await readRows(acct, device.deviceId)).toEqual([
      { device_id: device.deviceId, transport: "apns", token: APNS_TOKEN, created_at: SEEDED_AT },
    ]);
  });

  it("migrates rows stored before #304: one lowercase row per device token, FCM untouched", async () => {
    const acct = testAccount("acct-apns-case-migrate");
    const device = await pairDevice(acct);
    const otherDevice = "dev-apns-case-other";
    await seedRows(acct, [
      // Two non-canonical spellings of one token, and no lowercase row: they would collide on the
      // primary key if both were lowercased.
      { device_id: device.deviceId, transport: "apns", token: UPPER },
      { device_id: device.deviceId, transport: "apns", token: "Aa".repeat(32) },
      { device_id: device.deviceId, transport: "fcm", token: FCM_TOKEN },
      // The same token on another device is that device's own row.
      { device_id: otherDevice, transport: "apns", token: UPPER },
      { device_id: otherDevice, transport: "apns", token: "B".repeat(64) },
    ]);

    // A fresh instance on the same storage runs the schema migrations, as after a deploy.
    const migrate = () =>
      runInDurableObject(accountStub(acct), (_instance: AccountRelay, state) => {
        new AccountRelay(state, env);
      });
    await migrate();
    const once = await readRows(acct);
    await migrate();

    expect(await readRows(acct, device.deviceId)).toEqual([
      { device_id: device.deviceId, transport: "apns", token: APNS_TOKEN, created_at: SEEDED_AT },
      { device_id: device.deviceId, transport: "fcm", token: FCM_TOKEN, created_at: SEEDED_AT },
    ]);
    expect(await readRows(acct, otherDevice)).toEqual([
      { device_id: otherDevice, transport: "apns", token: APNS_TOKEN, created_at: SEEDED_AT },
      { device_id: otherDevice, transport: "apns", token: "b".repeat(64), created_at: SEEDED_AT },
    ]);
    // Idempotent: running again changes nothing.
    expect(await readRows(acct)).toEqual(once);
  });

  it("keeps the earliest registration when the migration collapses spellings (review-335)", async () => {
    const acct = testAccount("acct-apns-case-migrate-earliest");
    const lowerFirst = "dev-apns-case-lower-earlier";
    const upperFirst = "dev-apns-case-upper-earlier";
    await seedRows(acct, [
      // Inserted first (lower rowid) but registered later: rowid alone would keep created_at 100.
      { device_id: lowerFirst, transport: "apns", token: UPPER, created_at: 100 },
      { device_id: lowerFirst, transport: "apns", token: APNS_TOKEN, created_at: 50 },
      // The reverse: the earlier registration is the non-canonical spelling.
      { device_id: upperFirst, transport: "apns", token: APNS_TOKEN, created_at: 100 },
      { device_id: upperFirst, transport: "apns", token: UPPER, created_at: 50 },
    ]);

    await runInDurableObject(accountStub(acct), (_instance: AccountRelay, state) => {
      new AccountRelay(state, env);
    });

    expect(await readRows(acct, lowerFirst)).toEqual([
      { device_id: lowerFirst, transport: "apns", token: APNS_TOKEN, created_at: 50 },
    ]);
    expect(await readRows(acct, upperFirst)).toEqual([
      { device_id: upperFirst, transport: "apns", token: APNS_TOKEN, created_at: 50 },
    ]);
  });
});

describe("PUT /devices/{id}/push-tokens — auth (self only, revoke's order)", () => {
  const BODY = { push_tokens: [{ transport: "webpush", token: FCM_ENDPOINT }] };

  it("is 401 without a bearer token, even for a malformed body", async () => {
    const acct = testAccount("acct-push-tokens-no-bearer");
    const device = await pairDevice(acct);

    expect((await putPushTokens(acct, device.deviceId, BODY)).status).toBe(401);
    expect((await putPushTokens(acct, device.deviceId, "{not json")).status).toBe(401);
    expect(await readRows(acct)).toEqual([]);
  });

  it.each([
    ["a lowercase scheme", (token: string) => `bearer ${token}`],
    ["a Basic scheme", () => "Basic YWxsdzphbGx3"],
    ["a malformed bearer value", () => "Bearer a.b"],
  ])("is 401 for a garbled Authorization header (%s)", async (_name, header) => {
    const acct = testAccount(`acct-push-tokens-garbled-${_name.replace(/\W+/g, "-")}`);
    const device = await pairDevice(acct);

    const put = await putPushTokens(acct, device.deviceId, BODY, {
      Authorization: header(device.authToken),
    });

    expect(put.status).toBe(401);
    expect(await readRows(acct)).toEqual([]);
  });

  it("is 403 for a bearer that is no device's token", async () => {
    const acct = testAccount("acct-push-tokens-bad-bearer");
    const device = await pairDevice(acct);

    const put = await putPushTokens(acct, device.deviceId, BODY, bearer("not-a-device-token"));

    expect(put.status).toBe(403);
    expect(await readRows(acct)).toEqual([]);
  });

  it("is 403 when another device's token targets this device", async () => {
    const acct = testAccount("acct-push-tokens-other-device");
    const target = await pairDevice(acct, [{ transport: "webpush", token: MOZILLA_ENDPOINT }]);
    const other = await pairDevice(acct);

    const put = await putPushTokens(acct, target.deviceId, BODY, bearer(other.authToken));

    expect(put.status).toBe(403);
    expect(await readRows(acct, target.deviceId)).toEqual([
      expect.objectContaining({ token: MOZILLA_ENDPOINT }),
    ]);
  });

  it("is 403 for a pairing auth token, which is not a device bearer", async () => {
    const acct = testAccount("acct-push-tokens-pairing-bearer");
    const device = await pairDevice(acct);
    const start = await post<{ code: string; pairing_auth_token: string }>(
      acct,
      "/pairing/start",
      pairingStartBody(acct),
    );
    expect(start.status).toBe(201);

    const put = await putPushTokens(
      acct,
      device.deviceId,
      BODY,
      bearer(start.data.pairing_auth_token),
    );

    expect(put.status).toBe(403);
    expect(await readRows(acct)).toEqual([]);
  });

  it("is 403 for a device bearer from another account, whatever the target", async () => {
    const accountA = testAccount("acct-push-tokens-cross-a");
    const accountB = testAccount("acct-push-tokens-cross-b");
    const unbound = testAccount("acct-push-tokens-cross-unbound");
    const deviceA = await pairDevice(accountA);
    const deviceB = await pairDevice(accountB, [{ transport: "webpush", token: MOZILLA_ENDPOINT }]);

    // A's own device id under account B, B's device under B, and an account with no devices.
    expect(
      (await putPushTokens(accountB, deviceA.deviceId, BODY, bearer(deviceA.authToken))).status,
    ).toBe(403);
    expect(
      (await putPushTokens(accountB, deviceB.deviceId, BODY, bearer(deviceA.authToken))).status,
    ).toBe(403);
    expect(
      (await putPushTokens(unbound, deviceA.deviceId, BODY, bearer(deviceA.authToken))).status,
    ).toBe(403);
    expect((await readRows(accountB)).map((row) => row.token)).toEqual([MOZILLA_ENDPOINT]);
    expect(await readRows(accountA)).toEqual([]);
  });

  it("checks auth and the target device before validating the body", async () => {
    const acct = testAccount("acct-push-tokens-auth-order");
    const target = await pairDevice(acct, [{ transport: "webpush", token: MOZILLA_ENDPOINT }]);
    const other = await pairDevice(acct);

    // Another device's bearer is refused (403) before a malformed or incomplete body is a 400 …
    expect(
      (await putPushTokens(acct, target.deviceId, "{bad", bearer(other.authToken))).status,
    ).toBe(403);
    expect((await putPushTokens(acct, target.deviceId, {}, bearer(other.authToken))).status).toBe(
      403,
    );
    // … and an unknown target is a 404 before the body is judged.
    expect((await putPushTokens(acct, "dev-unknown", "{bad", bearer(other.authToken))).status).toBe(
      404,
    );
    expect((await readRows(acct)).map((row) => row.token)).toEqual([MOZILLA_ENDPOINT]);
  });

  it("is 404 for a device id that is not enrolled", async () => {
    const acct = testAccount("acct-push-tokens-unknown");
    const device = await pairDevice(acct);

    const put = await putPushTokens(acct, "dev-unknown", BODY, bearer(device.authToken));

    expect(put.status).toBe(404);
    expect(await readRows(acct)).toEqual([]);
  });

  it("after a revoke, the device's tokens are gone and the endpoint rejects it", async () => {
    const acct = testAccount("acct-push-tokens-revoked");
    const revoked = await pairDevice(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);
    const survivor = await pairDevice(acct);
    const revoke = await post<{ revoked: boolean }>(
      acct,
      `/devices/${revoked.deviceId}/revoke`,
      {},
      bearer(revoked.authToken),
    );
    expect(revoke.status).toBe(200);
    expect(await readRows(acct)).toEqual([]);

    // Its own (now orphaned) token authorizes nothing, and the device id is no longer enrolled.
    expect(
      (await putPushTokens(acct, revoked.deviceId, BODY, bearer(revoked.authToken))).status,
    ).toBe(403);
    expect(
      (await putPushTokens(acct, revoked.deviceId, BODY, bearer(survivor.authToken))).status,
    ).toBe(404);
    expect(await readRows(acct)).toEqual([]);
  });
});

describe("PUT /devices/{id}/push-tokens — validation shared with pairing", () => {
  it.each([
    ["invalid JSON", "{not json"],
    ["a non-object body", "[]"],
    ["a missing push_tokens", {}],
    ["a non-array push_tokens", { push_tokens: { transport: "webpush", token: FCM_ENDPOINT } }],
    ["an unsupported transport", { push_tokens: [{ transport: "sms", token: "+15555550100" }] }],
    ["a malformed APNs token", { push_tokens: [{ transport: "apns", token: "not-hex" }] }],
    ["an over-long token", { push_tokens: [{ transport: "fcm", token: "f".repeat(4097) }] }],
    ["an empty token", { push_tokens: [{ transport: "fcm", token: "" }] }],
    [
      "a non-allowlisted Web Push endpoint",
      { push_tokens: [{ transport: "webpush", token: "https://push.attacker.example/abc" }] },
    ],
    [
      "more than four entries",
      {
        push_tokens: [
          { transport: "webpush", token: FCM_ENDPOINT },
          { transport: "webpush", token: MOZILLA_ENDPOINT },
          { transport: "apns", token: APNS_TOKEN },
          { transport: "apns", token: "b".repeat(64) },
          { transport: "fcm", token: "fcm-token-1" },
        ],
      },
    ],
    [
      "more than two tokens for one transport",
      {
        push_tokens: [
          { transport: "fcm", token: "fcm-token-1" },
          { transport: "fcm", token: "fcm-token-2" },
          { transport: "fcm", token: "fcm-token-3" },
        ],
      },
    ],
  ])("rejects %s with 400 and leaves the stored set unchanged", async (_name, body) => {
    const acct = testAccount(`acct-push-tokens-400-${_name.replace(/\W+/g, "-")}`);
    const device = await pairDevice(acct, [{ transport: "webpush", token: FCM_ENDPOINT }]);

    const put = await putPushTokens(acct, device.deviceId, body, bearer(device.authToken));

    expect(put.status).toBe(400);
    expect(put.data.error).toEqual(expect.any(String));
    expect((await readRows(acct, device.deviceId)).map((row) => row.token)).toEqual([FCM_ENDPOINT]);
  });

  it("accepts exactly four entries (the per-registration accept boundary)", async () => {
    const acct = testAccount("acct-push-tokens-exactly-four");
    const device = await pairDevice(acct);

    const put = await putPushTokens(
      acct,
      device.deviceId,
      {
        push_tokens: [
          { transport: "webpush", token: FCM_ENDPOINT },
          { transport: "webpush", token: MOZILLA_ENDPOINT },
          { transport: "apns", token: APNS_TOKEN },
          { transport: "fcm", token: "fcm-token-1" },
        ],
      },
      bearer(device.authToken),
    );

    expect(put.status).toBe(200);
    expect(await readRows(acct, device.deviceId)).toHaveLength(4);
  });
});

describe("PUT /devices/{id}/push-tokens — account budget", () => {
  it("is 409 when other devices' tokens plus the new set exceed 32, changing nothing", async () => {
    const acct = testAccount("acct-push-tokens-budget-409");
    const device = await pairDevice(acct, [{ transport: "apns", token: APNS_TOKEN }]);
    await seedRows(acct, otherDeviceRows(31));

    const put = await putPushTokens(
      acct,
      device.deviceId,
      {
        push_tokens: [
          { transport: "webpush", token: FCM_ENDPOINT },
          { transport: "webpush", token: MOZILLA_ENDPOINT },
        ],
      },
      bearer(device.authToken),
    );

    expect(put.status).toBe(409);
    expect(put.data.error).toMatch(/push-token limit/);
    expect((await readRows(acct, device.deviceId)).map((row) => row.token)).toEqual([APNS_TOKEN]);
  });

  it("never refuses a clear, even on an account already over the budget (legacy rows)", async () => {
    const acct = testAccount("acct-push-tokens-budget-legacy-clear");
    const device = await pairDevice(acct, [{ transport: "apns", token: APNS_TOKEN }]);
    // Only rows from before budgets existed can exceed 32.
    await seedRows(acct, otherDeviceRows(33));

    const cleared = await putPushTokens(
      acct,
      device.deviceId,
      { push_tokens: [] },
      bearer(device.authToken),
    );

    expect(cleared.status).toBe(200);
    expect(await readRows(acct, device.deviceId)).toEqual([]);
  });

  it("still refuses growth on an account already over the budget", async () => {
    const acct = testAccount("acct-push-tokens-budget-legacy-grow");
    const device = await pairDevice(acct, [{ transport: "apns", token: APNS_TOKEN }]);
    await seedRows(acct, otherDeviceRows(33));

    const grown = await putPushTokens(
      acct,
      device.deviceId,
      {
        push_tokens: [
          { transport: "apns", token: APNS_TOKEN },
          { transport: "webpush", token: FCM_ENDPOINT },
        ],
      },
      bearer(device.authToken),
    );

    expect(grown.status).toBe(409);
    expect((await readRows(acct, device.deviceId)).map((row) => row.token)).toEqual([APNS_TOKEN]);
  });

  it("does not count the device's own rows, so a full account can still rotate", async () => {
    const acct = testAccount("acct-push-tokens-budget-rotate");
    const device = await pairDevice(acct, [
      { transport: "webpush", token: FCM_ENDPOINT },
      { transport: "apns", token: APNS_TOKEN },
    ]);
    await seedRows(acct, otherDeviceRows(30));
    expect(await readRows(acct)).toHaveLength(32);

    const put = await putPushTokens(
      acct,
      device.deviceId,
      {
        push_tokens: [
          { transport: "webpush", token: ROTATED_FCM_ENDPOINT },
          { transport: "webpush", token: MOZILLA_ENDPOINT },
        ],
      },
      bearer(device.authToken),
    );

    expect(put.status).toBe(200);
    expect(await readRows(acct)).toHaveLength(32);
  });
});

describe("/devices/{id}/push-tokens — routing", () => {
  it.each(["GET", "POST", "DELETE"])("is 405 for %s", async (method) => {
    const acct = testAccount(`acct-push-tokens-405-${method.toLowerCase()}`);
    const device = await pairDevice(acct);

    const resp = await exports.default.fetch(
      relayUrl(acct, `/devices/${device.deviceId}/push-tokens`),
      {
        method,
        headers: bearer(device.authToken),
      },
    );

    expect(resp.status).toBe(405);
  });

  it("is 404 for a deeper sub-path", async () => {
    const acct = testAccount("acct-push-tokens-deeper");
    const device = await pairDevice(acct);

    const resp = await exports.default.fetch(
      relayUrl(acct, `/devices/${device.deviceId}/push-tokens/extra`),
      {
        method: "PUT",
        headers: bearer(device.authToken),
        body: JSON.stringify({ push_tokens: [] }),
      },
    );
    expect(resp.status).toBe(404);
  });
});

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
