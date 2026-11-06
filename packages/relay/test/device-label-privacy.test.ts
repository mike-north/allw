/**
 * Device labels are private to enrolled devices of the same account (#251 item6).
 * Anonymous registry reads remain routing-only so vouch can refuse absent/mismatched keys;
 * neither registry agreement nor authenticated labels confer recipient or certificate trust.
 * @see ../../../docs/relay-api.md §1 Conventions, §3 Devices
 */
import { exports } from "cloudflare:workers";
import { expect, it } from "vitest";
import { pairingStartBody, testAccount, testRequestId } from "./support/accounts.js";
import { DEVICE_X25519_PUBKEY } from "./support/keys.js";
import { pinRelayClock } from "./support/relay-state.js";

/** Fixed pairing/creation instant, also inside submitted requests' valid window. */
const NOW = 1_800_000_000_000;

/** Send through the real Worker router and account Durable Object. */
async function call(account: string, path: string, body?: unknown, authorization?: string) {
  return exports.default.fetch(`https://relay.allw.test/${account}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(authorization === undefined ? {} : { Authorization: authorization }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

/** Issue real relay credentials; no planted token hashes can accidentally bypass enrollment. */
async function enroll(account: string, label: string | null, createdAt = NOW) {
  await pinRelayClock(account, createdAt);
  const start = await call(
    account,
    "/pairing/start",
    pairingStartBody(account, undefined, { issuedAt: createdAt }),
  );
  expect(start.status).toBe(201);
  const pairing = await start.json<{ code: string; pairing_auth_token: string }>();
  const complete = await call(
    account,
    "/pairing/complete",
    { code: pairing.code, pubkey: DEVICE_X25519_PUBKEY, ...(label === null ? {} : { label }) },
    `Bearer ${pairing.pairing_auth_token}`,
  );
  expect(complete.status).toBe(201);
  const device = await complete.json<{ device_id: string; device_auth_token: string }>();
  return { ...device, pairingToken: pairing.pairing_auth_token };
}

it("omits the label member for every anonymous row while preserving routing data/order", async () => {
  const account = testAccount("label-privacy-routing");
  const labels = ["Mike's iPhone", null, "", "phone\u001b[2J\u202eevil"];
  const expected = [];
  let token = "";
  for (const [index, label] of labels.entries()) {
    const createdAt = NOW + index;
    const device = await enroll(account, label ?? null, createdAt);
    token = device.device_auth_token;
    expected.push({
      device_id: device.device_id,
      pubkey: DEVICE_X25519_PUBKEY,
      created_at: createdAt,
      label,
    });
  }
  const anonymous = await call(account, "/devices");
  expect(anonymous.status).toBe(200);
  expect(await anonymous.json()).toEqual({
    devices: expected.map(({ device_id, pubkey, created_at }) => ({
      device_id,
      pubkey,
      created_at,
    })),
  });
  const authenticated = await call(account, "/devices", undefined, `Bearer ${token}`);
  expect(authenticated.status).toBe(200);
  expect(await authenticated.json()).toEqual({ devices: expected });
});

it("refuses malformed, unknown, cross-account, cross-scope and revoked credentials", async () => {
  const account = testAccount("label-privacy-auth");
  const device = await enroll(account, "private label");
  const foreign = await enroll(testAccount("label-privacy-other"), "foreign label");
  const submitted = await call(account, "/requests", {
    v: 1,
    id: testRequestId("label-privacy"),
    created_at: NOW,
    expires_at: NOW + 60_000,
    approver: "routing-id",
    context_ciphertext: "opaque",
  });
  expect(submitted.status).toBe(202);
  const request = await submitted.json<{ request_auth_token: string }>();
  for (const [authorization, status] of [
    ["Basic abc", 401],
    ["Bearer", 401],
    ["Bearer invalid!", 401],
    ["Bearer unknown-token", 403],
    [`Bearer ${foreign.device_auth_token}`, 403],
    [`Bearer ${device.pairingToken}`, 403],
    [`Bearer ${request.request_auth_token}`, 403],
  ] as const) {
    // A valid query token must never rescue a refused Authorization header on HTTP.
    const response = await call(
      account,
      `/devices?auth=${device.device_auth_token}`,
      undefined,
      authorization,
    );
    expect(response.status, authorization.split(" ")[0]).toBe(status);
    expect(await response.json()).toEqual({
      error: status === 401 ? "authorization required" : "authorization denied",
    });
  }
  const revoked = await call(
    account,
    `/devices/${device.device_id}/revoke`,
    {},
    `Bearer ${device.device_auth_token}`,
  );
  expect(revoked.status).toBe(200);
  const response = await call(account, "/devices", undefined, `Bearer ${device.device_auth_token}`);
  expect(response.status).toBe(403);
  expect(await response.json()).toEqual({ error: "authorization denied" });
});

it("never authenticates a query credential; unknown accounts retain the public empty array", async () => {
  const account = testAccount("label-privacy-query");
  const device = await enroll(account, "private label");
  const response = await call(account, `/devices?auth=${device.device_auth_token}`);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({
    devices: [{ device_id: device.device_id, pubkey: DEVICE_X25519_PUBKEY, created_at: NOW }],
  });
  const unknown = testAccount("label-privacy-unbound");
  const publicEmpty = await call(unknown, "/devices");
  expect(publicEmpty.status).toBe(200);
  expect(await publicEmpty.json()).toEqual({ devices: [] });
  const foreign = await call(unknown, "/devices", undefined, `Bearer ${device.device_auth_token}`);
  expect(foreign.status).toBe(403);
  expect(await foreign.json()).toEqual({ error: "authorization denied" });
});
