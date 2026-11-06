/**
 * Credential transport and negotiation for both live routes. These are real Workers-pool
 * upgrades using issued capabilities; HTTP and query strings cannot supply socket authority.
 * @see ../../../docs/relay-api.md §1, §4
 */
import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import type { AccountRelay } from "../src/index.js";
import { expect, it, vi } from "vitest";
import { pairingStartBody, testAccount, testRequestId } from "./support/accounts.js";
import { DEVICE_X25519_PUBKEY } from "./support/keys.js";
import { pinRelayClock } from "./support/relay-state.js";

const NOW = 4_102_444_500_000;

/** Issue a device capability and a request capability, through their public routes. */
async function fixture(name: string) {
  const account = testAccount(name);
  const base = `https://relay.allw.test/${account}`;
  const startResponse = await exports.default.fetch(`${base}/pairing/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(pairingStartBody(account)),
  });
  expect(startResponse.status).toBe(201);
  const start: { code: string; pairing_auth_token: string } = await startResponse.json();
  const complete = await exports.default.fetch(`${base}/pairing/complete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${start.pairing_auth_token}`,
    },
    body: JSON.stringify({ code: start.code, pubkey: DEVICE_X25519_PUBKEY }),
  });
  expect(complete.status).toBe(201);
  const device: { device_id: string; device_auth_token: string } = await complete.json();
  await pinRelayClock(account, NOW);
  const id = testRequestId(name);
  const submit = await exports.default.fetch(`${base}/requests`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      v: 1,
      id,
      created_at: NOW - 60_000,
      expires_at: NOW + 300_000,
      approver: account,
      context_ciphertext: "opaque-ciphertext",
    }),
  });
  expect(submit.status).toBe(202);
  const request: { request_auth_token: string } = await submit.json();
  return {
    account,
    base,
    device,
    routes: [
      {
        url: `${base}/devices/${device.device_id}/connect`,
        token: device.device_auth_token,
        other: request.request_auth_token,
      },
      {
        url: `${base}/requests/${id}/wait`,
        token: request.request_auth_token,
        other: device.device_auth_token,
      },
    ],
  };
}

/** No credential list is ever reflected in a selected protocol or rejection body. */
it("negotiates only the application marker; refuses query, malformed and wrong-scope credentials", async () => {
  const f = await fixture("subprotocol-contract");
  const foreign = await fixture("subprotocol-foreign");
  const logs = [vi.spyOn(console, "log"), vi.spyOn(console, "warn"), vi.spyOn(console, "error")];
  try {
    for (const route of f.routes) {
      const good = `allw.v1, allw.auth.${route.token}`;
      const success = await exports.default.fetch(route.url, {
        headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": good },
      });
      expect(success.status).toBe(101);
      expect(success.headers.get("Sec-WebSocket-Protocol")).toBe("allw.v1");
      success.webSocket?.accept();
      success.webSocket?.close();
      for (const [offer, status] of [
        [undefined, 401],
        ["allw.v1", 401],
        [`allw.auth.${route.token}`, 401],
        [`allw.v1, allw.auth.${route.token}, allw.auth.${route.token}`, 401],
        [`allw.v1, allw.v1, allw.auth.${route.token}`, 401],
        [`allw.v1, allw.auth.${route.token}, other`, 401],
        ["allw.v1,\u00a0allw.auth.synthetic-invalid", 401],
        ["allw.v1, allw.auth.bad=value", 401],
        ["allw.v1, allw.auth.", 401],
        [`allw.v1, allw.auth.${route.other}`, 403],
        [`allw.v1, allw.auth.${foreign.device.device_auth_token}`, 403],
        ["allw.v1, allw.auth.unknown-token", 403],
      ] as const) {
        const response = await exports.default.fetch(`${route.url}?auth=${route.token}`, {
          headers: {
            Upgrade: "websocket",
            ...(offer === undefined ? {} : { "Sec-WebSocket-Protocol": offer }),
          },
        });
        expect(response.status, offer).toBe(status);
        expect(response.headers.get("Sec-WebSocket-Protocol")).toBeNull();
        expect(await response.text()).not.toContain(route.token);
      }
      const http = await exports.default.fetch(route.url, {
        headers: { "Sec-WebSocket-Protocol": good },
      });
      expect(http.status).toBe(426);
    }
    for (const spy of logs) {
      expect(JSON.stringify(spy.mock.calls)).not.toContain(f.device.device_auth_token);
    }
  } finally {
    for (const spy of logs) spy.mockRestore();
  }
});

it("socket Authorization cannot override offers; HTTP cannot use offers; unknown wait ids preserve auth parity", async () => {
  const f = await fixture("subprotocol-boundaries");
  for (const route of f.routes) {
    for (const authorization of [
      "Bearer wrong-token",
      `Bearer ${route.token}`,
      "Basic bad",
      "Bearer malformed token",
    ]) {
      const response = await exports.default.fetch(route.url, {
        headers: {
          Upgrade: "websocket",
          Authorization: authorization,
          "Sec-WebSocket-Protocol": `allw.v1, allw.auth.${route.token}`,
        },
      });
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain(route.token);
    }
  }
  const route = f.routes[1];
  if (!route) throw new Error("missing request route");
  const unknown = `${f.base}/requests/${testRequestId("unknown-subprotocol")}/wait`;
  for (const offer of [
    undefined,
    "allw.v1, allw.auth.unknown-token",
    "allw.v1, allw.auth.bad=value",
  ]) {
    const replies = [];
    for (const url of [route.url, unknown]) {
      const response = await exports.default.fetch(url, {
        headers: {
          Upgrade: "websocket",
          ...(offer === undefined ? {} : { "Sec-WebSocket-Protocol": offer }),
        },
      });
      replies.push({ status: response.status, body: await response.text() });
    }
    expect(replies[0]).toEqual(replies[1]);
  }
  const httpUrl = route.url.replace(/\/wait$/, "");
  for (const upgrade of [false, true]) {
    const response = await exports.default.fetch(`${httpUrl}?auth=${route.token}`, {
      headers: {
        "Sec-WebSocket-Protocol": `allw.v1, allw.auth.${route.token}`,
        ...(upgrade ? { Upgrade: "websocket" } : {}),
      },
    });
    expect(response.status).toBe(401);
  }
});

it("revoked and foreign devices cannot upgrade; valid protocol ordering does not matter", async () => {
  const f = await fixture("subprotocol-revoked");
  const route = f.routes[0];
  if (!route) throw new Error("missing device route");
  const response = await exports.default.fetch(route.url, {
    headers: {
      Upgrade: "websocket",
      "Sec-WebSocket-Protocol": `allw.auth.${route.token}, allw.v1`,
    },
  });
  expect(response.status).toBe(101);
  expect(response.headers.get("Sec-WebSocket-Protocol")).toBe("allw.v1");
  response.webSocket?.accept();
  response.webSocket?.close();
  const revoked = await exports.default.fetch(`${f.base}/devices/${f.device.device_id}/revoke`, {
    method: "POST",
    headers: { Authorization: `Bearer ${route.token}` },
  });
  expect(revoked.status).toBe(200);
  const after = await exports.default.fetch(route.url, {
    headers: {
      Upgrade: "websocket",
      "Sec-WebSocket-Protocol": `allw.v1, allw.auth.${route.token}`,
    },
  });
  expect(after.status).toBe(404); // preserve the device enrollment check before device auth
  expect(after.headers.get("Sec-WebSocket-Protocol")).toBeNull();
});

it("the connect handler itself cannot use protocol or query credentials on plain HTTP", async () => {
  const f = await fixture("subprotocol-direct-http");
  const statuses = await runInDurableObject(
    env.ACCOUNT.get(env.ACCOUNT.idFromName(f.account)),
    async (relay: AccountRelay) => {
      const url = `${f.base}/devices/${f.device.device_id}/connect?auth=${f.device.device_auth_token}`;
      const response = await relay["handleDeviceConnect"](
        f.device.device_id,
        new Request(url, {
          headers: {
            "Sec-WebSocket-Protocol": `allw.v1, allw.auth.${f.device.device_auth_token}`,
          },
        }),
      );
      return response.status;
    },
  );
  expect(statuses).toBe(401);
});
