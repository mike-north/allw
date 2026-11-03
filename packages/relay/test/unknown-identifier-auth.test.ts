/**
 * Token-guarded identifiers never reveal whether they exist before the token is checked (#357).
 *
 * A request id (`GET /requests/{id}`, `GET /requests/{id}/wait`, `POST /requests/{id}/retract`) and
 * a pairing code (`POST /pairing/complete`) are each guarded by their own bearer token, whose hash
 * lives in the identifier's row. Without the right token, the relay must answer an identifier that
 * exists and one that does not identically, in status and body. Otherwise an unauthenticated caller
 * can probe for live identifiers.
 *
 * The expected answers are the relay's auth errors (`docs/relay-api.md` §Authentication and each
 * route's error order): no bearer token is `401 {"error":"authorization required"}`, and a token
 * that does not match is `403 {"error":"authorization denied"}`. Each test also shows the right
 * token still works on the existing identifier, so "exists" is real and not a typo.
 */
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import type { SqlStorage } from "@cloudflare/workers-types";
import { pairingStartBody, testAccount } from "./support/accounts.js";
import { DEVICE_X25519_PUBKEY } from "./support/keys.js";

/** Fixed envelope timestamps (never `Date.now()` in data); the expiry is far in the future. */
const CREATED_AT = 1_700_000_000_000;
const FUTURE_EXPIRES_AT = 4_102_444_800_000;

const NO_TOKEN = { status: 401, body: { error: "authorization required" } };
const WRONG_TOKEN = { status: 403, body: { error: "authorization denied" } };

/** A bearer token no row was issued for (the same shape as a real one). */
const STRANGER_TOKEN = "c3RyYW5nZXItdG9rZW4tbm90LWlzc3VlZC1ieS10aGlzLXJlbGF5";

interface Reply {
  readonly status: number;
  readonly body: unknown;
}

function relayUrl(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

async function call(
  accountId: string,
  method: "GET" | "POST",
  subPath: string,
  options: { token?: string | undefined; body?: unknown; websocket?: boolean } = {},
): Promise<Reply> {
  const headers: Record<string, string> = {};
  if (options.token !== undefined) headers.Authorization = `Bearer ${options.token}`;
  if (options.websocket) headers.Upgrade = "websocket";
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const resp = await SELF.fetch(relayUrl(accountId, subPath), {
    method,
    headers,
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });
  return { status: resp.status, body: await resp.json() };
}

/**
 * The unauthenticated replies for `existing` and `unknown` through `send`, with no token and with a
 * stranger's token: each pair must be identical, and equal to the relay's auth error.
 */
async function expectIndistinguishable(
  send: (id: string, token: string | undefined) => Promise<Reply>,
  existing: string,
  unknown: string,
): Promise<void> {
  for (const [token, expected] of [
    [undefined, NO_TOKEN],
    [STRANGER_TOKEN, WRONG_TOKEN],
  ] as const) {
    const forExisting = await send(existing, token);
    const forUnknown = await send(unknown, token);
    expect(forUnknown).toEqual(forExisting);
    expect(forExisting).toEqual(expected);
  }
}

/** Submit a pending request; returns its request-scoped auth token. */
async function submit(accountId: string, requestId: string): Promise<string> {
  const resp = await SELF.fetch(relayUrl(accountId, "/requests"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      v: 1,
      id: requestId,
      created_at: CREATED_AT,
      expires_at: FUTURE_EXPIRES_AT,
      approver: "acct-approver-routing-id",
      context_ciphertext: "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE",
    }),
  });
  expect(resp.status).toBe(202);
  const data: { request_auth_token: string } = await resp.json();
  return data.request_auth_token;
}

describe("request ids: an unknown id answers like a wrong token (#357)", () => {
  it("GET /requests/{id}", async () => {
    const acct = testAccount("acct-oracle-poll");
    const token = await submit(acct, "req-oracle-poll");
    await expectIndistinguishable(
      (id, t) => call(acct, "GET", `/requests/${id}`, { token: t }),
      "req-oracle-poll",
      "req-oracle-poll-unknown",
    );
    const owner = await call(acct, "GET", "/requests/req-oracle-poll", { token });
    expect(owner).toEqual({
      status: 200,
      body: { request_id: "req-oracle-poll", status: "pending" },
    });
  });

  it("GET /requests/{id}/wait", async () => {
    const acct = testAccount("acct-oracle-wait");
    const token = await submit(acct, "req-oracle-wait");
    await expectIndistinguishable(
      (id, t) => call(acct, "GET", `/requests/${id}/wait`, { token: t, websocket: true }),
      "req-oracle-wait",
      "req-oracle-wait-unknown",
    );
    const owner = await SELF.fetch(relayUrl(acct, "/requests/req-oracle-wait/wait"), {
      headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` },
    });
    expect(owner.status).toBe(101);
    owner.webSocket?.accept();
    owner.webSocket?.close();
  });

  it("POST /requests/{id}/retract", async () => {
    const acct = testAccount("acct-oracle-retract");
    const token = await submit(acct, "req-oracle-retract");
    await expectIndistinguishable(
      (id, t) => call(acct, "POST", `/requests/${id}/retract`, { token: t, body: {} }),
      "req-oracle-retract",
      "req-oracle-retract-unknown",
    );
    // The probes changed nothing: the owner's retract is the first to land.
    const owner = await call(acct, "POST", "/requests/req-oracle-retract/retract", {
      token,
      body: {},
    });
    expect(owner.status).toBe(200);
  });
});

describe("pairing codes: an unknown code answers like a wrong token (#357)", () => {
  interface PairingStart {
    code: string;
    pairing_auth_token: string;
  }

  async function startPairing(accountId: string): Promise<PairingStart> {
    const resp = await SELF.fetch(relayUrl(accountId, "/pairing/start"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(pairingStartBody(accountId)),
    });
    expect(resp.status).toBe(201);
    return resp.json();
  }

  const complete = (accountId: string) => (code: string, token: string | undefined) =>
    call(accountId, "POST", "/pairing/complete", {
      token,
      body: { code, pubkey: DEVICE_X25519_PUBKEY },
    });

  it("POST /pairing/complete", async () => {
    const acct = testAccount("acct-oracle-pairing");
    const start = await startPairing(acct);
    // A real code from another account: the right shape, but no row in this account.
    const elsewhere = await startPairing(testAccount("acct-oracle-pairing-elsewhere"));
    expect(elsewhere.code).not.toBe(start.code);

    await expectIndistinguishable(complete(acct), start.code, elsewhere.code);

    // The probes did not consume the code: its own token still completes the pairing.
    const owner = await complete(acct)(start.code, start.pairing_auth_token);
    expect(owner.status).toBe(201);
  });

  it("a legacy code with no stored token hash answers like an unknown code", async () => {
    const acct = testAccount("acct-oracle-pairing-legacy");
    const start = await startPairing(acct);
    await runInDurableObject(env.ACCOUNT.get(env.ACCOUNT.idFromName(acct)), (instance) => {
      const relay = instance as unknown as { sql: SqlStorage };
      relay.sql.exec(`UPDATE pairing SET auth_token_hash = NULL WHERE code = ?`, start.code);
    });
    const unknown = (await startPairing(testAccount("acct-oracle-pairing-legacy-elsewhere"))).code;

    await expectIndistinguishable(complete(acct), start.code, unknown);
    // Fail-closed: not even the token issued with the code completes a row without a hash.
    expect(await complete(acct)(start.code, start.pairing_auth_token)).toEqual(WRONG_TOKEN);
  });
});
