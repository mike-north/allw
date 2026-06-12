/**
 * Tests for `AccountRelay` Durable Object — device pairing, actor enrollment, and revocation.
 *
 * These tests run inside a real `workerd` runtime via `@cloudflare/vitest-pool-workers`,
 * so they exercise the actual SQLite storage and the full HTTP API surface.
 *
 * # Zero-knowledge invariant
 * Each returned record is asserted to contain ONLY public-key material + routing metadata.
 * No private-key or plaintext-secret field may appear.
 *
 * # Test isolation
 * Each test uses a distinct account id (e.g. `acct-<test-name>`) to get a fresh DO instance
 * from `idFromName(accountId)`.
 */

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { AccountRelay } from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Valid 32-byte Ed25519/X25519 public keys encoded as base64url-unpadded (43 chars each).
 * These are deterministic test vectors — not real key material.
 *
 * VALID_PUBKEY_1: 32 × 0x00 (all zero bytes)
 * VALID_PUBKEY_2: 32 × 0xFF (all 0xFF bytes)
 */
const VALID_PUBKEY_1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 × 0x00, base64url-unpadded
const VALID_PUBKEY_2 = "__________________________________________8"; // 32 × 0xFF, base64url-unpadded
const VALID_APNS_TOKEN = "a".repeat(64);
const VALID_FCM_TOKEN = "fcm-token_123:abc";

/**
 * Build the URL for a request to a given account's sub-path.
 * The Worker routes `/:accountId/...` → the DO, which strips the leading `/<accountId>` segment.
 */
function relayUrl(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

/**
 * POST a JSON body to the relay and return the parsed response.
 */
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
  const data = (await resp.json()) as T;
  return { status: resp.status, data };
}

/**
 * GET a resource from the relay and return the parsed response.
 */
async function get<T>(accountId: string, subPath: string): Promise<{ status: number; data: T }> {
  const resp = await SELF.fetch(relayUrl(accountId, subPath), {
    method: "GET",
  });
  const data = (await resp.json()) as T;
  return { status: resp.status, data };
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

interface PairingStartResult {
  code: string;
  expires_at: number;
  pairing_auth_token: string;
}

interface PairingCompleteResult {
  device_id: string;
  device_auth_token: string;
}

async function startPairing(accountId: string, label?: string): Promise<PairingStartResult> {
  const body = label === undefined ? {} : { label };
  const { status, data } = await post<PairingStartResult>(accountId, "/pairing/start", body);
  expect(status).toBe(201);
  expect(typeof data.pairing_auth_token).toBe("string");
  return data;
}

async function completePairing(
  accountId: string,
  start: PairingStartResult,
  body: Record<string, unknown> = {},
): Promise<{ status: number; data: PairingCompleteResult }> {
  return post<PairingCompleteResult>(
    accountId,
    "/pairing/complete",
    { code: start.code, pubkey: VALID_PUBKEY_1, ...body },
    bearer(start.pairing_auth_token),
  );
}

async function enrollDevice(accountId: string): Promise<PairingCompleteResult> {
  const start = await startPairing(accountId);
  const complete = await completePairing(accountId, start);
  expect(complete.status).toBe(201);
  return complete.data;
}

async function expirePairing(accountId: string, code: string): Promise<void> {
  const id = env.ACCOUNT.idFromName(accountId);
  const stub = env.ACCOUNT.get(id);
  await runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    relay.sql.exec(`UPDATE pairing SET expires_at = ? WHERE code = ?`, Date.now() - 1, code);
  });
}

async function readPushTokens(
  accountId: string,
  deviceId: string,
): Promise<Array<{ transport: string; token: string }>> {
  const id = env.ACCOUNT.idFromName(accountId);
  const stub = env.ACCOUNT.get(id);
  return runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    return [
      ...relay.sql.exec<{ transport: string; token: string }>(
        `SELECT transport, token FROM device_push_token
         WHERE device_id = ? ORDER BY created_at ASC`,
        deviceId,
      ),
    ];
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AccountRelay — pairing", () => {
  it("starts a pairing and returns a code + expires_at", async () => {
    const { status, data } = await post<PairingStartResult>(
      "acct-pairing-start",
      "/pairing/start",
      { label: "My MacBook" },
    );
    expect(status).toBe(201);
    expect(typeof data.code).toBe("string");
    expect(data.code.length).toBe(8);
    expect(typeof data.expires_at).toBe("number");
    expect(data.expires_at).toBeGreaterThan(Date.now());
    expect(typeof data.pairing_auth_token).toBe("string");
    expect(data.pairing_auth_token.length).toBeGreaterThan(40);
  });

  it("completes pairing: returns device_id and the device appears in /devices", async () => {
    const acct = "acct-pairing-complete";

    const start = await startPairing(acct, "My Phone");

    // Complete pairing
    const completeResp = await completePairing(acct, start, { label: "My Phone" });
    expect(completeResp.status).toBe(201);
    const { device_id, device_auth_token } = completeResp.data;
    expect(typeof device_id).toBe("string");
    expect(device_id.length).toBeGreaterThan(0);
    expect(typeof device_auth_token).toBe("string");
    expect(device_auth_token.length).toBeGreaterThan(40);

    // GET /devices
    const listResp = await get<{
      devices: Array<{
        device_id: string;
        pubkey: string;
        label: string | null;
        created_at: number;
      }>;
    }>(acct, "/devices");
    expect(listResp.status).toBe(200);

    const devices = listResp.data.devices;
    expect(devices).toHaveLength(1);
    const device = devices[0];
    expect(device).toBeDefined();
    // Verify the returned fields match what was enrolled
    expect(device?.device_id).toBe(device_id);
    expect(device?.pubkey).toBe(VALID_PUBKEY_1);
    expect(device?.label).toBe("My Phone");
    expect(typeof device?.created_at).toBe("number");

    // ZERO-KNOWLEDGE INVARIANT: the device record must contain ONLY these fields.
    // No private key or plaintext secret must appear.
    const allowedKeys = new Set(["device_id", "pubkey", "label", "created_at"]);
    const actualKeys = new Set(Object.keys(device ?? {}));
    for (const key of actualKeys) {
      expect(allowedKeys.has(key)).toBe(true);
    }
  });

  it("requires the pairing auth token to complete pairing and does not consume the code on auth failure", async () => {
    const acct = "acct-pairing-complete-auth";
    const start = await startPairing(acct);

    const noAuth = await post<{ error: string }>(acct, "/pairing/complete", {
      code: start.code,
      pubkey: VALID_PUBKEY_1,
    });
    expect(noAuth.status).toBe(401);

    const wrongAuth = await post<{ error: string }>(
      acct,
      "/pairing/complete",
      { code: start.code, pubkey: VALID_PUBKEY_1 },
      bearer("wrong-token"),
    );
    expect(wrongAuth.status).toBe(403);

    const goodAuth = await completePairing(acct, start);
    expect(goodAuth.status).toBe(201);
  });

  it("fails closed when a legacy pairing row has no stored auth-token hash", async () => {
    const acct = "acct-pairing-null-auth-hash";
    const start = await startPairing(acct);

    await runInDurableObject(env.ACCOUNT.get(env.ACCOUNT.idFromName(acct)), (instance) => {
      const relay = instance as unknown as { sql: SqlStorage };
      relay.sql.exec(`UPDATE pairing SET auth_token_hash = NULL WHERE code = ?`, start.code);
    });

    const noAuth = await post<{ error: string }>(acct, "/pairing/complete", {
      code: start.code,
      pubkey: VALID_PUBKEY_1,
    });
    expect(noAuth.status).toBe(401);
  });

  it("stores push tokens supplied while completing pairing without exposing them in /devices", async () => {
    const acct = "acct-pairing-push-token";
    const startResp = await startPairing(acct, "Phone");

    const completeResp = await completePairing(acct, startResp, {
      push_tokens: [
        { transport: "apns", token: VALID_APNS_TOKEN },
        { transport: "fcm", token: VALID_FCM_TOKEN },
      ],
    });
    expect(completeResp.status).toBe(201);

    const stored = await readPushTokens(acct, completeResp.data.device_id);
    expect(stored).toEqual([
      { transport: "apns", token: VALID_APNS_TOKEN },
      { transport: "fcm", token: VALID_FCM_TOKEN },
    ]);

    const listResp = await get<{ devices: Array<Record<string, unknown>> }>(acct, "/devices");
    expect(listResp.data.devices[0]).not.toHaveProperty("push_tokens");
  });

  it("deduplicates repeated push tokens before consuming the pairing code", async () => {
    const acct = "acct-pairing-duplicate-push-token";
    const startResp = await startPairing(acct, "Phone");

    const completeResp = await completePairing(acct, startResp, {
      push_tokens: [
        { transport: "apns", token: VALID_APNS_TOKEN },
        { transport: "apns", token: VALID_APNS_TOKEN },
      ],
    });
    expect(completeResp.status).toBe(201);

    const stored = await readPushTokens(acct, completeResp.data.device_id);
    expect(stored).toEqual([{ transport: "apns", token: VALID_APNS_TOKEN }]);
  });

  it("rejects malformed push tokens before consuming the pairing code", async () => {
    const acct = "acct-pairing-bad-push-token";
    const startResp = await startPairing(acct);

    const badComplete = await post<{ error: string }>(
      acct,
      "/pairing/complete",
      {
        code: startResp.code,
        pubkey: VALID_PUBKEY_1,
        push_tokens: [{ transport: "email", token: "not-a-push-transport" }],
      },
      bearer(startResp.pairing_auth_token),
    );
    expect(badComplete.status).toBe(400);
    expect(badComplete.data.error).toMatch(/push_tokens/);

    const goodComplete = await completePairing(acct, startResp);
    expect(goodComplete.status).toBe(201);
  });

  it("rejects malformed APNs and FCM token formats before consuming the pairing code", async () => {
    const acct = "acct-pairing-transport-token-format";
    const badApns = await startPairing(acct);
    const apnsResp = await post<{ error: string }>(
      acct,
      "/pairing/complete",
      {
        code: badApns.code,
        pubkey: VALID_PUBKEY_1,
        push_tokens: [{ transport: "apns", token: "not-hex" }],
      },
      bearer(badApns.pairing_auth_token),
    );
    expect(apnsResp.status).toBe(400);

    const badFcm = await startPairing(acct);
    const fcmResp = await post<{ error: string }>(
      acct,
      "/pairing/complete",
      {
        code: badFcm.code,
        pubkey: VALID_PUBKEY_1,
        push_tokens: [{ transport: "fcm", token: "has whitespace" }],
      },
      bearer(badFcm.pairing_auth_token),
    );
    expect(fcmResp.status).toBe(400);

    const goodComplete = await completePairing(acct, badApns);
    expect(goodComplete.status).toBe(201);
  });

  it("rejects completing a pairing with an unknown code (404)", async () => {
    const { status, data } = await post<{ error: string }>(
      "acct-unknown-code",
      "/pairing/complete",
      { code: "XXXXXXXX", pubkey: VALID_PUBKEY_1 },
    );
    expect(status).toBe(404);
    expect(typeof data.error).toBe("string");

    // No device should have been added
    const listResp = await get<{ devices: unknown[] }>("acct-unknown-code", "/devices");
    expect(listResp.data.devices).toHaveLength(0);
  });

  it("rejects completing a pairing that was already used (409)", async () => {
    const acct = "acct-already-used";

    const startData = await startPairing(acct);

    // First complete — succeeds
    await completePairing(acct, startData);

    // Second complete with same code — must be rejected
    const { status, data } = await post<{ error: string }>(
      acct,
      "/pairing/complete",
      {
        code: startData.code,
        pubkey: VALID_PUBKEY_2,
      },
      bearer(startData.pairing_auth_token),
    );
    expect(status).toBe(409);
    expect(typeof data.error).toBe("string");

    // Only one device should exist
    const listResp = await get<{ devices: unknown[] }>(acct, "/devices");
    expect(listResp.data.devices).toHaveLength(1);
  });

  it("rejects completing an expired pairing code (410)", async () => {
    const acct = "acct-expired-code";
    const start = await startPairing(acct);
    await expirePairing(acct, start.code);

    const { status, data } = await post<{ error: string }>(
      acct,
      "/pairing/complete",
      {
        code: start.code,
        pubkey: VALID_PUBKEY_1,
      },
      bearer(start.pairing_auth_token),
    );
    expect(status).toBe(410);
    expect(typeof data.error).toBe("string");

    // No device should have been added
    const listResp = await get<{ devices: unknown[] }>(acct, "/devices");
    expect(listResp.data.devices).toHaveLength(0);
  });

  it("rejects a pubkey that is not 32 bytes (400)", async () => {
    const acct = "acct-bad-pubkey";
    const startData = await startPairing(acct);

    // 19 base64url chars (decodes to ~14 bytes) — not the 43 chars / 32 bytes a valid key needs.
    const shortPubkey = "AAAAAAAAAAAAAAAAAAA";

    const { status, data } = await post<{ error: string }>(
      acct,
      "/pairing/complete",
      {
        code: startData.code,
        pubkey: shortPubkey,
      },
      bearer(startData.pairing_auth_token),
    );
    expect(status).toBe(400);
    expect(typeof data.error).toBe("string");

    // No device added
    const listResp = await get<{ devices: unknown[] }>(acct, "/devices");
    expect(listResp.data.devices).toHaveLength(0);
  });

  it("rejects a pubkey that contains non-base64url characters (400)", async () => {
    const acct = "acct-bad-b64";
    const startData = await startPairing(acct);

    // Contains '+' which is standard base64 but not base64url
    const badPubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+";

    const { status } = await post(
      acct,
      "/pairing/complete",
      {
        code: startData.code,
        pubkey: badPubkey,
      },
      bearer(startData.pairing_auth_token),
    );
    expect(status).toBe(400);
  });
});

describe("AccountRelay — actor enrollment", () => {
  it("enrolls an actor and it appears in /actors", async () => {
    const acct = "acct-actor-enroll";
    const device = await enrollDevice(acct);

    const { status, data } = await post<{ actor_id: string }>(
      acct,
      "/actors",
      {
        actor_id: "claude-code-mbp",
        pubkey: VALID_PUBKEY_1,
        label: "Claude Code on MacBook",
      },
      bearer(device.device_auth_token),
    );
    expect(status).toBe(201);
    expect(data.actor_id).toBe("claude-code-mbp");

    const listResp = await get<{
      actors: Array<{
        actor_id: string;
        pubkey: string;
        label: string | null;
        created_at: number;
      }>;
    }>(acct, "/actors");
    expect(listResp.status).toBe(200);

    const actors = listResp.data.actors;
    expect(actors).toHaveLength(1);
    const actor = actors[0];
    expect(actor?.actor_id).toBe("claude-code-mbp");
    expect(actor?.pubkey).toBe(VALID_PUBKEY_1);
    expect(actor?.label).toBe("Claude Code on MacBook");

    // ZERO-KNOWLEDGE INVARIANT: only public-key material + metadata may be present.
    const allowedKeys = new Set(["actor_id", "pubkey", "label", "created_at"]);
    const actualKeys = new Set(Object.keys(actor ?? {}));
    for (const key of actualKeys) {
      expect(allowedKeys.has(key)).toBe(true);
    }
  });

  it("rejects duplicate actor_id (409)", async () => {
    const acct = "acct-actor-dup";
    const device = await enrollDevice(acct);

    await post(
      acct,
      "/actors",
      {
        actor_id: "my-agent",
        pubkey: VALID_PUBKEY_1,
      },
      bearer(device.device_auth_token),
    );

    const { status } = await post(
      acct,
      "/actors",
      {
        actor_id: "my-agent",
        pubkey: VALID_PUBKEY_2,
      },
      bearer(device.device_auth_token),
    );
    expect(status).toBe(409);

    // Only one actor
    const listResp = await get<{ actors: unknown[] }>(acct, "/actors");
    expect(listResp.data.actors).toHaveLength(1);
  });

  it("rejects an actor pubkey that is not 32 bytes (400)", async () => {
    const acct = "acct-actor-bad-pk";
    const device = await enrollDevice(acct);
    const { status } = await post(
      acct,
      "/actors",
      {
        actor_id: "bad-agent",
        pubkey: "tooshort",
      },
      bearer(device.device_auth_token),
    );
    expect(status).toBe(400);
  });

  it("requires an enrolled device auth token to enroll actors", async () => {
    const acct = "acct-actor-auth-required";
    const noAuth = await post<{ error: string }>(acct, "/actors", {
      actor_id: "bad-agent",
      pubkey: VALID_PUBKEY_1,
    });
    expect(noAuth.status).toBe(401);

    const wrongAuth = await post<{ error: string }>(
      acct,
      "/actors",
      {
        actor_id: "bad-agent",
        pubkey: VALID_PUBKEY_1,
      },
      bearer("wrong-device-token"),
    );
    expect(wrongAuth.status).toBe(403);
  });
});

describe("AccountRelay — device revocation", () => {
  it("revokes a device and it no longer appears in /devices", async () => {
    const acct = "acct-revoke";

    const { device_id, device_auth_token } = await enrollDevice(acct);

    // Verify it is listed
    const before = await get<{ devices: Array<{ device_id: string }> }>(acct, "/devices");
    expect(before.data.devices).toHaveLength(1);

    // Revoke it
    const { status, data } = await post<{ revoked: boolean }>(
      acct,
      `/devices/${device_id}/revoke`,
      {},
      bearer(device_auth_token),
    );
    expect(status).toBe(200);
    expect(data.revoked).toBe(true);

    // Verify it is no longer listed
    const after = await get<{ devices: unknown[] }>(acct, "/devices");
    expect(after.data.devices).toHaveLength(0);
  });

  it("returns 404 when revoking an unknown device", async () => {
    const device = await enrollDevice("acct-revoke-unknown");
    const { status } = await post(
      "acct-revoke-unknown",
      "/devices/nonexistent-device-id/revoke",
      {},
      bearer(device.device_auth_token),
    );
    expect(status).toBe(404);
  });

  it("requires the target device auth token to revoke a device", async () => {
    const acct = "acct-revoke-auth-required";
    const device = await enrollDevice(acct);

    const noAuth = await post<{ error: string }>(acct, `/devices/${device.device_id}/revoke`, {});
    expect(noAuth.status).toBe(401);

    const wrongAuth = await post<{ error: string }>(
      acct,
      `/devices/${device.device_id}/revoke`,
      {},
      bearer("wrong-device-token"),
    );
    expect(wrongAuth.status).toBe(403);
  });

  it("rejects another enrolled device's real token when revoking the target device", async () => {
    const acct = "acct-revoke-token-scoped-to-device";
    const deviceA = await enrollDevice(acct);
    const startB = await startPairing(acct);
    const completeB = await completePairing(acct, startB, { pubkey: VALID_PUBKEY_2 });
    expect(completeB.status).toBe(201);

    const crossDevice = await post<{ error: string }>(
      acct,
      `/devices/${deviceA.device_id}/revoke`,
      {},
      bearer(completeB.data.device_auth_token),
    );
    expect(crossDevice.status).toBe(403);
  });

  it("deletes registered push tokens when revoking a device", async () => {
    const acct = "acct-revoke-clears-push-tokens";
    const startData = await startPairing(acct);
    const { data: completeData } = await completePairing(acct, startData, {
      push_tokens: [{ transport: "apns", token: VALID_APNS_TOKEN }],
    });

    expect(await readPushTokens(acct, completeData.device_id)).toEqual([
      { transport: "apns", token: VALID_APNS_TOKEN },
    ]);

    const revoke = await post<{ revoked: boolean }>(
      acct,
      `/devices/${completeData.device_id}/revoke`,
      {},
      bearer(completeData.device_auth_token),
    );
    expect(revoke.status).toBe(200);
    expect(await readPushTokens(acct, completeData.device_id)).toEqual([]);
  });
});

describe("AccountRelay — per-account isolation", () => {
  it("devices enrolled under acct1 are NOT visible under acct2", async () => {
    // Enroll a device under acct1
    await enrollDevice("acct-iso-1");

    // acct2 should have an empty device list
    const { data } = await get<{ devices: unknown[] }>("acct-iso-2", "/devices");
    expect(data.devices).toHaveLength(0);
  });

  it("actors enrolled under acct1 are NOT visible under acct2", async () => {
    const device = await enrollDevice("acct-iso-actors-1");
    await post(
      "acct-iso-actors-1",
      "/actors",
      {
        actor_id: "agent-a",
        pubkey: VALID_PUBKEY_1,
      },
      bearer(device.device_auth_token),
    );

    const { data } = await get<{ actors: unknown[] }>("acct-iso-actors-2", "/actors");
    expect(data.actors).toHaveLength(0);
  });
});

describe("AccountRelay — zero-knowledge invariant", () => {
  it("GET /devices returns ONLY device_id, pubkey, label, created_at (no secret fields)", async () => {
    const acct = "acct-zk-devices";

    const startData = await startPairing(acct);
    await completePairing(acct, startData, { label: "Test device" });

    const { data } = await get<{
      devices: Array<Record<string, unknown>>;
    }>(acct, "/devices");

    expect(data.devices).toHaveLength(1);
    const device = data.devices[0];
    const keys = Object.keys(device ?? {}).sort();

    // Exact set of allowed fields — no private_key, secret, or extra fields.
    expect(keys).toEqual(["created_at", "device_id", "label", "pubkey"]);
  });

  it("GET /actors returns ONLY actor_id, pubkey, label, created_at (no secret fields)", async () => {
    const acct = "acct-zk-actors";
    const device = await enrollDevice(acct);

    await post(
      acct,
      "/actors",
      {
        actor_id: "agent-zk",
        pubkey: VALID_PUBKEY_2,
        label: "ZK agent",
      },
      bearer(device.device_auth_token),
    );

    const { data } = await get<{
      actors: Array<Record<string, unknown>>;
    }>(acct, "/actors");

    expect(data.actors).toHaveLength(1);
    const actor = data.actors[0];
    const keys = Object.keys(actor ?? {}).sort();

    // Exact set of allowed fields — no private_key, secret, or extra fields.
    expect(keys).toEqual(["actor_id", "created_at", "label", "pubkey"]);
  });
});

describe("AccountRelay — routing edge cases", () => {
  it("returns 404 for an unknown path", async () => {
    const resp = await SELF.fetch(relayUrl("acct-routing", "/unknown/path"), { method: "GET" });
    expect(resp.status).toBe(404);
  });

  it("returns 405 for an unsupported method on a known path", async () => {
    const resp = await SELF.fetch(relayUrl("acct-routing-405", "/devices"), {
      method: "DELETE",
    });
    expect(resp.status).toBe(405);
  });
});
