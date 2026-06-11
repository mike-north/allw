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
// PAIRING_TTL_MS lives in a sibling module (not the worker entrypoint) so `wrangler dev` can boot:
// workerd validates every named export of the entrypoint as a handler/DO class (see constants.ts).
import { PAIRING_TTL_MS } from "../src/constants.js";

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
): Promise<{ status: number; data: T }> {
  const resp = await SELF.fetch(relayUrl(accountId, subPath), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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

/**
 * Seed an already-expired pairing row directly into the DO's SQLite storage.
 * Uses `runInDurableObject` to bypass the HTTP API and insert a deterministic row.
 */
async function seedExpiredPairing(accountId: string, code: string): Promise<void> {
  const id = env.ACCOUNT.idFromName(accountId);
  const stub = env.ACCOUNT.get(id);
  await runInDurableObject(stub, (instance: AccountRelay) => {
    // Access the sql storage via the DO's ctx (exposed via the constructor assignment).
    // We cast to access private storage for test seeding only.
    const relay = instance as unknown as {
      sql: SqlStorage;
    };
    const now = Date.now();
    // Set expires_at to 1ms in the past so it's already expired.
    relay.sql.exec(
      `INSERT OR REPLACE INTO pairing (code, label, created_at, expires_at, used)
       VALUES (?, ?, ?, ?, 0)`,
      code,
      null,
      now - PAIRING_TTL_MS - 1000,
      now - 1, // already expired
    );
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AccountRelay — pairing", () => {
  it("starts a pairing and returns a code + expires_at", async () => {
    const { status, data } = await post<{ code: string; expires_at: number }>(
      "acct-pairing-start",
      "/pairing/start",
      { label: "My MacBook" },
    );
    expect(status).toBe(201);
    expect(typeof data.code).toBe("string");
    expect(data.code.length).toBe(8);
    expect(typeof data.expires_at).toBe("number");
    expect(data.expires_at).toBeGreaterThan(Date.now());
  });

  it("completes pairing: returns device_id and the device appears in /devices", async () => {
    const acct = "acct-pairing-complete";

    // Start pairing
    const startResp = await post<{ code: string; expires_at: number }>(acct, "/pairing/start", {
      label: "My Phone",
    });
    expect(startResp.status).toBe(201);
    const { code } = startResp.data;

    // Complete pairing
    const completeResp = await post<{ device_id: string }>(acct, "/pairing/complete", {
      code,
      pubkey: VALID_PUBKEY_1,
      label: "My Phone",
    });
    expect(completeResp.status).toBe(201);
    const { device_id } = completeResp.data;
    expect(typeof device_id).toBe("string");
    expect(device_id.length).toBeGreaterThan(0);

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

    const { data: startData } = await post<{ code: string }>(acct, "/pairing/start", {});

    // First complete — succeeds
    await post(acct, "/pairing/complete", {
      code: startData.code,
      pubkey: VALID_PUBKEY_1,
    });

    // Second complete with same code — must be rejected
    const { status, data } = await post<{ error: string }>(acct, "/pairing/complete", {
      code: startData.code,
      pubkey: VALID_PUBKEY_2,
    });
    expect(status).toBe(409);
    expect(typeof data.error).toBe("string");

    // Only one device should exist
    const listResp = await get<{ devices: unknown[] }>(acct, "/devices");
    expect(listResp.data.devices).toHaveLength(1);
  });

  it("rejects completing an expired pairing code (410)", async () => {
    const acct = "acct-expired-code";
    const expiredCode = "EXPCODE1";

    // Seed an already-expired row via runInDurableObject
    await seedExpiredPairing(acct, expiredCode);

    const { status, data } = await post<{ error: string }>(acct, "/pairing/complete", {
      code: expiredCode,
      pubkey: VALID_PUBKEY_1,
    });
    expect(status).toBe(410);
    expect(typeof data.error).toBe("string");

    // No device should have been added
    const listResp = await get<{ devices: unknown[] }>(acct, "/devices");
    expect(listResp.data.devices).toHaveLength(0);
  });

  it("rejects a pubkey that is not 32 bytes (400)", async () => {
    const acct = "acct-bad-pubkey";
    const { data: startData } = await post<{ code: string }>(acct, "/pairing/start", {});

    // 19 base64url chars (decodes to ~14 bytes) — not the 43 chars / 32 bytes a valid key needs.
    const shortPubkey = "AAAAAAAAAAAAAAAAAAA";

    const { status, data } = await post<{ error: string }>(acct, "/pairing/complete", {
      code: startData.code,
      pubkey: shortPubkey,
    });
    expect(status).toBe(400);
    expect(typeof data.error).toBe("string");

    // No device added
    const listResp = await get<{ devices: unknown[] }>(acct, "/devices");
    expect(listResp.data.devices).toHaveLength(0);
  });

  it("rejects a pubkey that contains non-base64url characters (400)", async () => {
    const acct = "acct-bad-b64";
    const { data: startData } = await post<{ code: string }>(acct, "/pairing/start", {});

    // Contains '+' which is standard base64 but not base64url
    const badPubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+";

    const { status } = await post(acct, "/pairing/complete", {
      code: startData.code,
      pubkey: badPubkey,
    });
    expect(status).toBe(400);
  });
});

describe("AccountRelay — actor enrollment", () => {
  it("enrolls an actor and it appears in /actors", async () => {
    const acct = "acct-actor-enroll";

    const { status, data } = await post<{ actor_id: string }>(acct, "/actors", {
      actor_id: "claude-code-mbp",
      pubkey: VALID_PUBKEY_1,
      label: "Claude Code on MacBook",
    });
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

    await post(acct, "/actors", {
      actor_id: "my-agent",
      pubkey: VALID_PUBKEY_1,
    });

    const { status } = await post(acct, "/actors", {
      actor_id: "my-agent",
      pubkey: VALID_PUBKEY_2,
    });
    expect(status).toBe(409);

    // Only one actor
    const listResp = await get<{ actors: unknown[] }>(acct, "/actors");
    expect(listResp.data.actors).toHaveLength(1);
  });

  it("rejects an actor pubkey that is not 32 bytes (400)", async () => {
    const { status } = await post("acct-actor-bad-pk", "/actors", {
      actor_id: "bad-agent",
      pubkey: "tooshort",
    });
    expect(status).toBe(400);
  });
});

describe("AccountRelay — device revocation", () => {
  it("revokes a device and it no longer appears in /devices", async () => {
    const acct = "acct-revoke";

    // Enroll a device via pairing
    const { data: startData } = await post<{ code: string }>(acct, "/pairing/start", {});
    const { data: completeData } = await post<{ device_id: string }>(acct, "/pairing/complete", {
      code: startData.code,
      pubkey: VALID_PUBKEY_1,
    });
    const { device_id } = completeData;

    // Verify it is listed
    const before = await get<{ devices: Array<{ device_id: string }> }>(acct, "/devices");
    expect(before.data.devices).toHaveLength(1);

    // Revoke it
    const { status, data } = await post<{ revoked: boolean }>(
      acct,
      `/devices/${device_id}/revoke`,
      {},
    );
    expect(status).toBe(200);
    expect(data.revoked).toBe(true);

    // Verify it is no longer listed
    const after = await get<{ devices: unknown[] }>(acct, "/devices");
    expect(after.data.devices).toHaveLength(0);
  });

  it("returns 404 when revoking an unknown device", async () => {
    const { status } = await post(
      "acct-revoke-unknown",
      "/devices/nonexistent-device-id/revoke",
      {},
    );
    expect(status).toBe(404);
  });
});

describe("AccountRelay — per-account isolation", () => {
  it("devices enrolled under acct1 are NOT visible under acct2", async () => {
    // Enroll a device under acct1
    const { data: startData } = await post<{ code: string }>("acct-iso-1", "/pairing/start", {});
    await post("acct-iso-1", "/pairing/complete", {
      code: startData.code,
      pubkey: VALID_PUBKEY_1,
    });

    // acct2 should have an empty device list
    const { data } = await get<{ devices: unknown[] }>("acct-iso-2", "/devices");
    expect(data.devices).toHaveLength(0);
  });

  it("actors enrolled under acct1 are NOT visible under acct2", async () => {
    await post("acct-iso-actors-1", "/actors", {
      actor_id: "agent-a",
      pubkey: VALID_PUBKEY_1,
    });

    const { data } = await get<{ actors: unknown[] }>("acct-iso-actors-2", "/actors");
    expect(data.actors).toHaveLength(0);
  });
});

describe("AccountRelay — zero-knowledge invariant", () => {
  it("GET /devices returns ONLY device_id, pubkey, label, created_at (no secret fields)", async () => {
    const acct = "acct-zk-devices";

    const { data: startData } = await post<{ code: string }>(acct, "/pairing/start", {});
    await post(acct, "/pairing/complete", {
      code: startData.code,
      pubkey: VALID_PUBKEY_1,
      label: "Test device",
    });

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

    await post(acct, "/actors", {
      actor_id: "agent-zk",
      pubkey: VALID_PUBKEY_2,
      label: "ZK agent",
    });

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
