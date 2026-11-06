/**
 * A root-authorized pairing code enrolls at most one device, with its credential hash and entire
 * push-token set committed together. Crypto awaits must not turn a stale unused-code snapshot into
 * a second enrollment. These tests use the real Worker route and Durable Object SQLite storage;
 * only completion of Web Crypto hashing is held, never its digest value or the storage behavior.
 *
 * @see ../../../docs/relay-api.md §3 Pairing (single-use; atomic — no half-enrollment)
 * @see ../../../docs/enrollment.md §Pairing Flow, step 4 (consume exactly once)
 */
import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AccountRelay } from "../src/index.js";
import { PAIRING_TTL_MS } from "../src/constants.js";
import { pairingStartBody, testAccount } from "./support/accounts.js";
import { DEVICE_X25519_PUBKEY } from "./support/keys.js";
import { pinRelayClock } from "./support/relay-state.js";

/** Fixed relay time and signed authorization time; no wall-clock fixture data. */
const NOW = 1_800_000_000_000;
/** Two distinct valid tokens let rollback prove even the first token insert is undone. */
const PUSH_TOKENS = [
  { transport: "fcm", token: "atomic-first" },
  { transport: "fcm", token: "atomic-second" },
];

/** The code and capability issued by an actual root-signed start. */
interface Pairing {
  readonly code: string;
  readonly pairing_auth_token: string;
}

/** An enrolled device's relay-scoped capability, returned only after the enrollment commits. */
interface Credential {
  readonly device_id: string;
  readonly device_auth_token: string;
}

/** A manually released promise makes interleavings depend on arrivals, never sleeps. */
function latch(): { ready: Promise<void>; release: () => void } {
  let release = (): void => {};
  const ready = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { ready, release };
}

/**
 * Hold newly minted device-token hashes after doing the real digest. Pairing-token auth hashes
 * proceed normally. `arrived` proves all contenders crossed the old used check before any writes.
 */
function holdDeviceHashes(pairings: readonly Pairing[], count: number) {
  const arrived = latch();
  const resume = latch();
  const digest = crypto.subtle.digest.bind(crypto.subtle);
  let arrivals = 0;
  vi.spyOn(crypto.subtle, "digest").mockImplementation(async (algorithm, data) => {
    const result = await digest(algorithm, data);
    const token = new TextDecoder().decode(data);
    if (!pairings.some((pairing) => pairing.pairing_auth_token === token)) {
      arrivals += 1;
      if (arrivals === count) arrived.release();
      await resume.ready;
    }
    return result;
  });
  return { arrived: arrived.ready, release: resume.release, arrivals: () => arrivals };
}

/** Start a fresh pairing on an account whose relay clock and signed authorization agree. */
async function start(accountId: string): Promise<Pairing> {
  await pinRelayClock(accountId, NOW);
  const response = await exports.default.fetch(
    `https://relay.allw.test/${accountId}/pairing/start`,
    {
      method: "POST",
      body: JSON.stringify(pairingStartBody(accountId, "root label", { issuedAt: NOW })),
    },
  );
  expect(response.status).toBe(201);
  return response.json<Pairing>();
}

/** Complete through the public Worker route; overrides exercise rejected, non-consuming inputs. */
function complete(
  accountId: string,
  pairing: Pairing,
  overrides: Record<string, unknown> = {},
  token: string | null = pairing.pairing_auth_token,
): Promise<Response> {
  return exports.default.fetch(`https://relay.allw.test/${accountId}/pairing/complete`, {
    method: "POST",
    headers: token === null ? {} : { Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      code: pairing.code,
      pubkey: DEVICE_X25519_PUBKEY,
      push_tokens: PUSH_TOKENS,
      ...overrides,
    }),
  });
}

/** Inspect persisted code/device/credential/token state, including orphan rows hidden by APIs. */
async function stored(accountId: string, code: string) {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, (relay: AccountRelay) => ({
    pairing: [...relay["sql"].exec("SELECT used FROM pairing WHERE code = ?", code)],
    devices: [...relay["sql"].exec("SELECT device_id, label, auth_token_hash FROM device")],
    tokens: [...relay["sql"].exec("SELECT device_id, transport, token FROM device_push_token")],
  }));
}

afterEach(() => vi.restoreAllMocks());

describe("pairing completion atomicity", () => {
  it("lets exactly one concurrent completion enroll its device, credential and token set", async () => {
    const accountId = testAccount("atomic-concurrent-code");
    const pairing = await start(accountId);
    const barrier = holdDeviceHashes([pairing], 2);
    const pending = [
      complete(accountId, pairing, { label: "first contender" }),
      complete(accountId, pairing, { label: "second contender" }),
    ];
    try {
      await barrier.arrived;
      expect(barrier.arrivals()).toBe(2);
      expect(await stored(accountId, pairing.code)).toEqual({
        pairing: [{ used: 0 }],
        devices: [],
        tokens: [],
      });
    } finally {
      barrier.release();
    }
    const responses = await Promise.all(pending);
    expect(responses.map((response) => response.status).sort()).toEqual([201, 409]);
    const winner = responses.find((response) => response.status === 201);
    const loser = responses.find((response) => response.status === 409);
    expect(await loser?.json()).toEqual({ error: "pairing code already used" });
    const credential = await winner?.json<Credential>();
    expect(credential).toBeDefined();
    const state = await stored(accountId, pairing.code);
    expect(state.pairing).toEqual([{ used: 1 }]);
    expect(state.devices).toHaveLength(1);
    expect(state.devices[0]).toMatchObject({ device_id: credential?.device_id });
    expect(state.devices[0]?.auth_token_hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(state.devices[0]?.auth_token_hash).not.toBe(credential?.device_auth_token);
    expect(state.tokens).toEqual(
      PUSH_TOKENS.map((push) => ({
        device_id: credential?.device_id,
        ...push,
      })),
    );
    const inbox = await exports.default.fetch(
      `https://relay.allw.test/${accountId}/devices/${credential?.device_id}/inbox`,
      { headers: { Authorization: `Bearer ${credential?.device_auth_token}` } },
    );
    expect(inbox.status).toBe(200);
    expect((await complete(accountId, pairing)).status).toBe(409);
    expect(await stored(accountId, pairing.code)).toEqual(state);
  });

  it("rejects a completion that expires during hashing without consuming or enrolling", async () => {
    const accountId = testAccount("atomic-expiry-during-hash");
    const pairing = await start(accountId);
    const barrier = holdDeviceHashes([pairing], 1);
    const pending = complete(accountId, pairing);
    try {
      await barrier.arrived;
      await pinRelayClock(accountId, NOW + PAIRING_TTL_MS + 1);
    } finally {
      barrier.release();
    }
    const response = await pending;
    expect(response.status).toBe(410);
    expect(await response.json()).toEqual({ error: "pairing code expired" });
    expect(await stored(accountId, pairing.code)).toEqual({
      pairing: [{ used: 0 }],
      devices: [],
      tokens: [],
    });
  });

  it.each(["device", "device_push_token"])(
    "rolls back consumption and every enrollment row when a %s insert fails",
    async (table) => {
      const accountId = testAccount(`atomic-rollback-${table}`);
      const pairing = await start(accountId);
      const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
      await runInDurableObject(stub, (relay: AccountRelay) => {
        // Fail the second push insert so the rollback must undo both device and first token too.
        relay["sql"].exec(`CREATE TRIGGER fail_enrollment BEFORE INSERT ON ${table}
          ${table === "device_push_token" ? "WHEN NEW.token = 'atomic-second'" : ""}
          BEGIN SELECT RAISE(ABORT, 'injected enrollment failure'); END`);
      });
      try {
        expect((await complete(accountId, pairing)).status).toBe(500);
        expect(await stored(accountId, pairing.code)).toEqual({
          pairing: [{ used: 0 }],
          devices: [],
          tokens: [],
        });
      } finally {
        await runInDurableObject(stub, (relay: AccountRelay) => {
          relay["sql"].exec("DROP TRIGGER fail_enrollment");
        });
      }
      expect((await complete(accountId, pairing)).status).toBe(201);
      const state = await stored(accountId, pairing.code);
      expect(state.devices).toHaveLength(1);
      expect(state.devices[0]?.label).toBe("root label");
      expect(state.tokens).toHaveLength(2);
    },
  );

  it.each([
    { name: "missing auth", token: null, body: {}, status: 401 },
    { name: "wrong auth", token: "wrong-token", body: {}, status: 403 },
    { name: "unknown code", token: undefined, body: { code: "UNKNOWN1" }, status: 403 },
    { name: "malformed key", token: undefined, body: { pubkey: "bad-key" }, status: 400 },
    { name: "small-order key", token: undefined, body: { pubkey: "A".repeat(43) }, status: 400 },
    {
      name: "push registration budget",
      token: undefined,
      body: {
        push_tokens: Array.from({ length: 5 }, (_, n) => ({
          transport: "fcm",
          token: `push-${n}`,
        })),
      },
      status: 400,
    },
  ])("keeps the code usable after $name", async ({ name, token, body, status }) => {
    const accountId = testAccount(`atomic-reject-${name}`);
    const pairing = await start(accountId);
    const before = await stored(accountId, pairing.code);
    expect((await complete(accountId, pairing, body, token)).status).toBe(status);
    expect(await stored(accountId, pairing.code)).toEqual(before);
    expect((await complete(accountId, pairing)).status).toBe(201);
  });

  it("does not consume a code at the account token budget, and permits a token-free retry", async () => {
    const accountId = testAccount("atomic-account-token-budget");
    const pairing = await start(accountId);
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
    await runInDurableObject(stub, (relay: AccountRelay) => {
      relay["sql"].exec(
        "INSERT INTO device (device_id, pubkey, created_at) VALUES ('existing', ?, ?)",
        DEVICE_X25519_PUBKEY,
        NOW,
      );
      for (let n = 0; n < 32; n++) {
        relay["sql"].exec(
          "INSERT INTO device_push_token (device_id, transport, token, created_at) VALUES ('existing', 'fcm', ?, ?)",
          `existing-${n}`,
          NOW,
        );
      }
    });
    const before = await stored(accountId, pairing.code);
    expect((await complete(accountId, pairing)).status).toBe(409);
    expect(await stored(accountId, pairing.code)).toEqual(before);
    expect((await complete(accountId, pairing, { push_tokens: [] })).status).toBe(201);
    const after = await stored(accountId, pairing.code);
    expect(after.devices).toHaveLength(2);
    expect(after.tokens).toEqual(before.tokens);
  });
});
