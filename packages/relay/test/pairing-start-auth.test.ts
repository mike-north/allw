/**
 * `POST /{acct}/pairing/start` is root-authorized: the account id must derive from the presented
 * root key, and the body must carry a fresh, one-time, root-signed `allw-pairing-start+jws`. The
 * first verified root is bound to the account's Durable Object.
 *
 * Every rejection branch has its own test, and each rejection is asserted to leave the account
 * unchanged (no root bound, no pairing code issued).
 *
 * Forged authorizations (claims the honest core signer refuses to produce) are built with WebCrypto
 * Ed25519 in `forgeAuthorization`; `accepts an honestly-shaped forged authorization` proves that
 * helper produces JWS the core accepts, so each forged rejection is caused by the claim under test.
 *
 * @see ../../../docs/relay-api.md §3 Pairing
 * @see ../../../docs/enrollment.md §Model (account id derivation, root binding)
 * @see https://www.rfc-editor.org/rfc/rfc7515 (JWS compact serialization)
 * @see https://www.rfc-editor.org/rfc/rfc8037 (EdDSA in JOSE)
 */

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { AccountRelay } from "../src/index.js";
import {
  DEFAULT_AUTH_LIFETIME_MS,
  freshJti,
  pairingStartBody,
  rootFor,
  signPairingStart,
  testAccount,
  testRoot,
} from "./support/accounts.js";

const FIVE_MINUTES_MS = 5 * 60 * 1000;

async function postStart(
  accountId: string,
  body: unknown,
): Promise<{ status: number; data: Record<string, unknown> }> {
  const resp = await SELF.fetch(`http://relay.test/${accountId}/pairing/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return { status: resp.status, data: await resp.json() };
}

/** The account's persisted root binding and pairing-code count. */
async function accountState(
  accountId: string,
): Promise<{ boundRoot: string | null; pairings: number }> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    const meta = [
      ...relay.sql.exec<{ root_pubkey: string }>(
        `SELECT root_pubkey FROM account_meta WHERE id = 1`,
      ),
    ];
    const pairings = [...relay.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM pairing`)];
    return { boundRoot: meta[0]?.root_pubkey ?? null, pairings: pairings[0]?.n ?? 0 };
  });
}

async function expectUnchanged(accountId: string): Promise<void> {
  expect(await accountState(accountId)).toEqual({ boundRoot: null, pairings: 0 });
}

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromB64url(value: string): Uint8Array {
  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/** RFC 8410 PKCS#8 prefix for an Ed25519 private key; the 32-byte seed follows. */
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * Build an EdDSA compact JWS with an arbitrary header and payload, signed by `seedB64`. Test-only
 * adversary tooling: it lets a test present claims the core's honest signer refuses to produce.
 */
async function forgeAuthorization(
  seedB64: string,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): Promise<string> {
  const pkcs8 = new Uint8Array([...ED25519_PKCS8_PREFIX, ...fromB64url(seedB64)]);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  const enc = new TextEncoder();
  const signingInput = `${b64url(enc.encode(JSON.stringify(header)))}.${b64url(enc.encode(JSON.stringify(payload)))}`;
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, key, enc.encode(signingInput)),
  );
  return `${signingInput}.${b64url(sig)}`;
}

function honestHeader(accountId: string): Record<string, unknown> {
  return { alg: "EdDSA", typ: "allw-pairing-start+jws", kid: accountId };
}

function honestClaims(accountId: string, now = Date.now()): Record<string, unknown> {
  return {
    v: 1,
    account_id: accountId,
    issued_at: now,
    expires_at: now + DEFAULT_AUTH_LIFETIME_MS,
    jti: freshJti(),
  };
}

async function postForged(
  accountId: string,
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
): Promise<number> {
  const root = rootFor(accountId);
  const authorization = await forgeAuthorization(root.rootSeed, header, claims);
  const { status } = await postStart(accountId, { root_pubkey: root.rootPubkey, authorization });
  return status;
}

describe("pairing/start — root-signed authorization", () => {
  it("accepts a valid authorization, issues a code, and binds the root", async () => {
    const acct = testAccount("auth-valid");
    const { status, data } = await postStart(acct, pairingStartBody(acct, "Laptop"));
    expect(status).toBe(201);
    expect(typeof data.code).toBe("string");
    expect(typeof data.pairing_auth_token).toBe("string");
    expect(await accountState(acct)).toEqual({ boundRoot: rootFor(acct).rootPubkey, pairings: 1 });

    // A second fresh authorization from the same root succeeds against the bound root.
    const again = await postStart(acct, pairingStartBody(acct));
    expect(again.status).toBe(201);
    expect(await accountState(acct)).toEqual({ boundRoot: rootFor(acct).rootPubkey, pairings: 2 });
  });

  it("accepts an honestly-shaped forged authorization (validates the forge helper)", async () => {
    const acct = testAccount("auth-forge-control");
    expect(await postForged(acct, honestHeader(acct), honestClaims(acct))).toBe(201);
  });

  it("400 on a body that is not JSON", async () => {
    const acct = testAccount("auth-not-json");
    expect((await postStart(acct, "{not json")).status).toBe(400);
    await expectUnchanged(acct);
  });

  it("400 when root_pubkey is missing", async () => {
    const acct = testAccount("auth-no-root");
    const { status } = await postStart(acct, { authorization: signPairingStart(acct) });
    expect(status).toBe(400);
    await expectUnchanged(acct);
  });

  it("400 when root_pubkey is malformed", async () => {
    const acct = testAccount("auth-bad-root");
    const { status } = await postStart(acct, {
      root_pubkey: "not-a-key",
      authorization: signPairingStart(acct),
    });
    expect(status).toBe(400);
    await expectUnchanged(acct);
  });

  it("400 when {acct} does not derive from root_pubkey (another account's root)", async () => {
    const acct = testAccount("auth-victim");
    const attacker = testRoot("auth-attacker");
    // The attacker signs with their own root; their root derives to a different id.
    const { status } = await postStart(acct, {
      root_pubkey: attacker.rootPubkey,
      authorization: signPairingStart(attacker.id),
    });
    expect(status).toBe(400);
    await expectUnchanged(acct);
  });

  it("400 for a free-form (non-derived) account id, even with a valid root", async () => {
    const legacy = "acct-legacy-free-form";
    const root = testRoot("auth-legacy-root");
    const { status } = await postStart(legacy, {
      root_pubkey: root.rootPubkey,
      authorization: signPairingStart(root.id),
    });
    expect(status).toBe(400);
    await expectUnchanged(legacy);
  });

  it("401 when authorization is missing", async () => {
    const acct = testAccount("auth-missing");
    const { status } = await postStart(acct, { root_pubkey: rootFor(acct).rootPubkey });
    expect(status).toBe(401);
    await expectUnchanged(acct);
  });

  it("401 when authorization is not a string", async () => {
    const acct = testAccount("auth-non-string");
    const { status } = await postStart(acct, {
      root_pubkey: rootFor(acct).rootPubkey,
      authorization: 42,
    });
    expect(status).toBe(401);
    await expectUnchanged(acct);
  });

  it("403 for a bad signature", async () => {
    const acct = testAccount("auth-bad-sig");
    const [header, payload, sig] = signPairingStart(acct).split(".") as [string, string, string];
    // Flip the first signature character: a well-formed JWS whose signature no longer verifies.
    const flipped = (sig.startsWith("A") ? "B" : "A") + sig.slice(1);
    const { status } = await postStart(acct, {
      root_pubkey: rootFor(acct).rootPubkey,
      authorization: `${header}.${payload}.${flipped}`,
    });
    expect(status).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 for an authorization signed by another key", async () => {
    const acct = testAccount("auth-other-key");
    const other = testRoot("auth-other-key-signer");
    const authorization = await forgeAuthorization(
      other.rootSeed,
      honestHeader(acct),
      honestClaims(acct),
    );
    const { status } = await postStart(acct, {
      root_pubkey: rootFor(acct).rootPubkey,
      authorization,
    });
    expect(status).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 for junk that is not a JWS", async () => {
    const acct = testAccount("auth-junk");
    const { status } = await postStart(acct, {
      root_pubkey: rootFor(acct).rootPubkey,
      authorization: "a.b.c",
    });
    expect(status).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 for a wrong typ (another root-signed artifact)", async () => {
    const acct = testAccount("auth-wrong-typ");
    const header = { ...honestHeader(acct), typ: "allw-account-state+jws" };
    expect(await postForged(acct, header, honestClaims(acct))).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 for a wrong account_id claim", async () => {
    const acct = testAccount("auth-wrong-claim");
    const claims = { ...honestClaims(acct), account_id: testAccount("auth-wrong-claim-other") };
    expect(await postForged(acct, honestHeader(acct), claims)).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 for a wrong kid", async () => {
    const acct = testAccount("auth-wrong-kid");
    const header = { ...honestHeader(acct), kid: "someone-else" };
    expect(await postForged(acct, header, honestClaims(acct))).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 for a non-EdDSA alg, even with an honest root signature", async () => {
    // The forger always signs with the root's Ed25519 key; only the header `alg` differs, so
    // each 403 is the alg check (the honest-header control is the forge-helper test above).
    for (const alg of ["none", "HS256"]) {
      const acct = testAccount(`auth-alg-${alg}`);
      const header = { ...honestHeader(acct), alg };
      expect(await postForged(acct, header, honestClaims(acct)), alg).toBe(403);
      await expectUnchanged(acct);
    }
  });

  it("403 for an expired authorization", async () => {
    const acct = testAccount("auth-expired");
    const issuedAt = Date.now() - 10 * 60 * 1000;
    const { status } = await postStart(
      acct,
      pairingStartBody(acct, undefined, { issuedAt, expiresAt: issuedAt + 4 * 60 * 1000 }),
    );
    expect(status).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 for an authorization issued in the future (beyond clock skew)", async () => {
    const acct = testAccount("auth-future");
    const { status } = await postStart(
      acct,
      pairingStartBody(acct, undefined, { issuedAt: Date.now() + 10 * 60 * 1000 }),
    );
    expect(status).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 for a validity window longer than five minutes", async () => {
    const acct = testAccount("auth-overlong");
    const now = Date.now();
    const claims = { ...honestClaims(acct, now), expires_at: now + FIVE_MINUTES_MS + 1 };
    expect(await postForged(acct, honestHeader(acct), claims)).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 for an unsupported claim-set version", async () => {
    const acct = testAccount("auth-version");
    const claims = { ...honestClaims(acct), v: 2 };
    expect(await postForged(acct, honestHeader(acct), claims)).toBe(403);
    await expectUnchanged(acct);
  });

  it("403 when the same authorization is replayed", async () => {
    const acct = testAccount("auth-replay");
    const body = pairingStartBody(acct);
    expect((await postStart(acct, body)).status).toBe(201);
    const replay = await postStart(acct, body);
    expect(replay.status).toBe(403);
    expect(await accountState(acct)).toEqual({ boundRoot: rootFor(acct).rootPubkey, pairings: 1 });
  });

  it("403 when a different authorization reuses a jti", async () => {
    const acct = testAccount("auth-replay-jti");
    const jti = freshJti();
    const now = Date.now();
    expect(
      (await postStart(acct, pairingStartBody(acct, undefined, { jti, issuedAt: now }))).status,
    ).toBe(201);
    const reuse = await postStart(
      acct,
      pairingStartBody(acct, undefined, { jti, issuedAt: now + 1 }),
    );
    expect(reuse.status).toBe(403);
    expect(await accountState(acct)).toEqual({ boundRoot: rootFor(acct).rootPubkey, pairings: 1 });
  });

  it("403 when the presented root differs from the bound root", async () => {
    const acct = testAccount("auth-bound-mismatch");
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(acct));
    const otherRoot = testRoot("auth-bound-mismatch-other").rootPubkey;
    // Simulate a bound root that differs from the presented one (unreachable without a SHA-256
    // collision); the relay must still refuse rather than act for a second root.
    await runInDurableObject(stub, (instance: AccountRelay) => {
      const relay = instance as unknown as { sql: SqlStorage };
      relay.sql.exec(
        `INSERT INTO account_meta (id, root_pubkey, bound_at) VALUES (1, ?, 0)`,
        otherRoot,
      );
    });
    const { status } = await postStart(acct, pairingStartBody(acct));
    expect(status).toBe(403);
    expect(await accountState(acct)).toEqual({ boundRoot: otherRoot, pairings: 0 });
  });

  it("keeps a used jti for the clock-skew margin past its expiry", async () => {
    // A DO re-instantiated on a host whose clock lags could still accept a just-expired
    // authorization as fresh, so its replay record must outlive expires_at by the 60 s skew.
    const acct = testAccount("auth-jti-retention");
    expect((await postStart(acct, pairingStartBody(acct))).status).toBe(201);
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(acct));
    await runInDurableObject(stub, (instance: AccountRelay) => {
      const relay = instance as unknown as { sql: SqlStorage };
      relay.sql.exec(`UPDATE pairing_start_jti SET expires_at = ?`, Date.now() - 30 * 1000);
    });
    expect((await postStart(acct, pairingStartBody(acct))).status).toBe(201);
    const remaining = await runInDurableObject(stub, (instance: AccountRelay) => {
      const relay = instance as unknown as { sql: SqlStorage };
      return [...relay.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM pairing_start_jti`)][0]
        ?.n;
    });
    expect(remaining).toBe(2);
  });

  it("sweeps expired jti rows on the next pairing start", async () => {
    const acct = testAccount("auth-jti-sweep");
    expect((await postStart(acct, pairingStartBody(acct))).status).toBe(201);
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(acct));
    await runInDurableObject(stub, (instance: AccountRelay) => {
      const relay = instance as unknown as { sql: SqlStorage };
      relay.sql.exec(`UPDATE pairing_start_jti SET expires_at = 0`);
    });
    expect((await postStart(acct, pairingStartBody(acct))).status).toBe(201);
    const remaining = await runInDurableObject(stub, (instance: AccountRelay) => {
      const relay = instance as unknown as { sql: SqlStorage };
      return [...relay.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM pairing_start_jti`)][0]
        ?.n;
    });
    expect(remaining).toBe(1);
  });
});

/**
 * Before root binding existed, anyone could create devices, pairing codes, actors and account
 * state under any account id — including one derived from a root key they merely know (root keys
 * are public: integrators are configured with them). Binding a root over such rows would launder
 * them as root-authorized, so the first bind refuses (409) and an unbound account refuses every
 * pairing completion (403). The rows below are exactly what the pre-binding relay could leave.
 */
describe("pairing — state from before root binding is never adopted", () => {
  const ATTACKER_PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const LEGACY_PAIRING_TOKEN = "legacy-pairing-token-from-the-unauthenticated-start";

  async function seed(accountId: string, sql: string, ...params: (string | number)[]) {
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
    await runInDurableObject(stub, (instance: AccountRelay) => {
      (instance as unknown as { sql: SqlStorage }).sql.exec(sql, ...params);
    });
  }

  async function count(accountId: string, table: string): Promise<number> {
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
    return runInDurableObject(stub, (instance: AccountRelay) => {
      const relay = instance as unknown as { sql: SqlStorage };
      return [...relay.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM ${table}`)][0]?.n ?? 0;
    });
  }

  async function legacyTokenHash(): Promise<string> {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(LEGACY_PAIRING_TOKEN),
    );
    return b64url(new Uint8Array(digest));
  }

  const PRE_BINDING_ROWS: {
    table: string;
    sql: string;
    params: () => Promise<(string | number)[]>;
  }[] = [
    {
      table: "device",
      sql: `INSERT INTO device (device_id, pubkey, label, created_at, auth_token_hash)
              VALUES ('attacker-device', ?, 'attacker', 0, 'x')`,
      params: () => Promise.resolve([ATTACKER_PUBKEY]),
    },
    {
      table: "pairing",
      sql: `INSERT INTO pairing (code, label, created_at, expires_at, used, auth_token_hash)
              VALUES ('LEGACY01', NULL, 0, ?, 0, ?)`,
      params: async () => [Date.now() + 10 * 60 * 1000, await legacyTokenHash()],
    },
    {
      table: "actor",
      sql: `INSERT INTO actor (actor_id, pubkey, label, created_at)
              VALUES ('attacker-actor', ?, NULL, 0)`,
      params: () => Promise.resolve([ATTACKER_PUBKEY]),
    },
    {
      // Unreachable on an unbound account through the API (publish needs the bound root); the
      // check is defense in depth.
      table: "verified_account_state",
      sql: `INSERT INTO verified_account_state (state_jws, sequence, verified_at)
            VALUES ('a.b.c', 1, 0)`,
      params: () => Promise.resolve([]),
    },
  ];

  for (const row of PRE_BINDING_ROWS) {
    it(`409 and no bind when the unbound account already has ${row.table} rows`, async () => {
      const acct = testAccount(`pre-binding-${row.table}`);
      await seed(acct, row.sql, ...(await row.params()));

      const { status, data } = await postStart(acct, pairingStartBody(acct));
      expect(status).toBe(409);
      expect(String(data.error)).toMatch(/before root binding/);

      const state = await accountState(acct);
      expect(state.boundRoot).toBeNull();
      // Refused, not purged: the seeded row is left in place for the operator to see.
      expect(await count(acct, row.table)).toBe(1);
      expect(await count(acct, "pairing_start_jti")).toBe(0);
    });
  }

  it("the refused bind adds no device next to a pre-binding one", async () => {
    const acct = testAccount("pre-binding-device-list");
    const device = PRE_BINDING_ROWS[0];
    if (!device) throw new Error("missing device row fixture");
    await seed(acct, device.sql, ...(await device.params()));

    expect((await postStart(acct, pairingStartBody(acct))).status).toBe(409);
    const resp = await SELF.fetch(`http://relay.test/${acct}/devices`);
    const listed = (await resp.json()) as { devices: { device_id: string }[] };
    expect(listed.devices.map((d) => d.device_id)).toEqual(["attacker-device"]);
  });

  it("drops the legacy unverified account-state tables instead of adopting them", async () => {
    // The pre-binding relay cached unverified strings and a caller-asserted max_sequence there.
    const acct = testAccount("pre-binding-legacy-account-state");
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(acct));
    const tables = await runInDurableObject(stub, (instance: AccountRelay) => {
      const relay = instance as unknown as { sql: SqlStorage };
      return [
        ...relay.sql.exec<{ name: string }>(
          `SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'account_state%'`,
        ),
      ].map((row) => row.name);
    });
    expect(tables).toEqual([]);
    expect((await postStart(acct, pairingStartBody(acct))).status).toBe(201);
  });

  it("403 when completing a pre-binding pairing code on an unbound account", async () => {
    const acct = testAccount("pre-binding-complete");
    const pairing = PRE_BINDING_ROWS[1];
    if (!pairing) throw new Error("missing pairing row fixture");
    await seed(acct, pairing.sql, ...(await pairing.params()));

    const resp = await SELF.fetch(`http://relay.test/${acct}/pairing/complete`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${LEGACY_PAIRING_TOKEN}`,
      },
      body: JSON.stringify({ code: "LEGACY01", pubkey: ATTACKER_PUBKEY }),
    });
    expect(resp.status).toBe(403);
    expect(await count(acct, "device")).toBe(0);
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(acct));
    const used = await runInDurableObject(stub, (instance: AccountRelay) => {
      const relay = instance as unknown as { sql: SqlStorage };
      return [...relay.sql.exec<{ used: number }>(`SELECT used FROM pairing`)][0]?.used;
    });
    expect(used).toBe(0);
  });

  it("an honest first bind on an empty account still succeeds", async () => {
    const acct = testAccount("pre-binding-empty-control");
    expect((await postStart(acct, pairingStartBody(acct))).status).toBe(201);
    expect((await accountState(acct)).boundRoot).toBe(rootFor(acct).rootPubkey);
  });
});
