/**
 * `POST /{acct}/account-states` is authorized by the account root's signature, not by a device
 * token: the relay verifies every submitted document with the core's `verify_account_state`
 * against the root bound to the account (by a root-signed `pairing/start`) and the path's account
 * id, stores only verified documents, and tracks the highest *verified* sequence. `GET` is
 * unauthenticated and serves only those verified documents.
 *
 * Every rejection is asserted to leave the stored state unchanged. The 2^53-1 regression test
 * reproduces the pre-change attack: an enrolled device published junk at
 * `max_sequence = 2^53-1`, after which every honest publish got 409.
 *
 * @see ../../../docs/relay-api.md §3 Account state
 * @see ../../../docs/enrollment.md §Model (root binding)
 * @see ../../../crates/allw-core/src/crypto.rs (`verify_account_state`)
 */

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { AccountRelay } from "../src/index.js";
import {
  pairingStartBody,
  rootFor,
  signAccountState,
  signPairingStart,
  testAccount,
  testRoot,
  type TestAccount,
} from "./support/accounts.js";

/** 2^53-1: the largest sequence a JS number represents exactly. */
const MAX_SAFE_SEQUENCE = Number.MAX_SAFE_INTEGER;

/** A 32-byte public key that is not any test account's root (32 × 0x00). */
const UNRELATED_PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

interface Result {
  status: number;
  data: Record<string, unknown>;
}

async function request(
  accountId: string,
  path: string,
  init: { method: "GET" | "POST"; body?: unknown; headers?: Record<string, string> },
): Promise<Result> {
  const resp = await SELF.fetch(`https://relay.allw.test/${accountId}${path}`, {
    method: init.method,
    headers: { "Content-Type": "application/json", ...init.headers },
    ...(init.body === undefined
      ? {}
      : { body: typeof init.body === "string" ? init.body : JSON.stringify(init.body) }),
  });
  return { status: resp.status, data: await resp.json() };
}

function publish(accountId: string, body: unknown, headers?: Record<string, string>) {
  return request(accountId, "/account-states", {
    method: "POST",
    body,
    ...(headers ? { headers } : {}),
  });
}

function list(accountId: string, headers?: Record<string, string>) {
  return request(accountId, "/account-states", { method: "GET", ...(headers ? { headers } : {}) });
}

/** Bind the account's root by starting a root-signed pairing; returns the pairing-start body. */
async function bindRoot(accountId: string): Promise<{ code: string; pairing_auth_token: string }> {
  const { status, data } = await request(accountId, "/pairing/start", {
    method: "POST",
    body: pairingStartBody(accountId),
  });
  expect(status).toBe(201);
  return data as { code: string; pairing_auth_token: string };
}

/** Bind the root and enroll one device; returns its device token. */
async function enrollDevice(accountId: string): Promise<string> {
  const start = await bindRoot(accountId);
  const { status, data } = await request(accountId, "/pairing/complete", {
    method: "POST",
    body: { code: start.code, pubkey: UNRELATED_PUBKEY },
    headers: { Authorization: `Bearer ${start.pairing_auth_token}` },
  });
  expect(status).toBe(201);
  return (data as { device_auth_token: string }).device_auth_token;
}

/** The stored verified rows, read directly from the Durable Object's SQLite. */
async function stored(accountId: string): Promise<{ state_jws: string; sequence: number }[]> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    return [
      ...relay.sql.exec<{ state_jws: string; sequence: number }>(
        `SELECT state_jws, sequence FROM verified_account_state ORDER BY state_jws ASC`,
      ),
    ];
  });
}

/** A fresh account with its root bound and one verified document stored at `sequence`. */
async function accountWithState(
  name: string,
  sequence = 5,
): Promise<{ acct: string; root: TestAccount; current: string }> {
  const acct = testAccount(name);
  await bindRoot(acct);
  const root = rootFor(acct);
  const current = signAccountState(root, { sequence });
  const { status } = await publish(acct, { account_states: [current] });
  expect(status).toBe(200);
  return { acct, root, current };
}

async function expectStoredUnchanged(acct: string, current: string, sequence = 5): Promise<void> {
  expect(await stored(acct)).toEqual([{ state_jws: current, sequence }]);
  const fetched = await list(acct);
  expect(fetched.data).toEqual({ account_states: [current], max_sequence: sequence });
}

describe("account-state publish — root-verified, no device token", () => {
  it("stores a root-signed document published with no device token", async () => {
    const acct = testAccount("acct-state-verified-ok");
    await bindRoot(acct);
    const doc = signAccountState(rootFor(acct), { sequence: 1, revokedDevices: ["dev-a"] });

    const res = await publish(acct, { account_states: [doc] });
    expect(res.status).toBe(200);
    expect(res.data).toEqual({ account_states: [doc], max_sequence: 1 });
    expect(await stored(acct)).toEqual([{ state_jws: doc, sequence: 1 }]);
  });

  it("accepts an asserted max_sequence that equals the highest verified sequence", async () => {
    const acct = testAccount("acct-state-verified-asserted");
    await bindRoot(acct);
    const doc = signAccountState(rootFor(acct), { sequence: 3 });

    const res = await publish(acct, { account_states: [doc], max_sequence: 3 });
    expect(res.status).toBe(200);
    expect(res.data.max_sequence).toBe(3);
  });

  it("replaces the stored document with a verified higher-sequence one", async () => {
    const { acct, root } = await accountWithState("acct-state-verified-replace");
    const newer = signAccountState(root, { sequence: 6 });

    const res = await publish(acct, { account_states: [newer] });
    expect(res.status).toBe(200);
    expect(await stored(acct)).toEqual([{ state_jws: newer, sequence: 6 }]);
  });

  it("keeps only the documents at the highest verified sequence of a multi-document publish", async () => {
    const acct = testAccount("acct-state-verified-multi");
    await bindRoot(acct);
    const root = rootFor(acct);
    const older = signAccountState(root, { sequence: 1 });
    const newestA = signAccountState(root, { sequence: 2, revokedDevices: ["dev-a"] });
    const newestB = signAccountState(root, { sequence: 2, revokedDevices: ["dev-b"] });

    const res = await publish(acct, { account_states: [older, newestA, newestB] });
    expect(res.status).toBe(200);
    expect(res.data).toEqual({ account_states: [newestA, newestB].sort(), max_sequence: 2 });
    expect(await stored(acct)).toEqual(
      [newestA, newestB].sort().map((state_jws) => ({ state_jws, sequence: 2 })),
    );
  });

  it("accepts a root-signed document at exactly 2^53-1", async () => {
    const acct = testAccount("acct-state-verified-max-safe");
    await bindRoot(acct);
    const doc = signAccountState(rootFor(acct), { sequence: MAX_SAFE_SEQUENCE });

    const res = await publish(acct, { account_states: [doc] });
    expect(res.status).toBe(200);
    expect(res.data.max_sequence).toBe(MAX_SAFE_SEQUENCE);
  });
});

describe("account-state publish — rejections leave the stored state unchanged", () => {
  it("rejects a document signed by any other key (403)", async () => {
    const { acct, current } = await accountWithState("acct-state-reject-other-key");
    const attacker = testRoot("acct-state-reject-other-key/attacker");
    // Claims an honest-looking document for the victim account, but the attacker signs it.
    const forged = signAccountState(attacker, {
      sequence: 99,
      accountId: acct,
      currentRoot: rootFor(acct).rootPubkey,
    });

    const res = await publish(acct, { account_states: [forged] });
    expect(res.status).toBe(403);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects a root-signed document for a different account id (403)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-account-id");
    const mismatched = signAccountState(root, {
      sequence: 99,
      accountId: testAccount("acct-state-reject-account-id/other"),
    });

    const res = await publish(acct, { account_states: [mismatched] });
    expect(res.status).toBe(403);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects a root-signed document naming a different current_root (403)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-current-root");
    const wrongRoot = signAccountState(root, { sequence: 99, currentRoot: UNRELATED_PUBKEY });

    const res = await publish(acct, { account_states: [wrongRoot] });
    expect(res.status).toBe(403);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects a root-signed JWS of another type (403)", async () => {
    const { acct, current } = await accountWithState("acct-state-reject-typ");
    // A genuine root signature, but over an `allw-pairing-start+jws`.
    const otherType = signPairingStart(acct);

    const res = await publish(acct, { account_states: [otherType] });
    expect(res.status).toBe(403);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects a lower verified sequence (409)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-lower");
    const older = signAccountState(root, { sequence: 4 });

    const res = await publish(acct, { account_states: [older] });
    expect(res.status).toBe(409);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects an equal verified sequence, including a republish of the stored document (409)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-equal");
    const sibling = signAccountState(root, { sequence: 5, revokedDevices: ["dev-x"] });

    expect((await publish(acct, { account_states: [sibling] })).status).toBe(409);
    expect((await publish(acct, { account_states: [current] })).status).toBe(409);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects a compact-shaped junk JWS (403)", async () => {
    const { acct, current } = await accountWithState("acct-state-reject-junk");

    const res = await publish(acct, { account_states: ["eyJhbGciOiJFZERTQSJ9.eyJzIjoxfQ.sig"] });
    expect(res.status).toBe(403);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects a string that is not a compact JWS (400)", async () => {
    const { acct, current } = await accountWithState("acct-state-reject-not-compact");

    const res = await publish(acct, { account_states: ["not a compact jws"] });
    expect(res.status).toBe(400);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects the whole publish when one of several documents fails verification (403)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-mixed");
    const honest = signAccountState(root, { sequence: 6 });
    const forged = signAccountState(testRoot("acct-state-reject-mixed/attacker"), {
      sequence: 7,
      accountId: acct,
      currentRoot: root.rootPubkey,
    });

    const res = await publish(acct, { account_states: [honest, forged] });
    expect(res.status).toBe(403);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects an asserted max_sequence above the highest verified sequence (400)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-asserted-high");
    const newer = signAccountState(root, { sequence: 6 });

    const res = await publish(acct, { account_states: [newer], max_sequence: 7 });
    expect(res.status).toBe(400);
    expect(String(res.data.error)).toMatch(/max_sequence/);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects an asserted max_sequence below the highest verified sequence (400)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-asserted-low");
    const newer = signAccountState(root, { sequence: 7 });

    const res = await publish(acct, { account_states: [newer], max_sequence: 6 });
    expect(res.status).toBe(400);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects a non-integer max_sequence (400)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-asserted-shape");
    const newer = signAccountState(root, { sequence: 6 });

    for (const max_sequence of ["6", -1, 6.5, MAX_SAFE_SEQUENCE + 1, null]) {
      const res = await publish(acct, { account_states: [newer], max_sequence });
      expect(res.status, JSON.stringify(max_sequence)).toBe(400);
    }
    await expectStoredUnchanged(acct, current);
  });

  it("rejects a root-signed sequence above 2^53-1 (400)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-unsafe-sequence");
    // 2^53 + 1 is not representable as a JS number; the relay must not round it.
    const unsafe = signAccountState(root, { sequence: 9_007_199_254_740_993n });

    const res = await publish(acct, { account_states: [unsafe] });
    expect(res.status).toBe(400);
    expect(String(res.data.error)).toMatch(/2\^53-1/);
    await expectStoredUnchanged(acct, current);
  });

  it("rejects an empty, missing or oversized document list (400)", async () => {
    const { acct, root, current } = await accountWithState("acct-state-reject-list-shape");
    const many = Array.from({ length: 17 }, (_, i) => signAccountState(root, { sequence: 10 + i }));

    for (const body of [{}, { account_states: [] }, { account_states: many }, "not json"]) {
      const res = await publish(acct, body);
      expect(res.status, JSON.stringify(body).slice(0, 40)).toBe(400);
    }
    await expectStoredUnchanged(acct, current);
  });

  it("rejects a publish before any root is bound (409) and stores nothing", async () => {
    const acct = testAccount("acct-state-reject-unbound");
    const doc = signAccountState(rootFor(acct), { sequence: 1 });

    const res = await publish(acct, { account_states: [doc] });
    expect(res.status).toBe(409);
    expect(String(res.data.error)).toMatch(/not bound/);
    expect(await stored(acct)).toEqual([]);
  });
});

describe("account-state publish — 2^53-1 junk-sequence regression (#242)", () => {
  // Before #242 an enrolled device could publish any compact-shaped string with
  // `max_sequence = 2^53-1`; the relay stored it unverified and 409'd every later honest publish,
  // so revocations could never be distributed for the account again.
  it("a device publishing junk at max_sequence 2^53-1 does not block a later honest publish", async () => {
    const acct = testAccount("acct-state-regression-max-safe");
    const deviceToken = await enrollDevice(acct);

    const junk = await publish(
      acct,
      {
        account_states: ["eyJhbGciOiJFZERTQSJ9.eyJzZXF1ZW5jZSI6MX0.sig"],
        max_sequence: MAX_SAFE_SEQUENCE,
      },
      { Authorization: `Bearer ${deviceToken}` },
    );
    expect(junk.status).toBe(403);
    expect(await stored(acct)).toEqual([]);

    const honest = signAccountState(rootFor(acct), { sequence: 1, revokedDevices: ["dev-lost"] });
    const res = await publish(acct, { account_states: [honest] });
    expect(res.status).toBe(200);
    expect((await list(acct)).data).toEqual({ account_states: [honest], max_sequence: 1 });
  });
});

describe("account-state fetch — unauthenticated, verified documents only", () => {
  it("serves the verified documents with no token", async () => {
    const { acct, current } = await accountWithState("acct-state-get-no-token");

    const res = await list(acct);
    expect(res.status).toBe(200);
    expect(res.data).toEqual({ account_states: [current], max_sequence: 5 });
  });

  it("ignores any Authorization header rather than rejecting it", async () => {
    const { acct, current } = await accountWithState("acct-state-get-ignores-auth");

    const res = await list(acct, { Authorization: "Bearer not-a-device-token" });
    expect(res.status).toBe(200);
    expect(res.data).toEqual({ account_states: [current], max_sequence: 5 });
  });

  it("returns an empty set and max_sequence 0 for an account with no verified state", async () => {
    const acct = testAccount("acct-state-get-empty");

    const res = await list(acct);
    expect(res.status).toBe(200);
    expect(res.data).toEqual({ account_states: [], max_sequence: 0 });
  });

  it("never serves a rejected document", async () => {
    const { acct, current } = await accountWithState("acct-state-get-never-rejected");
    const forged = signAccountState(testRoot("acct-state-get-never-rejected/attacker"), {
      sequence: 99,
      accountId: acct,
      currentRoot: rootFor(acct).rootPubkey,
    });
    await publish(acct, { account_states: [forged] });

    const res = await list(acct);
    expect(res.data.account_states).toEqual([current]);
    expect(res.data.account_states).not.toContain(forged);
  });
});
