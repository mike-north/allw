/**
 * Fidelity tests for the in-process relay double (`src/lib/in-process-relay.ts`).
 *
 * The CI end-to-end round-trip is only as trustworthy as this double's faithfulness to the real
 * relay's observable contract (`docs/contract.md` §Transport → Relay routing API). These tests pin
 * the two behaviors a faithful double must get right — the offline-queue flush on (re)connect and
 * the full submit-validation allowlist — mirroring the corresponding cases in the real relay's
 * `workers-pool` suite so a regression in either surface is caught here, not only live.
 *
 * The double also mirrors the account-state publish rule (`docs/relay-api.md` §Account state):
 * keep only the highest-sequence documents, and 409 a publish that is not strictly above the stored
 * sequence.
 *
 * @see ../../../packages/relay/test/relay-routing.test.ts (the same cases against the real workerd relay)
 * @see ../../../docs/relay-api.md §Account state (trust distribution)
 * @see ../../../docs/contract.md §Transport, §Messages
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { InProcessRelay, ENVELOPE_KEYS } from "../dist/lib/in-process-relay.js";

// ── Fixed, deterministic timeline (fixed-dates rule: never Date.now() in fixtures) ──────────────
const NOW_MS = 1_700_000_000_000;
const FUTURE = NOW_MS + 300_000;
const now = () => NOW_MS;

/** A complete, valid envelope (exactly the contract's keys) with overridable fields. */
function envelope(overrides = {}) {
  return {
    v: 1,
    id: "req-1",
    created_at: NOW_MS,
    expires_at: FUTURE,
    approver: "acct-double",
    context_ciphertext: "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE",
    ...overrides,
  };
}

/** POST an envelope through the relay's fetchImpl and return `{ status, body }`. */
async function submit(relay, body) {
  const resp = await relay.fetchImpl("https://relay.test/acct-double/requests", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: resp.status, body: await resp.json() };
}

/** Poll a stored request with an optional relay-scoped bearer token. */
async function poll(relay, requestId, token) {
  const resp = await relay.fetchImpl(`https://relay.test/acct-double/requests/${requestId}`, {
    method: "GET",
    ...(token === undefined ? {} : { headers: { Authorization: `Bearer ${token}` } }),
  });
  return { status: resp.status, body: await resp.json() };
}

// ── Offline-queue flush (finding #1: queued-while-offline must be delivered on connect) ──────────

test("offline queue: a request submitted while offline is delivered once the device connects", async () => {
  const relay = new InProcessRelay({ now });
  relay.enrollDevice({ device_id: "dev-1", pubkey: "x", label: null, created_at: NOW_MS });

  // Submit with NO device connected → it must be stored pending and queued (delivered_to 0).
  const res = await submit(relay, envelope({ id: "req-offline" }));
  assert.equal(res.status, 202);
  assert.equal(res.body.delivered_to, 0, "no device was online to fan out to");
  assert.equal(res.body.status, "pending");

  // Device comes online, THEN attaches its handler (the real caller ordering). The queued request
  // must still arrive — this is the drop the reviewer flagged: deliver() ran before onRequest().
  const connection = relay.connectDevice();
  const received = [];
  connection.onRequest((requestId, env) => {
    received.push({ requestId, env });
  });

  assert.equal(received.length, 1, "the offline-queued request was flushed on connect");
  assert.equal(received[0].requestId, "req-offline");
  assert.equal(received[0].env.context_ciphertext, envelope().context_ciphertext);
});

test("offline queue: an expired queued request is NOT re-delivered on connect (fail-closed)", async () => {
  // Seed a pending request whose deadline is already past relative to a LATER clock.
  let clock = NOW_MS;
  const relay = new InProcessRelay({ now: () => clock });
  relay.enrollDevice({ device_id: "dev-1", pubkey: "x", label: null, created_at: NOW_MS });
  await submit(relay, envelope({ id: "req-stale", expires_at: NOW_MS + 1000 }));

  // Advance past the deadline, then connect — the dead request must be skipped (not flushed).
  clock = NOW_MS + 5000;
  const connection = relay.connectDevice();
  const received = [];
  connection.onRequest((requestId) => received.push(requestId));
  assert.equal(received.length, 0, "an expired queued request is never re-pushed");
});

// ── Online fan-out still works after the buffering change ────────────────────────────────────────

test("online: a request submitted after connect is delivered immediately", async () => {
  const relay = new InProcessRelay({ now });
  relay.enrollDevice({ device_id: "dev-1", pubkey: "x", label: null, created_at: NOW_MS });

  const connection = relay.connectDevice();
  const received = [];
  connection.onRequest((requestId) => received.push(requestId));

  const res = await submit(relay, envelope({ id: "req-online" }));
  assert.equal(res.body.delivered_to, 1, "fanned out to the one online device");
  assert.deepEqual(received, ["req-online"]);
});

// ── Submit validation allowlist (finding #2: mirror the real relay's required fields) ────────────

test("submit validation: rejects an envelope missing each required field (400)", async () => {
  const relay = new InProcessRelay({ now });
  for (const field of ENVELOPE_KEYS) {
    const body = envelope();
    delete body[field];
    const { status } = await submit(relay, body);
    assert.equal(status, 400, `missing '${field}' must be rejected with 400`);
  }
});

test("submit validation: rejects an unexpected (plaintext-looking) envelope key (400)", async () => {
  const relay = new InProcessRelay({ now });
  const { status, body } = await submit(relay, {
    ...envelope(),
    summary: "rm -rf / — please approve",
  });
  assert.equal(status, 400, "a stray plaintext field must be refused (zero-knowledge guard)");
  assert.match(String(body.error), /unexpected envelope field/);
});

test("submit validation: rejects a non-numeric v / created_at and an empty approver (400)", async () => {
  const relay = new InProcessRelay({ now });
  assert.equal((await submit(relay, envelope({ v: "1" }))).status, 400, "v must be a number");
  assert.equal(
    (await submit(relay, envelope({ created_at: "x" }))).status,
    400,
    "created_at must be a number",
  );
  assert.equal(
    (await submit(relay, envelope({ approver: "" }))).status,
    400,
    "approver must be a non-empty string",
  );
});

test("submit validation: rejects an already-expired request and a duplicate id", async () => {
  const relay = new InProcessRelay({ now });
  // Already past the deadline → 400.
  assert.equal(
    (await submit(relay, envelope({ id: "req-exp", expires_at: NOW_MS - 1 }))).status,
    400,
  );
  // Duplicate id → first 202, second 409.
  assert.equal((await submit(relay, envelope({ id: "req-dup" }))).status, 202);
  assert.equal((await submit(relay, envelope({ id: "req-dup" }))).status, 409);
});

test("submit validation: accepts a complete valid envelope (202 pending)", async () => {
  const relay = new InProcessRelay({ now });
  const { status, body } = await submit(relay, envelope({ id: "req-ok" }));
  assert.equal(status, 202);
  assert.equal(body.status, "pending");
  assert.equal(body.request_id, "req-ok");
  assert.equal(typeof body.request_auth_token, "string");
  assert.ok(body.request_auth_token.length > 0, "submit returns the token needed to poll");
});

test("poll auth: requires the request-scoped bearer token returned by submit", async () => {
  const relay = new InProcessRelay({ now });
  const { body } = await submit(relay, envelope({ id: "req-auth" }));

  assert.equal((await poll(relay, "req-auth")).status, 401, "missing bearer token is refused");
  assert.equal((await poll(relay, "req-auth", "wrong")).status, 403, "wrong token is refused");

  const { status, body: pollBody } = await poll(relay, "req-auth", body.request_auth_token);
  assert.equal(status, 200);
  assert.equal(pollBody.status, "pending");
  assert.equal(pollBody.request_id, "req-auth");
});

test("poll auth: an unknown id answers exactly as a wrong token, never 'not found' (#357)", async () => {
  const relay = new InProcessRelay({ now });
  await submit(relay, envelope({ id: "req-known" }));

  for (const token of [undefined, "wrong"]) {
    const known = await poll(relay, "req-known", token);
    const unknown = await poll(relay, "req-unknown", token);
    assert.deepEqual(unknown, known, `token ${String(token)}: indistinguishable`);
  }
  // The relay's auth answers (`docs/relay-api.md` §1).
  assert.deepEqual(await poll(relay, "req-unknown"), {
    status: 401,
    body: { error: "authorization required" },
  });
  assert.deepEqual(await poll(relay, "req-unknown", "wrong"), {
    status: 403,
    body: { error: "authorization denied" },
  });
});

// ── Account-state publish (`POST /:acct/account-states`) ────────────────────────────────────────

/** A compact-JWS-shaped string whose payload carries `sequence` (unsigned: the double never verifies). */
function stateJws(sequence) {
  const part = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${part({ alg: "EdDSA" })}.${part({ sequence })}.c2ln`;
}

async function publish(relay, accountStates) {
  const resp = await relay.fetchImpl("https://relay.test/acct-double/account-states", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ account_states: accountStates }),
  });
  return { status: resp.status, body: await resp.json() };
}

test("account-state publish: keeps only the highest-sequence documents and serves them", async () => {
  const relay = new InProcessRelay({ now });
  const published = await publish(relay, [stateJws(1), stateJws(2)]);
  assert.equal(published.status, 200);
  assert.deepEqual(published.body, { account_states: [stateJws(2)], max_sequence: 2 });

  const read = await relay.fetchImpl("https://relay.test/acct-double/account-states");
  assert.deepEqual(await read.json(), { account_states: [stateJws(2)], max_sequence: 2 });
});

test("account-state publish: refuses a sequence not strictly above the stored one (409)", async () => {
  const relay = new InProcessRelay({ now });
  assert.equal((await publish(relay, [stateJws(2)])).status, 200);
  assert.equal((await publish(relay, [stateJws(2)])).status, 409, "an idempotent republish");
  assert.equal((await publish(relay, [stateJws(1)])).status, 409, "a rollback");
  const read = await relay.fetchImpl("https://relay.test/acct-double/account-states");
  assert.equal((await read.json()).max_sequence, 2, "a refused publish leaves the stored state");
});

test("account-state publish: refuses an empty set or a non-JWS entry (400)", async () => {
  const relay = new InProcessRelay({ now });
  assert.equal((await publish(relay, [])).status, 400);
  assert.equal((await publish(relay, ["not-a-jws"])).status, 400);
});
