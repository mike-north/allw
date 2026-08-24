/**
 * Tests for {@link createRelayAccountStateResolver} — the relay-backed AccountStateResolver that
 * feeds root-signed account-state documents into the WASM core for actor-origin verification (#155,
 * parent #93). Tests cover:
 *
 *   - **valid root-signed account state → origin renders VERIFIED** (happy path, full round-trip
 *     through `createWasmRuntime.prepare` against the real WASM core);
 *   - **resolver outage → UNVERIFIED, never abort** (fail-closed per `docs/contract.md` §Invariants
 *     #6): network error, timeout, HTTP non-2xx, malformed body — all return `[]` without throwing;
 *   - **relay-substituted / invalid account state → never VERIFIED** (the WASM core rejects any
 *     account-state document that doesn't carry a valid root signature, regardless of what the relay
 *     serves);
 *   - **`max_sequence` is surfaced, not discarded** (#171): a valid response carries it through to
 *     the returned resolution; an omitted field yields no metadata (not malformed); a `max_sequence`
 *     that fails to parse as a non-negative safe integer fails closed on the WHOLE body.
 *
 * All timestamps are fixed constants — never `Date.now()` in test data.
 *
 * @see ../src/account-state.ts (the unit under test)
 * @see ../src/runtime.ts (AccountStateResolver consumer + the sequence-floor gate)
 * @see ../../../docs/enrollment.md §Account State, §Actor-Key Enrollment
 * @see ../../../docs/contract.md §Invariants #5, #6
 * @see ./account-state-sequence-floor.test.mjs (the sequence-floor gate's own negative-test suite)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { createRelayAccountStateResolver } from "../dist/account-state.js";
import { createWasmRuntime } from "../dist/index.js";
import { loadTestWasm } from "./wasm-helper.mjs";

// ── Deterministic fixtures ─────────────────────────────────────────────────────────────────────

const ACCOUNT_ID = "acct-account-state-test";
const DEVICE_ID = "dev-account-state-test";
const REQUEST_ID = "req-account-state-test-1";
const RELAY_URL = "https://relay.example.test";

/** 2023-11-14T22:13:20Z — cert issuance. */
const ISSUED_AT = 1700000000000;
/** 2023-11-14T23:13:20Z — request deadline. */
const EXPIRES_AT = 1700003600000;
/** 2023-11-14T22:38:20Z — the runtime/test "now" (mid-session, before deadline). */
const NOW_MS = 1700001500000;

/** Device auth bearer token — value not validated by the resolver itself. */
const DEVICE_AUTH_TOKEN = "test-device-auth-token";

/**
 * The canonical approval context.
 */
const CONTEXT = {
  action: {
    record_schema_version: 1,
    surface: "command",
    syntactic: { bin: "git", argv: ["git", "push", "--force", "origin", "main"], cwd: "/repo" },
    risk: "high",
  },
  summary: "force push to main",
  actor: { id: "machine:test-laptop", kind: "claude-code" },
  risk: "high",
  reversible: false,
  constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
};

/**
 * Build a fully-paired identity: fresh seeds whose account-root certifies the device signing key.
 * Returns `{ identity, accountRootSeed, encryptTo }`.
 */
function pairedIdentity(wasm) {
  const accountRootSeed = Buffer.alloc(32, 0xaa).toString("base64url");
  const deviceSigningSeed = Buffer.alloc(32, 0xbb).toString("base64url");
  const deviceEncryptionSeed = Buffer.alloc(32, 0xcc).toString("base64url");

  const accountRootPubkey = wasm.ed25519_public_key(accountRootSeed);
  const deviceSigningPubkey = wasm.ed25519_public_key(deviceSigningSeed);
  const deviceEncryptionPubkey = wasm.x25519_public_key(deviceEncryptionSeed);

  const deviceCert = wasm.issue_device_cert(
    accountRootSeed,
    ACCOUNT_ID,
    DEVICE_ID,
    deviceSigningPubkey,
    ISSUED_AT,
  );

  const identity = {
    accountId: ACCOUNT_ID,
    deviceId: DEVICE_ID,
    deviceEncryptionSeed,
    deviceSigningSeed,
    deviceCert,
    accountRootPubkey,
  };

  const encryptTo = (contextJson) =>
    wasm.encrypt_context(
      contextJson,
      JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: deviceEncryptionPubkey }]),
    );

  return { identity, accountRootSeed, encryptTo };
}

/**
 * Build a root-signed account-state document that enrolls `actorPubkey` as `actorId` (active).
 */
function buildAccountState(
  wasm,
  accountRootSeed,
  accountRootPubkey,
  actorId,
  actorKind,
  actorPubkey,
  sequence = 1,
) {
  const stateJson = JSON.stringify({
    v: 1,
    account_id: ACCOUNT_ID,
    sequence,
    current_root: accountRootPubkey,
    previous_roots: [],
    devices: [],
    actors: [
      {
        actor_id: actorId,
        kind: actorKind,
        pubkey: actorPubkey,
        status: "active",
      },
    ],
    revocations: [],
  });
  return wasm.sign_account_state(stateJson, accountRootSeed);
}

/** A relay envelope the runtime consumes. */
function makeEnvelope(contextCiphertext) {
  return {
    v: 1,
    id: REQUEST_ID,
    created_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    approver: ACCOUNT_ID,
    context_ciphertext: contextCiphertext,
  };
}

/**
 * Build a context that carries an actor attestation JWS bound to the given request/hash/actorSeed.
 */
function attestedContext(wasm, actorSeed) {
  const contextJson = JSON.stringify(CONTEXT);
  const requestHash = wasm.compute_request_hash(contextJson, EXPIRES_AT);
  const attestation = wasm.sign_actor_attestation(
    ACCOUNT_ID,
    CONTEXT.actor.id,
    CONTEXT.actor.kind,
    REQUEST_ID,
    requestHash,
    actorSeed,
  );
  return { ...CONTEXT, actor: { ...CONTEXT.actor, attestation } };
}

/**
 * Build a fake `fetch` that simulates the relay returning the given account_states array.
 */
function fakeFetch(accountStates, maxSequence = 1) {
  return async (_url, _init) => ({
    ok: true,
    status: 200,
    json: async () => ({ account_states: accountStates, max_sequence: maxSequence }),
  });
}

// ── Happy path: valid root-signed account state → VERIFIED ────────────────────────────────────

test("valid root-signed account state: actor-origin resolves to verified (#155)", async () => {
  const wasm = await loadTestWasm();
  const { identity, accountRootSeed, encryptTo } = pairedIdentity(wasm);

  const actorSeed = Buffer.alloc(32, 0xdd).toString("base64url");
  const actorPubkey = wasm.ed25519_public_key(actorSeed);

  const accountState = buildAccountState(
    wasm,
    accountRootSeed,
    identity.accountRootPubkey,
    CONTEXT.actor.id,
    CONTEXT.actor.kind,
    actorPubkey,
  );

  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: fakeFetch([accountState]),
  });

  const runtime = createWasmRuntime({
    wasm,
    identity,
    nowMs: () => NOW_MS,
    resolveAccountStates: resolver,
  });

  const attested = attestedContext(wasm, actorSeed);
  const envelope = makeEnvelope(encryptTo(JSON.stringify(attested)));
  const prepared = await runtime.prepare(envelope);

  assert.equal(
    prepared.context.actor.attestation,
    "verified",
    "a valid root-signed account state with a matching actor key renders attestation = verified",
  );
});

// ── Resolver sends the correct relay URL and Authorization header ──────────────────────────────

test("resolver fetches from GET /{accountId}/account-states with Bearer auth", async () => {
  const calls = [];
  const mockFetch = async (url, init) => {
    calls.push({ url, headers: init?.headers });
    return {
      ok: true,
      status: 200,
      json: async () => ({ account_states: [], max_sequence: 0 }),
    };
  };

  const resolver = createRelayAccountStateResolver({
    relayUrl: "https://relay.example.test/",
    accountId: "acct-url-test",
    deviceAuthToken: "tok-abc",
    fetchImpl: mockFetch,
  });

  await resolver("any-actor");

  assert.equal(calls.length, 1, "resolver fires exactly one fetch per call");
  assert.equal(
    calls[0].url,
    "https://relay.example.test/acct-url-test/account-states",
    "URL: trailing relay slash normalized, accountId encoded",
  );
  assert.equal(
    calls[0].headers.Authorization,
    "Bearer tok-abc",
    "Authorization header carries the device bearer token",
  );
});

// ── Fail-closed: outage / non-2xx / malformed body → empty array (no throw) ──────────────────

test("network error: resolver returns [] without throwing (fail-closed outage)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => {
      throw new Error("ECONNREFUSED — relay is down");
    },
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, [], "network error returns empty array, not a throw");
});

test("relay timeout: AbortSignal.timeout causes a fail-closed empty array (no throw)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    timeoutMs: 1, // 1ms — will fire before the slow response below resolves
    // A real `fetch` rejects once its `signal` aborts; this mock must honor that contract too, or
    // the test would pass merely because the eventual (never-aborted) response happens to be
    // empty — it would then no longer be exercising the timeout path at all.
    fetchImpl: (_url, init) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(
          () =>
            resolve({
              ok: true,
              status: 200,
              json: async () => ({ account_states: ["should-never-be-returned"], max_sequence: 9 }),
            }),
          100,
        );
        init?.signal?.addEventListener("abort", () => {
          clearTimeout(timer);
          reject(new DOMException("The operation was aborted.", "AbortError"));
        });
      }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, [], "timeout surfaces as empty array, not a throw");
});

test("HTTP 401: non-2xx response returns [] (fail-closed — token invalid or expired)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: false,
      status: 401,
      json: async () => ({ error: "Unauthorized" }),
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, [], "non-2xx returns empty array, never throws");
});

test("HTTP 503: relay unavailable returns [] (fail-closed outage)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: false,
      status: 503,
      json: async () => ({ error: "Service Unavailable" }),
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, [], "503 returns empty array, never throws");
});

test("malformed response — missing account_states field: returns [] (fail-closed)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ unexpected_field: "surprise" }),
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, [], "missing account_states field returns empty array");
});

test("malformed response — account_states is not an array: returns [] (fail-closed)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ account_states: "not-an-array" }),
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, [], "non-array account_states returns empty array");
});

test("malformed response — account_states contains non-strings: returns [] (fail-closed)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ account_states: [42, null, { key: "not-a-string" }] }),
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, [], "non-string array elements return empty array");
});

// ── Surfacing max_sequence (#171) ──────────────────────────────────────────────────────────────

test("max_sequence: a valid response surfaces both account_states and maxSequence", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: fakeFetch(["state-a", "state-b"], 7),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(
    result,
    { accountStates: ["state-a", "state-b"], maxSequence: 7 },
    "the resolver must surface the relay's max_sequence alongside the account-state documents",
  );
});

test("max_sequence: an omitted field resolves without a maxSequence key (no metadata, not malformed)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ account_states: ["state-a"] }),
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, { accountStates: ["state-a"] });
});

test("malformed response — max_sequence is not a number: fails closed to [] (never a resolution missing just the metadata)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ account_states: ["state-a"], max_sequence: "not-a-number" }),
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, [], "a malformed max_sequence must fail closed on the WHOLE body");
});

test("malformed response — max_sequence is negative: fails closed to []", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ account_states: [], max_sequence: -1 }),
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, []);
});

test("malformed response — max_sequence is not a safe integer: fails closed to []", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ account_states: [], max_sequence: 1.5 }),
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, []);
});

test("malformed response — body is not a JSON object: returns [] (fail-closed)", async () => {
  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ["array-not-object"],
    }),
  });

  const result = await resolver("actor-1");
  assert.deepEqual(result, [], "non-object body returns empty array");
});

// ── Relay-substituted / invalid state: WASM core rejects, never VERIFIED ─────────────────────

test("relay-substituted state: a document signed by the wrong key never produces VERIFIED (#16)", async () => {
  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);

  // The relay substitutes an account-state document signed by a DIFFERENT account root (not the
  // account root the device trusts). The WASM core rejects the foreign root signature → unverified.
  const foreignRootSeed = Buffer.alloc(32, 0xff).toString("base64url");
  const foreignRootPubkey = wasm.ed25519_public_key(foreignRootSeed);
  const actorSeed = Buffer.alloc(32, 0xdd).toString("base64url");
  const actorPubkey = wasm.ed25519_public_key(actorSeed);

  const foreignStateJson = JSON.stringify({
    v: 1,
    account_id: ACCOUNT_ID,
    sequence: 1,
    current_root: foreignRootPubkey,
    previous_roots: [],
    devices: [],
    actors: [
      {
        actor_id: CONTEXT.actor.id,
        kind: CONTEXT.actor.kind,
        pubkey: actorPubkey,
        status: "active",
      },
    ],
    revocations: [],
  });
  // Signed by the RELAY's/attacker's root, NOT the account's trusted root.
  const foreignState = wasm.sign_account_state(foreignStateJson, foreignRootSeed);

  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: fakeFetch([foreignState]),
  });

  const runtime = createWasmRuntime({
    wasm,
    identity,
    nowMs: () => NOW_MS,
    resolveAccountStates: resolver,
  });

  const attested = attestedContext(wasm, actorSeed);
  const envelope = makeEnvelope(encryptTo(JSON.stringify(attested)));
  const prepared = await runtime.prepare(envelope);

  assert.equal(
    prepared.context.actor.attestation,
    "unverified",
    "an account-state document signed by the wrong root can NEVER produce verified — relay substitution is rejected by the WASM core",
  );
});

test("invalid JWS string: a structurally broken account-state document never produces VERIFIED", async () => {
  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);

  const actorSeed = Buffer.alloc(32, 0xee).toString("base64url");

  const resolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: fakeFetch(["this-is-not-a-valid-jws", "also-garbage.stuff.here"]),
  });

  const runtime = createWasmRuntime({
    wasm,
    identity,
    nowMs: () => NOW_MS,
    resolveAccountStates: resolver,
  });

  const attested = attestedContext(wasm, actorSeed);
  const envelope = makeEnvelope(encryptTo(JSON.stringify(attested)));
  const prepared = await runtime.prepare(envelope);

  assert.equal(
    prepared.context.actor.attestation,
    "unverified",
    "structurally invalid account-state strings cannot drive verified — fail-closed",
  );
});

test("relay outage during prepare: origin downgrades to unverified without aborting the action review", async () => {
  const wasm = await loadTestWasm();
  const { identity, accountRootSeed, encryptTo } = pairedIdentity(wasm);

  const actorSeed = Buffer.alloc(32, 0xdd).toString("base64url");
  const actorPubkey = wasm.ed25519_public_key(actorSeed);
  const accountState = buildAccountState(
    wasm,
    accountRootSeed,
    identity.accountRootPubkey,
    CONTEXT.actor.id,
    CONTEXT.actor.kind,
    actorPubkey,
  );

  // Establish that a working resolver produces verified (baseline).
  const workingResolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: fakeFetch([accountState]),
  });
  const workingRuntime = createWasmRuntime({
    wasm,
    identity,
    nowMs: () => NOW_MS,
    resolveAccountStates: workingResolver,
  });
  const attested = attestedContext(wasm, actorSeed);
  const envelope = makeEnvelope(encryptTo(JSON.stringify(attested)));
  const workingPrepared = await workingRuntime.prepare(envelope);
  assert.equal(
    workingPrepared.context.actor.attestation,
    "verified",
    "baseline: working resolver → verified",
  );

  // Now simulate a relay outage on the same request.
  const outageResolver = createRelayAccountStateResolver({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    deviceAuthToken: DEVICE_AUTH_TOKEN,
    fetchImpl: async () => {
      throw new Error("connection refused");
    },
  });
  const outagedRuntime = createWasmRuntime({
    wasm,
    identity,
    nowMs: () => NOW_MS,
    resolveAccountStates: outageResolver,
  });

  // prepare must not throw — the action is still reviewable, just with unverified origin badge.
  const outagedPrepared = await outagedRuntime.prepare(
    makeEnvelope(encryptTo(JSON.stringify(attested))),
  );
  assert.equal(
    outagedPrepared.context.actor.attestation,
    "unverified",
    "relay outage during prepare downgrades to unverified — never aborts the action review",
  );
  // The action detail is still present (the human can still deny the request).
  assert.equal(
    outagedPrepared.context.kind,
    "command",
    "context kind is still accessible on outage",
  );
  assert.deepEqual(
    outagedPrepared.context.command?.argv,
    CONTEXT.action.syntactic.argv,
    "argv is still present for rendering after a resolver outage",
  );
});
