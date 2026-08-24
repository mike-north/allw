/**
 * Integration tests for the device-side account-state rollback floor (#171 — the web analogue of
 * #115's approver-keyfile floor) at the `createWasmRuntime.prepare` layer, against the **real WASM
 * core**. `test/sequence-floor.test.mjs` covers the persistence primitive in isolation; these tests
 * cover the actual security property: a relay that suppresses a newer revocation by re-serving an
 * older, still-validly-root-signed account-state document must not be able to render a revoked
 * actor's origin as `✓ VERIFIED`.
 *
 * Covers every rejection path the sequence-floor gate introduces:
 *   - **the regression case** (#171's acceptance criterion): a relay that once showed the device a
 *     higher, revoking sequence later reverts to an older, self-consistent (metadata matches served
 *     docs) but stale response ⇒ UNVERIFIED, caught by the PERSISTED FLOOR alone (the relay's
 *     per-fetch honesty check would not catch this, since that one fetch is internally consistent);
 *   - the floor persists **across reloads** (a fresh store instance over the same backing storage
 *     still rejects the stale fetch);
 *   - the floor is **monotonic** — it only ever ratchets up, never down, across a longer sequence of
 *     calls;
 *   - **storage tampering** (a corrupted persisted floor) still fails closed, because the
 *     independent per-fetch relay-metadata-honesty check is a SEPARATE signal — the effective floor
 *     for a given call is the higher of the two, so destroying one signal does not disable the other.
 *
 * All timestamps are fixed constants — never `Date.now()` in test data.
 *
 * @see ../src/runtime.ts (resolveAttestation — the two-signal sequence-floor gate under test)
 * @see ../src/sequence-floor.ts (the persistence primitive)
 * @see ./sequence-floor.test.mjs (store-level unit tests)
 * @see ../../../docs/enrollment.md §Account State, step 5
 * @see ../../approver/test/watch.test.mjs (the Node/CLI analogue, #115)
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import { createLocalAccountStateFloorStore } from "../dist/sequence-floor.js";
import { createWasmRuntime } from "../dist/index.js";
import { loadTestWasm } from "./wasm-helper.mjs";

// ── Deterministic fixtures (fixed timestamps; never Date.now() in test data) ──────────────────

const ACCOUNT_ID = "acct-seq-floor-test";
const DEVICE_ID = "dev-seq-floor-test";
const REQUEST_ID = "req-seq-floor-test-1";
const ACTOR_ID = "machine:seq-floor-laptop";
const ACTOR_KIND = "claude-code";

/** 2023-11-14T22:13:20Z — cert issuance. */
const ISSUED_AT = 1700000000000;
/** 2023-11-14T23:13:20Z — request deadline. */
const EXPIRES_AT = 1700003600000;
/** 2023-11-14T22:38:20Z — the runtime "now" (mid-session, before deadline). */
const NOW_MS = 1700001500000;

const CONTEXT = {
  action: {
    record_schema_version: 1,
    surface: "command",
    syntactic: { bin: "git", argv: ["git", "push", "--force", "origin", "main"], cwd: "/repo" },
    risk: "high",
  },
  summary: "force push to main",
  actor: { id: ACTOR_ID, kind: ACTOR_KIND },
  risk: "high",
  reversible: false,
  constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
};

/** A fake in-memory `Storage`, mirroring `pairing.test.mjs`'s `memoryStorage()`. */
function memoryStorage() {
  const map = new Map();
  return {
    getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    setItem(key, value) {
      map.set(key, value);
    },
    removeItem(key) {
      map.delete(key);
    },
  };
}

/** Build a fully-paired browser approver identity + an `encryptTo` helper. */
function pairedIdentity(wasm) {
  const accountRootSeed = Buffer.alloc(32, 0x11).toString("base64url");
  const deviceSigningSeed = Buffer.alloc(32, 0x22).toString("base64url");
  const deviceEncryptionSeed = Buffer.alloc(32, 0x33).toString("base64url");

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
    deviceAuthToken: "relay-bearer-test-token",
  };

  const encryptTo = (contextJson) =>
    wasm.encrypt_context(
      contextJson,
      JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: deviceEncryptionPubkey }]),
    );

  return { identity, accountRootSeed, encryptTo };
}

/** A root-signed account-state doc at `sequence` enrolling `actorPubkey` as ACTIVE. */
function activeAccountState(wasm, accountRootSeed, accountRootPubkey, actorPubkey, sequence) {
  const stateJson = JSON.stringify({
    v: 1,
    account_id: ACCOUNT_ID,
    sequence,
    current_root: accountRootPubkey,
    previous_roots: [],
    devices: [],
    actors: [{ actor_id: ACTOR_ID, kind: ACTOR_KIND, pubkey: actorPubkey, status: "active" }],
    revocations: [],
  });
  return wasm.sign_account_state(stateJson, accountRootSeed);
}

/** A root-signed account-state doc at `sequence` that REVOKES the actor (a real revocation). */
function revokingAccountState(wasm, accountRootSeed, accountRootPubkey, actorPubkey, sequence) {
  const stateJson = JSON.stringify({
    v: 1,
    account_id: ACCOUNT_ID,
    sequence,
    current_root: accountRootPubkey,
    previous_roots: [],
    devices: [],
    actors: [{ actor_id: ACTOR_ID, kind: ACTOR_KIND, pubkey: actorPubkey, status: "revoked" }],
    revocations: [
      { kind: "actor", id: ACTOR_ID, revoked_at: ISSUED_AT, reason: "test-revocation" },
    ],
  });
  return wasm.sign_account_state(stateJson, accountRootSeed);
}

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

/** Build the CONTEXT with a valid actor attestation bound to REQUEST_ID + its request_hash. */
function attestedContextJson(wasm, actorSeed) {
  const contextJson = JSON.stringify(CONTEXT);
  const requestHash = wasm.compute_request_hash(contextJson, EXPIRES_AT);
  const attestation = wasm.sign_actor_attestation(
    ACCOUNT_ID,
    ACTOR_ID,
    ACTOR_KIND,
    REQUEST_ID,
    requestHash,
    actorSeed,
  );
  return JSON.stringify({ ...CONTEXT, actor: { ...CONTEXT.actor, attestation } });
}

/** A fixed-clock runtime with the given account-state resolver + (optional) sequence-floor store. */
function runtimeWith(wasm, identity, resolveAccountStates, sequenceFloorStore) {
  return createWasmRuntime({
    wasm,
    identity,
    nowMs: () => NOW_MS,
    resolveAccountStates,
    ...(sequenceFloorStore ? { sequenceFloorStore } : {}),
  });
}

// ── The regression case: relay suppresses a newer revocation ⇒ UNVERIFIED ────────────────────

test("relay suppresses a newer revocation: a previously root-verified higher sequence persists as a floor and rejects the stale rollback (#171)", async () => {
  const wasm = await loadTestWasm();
  const { identity, accountRootSeed, encryptTo } = pairedIdentity(wasm);

  const actorSeed = Buffer.alloc(32, 0x44).toString("base64url");
  const actorPubkey = wasm.ed25519_public_key(actorSeed);

  const stateSeq1 = activeAccountState(
    wasm,
    accountRootSeed,
    identity.accountRootPubkey,
    actorPubkey,
    1,
  );
  const stateSeq2Revoked = revokingAccountState(
    wasm,
    accountRootSeed,
    identity.accountRootPubkey,
    actorPubkey,
    2,
  );

  const attested = attestedContextJson(wasm, actorSeed);
  const envelope = makeEnvelope(encryptTo(attested));

  // A single persisted-floor store, backed by storage that survives across "sessions" (reloads).
  const storage = memoryStorage();
  const floorStoreSessionOne = createLocalAccountStateFloorStore(storage);

  // Session 1: the account owner has just published the revocation (sequence 2). The relay is
  // honest THIS call — its max_sequence metadata (2) matches the highest doc it serves (2). The
  // device root-verifies sequence 2 (bumping the persisted floor to 2) but the actor is revoked
  // there, so the origin renders unverified — this call's own result is not the point; the POINT
  // is that the floor is now durably 2.
  const runtimeSessionOne = runtimeWith(
    wasm,
    identity,
    () => Promise.resolve({ accountStates: [stateSeq2Revoked], maxSequence: 2 }),
    floorStoreSessionOne,
  );
  const preparedSessionOne = await runtimeSessionOne.prepare(envelope);
  assert.equal(
    preparedSessionOne.context.actor.attestation,
    "unverified",
    "a genuinely revoked actor never renders verified",
  );
  assert.equal(
    floorStoreSessionOne.load(),
    2,
    "the floor must be raised to the highest ROOT-VERIFIED sequence actually observed, " +
      "independent of whether the actor was active or revoked in that document",
  );

  // Session 2 ("reload"): a COMPROMISED relay now suppresses the revocation, reverting to serving
  // ONLY the pre-revocation sequence-1 document — and, critically, reports max_sequence = 1,
  // matching what it serves (internally self-consistent; the per-fetch honesty check ALONE would
  // pass this). A fresh store instance simulates the browser reload; the underlying storage (and
  // therefore the floor) survives.
  const floorStoreSessionTwo = createLocalAccountStateFloorStore(storage);
  const runtimeSessionTwo = runtimeWith(
    wasm,
    identity,
    () => Promise.resolve({ accountStates: [stateSeq1], maxSequence: 1 }),
    floorStoreSessionTwo,
  );
  const preparedSessionTwo = await runtimeSessionTwo.prepare(envelope);

  assert.equal(
    preparedSessionTwo.context.actor.attestation,
    "unverified",
    "a relay that suppresses a newer revocation by re-serving an older, self-consistent " +
      "response must still be rejected — the persisted floor (not the per-fetch metadata check) " +
      "is what catches it",
  );
});

// ── Floor is monotonic across a longer sequence of calls ─────────────────────────────────────

test("monotonic across calls: the floor only ratchets up, even after a legitimate further rotation", async () => {
  const wasm = await loadTestWasm();
  const { identity, accountRootSeed, encryptTo } = pairedIdentity(wasm);

  const actorSeed = Buffer.alloc(32, 0x55).toString("base64url");
  const actorPubkey = wasm.ed25519_public_key(actorSeed);

  const stateSeq1 = activeAccountState(
    wasm,
    accountRootSeed,
    identity.accountRootPubkey,
    actorPubkey,
    1,
  );
  const stateSeq2 = activeAccountState(
    wasm,
    accountRootSeed,
    identity.accountRootPubkey,
    actorPubkey,
    2,
  );
  const stateSeq3 = activeAccountState(
    wasm,
    accountRootSeed,
    identity.accountRootPubkey,
    actorPubkey,
    3,
  );

  const attested = attestedContextJson(wasm, actorSeed);
  const envelope = makeEnvelope(encryptTo(attested));

  const storage = memoryStorage();

  // Call 1: sequence 1 — establishes the floor at 1, verified.
  const runtime1 = runtimeWith(
    wasm,
    identity,
    () => Promise.resolve({ accountStates: [stateSeq1], maxSequence: 1 }),
    createLocalAccountStateFloorStore(storage),
  );
  const prepared1 = await runtime1.prepare(envelope);
  assert.equal(prepared1.context.actor.attestation, "verified");

  // Call 2: a legitimate further rotation to sequence 3 — the floor ratchets up to 3, verified.
  const runtime2 = runtimeWith(
    wasm,
    identity,
    () => Promise.resolve({ accountStates: [stateSeq3], maxSequence: 3 }),
    createLocalAccountStateFloorStore(storage),
  );
  const prepared2 = await runtime2.prepare(envelope);
  assert.equal(prepared2.context.actor.attestation, "verified");
  assert.equal(createLocalAccountStateFloorStore(storage).load(), 3);

  // Call 3: a rollback attempt to sequence 2 (self-consistent metadata) — rejected; the floor must
  // NOT have been lowered by call 1 or 2 having ever seen a lower value first.
  const runtime3 = runtimeWith(
    wasm,
    identity,
    () => Promise.resolve({ accountStates: [stateSeq2], maxSequence: 2 }),
    createLocalAccountStateFloorStore(storage),
  );
  const prepared3 = await runtime3.prepare(envelope);
  assert.equal(
    prepared3.context.actor.attestation,
    "unverified",
    "a rollback to a previously-superseded sequence must be rejected even though it is higher " +
      "than the FIRST sequence ever seen (1) — the floor tracks the maximum, not the most recent",
  );
  assert.equal(
    createLocalAccountStateFloorStore(storage).load(),
    3,
    "a rejected rollback attempt must never lower the persisted floor",
  );
});

// ── Storage tampering: a corrupted persisted floor still fails closed via the OTHER signal ───

test("storage tampering: a corrupted persisted floor does not disable the independent per-fetch relay-metadata check", async () => {
  const wasm = await loadTestWasm();
  const { identity, accountRootSeed, encryptTo } = pairedIdentity(wasm);

  const actorSeed = Buffer.alloc(32, 0x66).toString("base64url");
  const actorPubkey = wasm.ed25519_public_key(actorSeed);

  // Only a sequence-1 document is ever served — but the relay LIES about its own max_sequence for
  // this fetch, asserting 5 (matching neither the served docs nor any prior legitimate sequence).
  const stateSeq1 = activeAccountState(
    wasm,
    accountRootSeed,
    identity.accountRootPubkey,
    actorPubkey,
    1,
  );

  const attested = attestedContextJson(wasm, actorSeed);
  const envelope = makeEnvelope(encryptTo(attested));

  // Corrupt the underlying storage directly (simulating tampering / a corrupted browser profile) —
  // never went through `save()`, so the persisted-floor signal is destroyed (`load()` fails closed
  // to `0`, per `sequence-floor.test.mjs`).
  const storage = memoryStorage();
  storage.setItem("allw:account-state-floor:v1", "not-a-number");
  const floorStore = createLocalAccountStateFloorStore(storage);
  assert.equal(floorStore.load(), 0, "sanity: the tampered value reads back as 0 (fail-closed)");

  const runtime = runtimeWith(
    wasm,
    identity,
    () => Promise.resolve({ accountStates: [stateSeq1], maxSequence: 5 }),
    floorStore,
  );
  const prepared = await runtime.prepare(envelope);

  assert.equal(
    prepared.context.actor.attestation,
    "unverified",
    "even with the persisted floor destroyed by storage tampering, a relay's own per-fetch " +
      "max_sequence metadata (5) not backed by the documents it actually served (highest " +
      "verified sequence 1) must still be rejected — the effective floor for a call is the " +
      "higher of the two signals, and a corrupted local one does not zero out the other",
  );
});

test("absent storage (never paired before): the per-fetch relay-metadata check alone still catches an inconsistent relay", async () => {
  const wasm = await loadTestWasm();
  const { identity, accountRootSeed, encryptTo } = pairedIdentity(wasm);

  const actorSeed = Buffer.alloc(32, 0x77).toString("base64url");
  const actorPubkey = wasm.ed25519_public_key(actorSeed);
  const stateSeq1 = activeAccountState(
    wasm,
    accountRootSeed,
    identity.accountRootPubkey,
    actorPubkey,
    1,
  );

  const attested = attestedContextJson(wasm, actorSeed);
  const envelope = makeEnvelope(encryptTo(attested));

  // Fresh storage — never written. This is the FIRST fetch this device has ever made.
  const floorStore = createLocalAccountStateFloorStore(memoryStorage());
  assert.equal(floorStore.load(), 0);

  const runtime = runtimeWith(
    wasm,
    identity,
    () => Promise.resolve({ accountStates: [stateSeq1], maxSequence: 9 }),
    floorStore,
  );
  const prepared = await runtime.prepare(envelope);

  assert.equal(
    prepared.context.actor.attestation,
    "unverified",
    "an absent persisted floor must not disable the independent relay-metadata-honesty check",
  );
});
