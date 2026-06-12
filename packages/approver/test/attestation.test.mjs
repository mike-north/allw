/**
 * Actor-key attestation: verified request origin (issue #16) — root-anchored trust.
 *
 * Proves the approver's *request-side* trust path against the **real WASM core** (no crypto mocks):
 *   1. an actor signs an attestation binding its identity to the request's `request_id` +
 *      `request_hash`;
 *   2. the approver resolves the actor key from a **root-signed account-state document**
 *      (`docs/enrollment.md` §Account State) — NOT a relay-supplied `/actors` key — and verifies
 *      the chain to the configured account root;
 *   3. the renderer shows a ✓ VERIFIED origin when it verifies, and an explicit ⚠ UNVERIFIED line
 *      when the attestation is absent, no root-signed account state is available, the actor key is
 *      forged (not root-anchored), the actor is revoked, the request id/hash binding is wrong, or
 *      the origin is spoofed — a failed/absent attestation is NEVER shown as verified.
 *
 * The blocker this guards: a malicious or compromised relay must not be able to forge a verified
 * origin. Because the actor key is trusted only when it appears, active, in account state signed by
 * the configured account root, a relay-substituted key can never drive ✓ VERIFIED.
 *
 * The approver is exercised through its built `dist/` ESM (its public surface); the WASM is the
 * same vendored `--target web` artifact the SDK test loads (`pnpm run build:wasm` from the repo
 * root). This is an integration test over the audited Rust crypto, not a unit test against stubs.
 *
 * Run order:
 *   pnpm run build:wasm
 *   pnpm --filter @allw/approver build
 *   pnpm --filter @allw/approver test
 *
 * @see ../../../docs/contract.md §Invariants #4 (Requester attestation), §Identity & keys
 * @see ../../../docs/enrollment.md §Account State, §Actor-Key Enrollment
 * @see ../../sdk/test/wasm.test.mjs (the loader + fixture pattern this mirrors)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadWasm } from "../dist/index.js";
import { generateKeyfile } from "../dist/lib/keyfile.js";
import { prepareRequest, verifyActorOrigin } from "../dist/lib/approver-core.js";
import { renderRequest } from "../dist/lib/render.js";

// ── Deterministic fixtures (fixed timestamps; never Date.now() in test data) ──────────────────

const ACCOUNT_ID = "acct-attest-test";
const DEVICE_ID = "dev-attest-test";
const REQUEST_ID = "req-attest-test-1";
const OTHER_REQUEST_ID = "req-attest-test-2";
const ISSUED_AT = 1700000000000;
const EXPIRES_AT = 1700003600000;
const NOW_MS = 1700001500000;

const ACTOR_ID = "machine:macbook-pro";
const ACTOR_KIND = "claude-code";

/** The actor's enrolled signing seed (fixed — deterministic key derivation). */
const ACTOR_SEED = Buffer.alloc(32, 0x44).toString("base64url");
/** A different (attacker) seed for forged-key / spoof cases. */
const OTHER_SEED = Buffer.alloc(32, 0x55).toString("base64url");

/** A context WITHOUT an attestation — the integrator fills `actor.attestation` per-test. */
function baseContext(attestation) {
  const actor =
    attestation === undefined
      ? { id: ACTOR_ID, kind: ACTOR_KIND }
      : { id: ACTOR_ID, kind: ACTOR_KIND, attestation };
  return {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: { bin: "git", raw: "git push --force origin main" },
      risk: "high",
    },
    summary: "force push to main",
    actor,
    risk: "high",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
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

/** A fully-paired approver keyfile (so prepareRequest can decrypt and we hold the account root). */
function pairedApprover(wasm) {
  const fresh = generateKeyfile(wasm);
  const cert = wasm.issue_device_cert(
    fresh.account_root_seed,
    ACCOUNT_ID,
    DEVICE_ID,
    fresh.device_signing_pubkey,
    ISSUED_AT,
  );
  return {
    ...fresh,
    relay_url: "https://relay.allw.test",
    account_id: ACCOUNT_ID,
    device_id: DEVICE_ID,
    device_cert: cert,
  };
}

/**
 * A root-signed account-state document (compact `allw-account-state+jws`) that enrolls the actor
 * with `actorPubkey` and `status`, optionally also revoking it. Signed by the keyfile's account
 * root — the only key the device trusts to author account state. `docs/enrollment.md` §Account State.
 */
function signedAccountState(
  wasm,
  keyfile,
  { sequence = 1, actorPubkey, status = "active", revokeActor = false } = {},
) {
  const state = {
    v: 1,
    account_id: ACCOUNT_ID,
    sequence,
    current_root: keyfile.account_root_pubkey,
    previous_roots: [],
    devices: [],
    actors: [{ actor_id: ACTOR_ID, kind: ACTOR_KIND, pubkey: actorPubkey, status }],
    revocations: revokeActor
      ? [{ kind: "actor", id: ACTOR_ID, revoked_at: ISSUED_AT, reason: "test" }]
      : [],
  };
  return wasm.sign_account_state(JSON.stringify(state), keyfile.account_root_seed);
}

/** The default account-state set: one active document enrolling the REAL actor key. */
function enrolledStates(wasm, keyfile) {
  return [signedAccountState(wasm, keyfile, { actorPubkey: wasm.ed25519_public_key(ACTOR_SEED) })];
}

/**
 * Encrypt a context to the device key and prepare it (decrypt + recompute request_hash). The
 * attestation is signed over the SAME request_id + request_hash the device recomputes/holds,
 * binding it to this exact request. `requestId`/`attestSeed` are overridable to model lifted/forged
 * attestations.
 */
function prepareWithAttestation(
  wasm,
  keyfile,
  { signOverHash = true, attestSeed = ACTOR_SEED, requestId = REQUEST_ID } = {},
) {
  // request_hash is computed over a context with NO attestation (attestation is excluded from the
  // hash by design), so the bound hash matches what the device recomputes.
  const ctxNoAttest = baseContext(undefined);
  const requestHash = wasm.compute_request_hash(JSON.stringify(ctxNoAttest), EXPIRES_AT);

  const boundHash = signOverHash ? requestHash : Buffer.alloc(32, 0xcd).toString("base64url");
  const attestation = wasm.sign_actor_attestation(
    ACCOUNT_ID,
    ACTOR_ID,
    ACTOR_KIND,
    requestId,
    boundHash,
    attestSeed,
  );

  const ctx = baseContext(attestation);
  const jwe = wasm.encrypt_context(
    JSON.stringify(ctx),
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  return prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
}

function verify(wasm, keyfile, prepared, accountStates) {
  return verifyActorOrigin(
    wasm,
    prepared,
    ACCOUNT_ID,
    keyfile.account_root_pubkey,
    accountStates,
  );
}

// ── Verified origin: sign → root-anchor via account state → verify → render shows ✓ VERIFIED ──

test("verified origin: a root-anchored attestation renders ✓ VERIFIED", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  const prepared = prepareWithAttestation(wasm, keyfile);
  const origin = verify(wasm, keyfile, prepared, enrolledStates(wasm, keyfile));

  assert.equal(origin.verified, true, "the attestation verifies against the root-anchored actor key");
  // docs/contract.md §Identity & keys: "{kind} · {id}".
  assert.equal(origin.origin, "claude-code · machine:macbook-pro", "verified origin string");

  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /✓ VERIFIED origin — claude-code · machine:macbook-pro/, "shows VERIFIED");
  assert.doesNotMatch(rendered, /⚠ UNVERIFIED/, "a verified origin must not also show UNVERIFIED");
});

// ── THE BLOCKER: a relay/forged key that is NOT root-anchored cannot drive ✓ VERIFIED ─────────

test("forged origin: an attestation by a key NOT in root-signed account state renders ⚠ UNVERIFIED", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  // The attestation is signed by OTHER_SEED (a relay/attacker key). Account state enrolls only the
  // REAL key, so the forged signature cannot verify under the root-anchored key → unverified.
  const prepared = prepareWithAttestation(wasm, keyfile, { attestSeed: OTHER_SEED });
  const origin = verify(wasm, keyfile, prepared, enrolledStates(wasm, keyfile));

  assert.equal(origin.verified, false, "a non-root-anchored (forged) key must NOT verify");

  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /⚠ UNVERIFIED/, "a forged attestation renders UNVERIFIED");
  assert.doesNotMatch(rendered, /✓ VERIFIED/, "a forged attestation is never shown as verified");
});

test("relay key substitution: account state enrolling a DIFFERENT key renders ⚠ UNVERIFIED", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  // The attestation is correctly self-signed by the REAL actor key, but the (root-signed) account
  // state enrolls the OTHER key for this actor id — modeling a relay/account-state substitution that
  // does not match the real signing key. The signature cannot verify under the enrolled key.
  const prepared = prepareWithAttestation(wasm, keyfile);
  const substituted = [
    signedAccountState(wasm, keyfile, { actorPubkey: wasm.ed25519_public_key(OTHER_SEED) }),
  ];
  const origin = verify(wasm, keyfile, prepared, substituted);

  assert.equal(origin.verified, false, "an enrolled key that does not match the signature must fail");
  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /⚠ UNVERIFIED/, "a substituted key renders UNVERIFIED");
});

// ── No root-anchored trust available: never shown as verified ──────────────────────────────────

test("no account state: a correctly-signed attestation with no root anchor renders ⚠ UNVERIFIED", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  const prepared = prepareWithAttestation(wasm, keyfile);
  // No account-state documents → no root anchor → unverified (NOT an abort).
  const origin = verify(wasm, keyfile, prepared, []);

  assert.equal(origin.verified, false, "with no root-signed account state there is no trust anchor");
  assert.match(origin.reason, /root-signed account state/, "the reason names the missing anchor");

  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /⚠ UNVERIFIED/, "no account state renders UNVERIFIED");
});

// ── Revoked actor: never shown as verified (fail-closed) ────────────────────────────────────────

test("revoked actor: a root-signed revocation renders ⚠ UNVERIFIED even with a valid signature", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  const prepared = prepareWithAttestation(wasm, keyfile);
  // Highest-sequence account state revokes the actor → fail-closed, never verified.
  const states = [
    signedAccountState(wasm, keyfile, {
      sequence: 2,
      actorPubkey: wasm.ed25519_public_key(ACTOR_SEED),
      revokeActor: true,
    }),
  ];
  const origin = verify(wasm, keyfile, prepared, states);

  assert.equal(origin.verified, false, "a revoked actor must not be shown as verified");
  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /⚠ UNVERIFIED/, "a revoked actor renders UNVERIFIED");
});

// ── Wrong request_id binding (no-swap): never shown as verified ─────────────────────────────────

test("wrong request_id: an attestation bound to a different request_id renders ⚠ UNVERIFIED", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  // Correctly signed by the enrolled key over the SAME request_hash but a DIFFERENT request_id —
  // models a lift onto a content-identical sibling request. The request_id binding catches it.
  const prepared = prepareWithAttestation(wasm, keyfile, { requestId: OTHER_REQUEST_ID });
  const origin = verify(wasm, keyfile, prepared, enrolledStates(wasm, keyfile));

  assert.equal(origin.verified, false, "an attestation for another request_id must NOT verify");
  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /⚠ UNVERIFIED/, "a wrong-request_id attestation renders UNVERIFIED");
});

// ── Lifted request_hash: never shown as verified ───────────────────────────────────────────────

test("lifted origin: an attestation bound to a different request_hash renders ⚠ UNVERIFIED", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  // Correctly signed by the enrolled key, but over a DIFFERENT request_hash (a lifted attestation).
  const prepared = prepareWithAttestation(wasm, keyfile, { signOverHash: false });
  const origin = verify(wasm, keyfile, prepared, enrolledStates(wasm, keyfile));

  assert.equal(origin.verified, false, "an attestation bound to another request must NOT verify");
  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /⚠ UNVERIFIED/, "a lifted attestation renders UNVERIFIED");
});

// ── Spoofed actor id: signature for a DIFFERENT actor → unverified ─────────────────────────────

test("spoofed origin: an outer actor.id claiming a trusted id over another actor's signature", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  // Sign an attestation legitimately for "machine:attacker" (with the real key), but present an
  // outer actor claiming the TRUSTED id. The signed actor_id ≠ outer actor.id → ActorIdMismatch.
  const ctxNoAttest = baseContext(undefined);
  const requestHash = wasm.compute_request_hash(JSON.stringify(ctxNoAttest), EXPIRES_AT);
  const attestation = wasm.sign_actor_attestation(
    ACCOUNT_ID,
    "machine:attacker",
    ACTOR_KIND,
    REQUEST_ID,
    requestHash,
    ACTOR_SEED,
  );
  const ctx = baseContext(attestation); // outer actor.id is the trusted ACTOR_ID
  const jwe = wasm.encrypt_context(
    JSON.stringify(ctx),
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const origin = verify(wasm, keyfile, prepared, enrolledStates(wasm, keyfile));

  assert.equal(origin.verified, false, "a spoofed outer actor.id must NOT verify");
  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /⚠ UNVERIFIED/, "a spoofed origin renders UNVERIFIED");
  assert.doesNotMatch(rendered, /✓ VERIFIED/, "a spoofed origin is never shown as verified");
});

// ── Absent attestation: never shown as verified ───────────────────────────────────────────────

test("absent attestation: an actor with no attestation renders ⚠ UNVERIFIED", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  // Context with NO attestation field at all.
  const ctx = baseContext(undefined);
  const jwe = wasm.encrypt_context(
    JSON.stringify(ctx),
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);

  const origin = verify(wasm, keyfile, prepared, enrolledStates(wasm, keyfile));
  assert.equal(origin.verified, false, "an absent attestation is unverified");
  assert.match(origin.reason, /no attestation present/, "the reason names the absent attestation");

  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /⚠ UNVERIFIED/, "an absent attestation renders UNVERIFIED");
});

// ── Tampered account state: a doc not signed by the trusted root is rejected (fail-closed) ─────

test("tampered account state: a doc signed by a non-root key renders ⚠ UNVERIFIED", async () => {
  const wasm = await loadWasm();
  const keyfile = pairedApprover(wasm);

  const prepared = prepareWithAttestation(wasm, keyfile);
  // Sign the account-state doc with the WRONG key (an attacker, not the configured account root) —
  // and declare its current_root as that attacker key so it is internally consistent but untrusted.
  const attackerPub = wasm.ed25519_public_key(OTHER_SEED);
  const forgedState = {
    v: 1,
    account_id: ACCOUNT_ID,
    sequence: 1,
    current_root: attackerPub,
    previous_roots: [],
    devices: [],
    actors: [
      {
        actor_id: ACTOR_ID,
        kind: ACTOR_KIND,
        pubkey: wasm.ed25519_public_key(ACTOR_SEED),
        status: "active",
      },
    ],
    revocations: [],
  };
  const forgedJws = wasm.sign_account_state(JSON.stringify(forgedState), OTHER_SEED);
  const origin = verify(wasm, keyfile, prepared, [forgedJws]);

  assert.equal(origin.verified, false, "an account-state doc not signed by the trusted root must fail");
  const rendered = renderRequest({ ...prepared, origin });
  assert.match(rendered, /⚠ UNVERIFIED/, "a tampered account-state doc renders UNVERIFIED");
});
