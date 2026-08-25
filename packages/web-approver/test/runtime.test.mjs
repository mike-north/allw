/**
 * Integration tests for the browser {@link createWasmRuntime} against the **real WASM core** (no
 * crypto mocks). This wires the `WebApproverRuntime` seam (#146) to `@allw/sdk`'s vendored core and
 * proves the parent epic's acceptance (#93) at the runtime layer:
 *
 *   - a valid relay envelope **decrypts → recomputes the WYSIWYS request_hash → is signable**, and
 *     the signed verdict **verifies** under the approver account root (the full requester↔approver
 *     round-trip);
 *   - the negatives each **fail closed**: an already-expired request, a tampered context (hash
 *     mismatch → the verdict cannot verify against the integrator's original), a denied verdict
 *     (a verified human "no", surfaced as a thrown verify error), and a revoked signing device
 *     (rejected by the revocation-aware verifier).
 *
 * Every cryptographic step goes through the audited core; the runtime only orchestrates JSON
 * (thin-shell, `docs/architecture.md`). All timestamps are fixed constants — never `Date.now()` in
 * test data (`docs/contract.md` §Wire encoding binds the hash to `expires_at`).
 *
 * @see ../src/runtime.ts (the unit under test)
 * @see ../../approver/test/approver-core.test.mjs (the device-side round-trip this mirrors)
 * @see ../../../docs/contract.md §Lifecycle, §Messages, §Verification checklist, §Invariants #6
 * @see ../../../docs/enrollment.md §Account State (revocation)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { actionSummary, createWasmRuntime, exactPlaintext } from "../dist/index.js";
import { loadTestWasm } from "./wasm-helper.mjs";

// ── Deterministic fixtures (fixed timestamps; never Date.now() in test data) ──────────────────

const ACCOUNT_ID = "acct-web-runtime-test";
const DEVICE_ID = "dev-web-runtime-test";
const REQUEST_ID = "req-web-runtime-test-1";
/** 2023-11-14T22:13:20Z — cert issuance. */
const ISSUED_AT = 1700000000000;
/** 2023-11-14T23:13:20Z — request deadline (bound into request_hash). */
const EXPIRES_AT = 1700003600000;
/** 2023-11-14T22:38:20Z — the runtime/verifier "now" (decision time and verify window). */
const NOW_MS = 1700001500000;

/**
 * The canonical human-shown context, built by hand from `docs/contract.md` §Messages →
 * ApprovalContext (NOT captured from program output).
 */
const CONTEXT = {
  action: {
    record_schema_version: 1,
    surface: "command",
    syntactic: { bin: "git", argv: ["git", "push", "--force", "origin", "main"], cwd: "/repo" },
    risk: "high",
  },
  summary: "force push to main",
  actor: { id: "machine:laptop", kind: "claude-code" },
  risk: "high",
  reversible: false,
  constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
};
const CONTEXT_JSON = JSON.stringify(CONTEXT);

/** The relay-visible envelope (web-approver `ApprovalEnvelope` shape) the runtime consumes. */
function makeEnvelope(contextCiphertext, overrides = {}) {
  return {
    v: 1,
    id: overrides.id ?? REQUEST_ID,
    created_at: ISSUED_AT,
    expires_at: overrides.expires_at ?? EXPIRES_AT,
    approver: ACCOUNT_ID,
    context_ciphertext: contextCiphertext,
  };
}

/** The integrator-side ApprovalRequest JSON (no ciphertext) passed to verify_verdict. */
function makeRequestJson() {
  return JSON.stringify({
    v: 1,
    id: REQUEST_ID,
    created_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    approver: ACCOUNT_ID,
  });
}

/**
 * Build a fully-paired browser approver identity: a fresh set of seeds whose account-root certifies
 * the device signing key. Returns `{ identity, accountRootSeed, encryptTo }` where `encryptTo`
 * encrypts a context JSON to this device's X25519 key (the integrator's encrypt step).
 */
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

  return { identity, accountRootSeed, deviceSigningPubkey, deviceEncryptionPubkey, encryptTo };
}

/** A fixed-clock runtime so device-side fail-closed expiry and `decided_at` are deterministic. */
function runtimeAt(wasm, identity, now = NOW_MS, extra = {}) {
  return createWasmRuntime({ wasm, identity, nowMs: () => now, ...extra });
}

// ── Happy path: decrypt → recompute hash → sign → verify (the #93 e2e at this layer) ──────────

test("valid envelope: prepare decrypts + recomputes the WYSIWYS hash; the signed verdict verifies", async () => {
  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);
  const runtime = runtimeAt(wasm, identity);

  const prepared = await runtime.prepare(makeEnvelope(encryptTo(CONTEXT_JSON)));

  // (a) The recomputed WYSIWYS hash equals the integrator's pre-send hash (WYSIWYS, no separate digest).
  const integratorHash = wasm.compute_request_hash(CONTEXT_JSON, EXPIRES_AT);
  assert.equal(
    prepared.requestHash,
    integratorHash,
    "device hash must equal the integrator's hash",
  );
  assert.equal(
    prepared.expiresAt,
    EXPIRES_AT,
    "the core-verified expiry is the hash-bound deadline",
  );
  assert.equal(prepared.context.kind, "command", "the command surface maps to a command context");
  assert.deepEqual(
    prepared.context.command?.argv,
    ["git", "push", "--force", "origin", "main"],
    "the decrypted argv round-trips into the view model",
  );
  assert.equal(prepared.context.risk.level, "high", "the risk tier round-trips");
  // No attestation + no account states ⇒ origin renders unverified (fail-closed display, #16).
  assert.equal(prepared.context.actor.attestation, "unverified");

  // (b) Sign an approval and verify it against the ACCOUNT-ROOT pubkey (id + request_hash, no swap).
  const verdict = await runtime.signDecision({
    envelope: makeEnvelope(""),
    prepared,
    decision: "approved",
  });
  assert.equal(verdict.decision, "approved");
  assert.equal(verdict.requestId, REQUEST_ID, "the verdict binds to the request id");

  const result = JSON.parse(
    wasm.verify_verdict(
      verdict.signedVerdictJson,
      makeRequestJson(),
      CONTEXT_JSON,
      identity.accountRootPubkey,
      NOW_MS,
    ),
  );
  assert.equal(result.approved, true, "the runtime's verdict verifies under the account root");
  assert.equal(result.device_id, DEVICE_ID, "verified device_id matches the paired device");
  assert.equal(result.decided_at, NOW_MS, "verified decided_at echoes the runtime clock");
});

test("agent_tool_call surface: maps to its own kind, distinct from mcp, with (server,tool) shown explicitly (Refs #217)", async () => {
  // An OpenClaw plugin permission request (docs/openclaw-integration.md §5.2) reuses the
  // (server, tool) wire shape from mcp_tool_call, but `server` holds a plugin id — folding it into
  // "mcp" would tell the human a false origin and, worse, the generic "command" fallback only
  // reads argv/cwd/raw, so the hash-bound function identity would be entirely absent from the
  // rendered plaintext even though it is inside request_hash.
  const AGENT_TOOL_CALL_CONTEXT = {
    action: {
      record_schema_version: 1,
      surface: "agent_tool_call",
      syntactic: {
        server: "deploy-plugin",
        tool: "deploy_service",
        raw: "This plugin wants to deploy to production.",
      },
      risk: "medium",
    },
    summary:
      "OpenClaw home-mini · agent agent-main · deploy-plugin/deploy_service: Deploy — deploy now",
    actor: { id: "openclaw:home-mini", kind: "openclaw" },
    risk: "medium",
    reversible: true,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const contextJson = JSON.stringify(AGENT_TOOL_CALL_CONTEXT);

  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);
  const runtime = runtimeAt(wasm, identity);

  const prepared = await runtime.prepare(makeEnvelope(encryptTo(contextJson)));

  assert.equal(
    prepared.context.kind,
    "agent_tool_call",
    "the agent_tool_call surface must map to its own kind, not 'mcp'",
  );
  assert.equal(prepared.context.mcp, undefined, "must not also populate the mcp action");
  assert.deepEqual(prepared.context.agentToolCall, {
    server: "deploy-plugin",
    tool: "deploy_service",
    params: undefined,
  });

  assert.equal(actionSummary(prepared.context), "deploy-plugin.deploy_service");
  assert.match(
    exactPlaintext(prepared.context),
    /^agent_tool_call: deploy-plugin\.deploy_service/,
    "the exact plaintext explicitly shows the (server, tool) identity under its own label",
  );
});

// ── Negative: already-expired request fails closed in prepare ────────────────────────────────

test("expired request: prepare refuses a dead request before any decrypt (device-side fail-closed)", async () => {
  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);
  const jwe = encryptTo(CONTEXT_JSON);

  // now == expires_at: at-or-past the deadline must be refused (boundary is inclusive: <=).
  const atDeadline = runtimeAt(wasm, identity, EXPIRES_AT);
  await assert.rejects(() => atDeadline.prepare(makeEnvelope(jwe)), /expired/);

  // well past the deadline: also refused.
  const pastDeadline = runtimeAt(wasm, identity, EXPIRES_AT + 60_000);
  await assert.rejects(() => pastDeadline.prepare(makeEnvelope(jwe)), /expired/);

  // one ms before the deadline is still live.
  const live = runtimeAt(wasm, identity, EXPIRES_AT - 1);
  const prepared = await live.prepare(makeEnvelope(jwe));
  assert.equal(prepared.requestHash, wasm.compute_request_hash(CONTEXT_JSON, EXPIRES_AT));
});

// ── Negative: tampered context (hash mismatch → blocked) ─────────────────────────────────────

test("tampered context: a mutated plaintext recomputes a different hash; the verdict cannot verify", async () => {
  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);
  const runtime = runtimeAt(wasm, identity);

  // The human-shown context the device decrypts differs from what the integrator hashed pre-send
  // (the argv was swapped to a benign command). The device recomputes the hash over the bytes it
  // actually saw — which must NOT equal the integrator's hash of the ORIGINAL context.
  const tamperedContext = {
    ...CONTEXT,
    summary: "innocuous: list files",
    action: { ...CONTEXT.action, syntactic: { bin: "ls", argv: ["ls", "-la"], cwd: "/repo" } },
  };
  const prepared = await runtime.prepare(makeEnvelope(encryptTo(JSON.stringify(tamperedContext))));

  const integratorHashOriginal = wasm.compute_request_hash(CONTEXT_JSON, EXPIRES_AT);
  assert.notEqual(
    prepared.requestHash,
    integratorHashOriginal,
    "a tampered context must produce a DIFFERENT request_hash than the integrator's original",
  );

  // A verdict signed over the tampered hash fails verify_verdict when the integrator verifies
  // against the ORIGINAL context it holds — the WYSIWYS binding catches the swap, fail-closed e2e.
  const verdict = await runtime.signDecision({
    envelope: makeEnvelope(""),
    prepared,
    decision: "approved",
  });
  assert.throws(
    () =>
      wasm.verify_verdict(
        verdict.signedVerdictJson,
        makeRequestJson(),
        CONTEXT_JSON, // integrator's ORIGINAL context
        identity.accountRootPubkey,
        NOW_MS,
      ),
    /verify_verdict failed/,
    "a verdict bound to a tampered context must not verify against the integrator's original",
  );
});

test("undecryptable context: a JWE the device key cannot open fails closed in prepare", async () => {
  const wasm = await loadTestWasm();
  const { identity } = pairedIdentity(wasm);
  const runtime = runtimeAt(wasm, identity);

  // Structurally-invalid JWE: the device key cannot decrypt it; prepare must throw so the controller
  // renders it unverified (deny-only), never approvable.
  await assert.rejects(
    () => runtime.prepare(makeEnvelope("eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.NOT-A-REAL.JWE")),
    /decrypt/i,
  );
});

test("missing ciphertext: a malformed envelope is rejected before any crypto", async () => {
  const wasm = await loadTestWasm();
  const { identity } = pairedIdentity(wasm);
  const runtime = runtimeAt(wasm, identity);

  const envelope = makeEnvelope("placeholder");
  delete envelope.context_ciphertext;
  await assert.rejects(() => runtime.prepare(envelope), /context_ciphertext/);
});

// ── Negative: denied verdict is a verified "no" (verify throws, fail-closed) ──────────────────

test("denied verdict: a signed denial verifies as a verified non-approval (verify_verdict throws)", async () => {
  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);
  const runtime = runtimeAt(wasm, identity);

  const prepared = await runtime.prepare(makeEnvelope(encryptTo(CONTEXT_JSON)));
  const verdict = await runtime.signDecision({
    envelope: makeEnvelope(""),
    prepared,
    decision: "denied",
  });
  assert.equal(verdict.decision, "denied", "the signed verdict carries the denied decision");

  // A VERIFIED non-approval surfaces as a thrown error (deny-by-default), not `approved: false` —
  // the throw proves the denial is authentic (signature + binding checked out; decision was 'denied').
  assert.throws(
    () =>
      wasm.verify_verdict(
        verdict.signedVerdictJson,
        makeRequestJson(),
        CONTEXT_JSON,
        identity.accountRootPubkey,
        NOW_MS,
      ),
    /verified human decision was not 'approved'/,
    "a verified denial surfaces as a thrown error (deny-by-default), not a falsy result",
  );
});

// ── Negative: revoked signing device → revocation-aware verify rejects the verdict ────────────

test("revoked device: a verdict from a revoked signing device is rejected by the verifier", async () => {
  const wasm = await loadTestWasm();
  const { identity, accountRootSeed, deviceSigningPubkey, deviceEncryptionPubkey, encryptTo } =
    pairedIdentity(wasm);
  const runtime = runtimeAt(wasm, identity);

  const prepared = await runtime.prepare(makeEnvelope(encryptTo(CONTEXT_JSON)));
  const verdict = await runtime.signDecision({
    envelope: makeEnvelope(""),
    prepared,
    decision: "approved",
  });

  // Sanity: without revocation context, the approval verifies (the device is still trusted).
  const okStateJson = JSON.stringify({
    v: 1,
    account_id: ACCOUNT_ID,
    sequence: 1,
    current_root: identity.accountRootPubkey,
    previous_roots: [],
    devices: [
      {
        device_id: DEVICE_ID,
        encryption_pubkey: deviceEncryptionPubkey,
        signing_pubkey: deviceSigningPubkey,
        status: "active",
      },
    ],
    actors: [],
    revocations: [],
  });
  const okState = wasm.sign_account_state(okStateJson, accountRootSeed);
  const okResult = JSON.parse(
    wasm.verify_verdict_with_account_states(
      verdict.signedVerdictJson,
      makeRequestJson(),
      CONTEXT_JSON,
      identity.accountRootPubkey,
      NOW_MS,
      JSON.stringify([okState]),
    ),
  );
  assert.equal(okResult.approved, true, "an un-revoked device's approval verifies");

  // Now revoke the signing device in a higher-sequence root-signed account state. The same verdict
  // must be rejected by the revocation-aware verifier — fail-closed (`docs/enrollment.md`).
  const revokedStateJson = JSON.stringify({
    v: 1,
    account_id: ACCOUNT_ID,
    sequence: 2,
    current_root: identity.accountRootPubkey,
    previous_roots: [],
    devices: [
      {
        device_id: DEVICE_ID,
        encryption_pubkey: deviceEncryptionPubkey,
        signing_pubkey: deviceSigningPubkey,
        status: "revoked",
      },
    ],
    actors: [],
    revocations: [{ kind: "device", id: DEVICE_ID, revoked_at: ISSUED_AT, reason: "test" }],
  });
  const revokedState = wasm.sign_account_state(revokedStateJson, accountRootSeed);
  assert.throws(
    () =>
      wasm.verify_verdict_with_account_states(
        verdict.signedVerdictJson,
        makeRequestJson(),
        CONTEXT_JSON,
        identity.accountRootPubkey,
        NOW_MS,
        JSON.stringify([revokedState]),
      ),
    /revoked/,
    "a verdict signed by a revoked device must not verify (fail-closed revocation)",
  );
});

// ── Number-match challenge: derived code gates signing ────────────────────────────────────────

test("number-match: prepare derives the code through the core and signDecision gates on it", async () => {
  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);
  const runtime = runtimeAt(wasm, identity);

  const challengedContext = {
    ...CONTEXT,
    constraints: { ...CONTEXT.constraints, challenge_required: true },
  };
  const challengedJson = JSON.stringify(challengedContext);
  const prepared = await runtime.prepare(makeEnvelope(encryptTo(challengedJson)));

  const expectedCode = wasm.derive_number_match_challenge(prepared.requestHash);
  assert.equal(prepared.context.challenge?.kind, "number-match");
  assert.equal(
    prepared.context.challenge?.code,
    expectedCode,
    "prepare derives the display challenge through the WASM core",
  );

  // Approving without the code is refused before signing (fail-closed).
  await assert.rejects(
    () => runtime.signDecision({ envelope: makeEnvelope(""), prepared, decision: "approved" }),
    /number-match challenge response/,
  );
  // An incorrect code is refused before signing.
  await assert.rejects(
    () =>
      runtime.signDecision({
        envelope: makeEnvelope(""),
        prepared,
        decision: "approved",
        challengeResponse: expectedCode === "0000" ? "0001" : "0000",
      }),
    /does not match the derived number-match code/,
  );

  // The matching code signs a verdict that verifies and carries the challenge response.
  const verdict = await runtime.signDecision({
    envelope: makeEnvelope(""),
    prepared,
    decision: "approved",
    challengeResponse: expectedCode,
  });
  const result = JSON.parse(
    wasm.verify_verdict(
      verdict.signedVerdictJson,
      makeRequestJson(),
      challengedJson,
      identity.accountRootPubkey,
      NOW_MS,
    ),
  );
  assert.equal(result.approved, true, "the challenged approval verifies under the core");
});

// ── Verified origin: a root-anchored attestation renders the actor as verified ────────────────

test("verified origin: a root-anchored actor attestation renders attestation = verified (#16)", async () => {
  const wasm = await loadTestWasm();
  const { identity, accountRootSeed, encryptTo } = pairedIdentity(wasm);

  const actorSeed = Buffer.alloc(32, 0x44).toString("base64url");
  const actorPubkey = wasm.ed25519_public_key(actorSeed);

  // The attestation binds to the request_id + the hash of the context WITHOUT the attestation field
  // (attestation is excluded from request_hash by design), so the device's recomputed hash matches.
  const requestHash = wasm.compute_request_hash(CONTEXT_JSON, EXPIRES_AT);
  const attestation = wasm.sign_actor_attestation(
    ACCOUNT_ID,
    CONTEXT.actor.id,
    CONTEXT.actor.kind,
    REQUEST_ID,
    requestHash,
    actorSeed,
  );
  const attestedContext = {
    ...CONTEXT,
    actor: { ...CONTEXT.actor, attestation },
  };

  const accountStateJson = JSON.stringify({
    v: 1,
    account_id: ACCOUNT_ID,
    sequence: 1,
    current_root: identity.accountRootPubkey,
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
  const accountState = wasm.sign_account_state(accountStateJson, accountRootSeed);

  const runtime = runtimeAt(wasm, identity, NOW_MS, {
    resolveAccountStates: () => Promise.resolve([accountState]),
  });
  const prepared = await runtime.prepare(makeEnvelope(encryptTo(JSON.stringify(attestedContext))));

  assert.equal(
    prepared.context.actor.attestation,
    "verified",
    "a root-anchored attestation renders the actor origin as verified",
  );

  // Fail-closed display: a resolver outage downgrades to unverified rather than aborting.
  const failing = runtimeAt(wasm, identity, NOW_MS, {
    resolveAccountStates: () => Promise.reject(new Error("relay down")),
  });
  const downgraded = await failing.prepare(
    makeEnvelope(encryptTo(JSON.stringify(attestedContext))),
  );
  assert.equal(
    downgraded.context.actor.attestation,
    "unverified",
    "an account-state resolver failure downgrades the origin to unverified (never aborts)",
  );
});
