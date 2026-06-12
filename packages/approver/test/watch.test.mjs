/**
 * Watch-loop / relay-protocol tests for the v0 stand-in approver (issue #41).
 *
 * Drives `handleRequest` (the per-request half of `watch`) against a stub WebSocket and a stub
 * prompter, with the **real WASM core** for crypto. Verifies the device→relay protocol
 * (`docs/contract.md` §Transport → Device socket): on Approve/Deny the approver emits a
 * `{ type: "verdict", request_id, verdict }` whose verdict verifies against the account root; on
 * Skip / undecryptable input it emits NOTHING (fail-closed — the integrator's gate stays closed).
 *
 * @see ../../../docs/contract.md §Transport, §Lifecycle, §Invariants #6 (fail-closed)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadWasm } from "../dist/index.js";
import { generateKeyfile, writeKeyfile } from "../dist/lib/keyfile.js";
import { handleRequest, runWatch } from "../dist/commands/watch.js";

const ACCOUNT_ID = "acct-watch-test";
const DEVICE_ID = "dev-watch-test";
const REQUEST_ID = "req-watch-1";
const ISSUED_AT = 1700000000000;
const EXPIRES_AT = 1700003600000;
const DECIDED_AT = 1700001000000;
const NOW_MS = 1700001500000;

const CONTEXT = {
  action: {
    record_schema_version: 1,
    surface: "command",
    syntactic: { bin: "rm", argv: ["rm", "-rf", "build"] },
    risk: "medium",
  },
  summary: "delete the build directory",
  actor: { id: "machine:ci", kind: "claude-code" },
  risk: "medium",
  reversible: true,
  constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
};
const CONTEXT_JSON = JSON.stringify(CONTEXT);

function pairedApprover(wasm) {
  const fresh = generateKeyfile(wasm);
  const cert = wasm.issue_device_cert(
    fresh.account_root_seed,
    ACCOUNT_ID,
    DEVICE_ID,
    fresh.device_signing_pubkey,
    ISSUED_AT,
  );
  const keyfile = {
    ...fresh,
    relay_url: "https://relay.allw.test",
    account_id: ACCOUNT_ID,
    device_id: DEVICE_ID,
    device_cert: cert,
  };
  const jwe = wasm.encrypt_context(
    CONTEXT_JSON,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: fresh.device_encryption_pubkey }]),
  );
  return { keyfile, jwe };
}

function makeEnvelope(jwe) {
  return {
    v: 1,
    id: REQUEST_ID,
    created_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    approver: ACCOUNT_ID,
    context_ciphertext: jwe,
  };
}

/** A stub WebSocket capturing every `send`. */
function stubSocket() {
  const sent = [];
  return {
    sent,
    send(data) {
      sent.push(JSON.parse(data));
    },
    close() {},
  };
}

/** A stub prompter that always returns the configured decision. */
function fixedPrompter(decision) {
  return {
    decide() {
      return Promise.resolve(decision);
    },
  };
}

/** A no-op logger that records lines for assertions. */
function recordingLogger() {
  const info = [];
  const warn = [];
  return { info: (l) => info.push(l), warn: (l) => warn.push(l), _info: info, _warn: warn };
}

/** A minimal socket that opens and closes after runWatch attaches its event listeners. */
function selfClosingSocket() {
  const listeners = { open: [], message: [], error: [], close: [] };
  const emit = (type) => {
    for (const listener of listeners[type]) listener({});
  };
  queueMicrotask(() => {
    emit("open");
    emit("close");
  });
  return {
    addEventListener(type, listener) {
      listeners[type].push(listener);
    },
    send() {},
    close() {
      emit("close");
    },
  };
}

test("runWatch logs a redacted device presence URL while connecting with the auth token", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);
  const dir = mkdtempSync(join(tmpdir(), "allw-watch-"));
  try {
    const keyfilePath = join(dir, "keyfile.json");
    const pairedKeyfile = { ...keyfile, device_auth_token: "device-secret-token" };
    writeKeyfile(keyfilePath, pairedKeyfile);

    const log = recordingLogger();
    let connectedUrl = "";
    await runWatch(
      wasm,
      { keyfilePath },
      {
        connect(url) {
          connectedUrl = url;
          return selfClosingSocket();
        },
        prompter: { decide: () => Promise.resolve(null) },
        log,
      },
    );

    assert.match(connectedUrl, /\?auth=device-secret-token$/, "the socket uses the real token URL");
    assert.ok(
      log._info.some((line) => line.startsWith("Connecting to ")),
      "the connection attempt is still logged",
    );
    assert.equal(
      log._info.some((line) => line.includes("device-secret-token") || line.includes("?auth=")),
      false,
      "logs must not expose the device bearer token or auth query string",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Approve → emits a verdict message whose verdict verifies against the account root", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const ws = stubSocket();
  const log = recordingLogger();

  const decision = await handleRequest(
    wasm,
    keyfile,
    ws,
    fixedPrompter("approved"),
    makeEnvelope(jwe),
    log,
    () => DECIDED_AT,
  );

  assert.equal(decision, "approved");
  assert.equal(ws.sent.length, 1, "exactly one verdict message is sent");
  const msg = ws.sent[0];
  assert.equal(msg.type, "verdict");
  assert.equal(msg.request_id, REQUEST_ID, "the verdict message targets the request id");

  // The emitted verdict must verify end-to-end against the account-root pubkey.
  const requestJson = JSON.stringify({
    v: 1,
    id: REQUEST_ID,
    created_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    approver: ACCOUNT_ID,
  });
  const result = JSON.parse(
    wasm.verify_verdict(
      JSON.stringify(msg.verdict),
      requestJson,
      CONTEXT_JSON,
      keyfile.account_root_pubkey,
      NOW_MS,
    ),
  );
  assert.equal(result.approved, true, "the emitted verdict verifies as approved");
  assert.equal(result.device_id, DEVICE_ID);
});

test("Deny → emits a denied verdict (a verified 'no'; verify_verdict throws)", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const ws = stubSocket();

  const decision = await handleRequest(
    wasm,
    keyfile,
    ws,
    fixedPrompter("denied"),
    makeEnvelope(jwe),
    recordingLogger(),
    () => DECIDED_AT,
  );

  assert.equal(decision, "denied");
  assert.equal(
    ws.sent.length,
    1,
    "a denied verdict is still emitted (the integrator gates closed)",
  );
  assert.equal(ws.sent[0].verdict.decision, "denied");

  // A verified denial throws (fail-closed surface) — proving authenticity, not a forgery.
  assert.throws(
    () =>
      wasm.verify_verdict(
        JSON.stringify(ws.sent[0].verdict),
        JSON.stringify({
          v: 1,
          id: REQUEST_ID,
          created_at: ISSUED_AT,
          expires_at: EXPIRES_AT,
          approver: ACCOUNT_ID,
        }),
        CONTEXT_JSON,
        keyfile.account_root_pubkey,
        NOW_MS,
      ),
    /verify_verdict failed/,
  );
});

test("Skip (no decision) → emits NO verdict (fail-closed: gate stays closed)", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const ws = stubSocket();

  const decision = await handleRequest(
    wasm,
    keyfile,
    ws,
    fixedPrompter(null), // null = skip / no decision
    makeEnvelope(jwe),
    recordingLogger(),
    () => DECIDED_AT,
  );

  assert.equal(decision, null);
  assert.equal(ws.sent.length, 0, "no verdict is sent when the human makes no decision");
});

test("fail-closed: an undecryptable request is skipped, emits no verdict, and is NOT prompted", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);
  const ws = stubSocket();
  const log = recordingLogger();
  let prompted = false;
  const prompter = {
    decide() {
      prompted = true;
      return Promise.resolve("approved");
    },
  };

  const envelope = makeEnvelope("eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.NOT-REAL.JWE");
  const decision = await handleRequest(
    wasm,
    keyfile,
    ws,
    prompter,
    envelope,
    log,
    () => DECIDED_AT,
  );

  assert.equal(decision, null, "an undecryptable request yields no decision");
  assert.equal(ws.sent.length, 0, "no verdict is emitted for a request that cannot be decrypted");
  assert.equal(prompted, false, "the human is never prompted for an undecryptable request");
  assert.ok(
    log._warn.some((l) => /could not decrypt/i.test(l)),
    "the skip is reported to the user",
  );
});

// ── Device-side fail-closed expiry in the watch loop (review fix #2) ──────────────────────────

test("fail-closed: an already-expired request emits no verdict and is NOT prompted", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const ws = stubSocket();
  const log = recordingLogger();
  let prompted = false;
  const prompter = {
    decide() {
      prompted = true;
      return Promise.resolve("approved");
    },
  };

  // Seeded clock already past the deadline → prepareRequest refuses before any prompt (no Date.now).
  const decision = await handleRequest(
    wasm,
    keyfile,
    ws,
    prompter,
    makeEnvelope(jwe),
    log,
    () => EXPIRES_AT + 1,
  );

  assert.equal(decision, null, "an expired request yields no decision");
  assert.equal(ws.sent.length, 0, "no verdict is emitted for an expired request");
  assert.equal(prompted, false, "the human is never prompted for an already-expired request");
});

test("fail-closed: a request that expires WHILE the human deliberates emits no verdict", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const ws = stubSocket();
  const log = recordingLogger();

  // Stateful seeded clock: the FIRST read (prepareRequest) is before the deadline so the request is
  // rendered + prompted; the prompt then "takes a long time" and every subsequent read (the
  // post-decision re-check, and signing) is AFTER the deadline. The approver must discard it.
  let firstRead = true;
  const now = () => {
    if (firstRead) {
      firstRead = false;
      return EXPIRES_AT - 1000; // live at arrival
    }
    return EXPIRES_AT + 1000; // expired by the time the human answered
  };

  let prompted = false;
  const prompter = {
    decide() {
      prompted = true;
      return Promise.resolve("approved"); // the human DID approve — but too late
    },
  };

  const decision = await handleRequest(wasm, keyfile, ws, prompter, makeEnvelope(jwe), log, now);

  assert.equal(prompted, true, "the human was prompted (it was live when it arrived)");
  assert.equal(decision, null, "a request that expired during the prompt yields no decision");
  assert.equal(
    ws.sent.length,
    0,
    "no stale-but-signed approval is emitted once the deadline passes mid-prompt",
  );
  assert.ok(
    log._warn.some((l) => /expired while awaiting a decision/i.test(l)),
    "the post-decision expiry is reported (fail-closed)",
  );
});

// ── Verified request origin in the watch loop (#16) ───────────────────────────────────────────

/** A capturing prompter that records the rendered block and returns a fixed decision. */
function capturingPrompter(decision) {
  const renders = [];
  return {
    renders,
    decide(rendered) {
      renders.push(rendered);
      return Promise.resolve(decision);
    },
  };
}

/** Build a paired approver whose decrypted context carries a correctly-signed actor attestation. */
function pairedApproverWithAttestation(wasm, { actorSeed }) {
  const fresh = generateKeyfile(wasm);
  const cert = wasm.issue_device_cert(
    fresh.account_root_seed,
    ACCOUNT_ID,
    DEVICE_ID,
    fresh.device_signing_pubkey,
    ISSUED_AT,
  );
  const keyfile = {
    ...fresh,
    relay_url: "https://relay.allw.test",
    account_id: ACCOUNT_ID,
    device_id: DEVICE_ID,
    device_cert: cert,
  };
  // The attestation binds to the request_id + request_hash of the attestation-free context
  // (attestation is excluded from request_hash), so the device's recomputed hash matches what was
  // signed.
  const requestHash = wasm.compute_request_hash(CONTEXT_JSON, EXPIRES_AT);
  const attestation = wasm.sign_actor_attestation(
    ACCOUNT_ID,
    CONTEXT.actor.id,
    CONTEXT.actor.kind,
    REQUEST_ID,
    requestHash,
    actorSeed,
  );
  const attestedContext = { ...CONTEXT, actor: { ...CONTEXT.actor, attestation } };
  const jwe = wasm.encrypt_context(
    JSON.stringify(attestedContext),
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: fresh.device_encryption_pubkey }]),
  );
  return { keyfile, jwe };
}

/**
 * A root-signed account-state document enrolling `actorId` with `actorPubkey`, signed by the
 * keyfile's account root. This is the device's root-anchored trust input (#16); a relay-supplied
 * key is never trusted. `docs/enrollment.md` §Account State.
 */
function signedAccountState(wasm, keyfile, actorPubkey) {
  const state = {
    v: 1,
    account_id: ACCOUNT_ID,
    sequence: 1,
    current_root: keyfile.account_root_pubkey,
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
  };
  return wasm.sign_account_state(JSON.stringify(state), keyfile.account_root_seed);
}

test("verified origin: a root-anchored key renders ✓ VERIFIED in the watch loop (#16)", async () => {
  const wasm = await loadWasm();
  const actorSeed = Buffer.alloc(32, 0x44).toString("base64url");
  const actorPub = wasm.ed25519_public_key(actorSeed);
  const { keyfile, jwe } = pairedApproverWithAttestation(wasm, { actorSeed });
  const ws = stubSocket();
  const prompter = capturingPrompter("approved");

  // The resolver returns a root-signed account-state document enrolling the real actor key. A
  // relay-supplied key would NOT be trusted here — only this root-signed material can drive VERIFIED.
  const accountStates = [signedAccountState(wasm, keyfile, actorPub)];
  const resolveAccountStates = () => Promise.resolve(accountStates);

  await handleRequest(
    wasm,
    keyfile,
    ws,
    prompter,
    makeEnvelope(jwe),
    recordingLogger(),
    () => DECIDED_AT,
    resolveAccountStates,
  );

  assert.equal(prompter.renders.length, 1, "the human was prompted with a rendered block");
  assert.match(
    prompter.renders[0],
    /✓ VERIFIED origin — claude-code · machine:ci/,
    "the rendered block shows the cryptographically-verified, root-anchored origin",
  );
});

test("origin fail-closed: a resolver error still renders the request as ⚠ UNVERIFIED (#16)", async () => {
  const wasm = await loadWasm();
  const actorSeed = Buffer.alloc(32, 0x44).toString("base64url");
  const { keyfile, jwe } = pairedApproverWithAttestation(wasm, { actorSeed });
  const ws = stubSocket();
  const prompter = capturingPrompter("approved");
  const log = recordingLogger();

  // A relay outage while resolving the root-signed account state must NOT abort the request — the
  // human still sees the action, with the origin explicitly marked unverified (fail-closed display).
  const resolveAccountStates = () => Promise.reject(new Error("relay account-state → HTTP 503"));

  const decision = await handleRequest(
    wasm,
    keyfile,
    ws,
    prompter,
    makeEnvelope(jwe),
    log,
    () => DECIDED_AT,
    resolveAccountStates,
  );

  assert.equal(
    decision,
    "approved",
    "the request is still decided despite the origin-lookup error",
  );
  assert.equal(prompter.renders.length, 1, "the human was still prompted");
  assert.match(
    prompter.renders[0],
    /⚠ UNVERIFIED/,
    "the origin is shown unverified on lookup error",
  );
  assert.ok(
    log._warn.some((l) => /could not resolve account state/i.test(l)),
    "the resolver error is reported (origin downgraded, not aborted)",
  );
});
