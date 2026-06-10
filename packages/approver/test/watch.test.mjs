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

import { loadWasm } from "../dist/index.js";
import { generateKeyfile } from "../dist/lib/keyfile.js";
import { handleRequest } from "../dist/commands/watch.js";

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
