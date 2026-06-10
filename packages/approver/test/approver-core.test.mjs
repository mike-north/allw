/**
 * Core round-trip tests for the v0 stand-in approver (issue #41).
 *
 * Proves the cryptographic heart of the approver against the **real WASM core** (no mocks for
 * crypto): given a `context_ciphertext` encrypted in-test to the device key, the approver
 *   1. decrypts it,
 *   2. recomputes the matching WYSIWYS `request_hash` (identical to the integrator's pre-send hash),
 *   3. signs a verdict that PASSES `verify_verdict` against the account-root pubkey (id +
 *      request_hash, no-swap) — the full approver↔integrator round-trip.
 * Plus the `denied` path and a malformed-ciphertext fail-closed path.
 *
 * The approver is exercised through its built `dist/` ESM (the package's public surface), and the
 * WASM is the same vendored `--target web` artifact the SDK test loads (built by
 * `pnpm run build:wasm` from the repo root) — so this is an integration test of the approver core
 * over the audited Rust crypto, not a unit test against stubs.
 *
 * Run order:
 *   pnpm run build:wasm               # from repo root — wasm-pack build (--target web)
 *   pnpm --filter @allw/approver build
 *   pnpm --filter @allw/approver test
 *
 * @see ../../sdk/test/wasm.test.mjs (the loader + fixture pattern this mirrors)
 * @see ../../../docs/contract.md §Lifecycle, §Messages, §Verification checklist, §Wire encoding
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadWasm } from "../dist/index.js";
import { generateKeyfile } from "../dist/lib/keyfile.js";
import { prepareRequest, signDecision } from "../dist/lib/approver-core.js";
import { renderRequest } from "../dist/lib/render.js";

// ── Deterministic fixtures (fixed timestamps; never Date.now() in test data) ─────────────────

const ACCOUNT_ID = "acct-approver-test";
const DEVICE_ID = "dev-approver-test";
const REQUEST_ID = "req-approver-test-1";
/** 2023-11-14T22:13:20Z — cert issuance. */
const ISSUED_AT = 1700000000000;
/** 2023-11-14T23:13:20Z — request deadline (bound into request_hash). */
const EXPIRES_AT = 1700003600000;
/** 2023-11-14T22:30:00Z — when the human decided (inside the verify window). */
const DECIDED_AT = 1700001000000;
/** 2023-11-14T22:38:20Z — verifier's "now" (after decided_at, before expiry). */
const NOW_MS = 1700001500000;

/**
 * The canonical human-shown context for these tests. Built by hand from `docs/contract.md`
 * §Messages → ApprovalContext (NOT captured from program output).
 */
const CONTEXT = {
  action: {
    record_schema_version: 1,
    surface: "command",
    syntactic: { bin: "git", raw: "git push --force origin main" },
    risk: "high",
  },
  summary: "force push to main",
  actor: { id: "machine:laptop", kind: "claude-code" },
  risk: "high",
  reversible: false,
  constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
};
const CONTEXT_JSON = JSON.stringify(CONTEXT);

/** The relay-visible envelope the integrator submits (minus the ciphertext, filled per-test). */
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
 * Build a fully-paired approver keyfile: a fresh identity whose account-root certifies the device
 * signing key, with relay/account/device populated. Returns { keyfile, jwe } where `jwe` encrypts
 * CONTEXT to the device's X25519 key (the integrator's encrypt step).
 */
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
  const recipients = JSON.stringify([
    { device_id: DEVICE_ID, public_key_b64: fresh.device_encryption_pubkey },
  ]);
  const jwe = wasm.encrypt_context(CONTEXT_JSON, recipients);
  return { keyfile, jwe };
}

// ── Round-trip: decrypt → recompute hash → sign → verify ─────────────────────────────────────

test("approved round-trip: decrypt → recompute request_hash → sign → verify_verdict accepts", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);

  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe));

  // (a) The recomputed WYSIWYS hash equals the integrator's pre-send hash (no separate digest).
  const integratorHash = wasm.compute_request_hash(CONTEXT_JSON, EXPIRES_AT);
  assert.equal(
    prepared.requestHash,
    integratorHash,
    "device-recomputed request_hash must equal the integrator's pre-send hash (WYSIWYS)",
  );
  assert.equal(prepared.requestId, REQUEST_ID, "the prepared request id comes from the envelope");
  assert.equal(prepared.context.summary, CONTEXT.summary, "the decrypted context round-trips");

  // (b) Sign an approval and verify it against the ACCOUNT-ROOT pubkey (id + request_hash, no swap).
  const verdict = signDecision(wasm, keyfile, prepared, "approved", DECIDED_AT);
  assert.equal(verdict.decision, "approved", "the signed verdict carries the approved decision");
  assert.equal(verdict.request_id, REQUEST_ID, "the verdict binds to the request id");

  const result = JSON.parse(
    wasm.verify_verdict(
      JSON.stringify(verdict),
      makeRequestJson(),
      CONTEXT_JSON,
      keyfile.account_root_pubkey,
      NOW_MS,
    ),
  );
  assert.equal(result.approved, true, "the approver's verdict must verify under the account root");
  assert.equal(result.device_id, DEVICE_ID, "verified device_id matches the paired device");
  assert.equal(result.decided_at, DECIDED_AT, "verified decided_at echoes the signed claim");
});

test("denied round-trip: a signed denial verifies as a verified 'no' (verify_verdict throws)", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe));

  const verdict = signDecision(wasm, keyfile, prepared, "denied", DECIDED_AT);
  assert.equal(verdict.decision, "denied", "the signed verdict carries the denied decision");

  // Per the WASM FFI contract, a VERIFIED non-approval is reported as a thrown error (fail-closed),
  // not `approved: false` — so the integrator's gate stays closed. The throw proves the denial was
  // authentic (it parsed, the signature + binding checked out, the decision was simply 'denied').
  assert.throws(
    () =>
      wasm.verify_verdict(
        JSON.stringify(verdict),
        makeRequestJson(),
        CONTEXT_JSON,
        keyfile.account_root_pubkey,
        NOW_MS,
      ),
    /verify_verdict failed/,
    "a verified denial surfaces as a thrown error (deny-by-default), not a falsy result",
  );
});

// ── Fail-closed: malformed / wrong-key ciphertext ────────────────────────────────────────────

test("fail-closed: a malformed ciphertext aborts the request (throws, no verdict)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // A structurally invalid JWE — the device key cannot decrypt it; prepareRequest must throw so the
  // approver emits no verdict and the integrator's gate stays closed.
  const envelope = makeEnvelope("eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.NOT-A-REAL.JWE");
  assert.throws(
    () => prepareRequest(wasm, keyfile, envelope),
    /decrypt/i,
    "a malformed ciphertext must throw (fail-closed), never yield a forged context",
  );
});

test("fail-closed: a ciphertext encrypted to a DIFFERENT device key cannot be decrypted", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // Encrypt to a stranger's X25519 key — our device key must not be able to unwrap the CEK.
  const strangerSeed = Buffer.alloc(32, 0x5a).toString("base64url");
  const strangerPub = wasm.x25519_public_key(strangerSeed);
  const jweForStranger = wasm.encrypt_context(
    CONTEXT_JSON,
    JSON.stringify([{ device_id: "dev-stranger", public_key_b64: strangerPub }]),
  );

  assert.throws(
    () => prepareRequest(wasm, keyfile, makeEnvelope(jweForStranger)),
    /decrypt/i,
    "a context encrypted to another device must fail to decrypt (fail-closed)",
  );
});

test("fail-closed: an envelope missing context_ciphertext is rejected before any crypto", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);
  const envelope = makeEnvelope("placeholder");
  delete envelope.context_ciphertext;

  assert.throws(
    () => prepareRequest(wasm, keyfile, envelope),
    /context_ciphertext/,
    "a malformed envelope must be rejected fail-closed",
  );
});

test("fail-closed: signing is refused when the keyfile has no device_cert", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe));

  // Strip the cert — without it the verdict cannot chain to the account root, so we must refuse to
  // sign rather than emit an unverifiable verdict.
  const certless = { ...keyfile, device_cert: undefined };
  assert.throws(
    () => signDecision(wasm, certless, prepared, "approved", DECIDED_AT),
    /device_cert/,
    "signing without a device_cert must be refused (the verdict could never verify)",
  );
});

// ── WYSIWYS render shows the EXACT action ────────────────────────────────────────────────────

test("renderRequest shows the exact action, actor, risk, expiry, and request_hash", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe));

  const rendered = renderRequest(prepared);
  // Every WYSIWYS field the human signs over must appear verbatim in the rendered block.
  assert.match(rendered, /git push --force origin main/, "the exact action/argv is shown");
  assert.match(rendered, /force push to main/, "the summary is shown");
  assert.match(rendered, /machine:laptop \(claude-code\)/, "the actor id + kind are shown");
  assert.match(rendered, /Risk:\s+high/, "the risk tier is shown");
  assert.match(rendered, /Reversible: no/, "reversibility is shown");
  assert.match(rendered, /2023-11-14T23:13:20\.000Z/, "the expiry is shown (ISO-8601 UTC)");
  assert.ok(
    rendered.includes(prepared.requestHash),
    "the request_hash is shown verbatim for out-of-band verification",
  );
});

test("nonce is a fresh, high-entropy (≥16-byte) value per verdict", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe));

  // Two signatures over the same unsigned verdict differ because each carries a fresh random nonce
  // — proving anti-replay nonces are generated per verdict (not reused).
  const v1 = signDecision(wasm, keyfile, prepared, "approved", DECIDED_AT);
  const v2 = signDecision(wasm, keyfile, prepared, "approved", DECIDED_AT);
  assert.notEqual(v1.sig, v2.sig, "each verdict signs a fresh random nonce (anti-replay)");
});
