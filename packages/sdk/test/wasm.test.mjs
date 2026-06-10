/**
 * Cross-platform parity test for the WASM bindings (issue #9): the same shared vector that the
 * Rust core asserts against (`crates/allw-core/tests/fixtures/wasm_vector.json`, guarded by
 * `crates/allw-core/tests/wasm_vector.rs`) is fed through the compiled `.wasm` here. This proves
 * Rust ↔ WASM parity for `request-hash/v2` and that `verify_verdict` accepts the known-good verdict
 * and rejects a tampered one (fail-closed surfaces as a thrown error).
 *
 * Run order (the wasm must be built first):
 *   pnpm run build:wasm          # from repo root — wasm-pack build (--target web)
 *   pnpm --filter @allw/sdk test # node --test
 *
 * The `--target web` glue is loaded synchronously by compiling the `.wasm` bytes into a
 * `WebAssembly.Module` and calling `initSync` — one ESM artifact works in both node and the
 * browser/worker (docs/architecture.md: the same wasm is browser-capable).
 *
 * @see crates/allw-core/tests/fixtures/wasm_vector.json (the shared vector)
 * @see crates/allw-core/src/hash.rs (FROZEN_HASH_HEX — the request-hash/v2 anchor)
 * @see docs/contract.md §Wire encoding, §Verification checklist
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

/** Loads the `--target web` wasm module synchronously from on-disk bytes (node-friendly). */
async function loadWasm() {
  // Convert the filesystem path to a file:// URL — a bare path string is not a valid ESM
  // specifier on Windows (`C:\...`), so dynamic import must use a URL for cross-platform parity.
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  const bytes = readFileSync(join(vendorDir, "allw_wasm_bg.wasm"));
  const module = new WebAssembly.Module(bytes);
  glue.initSync({ module });
  return glue;
}

/** The shared cross-platform vector (generated + guarded by the Rust side). */
function loadVector() {
  const raw = readFileSync(
    join(here, "..", "..", "..", "crates", "allw-core", "tests", "fixtures", "wasm_vector.json"),
    "utf8",
  );
  return JSON.parse(raw);
}

test("compute_request_hash reproduces the Rust request-hash/v2 vector", async () => {
  const wasm = await loadWasm();
  const v = loadVector();

  const got = wasm.compute_request_hash(v.context_json, v.expires_at);

  // (a) WASM output equals the fixture's expected base64url hash...
  assert.equal(
    got,
    v.expected_request_hash_b64,
    "WASM compute_request_hash must equal the shared vector's base64url hash",
  );

  // ...and decodes to the frozen hex (Rust ↔ WASM parity, request-hash/v2).
  const hex = Buffer.from(got.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("hex");
  assert.equal(hex, v.expected_request_hash_hex, "decoded hash must equal the frozen hex vector");
});

test("verify_verdict accepts the known-good signed verdict", async () => {
  const wasm = await loadWasm();
  const v = loadVector();

  const resultJson = wasm.verify_verdict(
    v.verdict_json,
    v.request_json,
    v.context_json,
    v.approver_root_pubkey_b64,
    v.now_ms,
  );
  const result = JSON.parse(resultJson);

  assert.equal(result.approved, true, "the known-good verdict must verify as approved");
  assert.equal(result.device_id, "dev_wasm_vector_01", "device_id comes from the verified verdict");
  assert.equal(result.decided_at, 1700001000000, "decided_at echoes the signed claim");
});

test("verify_verdict rejects a verdict whose decision was flipped to denied", async () => {
  const wasm = await loadWasm();
  const v = loadVector();

  // Tamper the OUTER decision so it no longer matches the signed claim (still "approved").
  // The core detects the outer↔claim divergence (ClaimsMismatch) and throws — fail-closed.
  const tampered = JSON.parse(v.verdict_json);
  tampered.decision = "denied";
  const tamperedJson = JSON.stringify(tampered);

  assert.throws(
    () =>
      wasm.verify_verdict(
        tamperedJson,
        v.request_json,
        v.context_json,
        v.approver_root_pubkey_b64,
        v.now_ms,
      ),
    /verify_verdict failed/,
    "a tampered verdict must throw, not return a falsy result",
  );
});

test("verify_verdict rejects a verdict whose request_hash was mutated", async () => {
  const wasm = await loadWasm();
  const v = loadVector();

  // Replace the request_hash with a different (valid-length) base64url 32-byte value. Both the
  // outer field and the signed claim now disagree with each other / the request → reject.
  const tampered = JSON.parse(v.verdict_json);
  tampered.request_hash = Buffer.alloc(32, 0xcd).toString("base64url");
  const tamperedJson = JSON.stringify(tampered);

  assert.throws(
    () =>
      wasm.verify_verdict(
        tamperedJson,
        v.request_json,
        v.context_json,
        v.approver_root_pubkey_b64,
        v.now_ms,
      ),
    /verify_verdict failed/,
    "a mutated request_hash must break the WYSIWYS binding and throw",
  );
});

test("compute_request_hash throws on invalid context JSON", async () => {
  const wasm = await loadWasm();
  assert.throws(
    () => wasm.compute_request_hash("not json", 1700003600000),
    /invalid ApprovalContext JSON/,
    "malformed context JSON must surface as a thrown JS error",
  );
});

// ── signing surface (issue #41 unblock): derive keys → cert → sign → verify ───────────

/**
 * Build a self-contained approver: an account-root key, a device key it certifies, and a verdict
 * the device signs — all through the WASM surface. Reuses the shared vector's request/context so
 * the recomputed `request_hash` and the verify window line up with a known-good pair.
 */
function approverFixture(wasm) {
  const v = loadVector();
  const accountSeed = Buffer.alloc(32, 7).toString("base64url");
  const deviceSeed = Buffer.alloc(32, 9).toString("base64url");
  const accountRootPub = wasm.ed25519_public_key(accountSeed);
  const devicePub = wasm.ed25519_public_key(deviceSeed);

  const request = JSON.parse(v.request_json);
  const requestHash = wasm.compute_request_hash(v.context_json, request.expires_at);
  // Reuse the vector's decided_at/now_ms — a pair already known to be inside the verify window.
  const decidedAt = JSON.parse(v.verdict_json).decided_at;

  const cert = wasm.issue_device_cert(accountSeed, "acct_rt", "dev_rt", devicePub, 1700000000000);

  const unsigned = {
    v: 1,
    request_id: request.id,
    request_hash: requestHash,
    decision: "approved",
    decided_at: decidedAt,
    approver: { account_id: "acct_rt", device_id: "dev_rt" },
  };
  const nonce = Buffer.alloc(16, 3).toString("base64url");
  return { v, accountSeed, deviceSeed, accountRootPub, devicePub, cert, unsigned, nonce, request };
}

test("ed25519/x25519 public-key derivation returns 43-char base64url keys", async () => {
  const wasm = await loadWasm();
  const seed = Buffer.alloc(32, 1).toString("base64url");
  const ed = wasm.ed25519_public_key(seed);
  const x = wasm.x25519_public_key(seed);
  // 32 bytes → 43 base64url-unpadded chars; deterministic from the seed.
  assert.equal(ed.length, 43, "Ed25519 pubkey is 43 base64url chars");
  assert.equal(x.length, 43, "X25519 pubkey is 43 base64url chars");
  assert.equal(wasm.ed25519_public_key(seed), ed, "derivation is deterministic");
  assert.notEqual(ed, x, "Ed25519 and X25519 keys differ for the same seed");
});

test("sign_verdict + issue_device_cert produce a verdict verify_verdict accepts", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  const verdictJson = wasm.sign_verdict(JSON.stringify(f.unsigned), f.deviceSeed, f.nonce, f.cert);

  const result = JSON.parse(
    wasm.verify_verdict(
      verdictJson,
      f.v.request_json,
      f.v.context_json,
      f.accountRootPub,
      f.v.now_ms,
    ),
  );
  assert.equal(result.approved, true, "the freshly signed verdict must verify as approved");
  assert.equal(result.device_id, "dev_rt", "device_id comes from the verified verdict");
});

test("verify rejects a verdict whose signing key the device-cert did not certify", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  // Sign with a DIFFERENT device seed than the cert certifies — the cert binds dev_rt to f.devicePub,
  // so a signature from another key must not chain to the account root. Fail-closed → throw.
  const wrongDeviceSeed = Buffer.alloc(32, 0x5a).toString("base64url");
  const forged = wasm.sign_verdict(JSON.stringify(f.unsigned), wrongDeviceSeed, f.nonce, f.cert);

  assert.throws(
    () =>
      wasm.verify_verdict(forged, f.v.request_json, f.v.context_json, f.accountRootPub, f.v.now_ms),
    /verify_verdict failed/,
    "a verdict signed by an uncertified key must not verify",
  );
});

test("sign_verdict throws on a non-32-byte device seed", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);
  assert.throws(
    () => wasm.sign_verdict(JSON.stringify(f.unsigned), "tooshort", f.nonce, f.cert),
    /device_seed_b64 must decode to exactly 32 bytes/,
    "a malformed signing seed must surface as a thrown JS error",
  );
});

test("sign_verdict carries an optional note through to a verifiable verdict", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  // Exercise the "sign optional fields only when present" path through the wasm boundary.
  const unsigned = { ...f.unsigned, note: "approved from the cabin" };
  const verdictJson = wasm.sign_verdict(JSON.stringify(unsigned), f.deviceSeed, f.nonce, f.cert);

  const verdict = JSON.parse(verdictJson);
  assert.equal(
    verdict.note,
    "approved from the cabin",
    "the optional note is carried on the verdict",
  );

  const result = JSON.parse(
    wasm.verify_verdict(
      verdictJson,
      f.v.request_json,
      f.v.context_json,
      f.accountRootPub,
      f.v.now_ms,
    ),
  );
  assert.equal(result.approved, true, "a verdict carrying an optional note still verifies");
});

test("verify rejects a verdict whose device-cert has expired", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  // Cert that expired long before now_ms (issued_at=1000, expires_at=2000 ms — both in 1970).
  // This is the only test that threads issue_device_cert's 6th (expires_at) parameter.
  const expiredCert = wasm.issue_device_cert(
    f.accountSeed,
    "acct_rt",
    "dev_rt",
    f.devicePub,
    1000,
    2000,
  );
  const verdictJson = wasm.sign_verdict(
    JSON.stringify(f.unsigned),
    f.deviceSeed,
    f.nonce,
    expiredCert,
  );

  assert.throws(
    () =>
      wasm.verify_verdict(
        verdictJson,
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
      ),
    /verify_verdict failed/,
    "an expired device-cert must break the chain to the account root",
  );
});

test("verify rejects a verdict whose device-cert was tampered", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  // Flip one char of the cert's payload segment → its account-root signature no longer verifies.
  const parts = f.cert.split(".");
  const last = parts[1].slice(-1);
  parts[1] = parts[1].slice(0, -1) + (last === "A" ? "B" : "A");
  const tamperedCert = parts.join(".");
  const verdictJson = wasm.sign_verdict(
    JSON.stringify(f.unsigned),
    f.deviceSeed,
    f.nonce,
    tamperedCert,
  );

  assert.throws(
    () =>
      wasm.verify_verdict(
        verdictJson,
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
      ),
    /verify_verdict failed/,
    "a tampered device-cert must not verify under the account root",
  );
});

test("verify rejects a device-cert presented as the verdict signature (typ domain separation)", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  const verdict = JSON.parse(
    wasm.sign_verdict(JSON.stringify(f.unsigned), f.deviceSeed, f.nonce, f.cert),
  );
  // Swap the verdict JWS for the device-cert JWS: wrong `typ` (device-cert vs verdict) AND wrong
  // signing key (root vs device). Either alone must reject — pins domain separation across the FFI.
  verdict.sig = f.cert;

  assert.throws(
    () =>
      wasm.verify_verdict(
        JSON.stringify(verdict),
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
      ),
    /verify_verdict failed/,
    "a device-cert used as a verdict signature must be rejected",
  );
});
