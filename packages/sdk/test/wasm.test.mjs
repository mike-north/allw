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
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

/** Loads the `--target web` wasm module synchronously from on-disk bytes (node-friendly). */
async function loadWasm() {
  const glue = await import(join(vendorDir, "allw_wasm.js"));
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
