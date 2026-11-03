/**
 * WASM half of the shared display-escaping vector (#246).
 *
 * `crates/allw-core/tests/fixtures/display_vector.json` is asserted by the Rust core
 * (`crates/allw-core/tests/display_vector.rs`) and, here, through the compiled `.wasm`, so the core
 * and every TypeScript surface agree byte-for-byte on how untrusted text is shown to a human. The
 * expected values are hand-written from the notation in `crates/allw-core/src/display.rs`.
 *
 * @see https://www.unicode.org/reports/tr9/ §2 (explicit bidi formatting characters)
 * @see ../../../docs/threat-model.md R3 (WYSIWYS completeness)
 * @see ../../../crates/allw-core/tests/fixtures/display_vector.json
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
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  const bytes = readFileSync(join(vendorDir, "allw_wasm_bg.wasm"));
  glue.initSync({ module: new WebAssembly.Module(bytes) });
  return glue;
}

function loadVector() {
  const raw = readFileSync(
    join(here, "..", "..", "..", "crates", "allw-core", "tests", "fixtures", "display_vector.json"),
    "utf8",
  );
  return JSON.parse(raw);
}

test("escape_for_display matches every class in the shared vector", async () => {
  const wasm = await loadWasm();
  const { escape_cases: cases } = loadVector();
  assert.ok(cases.length >= 10);
  for (const c of cases) {
    assert.equal(wasm.escape_for_display(c.input), c.escaped, c.class);
  }
});

test("display_model matches the shared vector's full model case", async () => {
  const wasm = await loadWasm();
  const { display_model_case: dm } = loadVector();
  const model = JSON.parse(wasm.display_model(JSON.stringify(dm.context)));
  assert.deepEqual(model, dm.expected);
});

test("display_model leaves the request hash bound to the raw bytes", async () => {
  const wasm = await loadWasm();
  const { display_model_case: dm } = loadVector();
  const contextJson = JSON.stringify(dm.context);
  const before = wasm.compute_request_hash(contextJson, 1_700_003_600_000);
  wasm.display_model(contextJson);
  assert.equal(wasm.compute_request_hash(contextJson, 1_700_003_600_000), before);
  // Substituting the escaped display form for the raw bytes is a different request.
  const displayed = structuredClone(dm.context);
  displayed.action.syntactic.raw = dm.expected.syntactic.raw;
  assert.notEqual(wasm.compute_request_hash(JSON.stringify(displayed), 1_700_003_600_000), before);
});

test("display_model throws on a malformed context (fail-closed)", async () => {
  const wasm = await loadWasm();
  assert.throws(() => wasm.display_model('{"summary":1}'), /invalid ApprovalContext JSON/);
});
