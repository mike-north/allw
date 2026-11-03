/**
 * Rust ↔ WASM parity for command risk classification (#268). The shared, hand-derived vectors in
 * `crates/allw-core/tests/fixtures/command_risk_vectors.json` (also asserted by
 * `crates/allw-core/tests/command_risk_vectors.rs`) are fed through the compiled `.wasm`
 * `action_from_command`. Risk is classified on the program that actually runs: a leading
 * `NAME=value`, a wrapper (`env`, `nice`, `sudo`, …) or `sh -c` never lowers it. `bin` stays
 * `argv[0]`. The public SDK builder `commandActionFromLine` must carry the same risk through.
 *
 * Run order (the wasm must be built first):
 *   pnpm run build:wasm          # from repo root
 *   pnpm --filter @allw/sdk test
 *
 * @see ../../../docs/policy-seam.md §ActionRecord
 * @see ../../../crates/allw-core/src/command.rs (module doc § Risk heuristic)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

import { commandActionFromLine } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

/** Load the `--target web` wasm synchronously (mirrors test/wasm.test.mjs). */
async function loadWasm() {
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  const bytes = readFileSync(join(vendorDir, "allw_wasm_bg.wasm"));
  glue.initSync({ module: new WebAssembly.Module(bytes) });
  return glue;
}

const fixture = JSON.parse(
  readFileSync(
    join(
      here,
      "..",
      "..",
      "..",
      "crates",
      "allw-core",
      "tests",
      "fixtures",
      "command_risk_vectors.json",
    ),
    "utf8",
  ),
);

test("the shared command risk vectors are non-empty", () => {
  assert.ok(Array.isArray(fixture.cases) && fixture.cases.length > 0);
});

for (const { command, risk, bin, why } of fixture.cases) {
  test(`WASM action_from_command(${JSON.stringify(command)}) → risk ${risk}, bin ${JSON.stringify(bin)}`, async () => {
    const wasm = await loadWasm();
    const record = JSON.parse(wasm.action_from_command(command, null));
    assert.equal(record.risk, risk, why);
    assert.equal(record.syntactic.bin, bin);
  });

  test(`SDK commandActionFromLine(${JSON.stringify(command)}) → risk ${risk}`, async () => {
    const action = await commandActionFromLine(command);
    assert.equal(action.risk, risk, why);
    assert.equal(action.syntactic.bin, bin);
  });
}
