/**
 * Rust ↔ WASM parity for command-line risk (#272). The shared, hand-derived vectors in
 * `crates/allw-core/tests/fixtures/command_line_risk_vectors.json` (also asserted by
 * `crates/allw-core/tests/command_line_risk_vectors.rs`) are fed through the compiled `.wasm`
 * `action_from_command` and through the public SDK builder `commandActionFromLine`. Unquoted
 * operators, substitutions and redirections raise risk to that of every command the shell would
 * run, and never lower it. `bin` stays the first word.
 *
 * Run order (the wasm must be built first):
 *   pnpm run build:wasm          # from repo root
 *   pnpm --filter @allw/sdk test
 *
 * @see ../../../docs/policy-seam.md §ActionRecord
 * @see ../../../crates/allw-core/src/command/risk.rs (module doc)
 * @see https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html
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
      "command_line_risk_vectors.json",
    ),
    "utf8",
  ),
);

test("the shared command-line risk vectors are non-empty", () => {
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

// The shared exhaustion cases use compact metadata rather than literal megabyte fixtures.
// A first charge larger than the documented 4 MiB budget exercises the pre-pass in WASM
// and in the public SDK builder; the expected tier remains the hand-derived fixture tier.
for (const { command, risk, bin, why, exhaust_padding } of fixture.cases) {
  if (!exhaust_padding) continue;
  test(`padded WASM/SDK command risk: ${JSON.stringify(command)}`, async () => {
    const padded = `${command} ;:${"x".repeat(4 * 1024 * 1024)}`;
    const wasm = await loadWasm();
    const record = JSON.parse(wasm.action_from_command(padded, null));
    const action = await commandActionFromLine(padded);
    for (const result of [record, action]) {
      assert.equal(result.risk, risk, why);
      assert.equal(result.syntactic.bin, bin);
    }
  });
}
