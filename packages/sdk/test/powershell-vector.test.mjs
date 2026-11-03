/**
 * WASM half of the shared PowerShell command-builder vector (#298).
 *
 * `crates/allw-core/tests/fixtures/powershell_vector.json` is asserted by the Rust core
 * (`crates/allw-core/tests/powershell_vector.rs`) and, here, through the compiled `.wasm`, so the
 * core and every TypeScript surface agree on how a PowerShell line becomes an `ActionRecord`. The
 * expected values are hand-written from the rules in `crates/allw-core/src/powershell.rs`.
 *
 * @see https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_quoting_rules
 * @see ../../../crates/allw-core/tests/fixtures/powershell_vector.json
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
    join(
      here,
      "..",
      "..",
      "..",
      "crates",
      "allw-core",
      "tests",
      "fixtures",
      "powershell_vector.json",
    ),
    "utf8",
  );
  return JSON.parse(raw);
}

test("action_from_powershell_command matches every case in the shared vector", async () => {
  const wasm = await loadWasm();
  const { cases } = loadVector();
  assert.ok(cases.length >= 5);
  for (const c of cases) {
    const record = JSON.parse(
      c.cwd === null
        ? wasm.action_from_powershell_command(c.command)
        : wasm.action_from_powershell_command(c.command, c.cwd),
    );
    assert.equal(record.surface, "command", c.class);
    assert.equal(record.risk, c.risk, c.class);
    assert.equal(record.syntactic.raw, c.command, c.class);
    assert.equal(record.syntactic.bin, c.bin, c.class);
    assert.deepEqual(record.syntactic.argv, c.argv, c.class);
    assert.equal(record.syntactic.cwd ?? null, c.cwd, c.class);
  }
});
