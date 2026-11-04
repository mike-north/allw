/**
 * WASM half of the shared command-refusal vector (#376).
 *
 * `crates/allw-core/tests/fixtures/command_refusal_vector.json` is asserted by the Rust core
 * (`crates/allw-core/tests/command_refusal_vector.rs`) and, here, through the compiled `.wasm`: every
 * line that runs no program is refused by `action_from_command` / `action_from_powershell_command`
 * with an `Error` whose `kind` is the core's code, so every surface inherits the refusal. The POSIX
 * cases are also checked through the SDK's `commandActionFromLine`.
 *
 * @see ../../../crates/allw-core/tests/fixtures/command_refusal_vector.json
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

import { CommandActionError, commandActionFromLine } from "../dist/index.js";

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
      "command_refusal_vector.json",
    ),
    "utf8",
  );
  return JSON.parse(raw);
}

const FUNCTIONS = {
  posix: "action_from_command",
  powershell: "action_from_powershell_command",
};

/** The SDK reason for each core code (`command-request.ts`). */
const SDK_REASONS = {
  no_command: "command_line_empty",
  no_program: "command_line_no_program",
  empty_program: "argv_program_empty",
};

test("the WASM builders refuse every case in the shared vector with its kind and message", async () => {
  const wasm = await loadWasm();
  const { cases } = loadVector();
  assert.ok(cases.length >= 10);
  for (const c of cases) {
    const fn = FUNCTIONS[c.builder];
    const label = `${c.class} (${c.builder}: ${JSON.stringify(c.command)})`;
    assert.throws(
      () => wasm[fn](c.command, null),
      (err) => {
        assert.ok(err instanceof Error, label);
        assert.equal(err.kind, c.code, label);
        assert.ok(Object.hasOwn(err, "kind"), label);
        assert.equal(err.message, `${fn} failed: ${c.message}`, label);
        return true;
      },
      label,
    );
  }
});

test("the WASM builders build every accepted case in the shared vector", async () => {
  const wasm = await loadWasm();
  const { accepted } = loadVector();
  assert.ok(accepted.length > 0);
  for (const c of accepted) {
    const record = JSON.parse(wasm[FUNCTIONS[c.builder]](c.command, null));
    assert.equal(record.surface, "command", c.class);
    assert.equal(record.syntactic.raw, c.command, c.class);
  }
});

test("commandActionFromLine refuses every POSIX case with the matching SDK reason", async () => {
  const { cases } = loadVector();
  for (const c of cases.filter((c) => c.builder === "posix")) {
    await assert.rejects(commandActionFromLine(c.command), (err) => {
      assert.ok(err instanceof CommandActionError, c.class);
      assert.equal(err.reason, SDK_REASONS[c.code], c.class);
      return true;
    });
  }
});
