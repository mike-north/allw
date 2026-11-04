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

import { CommandActionError, commandAction, commandActionFromLine } from "../dist/index.js";

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
  argv: "action_from_argv",
};

/** Call the case's WASM builder. */
function build(wasm, c) {
  return c.builder === "argv"
    ? wasm.action_from_argv(JSON.stringify(c.argv), c.raw ?? null, null)
    : wasm[FUNCTIONS[c.builder]](c.command, null);
}

/** A case's label, naming the input. */
function label(c) {
  const input = c.builder === "argv" ? JSON.stringify(c.argv) : JSON.stringify(c.command);
  return `${c.class} (${c.builder}: ${input})`;
}

/** The SDK reason for each core code from `action_from_argv` (`command-request.ts`). */
const SDK_ARGV_REASONS = {
  no_command: "argv_empty",
  no_program: "argv_no_program",
  empty_program: "argv_program_empty",
};

/** The SDK reason for each core code from `action_from_command` (`command-request.ts`). */
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
    assert.throws(
      () => build(wasm, c),
      (err) => {
        assert.ok(err instanceof Error, label(c));
        assert.equal(err.kind, c.code, label(c));
        assert.ok(Object.hasOwn(err, "kind"), label(c));
        assert.equal(err.message, `${fn} failed: ${c.message}`, label(c));
        return true;
      },
      label(c),
    );
  }
});

test("the WASM builders build every accepted case in the shared vector", async () => {
  const wasm = await loadWasm();
  const { accepted } = loadVector();
  assert.ok(accepted.length > 0);
  for (const c of accepted) {
    const record = JSON.parse(build(wasm, c));
    assert.equal(record.surface, "command", label(c));
    if (c.builder === "argv") assert.deepEqual(record.syntactic.argv, c.argv, label(c));
    else assert.equal(record.syntactic.raw, c.command, label(c));
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

// `validateArgv` refuses an empty argv and an empty `argv[0]` before the core is called (unchanged
// by #376); an empty program after an assignment and an all-assignment argv come from the core.
test("commandAction refuses every argv case with the matching SDK reason", async () => {
  const { cases } = loadVector();
  const argvCases = cases.filter((c) => c.builder === "argv");
  assert.ok(argvCases.length >= 4);
  for (const c of argvCases) {
    await assert.rejects(commandAction(c.argv, c.raw === null ? {} : { raw: c.raw }), (err) => {
      assert.ok(err instanceof CommandActionError, label(c));
      assert.equal(err.reason, SDK_ARGV_REASONS[c.code], label(c));
      return true;
    });
  }
});
