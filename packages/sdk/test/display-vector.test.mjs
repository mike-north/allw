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

/** The core's notation for an escaped code point: `⟨U+XXXX⟩`, uppercase hex, at least 4 digits. */
function codepointNotation(cp) {
  return `⟨U+${cp.toString(16).toUpperCase().padStart(4, "0")}⟩`;
}

test("canary: every combining mark in this runtime's Unicode is capped at two in a run", async () => {
  // The core's mark table is generated from one Unicode version (`UNICODE_VERSION`,
  // crates/allw-core/src/display/unicode_tables.rs), but approvers render on runtimes whose
  // Unicode may be newer. For every code point this runtime's ICU calls a nonspacing or
  // enclosing mark, three of them on one base must show the third escaped. A mark the core's
  // version doesn't assign still passes, because an unassigned code point counts toward a run;
  // a failure here means the core shows a known mark uncapped.
  const wasm = await loadWasm();
  const mark = /^[\p{Mn}\p{Me}]$/u;
  let checked = 0;
  const uncapped = [];
  for (let cp = 0; cp <= 0x10ffff; cp += 1) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const c = String.fromCodePoint(cp);
    if (!mark.test(c)) continue;
    checked += 1;
    if (!wasm.escape_for_display(`o${c}${c}${c}`).endsWith(codepointNotation(cp))) {
      uncapped.push(codepointNotation(cp));
    }
  }
  assert.ok(checked > 2000, `the runtime's ICU knows ${String(checked)} marks`);
  assert.deepEqual(uncapped, [], "a third stacked mark is shown raw");
});

/** `[major, minor]` of a `major.minor[.patch]` version string. */
function majorMinor(version) {
  const match = /^(\d+)\.(\d+)/.exec(version);
  assert.ok(match, `a Unicode version: ${version}`);
  return [Number(match[1]), Number(match[2])];
}

test("the core's Unicode tables are not older than this runtime's Unicode", () => {
  // Safety under skew comes from the unassigned-code-point rule (the canary above). This is the
  // prompt to regenerate: a runtime on a newer Unicode than the core's tables fails here. Equal or
  // older passes.
  const tables = readFileSync(
    join(here, "..", "..", "..", "crates", "allw-core", "src", "display", "unicode_tables.rs"),
    "utf8",
  );
  const core = /pub const UNICODE_VERSION: &str = "([^"]+)";/.exec(tables)?.[1];
  assert.ok(core, "unicode_tables.rs declares UNICODE_VERSION");
  const runtime = process.versions.unicode;
  assert.ok(runtime, "this runtime reports process.versions.unicode");
  const [coreMajor, coreMinor] = majorMinor(core);
  const [runMajor, runMinor] = majorMinor(runtime);
  const newer = runMajor > coreMajor || (runMajor === coreMajor && runMinor > coreMinor);
  assert.ok(
    !newer,
    `this runtime's Unicode (${runtime}) is newer than the core's tables (${core}). Regenerate them: ` +
      `node scripts/gen-unicode-tables.mjs ${String(runMajor)}.${String(runMinor)}.0`,
  );
});

test("display_model matches the shared vector's full model case", async () => {
  const wasm = await loadWasm();
  const { display_model_case: dm } = loadVector();
  const model = JSON.parse(wasm.display_model(JSON.stringify(dm.context)));
  assert.deepEqual(model, dm.expected);
});

test("display_model raw_lines match every per-surface case in the shared vector", async () => {
  const wasm = await loadWasm();
  const { raw_lines_cases: cases } = loadVector();
  assert.ok(cases.length > 0);
  for (const c of cases) {
    const context = {
      action: {
        record_schema_version: 1,
        surface: c.surface,
        syntactic: { raw: c.raw },
        risk: "high",
      },
      summary: "s",
      actor: { id: "machine:ci", kind: "claude-code" },
      risk: "high",
      reversible: false,
      constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
    };
    const model = JSON.parse(wasm.display_model(JSON.stringify(context)));
    assert.deepEqual(model.syntactic.raw_lines, c.raw_lines, c.class);
    assert.equal(model.has_hidden_or_control_chars, c.has_hidden_or_control_chars, c.class);
  }
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
