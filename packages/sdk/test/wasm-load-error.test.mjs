/**
 * The vendored WASM core's load error (#301, item 3).
 *
 * When a vendored file is missing, the error says to build it. When the files are there but loading
 * fails anyway (a glue module that throws, a corrupt `.wasm`), it quotes the underlying cause
 * instead of always saying `pnpm run build:wasm`. The cause is untrusted text that can reach a
 * terminal or a hook's deny reason, and the display-escaping core is what failed to load, so the
 * cause is reduced to bounded printable ASCII: every other character becomes a `\uXXXX` escape,
 * and the result is clipped to `MAX_WASM_LOAD_CAUSE_CHARS`.
 *
 * The unit tests drive `wasmLoadError` with an injected file-existence check. The integration
 * tests load a copy of the built `dist/wasm.js` against a temporary vendor directory (so the
 * module memo starts empty and the real vendor dir is untouched).
 *
 * @see https://github.com/mike-north/allw/issues/301
 * @see ../src/wasm.ts (wasmLoadError)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { MAX_WASM_LOAD_CAUSE_CHARS, wasmLoadError } from "../dist/wasm.js";

const DIST_WASM = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "wasm.js");
const DIR = "/opt/allw/vendor/allw-wasm";

const allPresent = () => true;

test("a missing vendored file → names it and says to run build:wasm", () => {
  const err = wasmLoadError(
    DIR,
    new Error("ENOENT"),
    (path) => !path.endsWith("allw_wasm_bg.wasm"),
  );
  assert.match(err.message, /allw_wasm_bg\.wasm is missing/);
  assert.match(err.message, /Run `pnpm run build:wasm`/);
  assert.ok(err.message.includes(DIR));
});

test("both vendored files missing → names both", () => {
  const err = wasmLoadError(DIR, new Error("ENOENT"), () => false);
  assert.match(err.message, /allw_wasm\.js and allw_wasm_bg\.wasm are missing/);
});

test("files present but the load fails → quotes the cause, not only build:wasm", () => {
  const cause = new SyntaxError("Unexpected token 'export'");
  const err = wasmLoadError(DIR, cause, allPresent);
  assert.match(err.message, /SyntaxError: Unexpected token 'export'/);
  assert.match(err.message, /vendored files are present/);
  assert.doesNotMatch(err.message, /is missing|are missing/);
  assert.equal(err.cause, cause, "the original error stays reachable as the cause");
});

test("control characters in the cause are escaped, never passed through", () => {
  const err = wasmLoadError(DIR, new Error("line one\nallw: APPROVED\r\u001b[2J‮evil"), allPresent);
  assert.ok(!/[\u0000-\u001f\u007f-￿]/u.test(err.message.replace(/…$/u, "")), err.message);
  assert.match(err.message, /line one\\u000aallw: APPROVED\\u000d\\u001b\[2J\\u202eevil/);
});

test("a long cause is clipped to the bound", () => {
  const err = wasmLoadError(DIR, new Error("x".repeat(10_000)), allPresent);
  const quoted = /: (Error: x+…)\./u.exec(err.message)?.[1];
  assert.ok(quoted !== undefined, err.message.slice(0, 300));
  assert.equal(quoted.length, MAX_WASM_LOAD_CAUSE_CHARS + 1, "the bound plus the ellipsis");
});

test("a non-Error cause, even one that throws when stringified, is described", () => {
  assert.match(wasmLoadError(DIR, 42, allPresent).message, /non-error thrown: 42/);
  const hostile = {
    toString() {
      throw new Error("no");
    },
  };
  assert.match(wasmLoadError(DIR, hostile, allPresent).message, /could not be described/);
});

/** A package-shaped temp dir: `dist/wasm.js` (copied) beside `vendor/allw-wasm/` (as given). */
function packageWithVendor(t, files) {
  const root = mkdtempSync(join(tmpdir(), "allw-wasm-load-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "dist"));
  copyFileSync(DIST_WASM, join(root, "dist", "wasm.js"));
  writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module" }));
  const vendor = join(root, "vendor", "allw-wasm");
  mkdirSync(vendor, { recursive: true });
  for (const [name, contents] of Object.entries(files)) writeFileSync(join(vendor, name), contents);
  return import(pathToFileURL(join(root, "dist", "wasm.js")).href);
}

test("integration: a glue module that throws on load → loadWasmSync quotes its error, escaped", async (t) => {
  const mod = await packageWithVendor(t, {
    "allw_wasm.js": 'throw new Error("glue exploded\\n\\u001b[31mspoof");\n',
    "allw_wasm_bg.wasm": "",
  });
  assert.throws(
    () => mod.loadWasmSync(),
    (err) => {
      assert.match(err.message, /Error: glue exploded\\u000a\\u001b\[31mspoof/);
      assert.doesNotMatch(err.message, /is missing/);
      return true;
    },
  );
});

test("integration: an empty vendor dir → loadWasm says the files are missing and to build them", async (t) => {
  const mod = await packageWithVendor(t, {});
  await assert.rejects(mod.loadWasm(), {
    message: /allw_wasm\.js and allw_wasm_bg\.wasm are missing\. Run `pnpm run build:wasm`/,
  });
});
