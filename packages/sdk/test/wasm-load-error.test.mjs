/**
 * The vendored WASM core's load error (#301, item 3).
 *
 * When a vendored file is missing, the error says to build it. When the files are there but loading
 * fails anyway (a glue module that throws, a corrupt `.wasm`), it quotes the underlying cause
 * instead of always saying `pnpm run build:wasm`. The cause is untrusted text that can reach a
 * terminal or a hook's deny reason, and the display-escaping core is what failed to load, so the
 * cause is reduced to bounded printable ASCII: every other UTF-16 unit, and the backslash, becomes a
 * `\uXXXX` escape, and the result is clipped to `MAX_WASM_LOAD_CAUSE_CHARS` on an escape boundary,
 * with an ASCII `...` when cut.
 *
 * The unit tests drive `wasmLoadError` with an injected file-existence check. The integration
 * tests load a copy of the built `dist/wasm.js` (and the escaper it imports) against a temporary vendor directory (so the
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

const DIST = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");

/** The built modules the loader needs: `wasm.js` and the escaper it imports. */
const DIST_MODULES = ["wasm.js", "printable-ascii.js"];
const DIR = "/opt/allw/vendor/allw-wasm";

const allPresent = () => true;

/** Printable ASCII only (0x20-0x7e): no control characters and nothing outside ASCII. */
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/u;

/** U+202E RIGHT-TO-LEFT OVERRIDE, built at runtime so no bidi control sits in this source file. */
const RLO = String.fromCharCode(0x202e);

/** The `\uXXXX` escape of one UTF-16 unit, as the loader writes it. */
const esc = (hex) => `\\u${hex}`;

/** The quoted cause in a files-present message: `... from <dir> (<cause>). The vendored ...`. */
function quotedCause(message) {
  const open = `${DIR} (`;
  const close = "). The vendored files are present";
  const start = message.indexOf(open);
  const end = message.lastIndexOf(close);
  assert.ok(start >= 0 && end > start, `message has a quoted cause: ${message}`);
  return message.slice(start + open.length, end);
}

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
  assert.equal(quotedCause(err.message), "SyntaxError: Unexpected token 'export'");
  assert.doesNotMatch(err.message, /is missing|are missing/);
  assert.equal(err.cause, cause, "the original error stays reachable as the cause");
});

test("control characters and non-ASCII in the cause are escaped, never passed through", () => {
  const err = wasmLoadError(
    DIR,
    new Error(`line one\nallw: APPROVED\r\u001b[2J${RLO}evil`),
    allPresent,
  );
  assert.match(err.message, PRINTABLE_ASCII, err.message);
  assert.equal(
    quotedCause(err.message),
    `Error: line one${esc("000a")}allw: APPROVED${esc("000d")}${esc("001b")}[2J${esc("202e")}evil`,
  );
});

test("a backslash is escaped too, so a literal \\u001b in a cause differs from an escaped ESC", () => {
  const literal = wasmLoadError(DIR, new Error("a\\u001bb"), allPresent);
  const real = wasmLoadError(DIR, new Error("a\u001bb"), allPresent);
  assert.equal(quotedCause(literal.message), `Error: a${esc("005c")}u001bb`);
  assert.equal(quotedCause(real.message), `Error: a${esc("001b")}b`);
  assert.notEqual(quotedCause(literal.message), quotedCause(real.message));
});

test("an astral character escapes as its two surrogates", () => {
  const err = wasmLoadError(DIR, new Error("\u{1d51e}"), allPresent);
  assert.equal(quotedCause(err.message), `Error: ${esc("d835")}${esc("dd1e")}`);
});

test("a long cause is clipped to the bound with an ASCII '...', and stays printable ASCII", () => {
  const err = wasmLoadError(DIR, new Error("x".repeat(10_000)), allPresent);
  assert.match(err.message, PRINTABLE_ASCII);
  assert.equal(
    quotedCause(err.message),
    `Error: ${"x".repeat(MAX_WASM_LOAD_CAUSE_CHARS - "Error: ".length)}...`,
  );
});

test("the clip never splits an escape sequence", () => {
  // Each ESC escapes to 6 characters and "Error: " is 7, so the 200-character bound falls inside
  // the 33rd escape: 7 + 32 * 6 = 199 fits, 205 would not.
  const err = wasmLoadError(DIR, new Error("\u001b".repeat(1_000)), allPresent);
  assert.match(err.message, PRINTABLE_ASCII);
  assert.equal(quotedCause(err.message), `Error: ${esc("001b").repeat(32)}...`);
});

test("a cause exactly at the bound is not clipped", () => {
  const message = "y".repeat(MAX_WASM_LOAD_CAUSE_CHARS - "Error: ".length);
  const err = wasmLoadError(DIR, new Error(message), allPresent);
  assert.equal(quotedCause(err.message), `Error: ${message}`);
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

/** A package-shaped temp dir: the loader's `dist/` modules (copied) beside `vendor/allw-wasm/` (as given). */
function packageWithVendor(t, files) {
  const root = mkdtempSync(join(tmpdir(), "allw-wasm-load-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "dist"));
  for (const name of DIST_MODULES) copyFileSync(join(DIST, name), join(root, "dist", name));
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
      assert.ok(
        err.message.includes(`Error: glue exploded${esc("000a")}${esc("001b")}[31mspoof`),
        err.message,
      );
      assert.doesNotMatch(err.message, /is missing/);
      assert.ok(
        PRINTABLE_ASCII.test(err.message.replace(/^.*?\(/su, "(")),
        "the quoted part is ASCII",
      );
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
