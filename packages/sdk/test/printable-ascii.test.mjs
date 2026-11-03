/**
 * The core-free diagnostics escape, `escapeToPrintableAscii` (#358, extracted from #301's WASM load
 * error). It reduces text to printable ASCII (0x20-0x7e) for error messages built before or without
 * the WASM core: every other UTF-16 unit, and the backslash, becomes a `\uXXXX` escape, and an
 * optional bound clips on an escape boundary with an ASCII `...`.
 *
 * @see https://github.com/mike-north/allw/issues/358
 * @see ../src/printable-ascii.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { escapeToPrintableAscii } from "../dist/index.js";

/** Printable ASCII only (0x20-0x7e). */
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/u;

/** U+202E RIGHT-TO-LEFT OVERRIDE, built at runtime so no bidi control sits in this source file. */
const RLO = String.fromCharCode(0x202e);

/** The `\uXXXX` escape of one UTF-16 unit. */
const esc = (hex) => `\\u${hex}`;

test("printable ASCII other than the backslash passes through unchanged", () => {
  const text = "allw: config file /home/u/.allw/config.json ~!@#$%^&*()_+{}|:\"<>?`-=[];',./";
  assert.equal(escapeToPrintableAscii(text), text);
  assert.equal(escapeToPrintableAscii(""), "");
});

test("newlines, ESC, DEL, C1 controls, bidi controls and non-ASCII become \\uXXXX escapes", () => {
  const out = escapeToPrintableAscii(`a\nb\r\u001b[2J\u007f\u0085${RLO}é${String.fromCharCode(0)}`);
  assert.equal(
    out,
    `a${esc("000a")}b${esc("000d")}${esc("001b")}[2J${esc("007f")}${esc("0085")}` +
      `${esc("202e")}${esc("00e9")}${esc("0000")}`,
  );
  assert.match(out, PRINTABLE_ASCII);
});

test("the backslash is escaped, so a literal \\u001b differs from an escaped ESC", () => {
  assert.equal(escapeToPrintableAscii("a\\u001bb"), `a${esc("005c")}u001bb`);
  assert.equal(escapeToPrintableAscii("a\u001bb"), `a${esc("001b")}b`);
});

test("an astral character escapes as its two surrogates", () => {
  assert.equal(escapeToPrintableAscii("\u{1d51e}"), `${esc("d835")}${esc("dd1e")}`);
});

test("without a bound, nothing is clipped", () => {
  const long = "x".repeat(10_000);
  assert.equal(escapeToPrintableAscii(long), long);
});

test("with a bound, the result is clipped with an ASCII '...' and never splits an escape", () => {
  assert.equal(escapeToPrintableAscii("abcdef", 4), "abcd...");
  // Each ESC escapes to 6 characters: 3 fit in 20 (18), a 4th (24) would not.
  assert.equal(escapeToPrintableAscii("\u001b".repeat(10), 20), `${esc("001b").repeat(3)}...`);
});

test("text exactly at the bound is not clipped", () => {
  assert.equal(escapeToPrintableAscii("abcd", 4), "abcd");
  assert.equal(escapeToPrintableAscii("\u001b", 6), esc("001b"));
});
