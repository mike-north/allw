/**
 * Source hygiene: no raw bidi control characters in the packages' source or tests.
 *
 * allw escapes bidi embeddings, overrides and isolates (U+202A-U+202E, U+2066-U+2069) wherever
 * untrusted text is shown, because they reorder what a reader sees ("Trojan Source"). Our own
 * sources must not carry them raw either: a reviewer can't see them, and a test that means to
 * build one at runtime can silently embed it instead (#368). Write them as `‮` escapes or
 * `String.fromCharCode(0x202e)`.
 *
 * This scans every text file under `packages/<pkg>/src` and `packages/<pkg>/test` (skipping
 * `node_modules`, `dist` and `vendor`) and fails naming each file, line and code point.
 *
 * @see https://trojansource.codes/
 * @see https://www.unicode.org/reports/tr9/ (explicit directional formatting characters)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Bidi embeddings and overrides (U+202A-U+202E) and isolates (U+2066-U+2069). */
const BIDI_CONTROL = /[\u202a-\u202e\u2066-\u2069]/gu;

/** Extensions of the text files the scan reads. */
const TEXT_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".mjs",
  ".cjs",
  ".json",
  ".md",
  ".html",
  ".css",
]);

/** Directory names never scanned: installed, built or vendored output, not our source. */
const SKIPPED_DIRS = new Set(["node_modules", "dist", "vendor"]);

/** Every text file under `dir`, recursively, skipping {@link SKIPPED_DIRS}. */
function textFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name)) files.push(...textFiles(path));
    } else if (entry.isFile() && TEXT_EXTENSIONS.has(extname(entry.name))) {
      files.push(path);
    }
  }
  return files;
}

/**
 * Each raw bidi control under `<root>/packages/<pkg>/{src,test}`, as `<file>:<line> U+XXXX` with the
 * file relative to `root`.
 */
export function findRawBidiControls(root) {
  const found = [];
  const packagesDir = join(root, "packages");
  for (const pkg of readdirSync(packagesDir, { withFileTypes: true })) {
    if (!pkg.isDirectory()) continue;
    for (const sub of ["src", "test"]) {
      let files;
      try {
        files = textFiles(join(packagesDir, pkg.name, sub));
      } catch (err) {
        if (err.code === "ENOENT") continue;
        throw err;
      }
      for (const file of files) {
        const lines = readFileSync(file, "utf8").split("\n");
        lines.forEach((line, i) => {
          for (const match of line.matchAll(BIDI_CONTROL)) {
            const hex = match[0].codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
            found.push(`${relative(root, file)}:${String(i + 1)} U+${hex}`);
          }
        });
      }
    }
  }
  return found;
}

test("the scan finds a planted bidi control, and ignores dist and node_modules", (t) => {
  const root = mkdtempSync(join(tmpdir(), "allw-bidi-scan-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const rlo = String.fromCharCode(0x202e);
  const lri = String.fromCharCode(0x2066);
  for (const dir of [
    "packages/a/src/lib",
    "packages/a/test",
    "packages/a/dist",
    "packages/a/src/node_modules/x",
  ]) {
    mkdirSync(join(root, dir), { recursive: true });
  }
  writeFileSync(join(root, "packages/a/src/lib/x.ts"), `const ok = 1;\nconst s = "${rlo}";\n`);
  writeFileSync(join(root, "packages/a/test/y.test.mjs"), `// ${lri}\n`);
  writeFileSync(join(root, "packages/a/dist/x.js"), `"${rlo}"`);
  writeFileSync(join(root, "packages/a/src/node_modules/x/index.js"), `"${rlo}"`);
  // An escape written as text (backslash, u, 202e) is the allowed spelling, not a control.
  writeFileSync(join(root, "packages/a/src/clean.ts"), 'const s = "\\u202e";\n');
  assert.deepEqual(findRawBidiControls(root).sort(), [
    "packages/a/src/lib/x.ts:2 U+202E",
    "packages/a/test/y.test.mjs:1 U+2066",
  ]);
});

test("no package source or test file contains a raw bidi control", () => {
  assert.deepEqual(
    findRawBidiControls(REPO_ROOT),
    [],
    "write bidi controls as \\u escapes or String.fromCharCode(...), never raw",
  );
});
