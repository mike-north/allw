#!/usr/bin/env node
/**
 * Generates `crates/allw-core/src/display/unicode_tables.rs`: the Unicode property tables the
 * core's display escaping (`crates/allw-core/src/display.rs`) depends on, from one version of the
 * Unicode Character Database. Every table in that file comes from the same version, so the core
 * has one Unicode version, recorded as `UNICODE_VERSION`.
 *
 * Tables, and the UCD file each is derived from:
 *
 * - `EMOJI_VARIATION_BASES`: the non-ASCII bases listed with U+FE0E or U+FE0F in
 *   `emoji/emoji-variation-sequences.txt` (the ASCII keycap bases are handled in code);
 * - `UNIFIED_IDEOGRAPH_RANGES`: `Unified_Ideograph` in `PropList.txt`;
 * - `COMBINING_MARK_RANGES`: General_Category `Mn` or `Me` in
 *   `extracted/DerivedGeneralCategory.txt`;
 * - `UNASSIGNED_RANGES`: General_Category `Cn` (unassigned, including noncharacters) in the same
 *   file. The core counts these toward a run of combining marks, so a mark added in a later
 *   Unicode version cannot extend a run unflagged.
 *
 * Ranges are inclusive, sorted, and merged where adjacent.
 *
 * Usage:
 *
 *   node scripts/gen-unicode-tables.mjs <version> [--ucd-dir <dir>]
 *
 * With no `--ucd-dir`, the three files are fetched from
 * `https://www.unicode.org/Public/<version>/ucd/`. With one, they are read from `<dir>` (flat:
 * `DerivedGeneralCategory.txt`, `PropList.txt`, `emoji-variation-sequences.txt`). The output is a
 * pure function of those files, so regenerating from the same version reproduces the same bytes.
 * After regenerating, update the version named in the display docs and run `cargo test`.
 *
 * @see https://www.unicode.org/reports/tr44/ (UCD file formats)
 * @see https://www.unicode.org/reports/tr51/#def_emoji_presentation_sequence
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "crates",
  "allw-core",
  "src",
  "display",
  "unicode_tables.rs",
);

/** The UCD files used, by flat file name, with their path under `ucd/`. */
const FILES = {
  "DerivedGeneralCategory.txt": "extracted/DerivedGeneralCategory.txt",
  "PropList.txt": "PropList.txt",
  "emoji-variation-sequences.txt": "emoji/emoji-variation-sequences.txt",
};

function usage() {
  console.error("usage: node scripts/gen-unicode-tables.mjs <version> [--ucd-dir <dir>]");
  process.exit(2);
}

const args = process.argv.slice(2);
const version = args[0];
if (version === undefined || !/^\d+\.\d+\.\d+$/.test(version)) usage();
let ucdDir;
if (args[1] === "--ucd-dir") {
  ucdDir = args[2];
  if (ucdDir === undefined) usage();
} else if (args.length > 1) {
  usage();
}

/** The text of one UCD file, from `--ucd-dir` or unicode.org. */
async function load(name) {
  if (ucdDir !== undefined) return readFileSync(join(ucdDir, name), "utf8");
  const url = `https://www.unicode.org/Public/${version}/ucd/${FILES[name]}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: HTTP ${String(response.status)}`);
  return response.text();
}

/** The `# Date:` header line of a UCD file, recorded in the output for provenance. */
function dateLine(text, name) {
  const date = /^# Date: (.+)$/m.exec(text)?.[1];
  if (date === undefined) throw new Error(`${name}: no "# Date:" header`);
  return date.trim();
}

/**
 * The data lines of a UCD file as `[lo, hi, fields]`: the code point or range in the first field,
 * then the remaining `;`-separated fields, trimmed, with comments dropped.
 */
function* records(text) {
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*/, "").trim();
    if (line === "") continue;
    const [first, ...rest] = line.split(";").map((f) => f.trim());
    const [lo, hi = lo] = first.split("..").map((h) => Number.parseInt(h, 16));
    yield [lo, hi, rest];
  }
}

/** Sort and merge inclusive ranges, joining adjacent ones. */
function merge(ranges) {
  const sorted = [...ranges].sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const [lo, hi] of sorted) {
    const last = out.at(-1);
    if (last !== undefined && lo <= last[1] + 1) last[1] = Math.max(last[1], hi);
    else out.push([lo, hi]);
  }
  return out;
}

function generalCategoryRanges(text, categories) {
  const ranges = [];
  for (const [lo, hi, [gc]] of records(text)) if (categories.has(gc)) ranges.push([lo, hi]);
  return merge(ranges);
}

function propertyRanges(text, property) {
  const ranges = [];
  for (const [lo, hi, [prop]] of records(text)) if (prop === property) ranges.push([lo, hi]);
  return merge(ranges);
}

/** The non-ASCII bases of the emoji variation sequences (each line is `base selector ; style`). */
function emojiVariationBases(text) {
  const bases = new Set();
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*/, "").trim();
    if (line === "") continue;
    const [base, selector] = line.split(";")[0].trim().split(/\s+/);
    if (selector !== "FE0E" && selector !== "FE0F") continue;
    const cp = Number.parseInt(base, 16);
    if (cp > 0x7f) bases.add(cp);
  }
  return [...bases].sort((a, b) => a - b);
}

const hex = (cp) => cp.toString(16).toUpperCase().padStart(4, "0");
const charLit = (cp) => `'\\u{${hex(cp)}}'`;

/** Rows of `perRow` items, each row indented four spaces and ending in a comma. */
function rows(items, perRow) {
  const out = [];
  for (let i = 0; i < items.length; i += perRow) {
    out.push(`    ${items.slice(i, i + perRow).join(", ")},`);
  }
  return out.join("\n");
}

function rangeTable(doc, name, ranges) {
  return [
    doc,
    "#[rustfmt::skip]",
    `pub(super) const ${name}: [(char, char); ${String(ranges.length)}] = [`,
    rows(
      ranges.map(([lo, hi]) => `(${charLit(lo)}, ${charLit(hi)})`),
      3,
    ),
    "];",
  ].join("\n");
}

const [gcText, propText, evsText] = await Promise.all(Object.keys(FILES).map(load));
const dates = {
  gc: dateLine(gcText, "DerivedGeneralCategory.txt"),
  prop: dateLine(propText, "PropList.txt"),
  evs: dateLine(evsText, "emoji-variation-sequences.txt"),
};
const bases = emojiVariationBases(evsText);
const ideographs = propertyRanges(propText, "Unified_Ideograph");
const marks = generalCategoryRanges(gcText, new Set(["Mn", "Me"]));
const unassigned = generalCategoryRanges(gcText, new Set(["Cn"]));
const base = `https://www.unicode.org/Public/${version}/ucd`;

const source = `// @generated by scripts/gen-unicode-tables.mjs from the Unicode Character Database ${version}.
// Do not edit by hand: run \`node scripts/gen-unicode-tables.mjs ${version}\` to regenerate.

//! Unicode property tables for the display model's escaping rules ([\`super\`]), all from one
//! version of the Unicode Character Database, [\`UNICODE_VERSION\`]. Ranges are inclusive, sorted
//! for binary search, and merged where adjacent.
//!
//! Sources:
//!
//! - \`extracted/DerivedGeneralCategory.txt\` (dated ${dates.gc}):
//!   [\`COMBINING_MARK_RANGES\`] and [\`UNASSIGNED_RANGES\`];
//! - \`PropList.txt\` (dated ${dates.prop}): [\`UNIFIED_IDEOGRAPH_RANGES\`];
//! - \`emoji/emoji-variation-sequences.txt\` (dated ${dates.evs}):
//!   [\`EMOJI_VARIATION_BASES\`].
//!
//! @see <${base}/extracted/DerivedGeneralCategory.txt>
//! @see <${base}/PropList.txt>
//! @see <${base}/emoji/emoji-variation-sequences.txt>

/// The Unicode version every table in this module was generated from.
pub const UNICODE_VERSION: &str = "${version}";

/// The non-ASCII bases of the emoji variation sequences: every code point listed with U+FE0E or
/// U+FE0F in \`emoji-variation-sequences.txt\` (each has both the text and the emoji style). The
/// file's ASCII bases (\`#\`, \`*\`, \`0\`–\`9\`) are left out: a selector after ASCII is shown only in
/// the full keycap form, which the display code handles itself.
#[rustfmt::skip]
pub(super) const EMOJI_VARIATION_BASES: [char; ${String(bases.length)}] = [
${rows(bases.map(charLit), 7)}
];

${rangeTable("/// The code points with the `Unified_Ideograph` property.", "UNIFIED_IDEOGRAPH_RANGES", ideographs)}

${rangeTable(
  "/// The code points whose General_Category is `Mn` (nonspacing mark) or `Me` (enclosing mark).\n/// Includes the variation selectors, which are `Mn`.",
  "COMBINING_MARK_RANGES",
  marks,
)}

${rangeTable(
  "/// The code points whose General_Category is `Cn` (unassigned in this version, including the\n/// noncharacters).",
  "UNASSIGNED_RANGES",
  unassigned,
)}
`;

writeFileSync(OUT, source);
console.log(
  `wrote ${OUT}: Unicode ${version}; ${String(bases.length)} emoji variation bases, ` +
    `${String(ideographs.length)} ideograph ranges, ${String(marks.length)} mark ranges, ` +
    `${String(unassigned.length)} unassigned ranges`,
);
