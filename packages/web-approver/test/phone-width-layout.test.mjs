/**
 * Phone-width layout of the approval card in a real browser engine (B1 of the #309 review).
 *
 * WYSIWYS holds only if the human can see everything the hash binds. At phone width an unwrapped
 * field used to widen the whole card past the viewport. Hash-bound tails and the hidden-character
 * warning then ran off-screen with no marker. This test renders cards for hostile requests through
 * the real WASM runtime and `mountWebApprover`, puts the result under the shipped `tokens.css` and
 * `styles.css` in a 360 px wide iframe, and measures the layout in headless Chrome. It asserts:
 *
 * - nothing extends past the viewport, and nothing scrolls sideways (page or plaintext block);
 * - each tail marker, which sits behind padding or a long unbroken token, is laid out inside the
 *   viewport;
 * - a wrapped row of a value starts indented, never in column 0 where field labels start;
 * - the hidden-character warning is inside the viewport, above the action heading.
 *
 * The audit-history receipt shows the same hash-bound content after the decision, so it is held to
 * the same bar: nothing past the viewport and every tail laid out inside it.
 *
 * It needs a Chrome or Chromium binary (`CHROME_PATH`, the macOS app, or one on `PATH`; GitHub's
 * Ubuntu runners ship `google-chrome`). Without one it skips and says so.
 *
 * @see ../../../docs/threat-model.md R3 (WYSIWYS completeness)
 * @see https://drafts.csswg.org/css-text-3/#overflow-wrap-property
 * @see https://drafts.csswg.org/css-grid-2/#min-size-auto (why the grid track needs `minmax(0, 1fr)`)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { mountAuditWith, mountWith } from "./support/real-runtime.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(here, "..", "public");

/** The phone viewport width under test, in CSS px. */
const VIEWPORT_WIDTH = 360;
const ESC = "\u001b";

/** A Chrome/Chromium binary, or `undefined` when none is installed. */
function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
  ];
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    const found = spawnSync("which", [name], { encoding: "utf8" });
    if (found.status === 0) candidates.push(found.stdout.trim());
  }
  return candidates.find((path) => path !== undefined && path !== "" && existsSync(path));
}

/** A wire `ApprovalContext` for `surface` with `syntactic`. */
function context(surface, syntactic, summary) {
  return {
    action: { record_schema_version: 1, surface, syntactic, risk: "high" },
    summary,
    actor: { id: "machine:laptop", kind: "claude-code" },
    risk: "high",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
}

/** Tail markers: each must end up laid out inside the viewport. */
const MARKERS = ["DROP TABLE users", "TAIL-OF-LONG-PATH", "TAIL-OF-LONG-HOST", "TAIL-OF-SUMMARY"];

const CONTEXTS = [
  // The review's probe: a padded SQL tail in the params of a benign-looking tool call.
  context(
    "mcp_tool_call",
    {
      server: "db",
      tool: "query",
      params: { sql: `SELECT 1${" ".repeat(160)}; DROP TABLE users` },
    },
    "read-only health check",
  ),
  // Long unbroken tokens, plus an ESC so the hidden-character warning shows.
  context(
    "command",
    {
      bin: "cat",
      argv: ["cat", `/srv/${"a".repeat(300)}${ESC}TAIL-OF-LONG-PATH`],
      host: `${"h".repeat(200)}TAIL-OF-LONG-HOST`,
    },
    `${"s".repeat(200)}TAIL-OF-SUMMARY`,
  ),
];

/**
 * The page under test: the mounted DOM under the shipped stylesheets, in a `VIEWPORT_WIDTH` iframe
 * (an iframe is its own viewport, so media queries see the phone width). On load a script measures
 * the layout and writes the JSON result into `#result`, which Chrome's `--dump-dom` returns.
 */
function harnessHtml(appHtml, markers) {
  const css = ["tokens.css", "styles.css"]
    .map((file) => readFileSync(join(PUBLIC_DIR, file), "utf8"))
    .join("\n");
  const page =
    `<!doctype html><html lang="en" class="theme-light"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<style>${css}</style></head><body>${appHtml}</body></html>`;
  const measure = `
    const frame = document.getElementById("frame");
    frame.onload = () => {
      const win = frame.contentWindow;
      const doc = frame.contentDocument;
      const vw = win.innerWidth;
      const out = { vw, docScrollWidth: doc.documentElement.scrollWidth, overflowing: [], markers: {} };
      for (const el of doc.body.querySelectorAll("*")) {
        const r = el.getBoundingClientRect();
        if (r.width === 0 && r.height === 0) continue;
        if (r.left < -0.5 || r.right > vw + 0.5) {
          out.overflowing.push(el.tagName + "." + el.className + " [" + r.left + ", " + r.right + "]");
        }
      }
      out.scrollers = [...doc.querySelectorAll(".approval-plaintext, .approval-card, .audit-wysiwys__pre, .audit-detail")]
        .filter((el) => el.scrollWidth > el.clientWidth + 1)
        .map((el) => el.className);
      const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT);
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        for (const marker of ${JSON.stringify(markers)}) {
          const at = node.data.indexOf(marker);
          if (at < 0) continue;
          const range = doc.createRange();
          range.setStart(node, at);
          range.setEnd(node, at + marker.length);
          const rects = [...range.getClientRects()].map((r) => ({ left: r.left, right: r.right }));
          const line = node.parentElement.closest(".plaintext-line");
          const lineLeft = line ? line.getBoundingClientRect().left : null;
          // One character cell of the line's own font, measured with a probe (not read from CSS).
          let chWidth = null;
          if (line) {
            const probe = doc.createElement("span");
            probe.textContent = "0000000000";
            probe.style.whiteSpace = "pre";
            line.append(probe);
            chWidth = probe.getBoundingClientRect().width / 10;
            probe.remove();
          }
          (out.markers[marker] ??= []).push({ rects, inPlaintext: line !== null, lineLeft, chWidth });
        }
      }
      const badge = doc.querySelector(".hidden-chars-warning");
      const heading = badge?.parentElement.querySelector("h3");
      out.badge = badge
        ? { rect: badge.getBoundingClientRect().toJSON(), headingTop: heading.getBoundingClientRect().top }
        : null;
      document.getElementById("result").textContent = JSON.stringify(out);
    };
    frame.srcdoc = ${JSON.stringify(page).replace(/</g, "\\u003c")};
  `;
  return (
    `<!doctype html><html><body>` +
    `<iframe id="frame" width="${VIEWPORT_WIDTH}" height="2000" style="border:0"></iframe>` +
    `<pre id="result"></pre><script>${measure}</script></body></html>`
  );
}

/** Run the harness in headless Chrome and return the measurements. */
function measureInChrome(chrome, html) {
  const dir = mkdtempSync(join(tmpdir(), "allw-phone-layout-"));
  try {
    const file = join(dir, "harness.html");
    writeFileSync(file, html);
    const run = spawnSync(
      chrome,
      [
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--no-first-run",
        `--user-data-dir=${join(dir, "profile")}`,
        "--virtual-time-budget=5000",
        "--dump-dom",
        pathToFileURL(file).href,
      ],
      { encoding: "utf8", timeout: 60_000, maxBuffer: 64 * 1024 * 1024 },
    );
    const match = /<pre id="result">([^<]*)<\/pre>/.exec(run.stdout ?? "");
    assert.ok(match?.[1], `Chrome produced no measurements (status ${String(run.status)})`);
    // `--dump-dom` HTML-escapes text content.
    const json = match[1].replaceAll("&quot;", '"').replaceAll("&lt;", "<").replaceAll("&gt;", ">");
    return JSON.parse(json.replaceAll("&amp;", "&"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * The shared layout bar: the iframe is the phone viewport, nothing extends past it or scrolls
 * sideways, and every marker is laid out inside it (on an indented row when it follows a wrap in
 * a plaintext block).
 */
function assertNothingOffScreen(m, markers) {
  assert.equal(m.vw, VIEWPORT_WIDTH, "the iframe is the phone viewport");
  assert.ok(m.docScrollWidth <= VIEWPORT_WIDTH, `page scrolls sideways (${m.docScrollWidth})`);
  assert.deepEqual(m.overflowing, [], "no element extends past the viewport");
  assert.deepEqual(m.scrollers, [], "no card, pane or plaintext block scrolls sideways");

  for (const marker of markers) {
    const hits = m.markers[marker];
    assert.ok(hits?.length, `${marker} is rendered`);
    for (const hit of hits) {
      for (const r of hit.rects) {
        assert.ok(
          r.left >= 0 && r.right <= VIEWPORT_WIDTH + 0.5,
          `${marker} is inside the viewport`,
        );
      }
      if (hit.inPlaintext) {
        // Each of these tails comes after a wrap, so it must sit on a hanging-indented row: at
        // least 3ch in from the line's start, never in the label column.
        const first = hit.rects[0];
        assert.ok(
          first.left >= hit.lineLeft + 3 * hit.chWidth,
          `${marker} starts on an indented wrapped row (left ${first.left}, line ${hit.lineLeft})`,
        );
      }
    }
  }
}

const chrome = findChrome();

test(
  `at ${String(VIEWPORT_WIDTH)} px nothing hash-bound is clipped or pushed off-screen`,
  { skip: chrome === undefined ? "no Chrome/Chromium binary found (set CHROME_PATH)" : false },
  async () => {
    const root = await mountWith(CONTEXTS);
    const m = measureInChrome(chrome, harnessHtml(root.outerHTML, MARKERS));

    assertNothingOffScreen(m, MARKERS);

    assert.ok(m.badge, "the hidden-character warning shows");
    assert.ok(
      m.badge.rect.left >= 0 && m.badge.rect.right <= VIEWPORT_WIDTH + 0.5,
      "the hidden-character warning is inside the viewport",
    );
    assert.ok(m.badge.rect.bottom <= m.badge.headingTop, "the warning comes before the action");
  },
);

/** Tail markers on the audit receipt: each must end up laid out inside the viewport. */
const AUDIT_MARKERS = ["TAIL-OF-AUDIT-SUMMARY", "TAIL-OF-AUDIT-CWD", "TAIL-OF-AUDIT-ARG"];

const AUDIT_CONTEXTS = [
  // The #309 round-2 probe: a long unbroken context summary in the receipt's detail pane.
  context(
    "command",
    {
      bin: "deploy",
      argv: ["deploy", `${"x".repeat(300)}TAIL-OF-AUDIT-ARG`],
      cwd: `/srv/${"c".repeat(200)}TAIL-OF-AUDIT-CWD`,
    },
    `${"s".repeat(800)}TAIL-OF-AUDIT-SUMMARY`,
  ),
];

test(
  `at ${String(VIEWPORT_WIDTH)} px the audit receipt keeps every hash-bound tail on-screen`,
  { skip: chrome === undefined ? "no Chrome/Chromium binary found (set CHROME_PATH)" : false },
  async () => {
    const root = await mountAuditWith(AUDIT_CONTEXTS);
    assert.ok(
      root.querySelector(".audit-context-summary"),
      "the receipt shows the context summary",
    );
    const m = measureInChrome(chrome, harnessHtml(root.outerHTML, AUDIT_MARKERS));
    assertNothingOffScreen(m, AUDIT_MARKERS);
  },
);
