/**
 * Tests for the design-token migration + dark-mode fix (issue #162).
 *
 * `public/styles.css` used to hardcode light-theme hex values instead of referencing
 * `design/web-approver/inbox/tokens.css`'s `var(--…)` custom properties, and `tokens.css` was not
 * vendored into the package at all — so even a `var(--bg)` reference would have resolved to
 * nothing. These tests load the *real* static shell (`public/index.html`, `public/tokens.css`,
 * `public/styles.css`) through jsdom with real stylesheet loading enabled (`resources: "usable"`)
 * — not a hand-built approximation of the CSS cascade — and assert:
 *
 *   - the page defaults to the light theme (`theme-light` on `<html>`) so it is never unstyled
 *     before any script runs;
 *   - the inline theme script upgrades to `theme-dark` when the OS/browser reports a dark
 *     preference (`prefers-color-scheme: dark`), the actual mechanism a browser uses;
 *   - switching between `theme-light`/`theme-dark` changes the *resolved* value of the tokens
 *     `styles.css` depends on (`--bg`, `--ink`) — i.e. dark mode is not just present in
 *     `tokens.css` but actually reachable from the shipped HTML/CSS, which is the bug this issue
 *     fixes.
 *
 * @see ../public/index.html
 * @see ../public/styles.css
 * @see ../../../design/web-approver/inbox/tokens.css (the vendored source of truth, ENG rule 19)
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test, { describe } from "node:test";

import { JSDOM } from "jsdom";

const publicDir = new URL("../public/", import.meta.url).pathname;

/**
 * Load `public/index.html` for real — real stylesheet fetch/parse (`resources: "usable"`), real
 * inline `<script>` execution (`runScripts: "dangerously"`) — with an injected `matchMedia` stub
 * so the dark-preference branch of the theme script is exercised deterministically (jsdom does not
 * implement `matchMedia` itself). `prefersDark` controls what `(prefers-color-scheme: dark)`
 * reports; a fresh listener list is captured so a test can simulate a live preference change.
 */
async function loadIndexHtml({ prefersDark }) {
  const listeners = [];
  const dom = await JSDOM.fromFile(join(publicDir, "index.html"), {
    url: `file://${publicDir}`,
    resources: "usable",
    pretendToBeVisual: true,
    runScripts: "dangerously",
    beforeParse(window) {
      window.matchMedia = (query) => ({
        matches: query.includes("dark") ? prefersDark : !prefersDark,
        media: query,
        addEventListener: (_type, listener) => listeners.push(listener),
        removeEventListener: () => {},
      });
    },
  });
  // Let the linked stylesheets finish loading before assertions run.
  await new Promise((resolve) => setTimeout(resolve, 100));
  return { dom, fireChange: (matches) => listeners.forEach((listener) => listener({ matches })) };
}

describe("web-approver theme (tokens.css migration, issue #162)", () => {
  test("defaults to theme-light on <html> so the page is never unstyled pre-JS", async () => {
    const { dom } = await loadIndexHtml({ prefersDark: false });
    // The static markup itself (before the script runs) carries the class — read the raw file
    // rather than the live DOM to prove the no-JS fallback, not just the post-script state.
    const rawHtml = readFileSync(join(publicDir, "index.html"), "utf8");
    assert.match(rawHtml, /<html[^>]*class="theme-light"/);
    assert.equal(dom.window.document.documentElement.classList.contains("theme-light"), true);
  });

  test("upgrades to theme-dark when the OS/browser reports prefers-color-scheme: dark", async () => {
    const { dom } = await loadIndexHtml({ prefersDark: true });
    const root = dom.window.document.documentElement;
    assert.equal(root.classList.contains("theme-dark"), true);
    assert.equal(root.classList.contains("theme-light"), false);
  });

  test("stays on theme-light when the OS/browser does not report a dark preference", async () => {
    const { dom } = await loadIndexHtml({ prefersDark: false });
    const root = dom.window.document.documentElement;
    assert.equal(root.classList.contains("theme-light"), true);
    assert.equal(root.classList.contains("theme-dark"), false);
  });

  test("follows a live prefers-color-scheme change (matchMedia 'change' event)", async () => {
    const { dom, fireChange } = await loadIndexHtml({ prefersDark: false });
    const root = dom.window.document.documentElement;
    assert.equal(root.classList.contains("theme-light"), true);

    fireChange(true);

    assert.equal(root.classList.contains("theme-dark"), true);
    assert.equal(root.classList.contains("theme-light"), false);
  });

  test("light and dark themes resolve different values for the tokens styles.css depends on", async () => {
    const { dom: lightDom } = await loadIndexHtml({ prefersDark: false });
    const { dom: darkDom } = await loadIndexHtml({ prefersDark: true });

    const lightRoot = lightDom.window.document.documentElement;
    const darkRoot = darkDom.window.document.documentElement;

    const lightBg = lightDom.window.getComputedStyle(lightRoot).getPropertyValue("--bg").trim();
    const darkBg = darkDom.window.getComputedStyle(darkRoot).getPropertyValue("--bg").trim();
    const lightInk = lightDom.window.getComputedStyle(lightRoot).getPropertyValue("--ink").trim();
    const darkInk = darkDom.window.getComputedStyle(darkRoot).getPropertyValue("--ink").trim();

    // Values must actually resolve (tokens.css was vendored and loaded) and must differ between
    // themes (dark mode is reachable, not just defined and unused).
    assert.notEqual(lightBg, "");
    assert.notEqual(darkBg, "");
    assert.notEqual(lightBg, darkBg);
    assert.notEqual(lightInk, "");
    assert.notEqual(darkInk, "");
    assert.notEqual(lightInk, darkInk);

    // Pin to the exact values in the vendored tokens.css (spec-first assertions, not derived from
    // the implementation under test) so a future edit to tokens.css that silently drops the dark
    // palette would fail this test.
    assert.equal(lightBg, "#F1EDE4");
    assert.equal(darkBg, "#080807");
    assert.equal(lightInk, "#1C1A15");
    assert.equal(darkInk, "#F8F5EE");
  });
});
