/**
 * Integration tests for the production static-site bundle (issue #180).
 *
 * These exercise the *real* artifact `scripts/build-site.mjs` produces — not an approximation:
 * the esbuild output is served over a real `http` server and the vendored WASM is fetched and
 * instantiated through the browser-shaped code path (`initWasm` in `src/wasm.ts`, via the same
 * `--target web` glue's `default()` init), never read from disk the way `test/wasm-helper.mjs`
 * does for the rest of the suite. This directly covers the acceptance criterion "the SDK's WASM
 * core must load correctly from a static host, not just from a Node `pnpm test` context."
 *
 * Requires the vendored WASM (`pnpm run build:wasm`, gitignored) to exist; when it does not
 * (e.g. `pnpm --filter @allw/web-approver test` run standalone before the workspace-level wasm
 * build step) these tests are skipped with a clear reason rather than failing — the same
 * precondition `scripts/build-site.mjs` itself checks. CI's `wasm` job runs `pnpm run build:wasm`
 * before `pnpm -r test`, so this suite runs for real there (`.github/workflows/ci.yml`).
 *
 * It also covers the hosted site's response headers (issue #249): `_headers` ships in the bundle
 * with a strict Content-Security-Policy whose `connect-src` relay list is set at build time, and
 * `index.html` carries no inline script for that policy to have to allow.
 *
 * @see ../scripts/build-site.mjs
 * @see ../src/app.ts
 * @see ../../../docs/web-approver-deploy.md
 * @see https://developers.cloudflare.com/pages/configuration/headers/
 * @see https://www.w3.org/TR/CSP3/
 * @see ../../sdk/test/fixtures/relay-url-vectors.json (shared with the SDK and the runtime rule)
 */

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before, describe } from "node:test";
import { pathToFileURL } from "node:url";

import {
  DEFAULT_RELAY_ORIGINS,
  buildSite,
  relayConnectSources,
  renderHeaders,
} from "../scripts/build-site.mjs";

const vendorWasmBinary = new URL("../../sdk/vendor/allw-wasm/allw_wasm_bg.wasm", import.meta.url)
  .pathname;
const wasmAvailable = existsSync(vendorWasmBinary);

if (!wasmAvailable) {
  console.warn(
    "[site-build.test.mjs] skipping — vendored WASM not found. Run 'pnpm run build:wasm' from " +
      "the repo root first.",
  );
}

describe("site bundle (build-site.mjs)", { skip: !wasmAvailable }, () => {
  let outDir;
  let server;
  let baseUrl;

  before(async () => {
    outDir = mkdtempSync(join(tmpdir(), "allw-web-approver-site-"));
    const result = await buildSite({ outDir });
    assert.equal(result.built, true, "buildSite must actually build when wasm is present");

    server = createServer((req, res) => {
      const requestedPath = req.url === "/" ? "/index.html" : req.url;
      const filePath = join(outDir, decodeURIComponent(requestedPath));
      try {
        const body = readFileSync(filePath);
        res.writeHead(200, { "content-type": contentTypeFor(filePath) });
        res.end(body);
      } catch {
        res.writeHead(404);
        res.end("not found");
      }
    });
    await new Promise((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    baseUrl = `http://127.0.0.1:${String(address.port)}`;
  });

  after(async () => {
    await new Promise((resolve) => {
      server.close(resolve);
    });
    rmSync(outDir, { recursive: true, force: true });
  });

  test("produces the expected flat static-file layout", () => {
    for (const relativePath of [
      "index.html",
      "theme.js",
      "_headers",
      "tokens.css",
      "styles.css",
      "app.js",
      "vendor/allw-wasm/allw_wasm.js",
      "vendor/allw-wasm/allw_wasm_bg.wasm",
    ]) {
      assert.ok(existsSync(join(outDir, relativePath)), `${relativePath} must exist in the bundle`);
    }
  });

  test("index.html references the bundled app.js as a same-directory sibling", () => {
    const html = readFileSync(join(outDir, "index.html"), "utf8");
    assert.match(html, /<script[^>]*type="module"[^>]*src="\.\/app\.js"/);
  });

  // Criterion (issue #162): tokens.css must ride into the built site output — the whole point of
  // vendoring it is that the deployed static bundle (not just the local dev checkout) resolves
  // styles.css's var(--…) declarations.
  test("the bundled tokens.css is an exact copy of the design source of truth (issue #162)", () => {
    const bundled = readFileSync(join(outDir, "tokens.css"), "utf8");
    const designSource = readFileSync(
      new URL("../../../design/web-approver/inbox/tokens.css", import.meta.url),
      "utf8",
    );
    assert.equal(bundled, designSource, "tokens.css must be vendored verbatim (ENG rule 19)");
  });

  test("index.html links tokens.css before styles.css so the custom properties are defined first", () => {
    const html = readFileSync(join(outDir, "index.html"), "utf8");
    const tokensIndex = html.indexOf('href="./tokens.css"');
    const stylesIndex = html.indexOf('href="./styles.css"');
    assert.ok(tokensIndex >= 0, "index.html must link tokens.css");
    assert.ok(stylesIndex >= 0, "index.html must link styles.css");
    assert.ok(tokensIndex < stylesIndex, "tokens.css must be linked before styles.css");
  });

  test("index.html defaults to theme-light and upgrades to theme-dark via prefers-color-scheme", () => {
    const html = readFileSync(join(outDir, "index.html"), "utf8");
    assert.match(
      html,
      /<html[^>]*class="theme-light"/,
      "the <html> element must default to theme-light so the page is never unstyled before JS runs",
    );
    assert.match(html, /<script src="\.\/theme\.js"><\/script>/, "index.html loads theme.js");
    assert.match(
      readFileSync(join(outDir, "theme.js"), "utf8"),
      /prefers-color-scheme:\s*dark/,
      "theme.js must switch to theme-dark based on the OS/browser color-scheme preference",
    );
  });

  // Criterion (issue #249): no inline script, so the CSP never has to allow 'unsafe-inline'.
  test("index.html contains no inline <script> body (source and bundle)", () => {
    for (const html of [
      readFileSync(join(outDir, "index.html"), "utf8"),
      readFileSync(new URL("../public/index.html", import.meta.url), "utf8"),
    ]) {
      const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
      assert.ok(scripts.length >= 2, "theme.js and app.js are both loaded");
      for (const [, attributes, body] of scripts) {
        assert.match(attributes, /\bsrc="/, "every <script> must load a file");
        assert.equal(body.trim(), "", "no <script> may carry an inline body");
      }
      assert.doesNotMatch(html, /\son[a-z]+\s*=/i, "no inline event-handler attributes");
    }
  });

  // Criterion (issue #249): the hosted site ships a strict CSP and companion headers.
  test("_headers sets the strict CSP, nosniff, and no-referrer for every path", () => {
    const headers = readFileSync(join(outDir, "_headers"), "utf8");
    const lines = headers.split("\n").filter((line) => !line.startsWith("#"));
    assert.equal(
      lines.find((line) => line.trim().length > 0),
      "/*",
      "rules apply to every path",
    );

    const csp = lines.find((line) => line.trim().startsWith("Content-Security-Policy:"));
    assert.ok(csp, "_headers must set Content-Security-Policy");
    const directives = new Map(
      csp
        .trim()
        .slice("Content-Security-Policy:".length)
        .split(";")
        .map((directive) => directive.trim().split(/\s+/))
        .map(([name, ...sources]) => [name, sources]),
    );
    assert.deepEqual(directives.get("default-src"), ["'self'"]);
    assert.deepEqual(directives.get("script-src"), ["'self'", "'wasm-unsafe-eval'"]);
    assert.deepEqual(directives.get("connect-src"), [
      "'self'",
      "https://allw-relay.mnorth.workers.dev",
      "wss://allw-relay.mnorth.workers.dev",
    ]);
    assert.deepEqual(directives.get("object-src"), ["'none'"]);
    assert.deepEqual(directives.get("base-uri"), ["'none'"]);
    assert.deepEqual(directives.get("frame-ancestors"), ["'none'"]);
    assert.ok(!csp.includes("unsafe-inline"), "the CSP must not allow inline script or style");
    assert.ok(!csp.includes("__ALLW_"), "the relay placeholder must be substituted");

    assert.ok(lines.some((line) => line.trim() === "X-Content-Type-Options: nosniff"));
    assert.ok(lines.some((line) => line.trim() === "Referrer-Policy: no-referrer"));
  });

  test("styles.css contains no hardcoded hex/rgb color literals (issue #162 — must use var(--…) tokens)", () => {
    const css = readFileSync(join(outDir, "styles.css"), "utf8");
    // Strip comments first so an issue-number reference like "issue #162" in a comment heading
    // doesn't false-positive as a hex color literal.
    const withoutComments = css.replace(/\/\*[\s\S]*?\*\//g, "");
    const hexMatches = withoutComments.match(/#[0-9a-fA-F]{3,8}\b/g) ?? [];
    const rgbMatches = withoutComments.match(/rgba?\(/g) ?? [];
    assert.deepEqual(hexMatches, [], "styles.css must not contain literal hex colors");
    assert.deepEqual(rgbMatches, [], "styles.css must not contain literal rgb()/rgba() colors");
  });

  test("the bundled app.js does not embed a literal relay URL at build time", () => {
    const bundle = readFileSync(join(outDir, "app.js"), "utf8");
    assert.doesNotMatch(
      bundle,
      /https:\/\/allw-relay/,
      "the relay URL must be resolved at runtime (query param / storage), never baked into the bundle",
    );
  });

  test("the bundled theme.js is the public/ source verbatim", () => {
    assert.equal(
      readFileSync(join(outDir, "theme.js"), "utf8"),
      readFileSync(new URL("../public/theme.js", import.meta.url), "utf8"),
    );
  });

  test("the .wasm asset is served with the correct content-type over real HTTP", async () => {
    const response = await fetch(`${baseUrl}/vendor/allw-wasm/allw_wasm_bg.wasm`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "application/wasm");
    const served = new Uint8Array(await response.arrayBuffer());
    const onDisk = readFileSync(join(outDir, "vendor", "allw-wasm", "allw_wasm_bg.wasm"));
    assert.deepEqual(
      served,
      new Uint8Array(onDisk),
      "served bytes must match the on-disk artifact",
    );
  });

  test("the browser-shaped fetch-based loader (initWasm) instantiates the .wasm served over real HTTP", async () => {
    // The glue module is loaded from the bundle output on disk (a real dynamic `import()`, the
    // same mechanism `app.ts` uses at runtime, just via a `file://` URL — Node's ESM loader does
    // not support importing `http://` module specifiers). What matters for this criterion is the
    // *binary*: it is fetched and instantiated via `fetch()` against the real HTTP server below,
    // exercising the exact browser code path (`initWasm` → `glue.default(url)` → `fetch(url)` →
    // `WebAssembly.instantiateStreaming`/`instantiate`) rather than `initWasmSync`'s Node
    // fs-read + `WebAssembly.Module` path `test/wasm-helper.mjs` uses for the rest of the suite.
    const gluePath = join(outDir, "vendor", "allw-wasm", "allw_wasm.js");
    const glue = await import(pathToFileURL(gluePath).href);

    const { initWasm, resetWasmForTests } = await import("../dist/index.js");
    resetWasmForTests();
    const wasm = await initWasm(glue, `${baseUrl}/vendor/allw-wasm/allw_wasm_bg.wasm`);

    const seed = Buffer.alloc(32, 0x07).toString("base64url");
    const pubkey = wasm.x25519_public_key(seed);
    assert.equal(typeof pubkey, "string");
    // 32 raw bytes, base64url-unpadded — 43 chars (ceil(32*4/3) with no '=' padding).
    assert.equal(pubkey.length, 43);
  });
});

function contentTypeFor(filePath) {
  if (filePath.endsWith(".wasm")) return "application/wasm";
  if (filePath.endsWith(".js")) return "text/javascript";
  if (filePath.endsWith(".html")) return "text/html";
  if (filePath.endsWith(".css")) return "text/css";
  return "application/octet-stream";
}

// ── Build-time relay list for connect-src (#249) ────────────────────────────────────────────────
// Pure validation — no WASM needed, so these run even when the site bundle tests are skipped.

describe("relayConnectSources (build-time CSP relay list)", () => {
  test("defaults to the hosted relay", () => {
    assert.deepEqual(DEFAULT_RELAY_ORIGINS, ["https://allw-relay.mnorth.workers.dev"]);
  });

  test("emits each origin with its WebSocket form, deduplicated", () => {
    assert.deepEqual(
      relayConnectSources([
        "https://relay.example.com",
        "https://relay.example.com/",
        "http://127.0.0.1:8787",
      ]),
      [
        "https://relay.example.com",
        "wss://relay.example.com",
        "http://127.0.0.1:8787",
        "ws://127.0.0.1:8787",
      ],
    );
  });

  for (const wildcard of ["https://*", "https://*.workers.dev", "https://a.com;sandbox"]) {
    test(`rejects ${wildcard} — CSP syntax must never reach connect-src`, () => {
      assert.throws(() => relayConnectSources([wildcard]), /must have a plain DNS hostname/);
    });
  }

  test("rejects [::1] with a pointer to 127.0.0.1 (no IPv6 host-source in CSP)", () => {
    assert.throws(
      () => relayConnectSources(["http://[::1]:8787"]),
      /IPv6 address.*use a DNS name, or http:\/\/127\.0\.0\.1/,
    );
  });

  test("rejects plaintext http:// to a remote relay (http://relay.example.com)", () => {
    assert.throws(() => relayConnectSources(["http://relay.example.com"]), /must use https:\/\//);
  });

  test("rejects an origin with a path (connect-src takes origins)", () => {
    assert.throws(
      () => relayConnectSources(["https://relay.example.com/acct"]),
      /must be a bare origin/,
    );
  });

  test("rejects a value that is not an absolute URL", () => {
    assert.throws(() => relayConnectSources(["relay.example.com"]), /not an absolute URL/);
  });

  test("rejects an empty list", () => {
    assert.throws(() => relayConnectSources([]), /at least one relay origin/);
  });
});

describe("renderHeaders", () => {
  const template = readFileSync(new URL("../public/_headers", import.meta.url), "utf8");

  test("rejects a relay list that pushes a line past Cloudflare's 2,000-character limit", () => {
    const many = Array.from({ length: 60 }, (_, i) => `https://relay-${String(i)}.example.com`);
    assert.throws(() => renderHeaders(template, many), /Cloudflare Pages allows 2000/);
  });

  test("rejects a template without the relay placeholder", () => {
    assert.throws(
      () => renderHeaders("/*\n  X-Content-Type-Options: nosniff\n", DEFAULT_RELAY_ORIGINS),
      /missing __ALLW_RELAY_CONNECT_SRC__/,
    );
  });
});

describe("buildSite with a self-hosted relay list", { skip: !wasmAvailable }, () => {
  test("relayOrigins replaces the hosted relay in connect-src", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "allw-web-approver-site-selfhost-"));
    try {
      await buildSite({ outDir, relayOrigins: ["https://relay.selfhost.example"] });
      const headers = readFileSync(join(outDir, "_headers"), "utf8");
      assert.match(
        headers,
        /connect-src 'self' https:\/\/relay\.selfhost\.example wss:\/\/relay\.selfhost\.example;/,
      );
      assert.doesNotMatch(headers, /connect-src[^;]*allw-relay\.mnorth\.workers\.dev/);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  test("an insecure relay origin fails the build before anything is written", async () => {
    const outDir = join(tmpdir(), "allw-web-approver-site-never-written");
    rmSync(outDir, { recursive: true, force: true });
    await assert.rejects(
      buildSite({ outDir, relayOrigins: ["http://relay.example.com"] }),
      /must use https:\/\//,
    );
    assert.equal(existsSync(outDir), false);
  });
});

/** The accept/reject vectors shared with the SDK's `createClient` and the runtime rule. */
const { vectors: relayUrlVectors } = JSON.parse(
  readFileSync(new URL("../../sdk/test/fixtures/relay-url-vectors.json", import.meta.url), "utf8"),
);

describe("relayConnectSources — shared vectors (#249)", () => {
  for (const { input, build, canonical, why } of relayUrlVectors) {
    test(`${build}s ${JSON.stringify(input)} (${why})`, () => {
      if (build === "accept") {
        const origin = canonical;
        assert.deepEqual(relayConnectSources([input]), [origin, origin.replace(/^http/, "ws")]);
      } else {
        assert.throws(() => relayConnectSources([input]), /^Error: \[web-approver\] /);
      }
    });
  }
});
