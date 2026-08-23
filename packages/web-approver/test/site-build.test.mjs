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
 * @see ../scripts/build-site.mjs
 * @see ../src/app.ts
 * @see ../../../docs/web-approver-deploy.md
 */

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before, describe } from "node:test";
import { pathToFileURL } from "node:url";

import { buildSite } from "../scripts/build-site.mjs";

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

  test("the bundled app.js does not embed a literal relay URL at build time", () => {
    const bundle = readFileSync(join(outDir, "app.js"), "utf8");
    assert.doesNotMatch(
      bundle,
      /https:\/\/allw-relay/,
      "the relay URL must be resolved at runtime (query param / storage), never baked into the bundle",
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
