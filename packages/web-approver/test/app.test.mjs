/**
 * Unit test for `src/app.ts`'s WASM asset URL construction (issue #180).
 *
 * Verifies the glue/binary URLs are computed as *relative siblings* of the bundled module's own
 * URL (`import.meta.url`), never an absolute path baked at build time — this is what lets the
 * same static bundle be relocated to any subpath or static host (`docs/web-approver-deploy.md`).
 * The heavier integration coverage (actually fetching/instantiating the `.wasm` over real HTTP)
 * lives in `test/site-build.test.mjs`.
 *
 * Importing `../dist/app.js` directly is safe under `node --test`: `app.ts`'s top-level
 * `if (typeof window !== "undefined") { void boot(); }` guard is `false` in Node (no `window`
 * global), so the module's only observable effect on import is exporting the two URL constants.
 *
 * @see ../src/app.ts
 */

import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { WASM_BINARY_URL, WASM_GLUE_URL } from "../dist/app.js";

describe("app.ts WASM asset URLs", () => {
  test("resolve as same-directory 'vendor/allw-wasm' siblings, not an absolute build-time path", () => {
    assert.equal(WASM_GLUE_URL.pathname.endsWith("/vendor/allw-wasm/allw_wasm.js"), true);
    assert.equal(WASM_BINARY_URL.pathname.endsWith("/vendor/allw-wasm/allw_wasm_bg.wasm"), true);
  });

  test("both URLs share the same base directory as each other", () => {
    const glueDir = WASM_GLUE_URL.href.replace(/allw_wasm\.js$/, "");
    const binaryDir = WASM_BINARY_URL.href.replace(/allw_wasm_bg\.wasm$/, "");
    assert.equal(glueDir, binaryDir);
  });
});
