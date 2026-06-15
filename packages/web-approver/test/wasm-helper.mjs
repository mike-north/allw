/**
 * Test-only loader for the vendored `allw-wasm` core, mirroring the Node loader pattern in
 * `packages/approver/src/lib/wasm.ts` and `packages/sdk/src/wasm.ts`.
 *
 * The browser runtime path is `initWasm(glue, fetchableUrl)`; under `node --test` there is no
 * `fetch`-served asset, so this helper resolves the vendored `--target web` glue + bytes via the
 * installed `@allw/sdk` package and instantiates synchronously through `initWasmSync`. The same
 * vendored artifact (`pnpm run build:wasm`) backs both paths — there is no second copy to drift.
 *
 * @see ../../sdk/test/wasm.test.mjs
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { initWasmSync, resetWasmForTests } from "../dist/index.js";

/** Resolve the vendored wasm directory via the installed `@allw/sdk` exports subpath. */
function vendorDir() {
  const wasmUrl = import.meta.resolve("@allw/sdk/vendor/allw-wasm/allw_wasm_bg.wasm");
  return dirname(fileURLToPath(wasmUrl));
}

/**
 * Load and initialize the WASM core for tests. Resets the memoized instance first so a suite that
 * imports this gets a fresh init regardless of prior callers.
 */
export async function loadTestWasm() {
  resetWasmForTests();
  const dir = vendorDir();
  const glue = await import(pathToFileURL(join(dir, "allw_wasm.js")).href);
  const bytes = readFileSync(join(dir, "allw_wasm_bg.wasm"));
  const module = new WebAssembly.Module(bytes);
  return initWasmSync(glue, module);
}
