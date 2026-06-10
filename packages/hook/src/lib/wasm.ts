/**
 * Loads the vendored `allw-wasm` core (the audited Rust core, compiled to WebAssembly) and exposes
 * the typed subset of its FFI the hook uses to build an `ActionRecord` from a pending tool call.
 *
 * # Why WASM-under-node (a hard constraint, not a preference)
 * On-machine `allw` code runs as **WASM under node**, never a standalone native binary, so
 * enterprise binary-allowlisting (Santa) and MDM cannot block it (`docs/architecture.md`). The
 * hook therefore never reimplements `ActionRecord` construction — both builders are the audited
 * core's, reached through this surface. (Crypto is reached through `@allw/sdk`, which loads the
 * same vendored artifact.)
 *
 * # Loading
 * Mirrors `packages/approver/src/lib/wasm.ts`: the `--target web` glue is loaded synchronously by
 * compiling the `.wasm` bytes into a `WebAssembly.Module` and calling `initSync` — one ESM artifact
 * works in both node and the browser/worker. The wasm is built once from the repo root
 * (`pnpm run build:wasm`) into `packages/sdk/vendor/allw-wasm`; the hook resolves that single
 * vendored artifact (no second copy to drift).
 *
 * @see ../../../approver/src/lib/wasm.ts (the loader pattern this mirrors)
 * @see ../../../../docs/architecture.md (WASM-local hard constraint)
 * @see ../../../../docs/policy-seam.md §The three tiers (the ActionRecord substrate)
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, parse as parsePath } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/**
 * The exact subset of the `allw-wasm` FFI the hook depends on: the two `ActionRecord` builders.
 * Both take strings (the language-agnostic wire contract) and return an `ActionRecord` as JSON;
 * a malformed input **throws** (fail-closed at the boundary). Mirrors `crates/allw-wasm/src/lib.rs`.
 */
export interface HookWasm {
  /**
   * Build an `ActionRecord` JSON for a shell command (the `command` surface). `cwd` is the working
   * directory at invocation, or omitted/`null` when unknown. **Throws** on invalid shell syntax
   * (unmatched quotes) — the hook denies rather than guessing.
   */
  action_from_command(commandLine: string, cwd?: string | null): string;
  /**
   * Build an `ActionRecord` JSON for an MCP tool call (the `mcp_tool_call` surface). `paramsJson`
   * is the tool parameters as a JSON string. **Throws** on invalid JSON — the hook denies rather
   * than submitting a record built from unparseable parameters.
   */
  action_from_mcp_tool_call(server: string, tool: string, paramsJson: string): string;
}

/** The `--target web` glue module shape we depend on (subset of the generated bindings). */
interface WasmGlue extends HookWasm {
  initSync(input: { module: WebAssembly.Module }): unknown;
}

/** The directory of this module — the anchor for resolving the vendored wasm. */
const moduleDir = dirname(fileURLToPath(import.meta.url));

/** The vendored wasm directory, relative to a repo root: `packages/sdk/vendor/allw-wasm`. */
const VENDOR_REL = join("packages", "sdk", "vendor", "allw-wasm");

/**
 * Resolve the directory holding the vendored wasm artifact. The wasm is vendored once under the
 * `@allw/sdk` package (`packages/sdk/vendor/allw-wasm`, built by `pnpm run build:wasm`) so there is
 * a single source of truth across surfaces. Resolution walks **up** from this module's directory,
 * working identically whether the hook runs from `src/` (tests) or `dist/` (compiled).
 *
 * @throws if the vendored wasm cannot be found (run `pnpm run build:wasm` from the repo root).
 */
function resolveVendorDir(): string {
  let dir = moduleDir;
  for (;;) {
    const candidate = join(dir, VENDOR_REL);
    if (existsSync(join(candidate, "allw_wasm_bg.wasm"))) return candidate;
    const parent = dirname(dir);
    if (parent === dir || parent === parsePath(dir).root) {
      const rootCandidate = join(parent, VENDOR_REL);
      if (existsSync(join(rootCandidate, "allw_wasm_bg.wasm"))) return rootCandidate;
      throw new Error(
        `vendored wasm not found (looked for ${VENDOR_REL} above ${moduleDir}). ` +
          "Run 'pnpm run build:wasm' from the repo root first.",
      );
    }
    dir = parent;
  }
}

let cached: HookWasm | undefined;

/**
 * Load (and memoize) the WASM core. Synchronous instantiation after a dynamic import of the glue;
 * idempotent — repeated calls return the same initialized module.
 *
 * @throws if the vendored wasm is missing (run `pnpm run build:wasm` from the repo root first).
 */
export async function loadWasm(): Promise<HookWasm> {
  if (cached) return cached;
  const vendorDir = resolveVendorDir();
  // A bare path is not a valid ESM specifier on Windows; use a file:// URL (cross-platform parity).
  const gluePath = join(vendorDir, "allw_wasm.js");
  const glue = (await import(pathToFileURL(gluePath).href)) as WasmGlue;
  const bytes = readFileSync(join(vendorDir, "allw_wasm_bg.wasm"));
  const module = new WebAssembly.Module(bytes);
  glue.initSync({ module });
  cached = glue;
  return glue;
}
