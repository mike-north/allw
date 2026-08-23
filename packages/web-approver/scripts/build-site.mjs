/**
 * Bundle the web approver into a deployable static site (issue #180).
 *
 * Bundles `src/app.ts` (the production bootstrap — `../src/app.ts`) into `dist-site/app.js` with
 * esbuild, copies the vendored `allw-wasm` browser artifact next to it (so `app.ts`'s
 * `import.meta.url`-relative asset URLs resolve on any static host, at any subpath), and copies
 * the static `public/` shell (`index.html`, `styles.css`) alongside. The result is a flat
 * directory of plain static files — no server-side runtime, no Cloudflare-specific API — hostable
 * on Cloudflare Pages or any static host (`docs/web-approver-deploy.md`).
 *
 * # Why esbuild (not Vite)
 * The repo's existing tooling taste is plain `tsc` plus small `scripts/*.mjs` (e.g.
 * `scripts/postbuild-wasm.mjs`); esbuild's JS API composes with that directly (one function call,
 * no dev-server/plugin ecosystem, no new config file format to introduce), and esbuild's
 * postinstall lifecycle script is already allow-listed at the workspace root
 * (`pnpm.onlyBuiltDependencies` in the root `package.json`), so this introduces no new tooling
 * category to the workspace.
 *
 * # Why this is not wired into `tsc`/typecheck/lint
 * The vendored WASM (`pnpm run build:wasm`, gitignored — see `../../../.gitignore`) is a
 * build-time prerequisite for the site bundle *only*: `tsc`/typecheck/lint must keep working
 * before wasm is built, because CI's `typescript` job runs `pnpm -r build` before any wasm step
 * (`.github/workflows/ci.yml`). This script is invoked as a chained step of `package.json`'s
 * `build` script (after `tsc`), and when the vendor artifact is absent it skips the bundle with a
 * clear message and exits 0 rather than failing the whole `pnpm -r build`. The `wasm` CI job
 * (which does build wasm first) explicitly re-runs `pnpm --filter @allw/web-approver build`
 * afterward so the real bundle is exercised in CI, not just this best-effort local skip.
 *
 * @see ../src/app.ts (the bundled entry point)
 * @see ../../../scripts/postbuild-wasm.mjs (the sibling small-script convention this follows)
 */

import { build } from "esbuild";
import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageDir = dirname(dirname(fileURLToPath(import.meta.url)));
const vendorDir = join(packageDir, "..", "sdk", "vendor", "allw-wasm");
const defaultOutDir = join(packageDir, "dist-site");

/**
 * Build the static site into `outDir` (defaults to `dist-site/` next to this package). Returns
 * `{ built: false, outDir }` (a no-op) when the vendored WASM has not been built yet, or
 * `{ built: true, outDir }` once the bundle + copied assets are written.
 */
export async function buildSite({ outDir = defaultOutDir } = {}) {
  const wasmBinary = join(vendorDir, "allw_wasm_bg.wasm");
  const wasmGlue = join(vendorDir, "allw_wasm.js");

  if (!existsSync(wasmBinary) || !existsSync(wasmGlue)) {
    console.warn(
      `[web-approver] skipping site bundle — vendored WASM not found at ${vendorDir}. ` +
        "Run 'pnpm run build:wasm' from the repo root, then re-run this build.",
    );
    return { built: false, outDir };
  }

  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  await build({
    entryPoints: [join(packageDir, "src", "app.ts")],
    outfile: join(outDir, "app.js"),
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "browser",
    sourcemap: true,
    minify: true,
    logLevel: "warning",
  });

  const vendorOutDir = join(outDir, "vendor", "allw-wasm");
  mkdirSync(vendorOutDir, { recursive: true });
  cpSync(wasmBinary, join(vendorOutDir, "allw_wasm_bg.wasm"));
  cpSync(wasmGlue, join(vendorOutDir, "allw_wasm.js"));

  cpSync(join(packageDir, "public", "index.html"), join(outDir, "index.html"));
  cpSync(join(packageDir, "public", "styles.css"), join(outDir, "styles.css"));

  console.log(`[web-approver] site bundle written to ${outDir}`);
  return { built: true, outDir };
}

// Run when invoked directly (`node scripts/build-site.mjs`) — not when imported by tests
// (`test/site-build.test.mjs` imports `buildSite` to build into a throwaway temp directory).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await buildSite();
}
