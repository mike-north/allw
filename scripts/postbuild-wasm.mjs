/**
 * Post-process the vendored wasm-pack output so it can ship inside the published `@allw/sdk`
 * tarball.
 *
 * `wasm-pack build --target web` writes a self-contained npm-style package into the out dir
 * (`packages/sdk/vendor/allw-wasm`), and that output includes a generated `.gitignore` whose sole
 * line is `*`. npm honors a nested `.gitignore` when assembling a tarball: even with the specific
 * vendored wasm paths on the SDK's `files` allowlist, that `*` would exclude the `.wasm` + glue
 * from the published package, defeating the whole point of vendoring (an `npm install` would then
 * need a Rust toolchain — a violation of `docs/architecture.md`: the wasm glue must SHIP in the
 * package).
 *
 * This script removes that generated `.gitignore` so the artifact ships. It is intentionally
 * idempotent and tolerant of a missing file (a re-run, or a future wasm-pack that stops emitting
 * it). The wasm itself stays gitignored at the **repo** level (it is a reproducible build artifact,
 * not source) — this only affects what npm packs.
 *
 * Run automatically as the `build:wasm` postbuild step from the repo root.
 *
 * @see ../packages/sdk/package.json (`files` lists specific vendored wasm paths — `allw_wasm_bg.wasm`, `allw_wasm.js`, `.d.ts` companions; `build:wasm` chains this script)
 * @see ../docs/architecture.md (WASM-local: the glue ships in the package, no toolchain at install)
 */

import { rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const vendorDir = join(repoRoot, "packages", "sdk", "vendor", "allw-wasm");

/** The wasm-pack-generated files that would otherwise prevent the artifact from being packed. */
const packBlockers = [".gitignore"];

for (const name of packBlockers) {
  // `force: true` makes a missing file a no-op, so the script is safe to re-run and safe if a
  // future wasm-pack stops emitting the file.
  rmSync(join(vendorDir, name), { force: true });
}
