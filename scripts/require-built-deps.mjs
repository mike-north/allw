/**
 * Fail fast, with an actionable message, when a package's workspace dependencies are not built.
 *
 * Package `test` / `typecheck` / `lint` scripts deliberately do **not** rebuild their workspace
 * dependencies (issue #275). `pnpm -r test` runs several packages at once; when each package's
 * script re-ran `tsc` on `@allw/sdk` / `@allw/hook`, one package's rebuild rewrote `dist/*.js`
 * underneath another package's running subprocess test, which then crashed loading a half-written
 * module (exit 1 instead of the hook's fail-closed exit 0). The build is now a separate, earlier
 * step — `pnpm run build:wasm` + `pnpm -r build` in the gate and CI, or
 * `pnpm --filter <pkg>... build` for a single package — and validation scripts only *read* `dist/`.
 *
 * This guard is what keeps the single-package flow honest: run from a package directory, it walks
 * that package's `workspace:` dependencies (transitively) and checks each one's built entry points
 * exist. If any is missing it prints the exact build command and exits 1. It only reads files, so
 * it is safe to run concurrently with anything.
 *
 * Two modes:
 *
 * - **runtime** (default; for `test`): each dep's `main` + `types` exist, and `main` is not older
 *   than any file under the dep's `src/` (a stale `dist/` would test old code). For `@allw/sdk` the
 *   vendored WASM glue must exist too, since its `dist/` loads it at runtime.
 * - **`--types`** (for `typecheck` / `lint`): only each dep's `types` entry must exist. No `main`,
 *   no freshness, no WASM: CI's TypeScript job runs `pnpm -r build` but never `build:wasm`.
 *
 * Usage (from a package's `package.json` script):
 *   `node ../../scripts/require-built-deps.mjs` or `node ../../scripts/require-built-deps.mjs --types`
 *
 * @see ../CLAUDE.md (§Commands — testing a single package)
 * @see ./recursive-scripts.test.mjs (asserts no validation script rebuilds a workspace dependency)
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Map every workspace package name → its directory (packages/* and examples/*). */
function workspacePackages() {
  const byName = new Map();
  for (const group of ["packages", "examples"]) {
    const groupDir = join(repoRoot, group);
    if (!existsSync(groupDir)) continue;
    for (const entry of readdirSync(groupDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const pkgJsonPath = join(groupDir, entry.name, "package.json");
      if (!existsSync(pkgJsonPath)) continue;
      const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
      byName.set(pkg.name, { dir: join(groupDir, entry.name), pkg });
    }
  }
  return byName;
}

/** Names of a package's `workspace:` dependencies (runtime and dev). */
function workspaceDeps(pkg) {
  const all = { ...pkg.dependencies, ...pkg.devDependencies };
  return Object.entries(all)
    .filter(([, spec]) => typeof spec === "string" && spec.startsWith("workspace:"))
    .map(([name]) => name);
}

const args = process.argv.slice(2);
const unknown = args.filter((a) => a !== "--types");
if (unknown.length > 0) {
  console.error(
    `require-built-deps: unknown argument(s): ${unknown.join(" ")} (expected nothing or --types)`,
  );
  process.exit(2);
}
const typesOnly = args.includes("--types");

/** The built files a consumer needs from a workspace dependency, in the current mode. */
function requiredOutputs(name, pkg) {
  if (typesOnly) return [pkg.types].filter((f) => typeof f === "string");
  const files = [pkg.main, pkg.types].filter((f) => typeof f === "string");
  if (name === "@allw/sdk") {
    // The SDK's dist loads the vendored wasm-bindgen glue at runtime.
    files.push("./vendor/allw-wasm/allw_wasm.js", "./vendor/allw-wasm/allw_wasm_bg.wasm");
  }
  return files;
}

/** The newest file under `dir` (recursively), or null if there is none. */
function newestFile(dir) {
  if (!existsSync(dir)) return null;
  let newest = null;
  for (const entry of readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile()) continue;
    const path = join(entry.parentPath, entry.name);
    const mtimeMs = statSync(path).mtimeMs;
    if (!newest || mtimeMs > newest.mtimeMs) newest = { path, mtimeMs };
  }
  return newest;
}

const packages = workspacePackages();
const self = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8"));

const seen = new Set();
const queue = workspaceDeps(self);
const problems = [];
while (queue.length > 0) {
  const name = queue.shift();
  if (seen.has(name)) continue;
  seen.add(name);
  const dep = packages.get(name);
  if (!dep) {
    problems.push({ name, detail: "not found in the workspace (packages/*, examples/*)" });
    continue;
  }
  for (const file of requiredOutputs(name, dep.pkg)) {
    const abs = join(dep.dir, file);
    if (!existsSync(abs)) problems.push({ name, detail: `missing ${relative(repoRoot, abs)}` });
  }
  if (!typesOnly && typeof dep.pkg.main === "string") {
    const main = join(dep.dir, dep.pkg.main);
    const newestSrc = newestFile(join(dep.dir, "src"));
    if (existsSync(main) && newestSrc && newestSrc.mtimeMs > statSync(main).mtimeMs) {
      problems.push({
        name,
        detail: `stale: ${relative(repoRoot, newestSrc.path)} is newer than ${relative(repoRoot, main)}`,
      });
    }
  }
  queue.push(...workspaceDeps(dep.pkg));
}

if (problems.length > 0) {
  const needsWasm = problems.some((p) => p.detail.includes("vendor/allw-wasm"));
  const lines = [
    `${self.name}: workspace dependencies are not built or are out of date (package scripts no longer rebuild them; see #275):`,
    ...problems.map((p) => `  - ${p.name}: ${p.detail}`),
    "Build first, from the repo root:",
    ...(needsWasm ? ["  pnpm run build:wasm"] : []),
    `  pnpm --filter "${self.name}..." build`,
  ];
  console.error(lines.join("\n"));
  process.exit(1);
}
