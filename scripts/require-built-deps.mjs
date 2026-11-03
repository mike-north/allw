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
 * Usage (from a package's `package.json` script): `node ../../scripts/require-built-deps.mjs`
 *
 * @see ../CLAUDE.md (§Commands — testing a single package)
 * @see ./recursive-scripts.test.mjs (asserts no validation script rebuilds a workspace dependency)
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
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

/** The built files a consumer needs from a workspace dependency. */
function requiredOutputs(name, pkg) {
  const files = [pkg.main, pkg.types].filter((f) => typeof f === "string");
  if (name === "@allw/sdk") {
    // The SDK's dist loads the vendored wasm-bindgen glue at runtime.
    files.push("./vendor/allw-wasm/allw_wasm.js", "./vendor/allw-wasm/allw_wasm_bg.wasm");
  }
  return files;
}

const packages = workspacePackages();
const self = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8"));

const seen = new Set();
const queue = workspaceDeps(self);
const missing = [];
while (queue.length > 0) {
  const name = queue.shift();
  if (seen.has(name)) continue;
  seen.add(name);
  const dep = packages.get(name);
  if (!dep) {
    missing.push({ name, file: "(not found in the workspace)" });
    continue;
  }
  for (const file of requiredOutputs(name, dep.pkg)) {
    const abs = join(dep.dir, file);
    if (!existsSync(abs)) missing.push({ name, file: relative(repoRoot, abs) });
  }
  queue.push(...workspaceDeps(dep.pkg));
}

if (missing.length > 0) {
  const needsWasm = missing.some((m) => m.file.includes("vendor/allw-wasm"));
  const lines = [
    `${self.name}: workspace dependencies are not built (package scripts no longer rebuild them; see #275):`,
    ...missing.map((m) => `  - ${m.name}: missing ${m.file}`),
    "Build first, from the repo root:",
    ...(needsWasm ? ["  pnpm run build:wasm"] : []),
    `  pnpm --filter "${self.name}..." build`,
  ];
  console.error(lines.join("\n"));
  process.exit(1);
}
