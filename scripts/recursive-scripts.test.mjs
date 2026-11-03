import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const GUARD = "node ../../scripts/require-built-deps.mjs && ";
const VALIDATION_SCRIPTS = ["typecheck", "lint", "test"];

async function readPackageJson(path) {
  return JSON.parse(await readFile(join(repoRoot, path), "utf8"));
}

function workspacePackagePaths() {
  return ["packages", "examples"].flatMap((group) =>
    readdirSync(join(repoRoot, group), { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => `${group}/${e.name}/package.json`),
  );
}

function hasWorkspaceDeps(pkg) {
  return Object.values({ ...pkg.dependencies, ...pkg.devDependencies }).some(
    (spec) => typeof spec === "string" && spec.startsWith("workspace:"),
  );
}

// Issue #275: `pnpm -r test` runs packages concurrently. When each package's validation script
// rebuilt its workspace dependencies (`pnpm --filter @allw/sdk build`, …), one package's `tsc`
// rewrote `packages/{sdk,hook}/dist/*.js` while another package's subprocess test was loading
// them, and the subprocess crashed with exit 1. Validation scripts must therefore only READ their
// dependencies' dist/; the build is a separate, earlier step (`pnpm -r build`, or
// `pnpm --filter "<pkg>..." build` for one package). A package may still compile ITSELF in `test`:
// `pnpm -r` runs a package's dependents only after its own script finishes, so that write never
// overlaps a consumer's run.
test("validation scripts never build another workspace package (#275)", async () => {
  for (const path of workspacePackagePaths()) {
    const pkg = await readPackageJson(path);
    assert.equal(pkg.scripts?.["build:deps"], undefined, `${path} should not define build:deps`);
    for (const name of VALIDATION_SCRIPTS) {
      const script = pkg.scripts?.[name] ?? "";
      for (const forbidden of [
        /\bpnpm\b[^&|;]*--filter/,
        /\bpnpm\b[^&|;]*\s-r\b/,
        /build:deps/,
        /pnpm run build\b/,
      ]) {
        assert.doesNotMatch(
          script,
          forbidden,
          `${path} ${name} must not rebuild workspace deps: ${script}`,
        );
      }
    }
  }
});

// The single-package developer flow stays honest: a consumer's validation scripts start with the
// read-only guard, so a missing dependency build fails with the exact command to run instead of an
// opaque module-not-found error.
test("packages with workspace deps guard their validation scripts with require-built-deps", async () => {
  let guarded = 0;
  for (const path of workspacePackagePaths()) {
    const pkg = await readPackageJson(path);
    if (!hasWorkspaceDeps(pkg) || path === "packages/relay/package.json") continue;
    for (const name of VALIDATION_SCRIPTS) {
      assert.ok(
        (pkg.scripts?.[name] ?? "").startsWith(GUARD),
        `${path} ${name} should begin with the require-built-deps guard`,
      );
    }
    guarded += 1;
  }
  // approver, hook, codex-hook, openclaw-bridge, web-approver, walking-skeleton.
  assert.ok(guarded >= 6, `expected at least 6 guarded packages, saw ${guarded}`);
});

/** A throwaway workspace: consumer `@t/app` → `@t/lib` → `@allw/sdk`, nothing built yet. */
function fixtureWorkspace() {
  const root = mkdtempSync(join(tmpdir(), "allw-require-built-deps-"));
  mkdirSync(join(root, "scripts"));
  copyFileSync(
    join(repoRoot, "scripts", "require-built-deps.mjs"),
    join(root, "scripts", "require-built-deps.mjs"),
  );
  const write = (dir, pkg) => {
    mkdirSync(join(root, dir), { recursive: true });
    writeFileSync(join(root, dir, "package.json"), JSON.stringify(pkg));
  };
  write("packages/sdk", { name: "@allw/sdk", main: "./dist/index.js", types: "./dist/index.d.ts" });
  write("packages/lib", {
    name: "@t/lib",
    main: "./dist/index.js",
    types: "./dist/index.d.ts",
    dependencies: { "@allw/sdk": "workspace:*" },
  });
  write("examples/app", { name: "@t/app", dependencies: { "@t/lib": "workspace:*" } });
  return root;
}

function runGuard(root) {
  return spawnSync(process.execPath, ["../../scripts/require-built-deps.mjs"], {
    cwd: join(root, "examples", "app"),
    encoding: "utf8",
  });
}

test("require-built-deps fails with the build command when a (transitive) dep is unbuilt", () => {
  const root = fixtureWorkspace();
  try {
    const result = runGuard(root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /@t\/app: workspace dependencies are not built/);
    assert.match(result.stderr, /@t\/lib: missing packages\/lib\/dist\/index\.js/);
    // Transitive: the SDK's dist and its vendored wasm glue are checked too.
    assert.match(result.stderr, /@allw\/sdk: missing packages\/sdk\/dist\/index\.js/);
    assert.match(
      result.stderr,
      /@allw\/sdk: missing packages\/sdk\/vendor\/allw-wasm\/allw_wasm\.js/,
    );
    assert.match(result.stderr, /pnpm run build:wasm/);
    assert.match(result.stderr, /pnpm --filter "@t\/app\.\.\." build/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("require-built-deps still fails when only the wasm glue is missing", () => {
  const root = fixtureWorkspace();
  try {
    for (const dir of ["packages/sdk/dist", "packages/lib/dist"]) {
      mkdirSync(join(root, dir), { recursive: true });
      writeFileSync(join(root, dir, "index.js"), "");
      writeFileSync(join(root, dir, "index.d.ts"), "");
    }
    const result = runGuard(root);
    assert.equal(result.status, 1);
    assert.doesNotMatch(result.stderr, /@t\/lib: missing/);
    assert.match(
      result.stderr,
      /@allw\/sdk: missing packages\/sdk\/vendor\/allw-wasm\/allw_wasm_bg\.wasm/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("require-built-deps passes silently once every dependency is built", () => {
  const root = fixtureWorkspace();
  try {
    for (const dir of ["packages/sdk/dist", "packages/lib/dist"]) {
      mkdirSync(join(root, dir), { recursive: true });
      writeFileSync(join(root, dir, "index.js"), "");
      writeFileSync(join(root, dir, "index.d.ts"), "");
    }
    mkdirSync(join(root, "packages/sdk/vendor/allw-wasm"), { recursive: true });
    writeFileSync(join(root, "packages/sdk/vendor/allw-wasm/allw_wasm.js"), "");
    writeFileSync(join(root, "packages/sdk/vendor/allw-wasm/allw_wasm_bg.wasm"), "");
    const result = runGuard(root);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
