import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const VALIDATION_SCRIPTS = ["typecheck", "lint", "test"];

/** The guard each validation script must start with: runtime for `test`, types-only otherwise. */
const GUARDS = {
  runtime: "node ../../scripts/require-built-deps.mjs",
  types: "node ../../scripts/require-built-deps.mjs --types",
};
const guardModeFor = (scriptName) => (scriptName === "test" ? "runtime" : "types");

/**
 * The closed set of commands a validation script may run after its guard. Everything here only
 * reads other packages; the one write, `tsc -p tsconfig.json`, emits the package's OWN dist/,
 * which is safe because `pnpm -r` starts a package's dependents only after its script finishes.
 */
const ALLOWED_COMMANDS = [
  /^tsc -p tsconfig\.json( --noEmit)?$/,
  /^node --test "test\/\*\*\/\*\.test\.mjs"$/,
  /^eslint src$/,
  /^vitest run$/,
];

/**
 * Validate one validation script against the allowlist. Returns a list of violations (empty when
 * the script is acceptable). `guard` is "runtime", "types", or null (no guard required).
 */
function validationScriptViolations(script, guard) {
  const segments = script.split(" && ");
  const violations = [];
  if (guard !== null) {
    if (segments[0] !== GUARDS[guard]) {
      violations.push(`must start with \`${GUARDS[guard]} && \``);
    } else {
      segments.shift();
    }
  }
  if (segments.length === 0 || segments.every((s) => s === "")) {
    violations.push("runs nothing after the guard");
  }
  for (const segment of segments) {
    if (!ALLOWED_COMMANDS.some((re) => re.test(segment))) {
      violations.push(`\`${segment}\` is not an allowed validation command`);
    }
  }
  return violations;
}

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

// The relay's only workspace dep is @allw/sdk, and it imports just the vendored WASM glue
// (`@allw/sdk/vendor/allw-wasm/*`), never the SDK's built dist/, so it needs no dist guard.
const GUARD_EXEMPT = new Set(["packages/relay/package.json"]);

// Issue #275: `pnpm -r test` runs packages concurrently. When each package's validation script
// rebuilt its workspace dependencies (`pnpm --filter @allw/sdk build`, …), one package's `tsc`
// rewrote `packages/{sdk,hook}/dist/*.js` while another package's subprocess test was loading
// them, and the subprocess crashed with exit 1. Validation scripts must therefore only READ their
// dependencies' dist/; the build is a separate, earlier step (`pnpm -r build`, or
// `pnpm --filter "<pkg>..." build` for one package). Enforced as an allowlist, not a denylist:
// there are too many ways to spell "build another package" to enumerate them.
test("every workspace validation script is the guard plus allowlisted commands only (#275)", async () => {
  let guarded = 0;
  for (const path of workspacePackagePaths()) {
    const pkg = await readPackageJson(path);
    assert.equal(pkg.scripts?.["build:deps"], undefined, `${path} should not define build:deps`);
    const needsGuard = hasWorkspaceDeps(pkg) && !GUARD_EXEMPT.has(path);
    if (needsGuard) guarded += 1;
    for (const name of VALIDATION_SCRIPTS) {
      const script = pkg.scripts?.[name];
      assert.equal(typeof script, "string", `${path} should define a ${name} script`);
      assert.deepEqual(
        validationScriptViolations(script, needsGuard ? guardModeFor(name) : null),
        [],
        `${path} ${name}: ${script}`,
      );
    }
  }
  // approver, hook, codex-hook, openclaw-bridge, web-approver, walking-skeleton.
  assert.ok(guarded >= 6, `expected at least 6 guarded packages, saw ${guarded}`);
});

test("the allowlist accepts the real script shapes", () => {
  const ok = [
    [`${GUARDS.runtime} && tsc -p tsconfig.json && node --test "test/**/*.test.mjs"`, "runtime"],
    [`${GUARDS.types} && tsc -p tsconfig.json --noEmit`, "types"],
    [`${GUARDS.types} && eslint src`, "types"],
    [`tsc -p tsconfig.json && node --test "test/**/*.test.mjs"`, null],
    ["vitest run", null],
  ];
  for (const [script, guard] of ok) {
    assert.deepEqual(validationScriptViolations(script, guard), [], script);
  }
});

test("the allowlist rejects every way of building another package", () => {
  const rebuilds = [
    "pnpm -F @allw/sdk build",
    "pnpm --recursive build",
    "pnpm -C ../sdk build",
    "pnpm --dir ../sdk run build",
    "pnpm build",
    "tsc -b ../sdk",
    "npm --prefix ../sdk run build",
    "pnpm --filter @allw/sdk build",
    "pnpm -r build",
    "pnpm run build:deps",
    "tsc -p ../sdk/tsconfig.json",
    "tsc -p tsconfig.json; pnpm build",
  ];
  const node = 'node --test "test/**/*.test.mjs"';
  for (const cmd of rebuilds) {
    for (const [script, guard] of [
      [`${GUARDS.runtime} && ${cmd} && ${node}`, "runtime"],
      [`${GUARDS.runtime} && ${node} && ${cmd}`, "runtime"],
      [`${cmd} && ${node}`, null],
    ]) {
      assert.notDeepEqual(validationScriptViolations(script, guard), [], `accepted: ${script}`);
    }
  }
});

test("the allowlist rejects a missing, wrong-mode, or misplaced guard", () => {
  const body = "tsc -p tsconfig.json --noEmit";
  assert.notDeepEqual(validationScriptViolations(body, "types"), []);
  assert.notDeepEqual(validationScriptViolations(`${GUARDS.runtime} && ${body}`, "types"), []);
  assert.notDeepEqual(validationScriptViolations(`${GUARDS.types} && ${body}`, "runtime"), []);
  assert.notDeepEqual(validationScriptViolations(`${body} && ${GUARDS.types}`, "types"), []);
  assert.notDeepEqual(validationScriptViolations(GUARDS.types, "types"), []);
});

// ---------------------------------------------------------------------------------------------
// require-built-deps.mjs, against a throwaway workspace.

// Fixed mtimes (seconds): never derived from the wall clock.
const OLDER = 1_700_000_000;
const NEWER = 1_700_000_100;

/** A throwaway workspace: consumer `@t/app` → `@t/lib` → `@allw/sdk`, nothing built yet. */
function fixtureWorkspace(appDeps = { "@t/lib": "workspace:*" }) {
  const root = mkdtempSync(join(tmpdir(), "allw-require-built-deps-"));
  mkdirSync(join(root, "scripts"));
  copyFileSync(
    join(repoRoot, "scripts", "require-built-deps.mjs"),
    join(root, "scripts", "require-built-deps.mjs"),
  );
  const write = (dir, pkg) => {
    mkdirSync(join(root, dir, "src"), { recursive: true });
    writeFileSync(join(root, dir, "package.json"), JSON.stringify(pkg));
    writeFileSync(join(root, dir, "src", "index.ts"), "");
    utimesSync(join(root, dir, "src", "index.ts"), OLDER, OLDER);
  };
  write("packages/sdk", { name: "@allw/sdk", main: "./dist/index.js", types: "./dist/index.d.ts" });
  write("packages/lib", {
    name: "@t/lib",
    main: "./dist/index.js",
    types: "./dist/index.d.ts",
    dependencies: { "@allw/sdk": "workspace:*" },
  });
  write("examples/app", { name: "@t/app", dependencies: appDeps });
  return root;
}

/** Emit `files` (relative to `root`) with the fixed NEWER mtime. */
function emit(root, files) {
  for (const file of files) {
    mkdirSync(join(root, file, ".."), { recursive: true });
    writeFileSync(join(root, file), "");
    utimesSync(join(root, file), NEWER, NEWER);
  }
}

const TYPES = ["packages/sdk/dist/index.d.ts", "packages/lib/dist/index.d.ts"];
const MAINS = ["packages/sdk/dist/index.js", "packages/lib/dist/index.js"];
const WASM = [
  "packages/sdk/vendor/allw-wasm/allw_wasm.js",
  "packages/sdk/vendor/allw-wasm/allw_wasm_bg.wasm",
];

function runGuard(root, ...args) {
  return spawnSync(process.execPath, ["../../scripts/require-built-deps.mjs", ...args], {
    cwd: join(root, "examples", "app"),
    encoding: "utf8",
  });
}

function withFixture(fn, appDeps) {
  const root = fixtureWorkspace(appDeps);
  try {
    fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("require-built-deps fails with the build command when a (transitive) dep is unbuilt", () => {
  withFixture((root) => {
    const result = runGuard(root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /@t\/app: workspace dependencies are not built or are out of date/);
    assert.match(result.stderr, /@t\/lib: missing packages\/lib\/dist\/index\.js/);
    // Transitive: the SDK's dist and its vendored wasm glue are checked too.
    assert.match(result.stderr, /@allw\/sdk: missing packages\/sdk\/dist\/index\.js/);
    assert.match(
      result.stderr,
      /@allw\/sdk: missing packages\/sdk\/vendor\/allw-wasm\/allw_wasm\.js/,
    );
    assert.match(result.stderr, /pnpm run build:wasm/);
    assert.match(result.stderr, /pnpm --filter "@t\/app\.\.\." build/);
  });
});

test("require-built-deps (runtime) still fails when only the wasm glue is missing", () => {
  withFixture((root) => {
    emit(root, [...TYPES, ...MAINS]);
    const result = runGuard(root);
    assert.equal(result.status, 1);
    assert.doesNotMatch(result.stderr, /@t\/lib: /);
    assert.match(
      result.stderr,
      /@allw\/sdk: missing packages\/sdk\/vendor\/allw-wasm\/allw_wasm_bg\.wasm/,
    );
  });
});

test("--types passes with only .d.ts outputs (no main, no WASM); runtime mode still fails", () => {
  withFixture((root) => {
    emit(root, TYPES);
    const types = runGuard(root, "--types");
    assert.equal(types.status, 0, types.stderr);
    assert.equal(types.stderr, "");

    const runtime = runGuard(root);
    assert.equal(runtime.status, 1);
    assert.match(runtime.stderr, /@t\/lib: missing packages\/lib\/dist\/index\.js/);
    assert.match(runtime.stderr, /vendor\/allw-wasm/);
  });
});

test("--types still fails when a dep's .d.ts is missing", () => {
  withFixture((root) => {
    emit(root, ["packages/sdk/dist/index.d.ts"]);
    const result = runGuard(root, "--types");
    assert.equal(result.status, 1);
    assert.match(result.stderr, /@t\/lib: missing packages\/lib\/dist\/index\.d\.ts/);
    assert.match(result.stderr, /pnpm --filter "@t\/app\.\.\." build/);
  });
});

test("require-built-deps (runtime) fails when a dep's src/ is newer than its main output", () => {
  withFixture((root) => {
    emit(root, [...TYPES, ...MAINS, ...WASM]);
    // Edit lib's source after its build.
    utimesSync(join(root, "packages/lib/src/index.ts"), NEWER + 1, NEWER + 1);
    const result = runGuard(root);
    assert.equal(result.status, 1);
    assert.match(
      result.stderr,
      /@t\/lib: stale: packages\/lib\/src\/index\.ts is newer than packages\/lib\/dist\/index\.js/,
    );
    assert.doesNotMatch(result.stderr, /@allw\/sdk: /);
    assert.match(result.stderr, /pnpm --filter "@t\/app\.\.\." build/);

    // Freshness is a runtime concern only: --types does not check it.
    assert.equal(runGuard(root, "--types").status, 0);
  });
});

test("require-built-deps fails when a workspace dependency is not in the workspace", () => {
  withFixture(
    (root) => {
      emit(root, [...TYPES, ...MAINS, ...WASM]);
      for (const args of [[], ["--types"]]) {
        const result = runGuard(root, ...args);
        assert.equal(result.status, 1);
        assert.match(
          result.stderr,
          /@t\/ghost: not found in the workspace \(packages\/\*, examples\/\*\)/,
        );
      }
    },
    { "@t/lib": "workspace:*", "@t/ghost": "workspace:*" },
  );
});

test("require-built-deps rejects an unknown argument", () => {
  withFixture((root) => {
    const result = runGuard(root, "--typos");
    assert.equal(result.status, 2);
    assert.match(result.stderr, /unknown argument/);
  });
});

test("require-built-deps passes silently once every dependency is built and fresh", () => {
  withFixture((root) => {
    emit(root, [...TYPES, ...MAINS, ...WASM]);
    for (const args of [[], ["--types"]]) {
      const result = runGuard(root, ...args);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, "");
    }
  });
});
