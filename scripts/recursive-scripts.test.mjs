import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

async function readPackageJson(path) {
  return JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), "utf8"));
}

// Recursive pnpm tasks can start a consumer package before its workspace
// dependency has emitted dist/. Packages that import built workspace exports
// must therefore build those dependencies inside their own validation scripts.
test("recursive workspace scripts build local dependencies before validation", async () => {
  const expectations = [
    {
      path: "packages/approver/package.json",
      requiredBuilds: ["pnpm --filter @allw/sdk build"],
      guardedScripts: ["typecheck", "lint", "test"],
    },
    {
      path: "packages/hook/package.json",
      requiredBuilds: ["pnpm --filter @allw/sdk build"],
      guardedScripts: ["typecheck", "lint", "test"],
    },
    {
      path: "examples/walking-skeleton/package.json",
      requiredBuilds: [
        "pnpm --filter @allw/sdk build",
        "pnpm --filter @allw/approver build",
        "pnpm --filter @allw/hook build",
      ],
      guardedScripts: ["typecheck", "lint", "test"],
    },
  ];

  for (const expectation of expectations) {
    const pkg = await readPackageJson(expectation.path);
    const buildDeps = pkg.scripts?.["build:deps"] ?? "";

    for (const requiredBuild of expectation.requiredBuilds) {
      assert.match(
        buildDeps,
        new RegExp(requiredBuild.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
        `${expectation.path} build:deps should run ${requiredBuild}`,
      );
    }

    for (const scriptName of expectation.guardedScripts) {
      assert.match(
        pkg.scripts?.[scriptName] ?? "",
        /^pnpm run build:deps && /,
        `${expectation.path} ${scriptName} should begin with build:deps`,
      );
    }
  }
});
