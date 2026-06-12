/**
 * UAT: `allw-approver --version` reports the version from the package's OWN package.json — never a
 * hardcoded literal. A hardcoded version silently drifts from the real release on every publish,
 * making it impossible to tell which build a user is running; this test both proves correctness and
 * guards against anyone re-hardcoding the value (no-hardcoded-versions rule).
 *
 * The expected value is read from package.json (not written inline), so the assertion can never go
 * stale against the literal — it is correct by construction for any version.
 *
 * @see ../src/version.ts (the runtime reader under test)
 * @see ../../../scripts/smoke-packaged-install.mjs (the packaged-tarball smoke that re-checks this)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
const PKG = join(here, "..", "package.json");

/** The version declared in this package's package.json — the single source of truth. */
const expectedVersion = JSON.parse(readFileSync(PKG, "utf8")).version;

/** Run the compiled approver bin with the given argv. */
function runCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("allw-approver --version did not exit within 5000ms"));
    }, 5000);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

test("allw-approver --version prints the package.json version and exits 0", async () => {
  const { code, stdout } = await runCli(["--version"]);
  assert.equal(code, 0);
  assert.equal(stdout.trim(), expectedVersion);
});

test("allw-approver -v is an alias for --version", async () => {
  const { code, stdout } = await runCli(["-v"]);
  assert.equal(code, 0);
  assert.equal(stdout.trim(), expectedVersion);
});

test("the reported version is a real semver-shaped string, not a placeholder", () => {
  // Negative guard: rejects a re-hardcoded "0.0.0" placeholder (the classic drift bug).
  assert.match(expectedVersion, /^\d+\.\d+\.\d+/);
  assert.notEqual(expectedVersion, "0.0.0");
});
