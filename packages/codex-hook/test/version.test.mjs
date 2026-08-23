/**
 * UAT: `allw-codex-hook --version` reports the version from the package's OWN package.json — never
 * a hardcoded literal. A hardcoded version silently drifts from the real release on every publish,
 * making it impossible to tell which build a user is running; this test both proves correctness and
 * guards against anyone re-hardcoding the value (no-hardcoded-versions rule).
 *
 * The expected value is read from package.json (not written inline), so the assertion can never go
 * stale against the literal — it is correct by construction for any version.
 *
 * @see ../src/version.ts (the runtime reader under test)
 * @see ../../hook/test/version.test.mjs (the Claude Code hook's mirror of this test)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
const PKG = join(here, "..", "package.json");

/** The version declared in this package's package.json — the single source of truth. */
const expectedVersion = JSON.parse(readFileSync(PKG, "utf8")).version;

/** Run the compiled hook bin with the given argv (no stdin needed for `--version`). */
function runCli(args, cliPath = CLI) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      // A clean env so an ambient ALLW_* on the dev machine can't influence the result.
      env: { PATH: process.env.PATH },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("allw-codex-hook --version did not exit within 5000ms"));
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

test("allw-codex-hook --version prints the package.json version and exits 0", async () => {
  const { code, stdout } = await runCli(["--version"]);
  assert.equal(code, 0);
  assert.equal(stdout.trim(), expectedVersion);
});

test("allw-codex-hook -v is an alias for --version", async () => {
  const { code, stdout } = await runCli(["-v"]);
  assert.equal(code, 0);
  assert.equal(stdout.trim(), expectedVersion);
});

test("the reported version is a real semver-shaped string, not a placeholder", () => {
  // Negative guard: a re-hardcoded "0.0.0" placeholder (the classic drift bug) would slip past an
  // equality check if package.json were also that value, so assert the version is non-empty and
  // looks like a release. (package.json is the source of truth; this only rejects placeholders.)
  assert.match(expectedVersion, /^\d+\.\d+\.\d+/);
  assert.notEqual(expectedVersion, "0.0.0");
});

// Regression: the `allw-codex-hook` bin is invoked through a symlink in `node_modules/.bin`, so
// `process.argv[1]` is the symlink path while `import.meta.url` is the real `dist/cli.js`. The
// entrypoint guard must resolve the symlink (realpath) before comparing — otherwise `main()` never
// runs and the bin silently prints nothing.
test("allw-codex-hook --version works when invoked through a symlink (node_modules/.bin parity)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "allw-codex-hook-symlink-"));
  const link = join(dir, "allw-codex-hook");
  try {
    symlinkSync(CLI, link);
    const { code, stdout } = await runCli(["--version"], link);
    assert.equal(code, 0);
    assert.equal(stdout.trim(), expectedVersion);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
