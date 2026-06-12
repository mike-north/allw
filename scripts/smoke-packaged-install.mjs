/**
 * Packaged-install smoke test (issue #96).
 *
 * Proves the published artifacts actually work from a clean `npm install` with **no Rust toolchain
 * and no repo checkout** — the property the rest of the build can't prove, because in-repo tests run
 * against the workspace's vendored wasm and workspace symlinks rather than the real tarballs.
 *
 * What it does:
 *   1. `pnpm pack` @allw/sdk, @allw/hook, @allw/approver into a temp dir (the exact tarballs that
 *      would be published).
 *   2. `npm install` all three tarballs into a fresh temp project (npm, not pnpm, so the dependency
 *      graph is resolved from the tarballs the way a real consumer's npm would do it — `@allw/sdk`
 *      is satisfied by the local sdk tarball).
 *   3. Headless checks that need no live relay or paired device:
 *        - `allw-hook --version` and `allw-approver --version` print their package.json version.
 *        - The hook runs end-to-end on a NON-gated tool call (stdin → `allow`) — this loads the
 *          bundled WASM from the installed @allw/sdk (the real "no toolchain at install" proof) and
 *          builds an ActionRecord path without ever contacting a relay.
 *        - The SDK imports and exposes `createClient` (module + bundled wasm resolve from the
 *          installed package).
 *
 * What it deliberately does NOT do (needs a live relay + a paired device — see docs/quickstart.md):
 *   - pairing, a real approval round-trip, or a gated command reaching a phone/web surface.
 *
 * Everything runs under the OS temp dir and is cleaned up on exit (success or failure).
 *
 * @see ../docs/quickstart.md (the end-to-end flow this smoke-tests the install half of)
 * @see ../docs/architecture.md (WASM-local: the wasm glue ships in the package; no toolchain)
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Packages to pack + install, in dependency order (sdk first so the others can resolve it). */
const PACKAGES = [
  { name: "@allw/sdk", dir: join(repoRoot, "packages", "sdk") },
  { name: "@allw/hook", dir: join(repoRoot, "packages", "hook") },
  { name: "@allw/approver", dir: join(repoRoot, "packages", "approver") },
];

/** Run a command, inheriting stderr, and fail loudly (non-zero exit) on error. */
function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  if (res.status !== 0) {
    const where = opts.cwd ? ` (cwd ${opts.cwd})` : "";
    throw new Error(
      `command failed${where}: ${cmd} ${args.join(" ")}\n` +
        `exit ${String(res.status)}\nstdout:\n${res.stdout ?? ""}\nstderr:\n${res.stderr ?? ""}`,
    );
  }
  return res;
}

/** A green check log line. */
function ok(msg) {
  console.log(`  ✓ ${msg}`);
}

const workDir = mkdtempSync(join(tmpdir(), "allw-smoke-"));
const packDir = join(workDir, "tarballs");
const projectDir = join(workDir, "consumer");
mkdirSync(packDir, { recursive: true });
mkdirSync(projectDir, { recursive: true });

let failed = false;
try {
  console.log(`allw packaged-install smoke test\n  workdir: ${workDir}`);

  // 1. Pack each package into packDir. `pnpm pack --pack-destination` writes the tarball there.
  console.log("\n[1/3] packing tarballs");
  const tarballs = [];
  for (const pkg of PACKAGES) {
    run("pnpm", ["pack", "--pack-destination", packDir], { cwd: pkg.dir });
    // pnpm names the file from the package name + version; find the one it just wrote.
    const file = readdirSync(packDir)
      .filter((f) => f.endsWith(".tgz"))
      .map((f) => join(packDir, f))
      .find((p) => !tarballs.includes(p));
    assert.ok(file, `no tarball produced for ${pkg.name}`);
    tarballs.push(file);
    ok(`packed ${pkg.name}`);
  }

  // Assert the SDK tarball actually contains the bundled wasm (the whole point). If this regresses,
  // an install would silently need a Rust toolchain.
  const sdkTarball = tarballs[0];
  const listing = run("tar", ["-tzf", sdkTarball]).stdout;
  assert.match(
    listing,
    /package\/vendor\/allw-wasm\/allw_wasm_bg\.wasm/,
    "the @allw/sdk tarball is missing the bundled .wasm — npm install would need a Rust toolchain",
  );
  assert.match(
    listing,
    /package\/vendor\/allw-wasm\/allw_wasm\.js/,
    "the @allw/sdk tarball is missing the wasm-bindgen glue",
  );
  ok("the @allw/sdk tarball bundles the wasm glue + .wasm");

  // 2. Install all three tarballs into a clean npm project (no pnpm workspace, no Rust toolchain).
  console.log("\n[2/3] installing into a clean project");
  writeFileSync(
    join(projectDir, "package.json"),
    `${JSON.stringify({ name: "allw-smoke-consumer", version: "0.0.0", private: true, type: "module" }, null, 2)}\n`,
  );
  // Install the SDK first so the hook/approver's @allw/sdk dependency resolves to the local tarball.
  run("npm", ["install", "--no-audit", "--no-fund", "--save", ...tarballs], { cwd: projectDir });
  ok("npm install of all three tarballs succeeded");

  const binDir = join(projectDir, "node_modules", ".bin");
  const hookBin = join(binDir, "allw-hook");
  const approverBin = join(binDir, "allw-approver");

  // 3a. Versions, read from the installed packages.
  console.log("\n[3/3] headless checks");
  const installedHookVersion = JSON.parse(
    readFileSync(join(projectDir, "node_modules", "@allw", "hook", "package.json"), "utf8"),
  ).version;
  const installedApproverVersion = JSON.parse(
    readFileSync(join(projectDir, "node_modules", "@allw", "approver", "package.json"), "utf8"),
  ).version;

  const hookVer = run(hookBin, ["--version"], { cwd: projectDir }).stdout.trim();
  assert.equal(hookVer, installedHookVersion, "allw-hook --version mismatch");
  ok(`allw-hook --version → ${hookVer}`);

  const approverVer = run(approverBin, ["--version"], { cwd: projectDir }).stdout.trim();
  assert.equal(approverVer, installedApproverVersion, "allw-approver --version mismatch");
  ok(`allw-approver --version → ${approverVer}`);

  // 3b. The hook loads the BUNDLED wasm and decides a non-gated tool call as `allow`, with no relay
  // and no config. A `Read` tool passes through without dialing the relay, so this exercises the
  // installed wasm-resolution path (`@allw/sdk/vendor/...`) end-to-end against the real tarballs.
  const nonGatedStdin = JSON.stringify({
    hook_event_name: "PreToolUse",
    cwd: projectDir,
    tool_name: "Read",
    tool_input: { file_path: "/etc/hostname" },
  });
  const hookOut = run(hookBin, [], { cwd: projectDir, input: nonGatedStdin }).stdout;
  const decision = JSON.parse(hookOut).hookSpecificOutput.permissionDecision;
  assert.equal(decision, "allow", "the hook should pass through a non-gated Read as allow");
  ok("allw-hook decides a non-gated tool call as allow (bundled wasm loaded, no relay)");

  // 3c. The SDK imports from the installed package and exposes its public entrypoint.
  const importProbe = join(projectDir, "probe.mjs");
  writeFileSync(
    importProbe,
    [
      'import { createClient } from "@allw/sdk";',
      'if (typeof createClient !== "function") { console.error("createClient missing"); process.exit(1); }',
      'console.log("sdk-import-ok");',
      "",
    ].join("\n"),
  );
  const probeOut = run("node", [importProbe], { cwd: projectDir }).stdout.trim();
  assert.equal(
    probeOut,
    "sdk-import-ok",
    "the SDK did not import cleanly from the installed package",
  );
  ok("@allw/sdk imports and exposes createClient from the installed package");

  console.log("\nPASS: packaged install works with no Rust toolchain.");
} catch (err) {
  failed = true;
  console.error(`\nFAIL: ${err instanceof Error ? err.message : String(err)}`);
} finally {
  rmSync(workDir, { recursive: true, force: true });
}

process.exit(failed ? 1 : 0);
