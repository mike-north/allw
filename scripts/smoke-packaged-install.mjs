/**
 * Packaged-install smoke test (issue #96).
 *
 * Proves the released artifacts actually work from a clean `npm install` with **no Rust toolchain
 * and no repo checkout**. The rest of the build can't prove this, because in-repo tests run against
 * the workspace's vendored wasm and workspace symlinks rather than the real tarballs.
 *
 * Usage:
 *
 *   node scripts/smoke-packaged-install.mjs                       # pack the release set, then smoke it
 *   node scripts/smoke-packaged-install.mjs --tarballs <dir>      # smoke the tarballs in <dir>
 *
 * `--tarballs` takes a directory written by `scripts/release-packages.mjs pack`, and tests exactly the
 * tarballs its `release-manifest.json` lists. The release workflow uses it, so the bytes it stages are
 * the bytes this test installed. Without it, the script packs the same release set itself with the
 * same code. Either way it covers every released package (scripts/release-packages.mjs).
 *
 * What it does:
 *   1. Collects the tarballs and asserts the @allw/sdk tarball bundles the wasm.
 *   2. `npm install`s all of them into a fresh temp project (npm, not pnpm, so the dependency graph is
 *      resolved from the tarballs the way a real consumer's npm would; `@allw/*` deps resolve to the
 *      local tarballs).
 *   3. Headless checks that need no live relay or paired device:
 *        - every bin of every package prints its package.json version for `--version`;
 *        - every package's main entry imports cleanly from the installed copy;
 *        - the hook runs end to end on a NON-gated tool call (stdin → `allow`), which loads the
 *          bundled WASM from the installed @allw/sdk without contacting a relay;
 *        - the SDK exposes `createClient`.
 *
 * What it deliberately does NOT do (needs a live relay + a paired device — see docs/quickstart.md):
 *   - pairing, a real approval round-trip, or a gated command reaching a phone/web surface.
 *
 * Everything runs under the OS temp dir and is cleaned up on exit (success or failure).
 *
 * @see ../docs/quickstart.md (the end-to-end flow this smoke-tests the install half of)
 * @see ../docs/architecture.md (WASM-local: the wasm glue ships in the package; no toolchain)
 * @see ../docs/releasing.md
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { PUBLISHED_PACKAGES, packAll, readReleaseManifest } from "./release-packages.mjs";

/** Run a command (stderr is piped and embedded in the thrown error on failure), fail loudly on error. */
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

const argv = process.argv.slice(2);
const tarballsFlag = argv.indexOf("--tarballs");
const givenDir = tarballsFlag >= 0 ? argv[tarballsFlag + 1] : null;
if (tarballsFlag >= 0 && !givenDir) {
  console.error("usage: node scripts/smoke-packaged-install.mjs [--tarballs <dir>]");
  process.exit(2);
}

const workDir = mkdtempSync(join(tmpdir(), "allw-smoke-"));
const projectDir = join(workDir, "consumer");
mkdirSync(projectDir, { recursive: true });

let failed = false;
try {
  console.log(`allw packaged-install smoke test\n  workdir: ${workDir}`);

  // 1. The tarballs under test: the ones given, or a fresh pack of the release set.
  console.log("\n[1/3] collecting tarballs");
  const packDir = givenDir ? resolve(givenDir) : join(workDir, "tarballs");
  const entries = givenDir ? readReleaseManifest(packDir) : packAll(packDir);
  assert.deepEqual(
    entries.map((e) => e.name),
    PUBLISHED_PACKAGES.map((p) => p.name),
    "the tarball set must be exactly the release set, in release order",
  );
  const tarballs = entries.map((e) => join(packDir, e.file));
  ok(`${entries.length} tarballs: ${entries.map((e) => `${e.name}@${e.version}`).join(", ")}`);

  // The SDK tarball must contain the bundled wasm (the whole point). If this regresses, an install
  // would silently need a Rust toolchain.
  const sdkEntry = entries.find((e) => e.name === "@allw/sdk");
  assert.ok(sdkEntry, "no @allw/sdk tarball");
  const listing = run("tar", ["-tzf", join(packDir, sdkEntry.file)]).stdout;
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

  // 2. Install every tarball into a clean npm project (no pnpm workspace, no Rust toolchain).
  console.log("\n[2/3] installing into a clean project");
  writeFileSync(
    join(projectDir, "package.json"),
    `${JSON.stringify({ name: "allw-smoke-consumer", version: "0.0.0", private: true, type: "module" }, null, 2)}\n`,
  );
  run("npm", ["install", "--no-audit", "--no-fund", "--save", ...tarballs], { cwd: projectDir });
  ok(`npm install of all ${tarballs.length} tarballs succeeded`);

  console.log("\n[3/3] headless checks");
  const binDir = join(projectDir, "node_modules", ".bin");

  // 3a. Every bin reports its own installed package.json version.
  for (const { name } of entries) {
    const installed = JSON.parse(
      readFileSync(join(projectDir, "node_modules", ...name.split("/"), "package.json"), "utf8"),
    );
    const bins =
      typeof installed.bin === "string" ? [name.split("/")[1]] : Object.keys(installed.bin ?? {});
    for (const bin of bins) {
      const out = run(join(binDir, bin), ["--version"], { cwd: projectDir }).stdout.trim();
      assert.equal(out, installed.version, `${bin} --version mismatch`);
      ok(`${bin} --version → ${out}`);
    }
  }

  // 3b. Every package's main entry imports from the installed copy.
  const importProbe = join(projectDir, "probe-imports.mjs");
  writeFileSync(
    importProbe,
    [
      `const names = ${JSON.stringify(entries.map((e) => e.name))};`,
      "for (const name of names) {",
      "  const mod = await import(name);",
      "  if (Object.keys(mod).length === 0) { console.error(`${name} exports nothing`); process.exit(1); }",
      "}",
      'const { createClient } = await import("@allw/sdk");',
      'if (typeof createClient !== "function") { console.error("createClient missing"); process.exit(1); }',
      'console.log("imports-ok");',
      "",
    ].join("\n"),
  );
  assert.equal(run("node", [importProbe], { cwd: projectDir }).stdout.trim(), "imports-ok");
  ok("every package imports from the installed copy; @allw/sdk exposes createClient");

  // 3c. The installed hook bin runs and makes no decision (empty stdout, exit 0) for a non-gated
  // tool call, with no relay and no config: allw never emits `allow` (#247). A `Read` passes through
  // without dialing the relay. The bundled-wasm path is exercised by the gated call in 3c-ii.
  const nonGatedStdin = JSON.stringify({
    hook_event_name: "PreToolUse",
    cwd: projectDir,
    tool_name: "Read",
    tool_input: { file_path: "/etc/hostname" },
  });
  const hookBin = join(binDir, "allw-hook");
  const hookOut = run(hookBin, [], {
    cwd: projectDir,
    input: nonGatedStdin,
    env: { ...process.env, HOME: workDir },
  }).stdout;
  assert.equal(hookOut, "", "the hook should make no decision (empty stdout) for a non-gated Read");
  ok("allw-hook makes no decision for a non-gated tool call (no relay)");

  // 3c-ii. A gated call loads the BUNDLED wasm (`@allw/sdk/vendor/...`) to build its ActionRecord,
  // then fails closed: the relay URL points at a closed loopback port, so the account state that
  // names the request's recipients can't be loaded and the hook prints a deny.
  const gatedStdin = JSON.stringify({
    hook_event_name: "PreToolUse",
    cwd: projectDir,
    tool_name: "Bash",
    tool_input: { command: "rm -rf build" },
  });
  // Accounts are self-certifying, so derive a valid root key and its account id with the installed
  // package's own core; the config loader rejects anything else before the gate runs.
  const coordinates = JSON.parse(
    run(
      "node",
      [
        "--input-type=module",
        "-e",
        [
          'import { loadWasm } from "@allw/hook";',
          "const wasm = await loadWasm();",
          'const root = wasm.ed25519_public_key(Buffer.alloc(32, 7).toString("base64url"));',
          "console.log(JSON.stringify({ root, account: wasm.account_id_for_root(root) }));",
        ].join("\n"),
      ],
      { cwd: projectDir },
    ).stdout,
  );
  const gatedOut = run(hookBin, [], {
    cwd: projectDir,
    input: gatedStdin,
    env: {
      ...process.env,
      // Even failed request paths must keep any sequence floor inside the smoke workspace.
      HOME: workDir,
      ALLW_RELAY_URL: "http://127.0.0.1:9",
      ALLW_ACCOUNT_ID: coordinates.account,
      ALLW_APPROVER_ROOT_KEY: coordinates.root,
    },
  }).stdout;
  const gated = JSON.parse(gatedOut).hookSpecificOutput;
  assert.equal(gated.permissionDecision, "deny", "a gated call with no reachable relay must deny");
  // The deny comes from loading account state (the dead relay), which the hook reaches only after
  // the bundled wasm core built the ActionRecord; a wasm that failed to load denies earlier, with
  // a different reason ("vendored wasm not found").
  assert.match(
    gated.permissionDecisionReason,
    /approval request failed \(fail-closed deny\): allw: loading account state failed/,
    "the gate built the ActionRecord with the bundled wasm, then failed closed loading account state",
  );
  ok("allw-hook denies a gated call it cannot get approved (bundled wasm loaded)");

  console.log("\nPASS: packaged install works with no Rust toolchain.");
} catch (err) {
  failed = true;
  console.error(`\nFAIL: ${err instanceof Error ? err.message : String(err)}`);
} finally {
  rmSync(workDir, { recursive: true, force: true });
}

process.exit(failed ? 1 : 0);
