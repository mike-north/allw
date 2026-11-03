/**
 * UAT: `allw-approver pair` and `allw-approver watch` (and its `serve` alias) print the same-machine
 * demo warning to stderr on every run (#241).
 *
 * The CLI approver keeps the account-root seed and device signing seed in a keyfile on the machine it
 * runs on, so a gated agent running as the same user can read them and approve its own requests.
 * Issue #241 requires each run of these commands to say so: the keys are on this machine, any process
 * running as this user (including the agent) can read them and approve its own requests, and the
 * setup is for demos only. The expected phrases below come from that requirement, not from captured
 * program output.
 *
 * The commands are driven as a real subprocess against inputs that make them fail fast (an
 * unreachable relay, a missing keyfile): the warning must appear before any work, so it shows even
 * when the command then fails.
 *
 * @see https://github.com/mike-north/allw/issues/241 (acceptance criteria: demo warning)
 * @see ../../../docs/threat-model.md (R8: the same-machine keyfile is the walking-skeleton exception)
 * @see ../src/lib/demo-warning.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

/**
 * Phrases the warning must contain (issue #241, "Demo warning"). Matched case-insensitively so
 * wording around them can evolve without weakening what is asserted.
 */
const REQUIRED_PHRASES = [
  /account root key/i, // what is held: the account root…
  /signing key/i, // …and the signing key
  /on this machine/i, // where: the machine the CLI runs on
  /any process running as this user/i, // who can read them
  /agent/i, // explicitly including the agent
  /approve its own requests/i, // the consequence
  /demos only/i, // the scope of the setup
];

/** Run the compiled approver bin with an isolated HOME; resolves { code, stdout, stderr }. */
function runCli(args, home) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { PATH: process.env.PATH, HOME: home },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`allw-approver ${args[0]} did not exit within 15000ms`));
    }, 15000);
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

/** A loopback URL nothing listens on: bind an ephemeral port, then release it. */
async function unreachableRelayUrl() {
  const server = createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  await new Promise((r) => server.close(r));
  return `http://127.0.0.1:${port}`;
}

/** Run `fn(dir)` with a fresh temp directory, removed afterwards. */
async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "allw-demo-warning-"));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function assertDemoWarning(stderr, command) {
  for (const phrase of REQUIRED_PHRASES) {
    assert.match(stderr, phrase, `'${command}' stderr must contain ${phrase}`);
  }
}

test("pair prints the demo warning to stderr (and not to stdout), even when pairing fails", async () => {
  await withTempDir(async (dir) => {
    const relay = await unreachableRelayUrl();
    const { code, stdout, stderr } = await runCli(
      ["pair", "--relay", relay, "--keyfile", join(dir, "keyfile.json")],
      dir,
    );
    assert.notEqual(code, 0, "pairing against an unreachable relay fails");
    assertDemoWarning(stderr, "pair");
    // stdout carries integrator values; the warning must not be mixed into it.
    assert.doesNotMatch(stdout, /DEMO ONLY/);
  });
});

test("watch prints the demo warning to stderr, even when the keyfile is missing", async () => {
  await withTempDir(async (dir) => {
    const { code, stderr } = await runCli(["watch", "--keyfile", join(dir, "absent.json")], dir);
    assert.notEqual(code, 0, "watch without a keyfile fails");
    assertDemoWarning(stderr, "watch");
  });
});

test("serve (the watch alias) prints the demo warning too", async () => {
  await withTempDir(async (dir) => {
    const { code, stderr } = await runCli(["serve", "--keyfile", join(dir, "absent.json")], dir);
    assert.notEqual(code, 0);
    assertDemoWarning(stderr, "serve");
  });
});

test("the warning is printed on every run, not once per machine", async () => {
  await withTempDir(async (dir) => {
    const keyfile = join(dir, "absent.json");
    const first = await runCli(["watch", "--keyfile", keyfile], dir);
    const second = await runCli(["watch", "--keyfile", keyfile], dir);
    assertDemoWarning(first.stderr, "watch (first run)");
    assertDemoWarning(second.stderr, "watch (second run)");
  });
});
