/**
 * UAT-layer test: drive the real `allw-hook` executable as a `node` subprocess, exactly as Claude
 * Code invokes it — JSON on stdin, a permission-decision JSON on stdout, exit 0. This proves the
 * acceptance criterion that the hook "runs entirely under node (no binary to allowlist)" and that
 * the process boundary is fail-closed.
 *
 * These cases use the no-config / non-gated / malformed paths so the subprocess never needs a live
 * relay; the full crypto round-trip is covered deterministically in integration.test.mjs.
 *
 * @see https://code.claude.com/docs/en/hooks (the stdin/stdout/exit-code contract)
 * @see ../../../docs/architecture.md (WASM-local: node entrypoint, never a native binary)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

/** Run the compiled hook bin under `node`, feeding `stdin`; resolves `{ code, stdout, stderr }`. */
function runCli(stdin, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI], {
      // A clean, minimal env so an ambient ALLW_* on the dev machine can't leak into the test.
      env: { PATH: process.env.PATH, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

/** Parse the single-line decision JSON the hook prints. */
function decisionOf(stdout) {
  return JSON.parse(stdout).hookSpecificOutput.permissionDecision;
}

test("subprocess: a non-gated tool (Read) emits allow and exits 0 (no config needed)", async () => {
  const stdin = JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Read",
    tool_input: { file_path: "/etc/hosts" },
  });
  const { code, stdout } = await runCli(stdin);
  assert.equal(code, 0, "the hook always exits 0 (it speaks in decisions, not error codes)");
  assert.equal(decisionOf(stdout), "allow");
});

test("subprocess: a gated Bash command with no config fails closed → deny, exit 0", async () => {
  const stdin = JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "rm -rf /" },
  });
  const { code, stdout } = await runCli(stdin);
  assert.equal(code, 0);
  assert.equal(decisionOf(stdout), "deny", "missing config blocks the gated command");
  assert.ok(
    /ALLW_RELAY_URL is not set/.test(
      JSON.parse(stdout).hookSpecificOutput.permissionDecisionReason,
    ),
  );
});

test("subprocess: malformed stdin fails closed → deny, exit 0", async () => {
  const { code, stdout } = await runCli("this is not json");
  assert.equal(code, 0);
  assert.equal(decisionOf(stdout), "deny");
});

test("subprocess: empty stdin fails closed → deny, exit 0", async () => {
  const { code, stdout } = await runCli("");
  assert.equal(code, 0);
  assert.equal(decisionOf(stdout), "deny");
});
