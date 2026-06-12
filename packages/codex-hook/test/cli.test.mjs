/**
 * End-to-end tests for `runCodexHook`, stopping at an injected SDK transport seam.
 *
 * These prove the process boundary remains fail-closed: malformed stdin and missing config produce
 * parseable `deny` decisions, while non-gated tools pass through without requiring allw env vars.
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runCodexHook } from "../dist/cli.js";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

function decisionOf(output) {
  return output.hookSpecificOutput.permissionDecision;
}

function runCli(stdin, cliPath = CLI) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath], {
      env: { PATH: process.env.PATH },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("allw-codex-hook subprocess did not exit within 5000ms"));
    }, 5000);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (data) => (stdout += data));
    child.stderr.on("data", (data) => (stderr += data));
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

function subprocessDecisionOf(stdout) {
  return JSON.parse(stdout).hookSpecificOutput.permissionDecision;
}

test("malformed stdin produces a Codex deny decision", async () => {
  const output = await runCodexHook("not json", {});

  assert.equal(decisionOf(output), "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /not valid JSON/);
});

test("gated actions with missing config deny before relay access", async () => {
  const output = await runCodexHook(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "git push origin main" },
    }),
    {},
  );

  assert.equal(decisionOf(output), "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /ALLW_RELAY_URL/);
});

test("non-gated tools pass through without config", async () => {
  const output = await runCodexHook(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_input: { file_path: "/tmp/a" },
    }),
    {},
  );

  assert.equal(decisionOf(output), "allow");
});

test("subprocess: non-gated Codex tool emits allow and exits 0 without config", async () => {
  const { code, stdout } = await runCli(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_input: { file_path: "/tmp/a" },
    }),
  );

  assert.equal(code, 0, "the hook exits 0 with an explicit Codex decision JSON");
  assert.equal(subprocessDecisionOf(stdout), "allow");
});

test("subprocess: installed symlinked bin emits allow and exits 0", async () => {
  const binDir = await mkdtemp(join(tmpdir(), "allw-codex-hook-bin-"));
  const binPath = join(binDir, "allw-codex-hook");
  try {
    // Package managers expose bins through symlinks; the CLI guard must still recognize itself.
    await symlink(CLI, binPath);
    const { code, stdout } = await runCli(
      JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: "Read",
        tool_input: { file_path: "/tmp/a" },
      }),
      binPath,
    );

    assert.equal(code, 0, "the installed bin exits 0 with an explicit Codex decision JSON");
    assert.equal(subprocessDecisionOf(stdout), "allow");
  } finally {
    await rm(binDir, { recursive: true, force: true });
  }
});

test("subprocess: gated Codex Bash with missing config emits deny and exits 0", async () => {
  const { code, stdout } = await runCli(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "git push origin main" },
    }),
  );

  assert.equal(code, 0);
  assert.equal(subprocessDecisionOf(stdout), "deny");
  assert.match(JSON.parse(stdout).hookSpecificOutput.permissionDecisionReason, /ALLW_RELAY_URL/);
});

test("subprocess: malformed Codex stdin emits deny and exits 0", async () => {
  const { code, stdout } = await runCli("not json");

  assert.equal(code, 0);
  assert.equal(subprocessDecisionOf(stdout), "deny");
});
