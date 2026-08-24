/**
 * End-to-end tests for `runCodexHook`, stopping at an injected SDK transport seam, plus real
 * subprocess tests for the actual stdin/stdout process boundary Codex drives.
 *
 * These prove the process boundary remains fail-closed: malformed stdin and missing config produce
 * an explicit, schema-conformant `deny` (never an undocumented `denyReason` field — #191), while
 * non-gated tools produce empty stdout + exit 0 rather than a wire `permissionDecision: "allow"`.
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runCodexHook } from "../dist/cli.js";
import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

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

test("malformed stdin produces a Codex deny with category=input-parse-error", async () => {
  const output = await runCodexHook("not json", {});

  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /not valid JSON/);
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /^allw\[input-parse-error\]: /);
  assertConformsToPreToolUseOutputContract(output);
});

test("gated actions with missing config deny with category=config-error", async () => {
  const output = await runCodexHook(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "git push origin main" },
    }),
    {},
  );

  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /ALLW_RELAY_URL/);
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /^allw\[config-error\]: /);
  assertConformsToPreToolUseOutputContract(output);
});

test("non-gated tools produce null — no output, not permissionDecision:'allow'", async () => {
  const output = await runCodexHook(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_input: { file_path: "/tmp/a" },
    }),
    {},
  );

  assert.equal(output, null);
  assertConformsToPreToolUseOutputContract(output);
});

test("subprocess: non-gated Codex tool emits empty stdout and exits 0", async () => {
  const { code, stdout, stderr } = await runCli(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_input: { file_path: "/tmp/a" },
    }),
  );

  assert.equal(code, 0, "Codex treats exit 0 with no output as a clean success");
  assert.equal(stdout, "", "the hook must write nothing to stdout when it does not block");
  assert.equal(stderr, "");
});

test("subprocess: installed symlinked bin emits empty stdout and exits 0", async () => {
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

    assert.equal(code, 0, "the installed bin exits 0 with no output when it does not block");
    assert.equal(stdout, "");
  } finally {
    await rm(binDir, { recursive: true, force: true });
  }
});

test("subprocess: gated Codex Bash with missing config emits a schema-conformant deny and exits 0", async () => {
  const { code, stdout } = await runCli(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "git push origin main" },
    }),
  );

  assert.equal(code, 0);
  const output = JSON.parse(stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /ALLW_RELAY_URL/);
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /^allw\[config-error\]: /);
  assertConformsToPreToolUseOutputContract(output);
});

test("subprocess: malformed Codex stdin emits a schema-conformant deny and exits 0", async () => {
  const { code, stdout } = await runCli("not json");

  assert.equal(code, 0);
  const output = JSON.parse(stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /^allw\[input-parse-error\]: /);
  assertConformsToPreToolUseOutputContract(output);
});
