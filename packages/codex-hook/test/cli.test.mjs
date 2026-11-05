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
import { mkdtempSync, rmSync } from "node:fs";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath } from "node:url";

import { runCodexHook } from "../dist/cli.js";
import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";

/** Isolate persisted sequence floors from the developer's ~/.allw. */
const CHILD_HOME = mkdtempSync(join(tmpdir(), "allw-hook-child-home-"));
after(() => rmSync(CHILD_HOME, { recursive: true, force: true }));

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

function runCli(stdin, cliPath = CLI, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath], {
      env: { PATH: process.env.PATH, HOME: CHILD_HOME, ...env },
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

// ── env-sourced text in a config deny reason is escaped (#358) ──────────────────────────────────

/** An `ALLW_CONFIG` that would forge a line and clear the screen if quoted raw. */
const HOSTILE_CONFIG_PATH = "/nonexistent-allw-358/line\nallw: APPROVED\u001b[2J.json";

/** A C0/C1 control character or DEL. */
const CONTROL_CHAR = /[\x00-\x1f\x7f-\x9f]/u;

/** Assert a schema-conformant config-error deny quoting the hostile path escaped. */
function assertEscapedConfigDeny(output) {
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  const reason = output.hookSpecificOutput.permissionDecisionReason;
  assert.match(reason, /^allw\[config-error\]: /);
  assert.doesNotMatch(reason, CONTROL_CHAR, reason);
  assert.ok(
    reason.includes("/nonexistent-allw-358/line\\u000aallw: APPROVED\\u001b[2J.json"),
    `the path is quoted escaped: ${reason}`,
  );
  assertConformsToPreToolUseOutputContract(output);
}

const GATED_STDIN = JSON.stringify({
  hook_event_name: "PreToolUse",
  tool_name: "Bash",
  tool_input: { command: "git push origin main" },
});

test("(#358) an ALLW_CONFIG with a newline and ESC gives a config-error deny with no raw control characters", async () => {
  assertEscapedConfigDeny(await runCodexHook(GATED_STDIN, { ALLW_CONFIG: HOSTILE_CONFIG_PATH }));
});

test("(#358) subprocess: the same ALLW_CONFIG through the real bin", async () => {
  const { code, stdout } = await runCli(GATED_STDIN, CLI, { ALLW_CONFIG: HOSTILE_CONFIG_PATH });
  assert.equal(code, 0);
  assertEscapedConfigDeny(JSON.parse(stdout));
});
