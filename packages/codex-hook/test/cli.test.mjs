/**
 * End-to-end tests for `runCodexHook`, stopping at an injected SDK transport seam.
 *
 * These prove the process boundary remains fail-closed: malformed stdin and missing config produce
 * parseable `deny` decisions, while non-gated tools pass through without requiring allw env vars.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { runCodexHook } from "../dist/cli.js";

function decisionOf(output) {
  return output.hookSpecificOutput.permissionDecision;
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
