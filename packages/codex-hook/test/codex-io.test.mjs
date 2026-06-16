/**
 * Tests for the Codex PreToolUse hook wire contract.
 *
 * These pin the current Codex hook schema documented at developers.openai.com/codex/hooks:
 * Codex sends one JSON object on stdin with `hook_event_name`, `tool_name`, `tool_input`, and
 * optional `cwd`; a PreToolUse denial/allow decision is returned under `hookSpecificOutput`.
 *
 * Deny outputs carry a `denyReason` category in `hookSpecificOutput` so operators can
 * distinguish failure kinds without parsing the human-readable `permissionDecisionReason`.
 *
 * @see https://developers.openai.com/codex/hooks
 */

import assert from "node:assert/strict";
import test from "node:test";

import { allowOutput, denyOutput, parseCodexHookInput } from "../dist/lib/codex-io.js";

test("parses a well-formed Codex Bash PreToolUse input", () => {
  const raw = JSON.stringify({
    session_id: "s1",
    turn_id: "t1",
    tool_use_id: "call-1",
    transcript_path: "/tmp/codex.jsonl",
    cwd: "/repo",
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "git push origin main" },
  });

  const result = parseCodexHookInput(raw);

  assert.equal(result.ok, true);
  assert.equal(result.input.toolName, "Bash");
  assert.equal(result.input.cwd, "/repo");
  assert.equal(result.input.toolUseId, "call-1");
  assert.deepEqual(result.input.toolInput, { command: "git push origin main" });
});

test("parses MCP tool input verbatim", () => {
  const raw = JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "mcp__filesystem__write_file",
    tool_input: { path: "/tmp/a", content: "hello" },
  });

  const result = parseCodexHookInput(raw);

  assert.equal(result.ok, true);
  assert.equal(result.input.toolName, "mcp__filesystem__write_file");
  assert.deepEqual(result.input.toolInput, { path: "/tmp/a", content: "hello" });
});

test("malformed stdin fails closed during parse with denyReason=input-parse-error", () => {
  const cases = [
    "not json",
    "[]",
    JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "Bash" }),
    JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "" }),
  ];
  for (const raw of cases) {
    const result = parseCodexHookInput(raw);
    assert.equal(result.ok, false, `expected failure for: ${raw}`);
    assert.equal(
      result.denyReason,
      "input-parse-error",
      `expected denyReason=input-parse-error for: ${raw}`,
    );
  }
});

test("allowOutput emits the Codex PreToolUse hookSpecificOutput shape without denyReason", () => {
  assert.deepEqual(allowOutput("approved by allw"), {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      permissionDecisionReason: "approved by allw",
    },
  });
});

test("denyOutput emits the Codex PreToolUse hookSpecificOutput shape with denyReason", () => {
  assert.deepEqual(denyOutput("blocked by allw", "no-approval"), {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "blocked by allw",
      denyReason: "no-approval",
    },
  });
});

test("denyOutput carries all DenyReason categories correctly", () => {
  /** @type {Array<import('../dist/lib/codex-io.js').DenyReason>} */
  const reasons = [
    "input-parse-error",
    "config-error",
    "build-error",
    "transport-error",
    "no-approval",
    "timeout",
    "aborted",
  ];
  for (const reason of reasons) {
    const output = denyOutput("test", reason);
    assert.equal(output.hookSpecificOutput.denyReason, reason);
    assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  }
});
