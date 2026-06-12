/**
 * Tests for the Codex PreToolUse hook wire contract.
 *
 * These pin the current Codex hook schema documented at developers.openai.com/codex/hooks:
 * Codex sends one JSON object on stdin with `hook_event_name`, `tool_name`, `tool_input`, and
 * optional `cwd`; a PreToolUse denial/allow decision is returned under `hookSpecificOutput`.
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

test("malformed stdin fails closed during parse", () => {
  assert.equal(parseCodexHookInput("not json").ok, false);
  assert.equal(parseCodexHookInput("[]").ok, false);
  assert.equal(
    parseCodexHookInput(JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "Bash" })).ok,
    false,
  );
  assert.equal(
    parseCodexHookInput(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "" })).ok,
    false,
  );
});

test("allowOutput and denyOutput emit the Codex PreToolUse hookSpecificOutput shape", () => {
  assert.deepEqual(allowOutput("approved by allw"), {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      permissionDecisionReason: "approved by allw",
    },
  });

  assert.deepEqual(denyOutput("blocked by allw"), {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "blocked by allw",
    },
  });
});
