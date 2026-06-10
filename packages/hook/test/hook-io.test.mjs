/**
 * Tests for the PreToolUse hook wire-contract parsing/shaping (`parseHookInput`, output builders).
 *
 * Fail-closed: every malformed-stdin path must report `{ ok: false }` so the caller denies. The
 * output shape (`hookSpecificOutput.{hookEventName,permissionDecision,permissionDecisionReason}`) is
 * asserted verbatim against the verified contract.
 *
 * @see https://code.claude.com/docs/en/hooks (PreToolUse JSON schema)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { allowOutput, denyOutput, makeOutput, parseHookInput } from "../dist/lib/hook-io.js";

test("parses a well-formed Bash PreToolUse input", () => {
  const raw = JSON.stringify({
    session_id: "s1",
    transcript_path: "/tmp/t",
    cwd: "/repo",
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "ls -la" },
  });
  const result = parseHookInput(raw);
  assert.equal(result.ok, true);
  assert.equal(result.input.toolName, "Bash");
  assert.equal(result.input.cwd, "/repo");
  assert.deepEqual(result.input.toolInput, { command: "ls -la" });
});

test("cwd is optional — a payload without it still parses", () => {
  const raw = JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "pwd" },
  });
  const result = parseHookInput(raw);
  assert.equal(result.ok, true);
  assert.equal(result.input.cwd, undefined);
});

// ── fail-closed parse paths ───────────────────────────────────────────────────────────────────

test("non-JSON stdin → not ok (fail-closed)", () => {
  const result = parseHookInput("this is not json");
  assert.equal(result.ok, false);
  assert.ok(/not valid JSON/.test(result.reason));
});

test("JSON that is not an object (array) → not ok", () => {
  const result = parseHookInput("[1,2,3]");
  assert.equal(result.ok, false);
  assert.ok(/not a JSON object/.test(result.reason));
});

test("JSON that is not an object (string) → not ok", () => {
  const result = parseHookInput('"a bare string"');
  assert.equal(result.ok, false);
});

test("wrong hook_event_name → not ok", () => {
  const raw = JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: {} });
  const result = parseHookInput(raw);
  assert.equal(result.ok, false);
  assert.ok(/unexpected hook_event_name/.test(result.reason));
});

test("missing tool_name → not ok", () => {
  const raw = JSON.stringify({ hook_event_name: "PreToolUse", tool_input: {} });
  const result = parseHookInput(raw);
  assert.equal(result.ok, false);
  assert.ok(/missing a string 'tool_name'/.test(result.reason));
});

test("empty-string tool_name → not ok", () => {
  const raw = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "", tool_input: {} });
  assert.equal(parseHookInput(raw).ok, false);
});

// ── output builders ───────────────────────────────────────────────────────────────────────────

test("makeOutput/allowOutput/denyOutput produce the exact hookSpecificOutput shape", () => {
  const allow = allowOutput("ok");
  assert.deepEqual(allow, {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      permissionDecisionReason: "ok",
    },
  });

  const deny = denyOutput("nope");
  assert.equal(deny.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(deny.hookSpecificOutput.permissionDecisionReason, "nope");

  const ask = makeOutput("ask", "why");
  assert.equal(ask.hookSpecificOutput.permissionDecision, "ask");
});
