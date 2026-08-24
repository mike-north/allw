/**
 * Tests for the Codex PreToolUse hook wire contract.
 *
 * These pin the current Codex hook schema documented at learn.chatgpt.com/docs/hooks: Codex sends
 * one JSON object on stdin with `hook_event_name`, `tool_name`, `tool_input`, and optional `cwd`;
 * a PreToolUse decision is returned under `hookSpecificOutput` on stdout, or nothing at all.
 *
 * `hookSpecificOutput` is documented as `additionalProperties: false`, so this package never emits
 * a field outside the documented set (see `../src/lib/codex-io.ts` and
 * `./support/codex-schema.mjs`). The machine-readable deny category is preserved by prefixing
 * `permissionDecisionReason` with `allw[<category>]: ` instead of adding an undocumented field.
 * Regression coverage for #191 (the undocumented `denyReason` field that made Codex silently
 * discard every deny) lives in `./regression-191.test.mjs`.
 *
 * @see https://learn.chatgpt.com/docs/hooks
 */

import assert from "node:assert/strict";
import test from "node:test";

import { denyOutput, noBlockOutput, parseCodexHookInput } from "../dist/lib/codex-io.js";
import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";

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

test("noBlockOutput emits null — never a wire permissionDecision:'allow'", () => {
  assert.equal(noBlockOutput(), null);
  assertConformsToPreToolUseOutputContract(noBlockOutput());
});

test("denyOutput emits only documented hookSpecificOutput fields, no denyReason", () => {
  const output = denyOutput("blocked by allw", "no-approval");

  assert.deepEqual(output, {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "allw[no-approval]: blocked by allw",
    },
  });
  assert.equal(
    Object.hasOwn(output.hookSpecificOutput, "denyReason"),
    false,
    "denyReason is not part of Codex's documented PreToolUse output contract (#191)",
  );
  assertConformsToPreToolUseOutputContract(output);
});

test("denyOutput strips a redundant leading 'allw: ' so the category prefix never doubles up", () => {
  const output = denyOutput("allw: ALLW_RELAY_URL is not set (fail-closed deny)", "config-error");

  assert.equal(
    output.hookSpecificOutput.permissionDecisionReason,
    "allw[config-error]: ALLW_RELAY_URL is not set (fail-closed deny)",
  );
});

test("denyOutput carries all DenyReason categories as a schema-conformant prefix", () => {
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
  for (const category of reasons) {
    const output = denyOutput("test", category);
    assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
    assert.match(
      output.hookSpecificOutput.permissionDecisionReason,
      new RegExp(`^allw\\[${category}\\]: `),
      `expected category '${category}' preserved as a permissionDecisionReason prefix`,
    );
    assertConformsToPreToolUseOutputContract(output);
  }
});

test("denyOutput never produces an empty permissionDecisionReason, even with an empty detail", () => {
  const output = denyOutput("", "build-error");

  assert.ok(output.hookSpecificOutput.permissionDecisionReason.length > 0);
  assertConformsToPreToolUseOutputContract(output);
});
