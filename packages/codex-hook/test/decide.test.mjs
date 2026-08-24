/**
 * Decision tests for the Codex PreToolUse hook.
 *
 * The hook must mirror the Claude Code hook's fail-closed mapping while using a distinct Codex
 * actor identity. Only a verified `approved` verdict (and non-gated tools) become "allw does not
 * block" — encoded as `null` (empty stdout), never a wire `permissionDecision: "allow"` (#191).
 * Denied, expired, aborted, build failures, and approval transport errors all produce an explicit,
 * schema-conformant `deny` whose `permissionDecisionReason` carries the machine-readable category
 * as an `allw[<category>]: ` prefix (Codex's `hookSpecificOutput` has no room for a separate
 * `denyReason` field — see `../src/lib/codex-io.ts`).
 */

import assert from "node:assert/strict";
import test from "node:test";

import { decide } from "../dist/lib/decide.js";
import { loadWasm } from "@allw/hook";
import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";

const HOSTNAME = "devbox-1";
const CONFIG = {
  relayUrl: "https://relay.allw.test",
  accountId: "acct-test",
  approverRootKey: "x".repeat(43),
};

function bashInput(command, cwd, toolUseId) {
  return {
    hookEventName: "PreToolUse",
    toolName: "Bash",
    toolInput: { command },
    ...(cwd ? { cwd } : {}),
    ...(toolUseId ? { toolUseId } : {}),
  };
}

function recording(decision) {
  const calls = [];
  return {
    calls,
    fn(req) {
      calls.push(req);
      return Promise.resolve({ decision });
    },
  };
}

test("approved Bash verdict does not block and carries a distinct Codex actor", async () => {
  const wasm = await loadWasm();
  const approver = recording("approved");

  const output = await decide(
    bashInput("git push origin main", "/repo", "call-1"),
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  assert.equal(output, null, "an approved verdict must be silence, not permissionDecision:'allow'");
  assertConformsToPreToolUseOutputContract(output);
  assert.equal(approver.calls.length, 1);
  assert.equal(approver.calls[0].actor.id, `codex:${HOSTNAME}`);
  assert.equal(approver.calls[0].actor.kind, "codex");
  assert.equal(approver.calls[0].action.surface, "command");
  assert.equal(approver.calls[0].action.syntactic.cwd, "/repo");
  assert.deepEqual(approver.calls[0].chain, ["codex:tool_use_id:call-1"]);
});

test("non-approved verdicts deny Codex fail-closed with the correct category prefix", async () => {
  const wasm = await loadWasm();

  /** @type {Array<[string, import('../dist/lib/codex-io.js').DenyReason]>} */
  const cases = [
    ["denied", "no-approval"],
    ["expired", "timeout"],
    ["aborted", "aborted"],
  ];
  for (const [verdict, expectedCategory] of cases) {
    const output = await decide(
      bashInput("rm -rf build"),
      { wasm, config: CONFIG, requestApproval: () => Promise.resolve({ decision: verdict }) },
      HOSTNAME,
    );
    assert.equal(output.hookSpecificOutput.permissionDecision, "deny", `${verdict} must deny`);
    assert.match(output.hookSpecificOutput.permissionDecisionReason, new RegExp(verdict));
    assert.match(
      output.hookSpecificOutput.permissionDecisionReason,
      new RegExp(`^allw\\[${expectedCategory}\\]: `),
      `verdict '${verdict}' must carry category '${expectedCategory}' as a reason prefix`,
    );
    assertConformsToPreToolUseOutputContract(output);
  }
});

test("approval transport errors deny Codex fail-closed with category=transport-error", async () => {
  const wasm = await loadWasm();
  const output = await decide(
    bashInput("rm -rf build"),
    {
      wasm,
      config: CONFIG,
      requestApproval: () => Promise.reject(new Error("relay unavailable")),
    },
    HOSTNAME,
  );

  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /relay unavailable/);
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /^allw\[transport-error\]: /);
  assertConformsToPreToolUseOutputContract(output);
});

test("malformed gated inputs deny before asking the approver with category=build-error", async () => {
  const wasm = await loadWasm();
  const approver = recording("approved");

  const output = await decide(
    bashInput('echo "unterminated'),
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /^allw\[build-error\]: /);
  assert.equal(approver.calls.length, 0);
  assertConformsToPreToolUseOutputContract(output);
});

test("MCP tools are gated through the shared ActionRecord builder", async () => {
  const wasm = await loadWasm();
  const approver = recording("approved");

  const output = await decide(
    {
      hookEventName: "PreToolUse",
      toolName: "mcp__filesystem__write_file",
      toolInput: { path: "/tmp/a", content: "hello" },
    },
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  assert.equal(output, null, "an approved verdict must be silence, not permissionDecision:'allow'");
  assertConformsToPreToolUseOutputContract(output);
  assert.equal(approver.calls[0].action.surface, "mcp_tool_call");
  assert.equal(approver.calls[0].action.syntactic.server, "filesystem");
  assert.equal(approver.calls[0].action.syntactic.tool, "write_file");
  assert.deepEqual(approver.calls[0].action.syntactic.params, {
    path: "/tmp/a",
    content: "hello",
  });
});

test("Codex apply_patch is gated through the file_edit ActionRecord builder", async () => {
  const wasm = await loadWasm();
  const approver = recording("approved");
  const patch = [
    "*** Begin Patch",
    "*** Update File: src/app.ts",
    "@@",
    "-old",
    "+new",
    "*** End Patch",
    "",
  ].join("\n");

  const output = await decide(
    {
      hookEventName: "PreToolUse",
      toolName: "apply_patch",
      toolInput: { patch },
      toolUseId: "patch-call-1",
    },
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  assert.equal(output, null, "an approved verdict must be silence, not permissionDecision:'allow'");
  assertConformsToPreToolUseOutputContract(output);
  assert.equal(approver.calls.length, 1, "apply_patch must request approval");
  assert.equal(approver.calls[0].action.surface, "file_edit");
  assert.equal(approver.calls[0].action.syntactic.operation, "patch");
  assert.deepEqual(approver.calls[0].action.syntactic.paths, ["src/app.ts"]);
  assert.equal(typeof approver.calls[0].action.syntactic.diff_hash, "string");
  assert.deepEqual(approver.calls[0].chain, ["codex:tool_use_id:patch-call-1"]);
});

test("non-gated Codex tools pass through without config-time approval", async () => {
  const wasm = await loadWasm();
  const approver = recording("denied");

  const output = await decide(
    { hookEventName: "PreToolUse", toolName: "Read", toolInput: { file_path: "/tmp/a" } },
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  assert.equal(output, null, "a non-gated tool must be silence, not permissionDecision:'allow'");
  assertConformsToPreToolUseOutputContract(output);
  assert.equal(approver.calls.length, 0);
});
