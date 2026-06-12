/**
 * Decision tests for the Codex PreToolUse hook.
 *
 * The hook must mirror the Claude Code hook's fail-closed mapping while using a distinct Codex
 * actor identity. Only a verified `approved` verdict becomes a Codex `allow`; denied, expired,
 * aborted, build failures, and approval transport errors all produce `deny`.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { decide } from "../dist/lib/decide.js";
import { loadWasm } from "@allw/hook";

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

function decisionOf(output) {
  return output.hookSpecificOutput.permissionDecision;
}

test("approved Bash verdict allows Codex and carries a distinct Codex actor", async () => {
  const wasm = await loadWasm();
  const approver = recording("approved");

  const output = await decide(
    bashInput("git push origin main", "/repo", "call-1"),
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  assert.equal(decisionOf(output), "allow");
  assert.equal(approver.calls.length, 1);
  assert.equal(approver.calls[0].actor.id, `codex:${HOSTNAME}`);
  assert.equal(approver.calls[0].actor.kind, "codex");
  assert.equal(approver.calls[0].action.surface, "command");
  assert.equal(approver.calls[0].action.syntactic.cwd, "/repo");
  assert.deepEqual(approver.calls[0].chain, ["codex:tool_use_id:call-1"]);
});

test("non-approved verdicts deny Codex fail-closed", async () => {
  const wasm = await loadWasm();
  for (const verdict of ["denied", "expired", "aborted"]) {
    const output = await decide(
      bashInput("rm -rf build"),
      { wasm, config: CONFIG, requestApproval: () => Promise.resolve({ decision: verdict }) },
      HOSTNAME,
    );
    assert.equal(decisionOf(output), "deny", `${verdict} must deny`);
    assert.match(output.hookSpecificOutput.permissionDecisionReason, new RegExp(verdict));
  }
});

test("approval transport errors deny Codex fail-closed", async () => {
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

  assert.equal(decisionOf(output), "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /relay unavailable/);
});

test("malformed gated inputs deny before asking the approver", async () => {
  const wasm = await loadWasm();
  const approver = recording("approved");

  const output = await decide(
    bashInput('echo "unterminated'),
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  assert.equal(decisionOf(output), "deny");
  assert.equal(approver.calls.length, 0);
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

  assert.equal(decisionOf(output), "allow");
  assert.equal(approver.calls[0].action.surface, "mcp_tool_call");
  assert.equal(approver.calls[0].action.syntactic.server, "filesystem");
  assert.equal(approver.calls[0].action.syntactic.tool, "write_file");
  assert.deepEqual(approver.calls[0].action.syntactic.params, {
    path: "/tmp/a",
    content: "hello",
  });
});

test("non-gated Codex tools pass through without config-time approval", async () => {
  const wasm = await loadWasm();
  const approver = recording("denied");

  const output = await decide(
    { hookEventName: "PreToolUse", toolName: "Read", toolInput: { file_path: "/tmp/a" } },
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  assert.equal(decisionOf(output), "allow");
  assert.equal(approver.calls.length, 0);
});
