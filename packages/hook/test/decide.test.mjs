/**
 * Decision-matrix tests for the Claude Code PreToolUse hook (issue #13).
 *
 * Drives `decide` (the I/O-free core) with the **real WASM core** for `ActionRecord` construction
 * and an **injectable `requestApproval` double** for the verdict, asserting the EXACT emitted hook
 * JSON (`hookSpecificOutput.permissionDecision`). This pins the fail-closed mapping from
 * `docs/contract.md` §Invariants #6: only a verified `approved` verdict becomes `allow`; every other
 * path — a verified non-approval, a timeout/expiry, a thrown approval call, a build error — denies.
 * Non-gated tools pass through as `allow` without ever calling the approver.
 *
 * @see ../../../docs/contract.md §Invariants #6 (fail-closed)
 * @see https://code.claude.com/docs/en/hooks (the PreToolUse decision JSON we assert against)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { decide } from "../dist/lib/decide.js";
import { loadWasm } from "../dist/lib/wasm.js";

const HOSTNAME = "test-host";

/** A resolved config (the relay coordinates are never dialed — requestApproval is a double here). */
const CONFIG = {
  relayUrl: "https://relay.allw.test",
  accountId: "acct-test",
  approverRootKey: "x".repeat(43),
};

/** A `requestApproval` double that always resolves to the given decision. */
function resolvesTo(decision) {
  return () => Promise.resolve({ decision });
}

/** A `requestApproval` double that records the request it was called with. */
function recording(decision) {
  const calls = [];
  const fn = (req) => {
    calls.push(req);
    return Promise.resolve({ decision });
  };
  return { fn, calls };
}

/** Pull the decision + reason out of an emitted hook output. */
function decisionOf(output) {
  return output.hookSpecificOutput.permissionDecision;
}

/** A Bash PreToolUse input for a given command. */
function bashInput(command, cwd) {
  return {
    hookEventName: "PreToolUse",
    toolName: "Bash",
    toolInput: { command },
    ...(cwd !== undefined ? { cwd } : {}),
  };
}

test("approved verdict → allow, and the emitted JSON is the exact PreToolUse decision shape", async () => {
  const wasm = await loadWasm();
  const output = await decide(
    bashInput("git push --force origin main", "/repo"),
    { wasm, config: CONFIG, requestApproval: resolvesTo("approved") },
    HOSTNAME,
  );

  // Assert the FULL stdout shape against the verified contract (field names/values are load-bearing).
  assert.equal(output.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(output.hookSpecificOutput.permissionDecision, "allow");
  assert.equal(typeof output.hookSpecificOutput.permissionDecisionReason, "string");
  assert.ok(
    output.hookSpecificOutput.permissionDecisionReason.includes("approved"),
    "the allow reason notes the human approval",
  );
});

test("denied verdict → deny", async () => {
  const wasm = await loadWasm();
  const output = await decide(
    bashInput("rm -rf build"),
    { wasm, config: CONFIG, requestApproval: resolvesTo("denied") },
    HOSTNAME,
  );
  assert.equal(decisionOf(output), "deny");
  assert.ok(output.hookSpecificOutput.permissionDecisionReason.includes("denied"));
});

test("expired verdict (timeout) → deny", async () => {
  const wasm = await loadWasm();
  const output = await decide(
    bashInput("rm -rf build"),
    { wasm, config: CONFIG, requestApproval: resolvesTo("expired") },
    HOSTNAME,
  );
  assert.equal(decisionOf(output), "deny");
  assert.ok(output.hookSpecificOutput.permissionDecisionReason.includes("expired"));
});

test("aborted verdict → deny", async () => {
  const wasm = await loadWasm();
  const output = await decide(
    bashInput("rm -rf build"),
    { wasm, config: CONFIG, requestApproval: resolvesTo("aborted") },
    HOSTNAME,
  );
  assert.equal(decisionOf(output), "deny");
});

test("requestApproval throws (network/relay error) → deny (never allow on failure)", async () => {
  const wasm = await loadWasm();
  const output = await decide(
    bashInput("rm -rf build"),
    {
      wasm,
      config: CONFIG,
      requestApproval: () => Promise.reject(new Error("relay unreachable")),
    },
    HOSTNAME,
  );
  assert.equal(decisionOf(output), "deny");
  assert.ok(
    output.hookSpecificOutput.permissionDecisionReason.includes("relay unreachable"),
    "the deny reason surfaces the underlying failure",
  );
});

test("non-gated tool (Read) → allow pass-through WITHOUT calling the approver", async () => {
  const wasm = await loadWasm();
  const approver = recording("denied"); // would deny if (wrongly) called
  const output = await decide(
    { hookEventName: "PreToolUse", toolName: "Read", toolInput: { file_path: "/etc/hosts" } },
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );
  assert.equal(decisionOf(output), "allow", "a non-gated tool passes through");
  assert.equal(approver.calls.length, 0, "the human is never bothered for a non-gated tool");
});

test("gated Bash with a malformed command (unmatched quote) → deny, approver NOT called", async () => {
  const wasm = await loadWasm();
  const approver = recording("approved");
  const output = await decide(
    bashInput('echo "unterminated'),
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );
  assert.equal(decisionOf(output), "deny", "an unbuildable ActionRecord fails closed");
  assert.equal(approver.calls.length, 0, "no approval is requested when the record can't be built");
});

test("gated Bash missing tool_input.command → deny (fail-closed)", async () => {
  const wasm = await loadWasm();
  const output = await decide(
    { hookEventName: "PreToolUse", toolName: "Bash", toolInput: {} },
    { wasm, config: CONFIG, requestApproval: resolvesTo("approved") },
    HOSTNAME,
  );
  assert.equal(decisionOf(output), "deny");
});

test("regression (#49): a malformed mcp__-prefixed tool name → deny, approver NOT called", async () => {
  // The `mcp__.*` settings matcher routes these to the hook; before the fix they passed through as
  // `allow`. They must now deny (fail-closed) — and must never even reach the approver.
  const wasm = await loadWasm();
  for (const toolName of ["mcp__server__", "mcp__onlytwo"]) {
    const approver = recording("approved");
    const output = await decide(
      { hookEventName: "PreToolUse", toolName, toolInput: { x: 1 } },
      { wasm, config: CONFIG, requestApproval: approver.fn },
      HOSTNAME,
    );
    assert.equal(decisionOf(output), "deny", `${toolName} must fail closed (not allow)`);
    assert.equal(
      approver.calls.length,
      0,
      "a name we can't build a record for never asks the human",
    );
  }
});

test("MCP tool call is gated; approved → allow, with the request built from the parsed name/params", async () => {
  const wasm = await loadWasm();
  const approver = recording("approved");
  const output = await decide(
    {
      hookEventName: "PreToolUse",
      toolName: "mcp__omnifocus__delete_project",
      toolInput: { project_id: "abc", list: "Agent Inbox" },
    },
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  assert.equal(decisionOf(output), "allow");
  assert.equal(approver.calls.length, 1, "the MCP tool call is gated → one approval requested");

  // The submitted request carries the mcp_tool_call ActionRecord built by the core.
  const req = approver.calls[0];
  assert.equal(req.action.surface, "mcp_tool_call");
  assert.equal(req.action.syntactic.server, "omnifocus");
  assert.equal(req.action.syntactic.tool, "delete_project");
  assert.deepEqual(req.action.syntactic.params, { project_id: "abc", list: "Agent Inbox" });
  // delete* → High risk (core heuristic).
  assert.equal(req.action.risk, "high");
  // Actor identity is machine:<hostname>, kind claude-code.
  assert.equal(req.actor.id, `machine:${HOSTNAME}`);
  assert.equal(req.actor.kind, "claude-code");
});

test("the ApprovalRequest carries the command ActionRecord + actor + risk-derived reversible", async () => {
  const wasm = await loadWasm();
  const approver = recording("approved");
  await decide(
    bashInput("ls -la", "/workspace"),
    { wasm, config: CONFIG, requestApproval: approver.fn },
    HOSTNAME,
  );

  const req = approver.calls[0];
  assert.equal(req.action.surface, "command");
  assert.equal(req.action.syntactic.bin, "ls");
  assert.equal(req.action.syntactic.cwd, "/workspace", "cwd is threaded into the record");
  // `ls` is Low risk → reversible defaults to true.
  assert.equal(req.action.risk, "low");
  assert.equal(req.reversible, true, "low/medium risk → reversible hint true");
});
