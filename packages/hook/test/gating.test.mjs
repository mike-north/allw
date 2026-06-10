/**
 * Tests for the hook's gating matcher: which tools are gated, MCP tool-name parsing, and the
 * `ActionRecord`-building outcomes (gated / pass-through / build-error). Uses the real WASM core.
 *
 * @see https://code.claude.com/docs/en/hooks (tool_name, mcp__server__tool naming)
 * @see ../../../docs/policy-seam.md §The three tiers (surfaces)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { gateToolCall, isGatedTool, parseMcpToolName } from "../dist/lib/gating.js";
import { loadWasm } from "../dist/lib/wasm.js";

// ── MCP tool-name parsing ───────────────────────────────────────────────────────────────────────

test("parseMcpToolName splits mcp__server__tool", () => {
  assert.deepEqual(parseMcpToolName("mcp__omnifocus__delete_project"), {
    server: "omnifocus",
    tool: "delete_project",
  });
});

test("parseMcpToolName keeps extra __ in the tool segment", () => {
  assert.deepEqual(parseMcpToolName("mcp__srv__a__b"), { server: "srv", tool: "a__b" });
});

test("parseMcpToolName returns null for non-MCP names and malformed forms", () => {
  assert.equal(parseMcpToolName("Bash"), null);
  assert.equal(parseMcpToolName("mcp__"), null);
  assert.equal(parseMcpToolName("mcp__server__"), null, "empty tool segment → null");
  assert.equal(parseMcpToolName("mcp____tool"), null, "empty server segment → null");
});

// ── which tools are gated ─────────────────────────────────────────────────────────────────────

test("Bash and MCP tools are gated; everything else is not", () => {
  assert.equal(isGatedTool("Bash"), true);
  assert.equal(isGatedTool("mcp__gh__create_pr"), true);
  for (const t of ["Read", "Edit", "Write", "Glob", "Grep", "WebFetch", "Task"]) {
    assert.equal(isGatedTool(t), false, `${t} must not be gated in v0`);
  }
});

// ── gate outcomes (real WASM) ───────────────────────────────────────────────────────────────────

test("gateToolCall(Bash) → gated with a command ActionRecord and a one-line summary", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "Bash", { command: "git push --force" }, "/repo");
  assert.equal(out.kind, "gated");
  const record = JSON.parse(out.actionRecord);
  assert.equal(record.surface, "command");
  assert.equal(record.syntactic.cwd, "/repo");
  assert.ok(out.summary.includes("git push --force"));
  assert.ok(!out.summary.includes("\n"), "summary is a single line");
});

test("gateToolCall(Bash) without cwd still builds (cwd unknown)", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "Bash", { command: "ls" }, undefined);
  assert.equal(out.kind, "gated");
});

test("gateToolCall(Bash) with a non-string command → build-error", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "Bash", { command: 42 }, "/repo");
  assert.equal(out.kind, "build-error");
});

test("gateToolCall(Bash) with malformed shell (unmatched quote) → build-error (fail-closed)", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "Bash", { command: 'echo "oops' }, "/repo");
  assert.equal(out.kind, "build-error");
});

test("gateToolCall(MCP) → gated with an mcp_tool_call ActionRecord (params verbatim)", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(
    wasm,
    "mcp__omnifocus__delete_project",
    { project_id: "abc", list: "Agent Inbox" },
    "/repo",
  );
  assert.equal(out.kind, "gated");
  const record = JSON.parse(out.actionRecord);
  assert.equal(record.surface, "mcp_tool_call");
  assert.equal(record.syntactic.server, "omnifocus");
  assert.equal(record.syntactic.tool, "delete_project");
  assert.deepEqual(record.syntactic.params, { project_id: "abc", list: "Agent Inbox" });
});

test("gateToolCall(MCP) with no params defaults to an empty object", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "mcp__srv__list", undefined, undefined);
  assert.equal(out.kind, "gated");
  const record = JSON.parse(out.actionRecord);
  assert.deepEqual(record.syntactic.params, {});
});

test("gateToolCall(non-gated) → pass-through", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "Read", { file_path: "/etc/hosts" }, "/repo");
  assert.equal(out.kind, "pass-through");
});
