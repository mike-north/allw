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

// ── Regression (#49 review, Copilot): fail-open gap on malformed mcp__-prefixed names ────────────
//
// The recommended .claude/settings.json matcher is `mcp__.*`, so Claude Code routes EVERY
// mcp__-prefixed name to the hook — including malformed ones that don't parse as
// `mcp__<server>__<tool>` (e.g. `mcp__server__`, `mcp__onlytwo`). Before the fix, `isGatedTool`
// returned false for these (→ pass-through allow) and `gateToolCall` fell through to pass-through —
// silently ALLOWING an MCP call, breaking fail-closed. They must now be gated and DENIED.

test("a malformed mcp__-prefixed name is GATED (not silently passed through)", () => {
  // Each of these is mcp__-prefixed but not a well-formed mcp__<server>__<tool>.
  for (const t of ["mcp__server__", "mcp__onlytwo", "mcp__", "mcp____tool"]) {
    assert.equal(isGatedTool(t), true, `${t} is mcp__-prefixed → must be gated (fail-closed)`);
  }
});

test("gateToolCall(malformed mcp__ name) → build-error (fail-closed deny), NOT pass-through", async () => {
  const wasm = await loadWasm();
  for (const t of ["mcp__server__", "mcp__onlytwo", "mcp____tool"]) {
    const out = gateToolCall(wasm, t, { x: 1 }, "/repo");
    assert.equal(
      out.kind,
      "build-error",
      `${t} must be a build-error (deny), never pass-through (the pre-fix fail-open bug)`,
    );
    assert.ok(/not a well-formed/.test(out.reason), "the deny reason explains the malformed name");
  }
});

test("a well-formed mcp__server__tool still parses and gates normally (no regression)", async () => {
  const wasm = await loadWasm();
  assert.equal(isGatedTool("mcp__omnifocus__delete_project"), true);
  const out = gateToolCall(wasm, "mcp__omnifocus__delete_project", { id: "abc" }, undefined);
  assert.equal(out.kind, "gated", "a well-formed MCP name still gates and builds a record");
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
