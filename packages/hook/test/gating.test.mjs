/**
 * Tests for the hook's gating matcher: which tools are gated, MCP tool-name parsing, and the
 * `ActionRecord`-building outcomes (gated / pass-through / build-error). Uses the real WASM core.
 *
 * @see https://code.claude.com/docs/en/hooks (tool_name, mcp__server__tool naming)
 * @see ../../../docs/action-record.md §The action record (surfaces)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  gateToolCall,
  isGatedTool,
  parseMcpToolName,
  commandBuildFailureReason,
  posixCommandCall,
} from "../dist/lib/gating.js";
import { decide } from "../dist/lib/decide.js";
import { commandRequest } from "@allw/sdk";
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

test("Bash, MCP, and file-edit tools are gated; read-only tools are not", () => {
  assert.equal(isGatedTool("Bash"), true);
  assert.equal(isGatedTool("mcp__gh__create_pr"), true);
  for (const t of ["PowerShell", "Monitor"]) {
    assert.equal(isGatedTool(t), true, `${t} runs shell commands, so it must be gated (#298)`);
  }
  for (const t of ["Edit", "MultiEdit", "Write", "NotebookEdit", "apply_patch"]) {
    assert.equal(isGatedTool(t), true, `${t} must be gated as a file-edit surface`);
  }
  for (const t of ["Read", "Glob", "Grep", "WebFetch", "Task"]) {
    assert.equal(isGatedTool(t), false, `${t} must not be gated in v0`);
  }
});

// ── Regression (#49 review, Copilot): fail-open gap on malformed mcp__-prefixed names ────────────
//
// The recommended .claude/settings.json matcher includes `^mcp__`, so Claude Code routes EVERY
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
  assert.equal(record.facts.cwd, "/repo");
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

test("gateToolCall(Bash) with a non-string command → build-error (fail-closed)", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "Bash", { command: 42 }, "/repo");
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
  assert.equal(record.facts.server, "omnifocus");
  assert.equal(record.facts.tool, "delete_project");
  assert.deepEqual(record.facts.params, { project_id: "abc", list: "Agent Inbox" });
});

test("gateToolCall(MCP) with no params defaults to an empty object", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "mcp__srv__list", undefined, undefined);
  assert.equal(out.kind, "gated");
  const record = JSON.parse(out.actionRecord);
  assert.deepEqual(record.facts.params, {});
});

test("gateToolCall(apply_patch) → gated with a file_edit ActionRecord", async () => {
  const wasm = await loadWasm();
  const patch = [
    "*** Begin Patch",
    "*** Update File: src/app.ts",
    "@@",
    "-old",
    "+new",
    "*** End Patch",
    "",
  ].join("\n");
  const out = gateToolCall(wasm, "apply_patch", { patch }, "/repo");
  assert.equal(out.kind, "gated");
  const record = JSON.parse(out.actionRecord);
  assert.equal(record.surface, "file_edit");
  assert.equal(record.facts.operation, "patch");
  assert.deepEqual(record.facts.paths, ["src/app.ts"]);
  assert.match(record.facts.diff_summary, /src\/app\.ts/);
  assert.equal(typeof record.facts.diff_hash, "string");
  assert.match(out.summary, /file edit/i);
});

test("gateToolCall(apply_patch rename) captures both source and destination paths", async () => {
  const wasm = await loadWasm();
  const patch = [
    "*** Begin Patch",
    "*** Update File: src/old.ts",
    "*** Move to: src/new.ts",
    "@@",
    "-old",
    "+new",
    "*** End Patch",
    "",
  ].join("\n");
  const out = gateToolCall(wasm, "apply_patch", { patch }, "/repo");
  assert.equal(out.kind, "gated");
  const record = JSON.parse(out.actionRecord);
  assert.equal(record.surface, "file_edit");
  assert.deepEqual(record.facts.paths, ["src/old.ts", "src/new.ts"]);
});

test("gateToolCall(Claude Edit/Write/MultiEdit) → gated file_edit records", async () => {
  const wasm = await loadWasm();
  const cases = [
    ["Edit", { file_path: "/repo/src/a.ts", old_string: "old", new_string: "new" }, "edit"],
    ["Write", { file_path: "/repo/src/b.ts", content: "hello" }, "write"],
    [
      "MultiEdit",
      { file_path: "/repo/src/c.ts", edits: [{ old_string: "a", new_string: "b" }] },
      "multi_edit",
    ],
  ];

  for (const [toolName, toolInput, operation] of cases) {
    const out = gateToolCall(wasm, toolName, toolInput, "/repo");
    assert.equal(out.kind, "gated", `${toolName} must gate`);
    const record = JSON.parse(out.actionRecord);
    assert.equal(record.surface, "file_edit");
    assert.equal(record.facts.operation, operation);
    assert.equal(record.facts.paths.length, 1);
    assert.equal(typeof record.facts.diff_hash, "string");
  }
});

test("gateToolCall(file edit with missing path/patch) → build-error", async () => {
  const wasm = await loadWasm();
  assert.equal(
    gateToolCall(wasm, "Edit", { old_string: "old", new_string: "new" }, "/repo").kind,
    "build-error",
  );
  assert.equal(
    gateToolCall(wasm, "apply_patch", { patch: "not a valid patch" }, "/repo").kind,
    "build-error",
  );
});

// ── #298: shell commands that reach the machine outside the Bash tool ──────────────────────────
//
// Monitor's `command` runs a shell command under Bash's permission rules, and PowerShell runs a
// PowerShell line: both must reach a human exactly like Bash. A Monitor WebSocket watch (`ws`) runs
// nothing and gets no decision; any other Monitor input shape denies.
// @see https://code.claude.com/docs/en/tools-reference (Monitor, PowerShell, NotebookEdit inputs)

test("gateToolCall(Monitor command) → gated exactly like Bash (#298)", async () => {
  const wasm = await loadWasm();
  const monitor = gateToolCall(wasm, "Monitor", { command: "tail -f build.log" }, "/repo");
  const bash = gateToolCall(wasm, "Bash", { command: "tail -f build.log" }, "/repo");
  assert.equal(monitor.kind, "gated");
  assert.deepEqual(JSON.parse(monitor.actionRecord), JSON.parse(bash.actionRecord));
  assert.match(monitor.summary, /Monitor/, "the human is told the command runs under Monitor");
  assert.ok(monitor.summary.includes("tail -f build.log"));
});

test("gateToolCall(Monitor command) with a non-string command → build-error, like Bash (#298)", async () => {
  const wasm = await loadWasm();
  assert.equal(gateToolCall(wasm, "Monitor", { command: 42 }, "/repo").kind, "build-error");
});

test("gateToolCall(Monitor ws watch) → pass-through: it runs no command (#298)", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "Monitor", { ws: { url: "wss://example.test/events" } }, "/repo");
  assert.equal(out.kind, "pass-through");
});

test("gateToolCall(Monitor) with a malformed input shape → build-error (fail-closed, #298)", async () => {
  const wasm = await loadWasm();
  const malformed = [
    {},
    { command: 42 },
    { ws: "wss://example.test" },
    { ws: { protocols: ["x"] } },
    { ws: { url: 7 } },
    // Claude Code takes exactly one of the two; both is not a watch, so it must not pass through.
    { command: "rm -rf /", ws: { url: "wss://example.test" } },
    null,
    ["tail"],
  ];
  for (const input of malformed) {
    assert.equal(
      gateToolCall(wasm, "Monitor", input, "/repo").kind,
      "build-error",
      `Monitor ${JSON.stringify(input)} must deny`,
    );
  }
});

test("gateToolCall(PowerShell) → gated command record, labelled PowerShell (#298)", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "PowerShell", { command: "Remove-Item -Recurse build" }, "C:\\w");
  assert.equal(out.kind, "gated");
  const record = JSON.parse(out.actionRecord);
  assert.equal(record.surface, "command");
  assert.equal(record.facts.raw, "Remove-Item -Recurse build");
  assert.equal(record.facts.cwd, "C:\\w");

  assert.equal(out.summary, "PowerShell: Remove-Item -Recurse build");
});

test("gateToolCall(PowerShell) never refuses PowerShell-only quoting; it fails upward (#298)", async () => {
  const wasm = await loadWasm();
  // A backtick-escaped quote is valid PowerShell but unbalanced POSIX: Bash would deny this as a
  // build error; PowerShell records it with the High floor so a human still sees it.
  const out = gateToolCall(wasm, "PowerShell", { command: 'Write-Output "it`"s"' }, undefined);
  assert.equal(out.kind, "gated");
});

test("gateToolCall(PowerShell) without a string command → build-error (#298)", async () => {
  const wasm = await loadWasm();
  assert.equal(gateToolCall(wasm, "PowerShell", { command: 1 }, "/repo").kind, "build-error");
  assert.equal(gateToolCall(wasm, "PowerShell", {}, "/repo").kind, "build-error");
});

test("gateToolCall(NotebookEdit) → gated file_edit record bound to the cell change (#298)", async () => {
  const wasm = await loadWasm();
  const input = {
    notebook_path: "/repo/analysis.ipynb",
    cell_id: "abc123",
    new_source: "import os\nos.remove('x')",
    cell_type: "code",
    edit_mode: "replace",
  };
  const out = gateToolCall(wasm, "NotebookEdit", input, "/repo");
  assert.equal(out.kind, "gated");
  const record = JSON.parse(out.actionRecord);
  assert.equal(record.surface, "file_edit");
  assert.equal(record.facts.operation, "notebook_edit");
  assert.deepEqual(record.facts.paths, ["/repo/analysis.ipynb"]);
  assert.ok(out.summary.includes("/repo/analysis.ipynb"));
  assert.ok(out.summary.includes("abc123"));

  // The hash binds the change itself: a different new_source is a different record.
  const other = gateToolCall(wasm, "NotebookEdit", { ...input, new_source: "print(1)" }, "/repo");
  assert.notEqual(JSON.parse(other.actionRecord).facts.diff_hash, record.facts.diff_hash);
});

test("gateToolCall(NotebookEdit) insert and delete modes gate; delete needs no new_source (#298)", async () => {
  const wasm = await loadWasm();
  const insert = gateToolCall(
    wasm,
    "NotebookEdit",
    { notebook_path: "/repo/n.ipynb", new_source: "x = 1", cell_type: "code", edit_mode: "insert" },
    "/repo",
  );
  assert.equal(insert.kind, "gated");
  const del = gateToolCall(
    wasm,
    "NotebookEdit",
    { notebook_path: "/repo/n.ipynb", cell_id: "c1", edit_mode: "delete" },
    "/repo",
  );
  assert.equal(del.kind, "gated");
});

test("gateToolCall(NotebookEdit) with a malformed input → build-error (#298)", async () => {
  const wasm = await loadWasm();
  const malformed = [
    { new_source: "x" },
    { notebook_path: "", new_source: "x" },
    { notebook_path: "/repo/n.ipynb" },
    { notebook_path: "/repo/n.ipynb", new_source: 5 },
    { notebook_path: "/repo/n.ipynb", new_source: "x", edit_mode: "append" },
    { notebook_path: "/repo/n.ipynb", new_source: "x", cell_id: 3 },
  ];
  for (const input of malformed) {
    assert.equal(
      gateToolCall(wasm, "NotebookEdit", input, "/repo").kind,
      "build-error",
      `NotebookEdit ${JSON.stringify(input)} must deny`,
    );
  }
});

// Regression (#316 review S2): the human must be shown which cell a NotebookEdit changes.

test("gateToolCall(NotebookEdit replace/delete) without a cell_id → build-error (#316 S2)", async () => {
  const wasm = await loadWasm();
  for (const input of [
    { notebook_path: "/repo/n.ipynb", new_source: "x" },
    { notebook_path: "/repo/n.ipynb", new_source: "x", edit_mode: "replace" },
    { notebook_path: "/repo/n.ipynb", edit_mode: "delete" },
    { notebook_path: "/repo/n.ipynb", edit_mode: "delete", cell_id: null },
    // Regression (#316 review R2-4): an empty cell_id names no cell either.
    { notebook_path: "/repo/n.ipynb", new_source: "x", cell_id: "" },
    { notebook_path: "/repo/n.ipynb", edit_mode: "delete", cell_id: "" },
  ]) {
    assert.equal(
      gateToolCall(wasm, "NotebookEdit", input, "/repo").kind,
      "build-error",
      `NotebookEdit ${JSON.stringify(input)} names no cell, so it must deny`,
    );
  }
});

test("gateToolCall(NotebookEdit) with a key the hook doesn't understand → build-error (#316 S2)", async () => {
  const wasm = await loadWasm();
  // `cell_number` is the older targeting field: dropped, it would pick a cell the human never saw.
  for (const input of [
    { notebook_path: "/repo/n.ipynb", cell_number: 3, new_source: "x" },
    { notebook_path: "/repo/n.ipynb", cell_id: "c1", new_source: "x", path: "/etc/x" },
  ]) {
    assert.equal(
      gateToolCall(wasm, "NotebookEdit", input, "/repo").kind,
      "build-error",
      `NotebookEdit ${JSON.stringify(input)} must deny`,
    );
  }
});

test("(#364) a build-error reason quoting tool input or a tool name shows it escaped", async () => {
  const wasm = await loadWasm();
  const rlo = String.fromCharCode(0x202e);
  const hostile = `\u001b[2J\nallw: APPROVED${rlo}`;
  // A NotebookEdit key and edit mode come from tool input; the malformed MCP name from a server.
  const cases = [
    ["NotebookEdit", { notebook_path: "/repo/n.ipynb", new_source: "x", [`k${hostile}`]: 1 }],
    ["NotebookEdit", { notebook_path: "/repo/n.ipynb", new_source: "x", edit_mode: hostile }],
    [`mcp__bad${hostile}`, {}],
  ];
  for (const [toolName, input] of cases) {
    const out = gateToolCall(wasm, toolName, input, "/repo");
    assert.equal(out.kind, "build-error");
    assert.doesNotMatch(out.reason, /[\x00-\x1f\x7f-\x9f]/u, out.reason);
    assert.ok(!out.reason.includes(rlo), "no raw bidi override");
    assert.ok(out.reason.includes(String.raw`\x1b[2J\nallw: APPROVED⟨U+202E⟩`), out.reason);
    assert.match(out.reason, /\(fail-closed deny\)$/u, "the fixed suffix survives");
  }
});

test("gateToolCall(NotebookEdit insert) says where the cell goes (#316 S2)", async () => {
  const wasm = await loadWasm();
  const base = { notebook_path: "/repo/n.ipynb", new_source: "x = 1", cell_type: "code" };
  const after = gateToolCall(wasm, "NotebookEdit", { ...base, edit_mode: "insert", cell_id: "c1" });
  assert.match(after.summary, /insert after cell c1/);
  assert.doesNotMatch(after.summary, /\(cell c1, insert\)/, "never reads as 'at cell c1'");
  const start = gateToolCall(wasm, "NotebookEdit", { ...base, edit_mode: "insert" });
  assert.match(start.summary, /insert at start/);
  const emptyId = gateToolCall(wasm, "NotebookEdit", { ...base, edit_mode: "insert", cell_id: "" });
  assert.match(emptyId.summary, /insert at start/, "an empty cell_id never reads 'after cell '");
  const replace = gateToolCall(wasm, "NotebookEdit", { ...base, cell_id: "c1" });
  assert.match(replace.summary, /replace cell c1/);
});

// Monitor's input schema is closed (`command` | `ws`, plus `description` and `timeout_ms`; `ws`
// holds only `url` and `protocols`). A watch carrying anything else isn't one the hook can vouch
// runs nothing (#316 review N3).

test("gateToolCall(Monitor ws) with the documented optional keys → pass-through", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(
    wasm,
    "Monitor",
    {
      ws: { url: "wss://example.test/events", protocols: ["v1"] },
      description: "deploy events",
      timeout_ms: 300000,
    },
    "/repo",
  );
  assert.equal(out.kind, "pass-through");
});

test("gateToolCall(Monitor ws) with an unknown key at either level → build-error (#316 N3)", async () => {
  const wasm = await loadWasm();
  for (const input of [
    { ws: { url: "wss://example.test" }, script: "rm -rf ~" },
    { ws: { url: "wss://example.test", command: "rm -rf ~" } },
  ]) {
    assert.equal(
      gateToolCall(wasm, "Monitor", input, "/repo").kind,
      "build-error",
      `Monitor ${JSON.stringify(input)} must deny`,
    );
  }
});

// Regression (#316 Copilot review): a watch's optional fields must have their schema types, or the
// call isn't the documented "runs no command" shape and must deny.
test("gateToolCall(Monitor ws) with a mistyped optional field → build-error", async () => {
  const wasm = await loadWasm();
  const url = "wss://example.test";
  for (const input of [
    { ws: { url, protocols: "v1" } },
    { ws: { url, protocols: ["v1", 2] } },
    { ws: { url, protocols: null } },
    { ws: { url }, description: 5 },
    { ws: { url }, description: null },
    { ws: { url }, timeout_ms: "300000" },
    { ws: { url }, timeout_ms: Number.POSITIVE_INFINITY },
    { ws: { url }, timeout_ms: Number.NaN },
  ]) {
    assert.equal(
      gateToolCall(wasm, "Monitor", input, "/repo").kind,
      "build-error",
      `Monitor ${JSON.stringify(input)} must deny`,
    );
  }
});

test("gateToolCall(non-gated) → pass-through", async () => {
  const wasm = await loadWasm();
  const out = gateToolCall(wasm, "Read", { file_path: "/etc/hosts" }, "/repo");
  assert.equal(out.kind, "pass-through");
});

test("(#269) posixCommandCall reads Bash and Monitor commands, and only those", () => {
  assert.deepEqual(posixCommandCall("Bash", { command: "ls  -la\n" }), {
    kind: "command",
    command: "ls  -la\n",
    summary: "Run command: ls -la",
  });
  assert.deepEqual(posixCommandCall("Monitor", { command: "tail -f log" }), {
    kind: "command",
    command: "tail -f log",
    summary: "Run command (Monitor): tail -f log",
  });
  assert.equal(posixCommandCall("Monitor", { ws: { url: "wss://x.test" } }).kind, "pass-through");
  assert.equal(posixCommandCall("Bash", {}).kind, "build-error");
  assert.equal(posixCommandCall("Monitor", { command: 1 }).kind, "build-error");
  // PowerShell is a command too, but has no SDK builder; it stays with gateToolCall.
  for (const toolName of ["PowerShell", "Edit", "mcp__srv__tool", "Read"]) {
    assert.equal(posixCommandCall(toolName, { command: "ls" }), null, toolName);
  }
});

test("(#374) gateToolCall refuses a command with no program, with the hooks' exact reason", async () => {
  const wasm = await loadWasm();
  const config = {
    relayUrl: "https://relay.allw.test",
    accountId: "acct-test",
    approverRootKey: "x".repeat(43),
  };
  for (const toolName of ["Bash", "Monitor"]) {
    for (const command of ["", "   ", "\t\n\t", "\r"]) {
      const gate = gateToolCall(wasm, toolName, { command }, "/repo");
      const label = `${toolName} ${JSON.stringify(command)}`;
      assert.equal(gate.kind, "build-error", label);
      // The hooks' path (the SDK's commandRequest) denies the same input; the reasons must match,
      // so the exported gate can never drift from what the hooks do.
      const hook = await decide(
        { hookEventName: "PreToolUse", toolName, toolInput: { command }, cwd: "/repo" },
        {
          wasm,
          config,
          commandRequest,
          requestApproval: () => Promise.reject(new Error("never asked")),
        },
        "host",
      );
      assert.equal(gate.reason, hook.hookSpecificOutput.permissionDecisionReason, label);
    }
  }
  // A command with a program still gates.
  assert.equal(gateToolCall(wasm, "Bash", { command: "rm -rf x" }, "/repo").kind, "gated");
});

test("(#374) commandBuildFailureReason recognises the SDK's error by name and reason, not instanceof", async () => {
  const wasm = await loadWasm();
  const prefix = "allw: could not build an ActionRecord for the command (fail-closed deny): ";
  // An error from a second copy of @allw/sdk: the same shape, but not an instance of this copy's
  // class (a published install may hold two copies).
  const foreign = (message, options) =>
    Object.assign(new Error(message, options), {
      name: "CommandActionError",
      reason: "command_line_empty",
    });
  assert.equal(
    commandBuildFailureReason(wasm, foreign("allw: commandLine contains no command")),
    `${prefix}commandLine contains no command`,
    "the SDK's allw: prefix is dropped",
  );
  assert.equal(
    commandBuildFailureReason(
      wasm,
      foreign("allw: commandLine could not be parsed", {
        cause: new Error("action_from_command failed: unmatched quotes"),
      }),
    ),
    `${prefix}action_from_command failed: unmatched quotes`,
    "the core's own error is quoted when the SDK wraps one",
  );
  // Not the SDK's error (no reason field): quoted whole.
  const lookalike = Object.assign(new Error("allw: something else"), {
    name: "CommandActionError",
  });
  assert.equal(commandBuildFailureReason(wasm, lookalike), `${prefix}allw: something else`);
});

/** @see docs/action-record.md — command capture is opaque for every shell tool. */
test("Bash, Monitor and PowerShell carry opaque nonblank lines without inferred argv", async () => {
  const wasm = await loadWasm();
  for (const tool of ["Bash", "Monitor", "PowerShell"]) {
    for (const raw of [
      "# comment",
      "FOO=1",
      "&&",
      "''",
      "'unmatched",
      "$env:X = 'a'; & Remove-Item C:\\a",
      "echo $(id)\nnext",
    ]) {
      const outcome = gateToolCall(wasm, tool, { command: raw }, "/caller");
      assert.equal(outcome.kind, "gated", `${tool}: ${raw}`);
      assert.deepEqual(JSON.parse(outcome.actionRecord), {
        record_schema_version: 3,
        surface: "command",
        facts: { raw, cwd: "/caller" },
      });
    }
    for (const command of ["", " \t\r\n", "\u00a0\u3000"]) {
      assert.equal(gateToolCall(wasm, tool, { command }, "/caller").kind, "build-error");
    }
  }
});

/** @see docs/contract.md — every unreadable/malformed core line result fails closed. */
test("malformed core line outputs deny without inferring a vector", async () => {
  const wasm = await loadWasm();
  for (const output of [
    "{",
    "null",
    "[]",
    "{}",
    '{"facts":null}',
    '{"facts":{}}',
    '{"facts":{"raw":[]}}',
    '{"facts":{"raw":" "}}',
  ]) {
    const broken = { ...wasm, action_from_command: () => output };
    assert.equal(
      gateToolCall(broken, "PowerShell", { command: "echo hi" }, "/repo").kind,
      "build-error",
      output,
    );
  }
});
