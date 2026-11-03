/**
 * The web approver shows every hash-bound field the CLI approver shows (#295), including the
 * context summary (#262) and the raw/argv divergence warning.
 *
 * Every field below is bound into `request_hash`, so the human must see it before signing. These
 * tests run the real path: the context is encrypted to the device, `createWasmRuntime` decrypts it
 * and builds the view from the core's `display_model`, and `mountWebApprover` renders it into jsdom.
 *
 * Expected text is written by hand from the layout rules in `src/index.ts` (`exactPlaintext`,
 * `actionSummary`) and `src/command-line.ts` (token and list quoting), and from the escape notation
 * in `crates/allw-core/src/display.rs` — never captured from program output.
 *
 * @see ../../../docs/contract.md §Invariants #3 (WYSIWYS)
 * @see ../../../docs/threat-model.md R3 (WYSIWYS completeness)
 * @see ../../../crates/allw-core/src/display.rs (`DisplaySubstrate`, escape notation)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { rawDivergesFromArgv, reconstructCommand } from "../dist/command-line.js";
import {
  CONTEXT_SUMMARY_LABEL,
  RAW_ARGV_DIVERGENCE_WARNING,
  TOOL_COMMAND_FORM_WARNING,
} from "../dist/index.js";
import { mountWith } from "./support/real-runtime.mjs";
import { loadTestWasm } from "./wasm-helper.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const ESC = "\u001b";

/** A wire `ApprovalContext` for `surface` with `syntactic`, plus top-level overrides. */
function context(surface, syntactic, overrides = {}) {
  return {
    action: { record_schema_version: 1, surface, syntactic, risk: "high" },
    summary: "push the release branch",
    actor: { id: "machine:laptop", kind: "claude-code" },
    risk: "high",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
    ...overrides,
  };
}

/** The one rendered approval card. */
function onlyCard(root) {
  const cards = root.querySelectorAll(".approval-card");
  assert.equal(cards.length, 1, "exactly one card is rendered");
  return cards[0];
}

/** The card's exact-plaintext block. */
function plaintextOf(card) {
  return card.querySelector(".approval-plaintext")?.textContent ?? "";
}

test("raw/argv divergence matches the shared CLI/web fixture", () => {
  const fixture = JSON.parse(
    readFileSync(join(here, "fixtures", "raw-argv-divergence.json"), "utf8"),
  );
  for (const c of fixture.cases) {
    assert.equal(rawDivergesFromArgv(c.syntactic), c.diverges, `${c.name}: diverges`);
    assert.equal(reconstructCommand(c.syntactic) ?? null, c.reconstructed, `${c.name}: line`);
  }
});

test("command: every hash-bound field is on the card, with the context summary (#295, #262)", async () => {
  const root = await mountWith([
    context(
      "command",
      {
        bin: "git",
        argv: ["git", "push", "--force", "origin", "main"],
        flags: ["--force"],
        positionals: ["origin", "main"],
        cwd: "/srv/app",
        host: "prod-db",
        env_refs: ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"],
        raw: "git push --force origin main",
      },
      { chain: ["gate-a", "gate b"] },
    ),
  ]);
  const card = onlyCard(root);
  assert.equal(card.querySelector("h3")?.textContent, "git push --force origin main");
  assert.equal(
    plaintextOf(card),
    [
      "cwd: /srv/app",
      "host: prod-db",
      "bin: git",
      "argv: git push --force origin main",
      "flags: --force",
      "positionals: origin main",
      "env_refs: AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN",
      "raw: git push --force origin main",
      "chain: gate-a, 'gate b'",
    ].join("\n"),
  );
  assert.equal(
    card.querySelector(".approval-context-summary")?.textContent,
    `${CONTEXT_SUMMARY_LABEL}: push the release branch`,
  );
  assert.equal(card.querySelector(".raw-argv-divergence-warning"), null, "raw matches argv");
});

test("mcp_tool_call: server :: tool, params and any other present field are on the card", async () => {
  const root = await mountWith([
    context("mcp_tool_call", {
      server: "fs",
      tool: "write_file",
      params: { path: "/etc/hosts", mode: "overwrite" },
      cwd: "/repo",
    }),
  ]);
  const card = onlyCard(root);
  assert.equal(card.querySelector("h3")?.textContent, "fs :: write_file");
  assert.equal(
    plaintextOf(card),
    [
      "mcp: fs :: write_file",
      "cwd: /repo",
      // Indented JSON with sorted keys, one line per entry (display.rs `params_json_lines`).
      'params: {\n  "mode": "overwrite",\n  "path": "/etc/hosts"\n}',
    ].join("\n"),
  );
});

test("agent_tool_call: the plugin id, tool, params and raw are on the card", async () => {
  const root = await mountWith([
    context("agent_tool_call", {
      server: "deploy-plugin",
      tool: "deploy_service",
      params: { env: "prod" },
      raw: "This plugin wants to deploy to production.",
    }),
  ]);
  const card = onlyCard(root);
  // A tool call heads with its tool identity; the plugin's raw is its own description (#321).
  assert.equal(card.querySelector("h3")?.textContent, "deploy-plugin :: deploy_service");
  assert.equal(
    plaintextOf(card),
    [
      "agent_tool_call: deploy-plugin :: deploy_service",
      'params: {\n  "env": "prod"\n}',
      "description: This plugin wants to deploy to production.",
    ].join("\n"),
  );
});

test("file_edit renders as a file edit: operation, paths, diff fields and content (#295)", async () => {
  const root = await mountWith([
    context("file_edit", {
      operation: "patch",
      paths: ["src/app.ts", "docs/a b.md"],
      diff_summary: "patch src/app.ts (+3 -1)",
      diff_hash: "sha256:0f1e",
      raw: "line one\r\nline two",
    }),
  ]);
  const card = onlyCard(root);
  assert.equal(card.querySelector("h3")?.textContent, "patch src/app.ts (+3 -1)");
  assert.equal(
    plaintextOf(card),
    [
      "file_edit: patch",
      "paths: src/app.ts, 'docs/a b.md'",
      "diff_summary: patch src/app.ts (+3 -1)",
      "diff_hash: sha256:0f1e",
      // A CR before LF in a file edit is a line ending, shown as ␍ (display.rs CRLF_MARKER).
      "content: line one␍\n   │ line two",
    ].join("\n"),
  );
  assert.equal(
    card.querySelector(".hidden-chars-warning"),
    null,
    "CRLF in a file edit is structure",
  );
});

test("a file edit without a diff summary is headed by its operation and paths", async () => {
  const root = await mountWith([
    context("file_edit", { operation: "write", paths: ["notes/todo.md"], raw: "- [ ] ship" }),
  ]);
  assert.equal(onlyCard(root).querySelector("h3")?.textContent, "write notes/todo.md");
});

/**
 * Collect every string the core's display substrate holds (arrays flattened). `params_json` is
 * skipped: `params_json_lines` holds the same params laid out for display, and that is checked.
 */
function substrateStrings(syntactic) {
  return Object.entries(syntactic)
    .filter(([key]) => key !== "params_json")
    .flatMap(([key, value]) => (Array.isArray(value) ? value : [value]).map((v) => [key, v]));
}

test("every string in the core display substrate reaches the card (mutation guard)", async () => {
  // Every substrate field set at once, on one surface: the card must show each of them, so
  // dropping any field from the view model fails this test.
  const all = context(
    "command",
    {
      bin: "bin-value",
      argv: ["argv-0", "argv-1"],
      flags: ["--flag-value"],
      positionals: ["positional-value"],
      cwd: "/cwd-value",
      host: "host-value",
      env_refs: ["ENV_REF_VALUE"],
      server: "server-value",
      tool: "tool-value",
      params: { "params-key": "params-value" },
      operation: "operation-value",
      paths: ["path-value"],
      diff_summary: "diff-summary-value",
      diff_hash: "diff-hash-value",
      raw: "raw-line-1\nraw-line-2",
    },
    { chain: ["chain-value"] },
  );
  const wasm = await loadTestWasm();
  const display = JSON.parse(wasm.display_model(JSON.stringify(all)));
  const expected = substrateStrings(display.syntactic);
  // Guard the guard: the core returned every field the wire carried.
  assert.deepEqual([...new Set(expected.map(([key]) => key))].sort(), [
    "argv",
    "bin",
    "cwd",
    "diff_hash",
    "diff_summary",
    "env_refs",
    "flags",
    "host",
    "operation",
    "params_json_lines",
    "paths",
    "positionals",
    "raw",
    "raw_lines",
    "server",
    "tool",
  ]);

  const text = onlyCard(await mountWith([all])).textContent ?? "";
  for (const [key, value] of expected) {
    if (key === "raw") continue; // shown through raw_lines; the one-line form is for headlines
    assert.ok(text.includes(value), `${key} value ${JSON.stringify(value)} is on the card`);
  }
  for (const value of [display.summary, display.actor_label, ...display.chain]) {
    assert.ok(text.includes(value), `${JSON.stringify(value)} is on the card`);
  }
});

/** A wire context with an ESC planted in exactly one field. */
const ESC_IN_ONE_FIELD = {
  summary: () => context("command", { argv: ["ls"], raw: "ls" }, { summary: `list${ESC}` }),
  "actor.id": () =>
    context("command", { argv: ["ls"], raw: "ls" }, { actor: { id: `m${ESC}`, kind: "k" } }),
  "actor.kind": () =>
    context("command", { argv: ["ls"], raw: "ls" }, { actor: { id: "m", kind: `k${ESC}` } }),
  bin: () => context("command", { bin: `ls${ESC}`, raw: "ls" }),
  argv: () => context("command", { argv: ["ls", `a${ESC}`], raw: "ls" }),
  flags: () => context("command", { argv: ["ls"], flags: [`-l${ESC}`], raw: "ls" }),
  positionals: () => context("command", { argv: ["ls"], positionals: [`p${ESC}`], raw: "ls" }),
  cwd: () => context("command", { argv: ["ls"], cwd: `/tmp${ESC}`, raw: "ls" }),
  host: () => context("command", { argv: ["ls"], host: `db${ESC}`, raw: "ls" }),
  env_refs: () => context("command", { argv: ["ls"], env_refs: [`TOKEN${ESC}`], raw: "ls" }),
  server: () => context("mcp_tool_call", { server: `fs${ESC}`, tool: "read" }),
  tool: () => context("mcp_tool_call", { server: "fs", tool: `read${ESC}` }),
  params: () => context("mcp_tool_call", { server: "fs", tool: "read", params: { p: `x${ESC}` } }),
  operation: () => context("file_edit", { operation: `patch${ESC}`, paths: ["a"] }),
  paths: () => context("file_edit", { operation: "patch", paths: [`a${ESC}`] }),
  diff_summary: () => context("file_edit", { operation: "patch", diff_summary: `d${ESC}` }),
  diff_hash: () => context("file_edit", { operation: "patch", diff_hash: `h${ESC}` }),
  raw: () => context("command", { raw: `ls${ESC}` }),
  chain: () => context("command", { argv: ["ls"], raw: "ls" }, { chain: [`gate${ESC}`] }),
};

test("whenever the warning badge shows, the escaped character is visible on the card (#262)", async () => {
  for (const [field, build] of Object.entries(ESC_IN_ONE_FIELD)) {
    const card = onlyCard(await mountWith([build()]));
    const text = card.textContent ?? "";
    assert.ok(card.querySelector(".hidden-chars-warning"), `${field}: the badge shows`);
    assert.equal(text.includes(ESC), false, `${field}: no raw ESC reaches the DOM`);
    // JSON params carry ESC as \u001b (JSON's own escape); every other field uses \x1b.
    const visible = field === "params" ? "\\u001b" : "\\x1b";
    const withoutBadge = text.replace(card.querySelector(".hidden-chars-warning").textContent, "");
    assert.ok(withoutBadge.includes(visible), `${field}: the escaped ESC is visible on the card`);
  }
});

test("raw/argv divergence: the heading is the hash-bound argv, with a warning and both forms", async () => {
  // A benign raw paired with a dangerous argv; both are hash-bound.
  const root = await mountWith([
    context("command", { argv: ["rm", "-rf", "~"], raw: "git status", cwd: "/home/me" }),
  ]);
  const card = onlyCard(root);
  assert.equal(card.querySelector("h3")?.textContent, "rm -rf '~'", "never only the raw half");
  const warning = card.querySelector(".raw-argv-divergence-warning");
  assert.ok(warning, "the divergence warning shows");
  assert.equal(warning.textContent, RAW_ARGV_DIVERGENCE_WARNING);
  assert.equal(warning.getAttribute("role"), "alert");
  const plaintext = plaintextOf(card);
  assert.ok(plaintext.includes("argv: rm -rf '~'"), "the argv form is in the plaintext");
  assert.ok(plaintext.includes("raw: git status"), "the raw form is in the plaintext");
});

test("the context summary is escaped, labelled, and not the card heading (#262)", async () => {
  const root = await mountWith([
    context(
      "command",
      { argv: ["git", "status"], raw: "git status" },
      { summary: `just checking status${ESC}[2K` },
    ),
  ]);
  const card = onlyCard(root);
  assert.equal(card.querySelector("h3")?.textContent, "git status", "the action stays the heading");
  assert.equal(
    card.querySelector(".approval-context-summary")?.textContent,
    `${CONTEXT_SUMMARY_LABEL}: just checking status\\x1b[2K`,
  );
  assert.ok(card.querySelector(".hidden-chars-warning"));
});

test("the card heading follows the CLI's precedence: shared CLI/web headline fixture", async () => {
  // One fixture for both approvers: a record heads the same way on each, and a tool call heads
  // with its tool identity while any command it carries is flagged (#321).
  const fixture = JSON.parse(readFileSync(join(here, "fixtures", "action-headline.json"), "utf8"));
  assert.equal(fixture.cases.length, 20);
  const shown = new Map();
  for (const c of fixture.cases) {
    const card = onlyCard(await mountWith([context(c.surface, c.syntactic)]));
    const heading = card.querySelector("h3")?.textContent;
    assert.equal(heading, c.heading, c.name);
    // On a tool surface the caller's raw is a labelled description, never the heading (#321).
    const plaintext = plaintextOf(card);
    shown.set(c.name, { heading, plaintext });
    if (c.description !== undefined) {
      assert.ok(plaintext.includes(`description: ${c.description}`), `${c.name}: description row`);
      assert.ok(!plaintext.includes("raw: "), `${c.name}: raw is not labelled raw`);
    } else {
      assert.doesNotMatch(plaintext, /^description: /m, `${c.name}: no description row`);
    }
    const commandForm = card.querySelector(".tool-command-form-warning");
    assert.equal(
      commandForm !== null,
      c.tool_command_form === true,
      `${c.name}: command-form warning`,
    );
    if (commandForm !== null) {
      assert.equal(commandForm.textContent, TOOL_COMMAND_FORM_WARNING);
      assert.equal(commandForm.getAttribute("role"), "alert");
      assert.equal(
        card.querySelector(".raw-argv-divergence-warning"),
        null,
        `${c.name}: no divergence`,
      );
      assert.match(plaintext, /^(bin|argv): /m, `${c.name}: the command form is in the plaintext`);
    }
  }
  // Two records that differ only in how a name splits into server and tool must not look alike.
  for (const c of fixture.cases) {
    if (c.distinct_from === undefined) continue;
    assert.ok(shown.has(c.distinct_from), `${c.name}: names a real case`);
    assert.notDeepEqual(shown.get(c.name), shown.get(c.distinct_from), `${c.name}: distinct`);
    assert.notEqual(shown.get(c.name).heading, shown.get(c.distinct_from).heading, c.name);
  }
});
