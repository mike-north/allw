/**
 * Tests for the command-surface request builders (issue #231): `commandAction`,
 * `commandActionFromLine`, and `commandRequest`.
 *
 * Parity: each builder must return **exactly** the record the core's `action_from_argv` /
 * `action_from_command` produces for the same input, so these tests call the vendored WASM core
 * directly and compare against its output — never against a hand-written record literal. Shape
 * assertions on top of that trace to `docs/policy-seam.md` §ActionRecord.
 *
 * Fail-closed: every rejection branch has its own negative test, and a malformed command never
 * reaches the relay (asserted with a counting `fetchImpl`).
 *
 * Run order (the wasm must be built and the SDK compiled first):
 *   pnpm run build:wasm                # from repo root
 *   pnpm --filter @allw/sdk test       # tsc → dist, then node --test
 *
 * @see ../../../docs/policy-seam.md §ActionRecord (the syntactic substrate; `surface: "command"`)
 * @see ../../../docs/contract.md §Invariants (fail-closed; never returns "allow")
 * @see ../../../crates/allw-wasm/src/lib.rs (`action_from_argv`, `action_from_command`)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { hostname } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

import {
  CommandActionError,
  commandAction,
  commandActionFromLine,
  commandRequest,
  createClient,
} from "../dist/index.js";
import { actionRecordFromCoreJson, assertRecordHasProgram } from "../dist/command-request.js";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

/** Load the `--target web` wasm synchronously (mirrors test/wasm.test.mjs). */
async function loadCore() {
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  const bytes = readFileSync(join(vendorDir, "allw_wasm_bg.wasm"));
  glue.initSync({ module: new WebAssembly.Module(bytes) });
  return glue;
}

/** The SDK's camelCase view of a core record: only top-level keys are renamed. */
function camel(coreJson) {
  const core = JSON.parse(coreJson);
  return {
    recordSchemaVersion: core.record_schema_version,
    surface: core.surface,
    syntactic: core.syntactic,
    risk: core.risk,
  };
}

const REFUND_ARGV = ["stripe", "refunds", "create", "--charge", "ch_123"];
const CWD = "/workspace/billing";

/** Assert `promise` rejects with a CommandActionError of `reason` whose message matches `pattern`. */
async function rejectsWith(promise, reason, pattern) {
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof CommandActionError, `expected CommandActionError, got ${err}`);
    assert.equal(err.reason, reason);
    assert.match(err.message, pattern);
    return true;
  });
}

// ── Parity with the core ──────────────────────────────────────────────────────────────────────

test("commandAction returns exactly the core's action_from_argv record", async () => {
  const core = await loadCore();
  const action = await commandAction(REFUND_ARGV);
  assert.deepEqual(action, camel(core.action_from_argv(JSON.stringify(REFUND_ARGV), null, null)));

  // policy-seam §ActionRecord: a command record is `surface: "command"` with the syntactic
  // substrate policy matches on (bin / argv / flags / positionals).
  assert.equal(action.surface, "command");
  assert.equal(action.syntactic.bin, "stripe");
  assert.deepEqual(action.syntactic.argv, REFUND_ARGV);
  assert.deepEqual(action.syntactic.flags, ["--charge"]);
});

test("commandAction binds cwd and raw exactly as the core does", async () => {
  const core = await loadCore();
  const raw = "stripe refunds create --charge $CHARGE_ID";
  const action = await commandAction(REFUND_ARGV, { cwd: CWD, raw });
  assert.deepEqual(action, camel(core.action_from_argv(JSON.stringify(REFUND_ARGV), raw, CWD)));
  assert.equal(action.syntactic.cwd, CWD);
  // `raw` is recorded verbatim and is the only source of env_refs; argv is never re-tokenized.
  assert.equal(action.syntactic.raw, raw);
  assert.deepEqual(action.syntactic.env_refs, ["CHARGE_ID"]);
  assert.deepEqual(action.syntactic.argv, REFUND_ARGV);
});

test("commandActionFromLine returns exactly the core's action_from_command record", async () => {
  const core = await loadCore();
  const line = "git push --force origin main";
  const action = await commandActionFromLine(line, { cwd: CWD });
  assert.deepEqual(action, camel(core.action_from_command(line, CWD)));
  assert.equal(action.surface, "command");
  assert.deepEqual(action.syntactic.argv, ["git", "push", "--force", "origin", "main"]);
  assert.equal(action.syntactic.raw, line);
});

// ── commandRequest defaults ──────────────────────────────────────────────────────────────────

test("commandRequest fills the documented defaults around the core-built action", async () => {
  const core = await loadCore();
  const req = await commandRequest({ argv: REFUND_ARGV, summary: "Refund charge ch_123" });

  // #231 review: cwd defaults to process.cwd() (where execFile/spawn run by default).
  assert.deepEqual(
    req.action,
    camel(core.action_from_argv(JSON.stringify(REFUND_ARGV), null, process.cwd())),
  );
  assert.equal(req.action.syntactic.cwd, process.cwd());
  assert.equal(req.summary, "Refund charge ch_123");
  // #231: top-level risk is taken from the core-built action, never stated twice.
  assert.equal(req.risk, req.action.risk);
  // #231: actor defaults to this machine acting as a script.
  assert.deepEqual(req.actor, { id: `machine:${hostname()}`, kind: "script" });
  // #231: reversible defaults to false (conservative — "cannot be undone").
  assert.equal(req.reversible, false);
  // Absent optionals are omitted, so requestApproval's own defaults apply.
  for (const key of ["timeoutMs", "signal", "constraints", "chain"]) {
    assert.equal(key in req, false, `${key} is omitted when not given`);
  }
});

test("commandRequest honors overrides and passes optional fields through", async () => {
  const signal = new AbortController().signal;
  const actor = { id: "ci:nightly", kind: "ci" };
  const constraints = { allowedDecisions: ["approved", "denied"], challengeRequired: true };
  const req = await commandRequest({
    argv: REFUND_ARGV,
    cwd: CWD,
    summary: "Refund",
    actor,
    reversible: true,
    timeoutMs: 30_000,
    signal,
    constraints,
    chain: ["gate-1"],
  });
  assert.deepEqual(req.actor, actor);
  assert.equal(req.reversible, true);
  assert.equal(req.timeoutMs, 30_000);
  assert.equal(req.signal, signal);
  assert.deepEqual(req.constraints, constraints);
  assert.deepEqual(req.chain, ["gate-1"]);
  assert.equal(req.action.syntactic.cwd, CWD);
  assert.equal("raw" in req.action.syntactic, false, "commandRequest never sets raw on argv");
});

test("commandRequest with cwd: null leaves the record unbound to any directory", async () => {
  const core = await loadCore();
  const req = await commandRequest({ argv: REFUND_ARGV, summary: "Refund", cwd: null });
  assert.deepEqual(
    req.action,
    camel(core.action_from_argv(JSON.stringify(REFUND_ARGV), null, null)),
  );
  assert.equal("cwd" in req.action.syntactic, false);
});

test("commandRequest accepts a commandLine and builds it with action_from_command", async () => {
  const core = await loadCore();
  const line = "rm -rf ./build";
  const req = await commandRequest({ commandLine: line, cwd: CWD, summary: "Clean build" });
  assert.deepEqual(req.action, camel(core.action_from_command(line, CWD)));
  assert.equal(req.risk, req.action.risk);
});

// ── Fail-closed: the three cases #231 names ──────────────────────────────────────────────────

test("rejects a non-string argv element and names it", async () => {
  await rejectsWith(
    commandAction(["stripe", "refunds", 42]),
    "argv_element_not_string",
    /argv\[2\] must be a string \(got number\)/,
  );
});

test("rejects an empty argv", async () => {
  await rejectsWith(commandAction([]), "argv_empty", /argv must not be empty/);
});

test("rejects an unparseable command line (unmatched quote) without echoing it", async () => {
  await rejectsWith(
    commandActionFromLine('stripe refunds create --charge "ch_123'),
    "command_line_unparseable",
    /could not be parsed.*unmatched quote/,
  );
  await assert.rejects(commandActionFromLine('echo "sk_live_SECRET'), (err) => {
    assert.ok(!err.message.includes("sk_live_SECRET"), "the command text is not echoed");
    return true;
  });
});

test("a malformed command never submits: requestApproval is never reached", async () => {
  let fetchCalls = 0;
  const client = createClient({
    relayUrl: "https://relay.allw.test",
    accountId: "acct_cmd_test",
    approverRootKey: "AAAA",
    fetchImpl: () => {
      fetchCalls += 1;
      return Promise.reject(new Error("must not be called"));
    },
  });
  for (const bad of [
    { argv: ["ok", 1], summary: "s" },
    { argv: [], summary: "s" },
    { commandLine: "echo 'unterminated", summary: "s" },
  ]) {
    await assert.rejects(
      (async () => client.requestApproval(await commandRequest(bad)))(),
      CommandActionError,
    );
  }
  assert.equal(fetchCalls, 0, "no relay call was made for any malformed command");
});

// ── Fail-closed: remaining rejection branches ────────────────────────────────────────────────

test("rejects a non-array argv", async () => {
  await rejectsWith(commandAction("stripe refunds"), "argv_not_array", /got string/);
});

test("rejects an empty program (argv[0])", async () => {
  await rejectsWith(commandAction(["", "x"]), "argv_program_empty", /argv\[0\]/);
});

// #376: validateArgv's own refusals are unchanged; an all-assignment argv is now refused by the
// core, and the SDK maps it to its own reason with no cause.
test("commandAction keeps its own argv refusals and maps the core's all-assignment refusal", async () => {
  await rejectsWith(commandAction([]), "argv_empty", /^allw: argv must not be empty/);
  await rejectsWith(commandAction([""]), "argv_program_empty", /^allw: argv\[0\] \(the program\)/);
  for (const argv of [["FOO=1"], ["FOO=1", "BAR=2"]]) {
    await assert.rejects(commandAction(argv), (err) => {
      assert.ok(err instanceof CommandActionError);
      assert.equal(err.reason, "argv_no_program");
      assert.equal(err.message, "allw: argv runs no program (only variable assignments)");
      assert.equal(err.cause, undefined);
      return true;
    });
  }
  await rejectsWith(commandAction(["FOO=1", ""]), "argv_program_empty", /non-empty/);
  // An operator word is a program name in an argv (no shell runs it): still built.
  assert.equal((await commandAction(["&&"])).syntactic.bin, "&&");
});

// #391: an assignment whose `$( … )` command holds an `=` is a program, not an all-assignment line.
test("commandActionFromLine builds an assignment whose substitution holds '=' (#391)", async () => {
  const version = await commandActionFromLine('VERSION="$(git log --format=%H -1)"');
  assert.equal(version.surface, "command");
  const dd = await commandActionFromLine('x="$(nice -n 1 dd if=/dev/zero of=/dev/sda)"');
  assert.equal(dd.risk, "critical");
  for (const line of ["X=1", "A=1 B=2", "A[0]=1", "X+=y"]) {
    await rejectsWith(commandActionFromLine(line), "command_line_no_program", /runs no program/);
  }
});

test("rejects a non-string command line", async () => {
  await rejectsWith(
    commandActionFromLine(["ls"]),
    "command_line_not_string",
    /commandLine must be a string \(got array\)/,
  );
});

test("rejects a blank command line (no command to show the human)", async () => {
  await rejectsWith(commandActionFromLine("   "), "command_line_empty", /no command/);
});

test("rejects a command line whose program is the empty string", async () => {
  await rejectsWith(commandActionFromLine("''"), "argv_program_empty", /program/);
  await rejectsWith(commandActionFromLine("'' rm -rf /"), "argv_program_empty", /program/);
  await rejectsWith(
    commandRequest({ commandLine: "'' rm -rf /", summary: "s" }),
    "argv_program_empty",
    /program/,
  );
});

test("rejects a command line that runs no program (only assignments or operators)", async () => {
  for (const line of ["FOO=1", "FOO=1 BAR=2", "FOO=1; BAR=2", "&&", "; |"]) {
    await rejectsWith(
      commandActionFromLine(line),
      "command_line_no_program",
      /^allw: commandLine runs no program \(only variable assignments or shell operators\)$/,
    );
  }
  await rejectsWith(
    commandRequest({ commandLine: "FOO=1", summary: "s" }),
    "command_line_no_program",
    /runs no program/,
  );
});

// The core refuses these itself (#376); the SDK maps its `kind` to the same reason and message it
// used before, with no `cause`, so the hooks' deny reasons are unchanged.
test("maps each core no-program refusal to the SDK's own message, with no cause", async () => {
  for (const [line, reason, message] of [
    ["   ", "command_line_empty", "allw: commandLine contains no command"],
    ["# only a comment", "command_line_empty", "allw: commandLine contains no command"],
    [
      "FOO=1",
      "command_line_no_program",
      "allw: commandLine runs no program (only variable assignments or shell operators)",
    ],
    [
      "'' rm",
      "argv_program_empty",
      "allw: commandLine's first word (the program) must be non-empty",
    ],
  ]) {
    await assert.rejects(commandActionFromLine(line), (err) => {
      assert.ok(err instanceof CommandActionError);
      assert.equal(err.reason, reason, line);
      assert.equal(err.message, message, line);
      assert.equal(err.cause, undefined, line);
      return true;
    });
  }
});

test("invalid shell syntax still carries the core's error as its cause", async () => {
  await assert.rejects(commandActionFromLine("echo 'open"), (err) => {
    assert.equal(err.reason, "command_line_unparseable");
    assert.ok(err.cause instanceof Error);
    assert.equal(err.cause.kind, "invalid_shell_syntax");
    return true;
  });
});

// Defence in depth: the real core never returns these records, so the check is exercised directly.
test("assertRecordHasProgram refuses a record with no argv or an empty program", () => {
  const record = (syntactic) => ({
    recordSchemaVersion: 1,
    surface: "command",
    syntactic,
    risk: "medium",
  });
  for (const [syntactic, reason] of [
    [{}, "command_line_empty"],
    [{ argv: [] }, "command_line_empty"],
    [{ argv: "ls" }, "command_line_empty"],
    [{ argv: ["", "rm"] }, "argv_program_empty"],
  ]) {
    assert.throws(
      () => assertRecordHasProgram(record(syntactic)),
      (err) => err instanceof CommandActionError && err.reason === reason,
      JSON.stringify(syntactic),
    );
  }
  assert.doesNotThrow(() => assertRecordHasProgram(record({ argv: ["ls"] })));
});

test("rejects a blank cwd", async () => {
  await rejectsWith(
    commandAction(["ls"], { cwd: "" }),
    "invalid_option",
    /cwd must be a non-blank string/,
  );
  await rejectsWith(commandAction(["ls"], { cwd: "  " }), "invalid_option", /non-blank/);
  await rejectsWith(commandActionFromLine("ls", { cwd: "" }), "invalid_option", /non-blank/);
  await rejectsWith(
    commandRequest({ argv: ["ls"], summary: "s", cwd: "" }),
    "invalid_option",
    /non-blank/,
  );
});

test("rejects a non-string cwd and a non-string raw", async () => {
  await rejectsWith(commandAction(["ls"], { cwd: 7 }), "invalid_option", /cwd must be a string/);
  await rejectsWith(commandAction(["ls"], { raw: {} }), "invalid_option", /raw must be a string/);
  await rejectsWith(
    commandActionFromLine("ls", { cwd: false }),
    "invalid_option",
    /cwd must be a string/,
  );
});

test("commandRequest rejects both argv and commandLine, and neither", async () => {
  await rejectsWith(
    commandRequest({ argv: ["ls"], commandLine: "ls", summary: "s" }),
    "ambiguous_command",
    /exactly one of/,
  );
  await rejectsWith(commandRequest({ summary: "s" }), "ambiguous_command", /exactly one of/);
});

test("commandRequest rejects a blank or missing summary", async () => {
  await rejectsWith(commandRequest({ argv: ["ls"], summary: "  " }), "invalid_option", /summary/);
  await rejectsWith(commandRequest({ argv: ["ls"] }), "invalid_option", /summary/);
});

test("commandRequest rejects raw on either form (raw belongs only on commandAction)", async () => {
  await rejectsWith(
    commandRequest({ argv: ["rm", "-rf", "/"], raw: "ls", summary: "s" }),
    "invalid_option",
    /does not take `raw`/,
  );
  await rejectsWith(
    commandRequest({ commandLine: "ls", raw: "something", summary: "s" }),
    "invalid_option",
    /does not take `raw`/,
  );
});

test("commandRequest rejects a malformed actor", async () => {
  for (const [actor, pattern] of [
    ["evil", /actor must be an object/],
    [null, /actor must be an object/],
    [["x"], /actor must be an object/],
    [{ id: "", kind: "script" }, /actor\.id must be a non-blank string/],
    [{ id: "m:1" }, /actor\.kind must be a non-blank string \(got undefined\)/],
    [{ id: "m:1", kind: "script", attestation: 5 }, /actor\.attestation must be a string/],
  ]) {
    await rejectsWith(
      commandRequest({ argv: ["ls"], summary: "s", actor }),
      "invalid_option",
      pattern,
    );
  }
});

test("commandRequest rejects a non-positive or non-integer timeoutMs", async () => {
  for (const timeoutMs of [Number.NaN, 0, -1000, 1.5, "100", Number.POSITIVE_INFINITY]) {
    await rejectsWith(
      commandRequest({ argv: ["ls"], summary: "s", timeoutMs }),
      "invalid_option",
      /timeoutMs must be a positive integer/,
    );
  }
});

test("commandRequest rejects a non-boolean reversible", async () => {
  await rejectsWith(
    commandRequest({ argv: ["ls"], summary: "s", reversible: "no" }),
    "invalid_option",
    /reversible must be a boolean/,
  );
});

// ── Fail-closed: a core record the SDK cannot faithfully represent ───────────────────────────

const GOOD_CORE = {
  record_schema_version: 1,
  surface: "command",
  syntactic: { bin: "ls", argv: ["ls"] },
  risk: "low",
};

test("core record translation accepts a v1 command record", () => {
  assert.deepEqual(actionRecordFromCoreJson(JSON.stringify(GOOD_CORE)), {
    recordSchemaVersion: 1,
    surface: "command",
    syntactic: { bin: "ls", argv: ["ls"] },
    risk: "low",
  });
});

for (const [name, json, pattern] of [
  ["invalid JSON", "{", /invalid JSON/],
  ["a non-object", "[]", /not a JSON object/],
  [
    "an extra (reserved T3) key",
    JSON.stringify({ ...GOOD_CORE, capabilities: [] }),
    /unexpected keys/,
  ],
  [
    "a missing key",
    JSON.stringify({ surface: "command", syntactic: {}, risk: "low" }),
    /unexpected keys/,
  ],
  [
    "a non-integer schema version",
    JSON.stringify({ ...GOOD_CORE, record_schema_version: "1" }),
    /schema version/,
  ],
  [
    "a non-command surface",
    JSON.stringify({ ...GOOD_CORE, surface: "mcp_tool_call" }),
    /not "command"/,
  ],
  ["an unknown risk tier", JSON.stringify({ ...GOOD_CORE, risk: "none" }), /not a known tier/],
  ["a non-object syntactic", JSON.stringify({ ...GOOD_CORE, syntactic: null }), /no syntactic/],
]) {
  test(`core record translation rejects ${name}`, () => {
    assert.throws(
      () => actionRecordFromCoreJson(json),
      (err) => err instanceof CommandActionError && err.reason === "core_record_invalid",
    );
    assert.throws(() => actionRecordFromCoreJson(json), pattern);
  });
}
