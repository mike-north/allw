/** Opaque caller facts, consumed through the built WASM and public SDK.
 * @see docs/action-record.md — Command capture; docs/contract.md — Unknown fields.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { commandAction, commandActionFromLine, CommandActionError } from "../dist/index.js";
import { loadWasm } from "../dist/wasm.js";

const lines = [
  "# only comment",
  "A=1",
  "&&",
  "''",
  "'unmatched",
  "echo $(id) # hi\nnext",
  "$env:X = 'a'; & Remove-Item C:\\a",
  "echo\r\nnext\u202e",
];

test("line builder carries exact bytes without inferred argv or scanner fields", async () => {
  const wasm = await loadWasm();
  for (const raw of lines) {
    const expected = {
      record_schema_version: 3,
      surface: "command",
      facts: { raw, cwd: "/caller" },
    };
    assert.deepEqual(JSON.parse(wasm.action_from_command(raw, "/caller")), expected);
    assert.deepEqual(await commandActionFromLine(raw, { cwd: "/caller" }), {
      recordSchemaVersion: 3,
      surface: "command",
      facts: expected.facts,
    });
  }
  assert.equal(
    wasm.action_from_powershell_command,
    undefined,
    "no alternate interpreter API remains",
  );
});

test("argv elements remain caller facts, including empty or assignment-looking words", async () => {
  for (const argv of [[""], ["A=1"], ["&&"], ["", "a b", "$HOME", "'", "\n"]]) {
    assert.deepEqual(await commandAction(argv, { raw: "caller text" }), {
      recordSchemaVersion: 3,
      surface: "command",
      facts: { argv, raw: "caller text" },
    });
  }
});

test("blank lines, empty argv and malformed schemas fail closed", async () => {
  for (const raw of ["", " \t\r\n", "\u00a0\u3000"]) {
    await assert.rejects(
      commandActionFromLine(raw),
      (e) => e instanceof CommandActionError && e.reason === "command_line_empty",
    );
  }
  await assert.rejects(
    commandAction([]),
    (e) => e instanceof CommandActionError && e.reason === "argv_empty",
  );
  for (const argv of [null, "echo", [1], ["echo", null]])
    await assert.rejects(commandAction(argv), CommandActionError);
  const wasm = await loadWasm();
  for (const argv of ["null", '"echo"', "[1]"])
    assert.throws(() => wasm.action_from_argv(argv, null, null));
});

test("removed parsing fields are ignored through WASM without entering its hash or display", async () => {
  const wasm = await loadWasm();
  const ctx = {
    action: { record_schema_version: 3, surface: "command", facts: { raw: "ssh $HOST" } },
    summary: "caller",
    actor: { id: "script", kind: "script" },
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const before = JSON.stringify(ctx);
  Object.assign(ctx.action.facts, {
    bin: {},
    flags: false,
    positionals: 1,
    host: [],
    env_refs: "x",
  });
  assert.equal(
    wasm.compute_request_hash(JSON.stringify(ctx), 1800000060000),
    wasm.compute_request_hash(before, 1800000060000),
  );
  const display = JSON.parse(wasm.display_model(JSON.stringify(ctx)));
  assert.deepEqual(display.facts, { raw: "ssh $HOST", raw_lines: ["ssh $HOST"] });
});

/** @see docs/contract.md — pinned independently from the contract's ASCII-key JCS ordering. */
test("WASM consumes the independent caller-facts hash anchor", async () => {
  const { readFileSync } = await import("node:fs");
  const vector = JSON.parse(
    readFileSync(
      new URL("../../../crates/allw-core/tests/fixtures/opaque_hash_vector.json", import.meta.url),
      "utf8",
    ),
  );
  const wasm = await loadWasm();
  for (const [canonical, expected] of [
    [vector.request_canonical, vector.request_hash_b64],
    [vector.agent_tool_call_request_canonical, vector.agent_tool_call_request_hash_b64],
  ]) {
    const { expires_at, ...context } = JSON.parse(canonical);
    assert.equal(wasm.compute_request_hash(JSON.stringify(context), expires_at), expected);
  }
});

/** Pre-rename artifacts stay evidence, never a current-format verified approval.
 * @see docs/contract.md — Unknown fields; docs/action-record.md — Verification and history.
 */
test("pre-rename schema-3 bytes cannot verify or alias facts through consumed WASM", async () => {
  const { readFileSync } = await import("node:fs");
  const old = JSON.parse(
    readFileSync(
      new URL(
        "../../../crates/allw-core/tests/fixtures/legacy_syntactic_schema3.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const wasm = await loadWasm();
  const verify = (context) =>
    wasm.verify_verdict(
      old.verdict_json,
      old.request_json,
      JSON.stringify(context),
      old.approver_root_pubkey_b64,
      old.now_ms,
    );
  const context = JSON.parse(old.context_json);
  assert.throws(() => verify(context), /facts/);
  // Even an explicit attempted migration cannot make the historical signature verify.
  context.action.facts = context.action.syntactic;
  assert.throws(() => verify(context), /hash/i);
  const currentHash = wasm.compute_request_hash(JSON.stringify(context), old.expires_at);
  context.action.syntactic = false;
  assert.equal(wasm.compute_request_hash(JSON.stringify(context), old.expires_at), currentHash);
  const model = JSON.parse(wasm.display_model(JSON.stringify(context)));
  assert.equal(model.facts.raw, "git push");
  assert.equal(Object.hasOwn(model, "syntactic"), false);
  context.action.facts.raw = [];
  assert.throws(() => wasm.display_model(JSON.stringify(context)));
});
