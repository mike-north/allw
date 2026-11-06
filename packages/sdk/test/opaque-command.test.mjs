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
      syntactic: { raw, cwd: "/caller" },
    };
    assert.deepEqual(JSON.parse(wasm.action_from_command(raw, "/caller")), expected);
    assert.deepEqual(await commandActionFromLine(raw, { cwd: "/caller" }), {
      recordSchemaVersion: 3,
      surface: "command",
      syntactic: expected.syntactic,
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
      syntactic: { argv, raw: "caller text" },
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
    action: { record_schema_version: 3, surface: "command", syntactic: { raw: "ssh $HOST" } },
    summary: "caller",
    actor: { id: "script", kind: "script" },
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const before = JSON.stringify(ctx);
  Object.assign(ctx.action.syntactic, {
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
  assert.deepEqual(display.syntactic, { raw: "ssh $HOST", raw_lines: ["ssh $HOST"] });
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
  const { expires_at, ...context } = JSON.parse(vector.request_canonical);
  const wasm = await loadWasm();
  assert.equal(
    wasm.compute_request_hash(JSON.stringify(context), expires_at),
    vector.request_hash_b64,
  );
});
