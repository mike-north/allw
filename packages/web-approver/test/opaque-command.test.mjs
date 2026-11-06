/** Display layout never splits caller text into words or derives a program identity.
 * @see docs/threat-model.md §R3; docs/action-record.md — Command capture.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { reconstructCommand, rawDivergesFromArgv } from "../dist/command-line.js";

test("opaque raw text supplies no inferred command form", () => {
  assert.equal(reconstructCommand({ raw: "echo $(id) # hi\nrm x" }), undefined);
  assert.equal(reconstructCommand({ bin: "legacy", positionals: ["data"] }), undefined);
});

test("supplied argv is quoted faithfully and compared without tokenizing raw", () => {
  assert.equal(reconstructCommand({ argv: ["", "a b", "'", "$HOME"] }), "'' 'a b' ''\\''' '$HOME'");
  assert.equal(rawDivergesFromArgv({ raw: "ls *.txt", argv: ["ls", "*.txt"] }), true);
  assert.equal(rawDivergesFromArgv({ raw: "git \t status", argv: ["git", "status"] }), true);
  assert.equal(rawDivergesFromArgv({ raw: "git status", argv: ["git", "status"] }), false);
  assert.equal(rawDivergesFromArgv({ raw: "# comment" }), false);
});
