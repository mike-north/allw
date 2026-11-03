/**
 * Tests for the validation of `seal_context_for_account_state`'s result. The SDK persists `sequence`
 * as the rollback floor and sends `ciphertext`, so a result that no successful seal could return
 * must be refused (fail-closed) rather than recorded or sent. Regression for a review finding: the
 * earlier check accepted a negative sequence and an empty ciphertext.
 *
 * @see ../../../docs/enrollment.md §Model (recipient selection rule; the sequence floor)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { parseSealedContext } from "../dist/sealed-context.js";

test("a well-formed result parses to { ciphertext, sequence }", () => {
  assert.deepEqual(parseSealedContext(JSON.stringify({ ciphertext: "eyJ.x", sequence: 3 })), {
    ciphertext: "eyJ.x",
    sequence: 3,
  });
  assert.deepEqual(parseSealedContext(JSON.stringify({ ciphertext: "c", sequence: 0 })), {
    ciphertext: "c",
    sequence: 0,
  });
});

test("a result no successful seal could return is refused", () => {
  for (const [name, json] of [
    ["negative sequence", JSON.stringify({ ciphertext: "c", sequence: -1 })],
    ["empty ciphertext", JSON.stringify({ ciphertext: "", sequence: 1 })],
    ["fractional sequence", JSON.stringify({ ciphertext: "c", sequence: 1.5 })],
    ["unsafe-integer sequence", `{"ciphertext":"c","sequence":9007199254740993}`],
    ["string sequence", JSON.stringify({ ciphertext: "c", sequence: "1" })],
    ["missing sequence", JSON.stringify({ ciphertext: "c" })],
    ["non-string ciphertext", JSON.stringify({ ciphertext: 1, sequence: 1 })],
    ["array", JSON.stringify([{ ciphertext: "c", sequence: 1 }])],
    ["null", "null"],
    ["not JSON", "{"],
  ]) {
    assert.equal(parseSealedContext(json), null, name);
  }
});
