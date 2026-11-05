/**
 * The published primitive exposes human decisions, never a standing-policy engine.
 * Test the consumed SDK and generated WASM artifacts so stale packaging cannot retain authority.
 * @see ../../../CLAUDE.md §Scope
 * @see ../../../docs/contract.md §Verification checklist
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as sdk from "../dist/index.js";
import * as wasm from "../vendor/allw-wasm/allw_wasm.js";

test("published approval surfaces carry no standing-rule operations", () => {
  for (const surface of [sdk, wasm]) {
    assert.deepEqual(
      Object.keys(surface).filter((name) => /policy|rule/i.test(name)),
      [],
      "callers must supply their own external policy layer",
    );
  }
  for (const artifact of ["../dist/index.d.ts", "../vendor/allw-wasm/allw_wasm.d.ts"]) {
    const declarations = readFileSync(new URL(artifact, import.meta.url), "utf8");
    assert.doesNotMatch(
      declarations,
      /PolicyRule|PolicyEvaluation|PolicyTier|evaluate_?policy|sign_policy_rule/i,
    );
  }
  assert.equal(typeof sdk.verifyVerdictWithAccountStates, "function");
  for (const name of [
    "verify_verdict",
    "verify_verdict_provenance",
    "verify_account_state",
    "compute_request_hash",
  ]) {
    assert.equal(typeof wasm[name], "function", `${name} remains available`);
  }
});
