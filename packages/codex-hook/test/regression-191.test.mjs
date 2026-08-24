/**
 * Regression tests for #191: `denyOutput` used to attach a `denyReason` field inside
 * `hookSpecificOutput` on every deny, and the pass-through/approve paths emitted a bare
 * `permissionDecision: "allow"`. Codex's `PreToolUse` output schema is `additionalProperties:
 * false`, so the undocumented `denyReason` field made the *entire* deny payload fail to parse —
 * Codex recorded a hook error and let the gated tool call proceed. That inverted the fail-closed
 * invariant for exactly the cases that matter: human denial, timeout, transport error.
 *
 * These tests exercise the pre-fix wire shapes directly (reconstructed inline, since the buggy
 * `allowOutput`/`makeOutput` exports and the `denyReason` field no longer exist in
 * `../src/lib/codex-io.ts`) against the spec-first validator in `./support/codex-schema.mjs`, to
 * prove the validator — and therefore this suite — would have caught the bug. They then assert the
 * fixed `denyOutput`/`noBlockOutput`/`runCodexHook` no longer produce those shapes.
 *
 * @see https://learn.chatgpt.com/docs/hooks
 */

import assert from "node:assert/strict";
import test from "node:test";

import { denyOutput } from "../dist/lib/codex-io.js";
import { runCodexHook } from "../dist/cli.js";
import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";

test("regression #191: the pre-fix denyReason field violates Codex's additionalProperties:false schema", () => {
  const preFixDenyShape = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "allw: blocked by allw",
      // The undocumented field that made Codex discard the entire payload and continue the tool
      // call — this is exactly what shipped in #166 and is fixed here.
      denyReason: "no-approval",
    },
  };

  assert.throws(
    () => assertConformsToPreToolUseOutputContract(preFixDenyShape),
    /undocumented field 'denyReason'/,
    "the pre-fix shape must fail schema conformance — this is the bug #191 fixes",
  );
});

test("regression #191: the pre-fix bare permissionDecision:'allow' is not a valid non-null payload", () => {
  const preFixAllowShape = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      permissionDecisionReason: "allw: tool 'Read' is not gated by allw; passing through",
    },
  };

  assert.throws(
    () => assertConformsToPreToolUseOutputContract(preFixAllowShape),
    /permissionDecision must be 'deny'/,
    "a bare 'allow' is unsupported on the 2026 surface; 'allw did not block' must be null (silence)",
  );
});

test("fixed: denyOutput never re-introduces a denyReason field", () => {
  const output = denyOutput("blocked by allw", "no-approval");

  assert.equal(Object.hasOwn(output.hookSpecificOutput, "denyReason"), false);
  assertConformsToPreToolUseOutputContract(output);
});

test("fixed: runCodexHook's approve/non-gated paths emit null (empty stdout), never permissionDecision:'allow'", async () => {
  const nonGated = await runCodexHook(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_input: { file_path: "/tmp/a" },
    }),
    {},
  );

  assert.equal(nonGated, null);
  assertConformsToPreToolUseOutputContract(nonGated);
});

test("fixed: runCodexHook's deny paths always conform to the documented schema", async () => {
  const malformedStdin = await runCodexHook("not json", {});
  const missingConfig = await runCodexHook(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "git push origin main" },
    }),
    {},
  );

  for (const output of [malformedStdin, missingConfig]) {
    assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
    assertConformsToPreToolUseOutputContract(output);
  }
});
