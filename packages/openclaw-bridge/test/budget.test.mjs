/**
 * Timeout-budgeting tests — the nesting rule.
 *
 * Expected values are computed by hand from the spec's formula, never captured from the
 * implementation:
 *
 * ```
 * budget_ms  = expiresAtMs − now_ms − ALLW_DEADLINE_MARGIN_MS
 * timeout_ms = min(budget_ms, ALLW_OPENCLAW_MAX_TIMEOUT_MS)
 * budget_ms < ALLW_OPENCLAW_MIN_TIMEOUT_MS ⇒ insufficient
 * ```
 *
 * @see ../../../docs/openclaw-integration.md §8 Timeout budgeting
 */

import assert from "node:assert/strict";
import test from "node:test";

import { deriveTimeout } from "../dist/index.js";
import { CREATED_AT_MS, EXPIRES_AT_MS } from "./support/fixtures.mjs";

const BASE = {
  expiresAtMs: EXPIRES_AT_MS,
  nowMs: CREATED_AT_MS,
  deadlineMarginMs: 60_000,
  minTimeoutMs: 15_000,
  maxTimeoutMs: 420_000,
};

test("a fresh exec approval is capped by ALLW_OPENCLAW_MAX_TIMEOUT_MS (§8)", () => {
  // budget = 1_800_000 − 0 − 60_000 = 1_740_000; min(1_740_000, 420_000) = 420_000.
  assert.deepEqual(deriveTimeout(BASE), { kind: "ok", timeoutMs: 420_000 });
});

test("the cap only ever lowers the budget, never raises it (§8)", () => {
  // 90 s remain: budget = 90_000 − 60_000 = 30_000, well under the 420 s cap.
  const result = deriveTimeout({ ...BASE, nowMs: EXPIRES_AT_MS - 90_000 });
  assert.deepEqual(result, { kind: "ok", timeoutMs: 30_000 });
});

test("allw's deadline always lands strictly inside OpenClaw's (§8 nesting invariant)", () => {
  for (const remaining of [80_000, 120_000, 500_000, 1_800_000]) {
    const nowMs = EXPIRES_AT_MS - remaining;
    const result = deriveTimeout({ ...BASE, nowMs });
    assert.equal(result.kind, "ok");
    assert.ok(
      nowMs + result.timeoutMs < EXPIRES_AT_MS,
      `allw deadline ${String(nowMs + result.timeoutMs)} must precede ${String(EXPIRES_AT_MS)}`,
    );
    assert.ok(
      EXPIRES_AT_MS - (nowMs + result.timeoutMs) >= BASE.deadlineMarginMs,
      "at least the full margin must remain for the verdict fetch and the resolve",
    );
  }
});

test("a budget below the minimum is insufficient — deny immediately, raise nothing (§8, §9)", () => {
  // 74 999 ms remain ⇒ budget 14 999 ms, one millisecond under the 15 000 ms floor.
  const result = deriveTimeout({ ...BASE, nowMs: EXPIRES_AT_MS - 74_999 });
  assert.deepEqual(result, { kind: "insufficient", budgetMs: 14_999 });
});

test("exactly the minimum budget is sufficient (boundary)", () => {
  const result = deriveTimeout({ ...BASE, nowMs: EXPIRES_AT_MS - 75_000 });
  assert.deepEqual(result, { kind: "ok", timeoutMs: 15_000 });
});

test("an already-expired approval yields a negative budget and is insufficient", () => {
  const result = deriveTimeout({ ...BASE, nowMs: EXPIRES_AT_MS + 1 });
  assert.equal(result.kind, "insufficient");
  assert.ok(result.budgetMs < 0);
});

test("the plugin default TTL of 120 s still leaves a usable budget (§8 constant table)", () => {
  // Upstream plugin default is 120 000 ms: 120_000 − 60_000 = 60_000 ms of human time.
  const result = deriveTimeout({ ...BASE, expiresAtMs: CREATED_AT_MS + 120_000 });
  assert.deepEqual(result, { kind: "ok", timeoutMs: 60_000 });
});
