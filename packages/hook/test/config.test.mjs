/**
 * Tests for the hook's env-sourced config (`readConfig`).
 *
 * Fail-closed: a missing required var must report `{ ok: false }` with an actionable reason naming
 * the var. `ALLW_TIMEOUT_MS` and `ALLW_FETCH_TIMEOUT_MS` are optional but, when present, must be
 * positive integers.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_TIMEOUT_MS,
  MAX_FETCH_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  PINNED_HOOK_TIMEOUT_MS,
  readConfig,
} from "../dist/lib/config.js";

const FULL = {
  ALLW_RELAY_URL: "https://relay.allw.test",
  ALLW_ACCOUNT_ID: "acct-1",
  ALLW_APPROVER_ROOT_KEY: "k".repeat(43),
};

test("reads a complete config (timeout omitted → undefined)", () => {
  const result = readConfig(FULL);
  assert.equal(result.ok, true);
  assert.equal(result.config.relayUrl, "https://relay.allw.test");
  assert.equal(result.config.accountId, "acct-1");
  assert.equal(result.config.approverRootKey, "k".repeat(43));
  assert.equal(result.config.timeoutMs, undefined, "absent ALLW_TIMEOUT_MS → no timeoutMs");
});

test("reads a valid ALLW_TIMEOUT_MS", () => {
  const result = readConfig({ ...FULL, ALLW_TIMEOUT_MS: "120000" });
  assert.equal(result.ok, true);
  assert.equal(result.config.timeoutMs, 120000);
});

test("(#54) reads a valid ALLW_FETCH_TIMEOUT_MS", () => {
  const result = readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: "100" });
  assert.equal(result.ok, true);
  assert.equal(result.config.fetchTimeoutMs, 100);
});

test("the default timeout constant is 5 minutes (documented contract default)", () => {
  // The hook leaves timeoutMs unset and lets the SDK apply its 5-minute default; this asserts the
  // documented value the README states.
  assert.equal(DEFAULT_TIMEOUT_MS, 5 * 60 * 1000);
});

// ── fail-closed: missing required vars ──────────────────────────────────────────────────────────

test("missing ALLW_RELAY_URL → not ok", () => {
  const { ALLW_RELAY_URL, ...rest } = FULL;
  void ALLW_RELAY_URL;
  const result = readConfig(rest);
  assert.equal(result.ok, false);
  assert.ok(/ALLW_RELAY_URL is not set/.test(result.reason));
});

test("missing ALLW_ACCOUNT_ID → not ok", () => {
  const { ALLW_ACCOUNT_ID, ...rest } = FULL;
  void ALLW_ACCOUNT_ID;
  const result = readConfig(rest);
  assert.equal(result.ok, false);
  assert.ok(/ALLW_ACCOUNT_ID is not set/.test(result.reason));
});

test("missing ALLW_APPROVER_ROOT_KEY → not ok", () => {
  const { ALLW_APPROVER_ROOT_KEY, ...rest } = FULL;
  void ALLW_APPROVER_ROOT_KEY;
  const result = readConfig(rest);
  assert.equal(result.ok, false);
  assert.ok(/ALLW_APPROVER_ROOT_KEY is not set/.test(result.reason));
});

test("blank (whitespace-only) required var is treated as missing → not ok", () => {
  const result = readConfig({ ...FULL, ALLW_RELAY_URL: "   " });
  assert.equal(result.ok, false);
});

// ── fail-closed: invalid timeout ────────────────────────────────────────────────────────────────

test("non-numeric ALLW_TIMEOUT_MS → not ok", () => {
  const result = readConfig({ ...FULL, ALLW_TIMEOUT_MS: "soon" });
  assert.equal(result.ok, false);
  assert.ok(/ALLW_TIMEOUT_MS must be a positive integer/.test(result.reason));
});

test("zero / negative ALLW_TIMEOUT_MS → not ok", () => {
  assert.equal(readConfig({ ...FULL, ALLW_TIMEOUT_MS: "0" }).ok, false);
  assert.equal(readConfig({ ...FULL, ALLW_TIMEOUT_MS: "-5" }).ok, false);
});

test("non-integer ALLW_TIMEOUT_MS → not ok", () => {
  assert.equal(readConfig({ ...FULL, ALLW_TIMEOUT_MS: "1.5" }).ok, false);
});

test("(#54) invalid ALLW_FETCH_TIMEOUT_MS → not ok", () => {
  for (const value of ["soon", "0", "-5", "1.5"]) {
    const result = readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: value });
    assert.equal(result.ok, false, `ALLW_FETCH_TIMEOUT_MS=${value} should fail closed`);
    assert.ok(/ALLW_FETCH_TIMEOUT_MS must be a positive integer/.test(result.reason));
  }
});

test("(#54) ALLW_FETCH_TIMEOUT_MS can lower but not raise the SDK default", () => {
  const atMax = readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: String(MAX_FETCH_TIMEOUT_MS) });
  assert.equal(atMax.ok, true);
  assert.equal(atMax.config.fetchTimeoutMs, MAX_FETCH_TIMEOUT_MS);

  const overMax = readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: String(MAX_FETCH_TIMEOUT_MS + 1) });
  assert.equal(overMax.ok, false);
  assert.ok(/ALLW_FETCH_TIMEOUT_MS=.*too large/.test(overMax.reason));
});

// ── fail-closed: ALLW_TIMEOUT_MS cap (issue #52 — must fire before Claude Code's hook timeout) ────

test("(#52) the pinned hook timeout is below Claude Code's 600s default, the cap below the pin", () => {
  // The whole ordering invariant: ALLW_TIMEOUT_MS cap < pinned hook timeout < Claude Code default.
  const CC_DEFAULT_HOOK_TIMEOUT_MS = 600_000;
  assert.ok(
    PINNED_HOOK_TIMEOUT_MS < CC_DEFAULT_HOOK_TIMEOUT_MS,
    "pinned hook timeout must be below Claude Code's 600s default",
  );
  assert.ok(
    MAX_TIMEOUT_MS < PINNED_HOOK_TIMEOUT_MS,
    "the ALLW_TIMEOUT_MS cap must be strictly below the pinned hook timeout",
  );
  assert.ok(
    PINNED_HOOK_TIMEOUT_MS - MAX_TIMEOUT_MS >= 30_000,
    "the margin must cover at least one SDK relay-fetch timeout (30s)",
  );
  assert.ok(
    DEFAULT_TIMEOUT_MS < MAX_TIMEOUT_MS,
    "the default deadline must sit comfortably under the cap",
  );
});

test("(#52) ALLW_TIMEOUT_MS just below the cap is accepted", () => {
  const result = readConfig({ ...FULL, ALLW_TIMEOUT_MS: String(MAX_TIMEOUT_MS - 1) });
  assert.equal(result.ok, true);
  assert.equal(result.config.timeoutMs, MAX_TIMEOUT_MS - 1);
});

test("(#52) ALLW_TIMEOUT_MS exactly at the cap → fail-closed deny", () => {
  const result = readConfig({ ...FULL, ALLW_TIMEOUT_MS: String(MAX_TIMEOUT_MS) });
  assert.equal(result.ok, false, "a value at the cap is rejected (must be strictly below)");
  assert.ok(/too large/.test(result.reason));
});

test("(#52) an oversized ALLW_TIMEOUT_MS (900000 = 15 min) → fail-closed deny", () => {
  // The motivating case: a user setting "give me time to reach my phone" (15 min) would push the SDK
  // deadline past Claude Code's hook timeout, where the outcome rides on undocumented CC behavior.
  const result = readConfig({ ...FULL, ALLW_TIMEOUT_MS: "900000" });
  assert.equal(result.ok, false);
  assert.ok(/too large/.test(result.reason));
});
