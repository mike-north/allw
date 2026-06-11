/**
 * Tests for the hook's env-sourced config (`readConfig`).
 *
 * Fail-closed: a missing required var must report `{ ok: false }` with an actionable reason naming
 * the var. `ALLW_TIMEOUT_MS` is optional but, when present, must be a positive integer.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_TIMEOUT_MS,
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

// ── ALLW_FETCH_TIMEOUT_MS (issue #54 — CI-fast knob: a shorter per-relay-fetch timeout) ───────────

test("(#54) ALLW_FETCH_TIMEOUT_MS is absent by default → fetchTimeoutMs undefined (SDK default applies)", () => {
  const result = readConfig(FULL);
  assert.equal(result.ok, true);
  assert.equal(result.config.fetchTimeoutMs, undefined);
});

test("(#54) a valid ALLW_FETCH_TIMEOUT_MS below the deadline is accepted", () => {
  const result = readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: "200" });
  assert.equal(result.ok, true);
  assert.equal(result.config.fetchTimeoutMs, 200, "a short fetch timeout (200ms) is honored");
});

test("(#54) non-numeric ALLW_FETCH_TIMEOUT_MS → fail-closed deny", () => {
  const result = readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: "soon" });
  assert.equal(result.ok, false);
  assert.ok(/ALLW_FETCH_TIMEOUT_MS must be a positive integer/.test(result.reason));
});

test("(#54) zero / negative / non-integer ALLW_FETCH_TIMEOUT_MS → fail-closed deny", () => {
  assert.equal(readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: "0" }).ok, false);
  assert.equal(readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: "-1" }).ok, false);
  assert.equal(readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: "1.5" }).ok, false);
});

test("(#54) ALLW_FETCH_TIMEOUT_MS at/above the default deadline → fail-closed deny", () => {
  // With no ALLW_TIMEOUT_MS the deadline is the 5-minute default; a fetch timeout >= it is pointless
  // (the overall deadline would fire first) and signals a misconfiguration.
  const atDeadline = readConfig({ ...FULL, ALLW_FETCH_TIMEOUT_MS: String(DEFAULT_TIMEOUT_MS) });
  assert.equal(atDeadline.ok, false);
  assert.ok(/strictly below the fail-closed deadline/.test(atDeadline.reason));

  const aboveDeadline = readConfig({
    ...FULL,
    ALLW_FETCH_TIMEOUT_MS: String(DEFAULT_TIMEOUT_MS + 1),
  });
  assert.equal(aboveDeadline.ok, false);
});

test("(#54) ALLW_FETCH_TIMEOUT_MS is validated against a configured ALLW_TIMEOUT_MS deadline", () => {
  // The deadline the fetch timeout is checked against is the *resolved* one: the configured
  // ALLW_TIMEOUT_MS when present, not the default. 500ms is below the 5-min default but >= a 400ms
  // configured deadline, so it must be rejected.
  const result = readConfig({
    ...FULL,
    ALLW_TIMEOUT_MS: "400",
    ALLW_FETCH_TIMEOUT_MS: "500",
  });
  assert.equal(result.ok, false, "fetch timeout >= the configured deadline is rejected");
  assert.ok(/strictly below the fail-closed deadline of 400ms/.test(result.reason));
});
