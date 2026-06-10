/**
 * Tests for the hook's env-sourced config (`readConfig`).
 *
 * Fail-closed: a missing required var must report `{ ok: false }` with an actionable reason naming
 * the var. `ALLW_TIMEOUT_MS` is optional but, when present, must be a positive integer.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { DEFAULT_TIMEOUT_MS, readConfig } from "../dist/lib/config.js";

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
