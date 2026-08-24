/**
 * Configuration + startup-gate tests.
 *
 * Every rule asserted here is a **startup failure** in the spec, not a runtime warning: a bridge
 * whose actor id is ambiguous, or whose allw deadline would land at or after OpenClaw's own, must
 * refuse to start rather than appear to be gating.
 *
 * @see ../../../docs/openclaw-integration.md §7.1 Actor identity, §8 Timeout budgeting
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  ConfigError,
  DEFAULT_DEADLINE_MARGIN_MS,
  DEFAULT_FETCH_TIMEOUT_MS,
  DEFAULT_MAX_TIMEOUT_MS,
  DEFAULT_MIN_TIMEOUT_MS,
  actorIdForGateway,
  loadConfig,
  normalizeGatewayId,
} from "../dist/index.js";

const HOME = "/home/operator";

function env(overrides = {}) {
  return {
    ALLW_OPENCLAW_GATEWAY_URL: "ws://127.0.0.1:18789",
    ALLW_OPENCLAW_GATEWAY_ID: "home-mini",
    ALLW_RELAY_URL: "https://relay.allw.test",
    ALLW_ACCOUNT_ID: "acct-test",
    ALLW_APPROVER_ROOT_KEY: "x".repeat(43),
    ...overrides,
  };
}

// ── §7.1 actor identity ─────────────────────────────────────────────────────────

test("gateway id is normalized by trimming and lowercasing before matching (§7.1)", () => {
  assert.equal(normalizeGatewayId("  Home-Mini  "), "home-mini");
  assert.equal(normalizeGatewayId("gw01"), "gw01");
  assert.equal(normalizeGatewayId("a.b_c-d"), "a.b_c-d");
});

test("malformed, blank, and missing gateway ids are rejected, not defaulted (§7.1)", () => {
  // A silently-defaulted actor id would let two gateways collide in one inbox.
  for (const bad of [
    undefined,
    "",
    "   ",
    "-leading-hyphen",
    ".leading-dot",
    "_leading-underscore",
    "has space",
    "has/slash",
    "has:colon",
    "ü-non-ascii",
    "x".repeat(64),
  ]) {
    assert.equal(normalizeGatewayId(bad), null, `expected '${String(bad)}' to be rejected`);
  }
  // 63 characters is the documented maximum ([a-z0-9] + up to 62 more).
  assert.equal(normalizeGatewayId("x".repeat(63)), "x".repeat(63));
});

test("actor id is openclaw:<gateway-id> (§7.1)", () => {
  assert.equal(actorIdForGateway("home-mini"), "openclaw:home-mini");
});

test("a missing gateway id is a startup failure (§7.1)", () => {
  assert.throws(
    () => loadConfig(env({ ALLW_OPENCLAW_GATEWAY_ID: undefined }), HOME),
    (err) => err instanceof ConfigError && /ALLW_OPENCLAW_GATEWAY_ID/.test(err.message),
  );
});

// ── required relay wiring ───────────────────────────────────────────────────────

for (const key of ["ALLW_RELAY_URL", "ALLW_ACCOUNT_ID", "ALLW_APPROVER_ROOT_KEY"]) {
  test(`${key} is required`, () => {
    assert.throws(
      () => loadConfig(env({ [key]: undefined }), HOME),
      (err) => err instanceof ConfigError && err.message.includes(key),
    );
  });
}

test("a non-WebSocket gateway URL is a startup failure", () => {
  assert.throws(
    () => loadConfig(env({ ALLW_OPENCLAW_GATEWAY_URL: "https://gateway.test" }), HOME),
    (err) => err instanceof ConfigError && /ws:\/\/ or wss:\/\//.test(err.message),
  );
  assert.throws(
    () => loadConfig(env({ ALLW_OPENCLAW_GATEWAY_URL: "not a url" }), HOME),
    (err) => err instanceof ConfigError && /not a valid URL/.test(err.message),
  );
});

// ── §8 timeout budgeting constants ──────────────────────────────────────────────

test("defaults match the spec's constant table (§8)", () => {
  const config = loadConfig(env(), HOME);
  assert.equal(config.deadlineMarginMs, DEFAULT_DEADLINE_MARGIN_MS);
  assert.equal(DEFAULT_DEADLINE_MARGIN_MS, 60_000);
  assert.equal(config.minTimeoutMs, DEFAULT_MIN_TIMEOUT_MS);
  assert.equal(DEFAULT_MIN_TIMEOUT_MS, 15_000);
  assert.equal(config.maxTimeoutMs, DEFAULT_MAX_TIMEOUT_MS);
  assert.equal(DEFAULT_MAX_TIMEOUT_MS, 420_000);
  assert.equal(config.fetchTimeoutMs, DEFAULT_FETCH_TIMEOUT_MS);
  assert.equal(DEFAULT_FETCH_TIMEOUT_MS, 30_000);
  assert.equal(config.stateDir, `${HOME}/.allw`);
  assert.equal(config.bootstrapToken, undefined);
});

test("a margin below 60s is a startup failure (§8: it must hold a fetch plus a resolve)", () => {
  assert.throws(
    () => loadConfig(env({ ALLW_DEADLINE_MARGIN_MS: "45000" }), HOME),
    (err) =>
      err instanceof ConfigError &&
      /ALLW_DEADLINE_MARGIN_MS must be at least 60000/.test(err.message),
  );
});

test("the fetch timeout may only lower the SDK default (§8)", () => {
  assert.throws(
    () => loadConfig(env({ ALLW_FETCH_TIMEOUT_MS: "45000" }), HOME),
    (err) => err instanceof ConfigError && /may only lower the SDK default/.test(err.message),
  );
  assert.equal(loadConfig(env({ ALLW_FETCH_TIMEOUT_MS: "10000" }), HOME).fetchTimeoutMs, 10_000);
});

test("a fetch timeout at or above the margin is a startup failure (§8 nesting)", () => {
  // The margin exists so the final verdict fetch AND the approval.resolve both land inside it; a
  // fetch timeout that fills the whole margin leaves no room for the resolve.
  assert.throws(
    () =>
      loadConfig(env({ ALLW_DEADLINE_MARGIN_MS: "60000", ALLW_FETCH_TIMEOUT_MS: "60000" }), HOME),
    (err) => err instanceof ConfigError && /must stay below/.test(err.message),
  );
  assert.throws(
    () =>
      loadConfig(env({ ALLW_DEADLINE_MARGIN_MS: "90000", ALLW_FETCH_TIMEOUT_MS: "120000" }), HOME),
    (err) => err instanceof ConfigError && /must stay below/.test(err.message),
  );
});

test("a minimum budget at or above the maximum is a startup failure (§8)", () => {
  assert.throws(
    () =>
      loadConfig(
        env({ ALLW_OPENCLAW_MIN_TIMEOUT_MS: "420000", ALLW_OPENCLAW_MAX_TIMEOUT_MS: "420000" }),
        HOME,
      ),
    (err) => err instanceof ConfigError && /must be below/.test(err.message),
  );
});

test("non-integer, zero, and negative millisecond values are rejected", () => {
  for (const bad of ["0", "-1", "1.5", "sixty", "60_000"]) {
    assert.throws(
      () => loadConfig(env({ ALLW_OPENCLAW_MAX_TIMEOUT_MS: bad }), HOME),
      (err) => err instanceof ConfigError && /positive integer/.test(err.message),
      `expected '${bad}' to be rejected`,
    );
  }
});

test("the bootstrap credential is optional and trimmed", () => {
  assert.equal(
    loadConfig(env({ ALLW_OPENCLAW_BOOTSTRAP_TOKEN: "  boot  " }), HOME).bootstrapToken,
    "boot",
  );
  assert.equal(
    loadConfig(env({ ALLW_OPENCLAW_BOOTSTRAP_TOKEN: "   " }), HOME).bootstrapToken,
    undefined,
  );
});
