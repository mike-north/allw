/**
 * Tests for the hook's config (`readConfig`), which reads the relay coordinates through the shared
 * `@allw/sdk` `loadClientConfig` (config file + per-field env overrides, issue #230) and the
 * hook-only timeouts from the env.
 *
 * Fail-closed: missing or invalid config must report `{ ok: false }` with an actionable reason
 * naming the var (and the config file). `ALLW_TIMEOUT_MS` and `ALLW_FETCH_TIMEOUT_MS` are optional
 * but, when present, must be positive integers. The loader's own rejection matrix is covered by
 * `packages/sdk/test/client-config.test.mjs`; these tests pin that the hook surfaces it as a deny.
 *
 * Every test pins `ALLW_CONFIG`/`path` or points `HOME` at an empty temp dir, so a developer's real
 * `~/.allw/config.json` never leaks in.
 *
 * @see ../../../docs/quickstart.md §4
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_TIMEOUT_MS,
  MAX_FETCH_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  PINNED_HOOK_TIMEOUT_MS,
  readConfig,
} from "../dist/lib/config.js";
import { loadWasm } from "../dist/lib/wasm.js";

const wasm = await loadWasm();
// A real root key and its self-certifying account id, both from the core.
const ROOT_KEY = wasm.ed25519_public_key(Buffer.alloc(32, 5).toString("base64url"));
const ACCOUNT_ID = wasm.account_id_for_root(ROOT_KEY);

const FULL = {
  ALLW_RELAY_URL: "https://relay.allw.test",
  ALLW_ACCOUNT_ID: ACCOUNT_ID,
  ALLW_APPROVER_ROOT_KEY: ROOT_KEY,
};

// Isolate from the developer's real ~/.allw/config.json: the default path lives under an empty HOME.
let home;
const prevHome = process.env.HOME;
const prevProfile = process.env.USERPROFILE;
before(() => {
  home = mkdtempSync(join(tmpdir(), "allw-hook-config-"));
  process.env.HOME = home;
  process.env.USERPROFILE = home;
});
after(() => {
  for (const [key, prev] of [
    ["HOME", prevHome],
    ["USERPROFILE", prevProfile],
  ]) {
    if (prev === undefined) delete process.env[key];
    else process.env[key] = prev;
  }
  rmSync(home, { recursive: true, force: true });
});

/** Write a config file into a fresh temp dir and return its path. */
function writeConfig(t, contents) {
  const dir = mkdtempSync(join(tmpdir(), "allw-hook-config-file-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "config.json");
  writeFileSync(path, typeof contents === "string" ? contents : JSON.stringify(contents), {
    mode: 0o600,
  });
  return path;
}

const FILE = {
  version: 1,
  relay_url: "https://relay.allw.test",
  account_id: ACCOUNT_ID,
  approver_root_key: ROOT_KEY,
};

test("reads a complete config (timeout omitted → undefined)", () => {
  const result = readConfig(FULL);
  assert.equal(result.ok, true);
  assert.equal(result.config.relayUrl, "https://relay.allw.test");
  assert.equal(result.config.accountId, ACCOUNT_ID);
  assert.equal(result.config.approverRootKey, ROOT_KEY);
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

// ── config file (issue #230) ─────────────────────────────────────────────────────────────────────

test("reads the coordinates from a config file with no ALLW_* env", (t) => {
  const result = readConfig({ ALLW_CONFIG: writeConfig(t, FILE) });
  assert.equal(result.ok, true);
  assert.equal(result.config.relayUrl, "https://relay.allw.test");
  assert.equal(result.config.accountId, ACCOUNT_ID);
  assert.equal(result.config.approverRootKey, ROOT_KEY);
});

test("reads the default ~/.allw/config.json (HOME) with no env at all", (t) => {
  const dir = join(home, ".allw");
  mkdirSync(dir, { mode: 0o700 });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, "config.json"), JSON.stringify(FILE), { mode: 0o600 });
  const result = readConfig({});
  assert.equal(result.ok, true);
  assert.equal(result.config.accountId, ACCOUNT_ID);
});

test("the path option overrides ALLW_CONFIG", (t) => {
  const result = readConfig(
    { ALLW_CONFIG: join(home, "does-not-exist.json") },
    { path: writeConfig(t, FILE) },
  );
  assert.equal(result.ok, true);
});

test("env overrides the file per field (relay URL)", (t) => {
  const result = readConfig({
    ALLW_CONFIG: writeConfig(t, FILE),
    ALLW_RELAY_URL: "https://override.allw.test",
  });
  assert.equal(result.ok, true);
  assert.equal(result.config.relayUrl, "https://override.allw.test");
  assert.equal(result.config.accountId, ACCOUNT_ID);
});

test("no file and no env → not ok, naming both ways to configure", () => {
  const result = readConfig({});
  assert.equal(result.ok, false);
  assert.match(result.reason, /\.allw[/\\]config\.json/, "names the config file path");
  assert.match(result.reason, /ALLW_RELAY_URL/);
  assert.match(result.reason, /ALLW_ACCOUNT_ID/);
  assert.match(result.reason, /ALLW_APPROVER_ROOT_KEY/);
  assert.match(result.reason, /fail-closed/);
});

test("malformed config file → not ok (even with full env)", (t) => {
  const path = writeConfig(t, "{");
  const result = readConfig({ ...FULL, ALLW_CONFIG: path });
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes(path));
  assert.match(result.reason, /not valid JSON/);
});

test("unknown config version → not ok", (t) => {
  const result = readConfig({ ALLW_CONFIG: writeConfig(t, { ...FILE, version: 9 }) });
  assert.equal(result.ok, false);
  assert.match(result.reason, /unsupported version 9/);
});

test("config file missing a field → not ok", (t) => {
  const { account_id, ...rest } = FILE;
  void account_id;
  const result = readConfig({ ALLW_CONFIG: writeConfig(t, rest) });
  assert.equal(result.ok, false);
  assert.match(result.reason, /missing 'account_id'/);
  assert.match(result.reason, /ALLW_ACCOUNT_ID/);
});

test("malformed root key → not ok", () => {
  const result = readConfig({ ...FULL, ALLW_APPROVER_ROOT_KEY: "k".repeat(42) });
  assert.equal(result.ok, false);
  assert.match(result.reason, /ALLW_APPROVER_ROOT_KEY is not a base64url-unpadded 32-byte/);
});

test("account id that does not derive from the root key → not ok", () => {
  const result = readConfig({ ...FULL, ALLW_ACCOUNT_ID: "acct-1" });
  assert.equal(result.ok, false);
  assert.match(result.reason, /does not derive from approver_root_key/);
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
