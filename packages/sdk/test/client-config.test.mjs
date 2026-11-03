/**
 * Tests for the integrator config loader `loadClientConfig` (issue #230).
 *
 * Fail-closed (`docs/contract.md` §Invariants #6): every rejection path has its own negative test,
 * each asserting the error is a `ClientConfigError` whose message names the config-file path and
 * the env var to fix — never a partial config. Precedence is per field (env > file), with one test
 * per field.
 *
 * Root keys and account ids are produced by the audited core through WASM (`ed25519_public_key`,
 * `account_id_for_root`), so the derivation check is exercised against the core's own definition
 * (`docs/enrollment.md` §Model), not a TS reimplementation.
 *
 * Run order: `pnpm run build:wasm` (repo root), then `pnpm --filter @allw/sdk test`.
 *
 * @see ../../../docs/quickstart.md §4 (config file; env vars are overrides)
 * @see ../../../docs/threat-model.md (integrator config: trust anchor at rest)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CLIENT_CONFIG_VERSION,
  ClientConfigError,
  defaultClientConfigPath,
  loadClientConfig,
} from "../dist/index.js";
import { loadWasm, loadWasmSync } from "../dist/wasm.js";

const wasm = await loadWasm();

/** A deterministic root key + its derived account id, from the core. */
function account(seedByte) {
  const rootKey = wasm.ed25519_public_key(Buffer.alloc(32, seedByte).toString("base64url"));
  return { rootKey, accountId: wasm.account_id_for_root(rootKey) };
}

const A = account(1);
const B = account(2);
const RELAY = "https://relay.allw.test";
const RELAY_ENV = "https://relay-override.allw.test";

/** A fresh temp dir, removed after the test. */
function tempDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "allw-config-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Write a config file (object → JSON, string → raw) and return its path. */
function writeConfig(t, contents) {
  const path = join(tempDir(t), "config.json");
  writeFileSync(path, typeof contents === "string" ? contents : JSON.stringify(contents), {
    mode: 0o600,
  });
  return path;
}

const VALID_FILE = {
  version: 1,
  relay_url: RELAY,
  account_id: A.accountId,
  approver_root_key: A.rootKey,
};

/** Assert `fn` throws a ClientConfigError naming `path` and every pattern in `mentions`. */
function assertConfigError(fn, path, mentions) {
  assert.throws(fn, (err) => {
    assert.ok(err instanceof ClientConfigError, `expected ClientConfigError, got ${String(err)}`);
    assert.equal(err.path, path);
    assert.ok(err.message.includes(path), `message names the path: ${err.message}`);
    for (const m of mentions) {
      assert.match(err.message, m);
    }
    assert.match(err.message, /fail-closed/);
    return true;
  });
}

// ── happy paths ─────────────────────────────────────────────────────────────────────────────────

test("reads a complete config file with no env", (t) => {
  const path = writeConfig(t, VALID_FILE);
  assert.deepEqual(loadClientConfig({ env: {}, path }), {
    relayUrl: RELAY,
    accountId: A.accountId,
    approverRootKey: A.rootKey,
  });
  assert.equal(CLIENT_CONFIG_VERSION, 1);
});

test("ALLW_CONFIG names the file when no path option is given", (t) => {
  const path = writeConfig(t, VALID_FILE);
  const config = loadClientConfig({ env: { ALLW_CONFIG: path } });
  assert.equal(config.accountId, A.accountId);
});

test("the path option wins over ALLW_CONFIG", (t) => {
  const path = writeConfig(t, VALID_FILE);
  const config = loadClientConfig({ env: { ALLW_CONFIG: join(tempDir(t), "nope.json") }, path });
  assert.equal(config.accountId, A.accountId);
});

test("default path is ~/.allw/config.json", () => {
  assert.match(defaultClientConfigPath(), /[/\\]\.allw[/\\]config\.json$/);
});

/** Point HOME (and USERPROFILE) at `dir` for one test so the default path is under it. */
function withHome(t, dir) {
  const prevHome = process.env.HOME;
  const prevProfile = process.env.USERPROFILE;
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  t.after(() => {
    for (const [key, prev] of [
      ["HOME", prevHome],
      ["USERPROFILE", prevProfile],
    ]) {
      if (prev === undefined) delete process.env[key];
      else process.env[key] = prev;
    }
  });
}

test("env alone (no file at the default path) is a complete config", (t) => {
  withHome(t, tempDir(t));
  const config = loadClientConfig({
    env: { ALLW_RELAY_URL: RELAY, ALLW_ACCOUNT_ID: A.accountId, ALLW_APPROVER_ROOT_KEY: A.rootKey },
  });
  assert.deepEqual(config, { relayUrl: RELAY, accountId: A.accountId, approverRootKey: A.rootKey });
});

test("reads the default ~/.allw/config.json when present", (t) => {
  const home = tempDir(t);
  withHome(t, home);
  mkdirSync(join(home, ".allw"), { mode: 0o700 });
  writeFileSync(join(home, ".allw", "config.json"), JSON.stringify(VALID_FILE), { mode: 0o600 });
  assert.equal(loadClientConfig({ env: {} }).accountId, A.accountId);
});

test("loadWasmSync returns the same memoized core as loadWasm", () => {
  assert.equal(loadWasmSync(), wasm);
});

// ── precedence: env > file, per field ───────────────────────────────────────────────────────────

test("ALLW_RELAY_URL overrides relay_url (other fields from the file)", (t) => {
  const path = writeConfig(t, VALID_FILE);
  const config = loadClientConfig({ env: { ALLW_RELAY_URL: RELAY_ENV }, path });
  assert.deepEqual(config, {
    relayUrl: RELAY_ENV,
    accountId: A.accountId,
    approverRootKey: A.rootKey,
  });
});

test("ALLW_ACCOUNT_ID overrides account_id (other fields from the file)", (t) => {
  // The overriding id must still derive from the (file) root key; overriding with the same
  // derived id via env proves the env value is the one used (the file holds B's id).
  const path = writeConfig(t, { ...VALID_FILE, account_id: B.accountId });
  assert.throws(() => loadClientConfig({ env: {}, path }), ClientConfigError);
  const config = loadClientConfig({ env: { ALLW_ACCOUNT_ID: A.accountId }, path });
  assert.equal(config.accountId, A.accountId);
  assert.equal(config.approverRootKey, A.rootKey);
});

test("ALLW_APPROVER_ROOT_KEY overrides approver_root_key (other fields from the file)", (t) => {
  // File holds B's root with A's id (inconsistent on its own); the env root makes it consistent.
  const path = writeConfig(t, { ...VALID_FILE, approver_root_key: B.rootKey });
  assert.throws(() => loadClientConfig({ env: {}, path }), ClientConfigError);
  const config = loadClientConfig({ env: { ALLW_APPROVER_ROOT_KEY: A.rootKey }, path });
  assert.equal(config.approverRootKey, A.rootKey);
  assert.equal(config.accountId, A.accountId);
});

test("blank env values do not override the file", (t) => {
  const path = writeConfig(t, VALID_FILE);
  const config = loadClientConfig({
    env: { ALLW_RELAY_URL: "  ", ALLW_ACCOUNT_ID: "", ALLW_APPROVER_ROOT_KEY: "" },
    path,
  });
  assert.equal(config.relayUrl, RELAY);
});

// ── fail-closed: one negative test per rejection path ───────────────────────────────────────────

test("no file and no env → error naming the file path and the env vars", (t) => {
  const dir = tempDir(t);
  // Point HOME at an empty dir so the *default* path is absent (not an explicit path).
  withHome(t, dir);
  const path = defaultClientConfigPath();
  assert.ok(path.startsWith(dir));
  assertConfigError(() => loadClientConfig({ env: {} }), path, [
    /does not exist/,
    /ALLW_RELAY_URL/,
    /ALLW_ACCOUNT_ID/,
    /ALLW_APPROVER_ROOT_KEY/,
    /ALLW_CONFIG/,
  ]);
});

test("no file and partial env → error (never a partial config)", (t) => {
  withHome(t, tempDir(t));
  assertConfigError(
    () => loadClientConfig({ env: { ALLW_RELAY_URL: RELAY, ALLW_ACCOUNT_ID: A.accountId } }),
    defaultClientConfigPath(),
    [/ALLW_APPROVER_ROOT_KEY is not set/],
  );
});

test("an explicitly named file that does not exist → error", (t) => {
  const path = join(tempDir(t), "missing.json");
  assertConfigError(
    () =>
      loadClientConfig({
        env: {
          ALLW_CONFIG: path,
          ALLW_RELAY_URL: RELAY,
          ALLW_ACCOUNT_ID: A.accountId,
          ALLW_APPROVER_ROOT_KEY: A.rootKey,
        },
      }),
    path,
    [/does not exist/, /ALLW_CONFIG/],
  );
});

test("an unreadable config path (a directory) → error", (t) => {
  const path = join(tempDir(t), "config.json");
  mkdirSync(path);
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /could not be read/,
    /ALLW_CONFIG/,
  ]);
});

test("malformed JSON → error", (t) => {
  const path = writeConfig(t, "{ not json");
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /not valid JSON/,
    /ALLW_APPROVER_ROOT_KEY/,
  ]);
});

test("malformed JSON is rejected even when env overrides every field", (t) => {
  const path = writeConfig(t, "{ not json");
  assertConfigError(
    () =>
      loadClientConfig({
        env: { ALLW_RELAY_URL: RELAY, ALLW_ACCOUNT_ID: A.accountId, ALLW_APPROVER_ROOT_KEY: A.rootKey },
        path,
      }),
    path,
    [/not valid JSON/],
  );
});

test("a JSON non-object → error", (t) => {
  const path = writeConfig(t, "[1, 2]");
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [/must be a JSON object/]);
});

test("an unknown version → error", (t) => {
  const path = writeConfig(t, { ...VALID_FILE, version: 2 });
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /unsupported version 2/,
    /only version 1/,
  ]);
});

test("a missing version → error", (t) => {
  const { version, ...rest } = VALID_FILE;
  void version;
  const path = writeConfig(t, rest);
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [/unsupported version/]);
});

for (const [key, envVar] of [
  ["relay_url", "ALLW_RELAY_URL"],
  ["account_id", "ALLW_ACCOUNT_ID"],
  ["approver_root_key", "ALLW_APPROVER_ROOT_KEY"],
]) {
  test(`a missing field (${key}) → error naming the key and ${envVar}`, (t) => {
    const { [key]: _omitted, ...rest } = VALID_FILE;
    void _omitted;
    const path = writeConfig(t, rest);
    assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
      new RegExp(`missing '${key}'`),
      new RegExp(envVar),
    ]);
  });

  test(`a non-string ${key} → error`, (t) => {
    const path = writeConfig(t, { ...VALID_FILE, [key]: 42 });
    assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
      new RegExp(`non-string or empty '${key}'`),
      new RegExp(envVar),
    ]);
  });
}

test("an unknown key (e.g. a secret) → error", (t) => {
  const path = writeConfig(t, { ...VALID_FILE, device_auth_token: "secret" });
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /unknown key 'device_auth_token'/,
    /never secrets/,
  ]);
});

test("a relay_url that fails the transport check → error naming its source", (t) => {
  const path = writeConfig(t, { ...VALID_FILE, relay_url: "http://relay.example.com" });
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /must use https/,
    /'relay_url' in /,
  ]);
});

for (const [label, badKey] of [
  ["not base64url", "not a key!"],
  ["padded base64", `${A.rootKey}=`],
  ["the wrong length (31 bytes)", Buffer.alloc(31, 1).toString("base64url")],
]) {
  test(`an approver_root_key that is ${label} → error`, (t) => {
    const path = writeConfig(t, { ...VALID_FILE, approver_root_key: badKey });
    assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
      /not a base64url-unpadded 32-byte Ed25519 public key/,
      /'approver_root_key' in /,
      /ALLW_APPROVER_ROOT_KEY/,
    ]);
  });
}

test("a malformed ALLW_APPROVER_ROOT_KEY override → error naming the env var", (t) => {
  const path = writeConfig(t, VALID_FILE);
  assertConfigError(
    () => loadClientConfig({ env: { ALLW_APPROVER_ROOT_KEY: "short" }, path }),
    path,
    [/env var ALLW_APPROVER_ROOT_KEY is not a base64url-unpadded 32-byte/],
  );
});

test("an account_id that does not derive from approver_root_key → error", (t) => {
  const path = writeConfig(t, { ...VALID_FILE, account_id: B.accountId });
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /account_id from 'account_id' in .* does not derive from approver_root_key/,
    /ALLW_ACCOUNT_ID/,
    /ALLW_APPROVER_ROOT_KEY/,
  ]);
});

test("a legacy free-form account_id → error", (t) => {
  const path = writeConfig(t, { ...VALID_FILE, account_id: "my-account" });
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [/does not derive/]);
});

test("the derivation check is the core's (an injected core that rejects is honored)", (t) => {
  const path = writeConfig(t, VALID_FILE);
  let checked = 0;
  const fake = {
    account_id_for_root: () => "x",
    check_account_id_for_root: () => {
      checked += 1;
      throw new Error("check_account_id_for_root failed: mismatch");
    },
  };
  assertConfigError(() => loadClientConfig({ env: {}, path, wasm: fake }), path, [
    /does not derive/,
  ]);
  assert.equal(checked, 1);
});
