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
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  CLIENT_CONFIG_VERSION,
  ClientConfigError,
  defaultClientConfigPath,
  loadClientConfig,
} from "../dist/index.js";
import { MAX_CLIENT_CONFIG_BYTES, loadClientConfigWith } from "../dist/config.js";
import { loadWasm, loadWasmSync } from "../dist/wasm.js";

const POSIX = process.platform !== "win32";
const distIndex = pathToFileURL(
  join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js"),
).href;

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

test("a directory at the config path → error (not a regular file)", (t) => {
  const path = join(tempDir(t), "config.json");
  mkdirSync(path);
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /is not a readable regular file/,
    /ALLW_CONFIG/,
  ]);
  assert.throws(
    () => loadClientConfig({ env: {}, path }),
    (err) => {
      assert.doesNotMatch(err.message, /permissions/, "no permissions hint unless EACCES");
      return true;
    },
  );
});

/**
 * Run the loader against `configPath` in a child process with a hard timeout, so a blocking read
 * shows up as a timed-out child instead of hanging the test runner.
 */
function loadInChild(configPath) {
  const script =
    `import(${JSON.stringify(distIndex)}).then((m) => {` +
    `  try { m.loadClientConfig({ env: { ALLW_CONFIG: ${JSON.stringify(configPath)} } });` +
    `        process.stdout.write("LOADED"); }` +
    `  catch (e) { process.stdout.write(e.name + ": " + e.message); }` +
    `});`;
  return spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8",
    timeout: 10_000,
  });
}

test("a FIFO at ALLW_CONFIG → error, without blocking", { skip: !POSIX }, (t) => {
  const path = join(tempDir(t), "config.json");
  execFileSync("mkfifo", ["-m", "600", path]);
  const child = loadInChild(path);
  assert.equal(
    child.error,
    undefined,
    `the loader must not block on a FIFO (${String(child.error)})`,
  );
  assert.match(child.stdout, /^ClientConfigError: /);
  assert.match(child.stdout, /is not a readable regular file/);
  assert.ok(child.stdout.includes(path));
});

test(
  "a character device (/dev/zero) at ALLW_CONFIG → error, without blocking",
  {
    skip: !POSIX,
  },
  () => {
    const child = loadInChild("/dev/zero");
    assert.equal(
      child.error,
      undefined,
      `the loader must not read /dev/zero (${String(child.error)})`,
    );
    assert.match(child.stdout, /^ClientConfigError: /);
    assert.match(child.stdout, /\/dev\/zero/);
  },
);

test("an oversize config file → error", (t) => {
  const path = writeConfig(t, " ".repeat(MAX_CLIENT_CONFIG_BYTES + 1));
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    new RegExp(`${String(MAX_CLIENT_CONFIG_BYTES)}-byte limit`),
  ]);
});

test("a config file at exactly the size cap is read", (t) => {
  const body = JSON.stringify(VALID_FILE);
  const path = writeConfig(t, body + " ".repeat(MAX_CLIENT_CONFIG_BYTES - body.length));
  assert.equal(loadClientConfig({ env: {}, path }).accountId, A.accountId);
});

// ── path rules: absolute only (a relative path would resolve against the agent's cwd) ──────────

test("a relative ALLW_CONFIG → error (must be an absolute path)", () => {
  assert.throws(
    () => loadClientConfig({ env: { ALLW_CONFIG: ".allw/config.json" } }),
    (err) => {
      assert.ok(err instanceof ClientConfigError);
      assert.match(err.message, /ALLW_CONFIG '\.allw\/config\.json' must be an absolute path/);
      return true;
    },
  );
});

test("a relative path option → error (must be an absolute path)", () => {
  assert.throws(
    () => loadClientConfig({ env: {}, path: "config.json" }),
    (err) => {
      assert.ok(err instanceof ClientConfigError);
      assert.match(err.message, /path option 'config\.json' must be an absolute path/);
      return true;
    },
  );
});

test("a leading ~/ in ALLW_CONFIG expands to the home directory", (t) => {
  const home = tempDir(t);
  withHome(t, home);
  mkdirSync(join(home, ".allw"), { mode: 0o700 });
  writeFileSync(join(home, "alt.json"), JSON.stringify(VALID_FILE), { mode: 0o600 });
  assert.equal(homedir(), home);
  assert.equal(loadClientConfig({ env: { ALLW_CONFIG: "~/alt.json" } }).accountId, A.accountId);
});

// ── POSIX ownership / mode: the trust anchor at rest must be yours and not writable by others ───

test("a group-writable config file → error naming chmod 600", { skip: !POSIX }, (t) => {
  const path = writeConfig(t, VALID_FILE);
  chmodSync(path, 0o620);
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /group- or world-writable \(mode 620\)/,
    new RegExp(`chmod 600 ${path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
  ]);
});

test("a world-writable config file → error naming chmod 600", { skip: !POSIX }, (t) => {
  const path = writeConfig(t, VALID_FILE);
  chmodSync(path, 0o606);
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /group- or world-writable \(mode 606\)/,
    /chmod 600/,
  ]);
});

test("a group-readable (not writable) config file is accepted", { skip: !POSIX }, (t) => {
  const path = writeConfig(t, VALID_FILE);
  chmodSync(path, 0o640);
  assert.equal(loadClientConfig({ env: {}, path }).accountId, A.accountId);
});

test("a config file not owned by the effective uid → error naming chown", { skip: !POSIX }, (t) => {
  const path = writeConfig(t, VALID_FILE);
  const notMe = (process.geteuid?.() ?? 0) + 4242;
  assertConfigError(() => loadClientConfigWith({ env: {}, path }, { geteuid: () => notMe }), path, [
    /not by the current user/,
    /chown/,
  ]);
});

test("the ownership/mode check is skipped on win32", (t) => {
  const path = writeConfig(t, VALID_FILE);
  if (POSIX) chmodSync(path, 0o666);
  const config = loadClientConfigWith(
    { env: {}, path },
    { platform: "win32", geteuid: () => 4242 },
  );
  assert.equal(config.accountId, A.accountId);
});

test("malformed JSON → error reporting the position", (t) => {
  const path = writeConfig(t, "{ not json");
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /not valid JSON \(at position 2\)/,
    /ALLW_APPROVER_ROOT_KEY/,
  ]);
});

test("malformed JSON never echoes the file's contents (Node's quoted snippet is stripped)", (t) => {
  // This parse error's Node message quotes the whole input and carries no position.
  const secretish = "SECRET-SEED-abcdef";
  const path = writeConfig(t, `{ "x": ${secretish} }`);
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /not valid JSON \(at an unknown position\)/,
  ]);
  assert.throws(
    () => loadClientConfig({ env: {}, path }),
    (err) => {
      assert.ok(!err.message.includes("SECRET"), `contents leaked: ${err.message}`);
      assert.ok(err.cause instanceof SyntaxError, "the parse error is kept only as { cause }");
      return true;
    },
  );
});

test("malformed JSON is rejected even when env overrides every field", (t) => {
  const path = writeConfig(t, "{ not json");
  assertConfigError(
    () =>
      loadClientConfig({
        env: {
          ALLW_RELAY_URL: RELAY,
          ALLW_ACCOUNT_ID: A.accountId,
          ALLW_APPROVER_ROOT_KEY: A.rootKey,
        },
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

test("an unknown version → error reporting only its JSON type", (t) => {
  const path = writeConfig(t, { ...VALID_FILE, version: 2 });
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /unsupported version \(got number\)/,
    /only version 1/,
  ]);
});

test("a string version → error that does not echo the value", (t) => {
  const path = writeConfig(t, { ...VALID_FILE, version: "hunter2-secret" });
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /unsupported version \(got string\)/,
  ]);
  assert.throws(
    () => loadClientConfig({ env: {}, path }),
    (err) => {
      assert.ok(!err.message.includes("hunter2-secret"));
      return true;
    },
  );
});

test("a missing version → error", (t) => {
  const { version, ...rest } = VALID_FILE;
  void version;
  const path = writeConfig(t, rest);
  assertConfigError(() => loadClientConfig({ env: {}, path }), path, [
    /unsupported version \(got missing\)/,
  ]);
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

test("half-set env: env root B over a file with account A → error naming env var and file key", (t) => {
  const path = writeConfig(t, VALID_FILE);
  assertConfigError(
    () => loadClientConfig({ env: { ALLW_APPROVER_ROOT_KEY: B.rootKey }, path }),
    path,
    [
      /account_id from 'account_id' in .* does not derive from approver_root_key from env var ALLW_APPROVER_ROOT_KEY/,
    ],
  );
});

test("half-set env: env account B over a file with root A → error naming env var and file key", (t) => {
  const path = writeConfig(t, VALID_FILE);
  assertConfigError(() => loadClientConfig({ env: { ALLW_ACCOUNT_ID: B.accountId }, path }), path, [
    /account_id from env var ALLW_ACCOUNT_ID does not derive from approver_root_key from 'approver_root_key' in /,
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
  assertConfigError(() => loadClientConfigWith({ env: {}, path }, { wasm: fake }), path, [
    /does not derive/,
  ]);
  assert.equal(checked, 1);
});
