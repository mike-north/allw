/**
 * Private diagnostics are optional and contain only lifecycle metadata, never action text.
 * @see ../../../docs/codex-integration.md (Private denial diagnostics)
 * @see https://github.com/mike-north/allw/issues/251 (item 1)
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const CLI = new URL("../dist/cli.js", import.meta.url);
const NOW = "2026-11-06T12:00:00.000Z";
const ID = "a1234567-1234-4234-8234-123456789abc";
const SECRET = "SECRET-token-key-command\nforged\u001b[2J";

/** All paths are disposable; no developer state or account is used. */
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "allw-private-log-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const cwd = join(root, "project");
  const home = join(root, "home");
  mkdirSync(join(cwd, ".codex"), { recursive: true });
  mkdirSync(home);
  return {
    root,
    cwd,
    home,
    env: { HOME: home, XDG_STATE_HOME: join(root, "xdg"), ALLW_CODEX_DENY_LOG: "1" },
  };
}

/** Real process boundary: logging failure must still yield the identical explicit deny. */
function cli(f, env = {}, stdin = "not json", preload) {
  const result = spawnSync(
    process.execPath,
    [...(preload ? ["--import", preload] : []), CLI.pathname],
    {
      cwd: f.cwd,
      env: { PATH: process.env.PATH, HOME: f.home, ...env },
      input: stdin,
      encoding: "utf8",
      timeout: 5000,
    },
  );
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, "deny");
  return result.stdout;
}

test("default off and every non-exact opt-in write nothing in project or user state", (t) => {
  const f = fixture(t);
  for (const flag of [undefined, "", "0", "true", "yes", "01", " 1", "1 ", "1\n"]) {
    cli(f, {
      XDG_STATE_HOME: f.env.XDG_STATE_HOME,
      ...(flag === undefined ? {} : { ALLW_CODEX_DENY_LOG: flag }),
    });
    assert.deepEqual(readdirSync(join(f.cwd, ".codex")), []);
    assert.deepEqual(readdirSync(f.home), []);
    assert.equal(existsSync(f.env.XDG_STATE_HOME), false);
  }
});

test("opt-in CLI writes only to XDG state and omits hostile reason text and fabricated ids", (t) => {
  const f = fixture(t);
  const stdout = cli(f, f.env, JSON.stringify({ hook_event_name: SECRET }));
  assert.match(stdout, /SECRET-token-key-command/);
  const bytes = readFileSync(join(f.env.XDG_STATE_HOME, "allw", "codex-deny.log"), "utf8");
  assert.match(
    bytes,
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z \[allw\] deny category=input-parse-error\n$/,
  );
  assert.doesNotMatch(bytes, /SECRET|forged|request_id|reason=/);
  assert.deepEqual(readdirSync(join(f.cwd, ".codex")), []);
});

// Imported dynamically so the process-boundary tests also provide pre-implementation red evidence.
async function logger() {
  return import("../dist/lib/deny-log.js");
}
async function output(reason = SECRET, id) {
  const { denyOutput } = await import("../dist/lib/codex-io.js");
  return denyOutput(reason, "no-approval", id);
}

test("fixed timestamps, available id, multiple denials, private permissions, and HOME fallback", async (t) => {
  const f = fixture(t);
  const { appendDenyLog } = await logger();
  const env = { ...f.env, XDG_STATE_HOME: "" };
  appendDenyLog(env, await output(SECRET, ID), () => NOW);
  appendDenyLog(env, await output(), () => "2026-11-06T12:00:01.000Z");
  const dir = join(f.home, ".allw", "state");
  const path = join(dir, "codex-deny.log");
  assert.equal(
    readFileSync(path, "utf8"),
    `${NOW} [allw] deny category=no-approval request_id=${ID}\n2026-11-06T12:00:01.000Z [allw] deny category=no-approval\n`,
  );
  if (process.platform !== "win32") {
    assert.equal(statSync(dir).mode & 0o777, 0o700);
    assert.equal(statSync(path).mode & 0o777, 0o600);
  }
  assert.deepEqual(readdirSync(join(f.cwd, ".codex")), []);
});

test("no-block outputs and malformed ids or categories cannot persist untrusted text", async (t) => {
  const f = fixture(t);
  const { appendDenyLog } = await logger();
  appendDenyLog(f.env, null, () => NOW);
  assert.equal(existsSync(f.env.XDG_STATE_HOME), false);
  for (const id of [SECRET, "", "fake", `${ID}\n`, undefined]) {
    appendDenyLog(f.env, await output(SECRET, id), () => NOW);
  }
  const path = join(f.env.XDG_STATE_HOME, "allw", "codex-deny.log");
  assert.equal(readFileSync(path, "utf8"), `${NOW} [allw] deny category=no-approval\n`.repeat(5));
  appendDenyLog(f.env, { hookSpecificOutput: { permissionDecisionReason: SECRET } }, () => NOW);
  assert.equal(readFileSync(path, "utf8"), `${NOW} [allw] deny category=no-approval\n`.repeat(5));
});

for (const failure of [
  "relative-xdg",
  "state-file",
  "state-link",
  "parent-link",
  "writable-dir",
  "log-link",
  "log-dir",
  "public-log",
  "hardlink",
  "fifo",
]) {
  test(`unsafe path/append failure (${failure}) preserves explicit deny and target bytes`, (t) => {
    const f = fixture(t);
    const dir = join(f.env.XDG_STATE_HOME, "allw");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const target = join(f.root, "target");
    writeFileSync(target, "unchanged", { mode: 0o600 });
    const log = join(dir, "codex-deny.log");
    if (failure === "relative-xdg") f.env.XDG_STATE_HOME = "relative-state";
    if (failure === "state-file" || failure === "state-link") {
      rmSync(dir, { recursive: true });
      if (failure === "state-file") writeFileSync(dir, "unchanged");
      else symlinkSync(f.home, dir);
    }
    if (failure === "parent-link") {
      rmSync(f.env.XDG_STATE_HOME, { recursive: true });
      symlinkSync(f.home, f.env.XDG_STATE_HOME);
    }
    if (failure === "writable-dir") chmodSync(dir, 0o777);
    if (failure === "log-link") symlinkSync(target, log);
    if (failure === "log-dir") mkdirSync(log);
    if (failure === "public-log") writeFileSync(log, "unchanged", { mode: 0o644 });
    if (failure === "hardlink") assert.equal(spawnSync("ln", [target, log]).status, 0);
    if (failure === "fifo") assert.equal(spawnSync("mkfifo", [log]).status, 0);
    const expected = cli(f);
    assert.equal(cli(f, f.env), expected);
    assert.equal(readFileSync(target, "utf8"), "unchanged");
    assert.equal(existsSync(join(f.cwd, "relative-state")), false);
    assert.deepEqual(readdirSync(join(f.cwd, ".codex")), []);
    if (failure === "public-log") assert.equal(readFileSync(log, "utf8"), "unchanged");
  });
}

/** An actual write error after opening a valid file must not escape the CLI or expose its text. */
test("append write failure preserves byte-identical stdout deny", (t) => {
  const f = fixture(t);
  const preload = join(f.root, "write-failure.mjs");
  writeFileSync(
    preload,
    `import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const originalWrite = fs.writeSync;
fs.writeSync = (fd, ...args) => {
  if (fd > 2) throw new Error("SECRET disk write failure");
  return originalWrite(fd, ...args);
};
syncBuiltinESMExports();
`,
  );
  assert.equal(cli(f, f.env, "not json", preload), cli(f));
  assert.equal(readFileSync(join(f.env.XDG_STATE_HOME, "allw", "codex-deny.log"), "utf8"), "");
});

/** The ownership check is about the effective user, not the environment's claimed home. */
test("foreign-owned state is skipped without writing", async (t) => {
  if (process.platform === "win32" || process.geteuid === undefined) return;
  const f = fixture(t);
  const { appendDenyLog } = await logger();
  mkdirSync(f.env.XDG_STATE_HOME, { mode: 0o700 });
  const uid = process.geteuid();
  t.mock.method(process, "geteuid", () => uid + 1);
  appendDenyLog(f.env, await output(), () => NOW);
  assert.deepEqual(readdirSync(f.env.XDG_STATE_HOME), []);
});
