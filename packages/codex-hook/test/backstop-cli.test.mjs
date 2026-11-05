/**
 * UAT: the real `allw-codex-hook` bin never exits silently before deciding (#265).
 *
 * Codex reads exit 0 with empty stdout as "no objection" (the encoding allw uses for an approval,
 * #191). So if the event loop drains while the hook is still waiting for a human (the #254 failure
 * shape), the process must print a schema-conformant `deny`, not nothing. A preloaded `fetch` that
 * never settles and holds no refs makes the gate's SDK wait exactly that; the bin itself is the real,
 * unmodified `dist/cli.js`.
 *
 * The other early ends the process can still see get the same treatment: `SIGTERM`/`SIGINT`/`SIGHUP`
 * while waiting, an uncaught async throw, and a stray `process.exit(1)`. Each must end in exit 0 and
 * **exactly one** deny (the whole of stdout is parsed as one JSON value, so a double write fails).
 *
 * @see https://learn.chatgpt.com/docs/hooks (PreToolUse: exit 0 + no output = success)
 * @see ../../../docs/codex-integration.md §Decision Mapping
 * @see https://github.com/mike-north/allw/issues/265
 */

import { after, test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "@allw/hook";

import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";
import { FETCH_PENDING_MARKER } from "./support/stalled-fetch.mjs";
import { PARTIAL_BYTES } from "./support/partial-write-fault.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
const NEVER_SETTLING_FETCH = join(here, "support", "never-settling-fetch.mjs");
const STALLED_FETCH = join(here, "support", "stalled-fetch.mjs");
const PARTIAL_WRITE_FAULT = join(here, "support", "partial-write-fault.mjs");
const BACKSTOP_REASON =
  "allw[premature-exit]: Codex hook exited before reaching a decision (fail-closed deny)";

/**
 * A valid account root key and its derived (self-certifying) account id, so the config loader
 * accepts the env and the run reaches the relay wait under test.
 */
function backstopCoordinates(wasm) {
  const root = wasm.ed25519_public_key(Buffer.alloc(32, 7).toString("base64url"));
  return { ALLW_ACCOUNT_ID: wasm.account_id_for_root(root), ALLW_APPROVER_ROOT_KEY: root };
}

/** A throwaway HOME for the child, so its sequence floor never lands in a real ~/.allw. */
const CHILD_HOME = mkdtempSync(join(tmpdir(), "allw-codex-cli-home-"));
after(() => rmSync(CHILD_HOME, { recursive: true, force: true }));

/**
 * Run the hook bin with node flags + `stdin`; resolves `{ code, signal, stdout, stderr }`. With
 * `signalOnPending`, that signal is sent once the bin reports it is waiting on the relay.
 */
function runCli(stdin, env, cwd, nodeArgs, { signalOnPending } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...nodeArgs, CLI], {
      cwd,
      env: { PATH: process.env.PATH, HOME: CHILD_HOME, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("allw-codex-hook did not exit within 20000ms"));
    }, 20_000);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    let signalled = false;
    child.stderr.on("data", (d) => {
      stderr += d;
      if (signalOnPending !== undefined && !signalled && stderr.includes(FETCH_PENDING_MARKER)) {
        signalled = true;
        child.kill(signalOnPending);
      }
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr });
    });
    child.stdin.end(stdin);
  });
}

test("backstop: an SDK wait that never settles (no refs) prints deny, not empty stdout (#265)", async (t) => {
  const cwd = mkdtempSync(join(tmpdir(), "allw-codex-backstop-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const wasm = await loadWasm();

  const { code, stdout, stderr } = await runCli(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      cwd,
      tool_name: "Bash",
      tool_input: { command: "git push origin main" },
    }),
    {
      ALLW_RELAY_URL: "http://127.0.0.1:9",
      ...backstopCoordinates(wasm),
    },
    cwd,
    ["--import", NEVER_SETTLING_FETCH],
  );

  assert.equal(code, 0, `stderr: ${stderr}`);
  assert.notEqual(stdout, "", "a premature exit must never read as consent");
  const output = JSON.parse(stdout);
  assertConformsToPreToolUseOutputContract(output);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(output.hookSpecificOutput.permissionDecisionReason, BACKSTOP_REASON);
});

/** Run a gated Bash call with the stalled-fetch preload; resolves the `runCli` result. */
async function runStalled(t, extraEnv, opts) {
  const cwd = mkdtempSync(join(tmpdir(), "allw-codex-backstop-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const wasm = await loadWasm();
  return runCli(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      cwd,
      tool_name: "Bash",
      tool_input: { command: "git push origin main" },
    }),
    {
      ALLW_RELAY_URL: "http://127.0.0.1:9",
      ...backstopCoordinates(wasm),
      ...extraEnv,
    },
    cwd,
    ["--import", STALLED_FETCH],
    opts,
  );
}

/** Exit 0, and the whole of stdout is exactly one schema-conformant backstop deny. */
function assertSingleBackstopDeny({ code, signal, stdout, stderr }) {
  assert.equal(signal, null, `the hook must not die by a signal; stderr: ${stderr}`);
  assert.equal(code, 0, `stderr: ${stderr}`);
  // JSON.parse of the whole of stdout fails on a second line, so this also proves one write.
  const output = JSON.parse(stdout);
  assertConformsToPreToolUseOutputContract(output);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(output.hookSpecificOutput.permissionDecisionReason, BACKSTOP_REASON);
}

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  test(`backstop: ${signal} while waiting for a human prints one deny and exits 0 (#265)`, async (t) => {
    assertSingleBackstopDeny(await runStalled(t, {}, { signalOnPending: signal }));
  });
}

test("backstop: an uncaught async throw while waiting prints one deny and exits 0 (#265)", async (t) => {
  assertSingleBackstopDeny(await runStalled(t, { ALLW_TEST_AFTER_FETCH: "throw" }));
});

test("backstop: a stray process.exit(1) while waiting prints one deny and exits 0 (#265)", async (t) => {
  assertSingleBackstopDeny(await runStalled(t, { ALLW_TEST_AFTER_FETCH: "exit1" }));
});

// Regression (#294 review R2-N2): a deny write that fails part-way must be final. Before the fix,
// the exit backstop appended a second, full deny after the partial one: invalid JSON on exit 0,
// which Codex reads as a non-blocking error. Now the hook exits 1 with only the partial bytes.
test("finalize: a decision write that fails part-way exits 1 and never appends a second deny", async (t) => {
  const cwd = mkdtempSync(join(tmpdir(), "allw-codex-partial-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  // No config file in this HOME and no ALLW_* env: the hook's own decision is a config deny.
  const { code, signal, stdout, stderr } = await runCli(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      cwd,
      tool_name: "Bash",
      tool_input: { command: "git push origin main" },
    }),
    { HOME: cwd },
    cwd,
    ["--import", PARTIAL_WRITE_FAULT],
  );
  assert.equal(signal, null, `stderr: ${stderr}`);
  assert.equal(code, 1, "a failed decision write is a hook failure, not a decision");
  assert.equal(stdout.length, PARTIAL_BYTES, `only the partial write reached stdout: ${stdout}`);
  assert.doesNotMatch(stdout, /exited before reaching a decision/, "no backstop deny was appended");
});
