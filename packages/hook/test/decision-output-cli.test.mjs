/**
 * UAT: the real `allw-hook` bin, driven as a subprocess exactly as Claude Code runs it (JSON on stdin,
 * exit code + stdout read back), emits **no decision** for a verified approval and a `deny` for
 * everything else (#247), and never exits silently before deciding (#265).
 *
 * - A verified approval must leave stdout **empty** (exit 0). An `allow` would skip Claude Code's own
 *   permission prompt, so an allw approval would grant access instead of only removing allw's
 *   objection (`docs/contract.md` §Invariants: a verdict only tightens).
 * - Because empty stdout now means "no objection", a process that reaches exit before deciding must
 *   print a `deny`, not nothing. The backstop case preloads a `fetch` that never settles and holds no
 *   refs, so the event loop drains mid-wait (the #254 failure shape).
 * - The same holds for every other way the wait can end early that the process can still see: a
 *   `SIGTERM`/`SIGINT`/`SIGHUP`, an uncaught async throw, and a stray `process.exit(1)`. Each must
 *   end in exit 0 and **exactly one** deny (the whole of stdout is parsed as one JSON value, so a
 *   double write fails).
 *
 * @see https://code.claude.com/docs/en/hooks#exit-code-output (exit 0 + no JSON = no decision)
 * @see https://code.claude.com/docs/en/hooks#pretooluse-decision-control (the deny JSON)
 * @see https://github.com/mike-north/allw/issues/247
 * @see https://github.com/mike-north/allw/issues/265
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { closeSync, mkdtempSync, openSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "../dist/lib/wasm.js";
import { startApprovingRelay } from "./support/approving-relay.mjs";
import { FETCH_PENDING_MARKER } from "./support/stalled-fetch.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
const NEVER_SETTLING_FETCH = join(here, "support", "never-settling-fetch.mjs");
const STALLED_FETCH = join(here, "support", "stalled-fetch.mjs");

/**
 * Run the hook bin (optionally with node flags first); resolves `{ code, signal, stdout, stderr }`.
 * With `signalOnPending`, that signal is sent once the bin reports it is waiting on the relay. With
 * `stdoutFd`, the child's stdout is that file descriptor instead of a pipe (`stdout` is then "").
 */
function runCli(stdin, env, nodeArgs = [], { signalOnPending, stdoutFd } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...nodeArgs, CLI], {
      env: { PATH: process.env.PATH, ...env },
      stdio: ["pipe", stdoutFd ?? "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("allw-hook did not exit within 20000ms"));
    }, 20_000);
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => (stdout += d));
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

/** A gated Bash call, as Claude Code sends it. */
const BASH_STDIN = JSON.stringify({
  hook_event_name: "PreToolUse",
  cwd: "/workspace/project",
  tool_name: "Bash",
  tool_input: { command: "git push origin main" },
});

test("a verified approval exits 0 with EMPTY stdout — no decision, never allow (#247)", async (t) => {
  const wasm = await loadWasm();
  const relay = await startApprovingRelay({ wasm, decision: "approved" });
  t.after(relay.close);

  const { code, stdout, stderr } = await runCli(BASH_STDIN, {
    ALLW_RELAY_URL: relay.url,
    ALLW_ACCOUNT_ID: relay.accountId,
    ALLW_APPROVER_ROOT_KEY: relay.accountRootPub,
  });

  assert.equal(code, 0, `stderr: ${stderr}`);
  assert.equal(stdout, "", "approval removes allw's objection; Claude Code's own rules decide");
  // The empty stdout is the approval, not a silent no-op: the request reached the relay and the hook
  // fetched (and verified) the signed verdict.
  assert.equal(relay.seen.submits, 1, "the hook submitted the request to the relay");
  assert.ok(relay.seen.verdictFetches >= 1, "the hook fetched the verdict");
});

test("a verified denial exits 0 with a deny decision JSON", async (t) => {
  const wasm = await loadWasm();
  const relay = await startApprovingRelay({ wasm, decision: "denied" });
  t.after(relay.close);

  const { code, stdout, stderr } = await runCli(BASH_STDIN, {
    ALLW_RELAY_URL: relay.url,
    ALLW_ACCOUNT_ID: relay.accountId,
    ALLW_APPROVER_ROOT_KEY: relay.accountRootPub,
  });

  assert.equal(code, 0, `stderr: ${stderr}`);
  const output = JSON.parse(stdout);
  assert.equal(output.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
});

test("backstop: an SDK wait that never settles (no refs) prints deny, not empty stdout (#265)", async () => {
  const wasm = await loadWasm();
  const { code, stdout, stderr } = await runCli(
    BASH_STDIN,
    {
      ALLW_RELAY_URL: "http://127.0.0.1:9",
      ALLW_ACCOUNT_ID: "acct_backstop",
      ALLW_APPROVER_ROOT_KEY: wasm.ed25519_public_key(Buffer.alloc(32, 7).toString("base64url")),
    },
    ["--import", NEVER_SETTLING_FETCH],
  );

  assert.equal(code, 0, `stderr: ${stderr}`);
  assert.notEqual(stdout, "", "a premature exit must never read as consent");
  const output = JSON.parse(stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(
    output.hookSpecificOutput.permissionDecisionReason,
    /exited before reaching a decision/,
    "the deny comes from the exit backstop",
  );
});

/** Env for a gated call against a relay that is never reached (the preload intercepts `fetch`). */
async function stalledEnv(extra = {}) {
  const wasm = await loadWasm();
  return {
    ALLW_RELAY_URL: "http://127.0.0.1:9",
    ALLW_ACCOUNT_ID: "acct_backstop",
    ALLW_APPROVER_ROOT_KEY: wasm.ed25519_public_key(Buffer.alloc(32, 7).toString("base64url")),
    ...extra,
  };
}

/** Exit 0, and the whole of stdout is exactly one backstop deny. */
function assertSingleBackstopDeny({ code, signal, stdout, stderr }) {
  assert.equal(signal, null, `the hook must not die by a signal; stderr: ${stderr}`);
  assert.equal(code, 0, `stderr: ${stderr}`);
  // JSON.parse of the whole of stdout fails on a second line, so this also proves one write.
  const output = JSON.parse(stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(
    output.hookSpecificOutput.permissionDecisionReason,
    /exited before reaching a decision/,
  );
}

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  test(`backstop: ${signal} while waiting for a human prints one deny and exits 0 (#265)`, async () => {
    const result = await runCli(BASH_STDIN, await stalledEnv(), ["--import", STALLED_FETCH], {
      signalOnPending: signal,
    });
    assertSingleBackstopDeny(result);
  });
}

test("backstop: an uncaught async throw while waiting prints one deny and exits 0 (#265)", async () => {
  const result = await runCli(BASH_STDIN, await stalledEnv({ ALLW_TEST_AFTER_FETCH: "throw" }), [
    "--import",
    STALLED_FETCH,
  ]);
  assertSingleBackstopDeny(result);
});

test("backstop: a stray process.exit(1) while waiting prints one deny and exits 0 (#265)", async () => {
  const result = await runCli(BASH_STDIN, await stalledEnv({ ALLW_TEST_AFTER_FETCH: "exit1" }), [
    "--import",
    STALLED_FETCH,
  ]);
  assertSingleBackstopDeny(result);
});

/**
 * A stdout the hook can't write to: a file opened read-only, so every write fails with `EBADF`. The
 * descriptor is closed and the file removed when the test ends.
 */
function unwritableStdout(t) {
  const dir = mkdtempSync(join(tmpdir(), "allw-unwritable-stdout-"));
  const file = join(dir, "stdout");
  writeFileSync(file, "");
  const fd = openSync(file, "r");
  t.after(() => {
    closeSync(fd);
    rmSync(dir, { recursive: true, force: true });
  });
  return fd;
}

// Regression (Copilot review on #294): when the backstop deny itself can't be written, the hook must
// not exit 0. Empty stdout plus exit 0 is "no objection"; a non-zero exit is a hook failure, which
// `"onFailure": "block"` turns into a blocked call.
for (const [label, extraEnv, nodeArgs, opts] of [
  ["the event loop drains", {}, ["--import", NEVER_SETTLING_FETCH], {}],
  ["a stray process.exit(1)", { ALLW_TEST_AFTER_FETCH: "exit1" }, ["--import", STALLED_FETCH], {}],
  ["SIGTERM arrives", {}, ["--import", STALLED_FETCH], { signalOnPending: "SIGTERM" }],
]) {
  test(`backstop: if the deny can't be written when ${label}, the hook exits non-zero, never 0`, async (t) => {
    const { code, signal, stderr } = await runCli(
      BASH_STDIN,
      await stalledEnv(extraEnv),
      nodeArgs,
      {
        ...opts,
        stdoutFd: unwritableStdout(t),
      },
    );
    assert.equal(signal, null, `stderr: ${stderr}`);
    assert.notEqual(code, 0, "an unwritten deny must read as a hook failure, not as no objection");
  });
}
