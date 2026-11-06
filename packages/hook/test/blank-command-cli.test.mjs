/**
 * UAT for #371/#372: a shell command with no program is denied without asking, and a blank `cwd`
 * means "unknown".
 *
 * Both hooks build a command request through `@allw/sdk`'s `commandRequest`, which refuses a blank
 * or whitespace-only command. Nonblank text is opaque and reaches the human unchanged. The Codex hook's mirror of this file drives the same corpus and expects
 * the same reason (`../../codex-hook/test/blank-command-cli.test.mjs`).
 *
 * Each case drives the real `allw-hook` bin as a subprocess against a loopback relay double, so
 * "denied without asking" is checked as zero submits reaching the relay.
 *
 * @see https://github.com/mike-north/allw/issues/372
 * @see ../../sdk/src/command-request.ts (commandActionFromLine: the refusals and their messages)
 */

import { after, test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "../dist/lib/wasm.js";
import { startApprovingRelay } from "./support/approving-relay.mjs";

/** Isolate persisted sequence floors from the developer's ~/.allw. */
const CHILD_HOME = mkdtempSync(join(tmpdir(), "allw-hook-child-home-"));
after(() => rmSync(CHILD_HOME, { recursive: true, force: true }));

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

/** The deny-reason prefix for a command whose request could not be built. */
const PREFIX = "allw: could not build an ActionRecord for the command (fail-closed deny): ";

/**
 * The shared corpus (the Codex hook's mirror uses the same one): each command and the SDK's
 * refusal, as `commandActionFromLine` words it.
 */
const EMPTY_COMMAND_CORPUS = [
  ["a blank command", "", "commandLine contains no command"],
  ["a whitespace-only command", "   ", "commandLine contains no command"],
  ["a tabs-and-newlines command", "\t\n\t", "commandLine contains no command"],
  ["a carriage-return-only command", "\r", "commandLine contains no command"],
];

/** Run the hook bin with `stdin` and a clean env; resolves `{ code, stdout, stderr }`. */
function runCli(stdin, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI], {
      env: { PATH: process.env.PATH, HOME: CHILD_HOME, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("allw-hook did not exit within 20000ms"));
    }, 20_000);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.end(stdin);
  });
}

/** Run a Bash call against a relay double answering `denied`; resolve the reason and the relay. */
async function runBash(t, command, cwd) {
  const wasm = await loadWasm();
  const relay = await startApprovingRelay({ wasm, decision: "denied" });
  t.after(relay.close);
  const stdin = JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command },
    ...(cwd !== undefined ? { cwd } : {}),
  });
  const { code, stdout, stderr } = await runCli(stdin, {
    ALLW_RELAY_URL: relay.url,
    ALLW_ACCOUNT_ID: relay.accountId,
    ALLW_APPROVER_ROOT_KEY: relay.accountRootPub,
  });
  assert.equal(code, 0, `stderr: ${stderr}`);
  const output = JSON.parse(stdout).hookSpecificOutput;
  assert.equal(output.permissionDecision, "deny");
  return { reason: output.permissionDecisionReason, relay };
}

for (const [label, command, refusal] of EMPTY_COMMAND_CORPUS) {
  test(`(#372) ${label} is denied without asking`, async (t) => {
    const { reason, relay } = await runBash(t, command, "/workspace/project");
    assert.equal(reason, `${PREFIX}${refusal}`);
    assert.equal(relay.seen.submits, 0, "no request reached the relay");
  });
}

test("(#371) a blank cwd is unknown: the human is asked, with a record bound to no directory", async (t) => {
  const { reason, relay } = await runBash(t, "rm -rf build", "  ");
  assert.match(reason, / — not approved \(verdict: denied\)$/u);
  assert.equal(relay.seen.submits, 1, "the call reached the relay and a human said no");
  assert.equal("cwd" in relay.seen.contexts[0].action.facts, false);
});

/** @see docs/action-record.md — nonblank shell-looking text always reaches a human. */
for (const command of [
  "# comment",
  "FOO=1",
  "&& ;",
  "'' rm -rf x",
  "'unmatched",
  "echo $(id) # hi\nnext",
]) {
  test(`opaque command reaches the approver: ${JSON.stringify(command)}`, async (t) => {
    const { reason, relay } = await runBash(t, command, "/workspace/project");
    assert.match(reason, /not approved/);
    assert.equal(relay.seen.submits, 1);
    assert.deepEqual(relay.seen.contexts[0].action.facts, {
      raw: command,
      cwd: "/workspace/project",
    });
  });
}
