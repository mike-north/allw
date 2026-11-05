/**
 * UAT for #372: the Codex hook denies a shell command with no program without asking, exactly like
 * the Claude Code hook, and treats a blank `cwd` as "unknown".
 *
 * Both hooks build a command request through `@allw/sdk`'s `commandRequest`, which refuses a blank
 * or whitespace-only command, and a command whose program is an empty word (`''`): there is no
 * program to show the human. This drives the same corpus as the Claude Code hook's mirror
 * (`../../hook/test/blank-command-cli.test.mjs`) and expects the same reason, under Codex's
 * `allw[build-error]: ` category prefix.
 *
 * Each case drives the real `allw-codex-hook` bin as a subprocess against the Claude Code hook's
 * loopback relay double, so "denied without asking" is checked as zero submits reaching the relay.
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

import { loadWasm } from "@allw/hook";
import { startApprovingRelay } from "../../hook/test/support/approving-relay.mjs";
import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";

/** Isolate persisted sequence floors from the developer's ~/.allw. */
const CHILD_HOME = mkdtempSync(join(tmpdir(), "allw-hook-child-home-"));
after(() => rmSync(CHILD_HOME, { recursive: true, force: true }));

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

/** The deny-reason prefix for a command whose request could not be built (Codex category form). */
const PREFIX =
  "allw[build-error]: could not build an ActionRecord for the command (fail-closed deny): ";

/**
 * The shared corpus (the Claude Code hook's mirror uses the same one): each command and the SDK's
 * refusal, as `commandActionFromLine` words it.
 */
const NO_PROGRAM_CORPUS = [
  ["a blank command", "", "commandLine contains no command"],
  ["a whitespace-only command", "   ", "commandLine contains no command"],
  ["a tabs-and-newlines command", "\t\n\t", "commandLine contains no command"],
  [
    "a command whose program is an empty word",
    "'' rm -rf x",
    "commandLine's first word (the program) must be non-empty",
  ],
  // #376: the core refuses these itself, so every surface inherits the refusal.
  [
    "a command that is only an env assignment",
    "FOO=1",
    "commandLine runs no program (only variable assignments or shell operators)",
  ],
  [
    "a command that is only operators",
    "&& ;",
    "commandLine runs no program (only variable assignments or shell operators)",
  ],
  ["a carriage-return-only command", "\r", "commandLine contains no command"],
];

/**
 * Run the Codex hook bin with `stdin` and a clean env, in a temp cwd (the bin appends its deny log
 * under the cwd); resolves `{ code, stdout, stderr }`.
 */
function runCli(t, stdin, env) {
  const cwd = mkdtempSync(join(tmpdir(), "allw-codex-372-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI], {
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
    session_id: "sess-codex",
    turn_id: "turn-codex",
    tool_use_id: "tool-codex",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command },
    ...(cwd !== undefined ? { cwd } : {}),
  });
  const { code, stdout, stderr } = await runCli(t, stdin, {
    ALLW_RELAY_URL: relay.url,
    ALLW_ACCOUNT_ID: relay.accountId,
    ALLW_APPROVER_ROOT_KEY: relay.accountRootPub,
  });
  assert.equal(code, 0, `stderr: ${stderr}`);
  const output = JSON.parse(stdout);
  assertConformsToPreToolUseOutputContract(output);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  return { reason: output.hookSpecificOutput.permissionDecisionReason, relay };
}

for (const [label, command, refusal] of NO_PROGRAM_CORPUS) {
  test(`(#372) ${label} is denied without asking, as in the Claude Code hook`, async (t) => {
    const { reason, relay } = await runBash(t, command, "/workspace/project");
    assert.equal(reason, `${PREFIX}${refusal}`);
    assert.equal(relay.seen.submits, 0, "no request reached the relay");
  });
}

test("(#372) a blank cwd is unknown: the human is asked, with a record bound to no directory", async (t) => {
  const { reason, relay } = await runBash(t, "rm -rf build", "  ");
  assert.match(reason, /^allw\[no-approval\]: .* — not approved \(verdict: denied\)$/u);
  assert.equal(relay.seen.submits, 1, "the call reached the relay and a human said no");
  assert.equal("cwd" in relay.seen.contexts[0].action.syntactic, false);
});
