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
 *
 * @see https://code.claude.com/docs/en/hooks#exit-code-output (exit 0 + no JSON = no decision)
 * @see https://code.claude.com/docs/en/hooks#pretooluse-decision-control (the deny JSON)
 * @see https://github.com/mike-north/allw/issues/247
 * @see https://github.com/mike-north/allw/issues/265
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "../dist/lib/wasm.js";
import { startApprovingRelay } from "./support/approving-relay.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
const NEVER_SETTLING_FETCH = join(here, "support", "never-settling-fetch.mjs");

/** Run the hook bin (optionally with node flags first); resolves `{ code, stdout, stderr }`. */
function runCli(stdin, env, nodeArgs = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...nodeArgs, CLI], {
      env: { PATH: process.env.PATH, ...env },
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
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
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
