/**
 * Process-level regression test (#254): the real `allw-codex-hook` bin keeps waiting on the SDK's
 * **poll** path until the relay answers, then prints an explicit decision.
 *
 * Bug: the SDK `unref`'d its poll-sleep timer, so with no WebSocket nothing held Node's event loop
 * between polls and the hook (`void main()`) exited 0 with **empty stdout**. For Codex that is not
 * merely "no decision": empty stdout + exit 0 is how this hook says "allw does not block"
 * (`docs/codex-integration.md`), so a pending request read as an approval whenever the human took
 * longer than one poll interval.
 *
 * The relay double answers only after several default poll intervals (1000 ms). Fixed, the hook
 * waits and prints a `deny` for the relay's `expired`.
 *
 * @see ../../../docs/codex-integration.md (decision encoding: empty stdout + exit 0 = no block)
 * @see ../../../docs/contract.md §Invariants (fail-closed)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "@allw/hook";

import { startSlowRelay } from "./support/slow-relay.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
/** Several default SDK poll intervals (1000 ms), so the wait must survive multiple sleeps. */
const ANSWER_AFTER_MS = 2500;

/** Run the hook bin with `stdin`; resolves `{ code, stdout, stderr }` (killed after 20 s). */
function runCli(stdin, env, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI], {
      cwd,
      env: { PATH: process.env.PATH, ...env },
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
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.end(stdin);
  });
}

test("codex hook bin waits across poll intervals and prints a deny (never empty stdout)", async (t) => {
  const wasm = await loadWasm();
  const relay = await startSlowRelay({
    devicePubkey: wasm.x25519_public_key(Buffer.alloc(32, 11).toString("base64url")),
    answerAfterMs: ANSWER_AFTER_MS,
  });
  t.after(relay.close);
  // The hook appends deny lines to a log under its cwd; keep that out of the repo.
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const cwd = await mkdtemp(join(tmpdir(), "allw-codex-poll-"));
  t.after(() => rm(cwd, { recursive: true, force: true }));

  const result = await runCli(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "git push --force origin main" },
    }),
    {
      ALLW_RELAY_URL: relay.url,
      ALLW_ACCOUNT_ID: "acct_poll_keepalive",
      ALLW_APPROVER_ROOT_KEY: wasm.ed25519_public_key(Buffer.alloc(32, 7).toString("base64url")),
    },
    cwd,
  );

  assert.equal(result.code, 0, `stderr: ${result.stderr}`);
  assert.notEqual(
    result.stdout.trim(),
    "",
    "empty stdout would mean 'no objection' to Codex; the hook must print its deny",
  );
  const output = JSON.parse(result.stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /expired/);
  assert.ok(relay.polls() >= 2, `the hook kept polling (polls: ${String(relay.polls())})`);
});
