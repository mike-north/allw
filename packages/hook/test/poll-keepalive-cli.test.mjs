/**
 * Process-level regression test (#254): the real `allw-hook` bin keeps waiting on the SDK's **poll**
 * path until the relay answers, then prints an explicit decision.
 *
 * Bug: the SDK `unref`'d its poll-sleep timer, so with no WebSocket (the relay or a proxy refusing
 * the `…/wait` upgrade) nothing held Node's event loop between polls. The hook (`void main()`)
 * then exited 0 with **no decision JSON**, and Claude Code fell back to its own permission flow,
 * so the allw gate was bypassed whenever the human took longer than one poll interval.
 *
 * The relay double answers only after several default poll intervals (1000 ms), so a pre-fix SDK
 * exits after the first poll. Fixed, the hook waits and prints a `deny` for the relay's `expired`.
 *
 * @see https://code.claude.com/docs/en/hooks (PreToolUse: exit 0 with JSON decision)
 * @see ../../../docs/contract.md §Invariants (fail-closed)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "../dist/lib/wasm.js";
import { startSlowRelay } from "./support/slow-relay.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
/** Several default SDK poll intervals (1000 ms), so the wait must survive multiple sleeps. */
const ANSWER_AFTER_MS = 2500;

/** Run the hook bin with `stdin`; resolves `{ code, stdout, stderr }` (killed after 20 s). */
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
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.end(stdin);
  });
}

/** One root-signed account state (root seed 7) vouching for the relay's one device (X25519 seed 11). */
function slowAccountState(wasm) {
  const accountSeed = Buffer.alloc(32, 7).toString("base64url");
  const accountRootPub = wasm.ed25519_public_key(accountSeed);
  return wasm.sign_account_state(
    JSON.stringify({
      v: 1,
      account_id: wasm.account_id_for_root(accountRootPub),
      sequence: 1,
      current_root: accountRootPub,
      previous_roots: [],
      devices: [
        {
          device_id: "dev_slow",
          encryption_pubkey: wasm.x25519_public_key(Buffer.alloc(32, 11).toString("base64url")),
          signing_pubkey: wasm.ed25519_public_key(Buffer.alloc(32, 9).toString("base64url")),
          status: "active",
        },
      ],
      actors: [],
      revocations: [],
    }),
    accountSeed,
  );
}

/** A throwaway HOME for the child, so its sequence floor never lands in a real ~/.allw. */
const CHILD_HOME = mkdtempSync(join(tmpdir(), "allw-poll-keepalive-home-"));

test("hook bin waits across poll intervals and prints a decision (never exits silently)", async (t) => {
  const wasm = await loadWasm();
  const relay = await startSlowRelay({
    accountStates: [slowAccountState(wasm)],
    answerAfterMs: ANSWER_AFTER_MS,
  });
  t.after(relay.close);

  const result = await runCli(
    JSON.stringify({
      hook_event_name: "PreToolUse",
      cwd: process.cwd(),
      tool_name: "Bash",
      tool_input: { command: "git push --force origin main" },
    }),
    {
      ALLW_RELAY_URL: relay.url,
      // Self-certifying account id: derived from the root key by the core (docs/enrollment.md).
      ALLW_ACCOUNT_ID: wasm.account_id_for_root(
        wasm.ed25519_public_key(Buffer.alloc(32, 7).toString("base64url")),
      ),
      ALLW_APPROVER_ROOT_KEY: wasm.ed25519_public_key(Buffer.alloc(32, 7).toString("base64url")),
    },
  );

  assert.equal(result.code, 0, `stderr: ${result.stderr}`);
  assert.notEqual(
    result.stdout.trim(),
    "",
    "the hook printed a decision instead of exiting silently",
  );
  const output = JSON.parse(result.stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /expired/);
  assert.ok(relay.polls() >= 2, `the hook kept polling (polls: ${String(relay.polls())})`);
});
