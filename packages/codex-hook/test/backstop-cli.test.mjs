/**
 * UAT: the real `allw-codex-hook` bin never exits silently before deciding (#265).
 *
 * Codex reads exit 0 with empty stdout as "no objection" (the encoding allw uses for an approval,
 * #191). So if the event loop drains while the hook is still waiting for a human (the #254 failure
 * shape), the process must print a schema-conformant `deny`, not nothing. A preloaded `fetch` that
 * never settles and holds no refs makes the gate's SDK wait exactly that; the bin itself is the real,
 * unmodified `dist/cli.js`.
 *
 * @see https://learn.chatgpt.com/docs/hooks (PreToolUse: exit 0 + no output = success)
 * @see ../../../docs/codex-integration.md §Decision Mapping
 * @see https://github.com/mike-north/allw/issues/265
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "@allw/hook";

import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
const NEVER_SETTLING_FETCH = join(here, "support", "never-settling-fetch.mjs");

/** Run the hook bin with node flags + `stdin`; resolves `{ code, stdout, stderr }`. */
function runCli(stdin, env, cwd, nodeArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...nodeArgs, CLI], {
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
      ALLW_ACCOUNT_ID: "acct_backstop",
      ALLW_APPROVER_ROOT_KEY: wasm.ed25519_public_key(Buffer.alloc(32, 7).toString("base64url")),
    },
    cwd,
    ["--import", NEVER_SETTLING_FETCH],
  );

  assert.equal(code, 0, `stderr: ${stderr}`);
  assert.notEqual(stdout, "", "a premature exit must never read as consent");
  const output = JSON.parse(stdout);
  assertConformsToPreToolUseOutputContract(output);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(
    output.hookSpecificOutput.permissionDecisionReason,
    "allw[premature-exit]: Codex hook exited before reaching a decision (fail-closed deny)",
  );
});
