/**
 * Regression test (#254): a caller waiting on the **poll** path stays alive until its verdict or the
 * fail-closed deadline.
 *
 * Bug: every SDK wait timer (deadline backstop and poll sleep) was `unref`'d, so when no WebSocket
 * was available nothing held Node's event loop between polls. The process exited mid-wait, with no
 * verdict at all: code 13 for a script using top-level await, and code 0 with no output for the hook
 * CLIs (`void main()`), which Claude Code reads as "no decision". Found while making a plain script
 * gate a command. The fixture runs as a real subprocess, since only a real process
 * exit shows the bug.
 *
 * @see ../../../docs/contract.md §Invariants (fail-closed: timeout ⇒ a non-approving verdict)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const fixture = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "poll-only-wait.mjs");

test("poll-path wait keeps the process alive until the deadline, then resolves expired", async () => {
  const result = await new Promise((resolve) => {
    execFile(process.execPath, [fixture], (error, stdout, stderr) => {
      resolve({ code: error ? error.code : 0, stdout, stderr });
    });
  });
  assert.equal(result.code, 0, `the process waited and exited cleanly (stderr: ${result.stderr})`);
  assert.match(result.stdout, /^decision: expired$/m);
});
