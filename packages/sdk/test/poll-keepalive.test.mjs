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
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const fixture = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "poll-only-wait.mjs");

/**
 * Run the fixture in `mode` as a subprocess; resolves `{ code, signal, stdout, stderr, ms }`. The
 * hard `timeout` makes a regression that never exits fail fast instead of wedging the test run.
 */
function runFixture(mode) {
  return new Promise((resolve) => {
    const startedAt = performance.now();
    execFile(
      process.execPath,
      [fixture, mode],
      { timeout: 15_000, killSignal: "SIGKILL" },
      (error, stdout, stderr) => {
        resolve({
          code: error ? error.code : 0,
          signal: error ? error.signal : null,
          stdout,
          stderr,
          ms: performance.now() - startedAt,
        });
      },
    );
  });
}

test("poll-path wait keeps the process alive until the deadline, then resolves expired", async () => {
  const result = await runFixture("never");
  assert.equal(result.signal, null, "the fixture exited on its own (not killed by the timeout)");
  assert.equal(result.code, 0, `the process waited and exited cleanly (stderr: ${result.stderr})`);
  assert.match(result.stdout, /^decision: expired$/m);
});

test("an outcome before the deadline still lets the process exit promptly", async () => {
  const result = await runFixture("early");
  assert.equal(result.code, 0, `stderr: ${result.stderr}`);
  assert.match(result.stdout, /^decision: expired$/m);
  // Terminal settlement clears the referenced 60 s backstop, allowing an immediate exit.
  assert.ok(result.ms < 10_000, `exited promptly (took ${String(Math.round(result.ms))} ms)`);
});

test("a poll interval longer than the deadline does not hold the process past it", async () => {
  const result = await runFixture("long-interval");
  assert.equal(result.code, 0, `stderr: ${result.stderr}`);
  assert.match(result.stdout, /^decision: expired$/m);
  // The 5 s poll sleep is clamped to the 400 ms deadline and the loop stops once the race settles,
  // so the process exits well before a full poll interval would have elapsed.
  assert.ok(result.ms < 3_000, `exited promptly (took ${String(Math.round(result.ms))} ms)`);
});

/**
 * Pending promise work is not a Node event-loop handle. A valid delivered verdict can therefore
 * leave the caller without a poll sleep or network I/O while its nonce store is still pending.
 * The real deadline must keep both script and hook callers alive to receive fail-closed expiry.
 * @see ../../../docs/contract.md §Transport → Fail-closed expiry
 */
for (const mode of ["pending-verification", "pending-verification-void"]) {
  test(`poll-path ${mode} keeps Node alive until expired`, async () => {
    const result = await runFixture(mode);
    assert.equal(result.signal, null, "the deadline, not the test harness, ends the wait");
    assert.equal(result.code, 0, `stderr: ${result.stderr}`);
    assert.match(
      result.stdout,
      /^nonce: pending$/m,
      "real WASM verification reached the nonce store",
    );
    assert.match(
      result.stdout,
      /^decision: expired$/m,
      "the caller receives expiry even while async verification owns no active handle",
    );
  });
}
