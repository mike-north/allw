/**
 * Deny-only decision output for allw's PreToolUse hook CLIs (`@allw/hook` and `@allw/codex-hook`).
 *
 * # Deny-only
 * A hook decision from allw can only ever **tighten** access (`docs/contract.md` §Invariants). So a
 * hook CLI has exactly two outcomes on the wire:
 *
 * - **No decision** (`null`): exit 0 with **empty stdout**. The host goes on to apply its own
 *   permission rules as if allw were not installed. Used for a non-gated tool, a pass-through, and a
 *   verified human approval. allw never emits `allow`: in Claude Code an `allow` skips the user's
 *   permission prompt, which would let an allw approval (or a widened matcher) grant access the
 *   user's own rules would have asked about.
 * - **Deny**: exit 0 with one line of host-specific deny JSON on stdout.
 *
 * The decision *format* (the deny JSON shape) stays with each host package; this module owns only how
 * a decision is written and the exit backstop below, so both CLIs share one implementation.
 *
 * # Exit backstop (#265)
 * Because empty stdout plus exit 0 now means "no objection", a process that exits *before* deciding
 * would be read as consent. That has happened: an unref'd SDK timer let the event loop drain mid-wait
 * and the hook exited 0 with no output (#254). {@link installDecisionBackstop} makes that outcome
 * impossible to confuse with an approval: if the process reaches `beforeExit` or `exit` without
 * {@link DecisionBackstop.finalize} having run, it writes the host's fail-closed deny and exits 0.
 * The same holds for `SIGTERM`, `SIGINT` and `SIGHUP` (another process, or the user, stopping the
 * hook while it waits for a human). Nothing in-process can answer `SIGKILL`, `process.abort()` or a
 * crash before the backstop is installed; the hook docs pair this module with Claude Code's
 * `"onFailure": "block"` for those.
 *
 * Writes use `fs.writeSync` on stdout's file descriptor, not `process.stdout.write`: stdout to a pipe
 * is asynchronous on macOS, and a write from an `exit` listener that has not flushed is lost. A
 * decision is written in full or not at all from the host's point of view: a truncated line would be
 * invalid JSON, which both hosts treat as a non-blocking error (the call goes ahead).
 *
 * @see ../../../../docs/contract.md §Invariants (a verdict only tightens; fail-closed)
 * @see ../../../../docs/claude-code-integration.md §Decision Mapping
 * @see https://code.claude.com/docs/en/hooks#exit-code-output
 * @see https://github.com/mike-north/allw/issues/247
 * @see https://github.com/mike-north/allw/issues/265
 */

import { writeSync } from "node:fs";

/** stdout's file descriptor. */
const STDOUT_FD = 1;

/** How long to wait before retrying a write that hit a full non-blocking pipe (`EAGAIN`). */
const EAGAIN_BACKOFF_MS = 1;

/** The signals the backstop answers with a deny: polite stop requests a process can handle. */
const BACKSTOP_SIGNALS = ["SIGTERM", "SIGINT", "SIGHUP"] as const;

/** The subset of `fs.writeSync` that {@link writeAllSync} needs (a seam for tests). */
export type WriteSyncFn = (
  fd: number,
  buffer: Uint8Array,
  offset: number,
  length: number,
) => number;

/** Block the thread for `ms` without spinning (synchronous code can't await a timer). */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Write every byte of `bytes` to `fd`, synchronously. `fs.writeSync` may write fewer bytes than asked
 * (a short write) or throw `EAGAIN` when `fd` is a non-blocking pipe whose buffer is full; this loops
 * until the whole buffer is out, backing off briefly on `EAGAIN`. Any other error is thrown.
 */
export function writeAllSync(fd: number, bytes: Uint8Array, write: WriteSyncFn = writeSync): void {
  let offset = 0;
  while (offset < bytes.length) {
    try {
      offset += write(fd, bytes, offset, bytes.length - offset);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EAGAIN") throw err;
      sleepSync(EAGAIN_BACKOFF_MS);
    }
  }
}

/**
 * Write a hook decision to stdout synchronously. `null` (no decision) writes nothing; a deny object
 * is written in full as one line of JSON.
 */
export function writeDecision(decision: object | null): void {
  if (decision === null) return;
  writeAllSync(STDOUT_FD, Buffer.from(`${JSON.stringify(decision)}\n`, "utf8"));
}

/** Finalizes the one decision a hook process makes. */
export interface DecisionBackstop<T extends object> {
  /**
   * Write the decision (`null` ⇒ nothing) and mark the process as decided, so the exit backstop
   * stays silent. Call it once, right before exiting.
   */
  finalize(decision: T | null): void;
}

/**
 * Install the exit backstop for a hook process and return the handle `main()` finalizes its decision
 * through.
 *
 * Install it only on the hook path (after any `--version`-style diagnostic exits), since every exit
 * after this call that has not been finalized prints a deny.
 *
 * @param backstopDeny builds the host's fail-closed deny output (called at most once).
 */
export function installDecisionBackstop<T extends object>(
  backstopDeny: () => T,
): DecisionBackstop<T> {
  let decided = false;
  /** The exit code once the backstop has spoken: 0 if its deny is on stdout, 1 if writing it failed. */
  let backstopExitCode = 0;

  /**
   * Write the backstop deny unless a decision is already out, and return the exit code the process
   * must end with. Exit 0 only when the deny was actually written: if stdout is gone, exit 0 would
   * leave empty stdout plus exit 0, which the host reads as "no objection". Exit 1 instead, a hook
   * failure that `"onFailure": "block"` turns into a blocked call.
   */
  const emitBackstopDeny = (): number => {
    if (decided) return backstopExitCode;
    decided = true;
    try {
      writeDecision(backstopDeny());
    } catch {
      backstopExitCode = 1;
    }
    return backstopExitCode;
  };

  // The event loop drained while `main()` was still waiting (a promise that will never settle and
  // holds no refs). Deny, then exit explicitly so the process does not linger.
  process.once("beforeExit", () => {
    if (decided) return;
    process.exit(emitBackstopDeny());
  });

  // Any other exit that skipped `finalize` (an explicit `process.exit` elsewhere, an uncaught
  // exception). Only synchronous work is possible here. Exit 0 so the host reads the deny JSON as a
  // decision rather than a hook error, or 1 if the deny could not be written.
  process.once("exit", () => {
    if (decided) return;
    process.exitCode = emitBackstopDeny();
  });

  // A polite stop while the hook waits (another process's `kill`, Ctrl-C, a closed terminal). Without
  // a handler Node dies by the signal with empty stdout, which the host reads as a hook error and
  // lets the call go ahead. Deny once, then exit 0 so the host reads the deny as the decision (1 if
  // the deny could not be written). If the decision was already finalized, it is on stdout: exit 0.
  for (const signal of BACKSTOP_SIGNALS) {
    process.once(signal, () => {
      process.exit(emitBackstopDeny());
    });
  }

  return {
    finalize(decision: T | null): void {
      writeDecision(decision);
      decided = true;
    },
  };
}
