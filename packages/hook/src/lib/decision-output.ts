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
 *
 * Writes use `fs.writeSync` on stdout's file descriptor, not `process.stdout.write`: stdout to a pipe
 * is asynchronous on macOS, and a write from an `exit` listener that has not flushed is lost.
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

/**
 * Write a hook decision to stdout synchronously. `null` (no decision) writes nothing; a deny object
 * is written as one line of JSON.
 */
export function writeDecision(decision: object | null): void {
  if (decision === null) return;
  writeSync(STDOUT_FD, `${JSON.stringify(decision)}\n`);
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

  const emitBackstopDeny = (): void => {
    if (decided) return;
    decided = true;
    try {
      writeDecision(backstopDeny());
    } catch {
      // Nothing more can be done if stdout itself is gone; the host sees a hook error.
    }
  };

  // The event loop drained while `main()` was still waiting (a promise that will never settle and
  // holds no refs). Deny, then exit explicitly so the process does not linger.
  process.once("beforeExit", () => {
    if (decided) return;
    emitBackstopDeny();
    process.exit(0);
  });

  // Any other exit that skipped `finalize` (an explicit `process.exit` elsewhere, an uncaught
  // exception). Only synchronous work is possible here. Exit 0 so the host reads the deny JSON as a
  // decision rather than a hook error.
  process.once("exit", () => {
    if (decided) return;
    emitBackstopDeny();
    process.exitCode = 0;
  });

  return {
    finalize(decision: T | null): void {
      writeDecision(decision);
      decided = true;
    },
  };
}
