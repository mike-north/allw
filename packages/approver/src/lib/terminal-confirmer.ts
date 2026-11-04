/**
 * The yes/no confirmation `allw-approver vouch` asks before it signs (#381).
 *
 * Fail-closed by construction: only an explicit `y` / `yes` answered with Enter confirms. Anything
 * else, and any way the question ends without an answer, is "not confirmed", so `vouch` exits
 * non-zero with nothing signed:
 *
 * - the input closes while the question is open (EOF, a closed pty), including after a partial
 *   answer such as `y` with no Enter. Without this, the pending question never settles, Node exits
 *   0 with nothing published, and a wrapper reads success (review-387 F2);
 * - the interface was already closed, or readline throws.
 */

import { createInterface, type Interface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";

import type { Confirmer } from "../commands/vouch.js";

/** Where the confirmer reads and writes. The CLI passes the process's stdin and stdout. */
export interface TerminalConfirmerOptions {
  readonly input: Readable;
  readonly output: Writable;
  /** Whether a human is at an interactive terminal (the CLI: stdin and stdout are both TTYs). */
  readonly interactive: boolean;
}

/** A {@link Confirmer} backed by readline, plus `close()` to release the input. */
export type TerminalConfirmer = Confirmer & { close(): void };

/**
 * Create the confirmer. The readline interface opens lazily on the first question, so a refused
 * non-interactive run never touches the input.
 */
export function createTerminalConfirmer(options: TerminalConfirmerOptions): TerminalConfirmer {
  let rl: Interface | undefined;
  let closed = false;
  return {
    interactive: options.interactive,
    async confirm(question: string): Promise<boolean> {
      if (closed) return false;
      // `terminal: true` matches the TTY the CLI requires: a line counts only when Enter submits
      // it, so a partial answer left in the buffer at EOF is never taken as the answer.
      rl ??= createInterface({ input: options.input, output: options.output, terminal: true });
      const abort = new AbortController();
      const onClose = (): void => {
        closed = true;
        abort.abort();
      };
      rl.once("close", onClose);
      try {
        const answer = (await rl.question(question, { signal: abort.signal })).trim().toLowerCase();
        return answer === "y" || answer === "yes";
      } catch {
        return false;
      } finally {
        rl.off("close", onClose);
      }
    },
    close(): void {
      closed = true;
      rl?.close();
    },
  };
}
