/**
 * Drive the **real** `@allw/approver` watch loop (`runWatch`) over a live relay WebSocket with an
 * unattended auto-decision prompter — for the locally-automatable `pnpm run demo:e2e` script.
 *
 * This is exactly the production `allw-approver watch` path (`packages/approver/src/commands/
 * watch.ts`): connect the device presence socket, decrypt each request via the WASM core, recompute
 * the WYSIWYS `request_hash`, render it, and sign a verdict. The ONLY difference from the
 * interactive CLI is the {@link Prompter}: instead of reading a TTY, it auto-answers `approve` /
 * `deny`, or (for the timeout variant) never answers. No crypto or contract logic is added here.
 *
 * The interactive recording uses the real `allw-approver watch` CLI directly; this auto path keeps
 * the demo (and any local automation) deterministic and walk-away.
 */

import { loadWasm, readKeyfile, runWatch } from "@allw/approver";
import type { Decision, Prompter, WatchLogger, WebSocketLike } from "@allw/approver";

/** How the auto-prompter answers each request (mirrors the harness's {@link AutoDecision}). */
export type LiveAutoDecision = "approved" | "denied" | "timeout";

/** Options for {@link runLiveApprover}. */
export interface LiveApproverOptions {
  readonly keyfilePath: string;
  readonly mode: LiveAutoDecision;
  /** Where to write human-facing log lines (defaults to stdout/stderr). */
  readonly log?: WatchLogger;
}

/**
 * Build an unattended {@link Prompter} that auto-answers every request per `mode`.
 *
 * - `approved` / `denied` → answer that decision (renders the WYSIWYS block first, like the CLI).
 * - `timeout` → return `null` (no decision) for every request, so it expires and the integrator
 *   fails closed.
 */
export function autoPrompter(mode: LiveAutoDecision, log: WatchLogger): Prompter {
  return {
    decide(rendered: string): Promise<Decision | null> {
      // Print the same WYSIWYS render the human would see, so a recording shows the exact action.
      log.info(rendered);
      if (mode === "timeout") {
        log.info("[auto] timeout mode — leaving the request unanswered (fail-closed).");
        return Promise.resolve(null);
      }
      const decision: Decision = mode === "approved" ? "approved" : "denied";
      log.info(`[auto] ${decision} (unattended demo mode)`);
      return Promise.resolve(decision);
    },
  };
}

/**
 * Connect the real approver watch loop to the paired keyfile's relay and auto-decide. Resolves when
 * the presence socket closes (the demo script closes it after the hook has its decision).
 */
export async function runLiveApprover(options: LiveApproverOptions): Promise<void> {
  const wasm = await loadWasm();
  const log: WatchLogger = options.log ?? {
    info: (line) => {
      console.log(line);
    },
    warn: (line) => {
      console.error(line);
    },
  };
  const keyfile = readKeyfile(options.keyfilePath);
  if (keyfile.relay_url === undefined) {
    throw new Error("keyfile is not paired (no relay_url) — run 'allw-approver pair' first");
  }

  await runWatch(
    wasm,
    { keyfilePath: options.keyfilePath },
    {
      // Node 24 ships a global WebSocket; it satisfies the structural WebSocketLike surface.
      connect: (url: string): WebSocketLike => new WebSocket(url),
      prompter: autoPrompter(options.mode, log),
      log,
    },
  );
}
