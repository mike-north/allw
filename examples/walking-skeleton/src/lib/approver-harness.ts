/**
 * A test/demo harness that drives the **real** `@allw/approver` core (`prepareRequest` →
 * recompute WYSIWYS `request_hash` → `signDecision`) against an {@link InProcessRelay} device
 * connection — the same decrypt→hash→sign sequence `allw-approver watch` performs over a live
 * WebSocket (`packages/approver/src/commands/watch.ts`), minus the TTY and the network.
 *
 * It deliberately reuses the approver's own exported functions so the CI round-trip exercises the
 * production code path, not a re-implementation. All cryptography stays in the WASM core.
 */

import { prepareRequest, signDecision } from "@allw/approver";
import type { AllwWasm, ApprovalContext, Decision, Keyfile } from "@allw/approver";

import type { DeviceConnection } from "./in-process-relay.js";

/**
 * How the harness decides each request, unattended:
 * - `"approved"` / `"denied"` → always answer that way (the demo's auto-approve / auto-deny modes).
 * - `"timeout"` → never answer (the request expires; the integrator fails closed).
 */
export type AutoDecision = Decision | "timeout";

/** A record of one decision the harness made, for assertions / logging. */
export interface DecisionLogEntry {
  readonly requestId: string;
  /** The WYSIWYS `request_hash` the approver recomputed device-side over the decrypted context. */
  readonly requestHash: string;
  /**
   * The **decrypted** human-shown `ApprovalContext` the approver rendered (the plaintext the relay
   * never saw), or `null` if decryption failed. Surfaced so a test can assert WYSIWYS directly —
   * that the command/cwd the approver saw equals exactly what was sent (acceptance criterion #2).
   */
  readonly context: ApprovalContext | null;
  /** The decision sent (or `null` when the mode left it to time out). */
  readonly decision: Decision | null;
}

/** A paired software approver identity (the v0 software-key stand-in) plus the WASM core. */
export interface ApproverIdentity {
  readonly wasm: AllwWasm;
  readonly keyfile: Keyfile;
}

/**
 * Attach the real approver core to a device connection. For every pushed request it decrypts,
 * recomputes the `request_hash`, and — per `mode` — signs and returns a verdict (or lets it expire).
 * Returns a log of the decisions made (mutated as requests arrive).
 *
 * @param now injected clock (ms) so the approver's device-side fail-closed expiry is deterministic.
 */
export function attachAutoApprover(
  identity: ApproverIdentity,
  connection: DeviceConnection,
  mode: AutoDecision,
  now: () => number,
): { readonly log: DecisionLogEntry[] } {
  const { wasm, keyfile } = identity;
  const log: DecisionLogEntry[] = [];

  connection.onRequest((requestId, envelope) => {
    // Decrypt → recompute WYSIWYS request_hash (the real approver core; fail-closed on any error).
    let prepared;
    try {
      prepared = prepareRequest(wasm, keyfile, envelope, now());
    } catch {
      // A request we cannot decrypt/verify (or that is already expired) yields NO verdict — the
      // integrator's gate stays closed (deny-by-default). Mirrors the watch loop's skip-on-error.
      log.push({ requestId, requestHash: "", context: null, decision: null });
      return;
    }

    if (mode === "timeout") {
      // Unattended "never answer" — the request will expire and the integrator fails closed.
      log.push({
        requestId,
        requestHash: prepared.requestHash,
        context: prepared.context,
        decision: null,
      });
      return;
    }

    // Sign the verdict (Ed25519 + device cert) over the recomputed hash and return it.
    const verdict = signDecision(wasm, keyfile, prepared, mode, now());
    connection.sendVerdict(requestId, verdict);
    log.push({
      requestId,
      requestHash: prepared.requestHash,
      context: prepared.context,
      decision: mode,
    });
  });

  return { log };
}
