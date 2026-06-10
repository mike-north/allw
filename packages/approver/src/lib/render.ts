/**
 * WYSIWYS terminal rendering (`docs/contract.md` §Invariant #3 — what you see is what you sign).
 *
 * The human must be shown the **exact** action they are signing over, and the rendered fields are
 * precisely the ones bound into `request_hash` (`action`, `summary`, `actor`, `risk`, `reversible`,
 * `expires_at`, plus the `request_hash` itself). Rendering is pure (returns a string) so it is
 * trivially testable and the CLI just prints it.
 */

import type { RenderableRequest } from "./approver-core.js";
import type { ActionRecord } from "./types.js";

/** Format a ms-since-epoch timestamp as an ISO-8601 UTC string (deterministic, unambiguous). */
function formatTimestamp(ms: number): string {
  return new Date(ms).toISOString();
}

/**
 * Render the action's syntactic substrate into the literal command/argv the agent attempted.
 * The substrate is opaque structure (`docs/policy-seam.md`); we surface the most human-meaningful
 * representation without interpreting it — preferring an explicit `raw` command line, then `argv`,
 * then a compact JSON fallback so nothing shown is ever silently dropped.
 */
function renderAction(action: ActionRecord): string {
  const syntactic = action.syntactic;
  if (syntactic && typeof syntactic === "object" && !Array.isArray(syntactic)) {
    const record = syntactic as Record<string, unknown>;
    if (typeof record.raw === "string") return record.raw;
    if (Array.isArray(record.argv)) {
      return record.argv.map((a) => String(a)).join(" ");
    }
  }
  return JSON.stringify(syntactic);
}

/**
 * Produce the full WYSIWYS block for a prepared request. Every line here is content the human is
 * attesting to by approving; the `request_hash` is shown verbatim so an out-of-band check is
 * possible. The block is framed so it stands out in a busy terminal.
 */
export function renderRequest(prepared: RenderableRequest): string {
  const { context, requestId, expiresAt, requestHash } = prepared;
  const lines: string[] = [];
  const rule = "─".repeat(72);

  lines.push(rule);
  lines.push("  APPROVAL REQUEST — review the EXACT action below before deciding");
  lines.push(rule);
  lines.push(`  Request:    ${requestId}`);
  lines.push(`  Summary:    ${context.summary}`);
  lines.push(`  Action:     ${renderAction(context.action)}`);
  lines.push(`  Surface:    ${context.action.surface}`);
  lines.push(`  Actor:      ${context.actor.id} (${context.actor.kind})`);
  lines.push(`  Risk:       ${context.risk}`);
  lines.push(`  Reversible: ${context.reversible ? "yes" : "no"}`);
  lines.push(`  Expires:    ${formatTimestamp(expiresAt)}`);
  if (context.chain && context.chain.length > 0) {
    lines.push(`  Chain:      ${context.chain.join(", ")}`);
  }
  lines.push(`  request_hash (WYSIWYS): ${requestHash}`);
  lines.push(rule);

  return lines.join("\n");
}
