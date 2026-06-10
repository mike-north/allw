/**
 * WYSIWYS terminal rendering (`docs/contract.md` §Invariant #3 — what you see is what you sign).
 *
 * The human must be shown the **exact** action they are signing over, and the rendered fields are
 * precisely the ones bound into `request_hash` (the full `ActionRecord` syntactic substrate,
 * `summary`, `actor`, `risk`, `reversible`, `expires_at`, plus the `request_hash` itself).
 * Rendering is pure (returns a string) so it is trivially testable and the CLI just prints it.
 *
 * # Completeness is a security property, not a nicety
 * Every field bound into `request_hash` that materially changes what the action *does* MUST be
 * shown. `cwd`, `host`, and `env_refs` change the meaning of an otherwise-identical command (e.g.
 * `rm -rf build` in `/tmp/scratch` vs `/etc`); MCP `params` are the entire payload. Hiding them
 * behind a `raw`-only summary reopens the context/action TOCTOU gap Invariant #3 closes, so the
 * renderer surfaces them explicitly rather than relying on `raw`.
 */

import type { RenderableRequest } from "./approver-core.js";
import type { ActionRecord } from "./types.js";

/** Format a ms-since-epoch timestamp as an ISO-8601 UTC string (deterministic, unambiguous). */
function formatTimestamp(ms: number): string {
  return new Date(ms).toISOString();
}

/** Narrow an untrusted decrypted value to a string-keyed object (rejects arrays/null). */
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Read a string field from an untrusted record, or `undefined` if absent/wrong-typed. */
function readString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

/** Read a string[] field from an untrusted record, or `undefined` if absent/wrong-typed. */
function readStringArray(record: Record<string, unknown>, key: string): string[] | undefined {
  const value = record[key];
  if (!Array.isArray(value)) return undefined;
  return value.map((entry) => String(entry));
}

/**
 * Render the action's syntactic substrate into the literal command / tool call the agent attempted,
 * as one display line. We surface `raw` when present, else reconstruct from `argv`, else a compact
 * JSON fallback so nothing is ever silently dropped. NOTE: this is the *headline* line only —
 * meaning-changing fields (`cwd`, `host`, `env_refs`, MCP `params`) are rendered as their own
 * labeled lines by {@link substrateDetailLines}, so a `raw`-only headline never hides them.
 */
function renderActionHeadline(action: ActionRecord): string {
  const syntactic = action.syntactic;
  if (isRecord(syntactic)) {
    const raw = readString(syntactic, "raw");
    if (raw !== undefined) return raw;
    const argv = readStringArray(syntactic, "argv");
    if (argv !== undefined) return argv.join(" ");
    // MCP headline when there is no raw/argv: "server :: tool".
    const tool = readString(syntactic, "tool");
    if (tool !== undefined) {
      const server = readString(syntactic, "server");
      return server !== undefined ? `${server} :: ${tool}` : tool;
    }
  }
  return JSON.stringify(syntactic);
}

/**
 * The labeled detail lines for the meaning-changing substrate fields. These are bound into
 * `request_hash` and so MUST be shown verbatim whenever present. Returns an empty array when none
 * apply (e.g. a bare `raw` command with no cwd/env).
 */
function substrateDetailLines(action: ActionRecord): string[] {
  const syntactic = action.syntactic;
  if (!isRecord(syntactic)) return [];
  const lines: string[] = [];

  const cwd = readString(syntactic, "cwd");
  if (cwd !== undefined) lines.push(`  Cwd:        ${cwd}`);

  const host = readString(syntactic, "host");
  if (host !== undefined) lines.push(`  Host:       ${host}`);

  const envRefs = readStringArray(syntactic, "env_refs");
  if (envRefs !== undefined && envRefs.length > 0) {
    lines.push(`  Env refs:   ${envRefs.join(", ")}`);
  }

  // MCP params are the entire call payload — show them in full (compact JSON), never elided.
  if ("params" in syntactic && syntactic.params !== undefined && syntactic.params !== null) {
    lines.push(`  Params:     ${JSON.stringify(syntactic.params)}`);
  }

  return lines;
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
  lines.push(`  Action:     ${renderActionHeadline(context.action)}`);
  lines.push(`  Surface:    ${context.action.surface}`);
  // Meaning-changing substrate fields (cwd/host/env_refs/params) — bound into request_hash, so
  // shown explicitly. A human must never sign over a cwd/params they could not see.
  for (const detail of substrateDetailLines(context.action)) {
    lines.push(detail);
  }
  // SECURITY (Invariant #4 — requester attestation): v0 cannot cryptographically verify the actor
  // origin (actor-key verification is #16, still open). The deferral is acceptable ONLY if visible,
  // so the origin is explicitly marked UNVERIFIED — it is spoofable plaintext, not an authenticated
  // identity. Do NOT render it as if trusted.
  lines.push(`  Actor:      ${context.actor.id} (${context.actor.kind})`);
  lines.push(`              ⚠ UNVERIFIED in v0 — origin is unauthenticated plaintext (#16)`);
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
