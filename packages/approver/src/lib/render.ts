/**
 * WYSIWYS terminal rendering (`docs/contract.md` §Invariant #3 — what you see is what you sign).
 *
 * The human must be shown the **exact** action they are signing over, and the rendered fields are
 * precisely the ones bound into `request_hash` (the full `ActionRecord` syntactic substrate,
 * `summary`, `actor`, `risk`, `reversible`, `expires_at`, plus the `request_hash` itself). When a
 * number-match challenge is required, the code derived from that `request_hash` is shown too; the
 * human must type it back before an approval can be signed.
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
 * Quote/escape a single command token **for display** so the human can see its exact boundaries.
 * A token containing whitespace or shell-significant characters is wrapped in single quotes (with
 * embedded single quotes escaped POSIX-style), so `["rm","-rf","my dir"]` renders as
 * `rm -rf 'my dir'` — visually distinct from three separate args. Empty tokens render as `''`.
 *
 * This is **display-only**: it never changes the bytes bound into `request_hash` (those come from
 * the substrate the core hashed). It only disambiguates what the human is reading.
 */
function quoteToken(token: string): string {
  // Shell-significant set (and whitespace) — if a token contains any of these its boundaries are
  // ambiguous when bare, so quote it. Plain tokens (e.g. `--force`, `origin`) render unquoted.
  //
  // RATIONALE for the hand-curated set: the goal here is **boundary disambiguation for a human
  // reader**, not producing a shell-safe string (this output is never executed). A token must be
  // quoted iff a reader could otherwise misjudge where it begins/ends or mistake it for shell
  // structure. We therefore quote on: whitespace (the only true token-splitter), quoting/escape
  // characters (`'"\`), and the shell metacharacters that visually imply structure
  // (`$\`&|;<>(){}[]*?#~!`). We intentionally OMIT `=` `:` `,` `@` `%` — none split a token or
  // read as shell structure, so quoting them would only add noise (e.g. `KEY=value`, `a:b`,
  // `user@host`, `50%` stay legible bare). If a future surface makes one of those ambiguous, widen
  // the set and extend the table-driven quoting test alongside it.
  if (token !== "" && !/[\s'"\\$`&|;<>(){}[\]*?#~!]/.test(token)) {
    return token;
  }
  // POSIX single-quote escaping: ' → '\'' (close, escaped quote, reopen).
  return `'${token.replace(/'/g, "'\\''")}'`;
}

/** Join argv tokens into one unambiguous, display-safe command line. */
function renderArgv(argv: readonly string[]): string {
  return argv.map(quoteToken).join(" ");
}

/**
 * Reconstruct the unambiguous command line from the `bin`/`argv` substrate, or `undefined` when
 * there is no command form (no `argv` and no `bin`). This is the single source of truth shared by
 * the headline ({@link renderActionHeadline}) and the divergence detail line
 * ({@link substrateDetailLines}) so they can never disagree about what argv reconstructs to.
 *
 * `bin` is prepended unless `argv` already leads with it (argv conventionally includes the binary),
 * so the human never sees args without the program they belong to.
 */
function reconstructCommand(syntactic: Record<string, unknown>): string | undefined {
  const argv = readStringArray(syntactic, "argv");
  const bin = readString(syntactic, "bin");
  if (argv !== undefined && argv.length > 0) {
    const tokens = bin !== undefined && argv[0] !== bin ? [bin, ...argv] : argv;
    return renderArgv(tokens);
  }
  // No argv: still show `bin` (+ any positionals) rather than dropping the program name.
  if (bin !== undefined) {
    const positionals = readStringArray(syntactic, "positionals");
    return renderArgv(positionals !== undefined ? [bin, ...positionals] : [bin]);
  }
  return undefined;
}

/**
 * Render the action's syntactic substrate into the literal command / tool call the agent attempted,
 * as one display line. NOTE: this is the *headline* line only — meaning-changing fields (`cwd`,
 * `host`, `env_refs`, MCP `params`) are rendered as their own labeled lines by
 * {@link substrateDetailLines}, so a `raw`-only headline never hides them.
 *
 * For the command surface the line is built to be **unambiguous**:
 * - tokens are quoted/escaped when they contain whitespace or shell metacharacters
 *   (so `my dir` is visibly one argument, not two), and
 * - the binary name (`bin`) is included when the substrate carries it separately from `argv` and
 *   `argv` does not already lead with it — the human must never see args without the program they
 *   belong to (per `docs/policy-seam.md`, `bin` and `argv` are distinct substrate fields).
 *
 * `raw` (the agent's original string form) is preferred when present; otherwise we reconstruct from
 * `bin`/`argv`; otherwise an MCP `server :: tool` headline; otherwise a compact JSON fallback so
 * nothing is ever silently dropped.
 *
 * SECURITY (`docs/contract.md` §Invariant #3): the **full** `bin`/`argv` substrate is bound into
 * `request_hash` (`crates/allw-core/src/hash.rs`), but `raw` is just one substrate field. A buggy
 * or malicious integrator could send a benign `raw` ("git status") alongside a divergent, dangerous
 * `argv` (`git push --force …`) — both hashed, but the human would only see the benign string. The
 * device must not rely on integrator honesty for *which* field it shows, so when `raw` is present
 * AND the reconstructed `bin`/`argv` command diverges from it, {@link substrateDetailLines} also
 * surfaces the reconstructed form as a labeled `Argv:` line. Display-only — it never changes the
 * hash.
 */
function renderActionHeadline(action: ActionRecord): string {
  const syntactic = action.syntactic;
  if (isRecord(syntactic)) {
    if (action.surface === "file_edit") {
      const diffSummary = readString(syntactic, "diff_summary");
      if (diffSummary !== undefined) return diffSummary;
      const operation = readString(syntactic, "operation");
      const paths = readStringArray(syntactic, "paths");
      if (operation !== undefined && paths !== undefined && paths.length > 0) {
        return `${operation} ${paths.join(", ")}`;
      }
    }

    const raw = readString(syntactic, "raw");
    if (raw !== undefined) return raw;

    // No `raw`: reconstruct the command from `bin`/`argv` (+ `positionals` when there is no argv).
    const reconstructed = reconstructCommand(syntactic);
    if (reconstructed !== undefined) return reconstructed;

    // MCP headline when there is no command form: "server :: tool".
    const tool = readString(syntactic, "tool");
    if (tool !== undefined) {
      const server = readString(syntactic, "server");
      return server !== undefined ? `${server} :: ${tool}` : tool;
    }

    // File-edit headline when no raw summary is present: "patch src/app.ts".
    const operation = readString(syntactic, "operation");
    const paths = readStringArray(syntactic, "paths");
    if (operation !== undefined && paths !== undefined && paths.length > 0) {
      return `${operation} ${paths.join(", ")}`;
    }
  }
  return JSON.stringify(syntactic);
}

/**
 * The labeled detail lines for the meaning-changing substrate fields. These are bound into
 * `request_hash` and so MUST be shown verbatim whenever present. Returns an empty array when none
 * apply (e.g. a bare `raw` command with no cwd/env).
 *
 * Includes the **anti-divergence** lines (`docs/contract.md` §Invariant #3): `argv`/`flags`/
 * `positionals` (command surface) and `server`/`tool` (MCP surface) are all bound into
 * `request_hash` but were not previously rendered on the `raw` path — so a benign `raw` (e.g.
 * `"echo hello"`) could mask a dangerous hashed `argv` OR a dangerous `server`/`tool`
 * (`fs :: delete_all_files`). The `Argv:` line appears whenever the reconstructed `bin`/`argv`
 * command **diverges** from the `raw` headline; `Flags:`, `Positionals:`, and the `MCP:` line always
 * appear when present, regardless of which headline path ran. All are display-only — never the hash.
 */
function substrateDetailLines(action: ActionRecord): string[] {
  const syntactic = action.syntactic;
  if (!isRecord(syntactic)) return [];
  const lines: string[] = [];

  // Anti-divergence: when `raw` is shown as the headline but the hash-bound `bin`/`argv`
  // reconstructs to a DIFFERENT command, surface that reconstructed form so a benign `raw` can
  // never hide a dangerous argv. (When there is no `raw`, the headline already IS the reconstructed
  // command, so the line would be redundant and is omitted.)
  const raw = readString(syntactic, "raw");
  if (raw !== undefined) {
    const reconstructed = reconstructCommand(syntactic);
    if (reconstructed !== undefined && reconstructed !== raw) {
      lines.push(`  Argv:       ${reconstructed}`);
    }
  }

  // `flags` / `positionals` are bound into the hash but were never rendered on any path before;
  // surface them verbatim (quoted for boundary clarity) whenever present.
  const flags = readStringArray(syntactic, "flags");
  if (flags !== undefined && flags.length > 0) {
    lines.push(`  Flags:      ${renderArgv(flags)}`);
  }

  const positionals = readStringArray(syntactic, "positionals");
  if (positionals !== undefined && positionals.length > 0) {
    lines.push(`  Positionals: ${renderArgv(positionals)}`);
  }

  const cwd = readString(syntactic, "cwd");
  if (cwd !== undefined) lines.push(`  Cwd:        ${cwd}`);

  const host = readString(syntactic, "host");
  if (host !== undefined) lines.push(`  Host:       ${host}`);

  const envRefs = readStringArray(syntactic, "env_refs");
  if (envRefs !== undefined && envRefs.length > 0) {
    lines.push(`  Env refs:   ${envRefs.join(", ")}`);
  }

  // MCP server/tool are hash-bound but were rendered on NO line when a `raw` headline ran — so a
  // benign `raw` ("echo hello") could mask a dangerous `fs :: delete_all_files`. Surface them on an
  // unconditional labeled line whenever both are present (mirrors the command-surface fix; #56).
  const tool = readString(syntactic, "tool");
  const server = readString(syntactic, "server");
  if (server !== undefined && tool !== undefined) {
    lines.push(`  MCP:        ${server} :: ${tool}`);
  }

  // MCP params are the entire call payload — show them in full (compact JSON), never elided.
  if ("params" in syntactic && syntactic.params !== undefined && syntactic.params !== null) {
    lines.push(`  Params:     ${JSON.stringify(syntactic.params)}`);
  }

  // File-edit fields are hash-bound and must be visible: a path or operation hidden behind a
  // generic summary would let the human sign over a different file mutation than they reviewed.
  const operation = readString(syntactic, "operation");
  if (operation !== undefined) {
    lines.push(`  File edit:  ${operation}`);
  }

  const paths = readStringArray(syntactic, "paths");
  if (paths !== undefined && paths.length > 0) {
    lines.push(`  Paths:      ${paths.join(", ")}`);
  }

  const diffSummary = readString(syntactic, "diff_summary");
  if (diffSummary !== undefined) {
    lines.push(`  Diff summary: ${diffSummary}`);
  }

  const diffHash = readString(syntactic, "diff_hash");
  if (diffHash !== undefined) {
    lines.push(`  Diff hash:  ${diffHash}`);
  }

  const rawEdit = action.surface === "file_edit" ? readString(syntactic, "raw") : undefined;
  if (rawEdit !== undefined) {
    lines.push("  File edit content:");
    for (const line of rawEdit.split(/\r?\n/)) {
      lines.push(`    ${line}`);
    }
  }

  return lines;
}

/**
 * Produce the full WYSIWYS block for a prepared request. Every line here is content the human is
 * attesting to by approving; the `request_hash` is shown verbatim so an out-of-band check is
 * possible. The block is framed so it stands out in a busy terminal.
 */
export function renderRequest(prepared: RenderableRequest): string {
  const { context, requestId, expiresAt, requestHash, origin } = prepared;
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
  // SECURITY (Invariant #4 — requester attestation): the actor origin is shown VERIFIED only when
  // the actor attestation (#16) verified against the actor key **root-anchored in signed account
  // state** (never a relay-supplied key), bound to THIS request_id + request_hash. Otherwise
  // (absent / not-root-anchored / revoked / failed) it is explicitly marked ⚠ UNVERIFIED —
  // spoofable plaintext, never rendered as if trusted. A failed/absent attestation MUST NOT look
  // verified.
  lines.push(`  Actor:      ${context.actor.id} (${context.actor.kind})`);
  if (origin?.verified === true) {
    lines.push(`              ✓ VERIFIED origin — ${origin.origin}`);
  } else {
    const reason = origin?.reason ?? "origin is unauthenticated plaintext";
    lines.push(`              ⚠ UNVERIFIED — ${reason} (#16)`);
  }
  lines.push(`  Risk:       ${context.risk}`);
  lines.push(`  Reversible: ${context.reversible ? "yes" : "no"}`);
  if (prepared.numberMatchChallenge !== undefined) {
    lines.push(`  Number match: ${prepared.numberMatchChallenge}`);
  }
  lines.push(`  Expires:    ${formatTimestamp(expiresAt)}`);
  if (context.chain && context.chain.length > 0) {
    lines.push(`  Chain:      ${context.chain.join(", ")}`);
  }
  lines.push(`  request_hash (WYSIWYS): ${requestHash}`);
  lines.push(rule);

  return lines.join("\n");
}
