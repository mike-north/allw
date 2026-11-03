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
 *
 * # Display safety: print only the core's escaped model (#246)
 * Context strings are untrusted bytes. A command carrying `ESC [2K` + `CR` can erase and repaint its
 * own terminal line, so printing it verbatim lets an agent show the human `git status` while the
 * hash binds `rm -rf …`. Every context string this module prints therefore comes from
 * `prepared.display` — the core's `display_model`, in which every control, bidi, and zero-width
 * character is already a visible escape (`\x1b`, `\r`, `⟨U+202E⟩`). This module never escapes
 * anything itself (thin-shell rule). It reads the raw `prepared.context` only to *decide* layout
 * (whether `raw` and the argv reconstruction diverge), never to produce printed text.
 *
 * # The decision point
 * A long block (a file edit, a multi-line command) can scroll the header and the `Action:` line off
 * screen before the human answers. So the block ends with a one-line escaped headline and, when the
 * model reports hidden/control characters, the warning — the last lines printed before the prompt.
 * The warning is also printed directly under the header.
 */

import type { RenderableRequest } from "./approver-core.js";
import type { ActionRecord, DisplayModel } from "./types.js";

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
 * the substrate the core hashed). It only disambiguates what the human is reading. Tokens reaching
 * it for printing are already core-escaped, so an escape such as `\x1b` (which contains `\`) is
 * itself quoted — the token boundary stays visible.
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

/** The command-form fields a command line is reconstructed from. */
interface CommandParts {
  readonly bin?: string | undefined;
  readonly argv?: readonly string[] | undefined;
  readonly positionals?: readonly string[] | undefined;
}

/**
 * Reconstruct the unambiguous command line from the `bin`/`argv` substrate, or `undefined` when
 * there is no command form (no `argv` and no `bin`). This is the single source of truth shared by
 * the headline ({@link renderActionHeadline}) and the divergence detail line
 * ({@link substrateDetailLines}) so they can never disagree about what argv reconstructs to.
 *
 * `bin` is prepended unless `argv` already leads with it (argv conventionally includes the binary),
 * so the human never sees args without the program they belong to.
 *
 * Applied to the raw substrate it yields the comparison value for divergence detection; applied to
 * the escaped display substrate it yields the printed line.
 */
function reconstructCommand(parts: CommandParts): string | undefined {
  const { argv, bin } = parts;
  if (argv !== undefined && argv.length > 0) {
    const tokens = bin !== undefined && argv[0] !== bin ? [bin, ...argv] : argv;
    return renderArgv(tokens);
  }
  // No argv: still show `bin` (+ any positionals) rather than dropping the program name.
  if (bin !== undefined) {
    const positionals = parts.positionals;
    return renderArgv(positionals !== undefined ? [bin, ...positionals] : [bin]);
  }
  return undefined;
}

/**
 * Whether the hash-bound `bin`/`argv` reconstructs to a different command than the `raw` headline.
 * Compared on the **raw** bytes (never on escaped text, where distinct inputs can render alike), so
 * the decision is exact. Returns false when there is no `raw` or no command form.
 */
function rawDivergesFromArgv(action: ActionRecord): boolean {
  const syntactic = action.syntactic;
  if (!isRecord(syntactic)) return false;
  const raw = readString(syntactic, "raw");
  if (raw === undefined) return false;
  const reconstructed = reconstructCommand({
    bin: readString(syntactic, "bin"),
    argv: readStringArray(syntactic, "argv"),
    positionals: readStringArray(syntactic, "positionals"),
  });
  return reconstructed !== undefined && reconstructed !== raw;
}

/**
 * Render the action into the literal command / tool call the agent attempted, as one display line,
 * from the core's escaped model. NOTE: this is the *headline* line only — meaning-changing fields
 * (`cwd`, `host`, `env_refs`, MCP `params`) are rendered as their own labeled lines by
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
 * `bin`/`argv`; otherwise an MCP `server :: tool` headline; otherwise the compact params JSON so
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
function renderActionHeadline(display: DisplayModel): string {
  const s = display.syntactic;
  if (display.surface === "file_edit") {
    if (s.diff_summary !== undefined) return s.diff_summary;
    if (s.operation !== undefined && s.paths !== undefined && s.paths.length > 0) {
      return `${s.operation} ${s.paths.join(", ")}`;
    }
  }

  if (s.raw !== undefined) return s.raw;

  // No `raw`: reconstruct the command from `bin`/`argv` (+ `positionals` when there is no argv).
  const reconstructed = reconstructCommand(s);
  if (reconstructed !== undefined) return reconstructed;

  // MCP / agent_tool_call headline when there is no command form and no `raw`: "server :: tool".
  if (s.tool !== undefined) {
    return s.server !== undefined ? `${s.server} :: ${s.tool}` : s.tool;
  }

  // File-edit headline when no raw summary is present: "patch src/app.ts".
  if (s.operation !== undefined && s.paths !== undefined && s.paths.length > 0) {
    return `${s.operation} ${s.paths.join(", ")}`;
  }
  return s.params_json ?? "(no command, tool, or file-edit fields)";
}

/**
 * The labeled detail lines for the meaning-changing substrate fields. These are bound into
 * `request_hash` and so MUST be shown whenever present. Returns an empty array when none apply
 * (e.g. a bare `raw` command with no cwd/env). Every printed value comes from the escaped model.
 *
 * Includes the **anti-divergence** lines (`docs/contract.md` §Invariant #3): `argv`/`flags`/
 * `positionals` (command surface) and `server`/`tool` (MCP surface) are all bound into
 * `request_hash` but were not previously rendered on the `raw` path — so a benign `raw` (e.g.
 * `"echo hello"`) could mask a dangerous hashed `argv` OR a dangerous `server`/`tool`
 * (`fs :: delete_all_files`). The `Argv:` line appears whenever the reconstructed `bin`/`argv`
 * command **diverges** from the `raw` headline; `Flags:`, `Positionals:`, and the `MCP:` line always
 * appear when present, regardless of which headline path ran. All are display-only — never the hash.
 */
function substrateDetailLines(action: ActionRecord, display: DisplayModel): string[] {
  const s = display.syntactic;
  const lines: string[] = [];

  // Anti-divergence: when `raw` is shown as the headline but the hash-bound `bin`/`argv`
  // reconstructs to a DIFFERENT command, surface that reconstructed form so a benign `raw` can
  // never hide a dangerous argv. (When there is no `raw`, the headline already IS the reconstructed
  // command, so the line would be redundant and is omitted.)
  if (rawDivergesFromArgv(action)) {
    const reconstructed = reconstructCommand(s);
    if (reconstructed !== undefined) lines.push(`  Argv:       ${reconstructed}`);
  }

  // `flags` / `positionals` are bound into the hash but were never rendered on any path before;
  // surface them (quoted for boundary clarity) whenever present.
  if (s.flags !== undefined && s.flags.length > 0) {
    lines.push(`  Flags:      ${renderArgv(s.flags)}`);
  }
  if (s.positionals !== undefined && s.positionals.length > 0) {
    lines.push(`  Positionals: ${renderArgv(s.positionals)}`);
  }

  if (s.cwd !== undefined) lines.push(`  Cwd:        ${s.cwd}`);
  if (s.host !== undefined) lines.push(`  Host:       ${s.host}`);
  if (s.env_refs !== undefined && s.env_refs.length > 0) {
    lines.push(`  Env refs:   ${s.env_refs.join(", ")}`);
  }

  // Server/tool are hash-bound but were rendered on NO line when a `raw` headline ran — so a
  // benign `raw` ("echo hello") could mask a dangerous `fs :: delete_all_files`. Surface them on an
  // unconditional labeled line whenever both are present (mirrors the command-surface fix; #56).
  // The label distinguishes an actual MCP tool call from an `agent_tool_call` (a harness/plugin
  // gating a tool call itself, not an MCP server — `docs/openclaw-integration.md` §5.2) so the
  // human is never told a plugin-owned action is an MCP call it never was.
  if (s.server !== undefined && s.tool !== undefined) {
    lines.push(
      display.surface === "agent_tool_call"
        ? `  Agent/plugin: ${s.server} :: ${s.tool}`
        : `  MCP:        ${s.server} :: ${s.tool}`,
    );
  }

  // MCP params are the entire call payload — show them in full (compact JSON), never elided.
  if (s.params_json !== undefined) lines.push(`  Params:     ${s.params_json}`);

  // File-edit fields are hash-bound and must be visible: a path or operation hidden behind a
  // generic summary would let the human sign over a different file mutation than they reviewed.
  if (s.operation !== undefined) lines.push(`  File edit:  ${s.operation}`);
  if (s.paths !== undefined && s.paths.length > 0) {
    lines.push(`  Paths:      ${s.paths.join(", ")}`);
  }
  if (s.diff_summary !== undefined) lines.push(`  Diff summary: ${s.diff_summary}`);
  if (s.diff_hash !== undefined) lines.push(`  Diff hash:  ${s.diff_hash}`);

  // The core splits a file edit's content on line feeds (structure, not hidden content) and
  // escapes each line, so a CR or bidi control inside a line is still visible.
  if (display.surface === "file_edit" && s.raw_lines !== undefined) {
    lines.push("  File edit content:");
    for (const line of s.raw_lines) {
      lines.push(`    ${line}`);
    }
  }

  return lines;
}

/**
 * The `Action:` lines of the block. A command's `raw` is multi-line content (e.g. a heredoc), so it
 * is printed from the core's `raw_lines`: the first line after the label, every further line as a
 * `│`-marked continuation, so no line of it can pass for a field label of its own. A file edit's
 * content is printed separately ({@link substrateDetailLines}), so its headline stays one line.
 */
function actionLines(display: DisplayModel): string[] {
  const lines = display.syntactic.raw_lines;
  if (display.surface === "file_edit" || display.syntactic.raw === undefined || !lines) {
    return [`  Action:     ${renderActionHeadline(display)}`];
  }
  const [first = "", ...rest] = lines;
  return [`  Action:     ${first}`, ...rest.map((line) => `            │ ${line}`)];
}

/** Shown under the header whenever the core escaped at least one character (#246). */
export const HIDDEN_CHARS_WARNING =
  "  ⚠ WARNING: contains hidden/control characters — shown escaped below (e.g. \\x1b, \\r, ⟨U+202E⟩). Review carefully.";

/**
 * Produce the full WYSIWYS block for a prepared request. Every line here is content the human is
 * attesting to by approving; the `request_hash` is shown verbatim so an out-of-band check is
 * possible. The block is framed so it stands out in a busy terminal.
 *
 * Context text comes only from `prepared.display` (the core's escaped model); the request id is
 * `prepared.displayRequestId`; origin strings are escaped by their producers. No raw context string
 * is ever interpolated into the output.
 */
export function renderRequest(prepared: RenderableRequest): string {
  const { context, display, expiresAt, requestHash, origin } = prepared;
  const lines: string[] = [];
  const rule = "─".repeat(72);

  lines.push(rule);
  lines.push("  APPROVAL REQUEST — review the EXACT action below before deciding");
  lines.push(rule);
  if (display.has_hidden_or_control_chars) {
    lines.push(HIDDEN_CHARS_WARNING);
  }
  lines.push(`  Request:    ${prepared.displayRequestId}`);
  lines.push(`  Summary:    ${display.summary}`);
  lines.push(...actionLines(display));
  lines.push(`  Surface:    ${display.surface}`);
  // Meaning-changing substrate fields (cwd/host/env_refs/params) — bound into request_hash, so
  // shown explicitly. A human must never sign over a cwd/params they could not see.
  for (const detail of substrateDetailLines(context.action, display)) {
    lines.push(detail);
  }
  // SECURITY (Invariant #4 — requester attestation): the actor origin is shown VERIFIED only when
  // the actor attestation (#16) verified against the actor key **root-anchored in signed account
  // state** (never a relay-supplied key), bound to THIS request_id + request_hash. Otherwise
  // (absent / not-root-anchored / revoked / failed) it is explicitly marked ⚠ UNVERIFIED —
  // spoofable plaintext, never rendered as if trusted. A failed/absent attestation MUST NOT look
  // verified.
  lines.push(`  Actor:      ${display.actor_label}`);
  if (origin?.verified === true) {
    lines.push(`              ✓ VERIFIED origin — ${origin.origin}`);
  } else {
    const reason = origin?.reason ?? "origin is unauthenticated plaintext";
    lines.push(`              ⚠ UNVERIFIED — ${reason} (#16)`);
  }
  lines.push(`  Risk:       ${display.risk}`);
  lines.push(`  Reversible: ${display.reversible ? "yes" : "no"}`);
  if (prepared.numberMatchChallenge !== undefined) {
    lines.push(`  Number match: ${prepared.numberMatchChallenge}`);
  }
  lines.push(`  Expires:    ${formatTimestamp(expiresAt)}`);
  if (display.chain !== undefined && display.chain.length > 0) {
    lines.push(`  Chain:      ${display.chain.join(", ")}`);
  }
  lines.push(`  request_hash (WYSIWYS): ${requestHash}`);
  lines.push(rule);
  // Repeated at the decision point: the prompt follows these lines directly, so the human answers
  // with the action (one escaped line) and any warning on screen however long the block was.
  lines.push(`  Deciding on: ${renderActionHeadline(display)}`);
  if (display.has_hidden_or_control_chars) {
    lines.push(HIDDEN_CHARS_WARNING);
  }

  return lines.join("\n");
}
