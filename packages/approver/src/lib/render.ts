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
 * When `raw` and the hash-bound argv diverge, that headline is the argv form, followed by a
 * divergence warning.
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

/**
 * Join list items (paths, env refs, chain ids) with `, `, each quoted by {@link quoteToken} so an
 * item containing `, ` or whitespace stays visibly one item: `["a, /etc/passwd"]` renders as
 * `'a, /etc/passwd'`, never like the two items `a, /etc/passwd`.
 */
function renderList(items: readonly string[]): string {
  return items.map(quoteToken).join(", ");
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
 *
 * The web approver applies the same rule (`packages/web-approver/src/command-line.ts`); both are
 * tested against one shared fixture (`packages/web-approver/test/fixtures/raw-argv-divergence.json`).
 */
export function reconstructCommand(parts: CommandParts): string | undefined {
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
export function rawDivergesFromArgv(action: ActionRecord): boolean {
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
 * The tool identity a tool-surface record heads with: `server :: tool`, or the tool alone. It is
 * `undefined` on any other surface, or when the record has no `tool`. A `.` join would make server
 * `fs.delete` + tool `x` look like server `fs` + tool `delete.x`, hence `::`.
 */
export function toolIdentity(display: DisplayModel): string | undefined {
  const isToolSurface =
    display.surface === "mcp_tool_call" || display.surface === "agent_tool_call";
  const { server, tool } = display.syntactic;
  if (!isToolSurface || tool === undefined) return undefined;
  return server !== undefined ? `${server} :: ${tool}` : tool;
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
 * On a tool surface (`mcp_tool_call`, `agent_tool_call`) with a `tool`, the headline is the tool
 * identity ({@link toolIdentity}): there `raw` is the caller's description of the call (OpenClaw's
 * plugin text), not the action, so it is shown on its own labelled `Description:` line instead.
 * Otherwise `raw` (the agent's original string form) is preferred when present; then we
 * reconstruct from `bin`/`argv`; then a `server :: tool` headline; then the compact params JSON so
 * nothing is ever silently dropped. The web approver uses the same rule, and both are checked
 * against one shared fixture (`packages/web-approver/test/fixtures/action-headline.json`).
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
export function renderActionHeadline(display: DisplayModel): string {
  const s = display.syntactic;
  const identity = toolIdentity(display);
  if (identity !== undefined) return identity;
  if (display.surface === "file_edit") {
    if (s.diff_summary !== undefined) return s.diff_summary;
    if (s.operation !== undefined && s.paths !== undefined && s.paths.length > 0) {
      return `${s.operation} ${renderList(s.paths)}`;
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
    return `${s.operation} ${renderList(s.paths)}`;
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
  // A tool-surface record heads with its tool identity, so any command form it also carries is
  // always shown, with a warning at the decision point (TOOL_COMMAND_FORM_WARNING).
  const reconstructed = reconstructCommand(s);
  const toolHeadline = toolIdentity(display) !== undefined;
  if (reconstructed !== undefined && (toolHeadline || rawDivergesFromArgv(action))) {
    lines.push(`  Argv:       ${reconstructed}`);
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
    lines.push(`  Env refs:   ${renderList(s.env_refs)}`);
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
    lines.push(`  Paths:      ${renderList(s.paths)}`);
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
  const identity = toolIdentity(display);
  if (identity !== undefined) {
    // A tool call heads with its identity; its `raw` is the caller's description, labelled so.
    if (display.syntactic.raw === undefined || !lines) return [`  Action:     ${identity}`];
    const [first = "", ...rest] = lines;
    return [
      `  Action:     ${identity}`,
      `  Description: ${first}`,
      ...rest.map((line) => `             │ ${line}`),
    ];
  }
  if (display.surface === "file_edit" || display.syntactic.raw === undefined || !lines) {
    return [`  Action:     ${renderActionHeadline(display)}`];
  }
  const [first = "", ...rest] = lines;
  return [`  Action:     ${first}`, ...rest.map((line) => `            │ ${line}`)];
}

/**
 * Printed directly above the prompt when the hash-bound `bin`/`argv` reconstructs to a different
 * command than `raw`. The `Deciding on:` line then shows the argv form, so the decision point never
 * shows only the benign half of a divergent pair.
 */
export const RAW_ARGV_DIVERGENCE_WARNING =
  "  ⚠ WARNING: raw and argv differ — the line above is the hash-bound argv; the Action line shows raw. Review both.";

/**
 * Printed directly above the prompt when a tool-surface record, which heads with its tool identity,
 * also carries a hash-bound command form (`bin`/`argv`). The `Argv:` line in the block shows it.
 */
export const TOOL_COMMAND_FORM_WARNING =
  "  ⚠ WARNING: this tool call also carries a command (see Argv above) — it is hash-bound too. Review both.";

/** Shown under the header whenever the core escaped at least one character (#246). */
export const HIDDEN_CHARS_WARNING =
  "  ⚠ WARNING: contains hidden/control characters — shown escaped below (e.g. \\x1b, \\r, ⟨U+202E⟩). Review carefully.";

/** The block's fixed title line. */
const HEADER = "  APPROVAL REQUEST — review the EXACT action below before deciding";

/** The terminal width assumed when the output is not a TTY (or reports no width). */
export const DEFAULT_COLUMNS = 80;

/**
 * Prefix of every row produced by wrapping a long printed line. Field labels start in column 2
 * (`  Actor:`), and the origin row's `✓ VERIFIED` / `⚠ UNVERIFIED` marker in column 14; a wrapped
 * row always starts with this marker instead, so no part of an untrusted value can begin a row that
 * looks like a label or an origin verdict.
 */
export const WRAP_MARKER = "  ↪ ";

/**
 * Conservative terminal cell width of `text`: ASCII counts as one cell and **every** other code
 * point as two (the widest a terminal renders one). Over-estimating only wraps earlier than
 * necessary; under-estimating would let the terminal soft-wrap the row itself, unmarked.
 */
function cellWidth(text: string): number {
  let width = 0;
  for (const ch of text) width += (ch.codePointAt(0) ?? 0) < 0x80 ? 1 : 2;
  return width;
}

/**
 * Hard-wrap one printed row to fit `columns` terminal cells, prefixing every continuation row with
 * {@link WRAP_MARKER}. The CLI owns wrapping (rather than leaving it to the terminal) because
 * printable padding — spaces are never escaped — would otherwise push the tail of an untrusted
 * value onto a soft-wrapped row of its own, starting in column 0, where it can pose as a field label
 * or a `✓ VERIFIED` origin row. Wrapping is layout only; no character is changed or dropped.
 */
export function wrapRow(row: string, columns: number): string[] {
  // Leave the last column free: some terminals wrap when a row fills the final cell exactly.
  const limit = Math.max(Math.floor(columns), 24) - 1;
  if (cellWidth(row) <= limit) return [row];
  const rows: string[] = [];
  let current = "";
  let width = 0;
  for (const ch of row) {
    const w = cellWidth(ch);
    if (width + w > limit) {
      rows.push(current);
      current = WRAP_MARKER;
      width = cellWidth(WRAP_MARKER);
    }
    current += ch;
    width += w;
  }
  rows.push(current);
  return rows;
}

/**
 * Produce the full WYSIWYS block for a prepared request. Every line here is content the human is
 * attesting to by approving; the `request_hash` is shown verbatim so an out-of-band check is
 * possible. The block is framed so it stands out in a busy terminal.
 *
 * Context text comes only from `prepared.display` (the core's escaped model); the request id is
 * `prepared.displayRequestId`; origin strings are escaped by their producers. No raw context string
 * is ever interpolated into the output.
 *
 * Every row that can carry untrusted text is hard-wrapped to `columns` terminal cells with
 * {@link wrapRow}; pass the terminal's width (the default suits a non-TTY).
 */
export function renderRequest(
  prepared: RenderableRequest,
  columns: number = DEFAULT_COLUMNS,
): string {
  const { context, display, expiresAt, requestHash, origin } = prepared;
  const lines: string[] = [];
  const rule = "─".repeat(72);

  lines.push(rule);
  lines.push(HEADER);
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
    lines.push(`  Chain:      ${renderList(display.chain)}`);
  }
  lines.push(`  request_hash (WYSIWYS): ${requestHash}`);
  lines.push(rule);
  // Repeated at the decision point: the prompt follows these lines directly, so the human answers
  // with the action (one escaped line) and any warning on screen however long the block was. When
  // raw and argv diverge, the decision line shows the hash-bound argv (never only the `raw` half,
  // which may be the benign one) and says so on the last line before the prompt.
  // On a tool surface `raw` is a description, not a command, so it is never compared with argv;
  // a command form there is flagged by its own warning instead.
  const toolHeadline = toolIdentity(display) !== undefined;
  const diverges = !toolHeadline && rawDivergesFromArgv(context.action);
  const decidingOn = diverges ? reconstructCommand(display.syntactic) : undefined;
  const toolCommandForm = toolHeadline && reconstructCommand(display.syntactic) !== undefined;
  lines.push(`  Deciding on: ${decidingOn ?? renderActionHeadline(display)}`);
  if (display.has_hidden_or_control_chars) {
    lines.push(HIDDEN_CHARS_WARNING);
  }
  if (decidingOn !== undefined) {
    lines.push(RAW_ARGV_DIVERGENCE_WARNING);
  }
  if (toolCommandForm) {
    lines.push(TOOL_COMMAND_FORM_WARNING);
  }

  // Every row that can carry untrusted text is hard-wrapped with a continuation marker. The fixed
  // chrome (rules, header, warnings) contains no untrusted text and is left whole.
  const fixed = new Set([
    rule,
    HEADER,
    HIDDEN_CHARS_WARNING,
    RAW_ARGV_DIVERGENCE_WARNING,
    TOOL_COMMAND_FORM_WARNING,
  ]);
  return lines.flatMap((line) => (fixed.has(line) ? [line] : wrapRow(line, columns))).join("\n");
}
