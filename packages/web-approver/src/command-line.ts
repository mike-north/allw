/**
 * How the web approver lays out command-form substrate fields as text: token quoting, list joining,
 * reconstructing a command line from caller `argv`, and detecting when that reconstruction differs
 * from the agent's `raw` string.
 *
 * These are **layout** rules, not escaping. Every string they print is already escaped by the core
 * (`display_model`, #246); they only make token and item boundaries unambiguous. They mirror the CLI
 * approver's rules (`packages/approver/src/lib/render.ts`) exactly, so the two surfaces show the
 * same command line and agree on when raw and argv diverge. Both surfaces test against one shared
 * fixture (`test/fixtures/raw-argv-divergence.json`) to keep them from drifting.
 *
 * @see ../../../docs/contract.md §Invariants #3 (WYSIWYS)
 * @see ../../approver/src/lib/render.ts (the CLI rules this mirrors)
 */

import type { ApprovalContext } from "./index.js";

/**
 * Quote one token **for display** so its boundaries are visible: `["rm","-rf","my dir"]` shows as
 * `rm -rf 'my dir'`, never like three separate arguments. A token with whitespace, a quoting or
 * escape character, or a shell metacharacter that implies structure is single-quoted (POSIX-style,
 * `'` → `'\''`); an empty token shows as `''`. Display only: it never changes hashed bytes and the
 * output is never executed.
 */
export function quoteToken(token: string): string {
  if (token !== "" && !/[\s'"\\$`&|;<>(){}[\]*?#~!]/.test(token)) {
    return token;
  }
  return `'${token.replace(/'/g, "'\\''")}'`;
}

/** Join tokens into one command line, each quoted by {@link quoteToken}. */
export function renderArgv(tokens: readonly string[]): string {
  return tokens.map(quoteToken).join(" ");
}

/**
 * Join list items (paths and chain ids) with `, `, each quoted by {@link quoteToken}, so an
 * item containing `, ` stays visibly one item.
 */
export function renderList(items: readonly string[]): string {
  return items.map(quoteToken).join(", ");
}

/** Caller-supplied execution vector; raw text never supplies missing words. */
interface CommandParts {
  readonly argv?: readonly string[] | undefined;
}

/** Quote supplied argv for display, preserving every word boundary; never infer a program. */
export function reconstructCommand(parts: CommandParts): string | undefined {
  return parts.argv !== undefined && parts.argv.length > 0 ? renderArgv(parts.argv) : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function readStringArray(record: Record<string, unknown>, key: string): string[] | undefined {
  const value = record[key];
  if (!Array.isArray(value)) return undefined;
  // Same coercion as the CLI. The core has already parsed this context, so entries are strings.
  return value.map((entry) => String(entry));
}

/**
 * Compare raw caller text with the literal quoted argv form, on unescaped bytes. Every mismatch
 * warns, including formatting-only differences: this never splits raw or claims semantic equivalence.
 * No divergence exists without both caller-supplied forms. The core hashes the original bytes.
 */
export function rawDivergesFromArgv(facts: unknown): boolean {
  if (!isRecord(facts)) return false;
  const raw = readString(facts, "raw");
  if (raw === undefined) return false;
  const argv = readStringArray(facts, "argv");
  return argv !== undefined && argv.length > 0 && renderArgv(argv) !== raw;
}

/**
 * Shown in place of the tool when a request names a `server` but no `tool`: `fs :: (tool missing)`.
 * A real tool literally named `(tool missing)` contains a space, so it is always shown quoted and
 * can't pass for this marker. The CLI uses the same text.
 */
export const TOOL_MISSING = "(tool missing)";

/**
 * Quote one half of a `server :: tool` identity so the split between the two stays visible. A half
 * is shown bare only when it is printable ASCII, contains no `::`, and {@link quoteToken} would
 * leave it bare. Anything else, including any non-ASCII text (which could hold a lookalike of the
 * ` :: ` separator), is single-quoted, so server `fs :: read_file` + tool `delete_all` shows as
 * `'fs :: read_file' :: delete_all`, never like server `fs` + tool `read_file :: delete_all`.
 */
function quoteIdentityPart(part: string): string {
  if (/^[\x21-\x7e]+$/.test(part) && !part.includes("::")) return quoteToken(part);
  return `'${part.replace(/'/g, "'\\''")}'`;
}

/**
 * The `server :: tool` identity of whichever tool-call fields a request carries, each half quoted
 * by {@link quoteIdentityPart}: the tool alone when there is no server, `server :: (tool missing)`
 * when there is no tool, `undefined` when there is neither. Mirrors the CLI's rule in
 * `packages/approver/src/lib/render.ts`.
 */
export function joinToolIdentity(
  server: string | undefined,
  tool: string | undefined,
): string | undefined {
  if (tool === undefined) {
    return server !== undefined ? `${quoteIdentityPart(server)} :: ${TOOL_MISSING}` : undefined;
  }
  const quotedTool = quoteIdentityPart(tool);
  return server !== undefined ? `${quoteIdentityPart(server)} :: ${quotedTool}` : quotedTool;
}

/**
 * What {@link toolIdentity} reads: the request's surface kind (the view model's `kind`, not the
 * wire surface, so `"mcp"` rather than `"mcp_tool_call"`) and its tool-call fields.
 */
export interface ToolIdentityParts {
  readonly kind: ApprovalContext["kind"];
  readonly substrate: { readonly server?: string | undefined; readonly tool?: string | undefined };
}

/**
 * The tool identity a tool-surface request heads with ({@link joinToolIdentity}): `server :: tool`,
 * the tool alone, or `server :: (tool missing)`. A `.` join would make server `fs.delete` + tool
 * `x` look like server `fs` + tool `delete.x`, hence `::`. It is `undefined` on any other surface,
 * or when the request names neither a server nor a tool. On a tool surface `raw` is the caller's
 * description of the call (e.g. OpenClaw's plugin text), not the action (#321). Mirrors the CLI's
 * `toolIdentity` in `packages/approver/src/lib/render.ts`.
 */
export function toolIdentity(parts: ToolIdentityParts): string | undefined {
  const isToolSurface = parts.kind === "mcp" || parts.kind === "agent_tool_call";
  if (!isToolSurface) return undefined;
  return joinToolIdentity(parts.substrate.server, parts.substrate.tool);
}
