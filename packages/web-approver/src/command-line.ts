/**
 * How the web approver lays out command-form substrate fields as text: token quoting, list joining,
 * reconstructing a command line from `bin`/`argv`, and detecting when that reconstruction differs
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
 * Join list items (paths, env refs, chain ids) with `, `, each quoted by {@link quoteToken}, so an
 * item containing `, ` stays visibly one item.
 */
export function renderList(items: readonly string[]): string {
  return items.map(quoteToken).join(", ");
}

/** The command-form fields a command line is reconstructed from. */
export interface CommandParts {
  readonly bin?: string | undefined;
  readonly argv?: readonly string[] | undefined;
  readonly positionals?: readonly string[] | undefined;
}

/**
 * The command line `bin`/`argv` describe, or `undefined` when there is no command form. `bin` is
 * prepended unless `argv` already starts with it; with no `argv`, `bin` and any `positionals` are
 * used, so a program name is never dropped.
 *
 * Applied to the raw wire substrate it gives the value divergence is decided on; applied to the
 * core-escaped substrate it gives the line that is shown.
 */
export function reconstructCommand(parts: CommandParts): string | undefined {
  const tokens = commandTokens(parts);
  return tokens === undefined ? undefined : renderArgv(tokens);
}

/**
 * The command-form tokens {@link reconstructCommand} renders, or `undefined` when there is no
 * command form.
 */
function commandTokens(parts: CommandParts): readonly string[] | undefined {
  const { argv, bin } = parts;
  if (argv !== undefined && argv.length > 0) {
    return bin !== undefined && argv[0] !== bin ? [bin, ...argv] : argv;
  }
  if (bin !== undefined) {
    const positionals = parts.positionals;
    return positionals !== undefined ? [bin, ...positionals] : [bin];
  }
  return undefined;
}

/**
 * Whether `tokens` are exactly `raw` split at ASCII whitespace (space, tab, line feed: the only
 * characters `shlex` splits on). Such an argv carries raw's bytes in raw's order and can't say
 * anything raw doesn't, so it is not a divergence. Any other separator, including a Unicode space or
 * a carriage return, stays inside a token here, so an argv split on it still diverges.
 */
function isWhitespaceSplitOf(tokens: readonly string[], raw: string): boolean {
  const words = raw.split(/[ \t\n]+/).filter((word) => word !== "");
  return words.length === tokens.length && words.every((word, i) => word === tokens[i]);
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
 * Whether the hash-bound `bin`/`argv` describes a different command than `raw`.
 *
 * Both halves are bound into `request_hash`, so an integrator could pair a benign `raw` with a
 * dangerous `argv`. This compares the **raw** (unescaped) substrate, because distinct inputs can
 * escape to the same text. Returns false when there is no `raw` or no command form, and when the
 * tokens are exactly `raw`'s ASCII-whitespace split (display quoting alone, such as a quoted
 * `C:\Users` path, is not a different command).
 *
 * @param syntactic the decrypted wire `syntactic` substrate (untrusted; any shape is tolerated)
 */
export function rawDivergesFromArgv(syntactic: unknown): boolean {
  if (!isRecord(syntactic)) return false;
  const raw = readString(syntactic, "raw");
  if (raw === undefined) return false;
  const tokens = commandTokens({
    bin: readString(syntactic, "bin"),
    argv: readStringArray(syntactic, "argv"),
    positionals: readStringArray(syntactic, "positionals"),
  });
  if (tokens === undefined || isWhitespaceSplitOf(tokens, raw)) return false;
  return renderArgv(tokens) !== raw;
}
