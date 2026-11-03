/**
 * Third-party text made safe to quote in a deny reason, once the WASM core is loaded.
 *
 * A deny reason is read by the agent. Text a hook quotes in one can come from a third party: an
 * MCP server or tool name, tool input, the gate's one-line summary of the call, or an error from
 * the untrusted relay. A newline there could pose as an allw diagnostic and instruct the agent,
 * and ESC or a bidi control could drive a terminal or reorder text. Every such segment goes through
 * the core's `escape_for_display` (the audited display model, #246), so control, bidi and
 * zero-width characters become visible escapes, and it is capped in length.
 *
 * Unlike the approver's display model, this agent-side copy carries no "hidden or control" flag:
 * the escaped text is all the agent sees, so a literal `\x1b` in the input reads the same as an
 * escaped ESC. That is acceptable here because these are deny-only reasons; nothing the agent reads
 * in them can grant anything.
 *
 * This is for paths that run after the WASM core loads. Before that (config loading, stdin
 * parsing), the SDK's core-free `escapeToPrintableAscii` fallback applies instead (#358).
 */

import type { HookWasm } from "./wasm.js";

/** The most characters of quoted text a deny reason carries (after escaping), plus `…`. */
export const MAX_ERROR_TEXT_CHARS = 256;

/**
 * The longest escape token the core writes, in code points: `⟨U+10FFFF⟩`. The others (`\n`, `\t`,
 * `\r`, `\xNN`) are shorter.
 */
const MAX_ESCAPE_TOKEN_CHARS = 10;

/** A cut `\xNN` token at the end of a clipped string: `\`, `\x` or `\x` and one hex digit. */
const CUT_BACKSLASH_TOKEN = /\\(?:x[0-9a-f]?)?$/u;

/**
 * The first `cap` code points of `chars`, backed up to an escape-token boundary so a token is never
 * cut in half (`⟨U+20` could read as U+0020). It backs up over an unclosed `⟨` within the last
 * token's length, and over a trailing cut `\xNN`. A literal `⟨` or `\` that happens to sit there is
 * dropped too, which only shortens the quote.
 */
function clipOnTokenBoundary(chars: readonly string[], cap: number): string {
  let end = cap;
  const open = chars.lastIndexOf("⟨", end - 1);
  if (open !== -1 && end - open < MAX_ESCAPE_TOKEN_CHARS && !chars.slice(open, end).includes("⟩")) {
    end = open;
  }
  const kept = chars.slice(0, end).join("");
  const cut = CUT_BACKSLASH_TOKEN.exec(kept);
  return cut === null ? kept : kept.slice(0, kept.length - cut[0].length);
}

/** Shown instead of text the core escape could not process. */
const WITHHELD_TEXT = "details withheld (the display-escaping core is unavailable)";

/**
 * `text` through the core's `escape_for_display`, capped at {@link MAX_ERROR_TEXT_CHARS} code
 * points on an escape-token boundary, with `…` appended when cut. If the core escape fails, the
 * text is withheld: the caller still denies, it just can't quote the text.
 */
export function agentSafeText(wasm: HookWasm, text: string): string {
  let escaped: string;
  try {
    escaped = wasm.escape_for_display(text);
  } catch {
    return WITHHELD_TEXT;
  }
  // Cap by code point, so a surrogate pair is never split, and never inside an escape token.
  const chars = Array.from(escaped);
  return chars.length > MAX_ERROR_TEXT_CHARS
    ? `${clipOnTokenBoundary(chars, MAX_ERROR_TEXT_CHARS)}…`
    : escaped;
}

/**
 * The text of an error, made safe to put in a deny reason ({@link agentSafeText}).
 *
 * Errors from `requestApproval` can carry relay-supplied text (a status body, a device id, a JSON
 * parse snippet), and the relay is untrusted; errors from the core's record builders are quoted
 * the same way. Both hooks use this one choke point.
 */
export function agentSafeErrorText(wasm: HookWasm, err: unknown): string {
  return agentSafeText(wasm, err instanceof Error ? err.message : String(err));
}
