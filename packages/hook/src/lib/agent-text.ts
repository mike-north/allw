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
 * This is for paths that run after the WASM core loads. Before that (config loading, stdin
 * parsing), the SDK's core-free `escapeToPrintableAscii` fallback applies instead (#358).
 */

import type { HookWasm } from "./wasm.js";

/** The most characters of quoted text a deny reason carries (after escaping), plus `…`. */
export const MAX_ERROR_TEXT_CHARS = 256;

/** Shown instead of text the core escape could not process. */
const WITHHELD_TEXT = "details withheld (the display-escaping core is unavailable)";

/**
 * `text` through the core's `escape_for_display`, capped at {@link MAX_ERROR_TEXT_CHARS} code
 * points with `…` appended when cut. If the core escape fails, the text is withheld: the caller
 * still denies, it just can't quote the text.
 */
export function agentSafeText(wasm: HookWasm, text: string): string {
  let escaped: string;
  try {
    escaped = wasm.escape_for_display(text);
  } catch {
    return WITHHELD_TEXT;
  }
  // Cap by code point, so a surrogate pair is never split.
  const chars = Array.from(escaped);
  return chars.length > MAX_ERROR_TEXT_CHARS
    ? `${chars.slice(0, MAX_ERROR_TEXT_CHARS).join("")}…`
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
