/**
 * A core-free escape for diagnostic text: error messages built before, or without, the WASM core.
 *
 * Untrusted or environment-sourced text in an error (a cause's message, an `ALLW_CONFIG` path, an
 * env value) can reach a terminal or a hook's deny reason, which an agent reads. A newline or
 * control character there can forge lines. The audited display escape (`escape_for_display`, #246)
 * lives in the WASM core, which these paths either can't rely on (config loading runs before the
 * hooks load the core) or is itself what failed (`wasmLoadError`). So they use this: a strict
 * allowlist that reduces any text to printable ASCII.
 *
 * It is **not** the display model and must not replace it for anything a human reviews (approval
 * context, relay-supplied text on approver screens). It only makes a diagnostic safe and
 * unambiguous to print.
 */

/**
 * The bound, in characters of escaped output, for environment- or input-sourced text quoted in a
 * diagnostic (a config path, an env value, a hook input field, an unexpected error's message). It
 * keeps a hostile value from inflating an error or deny reason: 100 KB of ESC would otherwise
 * escape to 600 KB. Long enough for any real path or value to read in full.
 */
export const MAX_ESCAPED_DIAGNOSTIC_CHARS = 512;

/**
 * `text` as printable ASCII (0x20-0x7e):
 *
 * - every UTF-16 unit outside printable ASCII (newlines, ESC, bidi controls, any non-ASCII
 *   character, each half of a surrogate pair) becomes a `\uXXXX` escape;
 * - the backslash becomes `\u005c` too, so a literal `\u001b` in the text reads differently from
 *   an escaped ESC.
 *
 * With `maxChars`, at most that many characters of escaped text are kept, cut on an escape
 * boundary (never inside a `\uXXXX`). `maxChars` is the budget before the marker: when anything
 * was cut, `...` is appended, so a clipped result is up to `maxChars + 3` characters long.
 */
export function escapeToPrintableAscii(text: string, maxChars?: number): string {
  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    const token =
      unit >= 0x20 && unit <= 0x7e && unit !== 0x5c
        ? text.charAt(i)
        : `\\u${unit.toString(16).padStart(4, "0")}`;
    if (maxChars !== undefined && out.length + token.length > maxChars) return `${out}...`;
    out += token;
  }
  return out;
}
