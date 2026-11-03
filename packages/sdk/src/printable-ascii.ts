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
 * `text` as printable ASCII (0x20-0x7e):
 *
 * - every UTF-16 unit outside printable ASCII (newlines, ESC, bidi controls, any non-ASCII
 *   character, each half of a surrogate pair) becomes a `\uXXXX` escape;
 * - the backslash becomes `\u005c` too, so a literal `\u001b` in the text reads differently from
 *   an escaped ESC.
 *
 * With `maxChars`, the result is clipped to at most that many characters on an escape boundary
 * (never inside a `\uXXXX`), and `...` is appended when anything was cut.
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
