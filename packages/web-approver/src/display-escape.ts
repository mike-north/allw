/**
 * How the web approver prints untrusted text that appears before the inbox's runtime exists: a
 * stored relay pin on the re-pair screen (#286), or an ignored `?relay=` link in the notice (#307).
 *
 * The display model (`docs/threat-model.md`, #246/#259) lets a surface print an untrusted string
 * only through the core's `escape_for_display`, never raw and never escaped by the surface itself.
 * The core is WASM and may not have loaded, so each such string is either the core's escape of it
 * or a fixed withheld text. Nothing here inspects or rewrites the string.
 */

/**
 * Escapes one untrusted string for display: the core's `escape_for_display` (#246), reached through
 * WASM. Every surface prints untrusted text only through the core (`docs/threat-model.md` R3).
 */
export type DisplayEscape = (text: string) => string;

/**
 * Shown in place of an untrusted string when the core escape is unavailable (the WASM core did not
 * load, or the escape threw): the text is withheld rather than printed unescaped or escaped by
 * this surface.
 */
export const WITHHELD_UNTRUSTED_TEXT = "(hidden: the approver core did not load)";

/**
 * `untrusted` as it may be shown: the core's escape of it, or {@link WITHHELD_UNTRUSTED_TEXT} when
 * there is no core escape or it throws.
 */
export function displayUntrusted(
  untrusted: string,
  escapeForDisplay: DisplayEscape | null,
): string {
  if (escapeForDisplay === null) return WITHHELD_UNTRUSTED_TEXT;
  try {
    return escapeForDisplay(untrusted);
  } catch {
    return WITHHELD_UNTRUSTED_TEXT;
  }
}
