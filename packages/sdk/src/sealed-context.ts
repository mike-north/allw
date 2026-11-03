/**
 * Validation of the core's `seal_context_for_account_state` result.
 *
 * The core returns `{ ciphertext, sequence }`: the JWE the request carries and the account-state
 * sequence whose devices it was sealed to. Both drive security decisions in the SDK. The sequence
 * is persisted as the rollback floor before the request is sent, and the ciphertext is what the
 * relay delivers. So this module accepts only a result that could have come from a successful seal:
 * a non-empty ciphertext string and a non-negative safe-integer sequence. Anything else is reported
 * as malformed, and the caller fails closed. Kept separate from `index.ts` so the check can be
 * tested directly; the WASM module itself cannot be substituted in tests.
 */

/** The core's sealed-context result (`seal_context_for_account_state`). */
export interface SealedContext {
  /** The JWE of the `ApprovalContext`, with one recipient per selected device. */
  readonly ciphertext: string;
  /** The account-state sequence the recipients were selected from (never the floor itself). */
  readonly sequence: number;
}

/**
 * Parse the core's JSON result, returning `null` unless it is an object with a non-empty string
 * `ciphertext` and a non-negative safe-integer `sequence`.
 */
export function parseSealedContext(json: string): SealedContext | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const { ciphertext, sequence } = parsed as Record<string, unknown>;
  if (typeof ciphertext !== "string" || ciphertext.length === 0) return null;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0) return null;
  return { ciphertext, sequence };
}
