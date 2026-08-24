/**
 * Timeout budgeting — the nesting rule (`docs/openclaw-integration.md` §8).
 *
 * allw's deadline must fire **strictly inside** OpenClaw's, with enough margin left for the verdict
 * to travel and the `approval.resolve` to land. If OpenClaw times out first, the human's decision is
 * discarded and the outcome is OpenClaw's `askFallback` rather than a verified verdict.
 *
 * OpenClaw's deadline is never hardcoded: every approval carries an authoritative `expiresAtMs`, and
 * the gateway's clock is authoritative for it (§8) — this module therefore takes `nowMs` from the
 * caller rather than reading a clock itself, so tests drive it deterministically and the production
 * caller can feed a gateway-derived reference time.
 *
 * @see ../../../../docs/openclaw-integration.md §8
 */

/** Result of budgeting one approval against its `expiresAtMs`. */
export type BudgetOutcome =
  | { readonly kind: "ok"; readonly timeoutMs: number }
  /** Below `ALLW_OPENCLAW_MIN_TIMEOUT_MS`: deny immediately, raise no allw request (§8, §9). */
  | { readonly kind: "insufficient"; readonly budgetMs: number };

/** Inputs to {@link deriveTimeout}. */
export interface BudgetInput {
  /** The gateway's authoritative deadline for this approval. */
  readonly expiresAtMs: number;
  /** Reference "now" in the same epoch as `expiresAtMs`. */
  readonly nowMs: number;
  readonly deadlineMarginMs: number;
  readonly minTimeoutMs: number;
  readonly maxTimeoutMs: number;
}

/**
 * ```
 * budget_ms  = expiresAtMs − now_ms − ALLW_DEADLINE_MARGIN_MS
 * timeout_ms = min(budget_ms, ALLW_OPENCLAW_MAX_TIMEOUT_MS)
 * if budget_ms < ALLW_OPENCLAW_MIN_TIMEOUT_MS ⇒ deny (`insufficient-budget`)
 * ```
 *
 * The cap only ever *lowers* the budget, so a generous operator cap can never push allw's deadline
 * past the gateway's.
 */
export function deriveTimeout(input: BudgetInput): BudgetOutcome {
  const budgetMs = input.expiresAtMs - input.nowMs - input.deadlineMarginMs;
  if (budgetMs < input.minTimeoutMs) return { kind: "insufficient", budgetMs };
  return { kind: "ok", timeoutMs: Math.min(budgetMs, input.maxTimeoutMs) };
}
