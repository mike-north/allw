/**
 * The single deadline of a stored approval request, and the one liveness rule built on it (#292).
 *
 * A pending request stops being live at its **deadline**: the earlier of the envelope's
 * `expires_at` and the request horizon measured from when the relay stored it
 * (`created_at + maxRequestTtlMs`). Every lifecycle decision reads this one value: the submit
 * check, the expiry alarm and its sweep, inbox and reconnect-flush delivery, lazy expiry on read,
 * wait and retract, verdict acceptance, and the deadline a push wakeup carries. A row is live
 * strictly before its deadline and expired at or after it, so no path can deliver or resolve a
 * request another path has already treated as expired.
 *
 * `created_at` here is the `request.created_at` **column**: the relay's own clock when it accepted
 * the submit. It is not the envelope's `created_at`, which the submitter chose and which only
 * bounds the verdict's `decided_at` window. The horizon is a relay-side storage limit, so it is
 * measured from the relay's receipt time. Since submit refuses an `expires_at` beyond the horizon,
 * the cap only bites for rows stored before the horizon existed or before an operator lowered
 * `MAX_REQUEST_TTL_MS`.
 *
 * @see ../../../docs/relay-api.md §3 Integrator endpoints (the request horizon)
 * @see ../../../docs/contract.md §Lifecycle (fail-closed expiry)
 */

/** The lifecycle columns of a stored `request` row that its deadline depends on. */
export interface RequestDeadlineFields {
  /** Relay receipt time (epoch ms) — the `request.created_at` column, never the envelope's. */
  readonly created_at: number;
  /** The envelope's `expires_at` (epoch ms). */
  readonly expires_at: number;
}

/** The row's deadline (epoch ms): `min(expires_at, created_at + maxRequestTtlMs)`. */
export function deadlineOf(row: RequestDeadlineFields, maxRequestTtlMs: number): number {
  return Math.min(row.expires_at, row.created_at + maxRequestTtlMs);
}

/**
 * {@link deadlineOf} as a SQL expression over the `request` table's columns, for queries that
 * filter or order by deadline. It has one `?` placeholder, which binds `maxRequestTtlMs`.
 */
export const DEADLINE_SQL = "MIN(expires_at, created_at + ?)";
