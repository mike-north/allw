/**
 * Relay constants shared between the worker and its tests.
 *
 * These live here (not in the worker entrypoint `index.ts`) because **workerd validates every named
 * export of the entrypoint module** as a potential entrypoint — a bare value export (e.g. a number)
 * makes `wrangler dev` refuse to boot with "the provided value is not of type 'function or
 * ExportedHandler'". Keeping non-handler constants in a sibling module lets the worker import them
 * and tests import them without polluting the entrypoint's export surface.
 *
 * @see https://github.com/cloudflare/workers-sdk/issues/10213
 */

/**
 * Pairing code TTL in milliseconds. Exported so tests can seed deterministically-expired rows
 * without waiting.
 */
export const PAIRING_TTL_MS = 10 * 60 * 1000; // 10 minutes

// ---------------------------------------------------------------------------
// Abuse limits on the unauthenticated `POST /{acct}/requests` (#248). Exported so tests can probe
// each boundary (at the limit and one past it) without restating the numbers.
// ---------------------------------------------------------------------------

/**
 * Largest accepted `POST /{acct}/requests` body, in bytes. Checked before JSON parsing (from
 * `Content-Length` when present, and again while reading the stream), so an oversized body is
 * refused with 413 without being buffered or parsed. Leaves room for the routing fields around a
 * maximum-size {@link MAX_CONTEXT_CIPHERTEXT_BYTES} ciphertext.
 */
export const MAX_REQUEST_BODY_BYTES = 128 * 1024;

/** Largest accepted `context_ciphertext` (UTF-8 bytes of the JWE string); larger gets 413. */
export const MAX_CONTEXT_CIPHERTEXT_BYTES = 64 * 1024;

/**
 * Default request horizon: `expires_at - now` above this gets 400. Fifteen minutes covers the
 * hooks' 420 s `MAX_TIMEOUT_MS` with margin. Self-hosters may override it with the
 * `MAX_REQUEST_TTL_MS` Worker var (see `parseMaxRequestTtlMs`).
 */
export const DEFAULT_MAX_REQUEST_TTL_MS = 15 * 60 * 1000;

/**
 * Most live pending requests one account may hold; the next submit gets 429. Requests past their
 * `expires_at` (or past the horizon), resolved, expired and retracted requests do not count.
 */
export const MAX_PENDING_REQUESTS_PER_ACCOUNT = 64;
