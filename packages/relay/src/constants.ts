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

/**
 * How long a terminal (expired / resolved / retracted) request row and its verdict are kept after
 * `terminal_at` before the alarm's sweep deletes them.
 */
export const REQUEST_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

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
 * How far ahead of the relay's clock a submitted `created_at` may be, absorbing clock skew between
 * the integrator and the relay; further ahead gets 400. The bound closes no attack (the window is
 * the submitter's own): it turns a request the device could never verify into a 400 at submit.
 */
export const MAX_CREATED_AT_SKEW_MS = 60 * 1000;

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

/**
 * Largest accepted `POST /{acct}/pairing/start` or `POST /{acct}/pairing/complete` body, in bytes
 * (checked before parsing; larger gets 413). Both bodies are a few keys plus short tokens.
 */
export const MAX_PAIRING_BODY_BYTES = 16 * 1024;

/** Most root-signed documents one `POST /{acct}/account-states` may carry (more gets 400). */
export const MAX_ACCOUNT_STATE_DOCS = 16;

/** Longest accepted account-state document (a compact JWS, so its length is its byte count). */
export const MAX_ACCOUNT_STATE_JWS_BYTES = 32 * 1024;

/**
 * Largest accepted `POST /{acct}/account-states` body, in bytes (checked before parsing; larger
 * gets 413). It is the most a valid publish can need — {@link MAX_ACCOUNT_STATE_DOCS} documents at
 * {@link MAX_ACCOUNT_STATE_JWS_BYTES} each — plus 4 KiB for the JSON framing and `max_sequence`,
 * so the cap never refuses a publish the document checks would accept.
 */
export const MAX_ACCOUNT_STATE_BODY_BYTES =
  MAX_ACCOUNT_STATE_DOCS * MAX_ACCOUNT_STATE_JWS_BYTES + 4 * 1024;

/**
 * The window, in seconds, of every rate-limiting binding in `wrangler.jsonc` (`simple.period`),
 * and so the `Retry-After` a rate-limit 429 sends. The binding's period isn't readable at runtime,
 * so the two are kept equal by hand: a deployment must keep `period` at 60 (a test pins
 * `wrangler.jsonc`).
 */
export const RATE_LIMIT_PERIOD_SECONDS = 60;
