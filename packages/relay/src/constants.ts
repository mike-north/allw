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
