/**
 * Constant-time comparison of a presented bearer token's hash with a row's stored token hash.
 *
 * The relay stores only `SHA-256(token)` (base64url) for each token-guarded row (a request, a pairing
 * code, a device). Whether a row exists must not show in how the relay answers, including in how
 * long it takes (`docs/relay-api.md` §1, #357). So the constant-time compare runs on every path,
 * against a same-length stand-in when there is no stored hash, and the result is decided only
 * afterwards.
 *
 * Hashing the presented token is the caller's job (it is async Web Crypto); this module is pure so
 * that the "the compare always runs" rule is unit-testable.
 */

/**
 * Stands in for a missing stored hash, so the compare does the same work as against a real one.
 * The same length as a base64url SHA-256 digest (43 characters). It is never treated as a match:
 * {@link matchesStoredHash} rejects a missing hash after comparing.
 */
const ABSENT_STORED_HASH = "A".repeat(43);

/** Compare two strings in time that depends only on their lengths, not on where they differ. */
export function timingSafeEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/**
 * Whether `presentedHash` (the hash of the bearer token the caller presented) equals `storedHash`.
 * `null` stored hash (no row, or a row from before token hashes were stored) never matches, but the
 * constant-time `compare` still runs against {@link ABSENT_STORED_HASH}, so a missing hash costs
 * the same comparison as a mismatched one. `compare` is injectable only so tests can observe that.
 */
export function matchesStoredHash(
  storedHash: string | null,
  presentedHash: string,
  compare: (a: string, b: string) => boolean = timingSafeEqual,
): boolean {
  const equal = compare(storedHash ?? ABSENT_STORED_HASH, presentedHash);
  return storedHash !== null && equal;
}
