/**
 * Ambient declarations for the vendored `allw-wasm` build (the audited Rust core compiled to
 * WebAssembly, `pnpm run build:wasm` → `packages/sdk/vendor/allw-wasm`), as the relay imports it.
 *
 * # Why hand-written
 * The wasm + its generated `.d.ts` are build artifacts (gitignored). Declaring the exact subset the
 * relay (and its tests) call keeps `typecheck`/`lint` independent of whether the wasm has been
 * built, and an exact-name ambient declaration takes precedence over the generated file, so the
 * relay type-checks identically either way. `test/core.test.ts` asserts at runtime that every
 * function declared here exists in the real glue, so a renamed export cannot drift silently.
 * This mirrors the narrow-interface pattern in `packages/approver/src/lib/wasm.ts`.
 *
 * Every function takes/returns strings (JSON or base64url) and throws a JS `Error` on any failure
 * — fail-closed at the boundary. Signatures mirror `crates/allw-wasm/src/lib.rs`.
 */

/** Wrangler and the Vitest workers pool load a `.wasm` import as a compiled module. */
declare module "*.wasm" {
  const module: WebAssembly.Module;
  export default module;
}

declare module "@allw/sdk/vendor/allw-wasm/allw_wasm.js" {
  /** Instantiate the glue from an already-compiled module. Idempotent. */
  export function initSync(input: { module: WebAssembly.Module }): unknown;

  /** Self-certifying account id for an account-root Ed25519 public key (base64url). */
  export function account_id_for_root(account_root_pubkey_b64: string): string;

  /** Throws unless `account_id` is exactly the id derived from the root public key. */
  export function check_account_id_for_root(
    account_id: string,
    account_root_pubkey_b64: string,
  ): void;

  /** Verify an `allw-pairing-start+jws`; returns the verified `PairingStartClaims` JSON. */
  export function verify_pairing_start_authorization(
    authorization: string,
    expected_account_id: string,
    account_root_pubkey_b64: string,
    now_ms: number,
  ): string;

  /** Sign an `allw-pairing-start+jws` with an account-root seed (tests act as the root holder). */
  export function sign_pairing_start_authorization(
    account_root_seed_b64: string,
    issued_at: number,
    expires_at: number,
    jti: string,
  ): string;

  /** Ed25519 public key for a 32-byte signing seed (base64url). */
  export function ed25519_public_key(seed_b64: string): string;
}
