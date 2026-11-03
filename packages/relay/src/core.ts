/**
 * The relay's binding to the audited Rust core (`allw-core`, via the vendored `allw-wasm` build).
 *
 * # Why the relay loads the core
 * The relay makes an account a cryptographic object: it re-derives the account id from a presented
 * root key and verifies root signatures before acting on them (`docs/enrollment.md` §Model). That
 * verification is security-critical, so it runs in the one audited core — never reimplemented in
 * TypeScript (`CLAUDE.md`: one audited Rust core; thin surfaces).
 *
 * # Loading
 * Wrangler and the Vitest workers pool both import a `.wasm` file as a compiled
 * `WebAssembly.Module`; the `--target web` glue is then instantiated synchronously with
 * `initSync`, once per isolate, on first use. The wasm must be built first
 * (`pnpm run build:wasm` from the repo root) — both for `wrangler deploy` and for relay tests.
 *
 * # Fail-closed
 * Every function here throws on any failure (malformed key, bad signature, expired, …). Callers map
 * a throw to a rejection status; there is no non-throwing failure path.
 *
 * @see ../../../docs/enrollment.md §Model
 * @see ../../../crates/allw-wasm/src/lib.rs (the exported functions)
 */

import wasmModule from "@allw/sdk/vendor/allw-wasm/allw_wasm_bg.wasm";
import * as glue from "@allw/sdk/vendor/allw-wasm/allw_wasm.js";

let initialized = false;

/** Instantiate the wasm once per isolate. */
function core(): typeof glue {
  if (!initialized) {
    glue.initSync({ module: wasmModule });
    initialized = true;
  }
  return glue;
}

/** Verified claims of an `allw-pairing-start+jws` (mirrors `allw_core::PairingStartClaims`). */
export interface PairingStartClaims {
  readonly v: number;
  readonly account_id: string;
  readonly issued_at: number;
  readonly expires_at: number;
  readonly jti: string;
}

/**
 * Throws unless `accountId` is exactly the id the core derives from `rootPubkey` (base64url
 * Ed25519). A malformed key also throws.
 */
export function checkAccountIdForRoot(accountId: string, rootPubkey: string): void {
  core().check_account_id_for_root(accountId, rootPubkey);
}

/**
 * Verify a root-signed pairing-start authorization for `accountId` at `nowMs`, returning its
 * claims. Throws on a bad signature, wrong `typ`, wrong account, malformed/overlong window,
 * future-dated or expired authorization. Replay of the returned `jti` is the caller's check.
 */
export function verifyPairingStartAuthorization(
  authorization: string,
  accountId: string,
  rootPubkey: string,
  nowMs: number,
): PairingStartClaims {
  const json = core().verify_pairing_start_authorization(
    authorization,
    accountId,
    rootPubkey,
    nowMs,
  );
  return JSON.parse(json) as PairingStartClaims;
}
