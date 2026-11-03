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
 * A failure to instantiate the wasm itself is the relay's fault, not the caller's, so it throws a
 * distinct {@link CoreUnavailableError}; handlers call {@link ensureCore} first and map that to a
 * 500 (still fail-closed) instead of blaming the request.
 *
 * @see ../../../docs/enrollment.md §Model
 * @see ../../../crates/allw-wasm/src/lib.rs (the exported functions)
 */

import wasmModule from "@allw/sdk/vendor/allw-wasm/allw_wasm_bg.wasm";
import * as glue from "@allw/sdk/vendor/allw-wasm/allw_wasm.js";

let initialized = false;

/** The audited core could not be instantiated (a bad build or runtime change), not a bad input. */
export class CoreUnavailableError extends Error {
  constructor(cause: unknown) {
    super("allw core wasm failed to initialize", { cause });
    this.name = "CoreUnavailableError";
  }
}

/** Instantiate the wasm once per isolate; throws {@link CoreUnavailableError} if it cannot. */
function core(): typeof glue {
  if (!initialized) {
    try {
      glue.initSync({ module: wasmModule });
    } catch (cause) {
      throw new CoreUnavailableError(cause);
    }
    initialized = true;
  }
  return glue;
}

/**
 * Instantiate the core now, so a handler can tell "the relay's core is broken" (500) apart from
 * "the request failed verification" (4xx). Throws {@link CoreUnavailableError}.
 */
export function ensureCore(): void {
  core();
}

/** Verified claims of an `allw-pairing-start+jws` (mirrors `allw_core::PairingStartClaims`). */
export interface PairingStartClaims {
  readonly v: number;
  readonly account_id: string;
  readonly issued_at: number;
  readonly expires_at: number;
  readonly jti: string;
}

/** The fields of a verified `AccountState` the relay reads (mirrors `allw_core::AccountState`). */
export interface VerifiedAccountState {
  readonly v: number;
  readonly account_id: string;
  /**
   * Monotonic sequence. A `u64` in the core; JSON-parsed here, so a value above 2^53-1 is not
   * exactly representable — callers must reject it (`Number.isSafeInteger`).
   */
  readonly sequence: number;
}

/**
 * Verify a root-signed `allw-account-state+jws` for `accountId` against `rootPubkey`. Throws on a
 * bad signature, wrong `typ`, wrong account id or `current_root`, unsupported version, or junk.
 */
export function verifyAccountState(
  stateJws: string,
  accountId: string,
  rootPubkey: string,
): VerifiedAccountState {
  return JSON.parse(
    core().verify_account_state(stateJws, accountId, rootPubkey),
  ) as VerifiedAccountState;
}

/**
 * Whether `pubkey` (base64url-unpadded, 32 bytes) is one of the core's small-order X25519 points
 * (`allw_core::X25519_SMALL_ORDER_POINTS`, matched with bit 255 masked). Every ECDH with such a key
 * yields a publicly known shared secret, so it can never be an encryption target. The relay keeps
 * no copy of the list; the core is the single source. A key that is not 32 base64url bytes throws.
 */
export function isSmallOrderX25519PublicKey(pubkey: string): boolean {
  return core().is_small_order_x25519_public_key(pubkey);
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
