/**
 * Test-side account-root holder for relay tests.
 *
 * Accounts are self-certifying (`docs/enrollment.md` §Model): an account id is derived from its
 * root public key, and `POST /{acct}/pairing/start` must carry a root-signed authorization. Tests
 * keep human-readable account *names* for isolation (one Durable Object per name); `testAccount`
 * turns a name into a deterministic root (seed = SHA-256 of the name) and returns the derived id,
 * so each test still gets a fresh, distinct account.
 *
 * All signing/derivation goes through the same vendored `allw-wasm` core the relay uses — the
 * tests never reimplement crypto.
 *
 * # Clock
 * The relay verifies freshness against its own `Date.now()`, which tests cannot inject. Default
 * authorizations are therefore issued relative to the current clock, with windows of minutes so
 * results never depend on scheduling. Negative tests shift the window explicitly.
 *
 * @see ../../../../docs/enrollment.md §Model
 * @see ../../../../docs/relay-api.md §3 Pairing
 */

import { createHash } from "node:crypto";
import wasmModule from "@allw/sdk/vendor/allw-wasm/allw_wasm_bg.wasm";
import * as glue from "@allw/sdk/vendor/allw-wasm/allw_wasm.js";

glue.initSync({ module: wasmModule });

/** A test account: its derived id plus the root key material the test holds. */
export interface TestAccount {
  readonly id: string;
  readonly rootSeed: string;
  readonly rootPubkey: string;
}

const accountsById = new Map<string, TestAccount>();

/** Deterministic root key material for a test account name. */
export function testRoot(name: string): TestAccount {
  const rootSeed = createHash("sha256").update(`allw-relay-test-root/${name}`).digest("base64url");
  const rootPubkey = glue.ed25519_public_key(rootSeed);
  const id = glue.account_id_for_root(rootPubkey);
  const account = { id, rootSeed, rootPubkey };
  accountsById.set(id, account);
  return account;
}

/** The self-certifying account id for a test account name (registers its root). */
export function testAccount(name: string): string {
  return testRoot(name).id;
}

/** The root key material for an account id created by {@link testAccount}. */
export function rootFor(accountId: string): TestAccount {
  const account = accountsById.get(accountId);
  if (!account) {
    throw new Error(`no test root registered for account ${accountId}; use testAccount(name)`);
  }
  return account;
}

/** Default authorization lifetime: 2 minutes (the core accepts up to 5). */
export const DEFAULT_AUTH_LIFETIME_MS = 2 * 60 * 1000;

let jtiCounter = 0;

/** A fresh, well-formed one-time id (16–128 base64url chars). */
export function freshJti(): string {
  jtiCounter += 1;
  return `test-jti-${String(jtiCounter).padStart(8, "0")}-${crypto.randomUUID()}`;
}

/** Options for a signed pairing-start authorization. */
export interface AuthorizationOptions {
  readonly issuedAt?: number;
  readonly expiresAt?: number;
  readonly jti?: string;
}

/** Sign an `allw-pairing-start+jws` with the account's root. */
export function signPairingStart(accountId: string, options: AuthorizationOptions = {}): string {
  const root = rootFor(accountId);
  const issuedAt = options.issuedAt ?? Date.now();
  const expiresAt = options.expiresAt ?? issuedAt + DEFAULT_AUTH_LIFETIME_MS;
  return glue.sign_pairing_start_authorization(
    root.rootSeed,
    issuedAt,
    expiresAt,
    options.jti ?? freshJti(),
  );
}

/** A valid `POST /{acct}/pairing/start` body for the account (optionally labelled). */
export function pairingStartBody(
  accountId: string,
  label?: string,
  options: AuthorizationOptions = {},
): Record<string, unknown> {
  return {
    root_pubkey: rootFor(accountId).rootPubkey,
    authorization: signPairingStart(accountId, options),
    ...(label === undefined ? {} : { label }),
  };
}
