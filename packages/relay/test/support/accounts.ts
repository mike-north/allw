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

/** Options for a root-signed account-state document. */
export interface AccountStateOptions {
  /**
   * The `sequence` claim. A `bigint` (or a decimal string) is written into the JSON verbatim, so a
   * test can sign a sequence above 2^53-1 that a JS number cannot represent.
   */
  readonly sequence: number | bigint | string;
  /** The `account_id` claim (default: the signing account's own id). */
  readonly accountId?: string;
  /** The `current_root` claim (default: the signing account's own root). */
  readonly currentRoot?: string;
  /** Device ids recorded as revoked in the document. */
  readonly revokedDevices?: readonly string[];
}

/**
 * Sign an `allw-account-state+jws` with `signer`'s root (the core's `sign_account_state`). The
 * claims default to an honest document for `signer`'s own account; overrides build the forged or
 * mismatched documents the relay must reject.
 */
export function signAccountState(signer: TestAccount, options: AccountStateOptions): string {
  const claims = {
    v: 1,
    account_id: options.accountId ?? signer.id,
    sequence: "__SEQUENCE__",
    current_root: options.currentRoot ?? signer.rootPubkey,
    previous_roots: [],
    devices: [],
    actors: [],
    revocations: (options.revokedDevices ?? []).map((id) => ({
      kind: "device",
      id,
      revoked_at: 1_700_000_000_000,
    })),
  };
  const sequence =
    typeof options.sequence === "string" ? options.sequence : String(options.sequence);
  // Spliced into the JSON verbatim, so fail here — not inside the core's JSON parser — on anything
  // that is not a plain non-negative decimal integer.
  if (!/^(0|[1-9][0-9]*)$/.test(sequence)) {
    throw new Error(
      `signAccountState: sequence must be a non-negative decimal integer, got ${sequence}`,
    );
  }
  const json = JSON.stringify(claims).replace('"__SEQUENCE__"', sequence);
  return glue.sign_account_state(json, signer.rootSeed);
}

/** Test device certificates are issued at this fixed time (Unix ms), with no expiry by default. */
export const TEST_CERT_ISSUED_AT = 1_700_000_000_000;
/**
 * The fixed `decided_at` of test verdicts (Unix ms, after {@link TEST_CERT_ISSUED_AT}). The relay
 * judges the certificate's expiry at `decided_at`, not its own clock, so fixtures stay deterministic.
 */
export const TEST_DECIDED_AT = 1_700_000_500_000;

/** Options for a device-signed verdict. */
export interface VerdictOptions {
  /** The signed decision (default `approved`). */
  readonly decision?: "approved" | "denied" | "expired" | "aborted";
  /**
   * The signed `decided_at` (default {@link TEST_DECIDED_AT}). The relay accepts it only inside the
   * request envelope's `[created_at, expires_at]`, and the certificate must be valid at it.
   */
  readonly decidedAt?: number;
  /**
   * The root that certifies the device key (default: the account's own root). Another account's
   * root yields a certificate the relay must not accept.
   */
  readonly certifiedBy?: TestAccount;
  /** Sign with a key the certificate does not vouch for (an uncertified key). */
  readonly uncertifiedKey?: boolean;
  /** The certificate's `expires_at` (default: none). */
  readonly certExpiresAt?: number;
}

/** A test device's deterministic Ed25519 signing seed. */
function deviceSeed(accountId: string, deviceId: string, salt = "device"): string {
  return createHash("sha256")
    .update(`allw-relay-test-${salt}/${accountId}/${deviceId}`)
    .digest("base64url");
}

/**
 * A genuinely signed `Verdict` (the core's `sign_verdict`) from `deviceId` of `accountId` for
 * `requestId`, with a device certificate issued by the account's root, as a real approver device
 * sends it. The `request_hash` is a fixed placeholder: the relay never sees the plaintext, and its
 * provenance check does not bind the hash. Options build the verdicts the relay must refuse.
 */
export function signTestVerdict(
  accountId: string,
  deviceId: string,
  requestId: string,
  options: VerdictOptions = {},
): Record<string, unknown> {
  const root = options.certifiedBy ?? rootFor(accountId);
  const seed = deviceSeed(accountId, deviceId);
  const cert = glue.issue_device_cert(
    root.rootSeed,
    accountId,
    deviceId,
    glue.ed25519_public_key(seed),
    TEST_CERT_ISSUED_AT,
    options.certExpiresAt ?? null,
  );
  const unsigned = {
    v: 1,
    request_id: requestId,
    request_hash: "ZmFrZS1yZXF1ZXN0LWhhc2gtMzItYnl0ZXMtYjY0dXI",
    decision: options.decision ?? "approved",
    decided_at: options.decidedAt ?? TEST_DECIDED_AT,
    approver: { account_id: accountId, device_id: deviceId },
  };
  const signingSeed = options.uncertifiedKey ? deviceSeed(accountId, deviceId, "rogue") : seed;
  return JSON.parse(
    glue.sign_verdict(
      JSON.stringify(unsigned),
      signingSeed,
      createHash("sha256").update(crypto.randomUUID()).digest("base64url"),
      cert,
    ),
  ) as Record<string, unknown>;
}
