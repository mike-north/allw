/**
 * `allw-approver pair` — enroll this software approver as a device on an account.
 *
 * Flow (`docs/contract.md` §Lifecycle / §Transport → pairing; relay #89 auth; #242):
 * 0. Check the relay URL against the transport rule (`https:`, or `http:` on loopback; #267) before
 *    touching the keyfile or the relay.
 * 1. Load (or generate) the local keyfile — three software-held seeds + derived pubkeys.
 * 1a. Derive the **self-certifying account id** from the keyfile's account-root pubkey
 *    (`docs/enrollment.md` §Self-Certifying Account Id). An explicit `accountId` is accepted only
 *    when it equals the derived id — the relay would reject any other id anyway.
 * 2. Obtain a pairing code: use `--code <code>` if supplied, else drive `POST /pairing/start`
 *    ourselves with a fresh root-signed authorization. The matching pairing auth token authorizes
 *    `/pairing/complete`.
 * 3. `POST /pairing/complete` registering the device **X25519** public key → relay-assigned
 *    `device_id` and relay `device_auth_token`.
 * 4. Mint a **device_cert** (`issue_device_cert`): the account-root key signs the device Ed25519
 *    verifying key → cert, so verifiers need only the account-root key.
 * 5. Persist relay/account/device + cert into the keyfile, and print the **account id** and the
 *    **account-root pubkey** (the integrator's routing id and trust anchor, #12).
 */

import { randomBytes } from "node:crypto";

import { generateKeyfile, loadKeyfile, writeKeyfile, type Keyfile } from "../lib/keyfile.js";
import { pairingComplete, pairingStart } from "../lib/relay-client.js";
import { assertCliRelayUrl } from "../lib/relay-url.js";
import type { AllwWasm } from "../lib/wasm.js";

/** Options for `pair`, parsed from argv by the CLI. */
export interface PairOptions {
  /**
   * Relay base URL. Must pass the relay transport rule (`../lib/relay-url.ts`: `https:`, or `http:`
   * on loopback), or `runPair` throws before touching the keyfile or the relay.
   */
  readonly relayUrl: string;
  /**
   * Optional explicit account id. The id is derived from the keyfile's account root; when this is
   * supplied it must equal the derived id, or pairing fails before contacting the relay.
   */
  readonly accountId?: string;
  readonly keyfilePath: string;
  readonly label?: string;
  /** An existing pairing code (account owner ran `/pairing/start`); omit to self-drive start. */
  readonly code?: string;
  /** Bearer token returned with an externally-started pairing code. */
  readonly pairingAuthToken?: string;
  /** Current time (ms) — injectable for deterministic tests; defaults to `Date.now()`. */
  readonly now?: number;
}

/** Lifetime of the root-signed pairing-start authorization `pair` sends (the core allows ≤ 5 min). */
export const PAIRING_START_AUTH_LIFETIME_MS = 2 * 60 * 1000;

/** A sink for human-facing output (stdout by default; captured in tests). */
export type Logger = (line: string) => void;

/**
 * Load the existing keyfile, or generate a fresh identity ONLY when none exists.
 *
 * A fresh identity is minted **exclusively** when the keyfile is genuinely absent (ENOENT). On any
 * other load failure — invalid JSON, failed validation, a permission/I/O error — `loadKeyfile`
 * throws and we let it propagate: silently regenerating would discard an existing (possibly
 * relay-registered) identity and its only copy of the seeds (review item #4).
 */
function loadOrGenerate(wasm: AllwWasm, path: string): { keyfile: Keyfile; fresh: boolean } {
  const loaded = loadKeyfile(path); // throws on corrupt/unreadable — do NOT regenerate over it
  if (loaded.kind === "absent") {
    return { keyfile: { ...generateKeyfile(wasm) }, fresh: true };
  }
  return { keyfile: loaded.keyfile, fresh: false };
}

/**
 * Run the pairing flow. Returns the updated keyfile (also persisted to disk). Throws fail-closed on
 * any relay error or malformed response — a partial pairing is never written.
 */
export async function runPair(
  wasm: AllwWasm,
  options: PairOptions,
  rawLog: Logger = console.log,
): Promise<Keyfile> {
  // The pairing code and device_id come from the relay: every printed line goes through the core's
  // display escape so relay-supplied text cannot carry terminal control sequences (#246).
  const log: Logger = (line) => {
    rawLog(wasm.escape_for_display(line));
  };
  // Reject a plaintext or malformed relay URL first (#267): before any request is built, and
  // before a fresh keyfile is generated or written, so a refused `pair` leaves nothing behind.
  // From here on only the canonical form is used: for every request and for the persisted relay_url.
  const relayUrl = assertCliRelayUrl(options.relayUrl, "--relay");
  const now = options.now ?? Date.now();
  const { keyfile: existing, fresh } = loadOrGenerate(wasm, options.keyfilePath);

  // 0. Crash-safety: if we just generated the seeds, persist the (unpaired) keyfile to disk BEFORE
  // registering with the relay. Otherwise a crash between registration and the final write would
  // leave a device enrolled on the relay whose only copy of the seeds was lost — unrecoverable.
  // A subsequent re-run reuses these persisted seeds (loadOrGenerate reads them back).
  if (fresh) {
    writeKeyfile(options.keyfilePath, existing);
  }

  // 0a. The account id is a function of the account root, never chosen.
  const accountId = wasm.account_id_for_root(existing.account_root_pubkey);
  if (options.accountId !== undefined && options.accountId !== accountId) {
    throw new Error(
      `--account ${options.accountId} does not match the account id derived from this keyfile's ` +
        `account root (${accountId}); omit --account to use the derived id`,
    );
  }

  // 1. Obtain a pairing code (supplied or self-driven).
  let code = options.code;
  let pairingAuthToken = options.pairingAuthToken;
  if (code === undefined) {
    // A fresh one-time jti (128 random bits) and a short window: the relay rejects reuse.
    const authorization = wasm.sign_pairing_start_authorization(
      existing.account_root_seed,
      now,
      now + PAIRING_START_AUTH_LIFETIME_MS,
      randomBytes(16).toString("base64url"),
    );
    const started = await pairingStart(
      relayUrl,
      accountId,
      { rootPubkey: existing.account_root_pubkey, authorization },
      options.label,
    );
    code = started.code;
    pairingAuthToken = started.pairing_auth_token;
    log(`Started pairing — code ${code} (expires ${new Date(started.expires_at).toISOString()})`);
  } else if (pairingAuthToken === undefined) {
    throw new Error("an externally supplied pairing code also requires its pairing auth token");
  }

  // 2. Complete pairing: register the device X25519 (encryption) key → device_id.
  const paired = await pairingComplete(
    relayUrl,
    accountId,
    code,
    pairingAuthToken,
    existing.device_encryption_pubkey,
    options.label,
  );
  const deviceId = paired.device_id;
  log(`Paired — device_id ${deviceId}`);

  // 3. Mint the device certificate: account-root signs the device Ed25519 verifying key.
  const deviceCert = wasm.issue_device_cert(
    existing.account_root_seed,
    accountId,
    deviceId,
    existing.device_signing_pubkey,
    now,
  );

  // 4. Persist the fully-paired identity (no partial writes before this point).
  const updated: Keyfile = {
    ...existing,
    relay_url: relayUrl,
    account_id: accountId,
    device_id: deviceId,
    device_auth_token: paired.device_auth_token,
    device_cert: deviceCert,
    ...(options.label !== undefined ? { label: options.label } : {}),
  };
  writeKeyfile(options.keyfilePath, updated);

  log("");
  log("Paired successfully. Configure integrators with (#12):");
  log(`  account id:          ${accountId}`);
  log(`  account-root pubkey: ${updated.account_root_pubkey}`);
  log(`  device id:           ${deviceId}`);
  log(`  keyfile:             ${options.keyfilePath}`);
  log("");
  log("⚠ v0 stand-in: the device keys are held in software in the keyfile above.");
  log("  Production custody is hardware-backed (Secure Enclave / StrongBox) — see issue #23.");

  return updated;
}
