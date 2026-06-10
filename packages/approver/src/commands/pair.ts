/**
 * `allw-approver pair` — enroll this software approver as a device on an account.
 *
 * Flow (`docs/contract.md` §Lifecycle / §Transport → pairing; relay #10):
 * 1. Load (or generate) the local keyfile — three software-held seeds + derived pubkeys.
 * 2. Obtain a pairing code: use `--code <code>` if supplied, else drive `POST /pairing/start`
 *    ourselves (fine for the v0 skeleton — in production the account owner starts the pairing).
 * 3. `POST /pairing/complete` registering the device **X25519** public key → relay-assigned
 *    `device_id`.
 * 4. Mint a **device_cert** (`issue_device_cert`): the account-root key signs the device Ed25519
 *    verifying key → cert, so verifiers need only the account-root key.
 * 5. Persist relay/account/device + cert into the keyfile, and print the **account-root pubkey**
 *    (the integrator's trust anchor, #12).
 */

import { generateKeyfile, readKeyfile, writeKeyfile, type Keyfile } from "../lib/keyfile.js";
import { pairingComplete, pairingStart } from "../lib/relay-client.js";
import type { AllwWasm } from "../lib/wasm.js";

/** Options for `pair`, parsed from argv by the CLI. */
export interface PairOptions {
  readonly relayUrl: string;
  readonly accountId: string;
  readonly keyfilePath: string;
  readonly label?: string;
  /** An existing pairing code (account owner ran `/pairing/start`); omit to self-drive start. */
  readonly code?: string;
  /** Current time (ms) — injectable for deterministic tests; defaults to `Date.now()`. */
  readonly now?: number;
}

/** A sink for human-facing output (stdout by default; captured in tests). */
export type Logger = (line: string) => void;

/** Load the keyfile at `path`, or generate a fresh one if none exists yet. */
function loadOrGenerate(wasm: AllwWasm, path: string): Keyfile {
  try {
    return readKeyfile(path);
  } catch {
    // No (valid) keyfile yet — generate a fresh identity. `pair` then fills in relay/account/cert.
    return { ...generateKeyfile(wasm) };
  }
}

/**
 * Run the pairing flow. Returns the updated keyfile (also persisted to disk). Throws fail-closed on
 * any relay error or malformed response — a partial pairing is never written.
 */
export async function runPair(
  wasm: AllwWasm,
  options: PairOptions,
  log: Logger = console.log,
): Promise<Keyfile> {
  const now = options.now ?? Date.now();
  const existing = loadOrGenerate(wasm, options.keyfilePath);

  // 1. Obtain a pairing code (supplied or self-driven).
  let code = options.code;
  if (code === undefined) {
    const started = await pairingStart(options.relayUrl, options.accountId, options.label);
    code = started.code;
    log(`Started pairing — code ${code} (expires ${new Date(started.expires_at).toISOString()})`);
  }

  // 2. Complete pairing: register the device X25519 (encryption) key → device_id.
  const deviceId = await pairingComplete(
    options.relayUrl,
    options.accountId,
    code,
    existing.device_encryption_pubkey,
    options.label,
  );
  log(`Paired — device_id ${deviceId}`);

  // 3. Mint the device certificate: account-root signs the device Ed25519 verifying key.
  const deviceCert = wasm.issue_device_cert(
    existing.account_root_seed,
    options.accountId,
    deviceId,
    existing.device_signing_pubkey,
    now,
  );

  // 4. Persist the fully-paired identity (no partial writes before this point).
  const updated: Keyfile = {
    ...existing,
    relay_url: options.relayUrl,
    account_id: options.accountId,
    device_id: deviceId,
    device_cert: deviceCert,
    ...(options.label !== undefined ? { label: options.label } : {}),
  };
  writeKeyfile(options.keyfilePath, updated);

  log("");
  log("Paired successfully. Trust anchor for integrators (#12):");
  log(`  account-root pubkey: ${updated.account_root_pubkey}`);
  log(`  device id:           ${deviceId}`);
  log(`  keyfile:             ${options.keyfilePath}`);
  log("");
  log("⚠ v0 stand-in: the device keys are held in software in the keyfile above.");
  log("  Production custody is hardware-backed (Secure Enclave / StrongBox) — see issue #23.");

  return updated;
}
