/**
 * `allw-approver pair` — enroll this software approver as a device on an account.
 *
 * Flow (`docs/contract.md` §Lifecycle / §Transport → pairing; relay #89 auth; #242):
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
 * 5. **Publish the next root-signed account state** listing this device (#243): integrators encrypt
 *    only to devices a verified account state vouches for, so a device is not reachable until this
 *    succeeds. The new state carries the previous verified state's devices, actors and revocations
 *    forward — never keys from the relay's device list.
 * 6. Persist relay/account/device + cert into the keyfile, and print the **account id** and the
 *    **account-root pubkey** (the integrator's routing id and trust anchor, #12).
 */

import { randomBytes } from "node:crypto";

import { generateKeyfile, loadKeyfile, writeKeyfile, type Keyfile } from "../lib/keyfile.js";
import {
  fetchAccountStatesWithMetadata,
  pairingComplete,
  pairingStart,
  publishAccountStates,
} from "../lib/relay-client.js";
import type { AllwWasm } from "../lib/wasm.js";

/** Options for `pair`, parsed from argv by the CLI. */
export interface PairOptions {
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

/** The fields of a verified `AccountState` that `pair` reads or rewrites; the rest pass through. */
interface AccountStateDoc {
  readonly v: number;
  readonly account_id: string;
  readonly sequence: number;
  readonly current_root: string;
  readonly devices: readonly { readonly device_id: string }[];
  readonly revocations: readonly { readonly kind: string; readonly id: string }[];
  readonly [field: string]: unknown;
}

/**
 * Root-sign and publish the account state that adds `deviceId` (`docs/enrollment.md` §Model).
 *
 * The relay's current documents are verified against the account root first; the next state is
 * the single highest verified one with this device added (or replacing an entry with the same id),
 * at sequence `max(highest, floor) + 1`. Fails closed — and so fails the pairing — when a document
 * does not verify, the relay claims a `max_sequence` no verified document backs, the relay's
 * highest is below this keyfile's floor (a rollback), siblings at the highest sequence disagree,
 * or the id is already revoked.
 *
 * @returns the published sequence.
 */
async function publishDeviceAccountState(
  wasm: AllwWasm,
  keyfile: Keyfile,
  relayUrl: string,
  accountId: string,
  deviceId: string,
): Promise<number> {
  const fetched = await fetchAccountStatesWithMetadata(relayUrl, accountId);
  const verified = fetched.accountStates.map(
    (jws) =>
      JSON.parse(
        wasm.verify_account_state(jws, accountId, keyfile.account_root_pubkey),
      ) as AccountStateDoc,
  );
  const highest = verified.reduce((max, state) => Math.max(max, state.sequence), 0);
  if (fetched.maxSequence > highest) {
    throw new Error(
      `relay reports account-state sequence ${String(fetched.maxSequence)} but serves no verified ` +
        `document at it (highest verified: ${String(highest)})`,
    );
  }
  const floor = keyfile.account_state_highest_sequence ?? 0;
  if (highest < floor) {
    throw new Error(
      `relay serves account-state sequence ${String(highest)}, below the ${String(floor)} this ` +
        `device already accepted (rollback)`,
    );
  }
  const top = verified.filter((state) => state.sequence === highest);
  const [base] = top;
  if (top.some((state) => JSON.stringify(state) !== JSON.stringify(base))) {
    throw new Error(
      `relay serves differing account-state documents at sequence ${String(highest)}; ` +
        `resolve them before pairing`,
    );
  }
  if (base?.revocations.some((r) => r.kind === "device" && r.id === deviceId) === true) {
    throw new Error(`device ${deviceId} is revoked in the current account state`);
  }
  const device = {
    device_id: deviceId,
    encryption_pubkey: keyfile.device_encryption_pubkey,
    signing_pubkey: keyfile.device_signing_pubkey,
    status: "active",
  };
  const sequence = Math.max(highest, floor) + 1;
  const next =
    base === undefined
      ? {
          v: 1,
          account_id: accountId,
          sequence,
          current_root: keyfile.account_root_pubkey,
          previous_roots: [],
          devices: [device],
          actors: [],
          revocations: [],
        }
      : {
          ...base,
          sequence,
          devices: [...base.devices.filter((d) => d.device_id !== deviceId), device],
        };
  const jws = wasm.sign_account_state(JSON.stringify(next), keyfile.account_root_seed);
  await publishAccountStates(relayUrl, accountId, [jws]);
  return sequence;
}

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
      options.relayUrl,
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
    options.relayUrl,
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

  // 4. Publish the account state that vouches for this device, so integrators can encrypt to it.
  // Before the keyfile write: a failure here leaves the keyfile unpaired, and re-running `pair`
  // starts over cleanly.
  const sequence = await publishDeviceAccountState(
    wasm,
    existing,
    options.relayUrl,
    accountId,
    deviceId,
  );
  log(`Published account state — sequence ${String(sequence)}`);

  // 5. Persist the fully-paired identity (no partial writes before this point).
  const updated: Keyfile = {
    ...existing,
    account_state_highest_sequence: sequence,
    relay_url: options.relayUrl,
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
