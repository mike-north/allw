/**
 * Build a paired software-approver identity for the in-process round-trip, using the **real**
 * `@allw/approver` key generation and device-cert issuance (the v0 software-key stand-in,
 * `packages/approver/src/lib/keyfile.ts`). No crypto is implemented here — `generateKeyfile`
 * derives the keys via the WASM core and `issue_device_cert` mints the device→account-root cert.
 *
 * The resulting {@link ApproverIdentity} is exactly what the live `allw-approver pair` writes to a
 * keyfile, so the CI round-trip and the live demo share one identity shape.
 */

import { generateKeyfile } from "@allw/approver";
import type { AllwWasm, Keyfile } from "@allw/approver";

import type { ApproverIdentity } from "./approver-harness.js";

/** Pairing parameters for {@link buildPairedApprover}. */
export interface PairingParams {
  /**
   * The account id to certify. Omit it to use the self-certifying id the core derives from the
   * generated account root (`account_id_for_root`, `docs/enrollment.md` §Model) — required by any
   * surface that reads config through `loadClientConfig`, such as the hook.
   */
  readonly accountId?: string;
  readonly deviceId: string;
  readonly relayUrl: string;
  /** Cert issuance time (ms). Optional cert expiry is omitted (not the thing under test). */
  readonly issuedAt: number;
  readonly label?: string;
}

/**
 * Generate a fresh software identity and pair it: derive the three seeds + pubkeys, then mint the
 * device certificate (account-root signs the device signing key). Returns the WASM core plus the
 * fully-paired keyfile — ready to hand to {@link attachAutoApprover}.
 */
export function buildPairedApprover(wasm: AllwWasm, params: PairingParams): ApproverIdentity {
  const fresh = generateKeyfile(wasm);
  const accountId = params.accountId ?? wasm.account_id_for_root(fresh.account_root_pubkey);
  const cert = wasm.issue_device_cert(
    fresh.account_root_seed,
    accountId,
    params.deviceId,
    fresh.device_signing_pubkey,
    params.issuedAt,
  );
  const keyfile: Keyfile = {
    ...fresh,
    relay_url: params.relayUrl,
    account_id: accountId,
    device_id: params.deviceId,
    device_cert: cert,
    ...(params.label !== undefined ? { label: params.label } : {}),
  };
  return { wasm, keyfile };
}

/**
 * Root-sign the account state that vouches for this identity's device — what `allw-approver pair`
 * publishes (#243). Integrators encrypt only to devices a verified account state names, so a relay
 * double must serve this for the round-trip to reach the approver.
 */
export function signDeviceAccountState(identity: ApproverIdentity, sequence = 1): string {
  const { wasm, keyfile } = identity;
  if (keyfile.account_id === undefined || keyfile.device_id === undefined) {
    throw new Error("signDeviceAccountState needs a paired identity (account_id and device_id)");
  }
  return wasm.sign_account_state(
    JSON.stringify({
      v: 1,
      account_id: keyfile.account_id,
      sequence,
      current_root: keyfile.account_root_pubkey,
      previous_roots: [],
      devices: [
        {
          device_id: keyfile.device_id,
          encryption_pubkey: keyfile.device_encryption_pubkey,
          signing_pubkey: keyfile.device_signing_pubkey,
          status: "active",
        },
      ],
      actors: [],
      revocations: [],
    }),
    keyfile.account_root_seed,
  );
}
