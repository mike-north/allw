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
  readonly accountId: string;
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
  const cert = wasm.issue_device_cert(
    fresh.account_root_seed,
    params.accountId,
    params.deviceId,
    fresh.device_signing_pubkey,
    params.issuedAt,
  );
  const keyfile: Keyfile = {
    ...fresh,
    relay_url: params.relayUrl,
    account_id: params.accountId,
    device_id: params.deviceId,
    device_cert: cert,
    ...(params.label !== undefined ? { label: params.label } : {}),
  };
  return { wasm, keyfile };
}
