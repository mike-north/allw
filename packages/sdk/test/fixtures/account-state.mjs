/**
 * Shared test helper: root-signed account state, the trust input `createClient` requires
 * (`ClientConfig.accountStates`). Requests are encrypted only to the devices a verified state
 * vouches for, so every test client that reaches the seal step needs one listing its device.
 *
 * @see ../../../../docs/enrollment.md (§Model, recipient selection rule)
 */

/** A fixed revocation time (fixed-dates rule). */
const REVOKED_AT_MS = 1700000000000;

/**
 * Root-sign an account-state document for `accountId`.
 *
 * @param wasm the vendored WASM glue
 * @param opts.accountSeed the account-root Ed25519 seed (base64url)
 * @param opts.devices `{ deviceId, encryptionPub, signingPub }` entries the state vouches for
 * @param opts.revokedDeviceIds device ids the state also revokes
 */
export function signedAccountState(
  wasm,
  { accountId, accountSeed, sequence = 1, devices = [], revokedDeviceIds = [] },
) {
  return wasm.sign_account_state(
    JSON.stringify({
      v: 1,
      account_id: accountId,
      sequence,
      current_root: wasm.ed25519_public_key(accountSeed),
      previous_roots: [],
      devices: devices.map((d) => ({
        device_id: d.deviceId,
        encryption_pubkey: d.encryptionPub,
        // Selection does not use the signing key; any valid Ed25519 public key will do.
        signing_pubkey:
          d.signingPub ?? wasm.ed25519_public_key(Buffer.alloc(32, 9).toString("base64url")),
        status: "active",
      })),
      actors: [],
      revocations: revokedDeviceIds.map((id) => ({
        kind: "device",
        id,
        revoked_at: REVOKED_AT_MS,
        reason: "test revocation",
      })),
    }),
    accountSeed,
  );
}

/** `[state]` vouching for exactly one device: the common single-device test account. */
export function oneDeviceAccountStates(wasm, { accountId, accountSeed, deviceId, encryptionPub }) {
  return [
    signedAccountState(wasm, { accountId, accountSeed, devices: [{ deviceId, encryptionPub }] }),
  ];
}
