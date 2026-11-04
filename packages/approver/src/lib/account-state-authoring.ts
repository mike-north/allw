/**
 * Root-holder account-state authoring for `pair` and `vouch` (#379, #381).
 *
 * The rules for what the next account state may be (verify every document, refuse an unbacked
 * `max_sequence`, a rollback below this keyfile's floor, or disagreeing siblings, then add the
 * device under the #378 one-entry-per-key-pair rule) live once, in the core's
 * `next_account_state`. This module only fetches the relay's documents, hands them to the core,
 * and root-signs and publishes what the core composed. It holds no sequence, sibling or floor
 * logic of its own.
 *
 * @see ../../../../docs/enrollment.md §Model, §Interim vouching
 */

import type { Keyfile } from "./keyfile.js";
import { fetchAccountStatesWithMetadata, publishAccountStates } from "./relay-client.js";
import type { AllwWasm } from "./wasm.js";

/** A device to list as active: its relay id and both public keys (base64url). */
export interface DeviceToAdd {
  readonly deviceId: string;
  readonly encryptionPubkey: string;
  readonly signingPubkey: string;
}

/**
 * The next account state the core composed, not yet signed, with what it changes. A caller that
 * asks a human to confirm shows {@link replacedDeviceIds} and {@link activeDeviceIds}: both come
 * from the core, never recomputed here.
 */
export interface AccountStateDraft {
  /** The unsigned `AccountState` JSON, exactly as the core produced it. */
  readonly stateJson: string;
  /** The new state's sequence: `max(highest, floor) + 1`. */
  readonly sequence: number;
  /**
   * Ids the change retires because they carried the added device's key pair under another id
   * (#378). They stop receiving requests once this state is published.
   */
  readonly replacedDeviceIds: readonly string[];
  /** Every active device id in the new state: the request recipients once it is published. */
  readonly activeDeviceIds: readonly string[];
}

/**
 * Fetch the relay's account states and have the core compose the state that adds `device`.
 * Throws, so nothing is signed, on any relay failure or core refusal.
 */
export async function composeAddDevice(
  wasm: AllwWasm,
  keyfile: Keyfile,
  relayUrl: string,
  accountId: string,
  device: DeviceToAdd,
): Promise<AccountStateDraft> {
  const fetched = await fetchAccountStatesWithMetadata(relayUrl, accountId);
  const composed = wasm.next_account_state(
    JSON.stringify(fetched.accountStates),
    fetched.maxSequence,
    keyfile.account_state_highest_sequence ?? 0,
    accountId,
    keyfile.account_root_pubkey,
    JSON.stringify({
      kind: "add_device",
      device_id: device.deviceId,
      encryption_pubkey: device.encryptionPubkey,
      signing_pubkey: device.signingPubkey,
    }),
  );
  const parsed = JSON.parse(composed) as {
    state_json: string;
    sequence: number;
    replaced_device_ids: string[];
    active_device_ids: string[];
  };
  return {
    stateJson: parsed.state_json,
    sequence: parsed.sequence,
    replacedDeviceIds: parsed.replaced_device_ids,
    activeDeviceIds: parsed.active_device_ids,
  };
}

/** Root-sign a composed draft with the keyfile's account root and publish it to the relay. */
export async function signAndPublish(
  wasm: AllwWasm,
  keyfile: Keyfile,
  relayUrl: string,
  accountId: string,
  draft: AccountStateDraft,
): Promise<void> {
  const jws = wasm.sign_account_state(draft.stateJson, keyfile.account_root_seed);
  await publishAccountStates(relayUrl, accountId, [jws]);
}
