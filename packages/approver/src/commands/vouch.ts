/**
 * `allw-approver vouch`: the account-root holder vouches for a device that has its own keys (an
 * iPhone approver, or a web approver with keys of its own), so integrators seal requests to it.
 *
 * **Interim.** This stands in for the cross-device enrollment ceremony (#199) until that ships.
 * The CLI's own device does not need it: `pair` vouches for that one, and a web approver that was
 * set up from this keyfile is the same device.
 *
 * **Decrypt only.** Vouching lists the device as a request recipient and nothing more. It issues no
 * `device_cert`, by decision: a cert is approval authority (a verdict verifies with a root-issued
 * cert plus non-revocation), and that grant belongs to #199's MAC-authenticated ceremony, never to
 * a fingerprint comparison. A vouched device without a cert can read requests; its verdicts deny.
 *
 * Flow (`docs/enrollment.md` §Interim vouching, #381). Every failure refuses with a non-zero exit,
 * and nothing is signed before the last step:
 *
 * 1. Require an interactive terminal. A device is never vouched for unseen, so there is no
 *    `--yes`.
 * 2. Load the paired keyfile, which holds the account root. Check the pasted device id and keys in
 *    the core (`check_device_enrollment`). Refuse if either pasted key is **this keyfile's own**
 *    (the core compares the parsed keys with the ones it derives from the keyfile's seeds): such a
 *    device is the keyfile's own device, or a copy of its secrets, under whatever id it shows, and
 *    `pair` is the tool for it.
 * 3. Fetch the relay's device registry. Refuse if the relay never registered the id, or
 *    registered it with a different encryption key. The registry holds no signing key, so the
 *    signing key is covered only by the human's fingerprint comparison in step 5.
 * 4. Have the core compose the next account state (`next_account_state`, #379). This refuses a
 *    rollback, disagreeing documents, a revoked id, or an id already listed with other keys.
 *    Refuse, too, if the composition would replace **this keyfile's own device** (#378: same keys
 *    under another id), which would stop the CLI decrypting. Step 2 already refuses the keyfile's
 *    own keys; this also covers a state that lists this keyfile's device id with other keys.
 * 5. Show the device id, the relay's label for it, both key fingerprints, every id the new state
 *    replaces, the new sequence and the resulting recipients, all escaped by the core, and ask for
 *    confirmation. The human compares the device's values with what the device itself shows.
 * 6. Root-sign and publish the state, then record its sequence as this keyfile's floor.
 */

import { composeAddDevice, signAndPublish } from "../lib/account-state-authoring.js";
import type { Logger } from "./pair.js";
import { loadKeyfile, writeKeyfile } from "../lib/keyfile.js";
import { fetchDeviceRegistry } from "../lib/relay-client.js";
import { assertCliRelayUrl } from "../lib/relay-url.js";
import type { AllwWasm } from "../lib/wasm.js";

/** Options for `vouch`, parsed from argv by the CLI. */
export interface VouchOptions {
  readonly keyfilePath: string;
  /** The relay-assigned id of the device to vouch for, as that device shows it. */
  readonly deviceId: string;
  /** The device's X25519 encryption public key (base64url), as that device shows it. */
  readonly encryptionPubkey: string;
  /** The device's Ed25519 signing public key (base64url), as that device shows it. */
  readonly signingPubkey: string;
  /** Override the keyfile's paired relay URL (same transport rule as `pair --relay`). */
  readonly relayUrl?: string;
}

/** How `vouch` asks the human to confirm. The CLI backs it with the terminal. */
export interface Confirmer {
  /** Whether a human is at an interactive terminal. `false` refuses before anything else. */
  readonly interactive: boolean;
  /** Ask a yes/no question; resolves `true` only for an explicit yes. */
  confirm(question: string): Promise<boolean>;
}

/** The most characters of the relay's label shown. Labels are relay-held text of any length. */
const LABEL_DISPLAY_MAX_CHARS = 80;

/**
 * Vouch for one device. Returns the published account-state sequence. Throws (fail-closed) on any
 * refusal; see the module docs for the order.
 */
export async function runVouch(
  wasm: AllwWasm,
  options: VouchOptions,
  confirmer: Confirmer,
  rawLog: Logger = console.log,
): Promise<number> {
  // Every printed line goes through the core's display escape: the label and ids are untrusted.
  const log: Logger = (line) => {
    rawLog(wasm.escape_for_display(line));
  };

  if (!confirmer.interactive) {
    throw new Error(
      "vouch needs an interactive terminal: a device is vouched for only after a human compares " +
        "its fingerprints, so it cannot run unattended",
    );
  }

  const loaded = loadKeyfile(options.keyfilePath);
  if (loaded.kind === "absent") {
    throw new Error(
      `no keyfile at ${options.keyfilePath}: vouch needs the account root, run allw-approver pair first`,
    );
  }
  const keyfile = loaded.keyfile;
  const relaySource = options.relayUrl ?? keyfile.relay_url;
  if (relaySource === undefined) {
    throw new Error(
      "this keyfile is not paired with a relay: run allw-approver pair, or pass --relay",
    );
  }
  const relayUrl = assertCliRelayUrl(
    relaySource,
    options.relayUrl !== undefined ? "--relay" : "keyfile relay_url",
  );
  const accountId = wasm.account_id_for_root(keyfile.account_root_pubkey);

  wasm.check_device_enrollment(options.deviceId, options.encryptionPubkey, options.signingPubkey);
  const ownKeys = JSON.parse(
    wasm.shared_device_keys(
      options.deviceId,
      options.encryptionPubkey,
      options.signingPubkey,
      wasm.x25519_public_key(keyfile.device_encryption_seed),
      wasm.ed25519_public_key(keyfile.device_signing_seed),
    ),
  ) as string[];
  if (ownKeys.length > 0) {
    throw new Error(
      `the pasted ${ownKeys.join(" and ")} key${ownKeys.length > 1 ? "s match" : " matches"} ` +
        `this keyfile's: these are this keyfile's own keys — use pair`,
    );
  }

  const registry = await fetchDeviceRegistry(relayUrl, accountId);
  const registered = registry.find((d) => d.device_id === options.deviceId);
  if (registered === undefined) {
    throw new Error(
      `device ${options.deviceId} is not registered at the relay for this account; the device ` +
        `must pair with the relay before it can be vouched for`,
    );
  }
  if (registered.pubkey !== options.encryptionPubkey) {
    throw new Error(
      `the relay registered device ${options.deviceId} with a different encryption key than the ` +
        `one given; refusing to vouch (check the key on the device itself)`,
    );
  }

  const draft = await composeAddDevice(wasm, keyfile, relayUrl, accountId, {
    deviceId: options.deviceId,
    encryptionPubkey: options.encryptionPubkey,
    signingPubkey: options.signingPubkey,
  });
  if (keyfile.device_id !== undefined && draft.replacedDeviceIds.includes(keyfile.device_id)) {
    throw new Error(
      `device ${options.deviceId} has the keys the account state lists for this keyfile's ` +
        `device ${keyfile.device_id}: vouching it would replace this keyfile's device, and the ` +
        `CLI would stop decrypting. Use pair for this device`,
    );
  }

  // Truncated raw, then escaped once by `log` with the rest of its line.
  const label = registered.label === null ? "(none)" : truncate(registered.label);
  log("Vouch for this device? It will be able to read every approval request for the account.");
  log("");
  log(`  account id:      ${accountId}`);
  log(`  device id:       ${options.deviceId}`);
  log(`  relay label:     ${label}`);
  log(`  encryption key:  ${wasm.device_key_fingerprint("encryption", options.encryptionPubkey)}`);
  log(`  signing key:     ${wasm.device_key_fingerprint("signing", options.signingPubkey)}`);
  log("");
  log(`The new account state (sequence ${String(draft.sequence)}):`);
  for (const replaced of draft.replacedDeviceIds) {
    log(`  replaces:        ${replaced} (same keys; it stops receiving requests)`);
  }
  log(`  recipients:      ${draft.activeDeviceIds.join(", ")}`);
  log("");
  log(
    "Compare the device id and all eight groups of both fingerprints with what the device shows.",
  );
  const confirmed = await confirmer.confirm("Do they all match, and do you vouch for it? [y/N] ");
  if (!confirmed) {
    throw new Error("not confirmed: nothing was signed or published");
  }

  await signAndPublish(wasm, keyfile, relayUrl, accountId, draft);
  // The published sequence is this root holder's new floor: a later pair or vouch refuses to build
  // on anything older.
  if (draft.sequence > (keyfile.account_state_highest_sequence ?? 0)) {
    writeKeyfile(options.keyfilePath, {
      ...keyfile,
      account_state_highest_sequence: draft.sequence,
    });
  }
  log(
    `Vouched for device ${options.deviceId}: published account state sequence ${String(draft.sequence)}.`,
  );
  log(
    "It can now decrypt requests. Its approvals are denied until it holds a device certificate " +
      "from this account root, which vouch does not issue (#199).",
  );
  return draft.sequence;
}

/** Cap untrusted text at {@link LABEL_DISPLAY_MAX_CHARS} characters before it is escaped. */
function truncate(text: string): string {
  const chars = Array.from(text);
  return chars.length <= LABEL_DISPLAY_MAX_CHARS
    ? text
    : `${chars.slice(0, LABEL_DISPLAY_MAX_CHARS).join("")}…`;
}
