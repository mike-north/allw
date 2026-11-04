/**
 * "This device" panel (#381): shows the paired device's id, both public keys, and the core's
 * fingerprints of those keys, so the account-root holder can vouch for it with the interim
 * `allw-approver vouch` and the human can compare the two screens.
 *
 * Integrators encrypt each request only to the devices the account root lists in signed account
 * state (`docs/enrollment.md` §Model). A device with keys of its own is not listed until the root
 * holder vouches for it. A browser set up by pasting the CLI keyfile's values is the CLI's own
 * device, which `pair` already listed; for it this panel is informational.
 *
 * Nothing here is secret: the public keys are derived from the stored seeds by the WASM core, and
 * the seeds never leave it. The device id came from a paste, so it is shown only through the core
 * escape, and the copyable `vouch` command is offered only when the core accepts the id and keys
 * (`check_device_enrollment`).
 *
 * The panel lives in `#device`, outside `#app`, like the notification controls: it never gates or
 * covers the inbox.
 *
 * @see ../../../docs/enrollment.md §Interim vouching
 */

import type { ApproverIdentity } from "./runtime.js";

/** The WASM functions the panel needs (a subset of `AllwWasm`). */
export interface DeviceDetailsWasm {
  x25519_public_key(seed_b64: string): string;
  ed25519_public_key(seed_b64: string): string;
  device_key_fingerprint(kind: "encryption" | "signing", key_b64: string): string;
  check_device_enrollment(
    device_id: string,
    encryption_pubkey_b64: string,
    signing_pubkey_b64: string,
  ): void;
  escape_for_display(text: string): string;
}

/** What the panel shows, computed by the core. */
export interface DeviceDetailsModel {
  /** The device id, escaped for display. */
  readonly deviceIdDisplay: string;
  readonly encryptionPubkey: string;
  readonly encryptionFingerprint: string;
  readonly signingPubkey: string;
  readonly signingFingerprint: string;
  /**
   * The full `allw-approver vouch …` command line, or `null` when the core refuses this device's
   * id or keys (then `problem` says why, escaped).
   */
  readonly vouchCommand: string | null;
  readonly problem: string | null;
}

/** Derive the panel's contents from the paired identity. Throws only if the core cannot load keys. */
export function deviceDetailsModel(
  wasm: DeviceDetailsWasm,
  identity: Pick<ApproverIdentity, "deviceId" | "deviceEncryptionSeed" | "deviceSigningSeed">,
): DeviceDetailsModel {
  const encryptionPubkey = wasm.x25519_public_key(identity.deviceEncryptionSeed);
  const signingPubkey = wasm.ed25519_public_key(identity.deviceSigningSeed);
  let problem: string | null = null;
  try {
    wasm.check_device_enrollment(identity.deviceId, encryptionPubkey, signingPubkey);
  } catch (err) {
    problem = wasm.escape_for_display(err instanceof Error ? err.message : String(err));
  }
  return {
    deviceIdDisplay: wasm.escape_for_display(identity.deviceId),
    encryptionPubkey,
    encryptionFingerprint: wasm.device_key_fingerprint("encryption", encryptionPubkey),
    signingPubkey,
    signingFingerprint: wasm.device_key_fingerprint("signing", signingPubkey),
    // Only built from an id the core accepted (base64url alphabet), so it needs no quoting.
    vouchCommand:
      problem === null
        ? `allw-approver vouch --device-id ${identity.deviceId} --encryption-pubkey ${encryptionPubkey} --signing-pubkey ${signingPubkey}`
        : null,
    problem,
  };
}

/** Options for {@link mountDeviceDetails}. */
export interface DeviceDetailsOptions {
  readonly host: HTMLElement;
  readonly model: DeviceDetailsModel;
  /** Copy text to the clipboard. Defaults to `navigator.clipboard.writeText` when available. */
  readonly copy?: ((text: string) => Promise<void>) | null;
}

/** Render the panel into `host` (replacing its contents). Collapsed by default. */
export function mountDeviceDetails(options: DeviceDetailsOptions): void {
  const { host, model } = options;
  const copy = options.copy === undefined ? defaultCopy() : options.copy;

  const panel = el("details", "device-details");
  panel.append(el("summary", "device-details-summary", "This device's keys (for vouching)"));
  panel.append(
    el(
      "p",
      "device-details-text",
      "If this device has keys of its own (it was not set up from the CLI keyfile), the " +
        "account-root holder must vouch for it before requests reach it: they run the command " +
        "below with allw-approver vouch, and compare the device id and all eight groups of both " +
        "fingerprints with what their terminal shows.",
    ),
  );

  const list = el("dl", "device-details-list");
  const row = (label: string, value: string, copyable: boolean): void => {
    const dd = el("dd", "device-details-value");
    dd.append(el("code", "device-details-code", value));
    if (copyable && copy !== null) dd.append(copyButton(copy, value));
    list.append(el("dt", "device-details-label", label), dd);
  };
  row("Device ID", model.deviceIdDisplay, model.problem === null);
  row("Encryption public key", model.encryptionPubkey, true);
  row("Encryption key fingerprint", model.encryptionFingerprint, false);
  row("Signing public key", model.signingPubkey, true);
  row("Signing key fingerprint", model.signingFingerprint, false);
  panel.append(list);

  if (model.vouchCommand !== null) {
    const command = el("div", "device-details-command");
    command.append(el("code", "device-details-code", model.vouchCommand));
    if (copy !== null) command.append(copyButton(copy, model.vouchCommand, "Copy command"));
    panel.append(command);
  } else {
    panel.append(
      el(
        "p",
        "device-details-problem",
        `This device cannot be vouched for as it is: ${model.problem ?? ""}`,
      ),
    );
  }
  host.replaceChildren(panel);
}

function copyButton(
  copy: (text: string) => Promise<void>,
  text: string,
  label = "Copy",
): HTMLButtonElement {
  const button = el("button", "device-details-copy", label);
  button.type = "button";
  button.addEventListener("click", () => {
    copy(text).then(
      () => {
        button.textContent = "Copied";
      },
      () => {
        button.textContent = "Copy failed";
      },
    );
  });
  return button;
}

function defaultCopy(): ((text: string) => Promise<void>) | null {
  const clipboard = typeof navigator === "undefined" ? undefined : navigator.clipboard;
  return clipboard === undefined ? null : (text) => clipboard.writeText(text);
}

function el<Tag extends keyof HTMLElementTagNameMap>(
  tag: Tag,
  className: string,
  textContent?: string,
): HTMLElementTagNameMap[Tag] {
  const element = document.createElement(tag);
  element.className = className;
  if (textContent !== undefined) element.textContent = textContent;
  return element;
}
