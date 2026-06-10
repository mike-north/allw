/**
 * `allw-approver keygen` — generate a fresh local keyfile (three software-held seeds + derived
 * pubkeys) without pairing. Useful to inspect/bootstrap an identity; `pair` also generates one
 * implicitly if none exists.
 *
 * ⚠ v0 stand-in: software-held seeds (see `keyfile.ts`); hardware custody is #23.
 */

import { existsSync } from "node:fs";

import { generateKeyfile, writeKeyfile, type Keyfile } from "../lib/keyfile.js";
import type { AllwWasm } from "../lib/wasm.js";
import type { Logger } from "./pair.js";

/** Options for `keygen`. */
export interface KeygenOptions {
  readonly keyfilePath: string;
  /** Overwrite an existing keyfile (default: refuse, to avoid clobbering paired seeds). */
  readonly force?: boolean;
}

/**
 * Generate and persist a fresh keyfile. Refuses to overwrite an existing one unless `force` — a
 * keyfile holds the only copy of the software seeds, so clobbering it would orphan a paired device.
 *
 * @throws if a keyfile already exists and `force` is not set.
 */
export function runKeygen(
  wasm: AllwWasm,
  options: KeygenOptions,
  log: Logger = console.log,
): Keyfile {
  if (existsSync(options.keyfilePath) && options.force !== true) {
    throw new Error(
      `keyfile already exists at ${options.keyfilePath} — pass --force to overwrite (this orphans the current device)`,
    );
  }
  const keyfile: Keyfile = { ...generateKeyfile(wasm) };
  writeKeyfile(options.keyfilePath, keyfile);

  log(`Generated a fresh keyfile at ${options.keyfilePath}`);
  log(`  account-root pubkey:     ${keyfile.account_root_pubkey}`);
  log(`  device signing pubkey:   ${keyfile.device_signing_pubkey}`);
  log(`  device encryption pubkey:${keyfile.device_encryption_pubkey}`);
  log("⚠ v0 stand-in: these seeds are held in software — replaced by hardware custody (#23).");
  return keyfile;
}
