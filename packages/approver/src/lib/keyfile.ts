/**
 * Key custody for the v0 stand-in approver.
 *
 * # ⚠️ v0 stand-in — software-held keys
 * This module generates and stores the approver's signing/encryption **seeds in a local JSON
 * keyfile**. That is a deliberate v0 stand-in to unblock the walking skeleton, mirroring the
 * core's `X25519KeyPair::from_seed`/`SigningKeyPair::from_seed`-is-not-production note
 * (`crates/allw-wasm/src/lib.rs`). Production device keys live in **Secure Enclave / StrongBox**
 * with biometric-gated signing and never serialize (`docs/contract.md` §Identity & keys); the
 * hardware-custody hero device is **#23**. The wire protocol does not depend on key custody, so
 * #23 swaps in later with no protocol change.
 *
 * The keyfile is written with `0600` (owner read/write only) and the seeds never leave this
 * process except through the WASM core's signing/decryption FFI.
 */

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { dirname } from "node:path";

import type { AllwWasm } from "./wasm.js";

/** Current on-disk keyfile schema version. Bumped only on a breaking change to the shape. */
export const KEYFILE_VERSION = 1 as const;

/**
 * The persisted approver identity. **Contains secret seeds** — never log, transmit, or commit it.
 *
 * Three independent 32-byte seeds (base64url-unpadded), per the issue's prescriptive scope:
 * - `account_root_seed` — Ed25519; the account trust anchor that certifies device keys.
 * - `device_signing_seed` — Ed25519; signs verdicts.
 * - `device_encryption_seed` — X25519; decrypts the `context_ciphertext`.
 */
export interface Keyfile {
  readonly version: typeof KEYFILE_VERSION;
  /** ⚠️ secret — Ed25519 account-root signing seed (base64url, 32 bytes). */
  readonly account_root_seed: string;
  /** ⚠️ secret — Ed25519 device signing seed (base64url, 32 bytes). */
  readonly device_signing_seed: string;
  /** ⚠️ secret — X25519 device encryption seed (base64url, 32 bytes). */
  readonly device_encryption_seed: string;
  /** Ed25519 account-root public key (base64url) — the integrator's trust anchor (#12). */
  readonly account_root_pubkey: string;
  /** Ed25519 device verifying key (base64url). */
  readonly device_signing_pubkey: string;
  /** X25519 device public key (base64url) — the JWE recipient key registered with the relay. */
  readonly device_encryption_pubkey: string;

  /** Relay base URL this identity is paired against (set by `pair`). */
  relay_url?: string;
  /** Account id on the relay (set by `pair`). */
  account_id?: string;
  /** Device id assigned by the relay at `/pairing/complete` (set by `pair`). */
  device_id?: string;
  /** Optional human label for this device. */
  label?: string;
  /** Device→account-root certificate (compact JWS) minted at pairing (set by `pair`). */
  device_cert?: string;
}

/** A freshly generated, not-yet-paired identity (seeds + derived pubkeys only). */
export type FreshKeyfile = Omit<
  Keyfile,
  "relay_url" | "account_id" | "device_id" | "label" | "device_cert"
>;

/** base64url-unpadded encode raw bytes (JOSE-consistent — matches every wire field). */
function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Draw 32 cryptographically-random bytes from the platform CSPRNG. */
function randomSeed(): Uint8Array {
  const seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);
  return seed;
}

/**
 * Generate a fresh approver identity: three random 32-byte seeds, with their public keys derived
 * through the WASM core (never re-implemented here). No relay/account state yet — that is added by
 * `pair`.
 */
export function generateKeyfile(wasm: AllwWasm): FreshKeyfile {
  const accountRootSeed = toBase64Url(randomSeed());
  const deviceSigningSeed = toBase64Url(randomSeed());
  const deviceEncryptionSeed = toBase64Url(randomSeed());

  return {
    version: KEYFILE_VERSION,
    account_root_seed: accountRootSeed,
    device_signing_seed: deviceSigningSeed,
    device_encryption_seed: deviceEncryptionSeed,
    account_root_pubkey: wasm.ed25519_public_key(accountRootSeed),
    device_signing_pubkey: wasm.ed25519_public_key(deviceSigningSeed),
    device_encryption_pubkey: wasm.x25519_public_key(deviceEncryptionSeed),
  };
}

/** Type guard: a parsed value is a string-keyed plain object (rejects arrays/null). */
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The six required base64url 32-byte key fields (three seeds + three derived pubkeys). */
const KEY_FIELDS = [
  "account_root_seed",
  "device_signing_seed",
  "device_encryption_seed",
  "account_root_pubkey",
  "device_signing_pubkey",
  "device_encryption_pubkey",
] as const;

/** The optional string fields populated by `pair` (validated as strings when present). */
const OPTIONAL_STRING_FIELDS = [
  "relay_url",
  "account_id",
  "device_id",
  "label",
  "device_cert",
] as const;

/**
 * Validate that `value` is a base64url-unpadded string decoding to **exactly 32 bytes** — the shape
 * of every seed and derived public key (Ed25519 / X25519 are 32-byte). A corrupt keyfile must fail
 * here (clearly), not later at first crypto use with an opaque WASM error.
 */
function isBase64Url32Bytes(value: unknown): value is string {
  if (typeof value !== "string") return false;
  // 32 bytes → 43 base64url-unpadded chars; reject by length first (cheap, bounds the work).
  if (value.length !== 43) return false;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  // Decode and confirm exactly 32 bytes (length alone can't catch every malformed 43-char string).
  return Buffer.from(value, "base64url").length === 32;
}

/**
 * Validate a parsed keyfile fail-closed: a corrupt/partial keyfile must abort rather than be
 * silently "repaired" (a missing/garbled seed could otherwise let the approver sign with the wrong
 * key, or fail opaquely deep inside the WASM core).
 *
 * Checks, in order: object shape → version → each seed/pubkey is well-formed base64url-32-bytes →
 * each optional pairing field is a string when present.
 *
 * @throws if the value is not a valid keyfile (with a message naming the offending field).
 */
export function validateKeyfile(value: unknown): Keyfile {
  if (!isRecord(value)) {
    throw new Error("keyfile is not a JSON object");
  }
  if (value.version !== KEYFILE_VERSION) {
    throw new Error(
      `unsupported keyfile version ${String(value.version)} (expected ${String(KEYFILE_VERSION)})`,
    );
  }
  for (const key of KEY_FIELDS) {
    const field = value[key];
    if (typeof field !== "string" || field.length === 0) {
      throw new Error(`keyfile is missing required field '${key}'`);
    }
    if (!isBase64Url32Bytes(field)) {
      throw new Error(
        `keyfile field '${key}' is not a valid base64url-unpadded 32-byte key (corrupt keyfile)`,
      );
    }
  }
  // Optional pairing fields: present-but-wrong-typed is corruption, not "unpaired" — reject it so a
  // garbled relay_url/device_id can never flow into routing or signing (review item #6).
  for (const key of OPTIONAL_STRING_FIELDS) {
    if (key in value && value[key] !== undefined && typeof value[key] !== "string") {
      throw new Error(`keyfile field '${key}' must be a string when present (corrupt keyfile)`);
    }
  }
  // Every required field is a validated 32-byte key and every present optional field is a string.
  return value as unknown as Keyfile;
}

/** Node augments I/O errors with a string `code` (e.g. `"ENOENT"`); narrow to read it safely. */
function errorCode(err: unknown): string | undefined {
  if (typeof err === "object" && err !== null && "code" in err) {
    const { code } = err;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

/**
 * The result of attempting to load a keyfile, distinguishing the three cases a caller must treat
 * differently (review items #2 + #4): the file genuinely does not exist (`pair`/`keygen` may mint a
 * fresh identity), the file is present and valid, or the file is present but unreadable/corrupt
 * (must fail loudly — NEVER silently discarded and replaced with a new identity).
 */
export type KeyfileLoad =
  | { readonly kind: "absent" }
  | { readonly kind: "ok"; readonly keyfile: Keyfile };

/**
 * Load the keyfile at `path`, distinguishing "absent" (ENOENT) from every other failure.
 *
 * - **ENOENT** → returns `{ kind: "absent" }` (the only case a caller may treat as "no keyfile").
 * - **Present + valid** → returns `{ kind: "ok", keyfile }`.
 * - **Any other error** (EACCES/permission, EISDIR, invalid JSON, failed validation) → **throws**
 *   with context. A permission or parse error must not be misreported as "not found" (review #2),
 *   and an existing-but-corrupt identity must not be silently replaced (review #4).
 *
 * @throws on any non-ENOENT read error, invalid JSON, or failed validation.
 */
export function loadKeyfile(path: string): KeyfileLoad {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    if (errorCode(err) === "ENOENT") {
      return { kind: "absent" };
    }
    // EACCES, EISDIR, etc. — surface the real failure rather than masking it as "no keyfile".
    throw new Error(`failed to read keyfile at ${path}: ${(err as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`keyfile at ${path} is not valid JSON: ${(err as Error).message}`);
  }
  return { kind: "ok", keyfile: validateKeyfile(parsed) };
}

/**
 * Read and validate the keyfile at `path`. A missing keyfile is an error here (callers that want to
 * mint a fresh one on absence use {@link loadKeyfile} and branch on `kind`).
 *
 * @throws if the keyfile is absent, unreadable, or invalid.
 */
export function readKeyfile(path: string): Keyfile {
  const loaded = loadKeyfile(path);
  if (loaded.kind === "absent") {
    throw new Error(
      `no keyfile at ${path} — run 'allw-approver pair' (or 'keygen') to create one first`,
    );
  }
  return loaded.keyfile;
}

/**
 * Write `keyfile` to `path` atomically-ish with `0600` permissions (owner-only). Creates parent
 * directories as needed. The restrictive mode is best-effort defense-in-depth for the v0
 * software-held seeds — the real fix is hardware custody (#23).
 */
export function writeKeyfile(path: string, keyfile: Keyfile): void {
  mkdirSync(dirname(path), { recursive: true });
  // mode on writeFileSync only applies when creating; chmod afterwards covers the overwrite case.
  writeFileSync(path, `${JSON.stringify(keyfile, null, 2)}\n`, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    // Best-effort on platforms without POSIX modes (e.g. Windows) — do not fail the write.
  }
}
