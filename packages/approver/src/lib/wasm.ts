/**
 * Loads the vendored `allw-wasm` module (the audited Rust core, compiled to WebAssembly) and
 * exposes the typed subset of its FFI the approver uses.
 *
 * # Why WASM-under-node (a hard constraint, not a preference)
 * On-machine `allw` code runs as **WASM under node**, never a standalone native binary, so
 * enterprise binary-allowlisting (Santa) and MDM cannot block it (`docs/architecture.md`). The
 * approver therefore never reimplements crypto/contract logic — every cryptographic operation
 * (key derivation, decrypt, request-hash, verdict signing, cert issuance) goes through this core.
 *
 * # Loading
 * Mirrors `packages/sdk/test/wasm.test.mjs`: the `--target web` glue is loaded synchronously by
 * compiling the `.wasm` bytes into a `WebAssembly.Module` and calling `initSync` — one ESM
 * artifact works in both node and the browser/worker. The wasm is built once from the repo root
 * (`pnpm run build:wasm`) into `packages/sdk/vendor/allw-wasm`; the approver resolves that single
 * vendored artifact via the `@allw/sdk` package location so there is no second copy to drift.
 *
 * @see ../../../sdk/test/wasm.test.mjs (the loader pattern this mirrors)
 * @see ../../../../docs/contract.md §Wire encoding, §Identity & keys
 * @see ../../../../docs/architecture.md (WASM-local hard constraint)
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, parse as parsePath } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/**
 * The exact subset of the `allw-wasm` FFI the approver depends on. Every function takes and
 * returns JSON / base64url **strings** (the language-agnostic wire contract); errors surface as
 * thrown JS `Error`s (fail-closed at the boundary). Mirrors `crates/allw-wasm/src/lib.rs`.
 */
export interface AllwWasm {
  /** Derive the Ed25519 verifying (public) key for a 32-byte signing seed (base64url). */
  ed25519_public_key(seed_b64: string): string;
  /** Derive the X25519 public key for a 32-byte secret seed (base64url). */
  x25519_public_key(seed_b64: string): string;
  /** Decrypt a General-JSON JWE for `device_id` with that device's X25519 secret (base64url). */
  decrypt_context(jwe: string, device_id: string, device_secret_b64: string): string;
  /** Compute the WYSIWYS `request_hash` (base64url) over an ApprovalContext + `expires_at`. */
  compute_request_hash(context_json: string, expires_at: number): string;
  /** Sign a verdict with the device key; returns the full Verdict JSON (its `sig` is a JWS). */
  sign_verdict(
    unsigned_json: string,
    device_seed_b64: string,
    nonce_b64: string,
    device_cert: string,
  ): string;
  /** Issue a device→account-root certificate (compact JWS) binding a device key to the account. */
  issue_device_cert(
    account_root_seed_b64: string,
    account_id: string,
    device_id: string,
    device_pubkey_b64: string,
    issued_at: number,
    expires_at?: number,
  ): string;
  /** Encrypt an ApprovalContext to recipient device(s); returns the JWE (test/round-trip helper). */
  encrypt_context(context_json: string, recipients_json: string): string;
  /** Verify a verdict against its request/context and the account-root key (test/round-trip). */
  verify_verdict(
    verdict_json: string,
    request_json: string,
    context_json: string,
    approver_root_pubkey_b64: string,
    now_ms: number,
  ): string;
  /** Verify a compact account-state JWS and return the authenticated AccountState JSON. */
  verify_account_state(
    account_state_jws: string,
    expected_account_id: string,
    account_root_pubkey_b64: string,
  ): string;
  /**
   * Verify an actor attestation (verified request origin, #16), resolving the actor's verifying
   * key from **root-signed account state** — never from a relay-supplied registry. Given the
   * `Actor` JSON (with its `attestation`), the trusted `account_id`, the envelope `request_id`, the
   * request's `request_hash` (base64url), a JSON array of compact `allw-account-state+jws` strings,
   * and the configured account-root public key (base64url), returns a JSON
   * `{ verified: true, actor_id, actor_kind, origin }` on success and **throws** on any failure
   * (missing/spoofed/altered origin, wrong `request_id`/hash, actor not root-anchored or revoked,
   * invalid account state) — fail-closed. A malicious relay cannot mint a verified origin because
   * the actor key is trusted only when it appears, active, in a root-signed account-state document.
   */
  verify_actor_attestation(
    actor_json: string,
    account_id: string,
    request_id: string,
    request_hash_b64: string,
    account_states_json: string,
    account_root_pubkey_b64: string,
  ): string;
}

/** The `--target web` glue module shape we depend on (subset of the generated bindings). */
interface WasmGlue extends AllwWasm {
  initSync(input: { module: WebAssembly.Module }): unknown;
}

/** The directory of this module — the anchor for resolving the vendored wasm. */
export const moduleDir = dirname(fileURLToPath(import.meta.url));

/** The vendored wasm directory, relative to a repo root: `packages/sdk/vendor/allw-wasm`. */
const VENDOR_REL = join("packages", "sdk", "vendor", "allw-wasm");

/**
 * Resolve the directory holding the vendored wasm artifact. The wasm is vendored once under the
 * `@allw/sdk` package (`packages/sdk/vendor/allw-wasm`, built by `pnpm run build:wasm`) so there is
 * a single source of truth across surfaces.
 *
 * Resolution walks **up** from this module's directory looking for `packages/sdk/vendor/allw-wasm`.
 * This works identically whether the approver runs from `src/` (tests) or `dist/` (compiled), and —
 * unlike `require.resolve("@allw/sdk")` — needs no SDK build to have run first, only the wasm build.
 *
 * @throws if the vendored wasm cannot be found (run `pnpm run build:wasm` from the repo root).
 */
function resolveVendorDir(): string {
  let dir = moduleDir;
  // Walk to the filesystem root, checking for the vendored wasm at each ancestor.
  for (;;) {
    const candidate = join(dir, VENDOR_REL);
    if (existsSync(join(candidate, "allw_wasm_bg.wasm"))) return candidate;
    const parent = dirname(dir);
    if (parent === dir || parent === parsePath(dir).root) {
      // Reached the root without finding it — also check the root itself once.
      const rootCandidate = join(parent, VENDOR_REL);
      if (existsSync(join(rootCandidate, "allw_wasm_bg.wasm"))) return rootCandidate;
      throw new Error(
        `vendored wasm not found (looked for ${VENDOR_REL} above ${moduleDir}). ` +
          "Run 'pnpm run build:wasm' from the repo root first.",
      );
    }
    dir = parent;
  }
}

let cached: AllwWasm | undefined;

/**
 * Load (and memoize) the WASM core. Synchronous instantiation after a dynamic import of the glue;
 * idempotent — repeated calls return the same initialized module.
 *
 * @throws if the vendored wasm is missing (run `pnpm run build:wasm` from the repo root first).
 */
export async function loadWasm(): Promise<AllwWasm> {
  if (cached) return cached;
  const vendorDir = resolveVendorDir();
  // A bare path is not a valid ESM specifier on Windows; use a file:// URL (cross-platform parity).
  const gluePath = join(vendorDir, "allw_wasm.js");
  const glue = (await import(pathToFileURL(gluePath).href)) as WasmGlue;
  const wasmPath = join(vendorDir, "allw_wasm_bg.wasm");
  const bytes = readFileSync(wasmPath);
  const module = new WebAssembly.Module(bytes);
  glue.initSync({ module });
  cached = glue;
  return glue;
}
