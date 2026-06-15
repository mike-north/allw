/**
 * Loads the vendored `allw-wasm` core (the audited Rust crypto, compiled to WebAssembly) for the
 * **browser** web approver and exposes the typed subset of its FFI the runtime calls.
 *
 * # Why WASM (a hard constraint, not a preference)
 * All security-critical logic — JWE decryption, the WYSIWYS `request_hash` canonicalization,
 * actor-attestation verification, and verdict signing — lives once in `allw-core` and is reached
 * here through WASM (`docs/architecture.md`). The web approver therefore **never reimplements**
 * crypto/contract logic; this module only loads the core and the runtime only orchestrates JSON in
 * and out of it (thin shell).
 *
 * # Two byte sources, one `--target web` artifact
 * The vendored glue is generated once by `pnpm run build:wasm` (from the repo root) into
 * `@allw/sdk`'s `vendor/allw-wasm`. The same artifact runs in both Node and the browser; only the
 * byte source differs:
 *
 * - **Browser** ({@link initWasm}): pass a `fetch`-able URL / `Response` / `WebAssembly.Module` to
 *   the glue's default async init. This is the production path for the web approver.
 * - **Node** ({@link loadWasm}): read the `.wasm` bytes from disk (resolved via the installed
 *   `@allw/sdk`) and instantiate synchronously. This is the test path; it mirrors
 *   `packages/approver/src/lib/wasm.ts` so there is a single vendored artifact across surfaces.
 *
 * @see ../../../sdk/src/wasm.ts (the SDK loader this complements)
 * @see ../../../approver/src/lib/wasm.ts (the Node device-side loader this mirrors)
 * @see ../../../../docs/architecture.md (WASM-local hard constraint)
 * @see ../../../../docs/contract.md §Wire encoding, §Identity & keys
 */

/**
 * The exact subset of the `allw-wasm` FFI the web approver depends on. Every function takes and
 * returns JSON / base64url **strings** (the language-agnostic wire contract) and **throws** on any
 * error (malformed input, failed decrypt/verify) — fail-closed at the language boundary
 * (`docs/contract.md` §Invariants #6). A hand-maintained mirror of the generated `allw_wasm.d.ts`
 * so this package's types do not require the gitignored vendor directory at downstream type-check.
 */
export interface AllwWasm {
  /** Decrypt a General-JSON JWE for `device_id` with that device's X25519 secret (base64url). */
  decrypt_context(jwe: string, device_id: string, device_secret_b64: string): string;
  /** Compute the WYSIWYS `request_hash` (base64url) over an ApprovalContext JSON + `expires_at`. */
  compute_request_hash(context_json: string, expires_at: number): string;
  /** Derive the four-digit number-match challenge for a base64url request hash. */
  derive_number_match_challenge(request_hash_b64: string): string;
  /**
   * Verify an actor attestation (verified request origin, #16), resolving the actor's verifying key
   * from **root-signed account state** — never from a relay-supplied registry. Returns a JSON
   * `{ verified: true, actor_id, actor_kind, origin }` on success and **throws** on any failure.
   */
  verify_actor_attestation(
    actor_json: string,
    account_id: string,
    request_id: string,
    request_hash_b64: string,
    account_states_json: string,
    account_root_pubkey_b64: string,
  ): string;
  /** Verify a compact account-state JWS and return the authenticated AccountState JSON. */
  verify_account_state(
    account_state_jws: string,
    expected_account_id: string,
    account_root_pubkey_b64: string,
  ): string;
  /** Sign a verdict with the device key; returns the full Verdict JSON (its `sig` is a JWS). */
  sign_verdict(
    unsigned_json: string,
    device_seed_b64: string,
    nonce_b64: string,
    device_cert: string,
  ): string;
  /** Derive the Ed25519 verifying (public) key for a 32-byte signing seed (base64url). */
  ed25519_public_key(seed_b64: string): string;
  /** Derive the X25519 public key for a 32-byte secret seed (base64url). */
  x25519_public_key(seed_b64: string): string;
}

/** A `fetch`-able source for the browser init: a URL string, a URL, or a Response. */
export type WasmModuleSource = string | URL | Response | WebAssembly.Module;

/** The init surface the generated `--target web` glue exposes alongside the FFI functions. */
interface WasmGlue extends AllwWasm {
  default(moduleOrPath?: WasmModuleSource | Promise<WasmModuleSource>): Promise<unknown>;
  initSync(input: { module: WebAssembly.Module } | WebAssembly.Module): unknown;
}

let cached: AllwWasm | undefined;

/**
 * Validate at runtime that a dynamically-imported glue module actually exposes the FFI subset the
 * runtime depends on. The vendored glue is gitignored and untyped at this seam, so a missing build
 * (or a drifted artifact) must fail loudly here rather than as an opaque `undefined is not a
 * function` deep inside a decrypt/sign call.
 */
function assertGlueShape(glue: Partial<WasmGlue>): asserts glue is WasmGlue {
  const required: readonly (keyof AllwWasm)[] = [
    "decrypt_context",
    "compute_request_hash",
    "derive_number_match_challenge",
    "verify_actor_attestation",
    "verify_account_state",
    "sign_verdict",
    "ed25519_public_key",
    "x25519_public_key",
  ];
  for (const fn of required) {
    if (typeof glue[fn] !== "function") {
      throw new Error(
        `allw: vendored WASM glue is missing '${fn}' — the artifact is stale or incomplete. ` +
          `Run \`pnpm run build:wasm\` from the repo root.`,
      );
    }
  }
}

/**
 * Initialize (and memoize) the WASM core in a **browser** from a `fetch`-able byte source.
 *
 * Pass the URL the bundler/host serves `allw_wasm_bg.wasm` from (e.g. an asset URL), a `Response`,
 * or a pre-compiled `WebAssembly.Module`. The `glue` is the dynamically-imported `--target web`
 * module (`@allw/sdk/vendor/allw-wasm/allw_wasm.js`); it is injected so this package never hard-codes
 * a vendor path the browser cannot resolve. Idempotent: repeated calls return the same instance.
 *
 * @throws if the glue is missing the FFI subset, or instantiation fails.
 */
export async function initWasm(
  glueModule: unknown,
  moduleSource: WasmModuleSource | Promise<WasmModuleSource>,
): Promise<AllwWasm> {
  if (cached) return cached;
  const glue = glueModule as Partial<WasmGlue>;
  assertGlueShape(glue);
  await glue.default(moduleSource);
  cached = glue;
  return glue;
}

/**
 * Initialize (and memoize) the WASM core from an already-imported glue module and a pre-compiled
 * `WebAssembly.Module`, synchronously instantiating it. Useful for Node/test hosts that read the
 * bytes themselves; the browser path is {@link initWasm}.
 *
 * @throws if the glue is missing the FFI subset.
 */
export function initWasmSync(glueModule: unknown, module: WebAssembly.Module): AllwWasm {
  if (cached) return cached;
  const glue = glueModule as Partial<WasmGlue>;
  assertGlueShape(glue);
  glue.initSync({ module });
  cached = glue;
  return glue;
}

/** Reset the memoized core. Test-only seam so independent suites can re-init a fresh instance. */
export function resetWasmForTests(): void {
  cached = undefined;
}
