/**
 * The cryptographic heart of the approver: turn an inbound encrypted request into a rendered
 * WYSIWYS payload, and turn a human decision into a correctly-signed verdict — all through the
 * WASM core (`docs/contract.md` §Lifecycle steps 4–5). **No crypto/contract logic is implemented
 * here**; this module only orchestrates the core and assembles plaintext JSON the core consumes.
 *
 * # Fail-closed (`docs/contract.md` §Invariants #6)
 * Every parse/decrypt failure throws. A thrown error aborts that one request safely — the approver
 * never fabricates an approval, and a request it cannot decrypt/parse simply yields no verdict
 * (which leaves the integrator's gate closed: deny-by-default). The approver only ever emits a
 * verdict that the WASM core signed over the real human decision.
 */

import { webcrypto } from "node:crypto";

import type { AllwWasm } from "./wasm.js";
import type { ApprovalContext, ApprovalRequest, Decision, UnsignedVerdict } from "./types.js";
import type { Keyfile } from "./keyfile.js";

/** Verdict protocol/schema version (`docs/contract.md` §Wire encoding). */
const VERDICT_VERSION = 1 as const;

/** Anti-replay nonce length in bytes. The core is length-agnostic; the contract requires ≥16. */
const NONCE_BYTES = 16;

/** A decrypted, hash-verified request ready to render to the human (WYSIWYS). */
export interface RenderableRequest {
  /** The envelope's request id (also the verdict's `request_id`). */
  readonly requestId: string;
  /** The decrypted human-shown context. */
  readonly context: ApprovalContext;
  /** Fail-closed deadline (ms) read from the envelope and bound into `request_hash`. */
  readonly expiresAt: number;
  /** The WYSIWYS `request_hash` (base64url) the core computed from `context` + `expiresAt`. */
  readonly requestHash: string;
}

/** A high-entropy anti-replay nonce as a base64url string (≥16 random bytes). */
export function generateNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  webcrypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}

/** Type guard: a parsed value is a string-keyed plain object (rejects arrays/null). */
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Validate the relay-visible envelope fields the approver depends on. The relay forwards the
 * envelope verbatim; we re-validate fail-closed because a malformed envelope must not flow into
 * the decrypt/hash path. Throws on any missing/ill-typed field.
 */
function parseEnvelope(value: unknown): ApprovalRequest {
  if (!isRecord(value)) throw new Error("envelope is not a JSON object");
  const { id, expires_at, context_ciphertext } = value;
  if (typeof id !== "string" || id.length === 0) {
    throw new Error("envelope is missing a string 'id'");
  }
  if (typeof expires_at !== "number" || !Number.isFinite(expires_at)) {
    throw new Error("envelope is missing a numeric 'expires_at'");
  }
  if (typeof context_ciphertext !== "string" || context_ciphertext.length === 0) {
    throw new Error("envelope is missing the 'context_ciphertext' (JWE) string");
  }
  return value as unknown as ApprovalRequest;
}

/**
 * Decrypt and prepare an inbound request for rendering (`docs/contract.md` §Lifecycle step 4):
 *
 * 1. Validate the envelope (fail-closed).
 * 2. `decrypt_context` the `context_ciphertext` with the **device X25519 seed** (via the core).
 * 3. Recompute `request_hash` over the decrypted context + the envelope's `expires_at` (the core
 *    pins the canonicalization; the integrator computed the same bytes pre-send — WYSIWYS).
 *
 * The recomputed hash IS the binding the human's verdict will carry, so by signing over it the
 * approver proves it saw exactly the bytes it rendered. Any failure throws (deny-by-default).
 *
 * @throws on a malformed envelope, a JWE the device key cannot decrypt, or a malformed context.
 */
export function prepareRequest(
  wasm: AllwWasm,
  keyfile: Keyfile,
  rawEnvelope: unknown,
): RenderableRequest {
  const envelope = parseEnvelope(rawEnvelope);
  const ciphertext = envelope.context_ciphertext;
  if (ciphertext === undefined) {
    // Unreachable after parseEnvelope, but keeps the type narrow without a non-null assertion.
    throw new Error("envelope has no context_ciphertext");
  }
  const deviceId = keyfile.device_id;
  if (deviceId === undefined || deviceId.length === 0) {
    throw new Error("keyfile has no device_id — pair the approver before watching");
  }

  // Decrypt via the core. A wrong key / tampered ciphertext / malformed JWE throws here.
  const contextJson = wasm.decrypt_context(ciphertext, deviceId, keyfile.device_encryption_seed);

  let context: unknown;
  try {
    context = JSON.parse(contextJson);
  } catch (err) {
    throw new Error(`decrypted context is not valid JSON: ${(err as Error).message}`);
  }
  if (!isRecord(context)) {
    throw new Error("decrypted context is not a JSON object");
  }

  // Recompute the WYSIWYS request_hash from the decrypted plaintext + the envelope's expires_at.
  // The core canonicalizes (RFC 8785 JCS) and hashes; we never derive these bytes ourselves.
  const requestHash = wasm.compute_request_hash(contextJson, envelope.expires_at);

  return {
    requestId: envelope.id,
    context: context as unknown as ApprovalContext,
    expiresAt: envelope.expires_at,
    requestHash,
  };
}

/**
 * Sign a verdict for a prepared request (`docs/contract.md` §Lifecycle step 5). Assembles the
 * unsigned verdict (echoing the recomputed `request_hash`, so the signature binds to exactly what
 * was rendered), generates a fresh ≥16-byte nonce, and hands it to the core's `sign_verdict` with
 * the **device signing seed** and the **device_cert** (so verifiers chain to the account root).
 *
 * Returns the full signed `Verdict` as a parsed JSON value, ready to wrap in a
 * `{ type: "verdict", request_id, verdict }` relay message.
 *
 * @throws if the keyfile is not paired (no device id / cert), or the core rejects the inputs.
 */
export function signDecision(
  wasm: AllwWasm,
  keyfile: Keyfile,
  prepared: RenderableRequest,
  decision: Decision,
  decidedAt: number,
  note?: string,
): unknown {
  const accountId = keyfile.account_id;
  const deviceId = keyfile.device_id;
  const cert = keyfile.device_cert;
  if (accountId === undefined || deviceId === undefined) {
    throw new Error("keyfile is not paired (missing account_id/device_id)");
  }
  if (cert === undefined || cert.length === 0) {
    // A verdict without a cert cannot chain to the account root → verify_verdict would reject it.
    throw new Error("keyfile has no device_cert — re-pair to mint one before deciding");
  }

  const unsigned: UnsignedVerdict = {
    v: VERDICT_VERSION,
    request_id: prepared.requestId,
    request_hash: prepared.requestHash,
    decision,
    decided_at: decidedAt,
    approver: { account_id: accountId, device_id: deviceId },
    ...(note !== undefined && note.length > 0 ? { note } : {}),
  };

  const nonce = generateNonce();
  const verdictJson = wasm.sign_verdict(
    JSON.stringify(unsigned),
    keyfile.device_signing_seed,
    nonce,
    cert,
  );
  return JSON.parse(verdictJson) as unknown;
}
