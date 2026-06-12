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

/**
 * The outcome of verifying a request's actor attestation (the *verified origin*, #16). Either the
 * origin is cryptographically verified (and carries a display string), or it is unverified — with a
 * concrete `reason` the renderer surfaces so an unverifiable origin is never shown as trusted.
 *
 * Fail-closed: a missing attestation, an unenrolled actor, a relay outage, or a failed verification
 * all yield `verified: false`. There is no "unknown → trusted" path.
 */
export type OriginVerification =
  | {
      readonly verified: true;
      /** Human-readable verified origin (`"{kind} · {id}"`) from the core. */
      readonly origin: string;
    }
  | {
      readonly verified: false;
      /** Why the origin could not be verified (shown alongside the ⚠ marker). */
      readonly reason: string;
    };

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
  /**
   * The actor-attestation outcome (#16). `undefined` only when origin verification was not
   * attempted (e.g. no relay configured); the renderer treats absent/unverified identically — it
   * never shows an unverified origin as trusted.
   */
  readonly origin?: OriginVerification;
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
 * 2. **Device-side fail-closed expiry** (`docs/contract.md` §Invariants #6): refuse a request whose
 *    `expires_at <= nowMs` BEFORE decrypting/rendering. A dead request must never be presented to
 *    the human or signed — the device, not just the relay (#43), enforces this, so a generous
 *    integrator clock-skew window can never accept a stale-but-signed approval.
 * 3. `decrypt_context` the `context_ciphertext` with the **device X25519 seed** (via the core).
 * 4. Recompute `request_hash` over the decrypted context + the envelope's `expires_at` (the core
 *    pins the canonicalization; the integrator computed the same bytes pre-send — WYSIWYS).
 *
 * The recomputed hash IS the binding the human's verdict will carry, so by signing over it the
 * approver proves it saw exactly the bytes it rendered. Any failure throws (deny-by-default).
 *
 * @param nowMs current time in Unix ms — injected so expiry is deterministic/testable (no
 *   wall-clock read inside).
 * @throws on a malformed envelope, an **already-expired** request, a JWE the device key cannot
 *   decrypt, or a malformed context.
 */
export function prepareRequest(
  wasm: AllwWasm,
  keyfile: Keyfile,
  rawEnvelope: unknown,
  nowMs: number,
): RenderableRequest {
  const envelope = parseEnvelope(rawEnvelope);

  // Fail-closed expiry — refuse a dead request before any decrypt/render/sign work.
  if (envelope.expires_at <= nowMs) {
    throw new Error(
      `request ${envelope.id} is expired (expires_at ${String(envelope.expires_at)} <= now ${String(nowMs)})`,
    );
  }

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
 * Verify a prepared request's **actor attestation** and return the verified-origin outcome (#16,
 * `docs/contract.md` §Invariants #4 — requester attestation). Resolves to a discriminated
 * {@link OriginVerification} the renderer consumes; it never throws for an *unverifiable* origin —
 * a failure is a `verified: false` result with a reason, so a bad origin downgrades the display
 * rather than aborting the request (the human still sees the action, just with an explicit ⚠).
 *
 * # Trust anchor: root-signed account state, never the relay (#16 blocker fix)
 * The attestation binds the actor identity to the request's `request_id` + recomputed
 * `request_hash` (so it is request-specific, not a reusable token), and is verified against the
 * actor key **resolved from root-signed account state** (`docs/enrollment.md` §Account State) — NOT
 * a relay-supplied `/actors` key. The WASM core verifies each account-state document against
 * `accountRootPubkey` and only trusts an actor key that appears, active and un-revoked, in the
 * highest-sequence document. A malicious or compromised relay can list its own key in `/actors`,
 * but it cannot author account state, so it can never drive a `verified: true` (✓ VERIFIED) result.
 *
 * @param accountId the account the device trusts (the attestation's `account_id` must match).
 * @param accountRootPubkey the configured account-root verifying key (base64url) — the device's
 *   trust anchor (from its keyfile), against which every account-state document is checked.
 * @param accountStates root-signed `allw-account-state+jws` documents that enroll the trusted actor
 *   keys. An empty list (no root-anchored trust available) yields an unverified origin, never an
 *   abort — the human still reviews the action with an explicit ⚠.
 */
export function verifyActorOrigin(
  wasm: AllwWasm,
  prepared: RenderableRequest,
  accountId: string,
  accountRootPubkey: string,
  accountStates: readonly string[],
): OriginVerification {
  const actor = prepared.context.actor;
  // No attestation present → unverifiable plaintext (mirrors the core's fail-closed `Missing`).
  if (actor.attestation === undefined || actor.attestation.length === 0) {
    return { verified: false, reason: "no attestation present (origin is unauthenticated)" };
  }
  // No root-anchored trust material → we cannot establish trust; show unverified, do not abort.
  // (Crucially: a relay-supplied `/actors` key is NEVER accepted here — only root-signed account
  // state can root-anchor an actor key.)
  if (accountStates.length === 0) {
    return {
      verified: false,
      reason: `no root-signed account state to anchor actor '${actor.id}' (origin not root-anchored)`,
    };
  }
  try {
    const resultJson = wasm.verify_actor_attestation(
      JSON.stringify(actor),
      accountId,
      prepared.requestId,
      prepared.requestHash,
      JSON.stringify(accountStates),
      accountRootPubkey,
    );
    const result = JSON.parse(resultJson) as { origin?: unknown };
    const origin =
      typeof result.origin === "string" ? result.origin : `${actor.kind} · ${actor.id}`;
    return { verified: true, origin };
  } catch (err) {
    // A failed verification (spoofed/altered origin, non-root-anchored key, revoked actor, wrong
    // request id/hash) is reported as unverified — the request is still rendered, but the origin is
    // explicitly NOT trusted (fail-closed display).
    return {
      verified: false,
      reason: `attestation failed verification: ${(err as Error).message}`,
    };
  }
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
