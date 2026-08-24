/**
 * The browser {@link WebApproverRuntime}: turn an inbound encrypted relay envelope into a rendered
 * WYSIWYS {@link PreparedApproval}, and turn the human's decision into a correctly-signed verdict —
 * **every cryptographic step delegated to the audited Rust core via WASM** (`docs/contract.md`
 * §Lifecycle steps 4–5; `docs/architecture.md` thin-shell). No crypto, hashing, or verification is
 * implemented here: this module only orchestrates the core and maps its JSON onto the controller's
 * view types.
 *
 * # Fail-closed (`docs/contract.md` §Invariants #6)
 * Any failure in {@link createWasmRuntime}'s `prepare` — a malformed envelope, an already-expired
 * request, a JWE the device key cannot decrypt, a tampered context, or a malformed plaintext —
 * **throws**. The controller maps a thrown `prepare` to the `unverified` (deny-only) state, so an
 * unverifiable request is never rendered as approvable. The actor-origin attestation is *not*
 * fail-closed in the same way: an unverifiable origin downgrades the rendered attestation to
 * `unverified` (the human still reviews the action) rather than blocking the whole request.
 *
 * `signDecision` only ever returns a verdict the core signed over the real human decision; it
 * re-checks the number-match challenge and refuses to sign without a paired device cert.
 */

import type {
  ApprovalActor,
  ApprovalContext,
  ApprovalDecision,
  ApprovalEnvelope,
  ApprovalRisk,
  CommandAction,
  McpCallAction,
  NumberMatchChallenge,
  PreparedApproval,
  SignDecisionInput,
  SignedVerdict,
  WebApproverRuntime,
} from "./index.js";
import type { AccountStateFloorStore } from "./sequence-floor.js";
import { createInMemoryAccountStateFloorStore } from "./sequence-floor.js";
import type { AllwWasm, WasmModuleSource } from "./wasm.js";
import { initWasm } from "./wasm.js";

/** Verdict protocol/schema version (`docs/contract.md` §Wire encoding). */
const VERDICT_VERSION = 1 as const;

/** Anti-replay nonce length in bytes. The core is length-agnostic; the contract requires ≥16. */
const NONCE_BYTES = 16;

/**
 * The device/account key material the runtime signs and decrypts with. In the browser this is
 * supplied by the surrounding pairing/session layer (out of scope here — #91/#23); the runtime
 * never derives or persists keys, it only hands the seeds to the WASM core.
 *
 * # ⚠ v0 stand-in — software-held seeds
 * Carrying raw seeds in JS memory mirrors the v0 device keyfile and is a deliberate stand-in until
 * hardware custody (#23). The wire protocol does not depend on key custody, so #23 swaps in later.
 */
export interface ApproverIdentity {
  /** The account id the device trusts (the verdict's `approver.account_id`). */
  readonly accountId: string;
  /** The relay device id assigned at pairing (the verdict's `approver.device_id`, JWE recipient). */
  readonly deviceId: string;
  /** ⚠ secret — X25519 device encryption seed (base64url, 32 bytes); decrypts `context_ciphertext`. */
  readonly deviceEncryptionSeed: string;
  /** ⚠ secret — Ed25519 device signing seed (base64url, 32 bytes); signs verdicts. */
  readonly deviceSigningSeed: string;
  /** Device→account-root certificate (compact JWS) minted at pairing; chains verdicts to the root. */
  readonly deviceCert: string;
  /** Ed25519 account-root verifying key (base64url) — the device's attestation trust anchor. */
  readonly accountRootPubkey: string;
  /**
   * ⚠ secret — the relay-issued bearer token authorizing this device against
   * `devices/{id}/inbox`, `devices/{id}/connect`, and `account-states` (`docs/relay-api.md`
   * §Device (approver) endpoints). Distinct from {@link deviceCert}: the cert chains verdict
   * signatures to the account root, while this token is an opaque relay-routing credential the
   * relay itself minted and hashes for storage. Required to drive live relay polling (#147) or
   * account-state resolution (#155) from a paired browser.
   */
  readonly deviceAuthToken: string;
}

/**
 * The relay-visible resolution for an actor's root-signed account-state documents, optionally
 * carrying the relay's own `max_sequence` publish bookkeeping for THIS fetch (`docs/relay-api.md`
 * `GET /{account_id}/account-states`; #171). `maxSequence` is never a substitute for root-signature
 * verification — it only tells the sequence-floor gate in {@link resolveAttestation} what the relay
 * itself is currently asserting, so a relay that under-reports it (to match a re-served older
 * document) can be caught even before comparing against the device-persisted floor.
 */
export interface AccountStateResolution {
  readonly accountStates: readonly string[];
  readonly maxSequence?: number;
}

/**
 * Resolve the root-signed account-state documents (compact `allw-account-state+jws`) that
 * root-anchor an actor's verifying key for origin verification (#16, `docs/enrollment.md` §Account
 * State). Returns an empty list (or a resolution with an empty `accountStates`) when no
 * root-anchored trust material is available → the origin renders `unverified` (never an abort; a
 * relay-supplied key is NEVER trusted). Defaults to "no resolution" so the runtime is usable before
 * relay account-state wiring (#147+) lands.
 *
 * A resolver may return either the bare array (no `max_sequence` metadata available) or the full
 * {@link AccountStateResolution} (with `maxSequence`) — {@link createRelayAccountStateResolver}
 * returns the latter on a successful fetch.
 */
export type AccountStateResolver = (
  actorId: string,
) => Promise<readonly string[] | AccountStateResolution>;

/** Normalize either return shape of {@link AccountStateResolver} to the full resolution object. */
function normalizeAccountStateResolution(
  resolution: readonly string[] | AccountStateResolution,
): AccountStateResolution {
  if (Array.isArray(resolution)) return { accountStates: resolution };
  return resolution as AccountStateResolution;
}

/**
 * The highest ROOT-VERIFIED `sequence` among `accountStates`, or `null` if any entry fails root
 * verification or lacks a well-formed `sequence` (fail-closed: a single bad/unparseable document
 * must not let a lower verified sequence pass silently). Delegates all signature/shape verification
 * to the WASM core (`wasm.verify_account_state`); this only reduces the verified results to a
 * maximum — no crypto or trust logic lives here (thin shell, `docs/architecture.md`). Never throws
 * (mirrors `packages/approver/src/commands/watch.ts`'s Node analogue, but catches per-document
 * verification failures locally so a malformed account state downgrades the origin display instead
 * of aborting the whole `prepare()` call).
 */
function highestVerifiedAccountStateSequence(
  wasm: AllwWasm,
  accountStates: readonly string[],
  accountId: string,
  accountRootPubkey: string,
): number | null {
  let highest: number | null = null;
  for (const accountState of accountStates) {
    let verified: { sequence?: unknown };
    try {
      verified = JSON.parse(
        wasm.verify_account_state(accountState, accountId, accountRootPubkey),
      ) as { sequence?: unknown };
    } catch {
      return null;
    }
    if (typeof verified.sequence !== "number" || !Number.isSafeInteger(verified.sequence)) {
      return null;
    }
    highest = highest === null ? verified.sequence : Math.max(highest, verified.sequence);
  }
  return highest;
}

/** Options for {@link createWasmRuntime}. */
export interface WasmRuntimeOptions {
  readonly wasm: AllwWasm;
  readonly identity: ApproverIdentity;
  /** Resolve root-signed account-state docs for origin verification. Defaults to none (unverified). */
  readonly resolveAccountStates?: AccountStateResolver;
  /**
   * Persists the device-side account-state rollback floor (#171) across `prepare()` calls. Defaults
   * to an in-memory store (no cross-reload persistence) — the production boot sequence (`app.ts`)
   * supplies {@link createLocalAccountStateFloorStore} explicitly so the floor survives reloads.
   */
  readonly sequenceFloorStore?: AccountStateFloorStore;
  /** Clock seam (ms). Defaults to `Date.now`; injected so fail-closed expiry is deterministic. */
  readonly nowMs?: () => number;
}

/** Type guard: a parsed value is a string-keyed plain object (rejects arrays/null). */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A high-entropy anti-replay nonce as a base64url string (≥16 random bytes). Browser-safe CSPRNG. */
function generateNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  crypto.getRandomValues(bytes);
  // base64url-unpadded, matching every JOSE wire field — no Node Buffer dependency.
  return base64UrlEncode(bytes);
}

/** Encode bytes as base64url-unpadded without a Node `Buffer` (browser/Node parity). */
function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/**
 * Validate the relay-visible envelope fields the runtime depends on before any crypto. The relay
 * forwards the envelope verbatim, so a malformed one must be rejected fail-closed rather than flow
 * into the decrypt/hash path.
 */
function validateEnvelope(envelope: ApprovalEnvelope): void {
  if (typeof envelope.id !== "string" || envelope.id.length === 0) {
    throw new Error("envelope is missing a string 'id'");
  }
  if (typeof envelope.expires_at !== "number" || !Number.isFinite(envelope.expires_at)) {
    throw new Error("envelope is missing a numeric 'expires_at'");
  }
  if (typeof envelope.context_ciphertext !== "string" || envelope.context_ciphertext.length === 0) {
    throw new Error("envelope is missing the 'context_ciphertext' (JWE) string");
  }
}

/** The decrypted wire context (Rust `allw_core::ApprovalContext` serde shape). */
interface WireApprovalContext {
  readonly action: { readonly surface: string; readonly syntactic: unknown; readonly risk: string };
  readonly summary: string;
  readonly actor: { readonly id: string; readonly kind: string; readonly attestation?: string };
  readonly risk: string;
  readonly reversible: boolean;
  readonly constraints: {
    readonly allowed_decisions: readonly string[];
    readonly challenge_required: boolean;
  };
}

/** Narrow a decrypted, untrusted value to the wire-context shape the renderer/mapper depends on. */
function asWireContext(value: unknown): WireApprovalContext {
  if (!isRecord(value)) throw new Error("decrypted context is not a JSON object");
  if (!isRecord(value.action)) throw new Error("decrypted context is missing an 'action' object");
  if (!isRecord(value.actor)) throw new Error("decrypted context is missing an 'actor' object");
  if (!isRecord(value.constraints)) throw new Error("decrypted context is missing 'constraints'");
  return value as unknown as WireApprovalContext;
}

const RISK_LEVELS: readonly ApprovalRisk["level"][] = ["low", "medium", "high", "critical"];

/** Coerce an untrusted risk string to a known level, defaulting to the most severe (fail-closed). */
function toRiskLevel(value: unknown): ApprovalRisk["level"] {
  return RISK_LEVELS.includes(value as ApprovalRisk["level"])
    ? (value as ApprovalRisk["level"])
    : "critical";
}

/** Narrow the allowed-decision wire strings to the controller's `ApprovalDecision` union. */
function toAllowedDecisions(values: readonly string[]): readonly ApprovalDecision[] {
  return values.filter((d): d is ApprovalDecision => d === "approved" || d === "denied");
}

/**
 * Map an untrusted, decrypted wire syntactic substrate onto the controller's {@link CommandAction}.
 * The substrate is opaque plaintext (`docs/policy-seam.md`); we read only the display-relevant
 * fields the renderer surfaces and default the rest, never interpreting the structure.
 */
function toCommandAction(syntactic: unknown): CommandAction | undefined {
  if (!isRecord(syntactic)) return undefined;
  const argv = Array.isArray(syntactic.argv)
    ? syntactic.argv.filter((a): a is string => typeof a === "string")
    : [];
  const command: CommandAction = { argv };
  const withCwd = typeof syntactic.cwd === "string" ? { ...command, cwd: syntactic.cwd } : command;
  return typeof syntactic.raw === "string" ? { ...withCwd, raw: syntactic.raw } : withCwd;
}

/** Map an untrusted, decrypted wire syntactic substrate onto the controller's {@link McpCallAction}. */
function toMcpAction(syntactic: unknown): McpCallAction | undefined {
  if (!isRecord(syntactic)) return undefined;
  if (typeof syntactic.server !== "string" || typeof syntactic.tool !== "string") return undefined;
  return { server: syntactic.server, tool: syntactic.tool, params: syntactic.params };
}

/**
 * Map the decrypted wire context + verified attestation + (optional) derived challenge onto the
 * controller's {@link ApprovalContext} view model. Surfaces other than `command`/`mcp_tool_call`
 * (e.g. `file_edit`) render as `command` with an empty action so the controller shows them as an
 * "Unknown action" rather than fabricating structure — the WYSIWYS hash still binds the full
 * plaintext regardless of this display mapping.
 */
function toApprovalContext(
  wire: WireApprovalContext,
  attestation: ApprovalActor["attestation"],
  challenge: NumberMatchChallenge | undefined,
): ApprovalContext {
  const actor: ApprovalActor = {
    id: wire.actor.id,
    display: `${wire.actor.id} (${wire.actor.kind})`,
    attestation,
  };
  const risk: ApprovalRisk = {
    level: toRiskLevel(wire.risk),
    reversible: wire.reversible,
    summary: wire.summary,
  };
  const allowed = toAllowedDecisions(wire.constraints.allowed_decisions);
  const kind: ApprovalContext["kind"] = wire.action.surface === "mcp_tool_call" ? "mcp" : "command";

  // Spread the surface-specific action only when present so `exactOptionalPropertyTypes` keeps the
  // optional `command`/`mcp`/`challenge` keys absent (not explicitly `undefined`).
  const base = { kind, actor, risk, allowed_decisions: allowed } as const;
  let withAction: ApprovalContext;
  if (kind === "mcp") {
    const mcp = toMcpAction(wire.action.syntactic);
    withAction = mcp ? { ...base, mcp } : base;
  } else {
    const command = toCommandAction(wire.action.syntactic);
    withAction = command ? { ...base, command } : base;
  }
  return challenge ? { ...withAction, challenge } : withAction;
}

/**
 * Verify the actor attestation through the core and reduce it to the rendered attestation badge.
 * Fail-closed *display*: any failure (no attestation, no root-anchored trust, spoofed/altered
 * origin, revoked actor, stale/rolled-back account state) yields `unverified` — never `verified`. A
 * relay-supplied key is never trusted; only a root-signed account-state document can drive
 * `verified`.
 *
 * # Device-side account-state rollback floor (#171, `docs/enrollment.md` §Account State step 5)
 * Before delegating to `verify_actor_attestation`, this gates on TWO independent signals so a
 * compromised relay cannot suppress a newer revocation by re-serving an older, still-validly
 * root-signed account-state document:
 *
 * 1. **This fetch's relay `max_sequence` metadata** must be backed by a root-verified document at
 *    least that new (a relay that under-reports its own metadata to match a stale doc is caught).
 * 2. **The device-persisted floor** (`sequenceFloorStore`, survives reloads) — the highest
 *    root-verified sequence this device has EVER accepted. A fetch below it fails closed even if
 *    the relay's metadata for THIS call is internally consistent with the stale documents it served.
 *
 * A verified-highest-sequence below EITHER signal renders `unverified` — the effective threshold a
 * fetch must reach is the higher of the two. On success (and only then) the floor is bumped to the
 * newly observed highest sequence, never lowered.
 */
function resolveAttestation(
  wasm: AllwWasm,
  wire: WireApprovalContext,
  requestId: string,
  requestHash: string,
  accountId: string,
  accountRootPubkey: string,
  accountStates: readonly string[],
  relayMaxSequence: number | undefined,
  sequenceFloorStore: AccountStateFloorStore,
): ApprovalActor["attestation"] {
  if (wire.actor.attestation === undefined || wire.actor.attestation.length === 0) {
    return "unverified";
  }
  if (accountStates.length === 0) return "unverified";

  const persistedFloor = sequenceFloorStore.load();
  // Only pay for verifying every account-state document's sequence when a comparison is actually
  // needed — neither signal present means there is nothing to gate against yet.
  const verifiedHighestSequence =
    (relayMaxSequence !== undefined && relayMaxSequence > 0) || persistedFloor > 0
      ? highestVerifiedAccountStateSequence(wasm, accountStates, accountId, accountRootPubkey)
      : null;

  if (
    relayMaxSequence !== undefined &&
    relayMaxSequence > 0 &&
    (verifiedHighestSequence === null || verifiedHighestSequence < relayMaxSequence)
  ) {
    // The relay's own metadata for THIS fetch is not backed by what it actually served.
    return "unverified";
  }
  if (
    persistedFloor > 0 &&
    (verifiedHighestSequence === null || verifiedHighestSequence < persistedFloor)
  ) {
    // This fetch never reaches the highest sequence this device has previously accepted.
    return "unverified";
  }
  if (verifiedHighestSequence !== null && verifiedHighestSequence > persistedFloor) {
    sequenceFloorStore.save(verifiedHighestSequence);
  }

  try {
    wasm.verify_actor_attestation(
      JSON.stringify(wire.actor),
      accountId,
      requestId,
      requestHash,
      JSON.stringify(accountStates),
      accountRootPubkey,
    );
    return "verified";
  } catch {
    return "unverified";
  }
}

/**
 * Construct a browser {@link WebApproverRuntime} backed by the WASM core.
 *
 * `prepare` (fail-closed): validate envelope → device-side expiry check → `decrypt_context` →
 * recompute the WYSIWYS `request_hash` → derive the number-match challenge (if required) → verify
 * the actor origin → map to the controller's view model. Any crypto/parse failure throws, which the
 * controller renders as `unverified`.
 *
 * `signDecision`: re-check the number-match challenge, assemble the unsigned verdict echoing the
 * recomputed `request_hash` (so the signature binds to exactly what was rendered — WYSIWYS), and
 * hand it to `sign_verdict` with the device signing seed + cert. Returns the signed verdict JSON.
 */
export function createWasmRuntime(options: WasmRuntimeOptions): WebApproverRuntime {
  const { wasm, identity } = options;
  const nowMs = options.nowMs ?? Date.now;
  const resolveAccountStates: AccountStateResolver =
    options.resolveAccountStates ?? (() => Promise.resolve([]));
  const sequenceFloorStore: AccountStateFloorStore =
    options.sequenceFloorStore ?? createInMemoryAccountStateFloorStore();

  // The recomputed request_hash is the binding the verdict carries; cache it per request id so
  // `signDecision` signs over exactly the bytes `prepare` recomputed (never re-derived from the
  // controller's mapped view, which is lossy by design).
  const hashByRequestId = new Map<string, string>();

  async function prepare(envelope: ApprovalEnvelope): Promise<PreparedApproval> {
    validateEnvelope(envelope);

    // Device-side fail-closed expiry: refuse a dead request before any decrypt/render work, so a
    // generous integrator clock-skew window can never accept a stale-but-signed approval (#43).
    if (envelope.expires_at <= nowMs()) {
      throw new Error(
        `request ${envelope.id} is expired (expires_at ${String(envelope.expires_at)} <= now)`,
      );
    }

    // Decrypt via the core. A wrong key / tampered ciphertext / malformed JWE throws here.
    const contextJson = wasm.decrypt_context(
      envelope.context_ciphertext,
      identity.deviceId,
      identity.deviceEncryptionSeed,
    );

    let parsed: unknown;
    try {
      parsed = JSON.parse(contextJson);
    } catch (err) {
      throw new Error(`decrypted context is not valid JSON: ${(err as Error).message}`);
    }
    const wire = asWireContext(parsed);

    // Recompute the WYSIWYS request_hash from the decrypted plaintext + the envelope's expires_at.
    // The core canonicalizes (RFC 8785 JCS) and hashes; we never derive these bytes ourselves. A
    // context tampered between encrypt and render yields a different hash than the integrator's, so
    // the eventual verify_verdict (bound to the integrator's hash) fails closed — WYSIWYS.
    const requestHash = wasm.compute_request_hash(contextJson, envelope.expires_at);

    const challenge: NumberMatchChallenge | undefined = wire.constraints.challenge_required
      ? {
          kind: "number-match",
          code: wasm.derive_number_match_challenge(requestHash),
          prompt: "Enter the code shown by the requesting CLI.",
        }
      : undefined;

    let accountStates: readonly string[] = [];
    let relayMaxSequence: number | undefined;
    try {
      const resolved = normalizeAccountStateResolution(await resolveAccountStates(wire.actor.id));
      accountStates = resolved.accountStates;
      relayMaxSequence = resolved.maxSequence;
    } catch {
      // A resolver outage downgrades origin to unverified — it must never block the action review.
      accountStates = [];
    }
    const attestation = resolveAttestation(
      wasm,
      wire,
      envelope.id,
      requestHash,
      identity.accountId,
      identity.accountRootPubkey,
      accountStates,
      relayMaxSequence,
      sequenceFloorStore,
    );

    hashByRequestId.set(envelope.id, requestHash);

    return {
      requestHash,
      // The core-verified expiry IS the envelope's expires_at, the value bound into request_hash.
      // The controller must not trust a relay-visible timestamp that is not hash-bound; this one is.
      expiresAt: envelope.expires_at,
      context: toApprovalContext(wire, attestation, challenge),
    };
  }

  // `async` so a validation failure (missing/wrong challenge, core reject) surfaces as a rejected
  // promise — never a synchronous throw — for callers that consume it via `.then/.catch` (the
  // controller's double-submit guard awaits it). Every core step is synchronous, hence the trivial
  // `await` to satisfy both the `WebApproverRuntime` contract and the no-floating-async lint.
  // eslint-disable-next-line @typescript-eslint/require-await -- async is the contract; reject-not-throw on validation failure
  async function signDecision(input: SignDecisionInput): Promise<SignedVerdict> {
    const { envelope, prepared, decision, challengeResponse } = input;
    // Sign over the hash `prepare` recomputed (cache-first), falling back to the prepared value —
    // both are the device-recomputed WYSIWYS hash, never a value re-derived from the lossy view.
    const requestHash = hashByRequestId.get(envelope.id) ?? prepared.requestHash;

    const challenge = prepared.context.challenge;
    if (decision === "approved" && challenge?.kind === "number-match") {
      if (challengeResponse === undefined || challengeResponse.length === 0) {
        throw new Error("approval requires a number-match challenge response");
      }
      if (challengeResponse !== challenge.code) {
        throw new Error("challenge response does not match the derived number-match code");
      }
    }

    const unsigned = {
      v: VERDICT_VERSION,
      request_id: envelope.id,
      request_hash: requestHash,
      decision,
      decided_at: nowMs(),
      approver: { account_id: identity.accountId, device_id: identity.deviceId },
      ...(decision === "approved" && challengeResponse !== undefined && challengeResponse.length > 0
        ? { challenge_response: challengeResponse }
        : {}),
    };

    const nonce = generateNonce();
    // All signing happens in the core; we only assemble the unsigned JSON and pass the device key.
    const verdictJson = wasm.sign_verdict(
      JSON.stringify(unsigned),
      identity.deviceSigningSeed,
      nonce,
      identity.deviceCert,
    );

    return {
      requestId: envelope.id,
      decision,
      signedVerdictJson: verdictJson,
    };
  }

  return { prepare, signDecision };
}

/** Options for {@link createBrowserRuntime}. */
export interface BrowserRuntimeOptions {
  /**
   * The dynamically-imported `--target web` glue module
   * (`@allw/sdk/vendor/allw-wasm/allw_wasm.js`). Injected so this package never hard-codes a vendor
   * path the browser/bundler cannot resolve.
   */
  readonly glueModule: unknown;
  /** A `fetch`-able source for the `.wasm` bytes (asset URL / `Response` / `WebAssembly.Module`). */
  readonly moduleSource: WasmModuleSource | Promise<WasmModuleSource>;
  readonly identity: ApproverIdentity;
  readonly resolveAccountStates?: AccountStateResolver;
  /** Persists the device-side account-state rollback floor (#171) across reloads when supplied. */
  readonly sequenceFloorStore?: AccountStateFloorStore;
  readonly nowMs?: () => number;
}

/**
 * Initialize the WASM core in a browser and construct a wired {@link WebApproverRuntime} in one
 * step — the production bootstrap for the web approver. Equivalent to {@link initWasm} followed by
 * {@link createWasmRuntime}, but co-located so a host needs only the glue import + asset URL +
 * identity. The crypto is the audited core; this only wires it (thin shell).
 */
export async function createBrowserRuntime(
  options: BrowserRuntimeOptions,
): Promise<WebApproverRuntime> {
  const wasm = await initWasm(options.glueModule, options.moduleSource);
  return createWasmRuntime({
    wasm,
    identity: options.identity,
    ...(options.resolveAccountStates ? { resolveAccountStates: options.resolveAccountStates } : {}),
    ...(options.sequenceFloorStore ? { sequenceFloorStore: options.sequenceFloorStore } : {}),
    ...(options.nowMs ? { nowMs: options.nowMs } : {}),
  });
}
