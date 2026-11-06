/**
 * `@allw/sdk` — the call site for agents, hooks, and CI to request a human approval.
 *
 * `requestApproval` runs the full keystone round-trip over the zero-knowledge relay
 * (`docs/contract.md`): build the human-shown `ApprovalContext`, compute the WYSIWYS
 * `request_hash`, encrypt the context to exactly the devices the approver's root-signed account state
 * vouches for, submit the opaque envelope, await
 * the signed verdict, and **verify it before returning**. Every security-critical step goes through
 * the audited Rust core via WASM (`./wasm.ts`); this package only orchestrates and shapes JSON.
 *
 * # Fail-closed (contract §Invariants #6)
 * The primitive **never returns "allow."** Timeout, no response, an unverifiable/forged verdict, or
 * a verified human "no" all resolve to a non-approving {@link Verdict} whose `decision` reflects
 * reality. Callers compute `allow = approved ∧ verified ∧ policy ∧ other gates`.
 *
 * @see ../../docs/contract.md
 */

import {
  RelayClient,
  RelayTimeoutError,
  type ApprovalRequestEnvelope,
  type FetchImpl,
  type NowImpl,
} from "./relay.js";
import { awaitVerdict, type WebSocketFactory } from "./wait.js";
import { loadWasm, type AllwWasm } from "./wasm.js";
import { parseSealedContext, type SealedContext } from "./sealed-context.js";

export {
  CommandActionError,
  commandAction,
  commandActionFromLine,
  commandRequest,
} from "./command-request.js";
export {
  CLIENT_CONFIG_PATH_ENV,
  CLIENT_CONFIG_VERSION,
  ClientConfigError,
  defaultClientConfigPath,
  loadClientConfig,
} from "./config.js";
export type { ConfigEnv, IntegratorConfig, LoadClientConfigOptions } from "./config.js";
export { MAX_ESCAPED_DIAGNOSTIC_CHARS, escapeToPrintableAscii } from "./printable-ascii.js";
export {
  defaultStateDir,
  fileSequenceFloorStore,
  relayAccountStateSource,
  SequenceFloorError,
} from "./account-state-source.js";
export type {
  FileSequenceFloorStoreOptions,
  RelayAccountStateSourceOptions,
  SequenceFloorStore,
} from "./account-state-source.js";
/**
 * Public because `relayAccountStateSource().load()` rejects with it when the account-state fetch
 * hangs past its timeout, so a caller of `load()` can narrow that case with `instanceof`.
 */
export { RelayTimeoutError };
export type {
  CommandActionErrorReason,
  CommandActionFromLineOptions,
  CommandActionOptions,
  CommandRequestInput,
} from "./command-request.js";
export { RelayError } from "./relay.js";

/**
 * A verdict decision. `requestApproval` *resolves* to `approved` (verified), `denied` (a verified
 * human "no"), or `expired` (verified human expiry or fail-closed timeout/cancellation).
 * `aborted` originates **only from a signed device verdict** — the SDK never synthesizes it.
 *
 * Integrator-initiated cancellation (issue #195, {@link ApprovalRequest.signal}) is a **separate**
 * mechanism from this enum: a retracted request was never decided by any device, so it is not a
 * verdict at all — `requestApproval` *rejects* with {@link RequestRetractedError} for that outcome
 * rather than resolving to a `Decision`.
 */
export type Decision = "approved" | "denied" | "expired" | "aborted";

/** The interception paradigm an action arrived through. */
export type Surface = "command" | "mcp_tool_call" | "file_edit" | "agent_tool_call";

/**
 * A reduced, matchable record of an approvable action. v1 carries the facts substrate;
 * no danger rating or policy-only metadata is carried. See `../../docs/action-record.md`.
 */
export interface ActionRecord {
  readonly recordSchemaVersion: number;
  readonly surface: Surface;
  /** Caller-described raw/argv, tool identity/params or file-edit facts; no command interpretation. */
  readonly facts: unknown;
}

/**
 * The automation requesting approval — shown to the human as the request's origin.
 *
 * v1 carries identity (`id`/`kind`); the actor-key `attestation` that lets the **device**
 * cryptographically verify that origin (contract §Identity & keys) is a reserved, optional slot —
 * its verifying-key enrollment and verification semantics are deferred (#16). Until then the shown
 * origin is asserted, not yet device-verified.
 */
export interface Actor {
  /** Stable actor identity (e.g. `"machine:macbook-pro"`). */
  readonly id: string;
  /** Actor kind (e.g. `"claude-code"`). */
  readonly kind: string;
  /**
   * Optional actor-key attestation (base64url-unpadded signature), carried inside the encrypted
   * `ApprovalContext` for the device to verify after decryption. Reserved for #16; excluded from
   * the WYSIWYS `request_hash` (the core omits it from the canonicalization).
   */
  readonly attestation?: string;
}

/** Which decisions the approver may select, and whether a number-match challenge is required. */
export interface Constraints {
  readonly allowedDecisions: readonly Decision[];
  readonly challengeRequired: boolean;
}

export interface ApprovalRequest {
  readonly action: ActionRecord;
  /** One-line, human-readable summary shown in the notification. */
  readonly summary: string;
  /** The automation requesting approval (identity shown to the human). */
  readonly actor: Actor;

  /** Optional caller assertion of reversibility; absence makes no claim. */
  readonly reversible?: boolean;
  /** Allowed decisions + challenge policy. Defaults to `{ approved, denied }`, no challenge. */
  readonly constraints?: Constraints;
  /** Upstream-gate IDs for audit-chain correlation (optional). */
  readonly chain?: readonly string[];
  /** Fail-closed deadline (ms from now); on expiry the verdict resolves to `expired`. */
  readonly timeoutMs?: number;
  /**
   * Integrator-initiated cancellation (issue #195): when this signal aborts, `requestApproval`
   * tells the relay to retract the pending request — so connected approver devices clear the
   * notification live. Confirmed retraction **rejects** with {@link RequestRetractedError}:
   * a retract is not a human verdict and never enters the audit chain as a decision. If retraction
   * is refused (including a request already resolved on an unverifiable verdict) or fails, the
   * still-pending local call resolves `expired` once that attempt settles. The original deadline
   * still bounds a hung attempt. A call already settled on a verified decision is unaffected.
   * Aborting before submission skips the network round-trip and rejects immediately.
   */
  readonly signal?: AbortSignal;
}

/**
 * Thrown by `requestApproval` when the caller's {@link ApprovalRequest.signal} aborted before a
 * verdict was received (issue #195). Distinct from every {@link Decision}: a retracted request was
 * never decided by any device, so it is not a verdict and never appears in the audit chain.
 */
export class RequestRetractedError extends Error {
  constructor(readonly requestId: string) {
    super(`allw: request '${requestId}' was retracted before a verdict was received`);
    this.name = "RequestRetractedError";
  }
}

/**
 * Where root-signed account state failed to establish who may read a request. Each stage fails
 * closed before anything is submitted:
 *
 * - `"load"`: {@link AccountStateSource.load} threw, or returned something that is not an
 *   {@link AccountStateSet}.
 * - `"seal"`: the core refused to select recipients from the loaded set (none verify, the highest
 *   sequence is below `minSequence`, no active device, too many, a small-order key, …) — nothing
 *   was encrypted.
 * - `"accept"`: {@link AccountStateSource.accepted} threw or rejected, so the sequence floor may not
 *   be persisted; the sealed request is discarded rather than sent.
 */
export type RecipientSelectionStage = "load" | "seal" | "accept";

/**
 * Thrown by `requestApproval` when no request was sent because account state could not establish
 * its recipients (contract §Invariants #6). A deny-class failure: the caller (e.g. a hook) maps it
 * to a deny, never to an allow. `cause` carries the underlying error.
 */
export class RecipientSelectionError extends Error {
  constructor(
    readonly stage: RecipientSelectionStage,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(`allw: ${message}`, options);
    this.name = "RecipientSelectionError";
  }
}

/**
 * A verified human decision bound to the exact request.
 *
 * **Not authorization.** `decision === "approved"` means the human approved AND the verdict
 * verified against the approver's root key; the caller still composes
 * `allow = approved ∧ verified ∧ policy ∧ other gates` (contract §Invariants #5). A verdict can
 * only ever tighten access, never grant it.
 */
export interface Verdict {
  readonly requestId: string;
  /** The verified human decision. `approved` only when the verdict passed full verification. */
  readonly decision: Decision;
  /**
   * Re-run full verification against the approver's account-root Ed25519 public key (base64url).
   * Returns `true` only for an authenticated, bound, fresh, **approved** verdict; `false` for any
   * non-approval, forgery, replay, or transport-synthesized expiry. Re-verifying the same Verdict
   * object is idempotent: the nonce accepted by `requestApproval` does not self-trip this method.
   * Never throws.
   */
  verify(approverRootKey: string, options?: VerdictVerifyOptions): Promise<boolean>;
}

/**
 * Integrator-owned anti-replay store for verdict nonces.
 *
 * Nonces are signed by the device and returned by the core only after the verdict is authenticated,
 * bound to the request, within its freshness window, and approved. The SDK stores that verified
 * base64url nonce here so a captured verdict cannot be replayed to the same long-lived client.
 */
export interface NonceStore {
  /**
   * Atomically records a freshly verified verdict nonce and returns true iff it was not already
   * present. Durable stores should implement this as a unique insert / conditional write, not as
   * separate read-then-write operations, so concurrent replay attempts cannot both be accepted.
   */
  checkAndInsert(nonceB64: string): boolean | Promise<boolean>;
}

/**
 * Account-state documents known to the verifier. Integrators must provide every state they know
 * about, or at least enforce a durably persisted highest sequence before calling; the SDK cannot
 * infer omitted newer revocations from a stale list.
 */
export interface AccountStateOptions {
  readonly accountStates?: readonly string[];
  /**
   * Optional caller-asserted account namespace. Multi-account verifiers should set this so a
   * verdict whose certified account id differs from the intended account fails closed.
   * On a returned verdict, omission, `undefined` and `""` fall back to the client account.
   * Standalone verification inputs require a non-empty account namespace.
   */
  readonly expectedAccountId?: string;
}

/**
 * Options for re-verifying a returned {@link Verdict}. Omitting or clearing the account option
 * preserves the client account guard, even when account state is explicitly omitted.
 */
export type VerdictVerifyOptions = AccountStateOptions;

/** One loaded set of account state for a request (see {@link AccountStateSource}). */
export interface AccountStateSet {
  /** Compact root-signed `allw-account-state+jws` documents, as fetched (unverified). */
  readonly accountStates: readonly string[];
  /**
   * The highest account-state sequence this caller has already accepted, if it persists one. The
   * core refuses a set whose highest verified sequence is below it (a rollback), rather than fall
   * back to the older state. Omit when nothing has been persisted yet.
   */
  readonly minSequence?: number;
}

/**
 * A per-request provider of root-signed account state — the trust input that decides who may read
 * a request (`docs/enrollment.md` §Model, recipient selection rule).
 *
 * # Contract
 * - **Called once per request.** `requestApproval` calls {@link load} once and uses that one set for
 *   both recipient selection and verdict revocation checks; it never reloads mid-request.
 * - **`load` returns documents, not trust.** The SDK verifies every document against the client's
 *   `approverRootKey` in the core; a source may fetch from the relay unauthenticated. A `load` that
 *   throws, or resolves to anything but an {@link AccountStateSet}, fails the request closed
 *   ({@link RecipientSelectionError}, stage `"load"`).
 * - **The source owns floor persistence.** After the core seals the request it reports the
 *   sequence it selected from through {@link accepted}, and the SDK awaits that **before**
 *   submitting. If `accepted` throws or rejects, nothing is sent (stage `"accept"`). Persist the
 *   maximum of the stored floor and `sequence`, and return the same floor from later `load`s as
 *   `minSequence`.
 * - **`accepted` must be idempotent and monotonic.** It may be called repeatedly with the same or a
 *   lower sequence (concurrent requests, retries); it must never lower a stored floor.
 */
export interface AccountStateSource {
  /** Load the account-state documents (and persisted floor) for one request. */
  load(): Promise<AccountStateSet>;
  /**
   * Record that a request was sealed from account state at `sequence`. Optional: a source without
   * a persisted floor omits it.
   */
  accepted?(sequence: number): void | Promise<void>;
}

/** Root-signed account trust state used by offline verdict verifiers for revocation. */
export interface AccountState {
  readonly v: number;
  readonly account_id: string;
  readonly sequence: number;
  readonly current_root: string;
  readonly previous_roots: readonly {
    readonly root: string;
    readonly valid_until: number;
  }[];
  readonly devices: readonly {
    readonly device_id: string;
    readonly encryption_pubkey: string;
    readonly signing_pubkey: string;
    readonly status: string;
    readonly cert_expires_at?: number;
  }[];
  readonly actors: readonly {
    readonly actor_id: string;
    readonly kind: string;
    readonly pubkey: string;
    readonly status: string;
  }[];
  readonly revocations: readonly {
    readonly kind: "device" | "actor";
    readonly id: string;
    readonly revoked_at: number;
    readonly reason?: string;
  }[];
}

/** Normalized successful verdict verification result from the WASM core. */
export interface VerifiedVerdictResult {
  readonly approved: true;
  readonly deviceId: string;
  readonly decidedAt: number;
  readonly nonceB64: string;
  /** The human's note from the authenticated claims, suitable for the audit record. */
  readonly note?: string;
}

export interface VerifyVerdictWithAccountStatesInput extends AccountStateOptions {
  /** Required account namespace; standalone helpers have no client account to fall back to. */
  readonly expectedAccountId: string;
  readonly verdict: unknown;
  readonly request: unknown;
  readonly context: unknown;
  readonly approverRootKey: string;
  readonly nowMs: number;
  /** Optional cross-call replay store. When omitted, the WASM core still enforces one-shot local replay. */
  readonly nonceStore?: NonceStore;
}

/** Configuration for {@link createClient}. */
export interface ClientConfig {
  /**
   * Base URL of the relay (e.g. `https://relay.allw.example`). Must be `https:`, or `http:` on a
   * loopback host for local development; {@link createClient} throws on anything else.
   */
  readonly relayUrl: string;
  /** The approver's relay account id (routes to the per-account Durable Object). */
  readonly accountId: string;
  /**
   * The account-root Ed25519 public key (base64url-unpadded), the trust anchor for verification.
   * The integrator configures who it trusts; every verdict must chain to this root.
   */
  readonly approverRootKey: string;
  /** Override the global `fetch` (tests / non-standard runtimes). */
  readonly fetchImpl?: FetchImpl;
  /** Override the clock (tests). Defaults to `Date.now`. */
  readonly nowImpl?: NowImpl;
  /**
   * Override the WebSocket factory (tests / runtimes without a global `WebSocket`). When omitted,
   * the SDK uses the global `WebSocket` if present and otherwise polls. Forward both `(url, protocols)`
   * to the constructor; protocols contain a private capability and must never be logged.
   */
  readonly webSocketFactory?: WebSocketFactory;
  /** Poll cadence in ms for the fallback path. Defaults to 1000. */
  readonly pollIntervalMs?: number;
  /**
   * Per-request relay-fetch timeout in ms — bounds every individual `fetch` (device list, submit,
   * each poll) so a hung connect/read can never wedge `requestApproval` indefinitely (issue #52).
   * Defaults to {@link DEFAULT_FETCH_TIMEOUT_MS}; must be well under the overall `timeoutMs` deadline.
   */
  readonly fetchTimeoutMs?: number;
  /**
   * Anti-replay store for verified verdict nonces. Defaults to an in-memory per-client store that
   * persists across `requestApproval` and `Verdict.verify()` calls for this client instance.
   */
  readonly nonceStore?: NonceStore;
  /**
   * **Required.** The root-signed account state that decides who may read each request: the
   * request is encrypted only to the devices it vouches for (never to the relay's device list), and
   * verdicts from devices it revokes are rejected.
   *
   * Either a fixed, non-empty list of compact account-state JWS documents (the caller then owns
   * monotonic persistence: supply every state you know, or one already checked against a durably
   * stored highest sequence), or an {@link AccountStateSource} the SDK calls once per request.
   * {@link createClient} throws when it is missing or empty.
   */
  readonly accountStates: readonly string[] | AccountStateSource;
  /**
   * Account namespace the client intended to verify; defaults to `accountId` when omitted or empty.
   * Verdict verification fails closed if the certified account id differs, even when a returned
   * verdict is re-verified without account state. Per-call omission, `undefined` or `""` preserves
   * this guard. This complements account-state account binding.
   */
  readonly expectedAccountId?: string;
  /**
   * Override the timer used for the poll sleep, the fail-closed deadline, and the per-fetch timeout.
   * Meant for tests, so the fail-closed timing can be driven by a fake clock instead of real time.
   *
   * The native deadline is referenced while waiting (including async verification), then cleared
   * on settlement so an early verdict does not keep the process alive. Poll sleeps are referenced
   * and clamped to the deadline; per-fetch timeouts are unref'd. An override replaces all three
   * and owns their keep-alive/cleanup behavior. Unref'ing every active timer lets Node exit with no
   * verdict (#254); an override without cancellation may instead keep it alive after settlement.
   */
  readonly scheduleImpl?: (fn: () => void, ms: number) => void;
}

/** A client bound to one relay account, exposing {@link requestApproval}. */
export interface Client {
  requestApproval(req: ApprovalRequest): Promise<Verdict>;
}

/** Protocol version stamped on the envelope and the unsigned verdict (contract `v`). */
const PROTOCOL_VERSION = 1;
/** Default fail-closed timeout when a request omits `timeoutMs`. */
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_POLL_INTERVAL_MS = 1000;

/** Per-client in-memory nonce store used when the integrator does not provide a durable store. */
class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Set<string>();

  checkAndInsert(nonceB64: string): boolean {
    if (this.seen.has(nonceB64)) return false;
    // This intentionally grows for the client lifetime. Persistent retention/expiry belongs to
    // integrator-provided durable stores once replay retention policy is specified.
    this.seen.add(nonceB64);
    return true;
  }
}

/** The default WebSocket factory: the global `WebSocket` if the runtime provides one, else none. */
function defaultWebSocketFactory(): WebSocketFactory | undefined {
  const ctor = (globalThis as { WebSocket?: new (url: string, protocols: string[]) => unknown })
    .WebSocket;
  if (!ctor) return undefined;
  return (url: string, protocols: string[]) => new ctor(url, protocols) as never;
}

/**
 * The snake_case wire shape of an `ApprovalContext` (the JSON the WASM core consumes). Mirrors
 * `allw_core::ApprovalContext` exactly — field names and casing are load-bearing for the
 * cross-platform `request_hash` (contract §Wire encoding).
 */
interface WireApprovalContext {
  readonly action: {
    readonly record_schema_version: number;
    readonly surface: Surface;
    readonly facts: unknown;
  };
  readonly summary: string;
  readonly actor: { readonly id: string; readonly kind: string; readonly attestation?: string };

  readonly reversible?: boolean;
  readonly constraints: {
    readonly allowed_decisions: readonly Decision[];
    readonly challenge_required: boolean;
  };
  readonly chain?: readonly string[];
}

/**
 * Translate the ergonomic camelCase {@link ApprovalRequest} into the snake_case
 * {@link WireApprovalContext} the core hashes/encrypts. `chain` is omitted entirely when absent
 * (the core omits `None`), keeping the WYSIWYS canonicalization byte-identical.
 */
function toWireContext(req: ApprovalRequest): WireApprovalContext {
  const constraints = req.constraints ?? {
    allowedDecisions: ["approved", "denied"],
    challengeRequired: false,
  };
  const ctx: WireApprovalContext = {
    action: {
      record_schema_version: req.action.recordSchemaVersion,
      surface: req.action.surface,
      facts: req.action.facts,
    },
    summary: req.summary,
    actor: {
      id: req.actor.id,
      kind: req.actor.kind,
      // Attestation is carried in the encrypted context when supplied (reserved for #16); omitted
      // when absent so the canonicalization stays byte-identical (the core excludes it from the hash).
      ...(req.actor.attestation !== undefined ? { attestation: req.actor.attestation } : {}),
    },

    ...(req.reversible !== undefined ? { reversible: req.reversible } : {}),
    constraints: {
      allowed_decisions: constraints.allowedDecisions,
      challenge_required: constraints.challengeRequired,
    },
    // `chain` is spread conditionally so an absent value omits the key (exactOptionalPropertyTypes).
    ...(req.chain !== undefined ? { chain: req.chain } : {}),
  };
  return ctx;
}

/** A high-entropy UUIDv4 request id (contract §Transport requires UUIDv4+ until endpoint authn). */
function newRequestId(): string {
  return crypto.randomUUID();
}

/** A decision a verified human "no" can carry: anything but `approved`. */
type NonApprovingDecision = Exclude<Decision, "approved">;

/**
 * The **signed** decision of a verified non-approval, read from the structured error WASM
 * `verify_verdict*` throws for one (`kind: "not_approved"`, `decision` from the signed claims), or
 * `null` for any other failure.
 *
 * Never classify by the error message: untrusted input (the relay-delivered verdict) is echoed
 * into parse errors, so any message substring can be forged (#311). Only the Rust boundary sets
 * these properties, and only for the core's `NotApproved`. This never returns `approved`.
 */
function signedNonApproval(err: unknown): NonApprovingDecision | null {
  if (!(err instanceof Error)) return null;
  // Own properties only, as WASM sets them: an inherited `kind`/`decision` (a polluted
  // `Error.prototype`) would otherwise turn every unverifiable error into a "verified" decision.
  if (!Object.hasOwn(err, "kind") || !Object.hasOwn(err, "decision")) return null;
  const { kind, decision } = err as { kind?: unknown; decision?: unknown };
  if (kind !== "not_approved") return null;
  if (decision === "denied" || decision === "expired" || decision === "aborted") return decision;
  return null;
}

/**
 * A verdict reduced to a verified decision. `approved` only ever comes from a successful WASM
 * verification (with its signed nonce); a verified non-approval can never be `approved`.
 */
type VerifiedDecision =
  | { readonly decision: "approved"; readonly nonceB64: string }
  | { readonly decision: NonApprovingDecision; readonly nonceB64?: undefined };

interface VerifiedWasmResult {
  readonly approved: true;
  readonly deviceId: string;
  readonly decidedAt: number;
  readonly nonceB64: string;
  /** Preserved verbatim from the core's authenticated claims; absence stays absent. */
  readonly note?: string;
}

/** Validate the core's verification result and normalize its wire fields without re-verifying it. */
function readVerifiedWasmResult(json: string): VerifiedWasmResult {
  const value = JSON.parse(json) as {
    approved?: unknown;
    device_id?: unknown;
    decided_at?: unknown;
    nonce_b64?: unknown;
    note?: unknown;
  };
  if (value.approved !== true) {
    throw new Error("allw: verify_verdict result was not approved");
  }
  if (typeof value.device_id !== "string" || value.device_id.length === 0) {
    throw new Error("allw: verify_verdict result did not include a device_id");
  }
  if (typeof value.decided_at !== "number" || !Number.isSafeInteger(value.decided_at)) {
    throw new Error("allw: verify_verdict result did not include a safe decided_at");
  }
  if (typeof value.nonce_b64 !== "string" || value.nonce_b64.length === 0) {
    throw new Error("allw: verify_verdict result did not include a nonce_b64");
  }
  // Inherited values cannot represent claims authenticated by the core.
  const hasNote = Object.hasOwn(value, "note");
  if (hasNote && typeof value.note !== "string") {
    throw new Error("allw: verify_verdict result included a malformed note");
  }
  return {
    approved: true,
    deviceId: value.device_id,
    decidedAt: value.decided_at,
    nonceB64: value.nonce_b64,
    ...(hasNote ? { note: value.note as string } : {}),
  };
}

/**
 * Accept a nonce into the client replay store. `acceptedNonceB64` is the nonce already accepted for
 * this exact public Verdict object, which keeps `verdict.verify()` idempotent without allowing the
 * same signed verdict to be accepted by a later request.
 */
async function acceptVerifiedNonce(
  nonceStore: NonceStore,
  nonceB64: string,
  acceptedNonceB64?: string,
): Promise<boolean> {
  if (acceptedNonceB64 !== undefined && nonceB64 === acceptedNonceB64) return true;
  return nonceStore.checkAndInsert(nonceB64);
}

/** Stringify the caller-provided account-state JWS list in the exact form the WASM bridge expects. */
function accountStatesJson(accountStates: readonly string[] | undefined): string {
  return JSON.stringify(accountStates ?? []);
}

/**
 * The message of an error a source, floor store or the core threw, for a
 * {@link RecipientSelectionError}'s message. The SDK's own errors there never quote relay text, and
 * the core escapes and bounds untrusted device ids; integrators still sanitize before showing it to
 * an agent.
 */
function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** A non-empty array of strings (a well-formed list of compact JWS documents, unverified). */
function isNonEmptyStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.length > 0 && value.every((doc) => typeof doc === "string");
}

/** Whether a `ClientConfig.accountStates` value is a provider rather than a fixed list. */
function isAccountStateSource(value: unknown): value is AccountStateSource {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as { load?: unknown }).load === "function"
  );
}

/**
 * Check `ClientConfig.accountStates` at construction: a non-empty document list or a source with a
 * `load` function. Anything else throws, so a client can never be built without a trust input.
 */
function assertAccountStatesConfigured(value: unknown): void {
  if (isAccountStateSource(value)) {
    const accepted = (value as { accepted?: unknown }).accepted;
    if (accepted !== undefined && typeof accepted !== "function") {
      throw new TypeError("allw: createClient accountStates.accepted must be a function when set");
    }
    return;
  }
  if (isNonEmptyStringArray(value)) return;
  throw new TypeError(
    "allw: createClient requires accountStates — a non-empty array of root-signed account-state " +
      "documents or an AccountStateSource; requests are encrypted only to the devices it vouches for",
  );
}

/** A floor is absent or a non-negative safe integer; anything else is a malformed source result. */
function isSequenceFloor(value: unknown): value is number | undefined {
  return value === undefined || (Number.isSafeInteger(value) && (value as number) >= 0);
}

/**
 * Resolve one request's {@link AccountStateSet}: a fixed list as-is, or one validated `load()` call.
 * Throws {@link RecipientSelectionError} (stage `"load"`) on any failure.
 */
async function loadAccountStateSet(
  configured: readonly string[] | AccountStateSource,
): Promise<AccountStateSet> {
  if (!isAccountStateSource(configured)) return { accountStates: configured };
  let loaded: unknown;
  try {
    loaded = await configured.load();
  } catch (cause) {
    throw new RecipientSelectionError("load", `loading account state failed: ${errorText(cause)}`, {
      cause,
    });
  }
  const set = loaded as Partial<AccountStateSet> | null;
  if (
    typeof loaded !== "object" ||
    set === null ||
    !isNonEmptyStringArray(set.accountStates) ||
    !isSequenceFloor(set.minSequence)
  ) {
    throw new RecipientSelectionError(
      "load",
      "account-state source returned no documents or a malformed result " +
        "(expected { accountStates: non-empty string[], minSequence?: non-negative safe integer })",
    );
  }
  return set.minSequence === undefined
    ? { accountStates: set.accountStates }
    : { accountStates: set.accountStates, minSequence: set.minSequence };
}

/**
 * Encrypt the context to exactly the devices the loaded account state vouches for — selection and
 * encryption both run in the core, so recipient keys never pass through this package. Throws
 * {@link RecipientSelectionError} (stage `"seal"`) when the core refuses.
 */
function sealContext(
  wasm: AllwWasm,
  contextJson: string,
  set: AccountStateSet,
  accountId: string,
  approverRootKey: string,
  nowMs: number,
): SealedContext {
  let json: string;
  try {
    json = wasm.seal_context_for_account_state(
      contextJson,
      JSON.stringify(set.accountStates),
      accountId,
      approverRootKey,
      nowMs,
      set.minSequence,
    );
  } catch (cause) {
    throw new RecipientSelectionError(
      "seal",
      `account state cannot seal this request for account '${accountId}': ${errorText(cause)}`,
      { cause },
    );
  }
  // Fail closed on anything a successful seal could not return: the sequence becomes the persisted
  // floor and the ciphertext is what gets sent.
  const sealed = parseSealedContext(json);
  if (sealed === null) {
    throw new RecipientSelectionError(
      "seal",
      "seal_context_for_account_state returned a malformed result",
    );
  }
  return sealed;
}

/**
 * Report the sealed sequence to the source and wait for it, so the floor is persisted before the
 * request leaves the machine. Throws {@link RecipientSelectionError} (stage `"accept"`) on failure.
 */
async function acceptSequence(
  configured: readonly string[] | AccountStateSource,
  sequence: number,
): Promise<void> {
  if (!isAccountStateSource(configured) || configured.accepted === undefined) return;
  try {
    await configured.accepted(sequence);
  } catch (cause) {
    throw new RecipientSelectionError(
      "accept",
      `could not record account-state sequence ${String(sequence)}; not sending the request: ` +
        errorText(cause),
      { cause },
    );
  }
}

/** Treat a blank optional account constraint like omission before crossing into WASM. */
function expectedAccountIdConstraint(expectedAccountId: string | undefined): string | undefined {
  return expectedAccountId === "" ? undefined : expectedAccountId;
}

/** Standalone verifiers cannot infer an account; reject missing authority before invoking the core. */
function requireExpectedAccountId(expectedAccountId: string): string {
  if (typeof expectedAccountId !== "string" || expectedAccountId.length === 0) {
    throw new TypeError("allw: expectedAccountId is required");
  }
  return expectedAccountId;
}

/**
 * Verify a (possibly null) verdict value through the WASM core and reduce it to a {@link Decision}.
 *
 * - WASM `verify_verdict` returns ⇒ authenticated, bound, fresh, **approved** ⇒ `"approved"`.
 * - It throws the structured `kind: "not_approved"` error ⇒ a *verified* human "no" ⇒ the
 *   **signed** decision it carries (`denied`/`expired`/`aborted`), never the outer verdict's.
 * - It throws anything else (forgery, tamper, bad sig, replay, window, unparseable JSON) ⇒
 *   unverifiable ⇒ `null` (the wait continues; without a verified verdict it ends `expired`).
 */
async function verifyToDecision(
  wasm: AllwWasm,
  verdictValue: unknown,
  requestJson: string,
  contextJson: string,
  approverRootKey: string,
  nowMs: number,
  nonceStore: NonceStore,
  accountStates?: readonly string[],
  expectedAccountId?: string,
  acceptedNonceB64?: string,
): Promise<VerifiedDecision | null> {
  if (verdictValue === null || verdictValue === undefined) return null;
  const verdictJson = JSON.stringify(verdictValue);
  const accountConstraint = expectedAccountIdConstraint(expectedAccountId);
  let verifyJson: string;
  try {
    verifyJson =
      accountStates === undefined
        ? wasm.verify_verdict(
            verdictJson,
            requestJson,
            contextJson,
            approverRootKey,
            nowMs,
            accountConstraint,
          )
        : wasm.verify_verdict_with_account_states(
            verdictJson,
            requestJson,
            contextJson,
            approverRootKey,
            nowMs,
            accountStatesJson(accountStates),
            accountConstraint,
          );
  } catch (err) {
    const decision = signedNonApproval(err);
    if (decision !== null) {
      // Authenticated, bound, fresh — but the human did not approve. Report the signed decision.
      return { decision };
    }
    // Forgery / tamper / expiry-window / replay / unparseable — unverifiable. Fail closed.
    return null;
  }

  try {
    const { nonceB64 } = readVerifiedWasmResult(verifyJson);
    if (!(await acceptVerifiedNonce(nonceStore, nonceB64, acceptedNonceB64))) return null;
    return { decision: "approved", nonceB64 };
  } catch {
    // A malformed binding result or nonce-store failure cannot be treated as approved.
    return null;
  }
}

/**
 * Sign an account-state document through the WASM core. This is intentionally thin: production
 * account-state authoring belongs to enrollment/recovery flows, while this helper keeps tests and
 * local tools on the same signed wire format as verifiers.
 */
export async function signAccountState(
  state: AccountState,
  accountRootSeedB64: string,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.sign_account_state(JSON.stringify(state), accountRootSeedB64);
}

/** Verify a root-signed account-state JWS and return the authenticated account-state document. */
export async function verifyAccountState(
  accountStateJws: string,
  expectedAccountId: string,
  accountRootKey: string,
): Promise<AccountState> {
  const wasm = await loadWasm();
  return JSON.parse(
    wasm.verify_account_state(accountStateJws, expectedAccountId, accountRootKey),
  ) as AccountState;
}

/**
 * Verify a verdict while enforcing account-state device revocations. The optional nonce store is
 * checked after the core authenticates the signed nonce, so replay protection composes with the
 * revocation-aware verification path.
 *
 * Throws on every verification failure (fail-closed). A *verified* non-approval throws an `Error`
 * with own properties `kind: "not_approved"` and `decision` (`denied`/`expired`/`aborted`, from the
 * signed claims); any other throw is unverifiable. Never classify by the error message: the relay
 * controls text echoed into it.
 */
export async function verifyVerdictWithAccountStates(
  input: VerifyVerdictWithAccountStatesInput,
): Promise<VerifiedVerdictResult> {
  const expectedAccountId = requireExpectedAccountId(input.expectedAccountId);
  const wasm = await loadWasm();
  const result = readVerifiedWasmResult(
    wasm.verify_verdict_with_account_states(
      JSON.stringify(input.verdict),
      JSON.stringify(input.request),
      JSON.stringify(input.context),
      input.approverRootKey,
      input.nowMs,
      accountStatesJson(input.accountStates),
      expectedAccountId,
    ),
  );
  if (input.nonceStore && !(await input.nonceStore.checkAndInsert(result.nonceB64))) {
    throw new Error("allw: verdict nonce replayed");
  }
  return result;
}

/**
 * Classify an error thrown by the pre-deadline relay round-trip (`submit`) as a
 * **transport** failure that should fail closed to a `Verdict` rather than reject.
 *
 * - {@link RelayTimeoutError} — a hung connect/read we bounded and aborted (the #52 case).
 * - A bare `TypeError` from `fetch` — a connection-level failure (DNS, refused, reset) that never
 *   produced an HTTP response; WHATWG `fetch` rejects with a `TypeError` for these.
 *
 * A {@link RelayError} (a real HTTP status from the relay) is **not** a transport failure — it
 * signals integrator/protocol misconfiguration and keeps throwing so the caller (the hook) surfaces
 * a precise deny reason. Account-state failures never reach this check: they throw
 * {@link RecipientSelectionError} before anything is submitted.
 */
function isPreDeadlineTransportFailure(err: unknown): boolean {
  if (err instanceof RelayTimeoutError) return true;
  // A connection-level fetch failure (no HTTP response). `RelayError extends Error` but not
  // `TypeError`, so the `instanceof TypeError` check correctly excludes it.
  if (err instanceof TypeError) return true;
  return false;
}

/**
 * Construct a relay-bound client. The returned {@link Client.requestApproval} runs the full
 * E2EE round-trip and resolves to a verified {@link Verdict} — never a bare "allow".
 */
export function createClient(config: ClientConfig): Client {
  assertAccountStatesConfigured(config.accountStates);
  // Preserve account authority even when a caller re-verifies without revocation context.
  const expectedAccountId =
    expectedAccountIdConstraint(config.expectedAccountId) ?? config.accountId;
  const fetchImpl = config.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const now: NowImpl = config.nowImpl ?? Date.now;
  // An explicitly-present `webSocketFactory` key is authoritative — passing `undefined` disables
  // WebSockets (poll-only), even on Node ≥22 where a global `WebSocket` exists. Only a fully absent
  // key falls back to the global. This keeps the poll-only path (and tests) free of real WS dials.
  const webSocketFactory =
    "webSocketFactory" in config ? config.webSocketFactory : defaultWebSocketFactory();
  const pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const nonceStore = config.nonceStore ?? new InMemoryNonceStore();
  const relay = new RelayClient(config.relayUrl, config.accountId, fetchImpl, {
    ...(config.fetchTimeoutMs !== undefined ? { fetchTimeoutMs: config.fetchTimeoutMs } : {}),
    // Share the fail-closed timer seam so a fake clock drives the fetch timeouts deterministically.
    ...(config.scheduleImpl ? { schedule: config.scheduleImpl } : {}),
  });

  async function requestApproval(req: ApprovalRequest): Promise<Verdict> {
    const wasm = await loadWasm();

    // 1. Build the human-shown ApprovalContext (the plaintext, never seen by the relay).
    const wireContext = toWireContext(req);
    const contextJson = JSON.stringify(wireContext);

    // 2. Lifecycle: deadline + the WYSIWYS request_hash bound to it (computed by the core).
    const createdAt = now();
    const expiresAt = createdAt + (req.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    // `compute_request_hash` throws on a malformed context — surfaces as a rejected promise.
    wasm.compute_request_hash(contextJson, expiresAt);

    // The request id is generated up front so a fail-closed `Verdict` (below) can carry it even if
    // the pre-deadline relay round-trip never completes.
    const id = newRequestId();

    // A caller that cancels before the request was ever submitted has nothing to retract on the
    // relay — reject immediately rather than paying for a network round-trip (issue #195).
    if (req.signal?.aborted) {
      throw new RequestRetractedError(id);
    }

    // 3. Load this request's account state once (it also drives verdict revocation below), seal the
    // context to exactly the devices it vouches for, and persist the sequence floor — all BEFORE
    // anything leaves the machine. Each step throws RecipientSelectionError (deny-class) on failure;
    // the relay's own device list is never read for keys.
    const accountStateSet = await loadAccountStateSet(config.accountStates);
    const sealed = sealContext(
      wasm,
      contextJson,
      accountStateSet,
      config.accountId,
      config.approverRootKey,
      now(),
    );
    await acceptSequence(config.accountStates, sealed.sequence);

    // This call owns its request credential through submission and the complete local wait,
    // including verification and abort retraction. Relay-reported finality alone cannot release
    // it: an unverifiable verdict must leave authentication available until local settlement.
    try {
      // 4. Submit. This runs BEFORE the await-verdict deadline timer is armed, so a hung relay
      // (TCP-accepted but never responding) would otherwise wedge the call forever. The per-request
      // fetch timeout (RelayClient) bounds it; here we additionally ensure a *transport* failure fails
      // closed to a `Verdict` (expired) instead of rejecting — the same fail-closed terminal a
      // wait-stage timeout produces (issue #52, contract §Invariants #6). An HTTP-level error (a relay
      // `RelayError` with a real status) still throws, surfacing misconfiguration loudly.
      try {
        // Build the relay-visible envelope (exactly the contract's key set) and submit it.
        const envelope: ApprovalRequestEnvelope = {
          v: PROTOCOL_VERSION,
          id,
          created_at: createdAt,
          expires_at: expiresAt,
          // The client is bound to one account; the envelope's routing `approver` IS that account.
          // Using `config.accountId` (not a per-request field) removes the footgun where a request
          // could be POSTed to one account DO while claiming a different approver in the request JSON.
          approver: config.accountId,
          context_ciphertext: sealed.ciphertext,
        };
        await relay.submit(envelope);
      } catch (err) {
        if (isPreDeadlineTransportFailure(err)) {
          // A hung/black-holed connection or a bare network error before the deadline ⇒ no verified
          // verdict is obtainable ⇒ fail closed to an `expired` Verdict (never approved). This is the
          // load-bearing fix for #52: the call resolves deterministically instead of hanging forever.
          return makeVerdict(id, "expired", { kind: "timeout" }, "", "", now, nonceStore);
        }
        // HTTP/protocol error ⇒ rethrow (the hook's try/catch maps it to a deny).
        throw err;
      }

      // The `request_json` the core verifies against is the envelope WITHOUT the ciphertext — the
      // verifier reads only routing/lifecycle (`v`, `id`, `created_at`, `expires_at`, `approver`).
      const requestJson = JSON.stringify({
        v: PROTOCOL_VERSION,
        id,
        created_at: createdAt,
        expires_at: expiresAt,
        approver: config.accountId,
      });

      // 5. The integrator owns finality: only full core verification ends the verdict wait. Reuse
      // the encryption-time account-state snapshot, and retain the accepted nonce so verify() can
      // recheck this same artifact without treating it as a replay.
      const verification: { accepted: VerifiedDecision | null } = { accepted: null };
      let outcome;
      try {
        outcome = await awaitVerdict(id, {
          relay,
          now,
          deadline: expiresAt,
          ...(req.signal ? { signal: req.signal } : {}),
          ...(webSocketFactory ? { webSocketFactory } : {}),
          pollIntervalMs,
          acceptVerdict: async (value: unknown): Promise<boolean> => {
            const verified = await verifyToDecision(
              wasm,
              value,
              requestJson,
              contextJson,
              config.approverRootKey,
              now(),
              nonceStore,
              accountStateSet.accountStates,
              expectedAccountId,
            );
            if (verified === null) return false;
            verification.accepted = verified;
            return true;
          },
          ...(config.scheduleImpl ? { schedule: config.scheduleImpl } : {}),
        });
      } catch {
        // Any transport error while awaiting ⇒ fail closed (no verdict ⇒ not approved).
        outcome = { kind: "timeout" } as const;
      }

      // 6. Reduce the outcome to a verified decision. Only a delivered, fully-verified verdict can
      //    be "approved"; every other path is a deny (contract §Invariants #6).
      let decision: Decision;
      let acceptedNonceB64: string | undefined;
      if (outcome.kind === "verdict") {
        // The wait returns a delivered verdict only after the callback accepted it. Preserve a
        // fail-closed default if this internal contract is ever violated.
        const verified = verification.accepted;
        decision = verified?.decision ?? "expired";
        acceptedNonceB64 = verified?.nonceB64;
      } else if (outcome.kind === "expired") {
        decision = "expired";
      } else if (outcome.kind === "retracted") {
        // NOT a verdict (issue #195) — no device ever decided, so this must never surface as a
        // `Decision`. Reject instead of resolving; contrast with `expired`/`timeout`, which are
        // fail-closed *decisions* about an unanswered request.
        throw new RequestRetractedError(id);
      } else {
        // timeout — fail closed.
        decision = "expired";
      }

      // 7. Resolve to a Verdict whose decision reflects reality; `verify()` re-runs the full check.
      return makeVerdict(
        id,
        decision,
        outcome,
        requestJson,
        contextJson,
        now,
        nonceStore,
        accountStateSet.accountStates,
        expectedAccountId,
        acceptedNonceB64,
      );
    } finally {
      relay.releaseRequest(id);
    }
  }

  return { requestApproval };
}

/**
 * Build the public {@link Verdict}. `verify()` re-runs full WASM verification against a
 * caller-supplied root key — returning `true` only for an authenticated, bound, approved verdict —
 * so a consumer can independently confirm the decision without trusting the SDK's own check.
 */
function makeVerdict(
  requestId: string,
  decision: Decision,
  outcome: { kind: string; value?: unknown },
  requestJson: string,
  contextJson: string,
  now: NowImpl,
  nonceStore: NonceStore,
  accountStates?: readonly string[],
  clientExpectedAccountId?: string,
  acceptedNonceB64?: string,
): Verdict {
  const verdictValue = outcome.kind === "verdict" ? outcome.value : null;
  return {
    requestId,
    decision,
    async verify(approverRootKey: string, options?: VerdictVerifyOptions): Promise<boolean> {
      // A synthesized (non-delivered) outcome has no verifiable artifact — it can never be approved.
      if (verdictValue === null || verdictValue === undefined) return false;
      const wasm = await loadWasm();
      // An explicit option overrides the client-level account-state set, including `[]` for tests
      // that intentionally verify without revocation context.
      const states = options && "accountStates" in options ? options.accountStates : accountStates;
      // Per-call options may name an account, but can never drop the client account guard.
      const expectedAccountId =
        expectedAccountIdConstraint(options?.expectedAccountId) ?? clientExpectedAccountId;
      const result = await verifyToDecision(
        wasm,
        verdictValue,
        requestJson,
        contextJson,
        approverRootKey,
        now(),
        nonceStore,
        states,
        expectedAccountId,
        acceptedNonceB64,
      );
      return result?.decision === "approved";
    },
  };
}

/** @public Credential offers shared by device connectors and request waiters. */
export { relayWebSocketProtocols } from "./relay-websocket.js";
