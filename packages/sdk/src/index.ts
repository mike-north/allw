/**
 * `@allw/sdk` — the call site for agents, hooks, and CI to request a human approval.
 *
 * `requestApproval` runs the full keystone round-trip over the zero-knowledge relay
 * (`docs/contract.md`): build the human-shown `ApprovalContext`, compute the WYSIWYS
 * `request_hash`, encrypt the context to the approver's devices, submit the opaque envelope, await
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
  type DeviceRecord,
  type FetchImpl,
  type NowImpl,
} from "./relay.js";
import { awaitVerdict, type WebSocketFactory } from "./wait.js";
import { loadWasm, type AllwWasm } from "./wasm.js";

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
export type {
  CommandActionErrorReason,
  CommandActionFromLineOptions,
  CommandActionOptions,
  CommandRequestInput,
} from "./command-request.js";

/**
 * A verdict decision. `requestApproval` *resolves* to `approved` (verified), `denied` (a verified
 * human "no" or a fail-closed synthesis), or `expired` (timeout / past deadline). `aborted` is part
 * of the wire vocabulary but originates **only from a signed device verdict** — the SDK never
 * synthesizes it.
 *
 * Integrator-initiated cancellation (issue #195, {@link ApprovalRequest.signal}) is a **separate**
 * mechanism from this enum: a retracted request was never decided by any device, so it is not a
 * verdict at all — `requestApproval` *rejects* with {@link RequestRetractedError} for that outcome
 * rather than resolving to a `Decision`.
 */
export type Decision = "approved" | "denied" | "expired" | "aborted";
export type Risk = "low" | "medium" | "high" | "critical";

/** The interception paradigm an action arrived through. */
export type Surface = "command" | "mcp_tool_call" | "file_edit" | "agent_tool_call";

/**
 * A reduced, matchable record of an approvable action. v1 carries the syntactic substrate;
 * semantic `capabilities`/`scope` are reserved for the policy layer. See `../../docs/policy-seam.md`.
 */
export interface ActionRecord {
  readonly recordSchemaVersion: number;
  readonly surface: Surface;
  /** Raw, structured syntactic form (tokenized command / MCP call). */
  readonly syntactic: unknown;
  readonly risk: Risk;
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
  /** Coarse risk classification shown to the human. */
  readonly risk: Risk;
  /** Whether the action can be undone if approved. */
  readonly reversible: boolean;
  /** Allowed decisions + challenge policy. Defaults to `{ approved, denied }`, no challenge. */
  readonly constraints?: Constraints;
  /** Upstream-gate IDs for audit-chain correlation (optional). */
  readonly chain?: readonly string[];
  /** Fail-closed deadline (ms from now); on expiry the verdict resolves to `expired`. */
  readonly timeoutMs?: number;
  /**
   * Integrator-initiated cancellation (issue #195): when this signal aborts, `requestApproval`
   * tells the relay to retract the pending request — so connected approver devices clear the
   * notification live — and the call **rejects** with {@link RequestRetractedError} instead of
   * resolving to a `Verdict`. A retract is NOT a verdict; it never enters the audit chain as a
   * decision. It is best-effort and cannot discard an already-recorded decision: if the request was
   * already `resolved` (a device decided first) the retract is refused server-side and
   * `requestApproval` still resolves normally to that verdict. Aborting before the request has even
   * been submitted skips the network round-trip entirely and rejects immediately.
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
   * non-approval, forgery, replay, or transport-synthesized denial. Re-verifying the same Verdict
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
   * verdict or policy rule whose signed account id differs from the intended account fails closed.
   * `""` is treated like omission at the SDK/WASM seam.
   */
  readonly expectedAccountId?: string;
}

/** Options for re-verifying a returned {@link Verdict}. */
export type VerdictVerifyOptions = AccountStateOptions;

/** Root-signed account trust state used by offline verdict/policy verifiers for revocation. */
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
}

/** Result of verifying a signed policy rule, normalized from the core's snake_case JSON. */
export interface VerifiedPolicyRule {
  readonly rule: unknown;
  readonly deviceId: string;
}

export type PolicyDecision = "allow" | "deny" | "escalate";
export type PolicyTier = "syntactic" | "semantic";

/** Result of policy evaluation for one action. */
export interface PolicyEvaluation {
  readonly decision: PolicyDecision;
  readonly ruleId?: string;
  readonly tier: PolicyTier;
  readonly schemaVersion: number;
}

export interface VerifyVerdictWithAccountStatesInput extends AccountStateOptions {
  readonly verdict: unknown;
  readonly request: unknown;
  readonly context: unknown;
  readonly approverRootKey: string;
  readonly nowMs: number;
  /** Optional cross-call replay store. When omitted, the WASM core still enforces one-shot local replay. */
  readonly nonceStore?: NonceStore;
}

export interface VerifyPolicyRuleWithAccountStatesInput extends AccountStateOptions {
  readonly rule: unknown;
  readonly accountRootKey: string;
  readonly nowMs: number;
}

export interface EvaluatePolicyWithAccountStatesInput extends AccountStateOptions {
  readonly action: unknown;
  readonly actor?: unknown;
  readonly signedRules: readonly unknown[];
  readonly accountRootKey: string;
  readonly nowMs: number;
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
   * the SDK uses the global `WebSocket` if present and otherwise polls.
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
   * Root-signed account-state JWS documents used to reject verdicts from revoked devices.
   * The caller owns monotonic persistence: supply all known states, or only call with a state set
   * already checked against a durably stored highest sequence.
   */
  readonly accountStates?: readonly string[];
  /**
   * Optional account namespace the client intended to verify. When set, verdict verification fails
   * closed if the signed verdict's certified account id differs from this value.
   */
  readonly expectedAccountId?: string;
  /**
   * Override the timer used for the poll sleep, the fail-closed deadline, and the per-fetch timeout.
   * Meant for tests, so the fail-closed timing can be driven by a fake clock instead of real time.
   *
   * The defaults are two different `setTimeout` timers: the deadline backstop and per-fetch timeout
   * are `unref`'d (they never hold a process open after the wait resolves), while the poll sleep is
   * ref'd (it keeps the process alive between polls when no WebSocket is available). An override
   * replaces **all** of them, so it must keep the event loop alive for the poll sleep. An override
   * that `unref`s it lets node exit mid-wait with no verdict (#254); one that refs everything keeps
   * the process alive until the deadline even after a verdict arrives.
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
  const ctor = (globalThis as { WebSocket?: new (url: string) => unknown }).WebSocket;
  if (!ctor) return undefined;
  return (url: string) => new ctor(url) as never;
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
    readonly syntactic: unknown;
    readonly risk: Risk;
  };
  readonly summary: string;
  readonly actor: { readonly id: string; readonly kind: string; readonly attestation?: string };
  readonly risk: Risk;
  readonly reversible: boolean;
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
      syntactic: req.action.syntactic,
      risk: req.action.risk,
    },
    summary: req.summary,
    actor: {
      id: req.actor.id,
      kind: req.actor.kind,
      // Attestation is carried in the encrypted context when supplied (reserved for #16); omitted
      // when absent so the canonicalization stays byte-identical (the core excludes it from the hash).
      ...(req.actor.attestation !== undefined ? { attestation: req.actor.attestation } : {}),
    },
    risk: req.risk,
    reversible: req.reversible,
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
}

/** Parse the WASM verification JSON and normalize its snake_case nonce field for SDK use. */
function readVerifiedWasmResult(json: string): VerifiedWasmResult {
  const value = JSON.parse(json) as {
    approved?: unknown;
    device_id?: unknown;
    decided_at?: unknown;
    nonce_b64?: unknown;
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
  return {
    approved: true,
    deviceId: value.device_id,
    decidedAt: value.decided_at,
    nonceB64: value.nonce_b64,
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

/** Parse the WASM `revoked_device_ids` JSON result into a `Set` for O(1) recipient filtering. */
function parseRevokedDeviceIds(json: string): ReadonlySet<string> {
  const ids = JSON.parse(json) as unknown;
  if (!Array.isArray(ids) || !ids.every((id) => typeof id === "string")) {
    throw new Error("allw: revoked_device_ids returned a non-string-array result");
  }
  return new Set(ids);
}

/**
 * Drops any device revoked in the caller's verified account-state set from `devices`, **before**
 * a new request is ever encrypted to it (issue #204 fix 1). Without this, a device revoked after
 * enrollment keeps receiving every new request's plaintext `ApprovalContext` indefinitely — the
 * relay-listed device set is untrusted input and account-state revocation was previously enforced
 * only at verdict-verification time, long after the plaintext had already been sent.
 *
 * The revocation-set parse/verify/resolve logic runs entirely in the audited core via
 * `wasm.revoked_device_ids` (thin-shell: this function only threads JSON through and filters the
 * caller-supplied array by device id).
 *
 * When `config.accountStates` is omitted, this resolves to no known revocations (a no-op filter) —
 * matching the same opt-in semantics as verdict-verification's account-state enforcement.
 *
 * @throws when filtering would leave zero recipients, so a fully-revoked account fails loudly
 * (the hook maps the thrown error to a deny) instead of silently submitting a request nobody can
 * decrypt, or worse, only to devices the account owner already revoked.
 */
function filterRevokedDevices(
  wasm: AllwWasm,
  devices: readonly DeviceRecord[],
  accountId: string,
  approverRootKey: string,
  accountStates: readonly string[] | undefined,
): readonly DeviceRecord[] {
  const revokedIds = parseRevokedDeviceIds(
    wasm.revoked_device_ids(accountStatesJson(accountStates), accountId, approverRootKey),
  );
  if (revokedIds.size === 0) return devices;
  const nonRevoked = devices.filter((d) => !revokedIds.has(d.device_id));
  if (nonRevoked.length === 0) {
    throw new Error(
      `allw: approver account '${accountId}' has no non-revoked devices to encrypt to ` +
        `(${String(devices.length)} enrolled device(s), all revoked per account state)`,
    );
  }
  return nonRevoked;
}

/** Treat a blank optional account constraint like omission before crossing into WASM. */
function expectedAccountIdConstraint(expectedAccountId: string | undefined): string | undefined {
  return expectedAccountId === "" ? undefined : expectedAccountId;
}

/**
 * Verify a (possibly null) verdict value through the WASM core and reduce it to a {@link Decision}.
 *
 * - WASM `verify_verdict` returns ⇒ authenticated, bound, fresh, **approved** ⇒ `"approved"`.
 * - It throws the structured `kind: "not_approved"` error ⇒ a *verified* human "no" ⇒ the
 *   **signed** decision it carries (`denied`/`expired`/`aborted`), never the outer verdict's.
 * - It throws anything else (forgery, tamper, bad sig, replay, window, unparseable JSON) ⇒
 *   unverifiable ⇒ `null` (the caller fails closed to a synthesized `denied`).
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
  const wasm = await loadWasm();
  const result = readVerifiedWasmResult(
    wasm.verify_verdict_with_account_states(
      JSON.stringify(input.verdict),
      JSON.stringify(input.request),
      JSON.stringify(input.context),
      input.approverRootKey,
      input.nowMs,
      accountStatesJson(input.accountStates),
      expectedAccountIdConstraint(input.expectedAccountId),
    ),
  );
  if (input.nonceStore && !(await input.nonceStore.checkAndInsert(result.nonceB64))) {
    throw new Error("allw: verdict nonce replayed");
  }
  return result;
}

/** Verify one signed policy rule while enforcing account-state device revocations. */
export async function verifyPolicyRuleWithAccountStates(
  input: VerifyPolicyRuleWithAccountStatesInput,
): Promise<VerifiedPolicyRule> {
  const wasm = await loadWasm();
  const value = JSON.parse(
    wasm.verify_policy_rule_with_account_states(
      JSON.stringify(input.rule),
      input.accountRootKey,
      input.nowMs,
      accountStatesJson(input.accountStates),
      expectedAccountIdConstraint(input.expectedAccountId),
    ),
  ) as { rule?: unknown; device_id?: unknown };
  if (typeof value.device_id !== "string" || value.device_id.length === 0) {
    throw new Error("allw: verified policy rule did not include a device_id");
  }
  return { rule: value.rule, deviceId: value.device_id };
}

/** Evaluate signed policy rules after revocation-aware verification of every rule. */
export async function evaluatePolicyWithAccountStates(
  input: EvaluatePolicyWithAccountStatesInput,
): Promise<PolicyEvaluation> {
  const wasm = await loadWasm();
  const value = JSON.parse(
    wasm.evaluate_policy_with_account_states(
      JSON.stringify(input.action),
      input.actor === undefined ? null : JSON.stringify(input.actor),
      JSON.stringify(input.signedRules),
      input.accountRootKey,
      input.nowMs,
      accountStatesJson(input.accountStates),
      expectedAccountIdConstraint(input.expectedAccountId),
    ),
  ) as { decision?: unknown; rule_id?: unknown; tier?: unknown; schema_version?: unknown };
  if (value.decision !== "allow" && value.decision !== "deny" && value.decision !== "escalate") {
    throw new Error("allw: policy evaluation returned an invalid decision");
  }
  if (value.tier !== "syntactic" && value.tier !== "semantic") {
    throw new Error("allw: policy evaluation returned an invalid tier");
  }
  if (typeof value.schema_version !== "number" || !Number.isSafeInteger(value.schema_version)) {
    throw new Error("allw: policy evaluation returned an invalid schema_version");
  }
  return {
    decision: value.decision,
    ...(typeof value.rule_id === "string" ? { ruleId: value.rule_id } : {}),
    tier: value.tier,
    schemaVersion: value.schema_version,
  };
}

/**
 * Classify an error thrown by the pre-deadline relay round-trip (`fetchDevices`/`submit`) as a
 * **transport** failure that should fail closed to a `Verdict` rather than reject.
 *
 * - {@link RelayTimeoutError} — a hung connect/read we bounded and aborted (the #52 case).
 * - A bare `TypeError` from `fetch` — a connection-level failure (DNS, refused, reset) that never
 *   produced an HTTP response; WHATWG `fetch` rejects with a `TypeError` for these.
 *
 * A {@link RelayError} (a real HTTP status from the relay), the explicit no-devices `Error`, and the
 * explicit all-devices-revoked `Error` (from {@link filterRevokedDevices}) are **not** transport
 * failures — they signal integrator/protocol misconfiguration or a fully-revoked account and keep
 * throwing so the caller (the hook) surfaces a precise deny reason.
 */
function isPreDeadlineTransportFailure(err: unknown): boolean {
  if (err instanceof RelayTimeoutError) return true;
  // A connection-level fetch failure (no HTTP response). `RelayError extends Error` but not
  // `TypeError`, so the `instanceof TypeError` check correctly excludes it.
  if (err instanceof TypeError) return true;
  return false;
}

/**
 * Arm the integrator-initiated cancellation (issue #195): once the request has a
 * `request_auth_token` (i.e. `submit` succeeded), tell the relay to retract it the moment `signal`
 * aborts — immediately, if it is already aborted. Fire-and-forget and best-effort by design: the
 * awaiting `requestApproval` call learns of the retraction through the normal wait mechanism (the
 * relay pushes/reports the terminal `retracted` status back over the same WS/poll path a verdict
 * would arrive on — `wait.ts`), so a failed retract call here can only leave the original deadline
 * in force, never fabricate an approval or silently drop an already-recorded verdict.
 */
function armRetractOnAbort(
  relay: RelayClient,
  requestId: string,
  signal: AbortSignal | undefined,
): void {
  if (!signal) return;
  const doRetract = (): void => {
    relay.retract(requestId).catch(() => {
      // Best-effort: a failed retract just means cancellation had no effect; the deadline still
      // governs (fail-closed default), and a verdict recorded first is never discarded by this.
    });
  };
  if (signal.aborted) {
    doRetract();
    return;
  }
  signal.addEventListener("abort", doRetract, { once: true });
}

/**
 * Construct a relay-bound client. The returned {@link Client.requestApproval} runs the full
 * E2EE round-trip and resolves to a verified {@link Verdict} — never a bare "allow".
 */
export function createClient(config: ClientConfig): Client {
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

    // 3–4. Fetch devices, filter out revoked ones, encrypt, and submit. These run BEFORE the
    // await-verdict deadline timer is armed, so a hung relay (TCP-accepted but never responding)
    // would otherwise wedge the call forever. The per-request fetch timeout (RelayClient) bounds
    // each fetch; here we additionally ensure a *transport* failure on these calls fails closed to
    // a `Verdict` (expired) instead of rejecting — the same fail-closed terminal a wait-stage
    // timeout produces (issue #52, contract §Invariants #6). HTTP-level errors (a relay
    // `RelayError` with a real status, including a malformed device entry), a no-devices account,
    // and an all-devices-revoked account still throw, surfacing integrator/protocol misconfiguration
    // loudly.
    let contextCiphertext: string;
    try {
      const devices = await relay.fetchDevices();
      if (devices.length === 0) {
        throw new Error(
          `allw: approver account '${config.accountId}' has no enrolled devices to encrypt to`,
        );
      }
      // Drop revoked devices from the relay-listed recipient set BEFORE encrypting — the relay is
      // untrusted, so this must run against the caller's own verified account-state, not the
      // relay's device registry (issue #204 fix 1). Throws (fail-closed) if every device is
      // revoked; relay-side eviction (issue #204 fix 2) is a separate, still-open slice.
      const nonRevokedDevices = filterRevokedDevices(
        wasm,
        devices,
        config.accountId,
        config.approverRootKey,
        config.accountStates,
      );
      const recipients = nonRevokedDevices.map((d: DeviceRecord) => ({
        device_id: d.device_id,
        public_key_b64: d.pubkey,
      }));
      // Throws (fail-closed, rethrown below) if any relay-listed device key is a small-order
      // X25519 point: the core refuses the whole encryption and names the device (#248).
      contextCiphertext = wasm.encrypt_context(contextJson, JSON.stringify(recipients));

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
        context_ciphertext: contextCiphertext,
      };
      await relay.submit(envelope);
      // The request now has a `request_auth_token` to retract with — arm cancellation (issue #195).
      armRetractOnAbort(relay, id, req.signal);
    } catch (err) {
      if (isPreDeadlineTransportFailure(err)) {
        // A hung/black-holed connection or a bare network error before the deadline ⇒ no verified
        // verdict is obtainable ⇒ fail closed to an `expired` Verdict (never approved). This is the
        // load-bearing fix for #52: the call resolves deterministically instead of hanging forever.
        return makeVerdict(id, "expired", { kind: "timeout" }, "", "", now, nonceStore);
      }
      // HTTP/protocol error or no-devices ⇒ rethrow (the hook's try/catch maps it to a deny).
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

    // 5. Await the verdict (WS-preferred, poll fallback), fail-closed at `expires_at`.
    let outcome;
    try {
      outcome = await awaitVerdict(id, {
        relay,
        now,
        deadline: expiresAt,
        ...(webSocketFactory ? { webSocketFactory } : {}),
        pollIntervalMs,
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
      const verified = await verifyToDecision(
        wasm,
        outcome.value,
        requestJson,
        contextJson,
        config.approverRootKey,
        now(),
        nonceStore,
        config.accountStates,
        config.expectedAccountId,
      );
      // Unverifiable verdict ⇒ synthesized `denied` (never surface a forged decision as truth).
      decision = verified?.decision ?? "denied";
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
      config.accountStates,
      config.expectedAccountId,
      acceptedNonceB64,
    );
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
      const expectedAccountId =
        options && "expectedAccountId" in options
          ? options.expectedAccountId
          : clientExpectedAccountId;
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
