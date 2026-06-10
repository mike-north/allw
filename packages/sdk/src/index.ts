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
  type ApprovalRequestEnvelope,
  type DeviceRecord,
  type FetchImpl,
  type NowImpl,
} from "./relay.js";
import { awaitVerdict, type WebSocketFactory } from "./wait.js";
import { loadWasm, type AllwWasm } from "./wasm.js";

/**
 * A verdict decision. In v0 `requestApproval` only ever *resolves* to `approved` (verified),
 * `denied` (a verified human "no" or a fail-closed synthesis), or `expired` (timeout / past
 * deadline). `aborted` is part of the wire vocabulary but originates **only from a signed device
 * verdict** — there is no client-side cancellation (`AbortSignal`) in v0, so the SDK never
 * synthesizes it.
 */
export type Decision = "approved" | "denied" | "expired" | "aborted";
export type Risk = "low" | "medium" | "high" | "critical";

/** The interception paradigm an action arrived through. */
export type Surface = "command" | "mcp_tool_call";

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
   * non-approval, forgery, or transport-synthesized denial. Never throws.
   */
  verify(approverRootKey: string): Promise<boolean>;
}

/** Configuration for {@link createClient}. */
export interface ClientConfig {
  /** Base URL of the relay (e.g. `https://relay.allw.example`). */
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
   * Override the timer used to schedule the poll cadence and the fail-closed deadline (tests).
   * Defaults to `setTimeout`. Exposed so the fail-closed timing can be driven deterministically by
   * a fake clock instead of waiting in real time.
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

/** Validate that a parsed verdict is an object carrying a string `decision`; returns it or `null`. */
function readDecision(value: unknown): Decision | null {
  if (typeof value !== "object" || value === null) return null;
  const decision = (value as { decision?: unknown }).decision;
  if (
    decision === "approved" ||
    decision === "denied" ||
    decision === "expired" ||
    decision === "aborted"
  ) {
    return decision;
  }
  return null;
}

/** True when a thrown WASM verify error is an *authenticated* non-approval (a verified human "no"). */
function isAuthenticatedNonApproval(message: string): boolean {
  // The core's `VerifyError::NotApproved` Display: "verified human decision was not 'approved': …".
  return message.includes("verified human decision was not");
}

/**
 * Verify a (possibly null) verdict value through the WASM core and reduce it to a {@link Decision}.
 *
 * - WASM `verify_verdict` returns ⇒ authenticated, bound, fresh, **approved** ⇒ `"approved"`.
 * - It throws `NotApproved` ⇒ a *verified* human "no" ⇒ the verdict's real `decision`
 *   (`denied`/`expired`/`aborted`), defaulting to `denied` if unreadable.
 * - It throws anything else (forgery, tamper, bad sig, replay, window) ⇒ unverifiable ⇒ `null`
 *   (the caller fails closed to a synthesized `denied`).
 *
 * NOTE (replay): the WASM `verify_verdict` uses a fresh single-shot nonce store per call, so this
 * SDK does **not** provide cross-request replay protection on its own — guarding against a replayed
 * verdict across requests is the integrator's responsibility (a persistent nonce store) until the
 * SDK threads one through (#48). Not required for the v0 walking skeleton.
 */
function verifyToDecision(
  wasm: AllwWasm,
  verdictValue: unknown,
  requestJson: string,
  contextJson: string,
  approverRootKey: string,
  nowMs: number,
): Decision | null {
  if (verdictValue === null || verdictValue === undefined) return null;
  const verdictJson = JSON.stringify(verdictValue);
  try {
    wasm.verify_verdict(verdictJson, requestJson, contextJson, approverRootKey, nowMs);
    return "approved";
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (isAuthenticatedNonApproval(message)) {
      // Authenticated, bound, fresh — but the human did not approve. Report the verified decision.
      return readDecision(verdictValue) ?? "denied";
    }
    // Forgery / tamper / expiry-window / replay — unverifiable. Fail closed.
    return null;
  }
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
  const relay = new RelayClient(config.relayUrl, config.accountId, fetchImpl);

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

    // 3. Fetch the approver's enrolled devices and encrypt the context to their keys (JWE).
    const devices = await relay.fetchDevices();
    if (devices.length === 0) {
      throw new Error(
        `allw: approver account '${config.accountId}' has no enrolled devices to encrypt to`,
      );
    }
    const recipients = devices.map((d: DeviceRecord) => ({
      device_id: d.device_id,
      public_key_b64: d.pubkey,
    }));
    const contextCiphertext = wasm.encrypt_context(contextJson, JSON.stringify(recipients));

    // 4. Build the relay-visible envelope (exactly the contract's key set) and submit it.
    const id = newRequestId();
    const envelope: ApprovalRequestEnvelope = {
      v: PROTOCOL_VERSION,
      id,
      created_at: createdAt,
      expires_at: expiresAt,
      // The client is bound to one account; the envelope's routing `approver` IS that account. Using
      // `config.accountId` (not a per-request field) removes the footgun where a request could be
      // POSTed to one account DO while claiming a different approver in the verified request JSON.
      approver: config.accountId,
      context_ciphertext: contextCiphertext,
    };
    await relay.submit(envelope);

    // The `request_json` the core verifies against is the envelope WITHOUT the ciphertext — the
    // verifier reads only routing/lifecycle (`v`, `id`, `created_at`, `expires_at`, `approver`).
    const requestJson = JSON.stringify({
      v: envelope.v,
      id: envelope.id,
      created_at: envelope.created_at,
      expires_at: envelope.expires_at,
      approver: envelope.approver,
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
    if (outcome.kind === "verdict") {
      const verified = verifyToDecision(
        wasm,
        outcome.value,
        requestJson,
        contextJson,
        config.approverRootKey,
        now(),
      );
      // Unverifiable verdict ⇒ synthesized `denied` (never surface a forged decision as truth).
      decision = verified ?? "denied";
    } else if (outcome.kind === "expired") {
      decision = "expired";
    } else {
      // timeout — fail closed.
      decision = "expired";
    }

    // 7. Resolve to a Verdict whose decision reflects reality; `verify()` re-runs the full check.
    return makeVerdict(id, decision, outcome, requestJson, contextJson, now);
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
): Verdict {
  const verdictValue = outcome.kind === "verdict" ? outcome.value : null;
  return {
    requestId,
    decision,
    async verify(approverRootKey: string): Promise<boolean> {
      // A synthesized (non-delivered) outcome has no verifiable artifact — it can never be approved.
      if (verdictValue === null || verdictValue === undefined) return false;
      const wasm = await loadWasm();
      const result = verifyToDecision(
        wasm,
        verdictValue,
        requestJson,
        contextJson,
        approverRootKey,
        now(),
      );
      return result === "approved";
    },
  };
}
