/**
 * Wire types the approver reads/writes, mirrored from the Rust core's serde shapes
 * (`crates/allw-core/src/contract.rs`) and `docs/contract.md` §Messages / §Wire encoding.
 *
 * These are **read models** only — the approver never re-derives any of these bytes itself; it
 * decrypts via the WASM core and renders/echoes what the core produces. They exist so the TS
 * surface is strongly typed at the trust boundary (decrypted plaintext, relay messages).
 */

/** The human's decision (`docs/contract.md` §Messages → Verdict). */
export type Decision = "approved" | "denied" | "expired" | "aborted";

/** Coarse risk classification shown to the human. */
export type Risk = "low" | "medium" | "high" | "critical";

/** The interception paradigm an action arrived through. */
export type Surface = "command" | "mcp_tool_call";

/**
 * Tokenized syntactic substrate — opaque, untrusted structure the approver renders but never
 * interprets. Typed `unknown` because it arrives from decrypted plaintext: the renderer must
 * narrow it defensively rather than assume a shape.
 */
export type SyntacticSubstrate = unknown;

/** Reduced, matchable record of an approvable action (v1 carries the syntactic substrate only). */
export interface ActionRecord {
  readonly record_schema_version: number;
  readonly surface: Surface;
  readonly syntactic: SyntacticSubstrate;
  readonly risk: Risk;
  /** Reserved for the T3 semantic tier — null/absent in v1. */
  readonly capabilities?: unknown[] | null;
  /** Reserved for the T3 semantic tier — null/absent in v1. */
  readonly scope?: unknown;
}

/** The automation requesting approval (identity + optional attestation). */
export interface Actor {
  readonly id: string;
  readonly kind: string;
  /** Actor-key signature (base64url) — a verification artifact, excluded from `request_hash`. */
  readonly attestation?: string;
}

/** Allowed decisions + challenge policy. */
export interface Constraints {
  readonly allowed_decisions: Decision[];
  readonly challenge_required: boolean;
}

/**
 * The complete human-shown payload, decrypted from the envelope's `context_ciphertext`.
 * `request_hash` is computed (by the WASM core) over these fields **plus** the envelope's
 * `expires_at` (`docs/contract.md` §Wire encoding → request_hash).
 */
export interface ApprovalContext {
  readonly action: ActionRecord;
  readonly summary: string;
  readonly actor: Actor;
  readonly risk: Risk;
  readonly reversible: boolean;
  readonly constraints: Constraints;
  /** Upstream-gate IDs for audit correlation; omitted when absent. */
  readonly chain?: string[];
}

/**
 * The relay-visible envelope wrapping the ciphertext (`docs/contract.md` §Messages →
 * ApprovalRequest). The approver reads `expires_at` from here (bound into `request_hash`) and
 * decrypts `context_ciphertext`.
 */
export interface ApprovalRequest {
  readonly v: number;
  readonly id: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly approver: string;
  readonly context_ciphertext?: string;
}

/** Identifies the approver account + device that signed a verdict. */
export interface Approver {
  readonly account_id: string;
  readonly device_id: string;
}

/**
 * The unsigned verdict the approver assembles before handing it to the WASM core to sign.
 * `request_hash` is the base64url digest the core computed from the decrypted context.
 */
export interface UnsignedVerdict {
  readonly v: number;
  readonly request_id: string;
  readonly request_hash: string;
  readonly decision: Decision;
  readonly decided_at: number;
  readonly approver: Approver;
  readonly note?: string;
  readonly challenge_response?: string;
}

/** Relay → device presence-socket message (`docs/contract.md` §Transport → Device socket). */
export type DeviceInboundMessage =
  | { readonly type: "request"; readonly request_id: string; readonly envelope: ApprovalRequest }
  | { readonly type: "retract"; readonly request_id: string }
  | { readonly type: "ack"; readonly request_id: string; readonly status: string }
  | { readonly type: "error"; readonly error: string };

/** Device → relay presence-socket message. */
export interface VerdictOutboundMessage {
  readonly type: "verdict";
  readonly request_id: string;
  readonly verdict: unknown;
}
