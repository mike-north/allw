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
export type Surface = "command" | "mcp_tool_call" | "file_edit" | "agent_tool_call";

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
 * The escaped syntactic substrate (Rust `allw_core::DisplaySubstrate`). Each field is present
 * exactly when the hashed substrate field is; every string has already been escaped by the core.
 */
export interface DisplaySubstrate {
  readonly bin?: string;
  readonly argv?: readonly string[];
  readonly flags?: readonly string[];
  readonly positionals?: readonly string[];
  readonly cwd?: string;
  readonly host?: string;
  readonly env_refs?: readonly string[];
  readonly server?: string;
  readonly tool?: string;
  /** `params` as compact, escaped JSON (sorted keys). */
  readonly params_json?: string;
  /** `params` as indented JSON, one escaped line per entry. */
  readonly params_json_lines?: readonly string[];
  readonly operation?: string;
  readonly paths?: readonly string[];
  readonly diff_summary?: string;
  readonly diff_hash?: string;
  /** `raw` as one escaped line (a line feed shows as `\n`). */
  readonly raw?: string;
  /** `file_edit` only: `raw` split on line feeds, each line escaped. */
  readonly raw_lines?: readonly string[];
}

/**
 * The core's display model of an {@link ApprovalContext} (Rust `allw_core::DisplayModel`, built by
 * the WASM `display_model`). It is the only source of context text the approver may print: every
 * string is escaped with the core notation (`\x1b`, `\r`, `⟨U+202E⟩`, …), and
 * `has_hidden_or_control_chars` reports whether any escape was needed (#246). Display only — never
 * hashed, signed, or sent.
 */
export interface DisplayModel {
  readonly surface: Surface;
  readonly risk: Risk;
  readonly reversible: boolean;
  readonly summary: string;
  readonly actor_id: string;
  readonly actor_kind: string;
  /** `"<id> (<kind>)"`, both parts escaped. */
  readonly actor_label: string;
  readonly syntactic: DisplaySubstrate;
  readonly chain?: readonly string[];
  readonly has_hidden_or_control_chars: boolean;
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
