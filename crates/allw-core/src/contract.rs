//! Wire types for the approval contract. See `docs/contract.md`.
//!
//! Every surface — the WASM/TS SDK, the relay, and native apps via UniFFI — shares exactly
//! these types. Correctness against the design docs is paramount: the whole trust model
//! depends on byte-identical JSON across language boundaries.
//!
//! # Wire encoding decisions (pinned in docs/contract.md §Wire encoding)
//!
//! - **Binary fields** (`request_hash`, `prev_hash`, `record_hash`, `attestation`) serialize as
//!   **base64url-unpadded JSON strings** (JOSE-consistent). See [`wire_b64`]. (`sig` and
//!   `device_cert` are NOT binary — they are compact-JWS strings; `context_ciphertext` is a
//!   compact-JWE string.)
//! - **Timestamps** (`created_at`, `expires_at`, `decided_at`) are `i64` Unix milliseconds (UTC).
//!   No chrono/time dependency; computing "now"/expiry is a later issue.
//! - **IDs** are plain `String`. Newtypes are deferred.
//! - **Optional fields** carry `#[serde(skip_serializing_if = "Option::is_none", default)]`
//!   so `None` is omitted from JSON (and `null`/absent both deserialize to `None`).
//! - **JSON casing**: struct fields stay snake_case (Rust default); enums carry
//!   `#[serde(rename_all = "snake_case")]`.

use serde::{Deserialize, Serialize};

// ── base64url helpers ─────────────────────────────────────────────────────────

/// Private serde helpers for binary wire fields.
///
/// All binary values in the wire format are base64url-unpadded strings, consistent with JOSE.
/// This enables byte-identical output across the Rust core and the WASM/TS surface.
mod wire_b64 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    /// The single place the base64url engine choice lives — all binary wire fields route through
    /// `encode`/`decode` so the encoding cannot drift between helpers.
    pub fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Decodes a base64url-unpadded string. Counterpart to [`encode`].
    pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(s)
    }

    /// Serialize a `[u8; 32]` as a base64url-unpadded string.
    pub fn serialize_32<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(bytes))
    }

    /// Deserialize a `[u8; 32]` from a base64url-unpadded string.
    ///
    /// Returns an error if the string does not decode to exactly 32 bytes.
    pub fn deserialize_32<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = decode(&s).map_err(D::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected exactly 32 bytes after base64url decode"))
    }

    /// Serialize a `Vec<u8>` as a base64url-unpadded string.
    pub fn serialize_vec<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(bytes))
    }
}

// ── Enums ─────────────────────────────────────────────────────────────────────

/// The interception paradigm an action arrived through.
///
/// `#[non_exhaustive]` preserves forward-compat as new surfaces are added
/// (e.g. `AgentToolCall`, `DelegatedFetch`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// A shell command (with sub-paradigms: subcommand-tree, object-action, …).
    Command,
    /// An MCP tool call.
    McpToolCall,
    /// A direct file-edit tool call such as Codex `apply_patch` or Claude Code `Edit`/`Write`.
    FileEdit,
    // Future: AgentToolCall, DelegatedFetch.
}

/// The human's decision.
///
/// One-shot and scope-free — standing autonomy lives in the policy layer, never here.
/// See `docs/contract.md` §Invariants #5 and the `Verdict` doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approved,
    Denied,
    Expired,
    Aborted,
}

/// Coarse risk tier.
///
/// v1: coarse heuristic assigned by the integrator/SDK.
/// Later (T3): capability-derived from the semantic `ActionRecord` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

// ── SyntacticSubstrate ────────────────────────────────────────────────────────

/// The tokenized, matchable syntactic form of an action.
///
/// All fields are optional; which ones are populated depends on the `surface`:
///
/// - `surface = command`: `bin`, `argv`, `flags`, `positionals`, `cwd`, `host`, `env_refs`
/// - `surface = mcp_tool_call`: `server`, `tool`, `params`
/// - `surface = file_edit`: `operation`, `paths`, `diff_summary`, `diff_hash`, `raw`
/// - File edits set `raw` to the exact edit/patch text for WYSIWYS display.
/// - Other surfaces may set `raw` for display/fallback.
///
/// The T1 syntactic substrate is the durable base that all three policy tiers match against.
/// See `docs/policy-seam.md` §The action record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyntacticSubstrate {
    // ── command-surface fields ────────────────────────────────────────────────
    /// The binary/executable name (e.g. `"git"`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bin: Option<String>,

    /// Full argument vector including the binary (e.g. `["git", "push", "--force"]`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub argv: Option<Vec<String>>,

    /// Parsed flag tokens (e.g. `["--force", "-f"]`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub flags: Option<Vec<String>>,

    /// Positional arguments stripped of flags (e.g. `["origin", "main"]`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub positionals: Option<Vec<String>>,

    /// Working directory at time of invocation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cwd: Option<String>,

    /// Hostname if the command targets a remote host (e.g. SSH targets).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub host: Option<String>,

    /// Names of environment variables referenced (values are NOT captured).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub env_refs: Option<Vec<String>>,

    // ── mcp_tool_call-surface fields ─────────────────────────────────────────
    /// MCP server name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub server: Option<String>,

    /// MCP tool name within the server.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool: Option<String>,

    /// Tool call parameters as raw/structured JSON values.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub params: Option<serde_json::Value>,

    // ── file_edit-surface fields ─────────────────────────────────────────────
    /// File edit operation kind (`patch`, `edit`, `multi_edit`, `write`, …).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operation: Option<String>,

    /// Target file paths affected by the edit.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub paths: Option<Vec<String>>,

    /// Human-readable compact summary of the file edit/diff.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub diff_summary: Option<String>,

    /// Base64url-unpadded SHA-256 hash of the full diff/edit bytes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub diff_hash: Option<String>,

    // ── cross-surface fields ─────────────────────────────────────────────────
    /// Original string form — used for display and as a fallback for matching.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub raw: Option<String>,
}

// ── ActionRecord ──────────────────────────────────────────────────────────────

/// A reduced, matchable record of an approvable action.
///
/// v1 populates the syntactic substrate; the semantic `capabilities`/`scope` fields are
/// reserved for the policy layer's T3 semantic tier and are always `None` in v1.
/// See `docs/policy-seam.md` §Forward-compat requirements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRecord {
    /// Schema version for this record shape. Bumped only on a breaking change.
    pub record_schema_version: u32,

    /// The interception paradigm this action arrived through.
    pub surface: Surface,

    /// Tokenized syntactic form. Populated in v1; the base all three policy tiers match against.
    pub syntactic: SyntacticSubstrate,

    /// Coarse risk tier. v1: heuristic. T3: capability-derived.
    pub risk: Risk,

    /// Reserved for the T3 semantic tier (docs/policy-seam.md §forward-compat req #3).
    ///
    /// MUST be `None` in v1. The field is typed `Option<Vec<serde_json::Value>>` so the T3
    /// engine can layer on capability annotations without a wire-format break. Omitted from
    /// JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub capabilities: Option<Vec<serde_json::Value>>,

    /// Reserved for the T3 semantic tier (docs/policy-seam.md §forward-compat req #3).
    ///
    /// MUST be `None` in v1. Typed as unstructured JSON to avoid foreclosing the T3 scope
    /// shape. Omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scope: Option<serde_json::Value>,
}

// ── Actor ─────────────────────────────────────────────────────────────────────

/// The automation (agent, hook, gateway) requesting approval.
///
/// `id` and `kind` are strings; the doc enumerates no closed kind set, so `String` avoids
/// foreclosing future actor kinds (e.g. `"machine:macbook"`, `"claude-code"`, `"gateway"`).
///
/// `attestation` carries an actor-key signature. The verifying key and full attestation
/// semantics are owned by later identity issues; the field is typed `Option<Vec<u8>>` here
/// and serializes as a base64url-unpadded string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Actor {
    /// Stable actor identity (e.g. `"machine:macbook-pro"`).
    pub id: String,

    /// Actor kind — not enumerated in v1; kept as `String` to avoid foreclosing future kinds.
    pub kind: String,

    /// Actor-key signature (attestation payload). Omitted when absent.
    ///
    /// The verifying key, key enrollment, and full attestation semantics are deferred to
    /// later identity issues. See `docs/contract.md` §Identity & keys.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "option_wire_b64_vec"
    )]
    pub attestation: Option<Vec<u8>>,
}

// serde helper: Option<Vec<u8>> ↔ Option<base64url string>
mod option_wire_b64_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match val {
            Some(bytes) => super::wire_b64::serialize_vec(bytes, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            None => Ok(None),
            // Route through wire_b64 so the base64url engine choice lives in exactly one place.
            Some(s) => super::wire_b64::decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

// ── Constraints ───────────────────────────────────────────────────────────────

/// Request constraints on which decisions are valid and whether a challenge is required.
///
/// `challenge_required` governs the number-match challenge for destructive/critical ops. When
/// true, the approver signs the four-digit code derived from `request_hash`; verification
/// fail-closes unless `challenge_response` matches that derived value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Constraints {
    /// Which [`Decision`] variants the approver is permitted to select.
    pub allowed_decisions: Vec<Decision>,

    /// Whether a number-match challenge is required (destructive/critical operations).
    pub challenge_required: bool,
}

// ── ApprovalContext ───────────────────────────────────────────────────────────

/// The complete human-shown approval payload — the plaintext encrypted into the JWE.
///
/// Per `docs/contract.md` §Messages, this is the payload that is encrypted to the approver's
/// device key(s) (the JWE — wired in issue #5) and carried inside an [`ApprovalRequest`]
/// envelope as `context_ciphertext`. **The relay never sees this** — only the approver's
/// devices (and the integrator, which builds it locally) hold the plaintext.
///
/// The WYSIWYS `request_hash` is computed over the canonical *request-hash input* — every
/// field of this struct **plus** the envelope's `expires_at`, as one flat object
/// (see `docs/contract.md` §Wire encoding → request_hash and [`crate::hash`]). The actor's
/// `attestation` is excluded from that hash (it is a verification artifact the device checks
/// separately, not shown content) but is carried here for the device to verify after decryption.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalContext {
    /// The approvable action, in reduced matchable form.
    pub action: ActionRecord,

    /// Human-readable summary of what is being approved (shown in the inbox).
    pub summary: String,

    /// The automation requesting approval (identity + attestation).
    pub actor: Actor,

    /// Coarse risk classification.
    pub risk: Risk,

    /// Whether the action can be undone if approved.
    pub reversible: bool,

    /// Allowed decisions and challenge policy.
    pub constraints: Constraints,

    /// Upstream-gate IDs for audit-chain correlation. Omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chain: Option<Vec<String>>,
}

// ── ApprovalRequest ───────────────────────────────────────────────────────────

/// The relay-visible **envelope** wrapping the encrypted [`ApprovalContext`].
///
/// Per `docs/contract.md` §Messages → ApprovalRequest, this carries only routing + lifecycle
/// metadata plus the opaque `context_ciphertext`; **the relay never sees the
/// [`ApprovalContext`]** (the `ActionRecord`, `summary`, `actor`, constraints, …) or any
/// rendered content.
///
/// `request_hash` is **not** an envelope field: it is computed over the [`ApprovalContext`]
/// (plus this envelope's `expires_at`) by the integrator pre-send and recomputed by the device
/// post-decryption, and travels only inside the [`Verdict`]. See [`crate::hash`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Protocol/schema version.
    pub v: u32,

    /// Request ID (UUID or equivalent).
    pub id: String,

    /// Creation time — Unix milliseconds (UTC).
    pub created_at: i64,

    /// Expiry time — Unix milliseconds (UTC). After this the request is void (fail-closed).
    pub expires_at: i64,

    /// Approver routing ID (maps to the approver's account/inbox on the relay).
    pub approver: String,

    /// Compact-JWE string encrypting the [`ApprovalContext`] to the approver's device key(s).
    ///
    /// `None` while encryption is not yet wired (see issue #5). Omitted from JSON when absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context_ciphertext: Option<String>,
}

// ── Approver ──────────────────────────────────────────────────────────────────

/// Identifies the approver account and device that signed the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approver {
    /// Account ID (the approver's allw account).
    pub account_id: String,

    /// Device ID of the enrolled device that signed the verdict.
    pub device_id: String,
}

// ── Verdict ───────────────────────────────────────────────────────────────────

/// A signed, verifiable verdict bound to a specific request.
///
/// # Invariants (from `docs/contract.md`)
///
/// - **One-shot and scope-free** — standing autonomy lives in the policy layer, never here.
///   There is intentionally no `scope`/reuse field.
/// - **Fail-closed** — timeout / no-response / unverifiable ⇒ deny. The `decision` field
///   reports what the human chose; `is_human_approved` is a convenience reader.
/// - **WYSIWYS** — `request_hash` is echoed back and covered by `sig`, binding the verdict
///   to the exact plaintext the human was shown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// Protocol/schema version.
    pub v: u32,

    /// The [`ApprovalRequest::id`] this verdict responds to.
    pub request_id: String,

    /// Echoes [`ApprovalRequest::request_hash`]; covered by `sig` (WYSIWYS binding).
    #[serde(with = "wire_b64_32")]
    pub request_hash: [u8; 32],

    /// The human's decision.
    pub decision: Decision,

    /// Time the decision was made — Unix milliseconds (UTC).
    pub decided_at: i64,

    /// The approver account and device that signed this verdict.
    pub approver: Approver,

    /// Optional free-form note from the approver. Omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub note: Option<String>,

    /// Number-match challenge response. Omitted when no challenge was required.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub challenge_response: Option<String>,

    /// Device-key signature as an **EdDSA compact JWS** (RFC 7515 + RFC 8037).
    ///
    /// Format: `b64url(protected_header) + "." + b64url(payload) + "." + b64url(signature)`.
    /// The protected header is `{"alg":"EdDSA","typ":"allw-verdict+jws","kid":<device_id>}`
    /// and the payload is the signed [`crypto::VerdictClaims`] set — `request_id`,
    /// `request_hash`, `decision`, `decided_at`, `nonce`, and (when present)
    /// `challenge_response`. Those claims are what the signature authenticates; the outer
    /// fields here are a decoded convenience and are cross-checked against the claims during
    /// [`crypto::verify_verdict`]. See `docs/contract.md` §Wire encoding → verdict signature.
    ///
    /// [`crypto::VerdictClaims`]: crate::crypto::VerdictClaims
    /// [`crypto::verify_verdict`]: crate::crypto::verify_verdict
    pub sig: String,

    /// JWS/DID certificate chaining the device key to the account root.
    ///
    /// Allows verifiers to trust only the account root key. Omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub device_cert: Option<String>,
}

impl Verdict {
    /// Reports the human decision only.
    ///
    /// This is **not** authorization: the primitive never returns "allow". The integrator
    /// computes `allow = approved ∧ verified ∧ policy ∧ other_gates` — a verdict can only
    /// ever tighten, never loosen. See `docs/contract.md` §Invariants #5.
    #[must_use]
    pub fn is_human_approved(&self) -> bool {
        matches!(self.decision, Decision::Approved)
    }
}

// ── PolicyDecision / PolicyBlock ──────────────────────────────────────────────

/// The policy engine's outcome for an action.
///
/// v1 always writes `Escalate` (the action was sent to the human gate). `Allow`/`Deny`
/// are reserved for the T3 engine so that audit history is policy-analyzable later.
/// See `docs/policy-seam.md` §forward-compat req #4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny,
    Escalate,
}

/// Reserved policy block embedded in every [`AuditRecord`].
///
/// v1 always writes `decision: escalate`. The block exists so that the audit history is
/// policy-analyzable once the T3 engine is built. See `docs/policy-seam.md` §forward-compat
/// req #4 and `AuditRecord` doc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyBlock {
    /// The policy engine's decision that led to this audit entry.
    pub decision: PolicyDecision,

    /// The policy rule that matched, if any. Omitted when no rule matched (escalate path).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rule_id: Option<String>,

    /// Policy tier that produced this decision (`"syntactic"` in v1; `"semantic"` later).
    pub tier: String,

    /// Schema version of the policy evaluation that produced this block.
    pub schema_version: u32,
}

// ── AuditRecord ───────────────────────────────────────────────────────────────

/// One entry in the append-only, hash-chained audit log.
///
/// Per `docs/contract.md` §Messages → AuditRecord, `request_hash` (the hash of the canonical
/// [`ApprovalContext`]) is the complete "prove-what-was-shown-without-storing-plaintext" proof;
/// there is intentionally **no** separate `context_digest`.
///
/// See `docs/contract.md` §Messages → AuditRecord.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Monotonically increasing sequence number within the audit chain.
    pub seq: u64,

    /// SHA-256 of the previous record's canonical JSON (hash chain linkage).
    #[serde(with = "wire_b64_32")]
    pub prev_hash: [u8; 32],

    /// SHA-256 of this record's canonical JSON (self-hash; filled after construction).
    #[serde(with = "wire_b64_32")]
    pub record_hash: [u8; 32],

    /// The [`ApprovalRequest::id`] this record covers.
    pub request_id: String,

    /// Echoes [`ApprovalRequest::request_hash`]; binds the audit entry to the exact context.
    #[serde(with = "wire_b64_32")]
    pub request_hash: [u8; 32],

    /// The actor who submitted the request.
    pub actor: Actor,

    /// The approver who decided.
    pub approver: Approver,

    /// The decision that was made.
    pub decision: Decision,

    /// Time of decision — Unix milliseconds (UTC).
    pub decided_at: i64,

    /// The action that was approved/denied (full record for audit completeness).
    pub action: ActionRecord,

    /// Reserved policy block. v1 always writes `escalate`. See [`PolicyBlock`].
    pub policy: PolicyBlock,

    /// Optional free-form note from the approver. Omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub note: Option<String>,

    /// The verdict's device-key signature — the **EdDSA compact JWS** string, carried into the
    /// audit record verbatim for non-repudiation. Same format as [`Verdict::sig`].
    pub sig: String,
}

// ── serde helper modules (newtype-style, used via `#[serde(with = ...)]`) ─────

/// `[u8; 32]` ↔ base64url-unpadded string.
mod wire_b64_32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        super::wire_b64::serialize_32(bytes, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        super::wire_b64::deserialize_32(d)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    // ── Fixed test data ───────────────────────────────────────────────────────

    /// Fixed 32-byte value used as a stand-in for hashes. All zeros would technically work,
    /// but a non-trivial value surfaces endianness or padding bugs in base64 encoding.
    const HASH_A: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    const HASH_B: [u8; 32] = [
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1,
        0xf0, 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2,
        0xe1, 0xe0,
    ];

    // Fixed Unix millisecond timestamps (deterministic — never SystemTime::now()).
    // 2023-11-14T22:13:20Z
    const TS_CREATED: i64 = 1_700_000_000_000;
    // 2023-11-14T23:13:20Z (+1 hour)
    const TS_EXPIRES: i64 = 1_700_003_600_000;
    // 2023-11-14T22:30:00Z
    const TS_DECIDED: i64 = 1_700_001_000_000;

    /// A representative EdDSA compact JWS (`header.payload.signature`, three base64url parts).
    /// These contract-layer tests only exercise the wire shape — `sig` is now an opaque JWS
    /// `String`; cryptographic construction/verification is covered in `crypto.rs`.
    const SAMPLE_JWS: &str = "eyJhbGciOiJFZERTQSJ9.eyJyZXF1ZXN0X2lkIjoicmVxXzEifQ.3q2-7w";

    fn make_actor() -> Actor {
        Actor {
            id: "machine:macbook-pro".to_string(),
            kind: "claude-code".to_string(),
            attestation: None,
        }
    }

    fn make_syntactic_command() -> SyntacticSubstrate {
        SyntacticSubstrate {
            bin: Some("git".to_string()),
            argv: Some(vec![
                "git".to_string(),
                "push".to_string(),
                "--force".to_string(),
            ]),
            flags: Some(vec!["--force".to_string()]),
            positionals: Some(vec!["origin".to_string(), "main".to_string()]),
            cwd: Some("/home/user/repo".to_string()),
            host: None,
            env_refs: None,
            server: None,
            tool: None,
            params: None,
            operation: None,
            paths: None,
            diff_summary: None,
            diff_hash: None,
            raw: Some("git push --force".to_string()),
        }
    }

    fn make_action_record() -> ActionRecord {
        ActionRecord {
            record_schema_version: 1,
            surface: Surface::Command,
            syntactic: make_syntactic_command(),
            risk: Risk::High,
            capabilities: None,
            scope: None,
        }
    }

    fn make_constraints() -> Constraints {
        Constraints {
            allowed_decisions: vec![Decision::Approved, Decision::Denied],
            challenge_required: false,
        }
    }

    fn make_approval_request() -> ApprovalRequest {
        ApprovalRequest {
            v: 1,
            id: "req_01hk0000000000000000000000".to_string(),
            created_at: TS_CREATED,
            expires_at: TS_EXPIRES,
            approver: "acc_01hk0000000000000000000001".to_string(),
            context_ciphertext: None,
        }
    }

    fn make_approval_context() -> ApprovalContext {
        ApprovalContext {
            action: make_action_record(),
            summary: "Force-push to main branch".to_string(),
            actor: make_actor(),
            risk: Risk::High,
            reversible: false,
            constraints: make_constraints(),
            chain: None,
        }
    }

    fn make_verdict() -> Verdict {
        Verdict {
            v: 1,
            request_id: "req_01hk0000000000000000000000".to_string(),
            request_hash: HASH_A,
            decision: Decision::Approved,
            decided_at: TS_DECIDED,
            approver: Approver {
                account_id: "acc_01hk0000000000000000000001".to_string(),
                device_id: "dev_01hk0000000000000000000002".to_string(),
            },
            note: None,
            challenge_response: None,
            sig: SAMPLE_JWS.to_string(),
            device_cert: None,
        }
    }

    fn make_audit_record() -> AuditRecord {
        AuditRecord {
            seq: 42,
            prev_hash: HASH_B,
            record_hash: HASH_A,
            request_id: "req_01hk0000000000000000000000".to_string(),
            request_hash: HASH_A,
            actor: make_actor(),
            approver: Approver {
                account_id: "acc_01hk0000000000000000000001".to_string(),
                device_id: "dev_01hk0000000000000000000002".to_string(),
            },
            decision: Decision::Approved,
            decided_at: TS_DECIDED,
            action: make_action_record(),
            policy: PolicyBlock {
                decision: PolicyDecision::Escalate,
                rule_id: None,
                tier: "syntactic".to_string(),
                schema_version: 1,
            },
            note: None,
            sig: SAMPLE_JWS.to_string(),
        }
    }

    // ── Round-trip tests ──────────────────────────────────────────────────────

    #[test]
    fn surface_round_trip() {
        for v in [Surface::Command, Surface::McpToolCall, Surface::FileEdit] {
            let json = serde_json::to_string(&v).unwrap();
            let back: Surface = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn decision_round_trip() {
        for v in [
            Decision::Approved,
            Decision::Denied,
            Decision::Expired,
            Decision::Aborted,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: Decision = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn risk_round_trip() {
        for v in [Risk::Low, Risk::Medium, Risk::High, Risk::Critical] {
            let json = serde_json::to_string(&v).unwrap();
            let back: Risk = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn syntactic_substrate_round_trip() {
        let orig = make_syntactic_command();
        let json = serde_json::to_string(&orig).unwrap();
        let back: SyntacticSubstrate = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    /// policy-seam.md §The action record: the substrate is a FLAT object whose command- and
    /// mcp-surface fields coexist under their own snake_case keys. Pin the field names and the
    /// flat shape so a rename or accidental nesting is caught.
    #[test]
    fn syntactic_substrate_is_flat_with_snake_case_field_names() {
        let s = SyntacticSubstrate {
            bin: Some("git".to_string()),
            argv: None,
            flags: None,
            positionals: None,
            cwd: None,
            host: None,
            env_refs: Some(vec!["AWS_PROFILE".to_string()]),
            server: Some("omnifocus".to_string()),
            tool: Some("delete_project".to_string()),
            params: Some(json!({ "list": "Agent Inbox" })),
            operation: Some("patch".to_string()),
            paths: Some(vec!["src/app.ts".to_string()]),
            diff_summary: Some("patch src/app.ts (+1 -1)".to_string()),
            diff_hash: Some("d".repeat(43)),
            raw: Some("git status".to_string()),
        };
        let val: Value = serde_json::to_value(&s).unwrap();

        // Flat: the command- and mcp-surface fields are siblings at the top level (no nesting).
        assert!(val.get("bin").is_some(), "command field `bin` is top-level");
        assert!(
            val.get("server").is_some() && val.get("tool").is_some(),
            "mcp fields `server`/`tool` coexist at the top level (flat substrate)"
        );
        assert!(
            val.get("operation").is_some()
                && val.get("paths").is_some()
                && val.get("diff_summary").is_some()
                && val.get("diff_hash").is_some(),
            "file-edit fields coexist at the top level (flat substrate)"
        );
        // snake_case key name, not `envRefs`/`env-refs`.
        assert_eq!(
            val.get("env_refs"),
            Some(&json!(["AWS_PROFILE"])),
            "env_refs must serialize under the snake_case key `env_refs`"
        );
        // `params` is preserved as a structured JSON value (policy-seam.md: params as raw/structured).
        assert_eq!(val["params"]["list"], json!("Agent Inbox"));
    }

    #[test]
    fn action_record_round_trip() {
        let orig = make_action_record();
        let json = serde_json::to_string(&orig).unwrap();
        let back: ActionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn actor_round_trip() {
        let orig = make_actor();
        let json = serde_json::to_string(&orig).unwrap();
        let back: Actor = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn actor_with_attestation_round_trip() {
        let orig = Actor {
            id: "machine:macbook-pro".to_string(),
            kind: "claude-code".to_string(),
            attestation: Some(vec![0xca, 0xfe, 0xba, 0xbe]),
        };
        let json = serde_json::to_string(&orig).unwrap();
        let back: Actor = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn constraints_round_trip() {
        let orig = make_constraints();
        let json = serde_json::to_string(&orig).unwrap();
        let back: Constraints = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn approval_request_round_trip() {
        let orig = make_approval_request();
        let json = serde_json::to_string(&orig).unwrap();
        let back: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn approval_context_round_trip() {
        let orig = make_approval_context();
        let json = serde_json::to_string(&orig).unwrap();
        let back: ApprovalContext = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    /// docs/contract.md §Messages → ApprovalRequest: the envelope is routing + lifecycle +
    /// the opaque ciphertext, nothing more. The human-facing fields and `request_hash` live
    /// in the (encrypted) [`ApprovalContext`] / [`Verdict`] respectively, NOT the envelope.
    #[test]
    fn approval_request_envelope_omits_context_and_request_hash_keys() {
        let req = make_approval_request();
        let val: Value = serde_json::to_value(&req).unwrap();

        // request_hash is computed over the ApprovalContext and carried in the Verdict, never
        // on the envelope (#28).
        assert!(
            val.get("request_hash").is_none(),
            "ApprovalRequest envelope must NOT carry request_hash (#28)"
        );
        // All human-facing context moved into the (encrypted) ApprovalContext.
        for forbidden in &[
            "action",
            "summary",
            "actor",
            "risk",
            "reversible",
            "constraints",
            "chain",
        ] {
            assert!(
                val.get(forbidden).is_none(),
                "ApprovalRequest envelope must NOT carry the context field \"{forbidden}\" (#28)"
            );
        }

        // It DOES carry exactly the routing/lifecycle keys.
        for required in &["v", "id", "created_at", "expires_at", "approver"] {
            assert!(
                val.get(required).is_some(),
                "ApprovalRequest envelope must carry the routing/lifecycle key \"{required}\""
            );
        }
    }

    /// docs/contract.md §Messages → ApprovalContext: `actor.attestation` and the reserved
    /// semantic `ActionRecord` fields are omitted from JSON when absent.
    #[test]
    fn approval_context_omits_attestation_and_reserved_fields_when_none() {
        let ctx = make_approval_context(); // actor.attestation: None, capabilities/scope: None
        let val: Value = serde_json::to_value(&ctx).unwrap();

        assert!(
            val["actor"].get("attestation").is_none(),
            "actor.attestation: None must be omitted from JSON"
        );
        assert!(
            val["action"].get("capabilities").is_none(),
            "ActionRecord.capabilities: None must be omitted from JSON (reserved T3 field)"
        );
        assert!(
            val["action"].get("scope").is_none(),
            "ActionRecord.scope: None must be omitted from JSON (reserved T3 field)"
        );
        // chain: None is omitted too.
        assert!(
            val.get("chain").is_none(),
            "ApprovalContext.chain: None must be omitted from JSON"
        );
    }

    #[test]
    fn verdict_round_trip() {
        let orig = make_verdict();
        let json = serde_json::to_string(&orig).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn policy_block_round_trip() {
        let orig = PolicyBlock {
            decision: PolicyDecision::Escalate,
            rule_id: None,
            tier: "syntactic".to_string(),
            schema_version: 1,
        };
        let json = serde_json::to_string(&orig).unwrap();
        let back: PolicyBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn audit_record_round_trip() {
        let orig = make_audit_record();
        let json = serde_json::to_string(&orig).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    // ── Structural JSON assertions: enum casing ────────────────────────────────

    /// docs/contract.md §Wire encoding + cross-cutting wire decision #1:
    /// all enum variants must serialize to snake_case strings.
    #[test]
    fn surface_mcp_tool_call_serializes_to_snake_case() {
        let v: Value = serde_json::to_value(Surface::McpToolCall).unwrap();
        assert_eq!(
            v,
            json!("mcp_tool_call"),
            "Surface::McpToolCall must serialize to \"mcp_tool_call\" (snake_case)"
        );
    }

    #[test]
    fn surface_command_serializes_to_snake_case() {
        let v: Value = serde_json::to_value(Surface::Command).unwrap();
        assert_eq!(v, json!("command"));
    }

    #[test]
    fn decision_variants_serialize_to_snake_case() {
        // contract.md §Wire encoding: Decision variants are snake_case
        assert_eq!(
            serde_json::to_value(Decision::Approved).unwrap(),
            json!("approved")
        );
        assert_eq!(
            serde_json::to_value(Decision::Denied).unwrap(),
            json!("denied")
        );
        assert_eq!(
            serde_json::to_value(Decision::Expired).unwrap(),
            json!("expired")
        );
        assert_eq!(
            serde_json::to_value(Decision::Aborted).unwrap(),
            json!("aborted")
        );
    }

    #[test]
    fn risk_variants_serialize_to_snake_case() {
        // contract.md §Wire encoding: Risk variants are snake_case
        assert_eq!(serde_json::to_value(Risk::Low).unwrap(), json!("low"));
        assert_eq!(serde_json::to_value(Risk::Medium).unwrap(), json!("medium"));
        assert_eq!(serde_json::to_value(Risk::High).unwrap(), json!("high"));
        assert_eq!(
            serde_json::to_value(Risk::Critical).unwrap(),
            json!("critical")
        );
    }

    #[test]
    fn policy_decision_variants_serialize_to_snake_case() {
        assert_eq!(
            serde_json::to_value(PolicyDecision::Allow).unwrap(),
            json!("allow")
        );
        assert_eq!(
            serde_json::to_value(PolicyDecision::Deny).unwrap(),
            json!("deny")
        );
        assert_eq!(
            serde_json::to_value(PolicyDecision::Escalate).unwrap(),
            json!("escalate")
        );
    }

    // ── Structural JSON assertions: binary field encoding ─────────────────────

    /// docs/contract.md §Wire encoding:
    /// Binary fields serialize as base64url-unpadded JSON strings (not byte arrays).
    /// For a 32-byte value the unpadded base64url encoding is exactly 43 characters.
    /// (`request_hash` now lives on the [`Verdict`], not the envelope — #28.)
    #[test]
    fn request_hash_serializes_as_base64url_string() {
        let verdict = make_verdict();
        let val: Value = serde_json::to_value(&verdict).unwrap();
        let encoded = val["request_hash"]
            .as_str()
            .expect("request_hash must be a JSON string, not an array");

        // 32 bytes → ceil(32*4/3) = 43 chars (unpadded)
        assert_eq!(
            encoded.len(),
            43,
            "base64url-unpadded encoding of 32 bytes must be 43 chars; got {}",
            encoded.len()
        );

        // Decode back and assert byte-equality
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let decoded: [u8; 32] = URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("must be valid base64url")
            .try_into()
            .expect("must be 32 bytes");
        assert_eq!(
            decoded, HASH_A,
            "decoded request_hash must equal original bytes"
        );
    }

    #[test]
    fn audit_prev_hash_serializes_as_base64url_string() {
        let rec = make_audit_record();
        let val: Value = serde_json::to_value(&rec).unwrap();
        let encoded = val["prev_hash"]
            .as_str()
            .expect("prev_hash must be a JSON string");

        assert_eq!(encoded.len(), 43);

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let decoded: [u8; 32] = URL_SAFE_NO_PAD.decode(encoded).unwrap().try_into().unwrap();
        assert_eq!(decoded, HASH_B);
    }

    // ── Structural JSON assertions: reserved semantic fields omitted ───────────

    /// docs/policy-seam.md §forward-compat req #3 + issue #1 AC:
    /// When capabilities and scope are None, they MUST be absent from JSON.
    #[test]
    fn action_record_omits_reserved_fields_when_none() {
        let action = make_action_record(); // capabilities: None, scope: None
        let val: Value = serde_json::to_value(&action).unwrap();

        assert!(
            val.get("capabilities").is_none(),
            "capabilities MUST be absent from JSON when None (policy-seam.md §forward-compat req #3)"
        );
        assert!(
            val.get("scope").is_none(),
            "scope MUST be absent from JSON when None (policy-seam.md §forward-compat req #3)"
        );
    }

    /// When capabilities is Some, the key MUST be present (proves T3 reserve round-trips).
    #[test]
    fn action_record_includes_capabilities_when_some() {
        let mut action = make_action_record();
        action.capabilities = Some(vec![json!({"name": "filesystem.write"})]);
        action.scope = Some(json!({"path": "/home/user/repo"}));

        let val: Value = serde_json::to_value(&action).unwrap();

        assert!(
            val.get("capabilities").is_some(),
            "capabilities must be present in JSON when Some"
        );
        assert!(
            val.get("scope").is_some(),
            "scope must be present in JSON when Some"
        );
    }

    // ── Structural JSON assertions: verdict scope-free invariant ──────────────

    /// docs/contract.md §Verdict: "No scope/reuse field — standing autonomy lives in the
    /// policy layer, not the verdict." Assert the serialized verdict has no such key.
    #[test]
    fn verdict_has_no_scope_or_reuse_field() {
        let verdict = make_verdict();
        let val: Value = serde_json::to_value(&verdict).unwrap();

        for forbidden in &["scope", "reuse", "standing", "autonomy", "ttl", "max_uses"] {
            assert!(
                val.get(forbidden).is_none(),
                "Verdict must not contain a \"{forbidden}\" field (one-shot scope-free invariant, \
                 docs/contract.md §Verdict)"
            );
        }
    }

    // ── Negative tests ────────────────────────────────────────────────────────

    /// A base64 string decoding to the wrong number of bytes must be rejected for [u8;32] fields.
    #[test]
    fn wrong_length_base64_rejected_for_hash_field() {
        // Encode 16 bytes (too short) as base64url and inject into a Verdict JSON
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let short: Vec<u8> = vec![0u8; 16];
        let short_b64 = URL_SAFE_NO_PAD.encode(&short);

        let bad_json = format!(
            r#"{{
                "v": 1,
                "request_id": "req_test",
                "request_hash": "{short_b64}",
                "decision": "approved",
                "decided_at": 1700000000000,
                "approver": {{"account_id": "acc_1", "device_id": "dev_1"}},
                "sig": "3q2-7w"
            }}"#
        );

        let result: Result<Verdict, _> = serde_json::from_str(&bad_json);
        assert!(
            result.is_err(),
            "Deserializing a [u8;32] field from a 16-byte base64 string must fail"
        );
    }

    /// Invalid base64 must also be rejected.
    #[test]
    fn invalid_base64_rejected_for_hash_field() {
        let bad_json = r#"{
            "v": 1,
            "request_id": "req_test",
            "request_hash": "not!valid+base64url@string==",
            "decision": "approved",
            "decided_at": 1700000000000,
            "approver": {"account_id": "acc_1", "device_id": "dev_1"},
            "sig": "3q2-7w"
        }"#;

        let result: Result<Verdict, _> = serde_json::from_str(bad_json);
        assert!(result.is_err(), "Invalid base64 must be rejected");
    }

    // ── Optional field omission ───────────────────────────────────────────────

    /// Optional None fields must be absent from JSON (not serialized as `null`).
    #[test]
    fn verdict_optional_none_fields_omitted() {
        let verdict = make_verdict(); // note: None, device_cert: None, challenge_response: None
        let val: Value = serde_json::to_value(&verdict).unwrap();

        assert!(
            val.get("note").is_none(),
            "note: None must be omitted from JSON"
        );
        assert!(
            val.get("device_cert").is_none(),
            "device_cert: None must be omitted from JSON"
        );
        assert!(
            val.get("challenge_response").is_none(),
            "challenge_response: None must be omitted from JSON"
        );
    }

    #[test]
    fn approval_request_optional_none_fields_omitted() {
        let req = make_approval_request(); // context_ciphertext: None
        let val: Value = serde_json::to_value(&req).unwrap();

        assert!(
            val.get("context_ciphertext").is_none(),
            "context_ciphertext: None must be omitted from JSON"
        );
    }

    // ── is_human_approved ─────────────────────────────────────────────────────

    #[test]
    fn is_human_approved_returns_true_only_for_approved() {
        // contract.md §Invariants #5: the primitive never returns "allow"; this is a read
        // of the human decision only, not authorization.
        let mut v = make_verdict();

        v.decision = Decision::Approved;
        assert!(v.is_human_approved());

        for non_approved in [Decision::Denied, Decision::Expired, Decision::Aborted] {
            v.decision = non_approved;
            assert!(
                !v.is_human_approved(),
                "{:?} must not be reported as approved",
                non_approved
            );
        }
    }
}
