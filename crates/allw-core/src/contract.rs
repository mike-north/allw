//! Wire types for the approval contract. See `docs/contract.md`.

/// The interception paradigm an action arrived through.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// A shell command (with sub-paradigms: subcommand-tree, object-action, …).
    Command,
    /// An MCP tool call.
    McpToolCall,
    // Future: AgentToolCall, DelegatedFetch.
}

/// Coarse risk tier. v1: heuristic; later: capability-derived (policy-seam T3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

/// A reduced, matchable record of an approvable action.
///
/// v1 populates the syntactic substrate; the semantic `capabilities`/`scope` fields are
/// reserved for the policy layer's later semantic tier (T3). See `docs/policy-seam.md`.
#[derive(Debug, Clone)]
pub struct ActionRecord {
    /// Bumped only on a breaking change to the record shape.
    pub record_schema_version: u32,
    pub surface: Surface,
    /// Raw, structured syntactic form (tokenized command / MCP call).
    ///
    /// TODO: replace `String` with a structured, serde-backed type once wire types land.
    pub syntactic: String,
    pub risk: Risk,
    // Reserved (None in v1): capabilities, scope.
}

/// A request for a human decision on an [`ActionRecord`].
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub id: String,
    pub action: ActionRecord,
    /// Hash over the canonical plaintext the human will see (WYSIWYS binding).
    pub request_hash: [u8; 32],
    // TODO: actor attestation, approver routing, context ciphertext, timestamps, constraints.
}

/// The human's decision.
///
/// One-shot and scope-free — standing autonomy lives in the policy layer, never here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approved,
    Denied,
    Expired,
    Aborted,
}

/// A signed, verifiable verdict bound to a specific request.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub request_id: String,
    /// Echoes [`ApprovalRequest::request_hash`]; the signature covers it.
    pub request_hash: [u8; 32],
    pub decision: Decision,
    // TODO: decided_at, approver, note, challenge_response, signature, device_cert.
}

impl Verdict {
    /// Reports the human decision only.
    ///
    /// This is **not** authorization: the primitive never returns "allow". The integrator
    /// computes `allow = approved ∧ verified ∧ policy ∧ other_gates` — a verdict can only
    /// ever tighten, never loosen.
    #[must_use]
    pub fn is_human_approved(&self) -> bool {
        matches!(self.decision, Decision::Approved)
    }
}
