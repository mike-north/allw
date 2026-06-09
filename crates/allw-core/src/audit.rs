//! Append-only, hash-chained audit records. See `docs/contract.md`.
//!
//! # Design
//!
//! Every [`AuditRecord`] in the chain commits to its predecessor via `prev_hash`, creating
//! a tamper-evident singly-linked list of decisions.  [`AuditChain::verify`] detects any
//! **mid-chain** mutation, reordering, or middle-deletion — each breaks `record_hash` or the
//! `prev_hash` linkage.
//!
//! # What `verify()` does and does NOT catch
//!
//! `verify()` proves the chain it is given is **internally consistent**. It walks from `seq 0`,
//! so it **cannot detect tail truncation**: dropping the last N records leaves a shorter,
//! still-internally-consistent chain that verifies `Ok`. Detecting truncation (and rollback of
//! the whole log) requires comparing [`AuditChain::head_hash`] against an **externally anchored**
//! prior head — that is exactly what periodic head-hash anchoring is for. `verify()` is the
//! integrity check; the external anchor is the freshness/completeness check. The two are
//! complementary.
//!
//! # Record hash recipe
//!
//! ```text
//! record_hash = SHA-256( b"allw/audit-record/v1" || 0x00 || JCS(record_without_record_hash) )
//! ```
//!
//! - **JCS** — RFC 8785 JSON Canonicalization Scheme via `serde_jcs`.
//! - **Domain tag** `b"allw/audit-record/v1"` provides domain separation from every other
//!   SHA-256 use in the system (e.g. `b"allw/request-hash/v1"` in `hash.rs`).  The `/v1`
//!   suffix is the version knob — bump it if the hashed fields or recipe change.
//! - **`record_hash` is excluded** (circular; including it would make the hash impossible to
//!   compute).  Every other field is included — critically `prev_hash`, which is how each
//!   record commits to its predecessor.
//!
//! # `record_hash` exclusion mechanism
//!
//! To exclude only `record_hash` without a parallel "shadow" struct (which could drift from
//! [`AuditRecord`] silently), [`compute_record_hash`] serializes the full record to a
//! [`serde_json::Value`], removes the `"record_hash"` key, then passes the remainder through
//! `serde_jcs`.  This is the same Value-manipulation approach recommended for JOSE JWS payload
//! canonicalization when one field must be computed from the others.
//!
//! # Minor duplication with `hash.rs`
//!
//! The domain-tag + 0x00 + SHA-256 pattern appears in both this module and `hash.rs`.
//! The intentional repetition avoids coupling this PR to the hash module, and the domain tags
//! differ (so sharing code would require parameterisation that adds more complexity than it
//! saves).  A future refactor could unify both into a shared `canon::hash_with_tag` helper.
//!
//! # Genesis sentinel
//!
//! The first record has `prev_hash = GENESIS_PREV_HASH` (`[0u8; 32]`).  Any attempt to
//! forge a predecessor for the genesis record would require finding a SHA-256 preimage of the
//! all-zeros value, which is computationally infeasible.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::contract::{ActionRecord, Actor, Approver, AuditRecord, Decision, PolicyBlock};

/// The domain separation tag for audit record hashes.
///
/// Distinct from `b"allw/request-hash/v1"` in `hash.rs` — cryptographic domain separation
/// ensures these digests cannot collide with request hashes.  The `/v1` suffix is the
/// canonicalization version knob; bump it if the hashed fields or recipe change.
const AUDIT_DOMAIN_TAG: &[u8] = b"allw/audit-record/v1";

/// Null-byte separator between the domain tag and the JCS payload in the hash input.
const SEPARATOR: u8 = 0x00;

/// The `prev_hash` for the first record in a chain (sequence number 0).
///
/// All-zeros is the genesis sentinel.  Forging a predecessor would require finding a
/// SHA-256 preimage of this value, which is computationally infeasible.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

// ── Error type ────────────────────────────────────────────────────────────────

/// Error returned by [`AuditChain::verify`] when the chain is found to be invalid.
///
/// Each variant carries the `seq` of the offending record so the caller can locate the
/// tampered or corrupted entry.
#[derive(Debug, PartialEq, Eq)]
pub enum AuditChainError {
    /// The `seq` field of a record does not match the expected 0-based contiguous value.
    SeqMismatch {
        /// The seq value the record should have had.
        expected: u64,
        /// The seq value actually stored in the record.
        found: u64,
    },
    /// The `prev_hash` of a record does not match the `record_hash` of its predecessor
    /// (or the genesis sentinel for the first record).
    PrevHashMismatch {
        /// The seq of the record whose `prev_hash` is wrong.
        seq: u64,
    },
    /// The stored `record_hash` does not match the freshly recomputed hash of the record.
    RecordHashMismatch {
        /// The seq of the record whose `record_hash` is invalid.
        seq: u64,
    },
}

impl std::fmt::Display for AuditChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeqMismatch { expected, found } => {
                write!(
                    f,
                    "audit chain seq mismatch at expected seq {expected}: found {found}"
                )
            }
            Self::PrevHashMismatch { seq } => {
                write!(
                    f,
                    "audit chain prev_hash mismatch at seq {seq}: does not link to predecessor"
                )
            }
            Self::RecordHashMismatch { seq } => {
                write!(
                    f,
                    "audit chain record_hash mismatch at seq {seq}: stored hash does not match recomputed hash"
                )
            }
        }
    }
}

impl std::error::Error for AuditChainError {}

// ── AuditEntryInput ───────────────────────────────────────────────────────────

/// All fields needed to append a new record to an [`AuditChain`], excluding the
/// chain-managed fields (`seq`, `prev_hash`, `record_hash`) which the chain computes.
///
/// # `context_digest`
///
/// This field is the SHA-256 of the plaintext the human was shown (WYSIWYS).  **Deriving
/// it from the plaintext is the integrator's responsibility**, not this module's.  The chain
/// stores it opaquely for non-repudiation purposes.
pub struct AuditEntryInput {
    /// The [`ApprovalRequest`](crate::contract::ApprovalRequest) `id` this record covers.
    pub request_id: String,
    /// Echoes the WYSIWYS `request_hash` from the request.
    pub request_hash: [u8; 32],
    /// The automation that submitted the request.
    pub actor: Actor,
    /// The approver account and device that decided.
    pub approver: Approver,
    /// The human's decision.
    pub decision: Decision,
    /// Time of decision — Unix milliseconds (UTC).  Must be a fixed deterministic value;
    /// the caller is responsible for capturing the actual decision timestamp.
    pub decided_at: i64,
    /// The full action record (for audit completeness).
    pub action: ActionRecord,
    /// SHA-256 of the plaintext shown to the human.  Supplied by the integrator after
    /// decrypting the context; NOT derived here.
    pub context_digest: [u8; 32],
    /// Reserved policy block.  **v1 callers MUST set `decision: PolicyDecision::Escalate`** —
    /// the field is unconstrained at the type level so the T3 engine can later write
    /// `allow`/`deny`, but writing a non-`escalate` decision in v1 violates the pinned contract
    /// (`docs/policy-seam.md` §forward-compat req #4) and will mislead later policy analysis.
    pub policy: PolicyBlock,
    /// Optional free-form note from the approver.
    pub note: Option<String>,
    /// The verdict's device-key signature, carried into the audit record for non-repudiation.
    pub sig: Vec<u8>,
}

// ── AuditChain ────────────────────────────────────────────────────────────────

/// An append-only, hash-chained sequence of [`AuditRecord`]s.
///
/// # Invariants enforced
///
/// - `seq` is 0-based and contiguous.
/// - Each record's `prev_hash` links to the previous record's `record_hash` (or
///   [`GENESIS_PREV_HASH`] for the first record).
/// - Each record's `record_hash` equals `SHA-256(DOMAIN_TAG || 0x00 || JCS(record \ {record_hash}))`.
///
/// Call [`AuditChain::verify`] to re-validate the full chain at any time.
#[derive(Debug, Default)]
pub struct AuditChain {
    records: Vec<AuditRecord>,
}

impl AuditChain {
    /// Creates a new, empty audit chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Returns a slice of all records in the chain, oldest first.
    #[must_use]
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Returns the `record_hash` of the most recently appended record, or
    /// [`GENESIS_PREV_HASH`] if the chain is empty.
    ///
    /// Use this value for periodic anchoring (e.g. writing the head hash to an external
    /// notary or a distributed ledger) for non-repudiation.
    #[must_use]
    pub fn head_hash(&self) -> [u8; 32] {
        self.records
            .last()
            .map(|r| r.record_hash)
            .unwrap_or(GENESIS_PREV_HASH)
    }

    /// Appends a new record to the chain and returns a reference to it.
    ///
    /// The chain-managed fields are computed automatically:
    ///
    /// - `seq` = number of existing records (0 for the first append).
    /// - `prev_hash` = [`GENESIS_PREV_HASH`] if the chain was empty, otherwise the
    ///   `record_hash` of the current head.
    /// - `record_hash` = [`compute_record_hash`] of the completed record.
    pub fn append(&mut self, input: AuditEntryInput) -> &AuditRecord {
        let seq = self.records.len() as u64;
        let prev_hash = self.head_hash();

        // Build with a placeholder record_hash (all-zeros) so all other fields are fixed
        // before we compute the real hash.
        let mut record = AuditRecord {
            seq,
            prev_hash,
            record_hash: [0u8; 32],
            request_id: input.request_id,
            request_hash: input.request_hash,
            actor: input.actor,
            approver: input.approver,
            decision: input.decision,
            decided_at: input.decided_at,
            action: input.action,
            context_digest: input.context_digest,
            policy: input.policy,
            note: input.note,
            sig: input.sig,
        };

        // Compute the real record_hash and store it back.
        record.record_hash = compute_record_hash(&record);

        self.records.push(record);
        // SAFETY: we just pushed, so last() is always Some.
        self.records.last().unwrap()
    }

    /// Walks the chain and verifies all structural invariants.
    ///
    /// Checks for every record:
    ///
    /// 1. `seq` is 0-based and contiguous.
    /// 2. `prev_hash` links correctly to the predecessor's `record_hash` (or
    ///    [`GENESIS_PREV_HASH`] for seq 0).
    /// 3. The stored `record_hash` equals the freshly recomputed hash.
    ///
    /// Returns `Ok(())` if all records pass.  Returns the first [`AuditChainError`]
    /// encountered on failure.
    ///
    /// # Tamper evidence
    ///
    /// Because each record commits to `prev_hash`, even "re-signing" a tampered middle record
    /// (updating its own `record_hash`) leaves the next record's `prev_hash` stale, which
    /// [`PrevHashMismatch`][`AuditChainError::PrevHashMismatch`] will detect.
    ///
    /// # Limitation: tail truncation is NOT detected here
    ///
    /// `verify()` proves the chain it is given is internally consistent. A chain with the last
    /// N records **dropped** is still internally consistent, so it returns `Ok`. Detecting
    /// truncation (or whole-log rollback) requires comparing [`head_hash`](Self::head_hash)
    /// against an externally anchored prior head — see the module-level docs.
    pub fn verify(&self) -> Result<(), AuditChainError> {
        let mut expected_prev = GENESIS_PREV_HASH;

        for (idx, record) in self.records.iter().enumerate() {
            let expected_seq = idx as u64;

            // (1) seq contiguity
            if record.seq != expected_seq {
                return Err(AuditChainError::SeqMismatch {
                    expected: expected_seq,
                    found: record.seq,
                });
            }

            // (2) prev_hash linkage
            if record.prev_hash != expected_prev {
                return Err(AuditChainError::PrevHashMismatch { seq: record.seq });
            }

            // (3) record_hash self-consistency
            let recomputed = compute_record_hash(record);
            if record.record_hash != recomputed {
                return Err(AuditChainError::RecordHashMismatch { seq: record.seq });
            }

            expected_prev = record.record_hash;
        }

        Ok(())
    }
}

// ── Public hash API ───────────────────────────────────────────────────────────

/// Computes the tamper-evident self-hash for an [`AuditRecord`].
///
/// # Recipe
///
/// ```text
/// record_hash = SHA-256( b"allw/audit-record/v1" || 0x00 || JCS(record_without_record_hash) )
/// ```
///
/// # Exclusion of `record_hash`
///
/// The `"record_hash"` key is removed from the JSON [`Value`] representation before
/// JCS-canonicalization.  This is the only excluded field — every other field (including
/// `prev_hash`) is covered by the hash, ensuring chain linkage is tamper-evident.
///
/// The Value-key-removal approach avoids maintaining a parallel struct that could silently
/// drift from [`AuditRecord`]'s field set.
///
/// # Domain separation
///
/// `b"allw/audit-record/v1"` is distinct from `b"allw/request-hash/v1"` (in `hash.rs`),
/// ensuring audit record hashes cannot be confused with request hashes.
///
/// # Determinism
///
/// JCS guarantees stable key order for the same input; this function is pure and
/// deterministic: identical [`AuditRecord`]s produce identical hashes (regardless of the
/// stored `record_hash` value, since that field is excluded before hashing).
///
/// # Panics
///
/// Panics only if JCS serialization of a well-formed [`AuditRecord`] fails, which cannot
/// happen for in-memory values constructed through normal means.
#[must_use]
pub fn compute_record_hash(record: &AuditRecord) -> [u8; 32] {
    // Step 1: serialize the full record to a JSON Value.
    let mut value: Value = serde_json::to_value(record)
        .expect("compute_record_hash: AuditRecord must serialize to JSON");

    // Step 2: remove "record_hash" — it is circular and must be excluded.
    if let Value::Object(ref mut map) = value {
        map.remove("record_hash");
    }

    // Step 3: JCS-canonicalize the remaining object (RFC 8785).
    let canonical = serde_jcs::to_vec(&value)
        .expect("compute_record_hash: JCS serialization must not fail for well-formed Value");

    // Step 4: SHA-256( domain_tag || 0x00 || canonical )
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_DOMAIN_TAG);
    hasher.update([SEPARATOR]);
    hasher.update(&canonical);
    hasher.finalize().into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        ActionRecord, Actor, Approver, Decision, PolicyBlock, PolicyDecision, Risk, Surface,
        SyntacticSubstrate,
    };
    use sha2::{Digest, Sha256};

    // ── Fixed test fixtures ───────────────────────────────────────────────────
    //
    // All timestamps are deterministic i64 milliseconds — never SystemTime::now().
    // 2024-01-15T10:30:00.000Z
    const TS_DECIDED: i64 = 1_705_311_000_000;

    fn make_actor() -> Actor {
        Actor {
            id: "machine:test-macbook".to_string(),
            kind: "claude-code".to_string(),
            attestation: None,
        }
    }

    fn make_approver() -> Approver {
        Approver {
            account_id: "acc_test_01".to_string(),
            device_id: "dev_test_01".to_string(),
        }
    }

    fn make_action() -> ActionRecord {
        ActionRecord {
            record_schema_version: 1,
            surface: Surface::Command,
            syntactic: SyntacticSubstrate {
                bin: Some("git".to_string()),
                argv: Some(vec![
                    "git".to_string(),
                    "push".to_string(),
                    "--force".to_string(),
                ]),
                flags: Some(vec!["--force".to_string()]),
                positionals: Some(vec!["origin".to_string(), "main".to_string()]),
                cwd: Some("/repo".to_string()),
                host: None,
                env_refs: None,
                server: None,
                tool: None,
                params: None,
                raw: Some("git push --force".to_string()),
            },
            risk: Risk::High,
            capabilities: None,
            scope: None,
        }
    }

    fn make_policy() -> PolicyBlock {
        // docs/policy-seam.md §forward-compat req #4: v1 always writes escalate.
        PolicyBlock {
            decision: PolicyDecision::Escalate,
            rule_id: None,
            tier: "syntactic".to_string(),
            schema_version: 1,
        }
    }

    fn make_entry(request_id: &str) -> AuditEntryInput {
        AuditEntryInput {
            request_id: request_id.to_string(),
            request_hash: [0x11u8; 32],
            actor: make_actor(),
            approver: make_approver(),
            decision: Decision::Approved,
            decided_at: TS_DECIDED,
            action: make_action(),
            context_digest: [0x22u8; 32],
            policy: make_policy(),
            note: None,
            sig: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    // ── 1. Genesis correctness ─────────────────────────────────────────────────

    #[test]
    fn genesis_seq_is_zero() {
        let mut chain = AuditChain::new();
        let rec = chain.append(make_entry("req_001"));
        assert_eq!(rec.seq, 0, "first record must have seq == 0");
    }

    #[test]
    fn genesis_prev_hash_is_sentinel() {
        let mut chain = AuditChain::new();
        let rec = chain.append(make_entry("req_001"));
        assert_eq!(
            rec.prev_hash, GENESIS_PREV_HASH,
            "first record must have prev_hash == GENESIS_PREV_HASH ([0u8;32])"
        );
    }

    #[test]
    fn genesis_record_hash_is_non_zero() {
        let mut chain = AuditChain::new();
        let rec = chain.append(make_entry("req_001"));
        assert_ne!(
            rec.record_hash, [0u8; 32],
            "record_hash must be non-zero after append"
        );
    }

    #[test]
    fn head_hash_equals_genesis_record_hash() {
        let mut chain = AuditChain::new();
        let expected = chain.append(make_entry("req_001")).record_hash;
        assert_eq!(
            chain.head_hash(),
            expected,
            "head_hash() must equal the record_hash of the first appended record"
        );
    }

    #[test]
    fn empty_chain_head_hash_is_genesis_sentinel() {
        let chain = AuditChain::new();
        assert_eq!(
            chain.head_hash(),
            GENESIS_PREV_HASH,
            "head_hash() of an empty chain must be GENESIS_PREV_HASH"
        );
    }

    // ── 2. Linkage ────────────────────────────────────────────────────────────

    #[test]
    fn second_record_seq_is_one() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        let rec1 = chain.append(make_entry("req_002"));
        assert_eq!(rec1.seq, 1, "second record must have seq == 1");
    }

    #[test]
    fn second_record_prev_hash_equals_first_record_hash() {
        let mut chain = AuditChain::new();
        let first_hash = chain.append(make_entry("req_001")).record_hash;
        let rec1 = chain.append(make_entry("req_002"));
        assert_eq!(
            rec1.prev_hash, first_hash,
            "second record's prev_hash must equal first record's record_hash"
        );
    }

    // ── 3. record_hash excludes itself + matches documented recipe ─────────────
    //
    // This test independently re-derives the hash using the documented algorithm:
    //   1. Serialize record to serde_json::Value
    //   2. Remove "record_hash" key
    //   3. serde_jcs::to_vec (RFC 8785 JCS canonicalization)
    //   4. SHA-256( b"allw/audit-record/v1" || 0x00 || jcs )
    // and asserts equality with compute_record_hash.

    #[test]
    fn record_hash_matches_documented_recipe() {
        let mut chain = AuditChain::new();
        let rec = chain.append(make_entry("req_001")).clone();

        // Independently re-derive using the documented recipe (NOT calling compute_record_hash):
        let mut value: serde_json::Value = serde_json::to_value(&rec).unwrap();
        if let serde_json::Value::Object(ref mut map) = value {
            map.remove("record_hash");
        }
        let canonical = serde_jcs::to_vec(&value).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"allw/audit-record/v1"); // AUDIT_DOMAIN_TAG
        hasher.update([0x00u8]); // SEPARATOR
        hasher.update(&canonical);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(
            rec.record_hash, expected,
            "record_hash must equal SHA-256(b\"allw/audit-record/v1\" || 0x00 || JCS(record \\ {{record_hash}}))"
        );
    }

    /// Proves that `record_hash` is excluded from hashing: two records identical in every
    /// field except `record_hash` must produce the same `compute_record_hash` output.
    #[test]
    fn compute_record_hash_excludes_record_hash_field() {
        let mut chain = AuditChain::new();
        let mut rec = chain.append(make_entry("req_001")).clone();

        let original_hash = compute_record_hash(&rec);

        // Mutate record_hash — if the field were included in hashing, the result would differ.
        rec.record_hash = [0xffu8; 32];
        let after_mutation = compute_record_hash(&rec);

        assert_eq!(
            original_hash, after_mutation,
            "compute_record_hash must produce the same value regardless of the stored record_hash field"
        );
    }

    // ── 4. verify() accepts a well-formed chain ────────────────────────────────

    #[test]
    fn verify_accepts_well_formed_chain_of_three() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        chain.append(make_entry("req_002"));
        chain.append(make_entry("req_003"));

        assert!(
            chain.verify().is_ok(),
            "verify() must return Ok for a well-formed 3-record chain"
        );
    }

    #[test]
    fn verify_accepts_single_record_chain() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn verify_accepts_empty_chain() {
        let chain = AuditChain::new();
        assert!(chain.verify().is_ok(), "empty chain must verify Ok");
    }

    // ── 5. Tamper-evidence ─────────────────────────────────────────────────────

    /// Mutating a payload field WITHOUT recomputing record_hash → RecordHashMismatch.
    #[test]
    fn tamper_payload_field_detected_as_record_hash_mismatch() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        chain.append(make_entry("req_002"));
        chain.append(make_entry("req_003"));

        // Mutate the decision of the middle record (seq=1) without recomputing its record_hash.
        chain.records[1].decision = Decision::Denied;

        let err = chain.verify().unwrap_err();
        assert_eq!(
            err,
            AuditChainError::RecordHashMismatch { seq: 1 },
            "mutating a payload field must produce RecordHashMismatch at the tampered seq"
        );
    }

    /// Mutating context_digest WITHOUT recomputing record_hash → RecordHashMismatch.
    #[test]
    fn tamper_context_digest_detected_as_record_hash_mismatch() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        chain.append(make_entry("req_002"));

        chain.records[0].context_digest = [0xabu8; 32];

        let err = chain.verify().unwrap_err();
        assert_eq!(err, AuditChainError::RecordHashMismatch { seq: 0 });
    }

    /// Mutating action.risk WITHOUT recomputing record_hash → RecordHashMismatch.
    #[test]
    fn tamper_action_field_detected_as_record_hash_mismatch() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        chain.append(make_entry("req_002"));

        chain.records[1].action.risk = Risk::Critical;

        let err = chain.verify().unwrap_err();
        assert_eq!(err, AuditChainError::RecordHashMismatch { seq: 1 });
    }

    /// Mutating a record's prev_hash → PrevHashMismatch.
    #[test]
    fn tamper_prev_hash_detected_as_prev_hash_mismatch() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        chain.append(make_entry("req_002"));
        chain.append(make_entry("req_003"));

        // Corrupt the prev_hash of the second record (seq=1).
        chain.records[1].prev_hash = [0xffu8; 32];

        let err = chain.verify().unwrap_err();
        assert_eq!(
            err,
            AuditChainError::PrevHashMismatch { seq: 1 },
            "corrupted prev_hash must produce PrevHashMismatch at the corrupted seq"
        );
    }

    /// Corrupting seq to be non-contiguous → SeqMismatch.
    #[test]
    fn tamper_seq_detected_as_seq_mismatch() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        chain.append(make_entry("req_002"));
        chain.append(make_entry("req_003"));

        // Make seq=1 look like seq=5 (non-contiguous).
        chain.records[1].seq = 5;

        let err = chain.verify().unwrap_err();
        assert_eq!(
            err,
            AuditChainError::SeqMismatch {
                expected: 1,
                found: 5
            },
            "corrupted seq must produce SeqMismatch"
        );
    }

    /// Re-compute the tampered record's record_hash to "cover" the change, but DON'T fix
    /// the next record's prev_hash.  The NEXT record's prev_hash no longer matches the new
    /// (re-signed) hash → PrevHashMismatch at seq+1.
    ///
    /// This is the key chain-level tamper-evidence test: it proves that even a "clever"
    /// attacker who updates the tampered record's own hash cannot escape detection without
    /// also touching every subsequent record.
    #[test]
    fn re_signing_tampered_record_still_detected_via_chain_linkage() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        chain.append(make_entry("req_002"));
        chain.append(make_entry("req_003"));

        // Tamper with seq=1: mutate a field AND recompute its record_hash.
        chain.records[1].decision = Decision::Denied;
        chain.records[1].record_hash = compute_record_hash(&chain.records[1]);

        // seq=1 itself now passes RecordHashMismatch — BUT seq=2's prev_hash still points
        // to the *old* hash of seq=1, so PrevHashMismatch fires at seq=2.
        let err = chain.verify().unwrap_err();
        assert_eq!(
            err,
            AuditChainError::PrevHashMismatch { seq: 2 },
            "re-signing a tampered record must be detected at the NEXT record via PrevHashMismatch"
        );
    }

    // ── 5b. Truncation (NOT caught by verify) & reorder (caught) ────────────────

    /// Tail truncation is the documented limitation of `verify()`: dropping the last record
    /// leaves an internally-consistent chain that still verifies `Ok`. It is caught ONLY by
    /// comparing `head_hash()` to an externally anchored prior head. (module docs + verify docs)
    #[test]
    fn tail_truncation_passes_verify_but_changes_head_hash() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        chain.append(make_entry("req_002"));
        chain.append(make_entry("req_003"));

        // An external anchor captured when the chain had all 3 records.
        let anchor = chain.head_hash();

        // Drop the last record (tail truncation).
        chain.records.truncate(2);

        // verify() still passes — the shorter chain is internally consistent.
        assert!(
            chain.verify().is_ok(),
            "a truncated chain is internally consistent and verify() returns Ok"
        );

        // ...but the head no longer matches the anchor — THIS is how truncation is detected.
        assert_ne!(
            chain.head_hash(),
            anchor,
            "head_hash() must diverge from the prior anchor after truncation (anchor comparison \
             is the only truncation/rollback detector)"
        );
    }

    /// Swapping two adjacent records is detected: their `seq` fields move with them, so the
    /// contiguity check trips at the first out-of-order position.
    #[test]
    fn adjacent_reorder_detected_as_seq_mismatch() {
        let mut chain = AuditChain::new();
        chain.append(make_entry("req_001"));
        chain.append(make_entry("req_002"));
        chain.append(make_entry("req_003"));

        // Swap records at positions 1 and 2 (their seq fields, 1 and 2, swap with them).
        chain.records.swap(1, 2);

        // At index 1 the verifier expects seq 1 but finds the record carrying seq 2.
        let err = chain.verify().unwrap_err();
        assert_eq!(
            err,
            AuditChainError::SeqMismatch {
                expected: 1,
                found: 2
            },
            "an adjacent reorder must be detected (here via SeqMismatch at the first bad position)"
        );
    }

    // ── 6. Reserved policy block ───────────────────────────────────────────────
    //
    // docs/policy-seam.md §forward-compat req #4: the `policy` block must be present even
    // though v1 only writes `escalate`.  Assert the block serializes with the `policy` key
    // present and round-trips correctly.

    #[test]
    fn policy_block_present_in_serialized_record() {
        let mut chain = AuditChain::new();
        let rec = chain.append(make_entry("req_001"));
        let val: serde_json::Value = serde_json::to_value(rec).unwrap();

        assert!(
            val.get("policy").is_some(),
            "AuditRecord must include a 'policy' key in JSON (policy-seam.md §forward-compat req #4)"
        );
    }

    #[test]
    fn policy_block_decision_is_escalate_after_round_trip() {
        // docs/policy-seam.md §forward-compat req #4: v1 always writes escalate.
        let mut chain = AuditChain::new();
        let rec = chain.append(make_entry("req_001"));
        let json = serde_json::to_string(rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(
            back.policy.decision,
            PolicyDecision::Escalate,
            "policy.decision must round-trip as Escalate (policy-seam.md §forward-compat req #4)"
        );
    }

    // ── 7. Determinism ────────────────────────────────────────────────────────

    #[test]
    fn same_entry_on_two_fresh_chains_yields_identical_record_hash() {
        let entry1 = make_entry("req_001");
        let entry2 = make_entry("req_001");

        let mut chain1 = AuditChain::new();
        let hash1 = chain1.append(entry1).record_hash;

        let mut chain2 = AuditChain::new();
        let hash2 = chain2.append(entry2).record_hash;

        assert_eq!(
            hash1, hash2,
            "identical entries on fresh chains must produce identical record_hash (determinism)"
        );
    }
}
