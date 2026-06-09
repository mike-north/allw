//! WYSIWYS binding: canonical `request_hash` computation.
//!
//! The `request_hash` is a SHA-256 digest that binds a [`Verdict`] to the exact content the
//! human was shown in the approval inbox.  Both sides of the protocol compute the same value
//! independently:
//!
//! - The **integrator** computes it (via [`compute_request_hash`]) before sending the
//!   [`ApprovalRequest`] to the relay.
//! - The **device** recomputes it after decrypting the JWE context and before presenting the
//!   request to the human; the device then covers the hash in its [`Verdict`] signature.
//! - The **WASM binding** (issue #9) must reproduce the same bytes; the frozen cross-platform
//!   test vector anchors that requirement.
//!
//! # Recipe
//!
//! ```text
//! request_hash = SHA-256( b"allw/request-hash/v1" || 0x00 || JCS(subset) )
//! ```
//!
//! where `JCS(subset)` is the RFC 8785 JSON Canonicalization Scheme encoding of the
//! **human-shown content subset** (see below), and `0x00` is a single null byte that
//! separates the domain tag from the payload.
//!
//! # Hashed subset (human-shown content)
//!
//! Exactly four fields from the [`ApprovalRequest`] are bound:
//!
//! | Field | Why included |
//! |---|---|
//! | `action` | The full [`ActionRecord`] — what the human approved |
//! | `summary` | The human-readable description shown in the inbox |
//! | `actor.id`, `actor.kind` | Actor identity as shown — NOT `attestation` (that is for cryptographic verification, not display) |
//! | `expires_at` | The expiry time shown to the human |
//!
//! **`request_hash` is not the complete WYSIWYS binding on its own.** It binds the structured
//! [`ApprovalRequest`] fields above; the decrypted human-facing context is bound separately by the
//! audit record's `context_digest`. Whether `request_hash ∧ context_digest` is the full picture —
//! and exactly what is plaintext vs inside the E2EE envelope — is tracked in #28.
//!
//! # Excluded fields (and rationale)
//!
//! Everything else in [`ApprovalRequest`] is deliberately excluded:
//!
//! - **`request_hash` itself** — circular; cannot be included.
//! - **`context_ciphertext`** — AEAD-protected ciphertext; the plaintext is captured via the
//!   hashed subset above.  Including the ciphertext would break the invariant that device and
//!   integrator compute the same hash from the same plaintext.
//! - **`actor.attestation`** — used for cryptographic verification of actor identity, not shown
//!   to the human in the display.
//! - **`constraints`, `chain`** — policy/routing metadata, not content the human evaluates.
//! - **`request_id` / `id`** — correlation identifiers, not human-facing content.
//! - **`created_at`** — internal timestamp; the human sees `expires_at` (the deadline), not the
//!   creation time.
//! - **`approver`** — routing ID, not shown in the display.
//! - **Top-level `risk`, `reversible`** — echoed from `action.risk`; binding `action` already
//!   covers the risk and reversibility that affect the display.
//! - **`v`** — protocol version; a version change implies a new canonicalization version too
//!   (bump `DOMAIN_TAG`).
//!
//! # Domain tag and versioning
//!
//! `DOMAIN_TAG = b"allw/request-hash/v1"` provides cryptographic domain separation so this
//! hash cannot be confused with any other SHA-256 digest in the system.  Bumping `v1` → `v2`
//! is the version knob for the canonicalization: any change to the hashed subset, the JCS
//! encoding, or the recipe itself requires a domain-tag bump.
//!
//! # JCS crate
//!
//! Uses `serde_jcs` 0.2.x — RFC 8785 conformant, actively maintained.  The on-the-wire key
//! order is JCS-sorted (lexicographic by UTF-16 code unit), not the declaration order in the
//! Rust structs.  The canonical object passed to JCS has fixed keys
//! `{ "action", "actor", "expires_at", "summary" }` (ASCII, so UTF-16 sort = byte sort):
//! `action` < `actor` < `expires_at` < `summary`.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::contract::{ActionRecord, ApprovalRequest};

/// Domain separation tag — prefixed to the JCS bytes before hashing.
///
/// Bump to `allw/request-hash/v2` (etc.) whenever the hashed subset, encoding, or recipe
/// changes.  This tag is a version knob, not just a label.
const DOMAIN_TAG: &[u8] = b"allw/request-hash/v1";

/// Null-byte separator between domain tag and payload in the hash input.
const SEPARATOR: u8 = 0x00;

// ── Canonical helper struct ───────────────────────────────────────────────────

/// The human-shown content subset serialized for JCS canonicalization.
///
/// Field names are chosen so that JCS (lexicographic UTF-16 key sort) produces the order:
/// `action` < `actor` < `expires_at` < `summary`.
///
/// This type is private; the public API is [`compute_request_hash`] and
/// [`canonical_request_bytes`].
#[derive(Serialize)]
struct CanonicalSubset<'a> {
    action: &'a ActionRecord,
    actor: CanonicalActor<'a>,
    expires_at: i64,
    summary: &'a str,
}

/// The `{ id, kind }` projection of [`Actor`].
///
/// `attestation` is deliberately excluded — it is used for cryptographic verification of
/// actor identity, not for display.  JCS key order: `id` < `kind`.
///
/// [`Actor`]: crate::contract::Actor
#[derive(Serialize)]
struct CanonicalActor<'a> {
    id: &'a str,
    kind: &'a str,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Returns the RFC 8785 JCS canonical JSON bytes for the human-shown content subset of `req`.
///
/// This is the payload fed into the hash recipe *before* the domain tag and SHA-256 step.
/// Exposed publicly so:
/// - Tests can assert the canonicalization is spec-correct independently of the hash.
/// - The WASM binding (issue #9) can validate its own canonicalization against the Rust output.
/// - A cross-platform vector can be pinned in tests.
///
/// # Hashed fields
///
/// `action` (full [`ActionRecord`]), `actor.id`, `actor.kind`, `expires_at`, `summary`.
/// See the module doc for the full rationale and exclusion list.
///
/// # Key order (JCS / RFC 8785)
///
/// Top-level: `action` < `actor` < `expires_at` < `summary`.
/// Within `actor`: `id` < `kind`.
/// Within `action`: JCS-sorted (depends on [`ActionRecord`]'s field names).
///
/// # Panics
///
/// Panics only if JCS serialization of the contract types fails, which cannot happen for
/// well-formed in-memory values (the contract types always serialize). The hash is modeled as
/// infallible: [`compute_request_hash`] returns `[u8; 32]`, not a `Result`.
#[must_use]
pub fn canonical_request_bytes(req: &ApprovalRequest) -> Vec<u8> {
    let subset = CanonicalSubset {
        action: &req.action,
        actor: CanonicalActor {
            id: &req.actor.id,
            kind: &req.actor.kind,
        },
        expires_at: req.expires_at,
        summary: &req.summary,
    };
    // serde_jcs::to_vec implements RFC 8785 canonicalization; it sorts object keys
    // lexicographically by UTF-16 code unit and encodes floats per the JCS spec.
    serde_jcs::to_vec(&subset).expect(
        "canonical_request_bytes: JCS serialization must not fail for well-formed contract types",
    )
}

/// Computes the WYSIWYS `request_hash` for `req`.
///
/// # Recipe
///
/// ```text
/// request_hash = SHA-256( b"allw/request-hash/v1" || 0x00 || JCS(subset) )
/// ```
///
/// where `JCS(subset)` is the output of [`canonical_request_bytes`].
///
/// # Hashed fields
///
/// `action`, `actor.id`, `actor.kind`, `expires_at`, `summary`.  See module doc for the full
/// rationale and the excluded-fields list.
///
/// # Domain separation
///
/// `b"allw/request-hash/v1"` ensures this digest cannot collide with any other SHA-256 use in
/// the system.  Bumping the version suffix is the canonicalization version knob.
///
/// # Determinism
///
/// JCS guarantees a stable key order for the same input, so this function is pure and
/// deterministic: identical inputs always produce identical outputs.
#[must_use]
pub fn compute_request_hash(req: &ApprovalRequest) -> [u8; 32] {
    let canonical = canonical_request_bytes(req);
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG);
    hasher.update([SEPARATOR]);
    hasher.update(&canonical);
    hasher.finalize().into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        ActionRecord, Actor, ApprovalRequest, Constraints, Decision, Risk, Surface,
        SyntacticSubstrate,
    };
    use sha2::{Digest, Sha256};

    // ── Fixture helpers ───────────────────────────────────────────────────────

    // Fixed Unix millisecond timestamps — never SystemTime::now().
    // 2023-11-14T22:13:20Z
    const TS_CREATED: i64 = 1_700_000_000_000;
    // 2023-11-14T23:13:20Z (+1 hour)
    const TS_EXPIRES: i64 = 1_700_003_600_000;

    // Dummy [u8; 32] placeholder for request_hash in the ApprovalRequest fixture.
    // The hash field in ApprovalRequest is what we're *computing*, but the struct still
    // requires a value for the other fields; we use zeros as a placeholder.
    const PLACEHOLDER_HASH: [u8; 32] = [0u8; 32];

    /// Minimal action used for the canonicalization anchor test.
    ///
    /// Uses only `bin` and `raw` in the syntactic substrate so the hand-written JCS string
    /// remains tractable.  capabilities/scope are None (omitted from JSON per wire spec).
    fn make_minimal_action() -> ActionRecord {
        ActionRecord {
            record_schema_version: 1,
            surface: Surface::Command,
            syntactic: SyntacticSubstrate {
                bin: Some("git".to_string()),
                argv: None,
                flags: None,
                positionals: None,
                cwd: None,
                host: None,
                env_refs: None,
                server: None,
                tool: None,
                params: None,
                raw: Some("git push".to_string()),
            },
            risk: Risk::High,
            capabilities: None,
            scope: None,
        }
    }

    fn make_minimal_actor() -> Actor {
        Actor {
            id: "machine:x".to_string(),
            kind: "claude-code".to_string(),
            attestation: None,
        }
    }

    fn make_minimal_constraints() -> Constraints {
        Constraints {
            allowed_decisions: vec![Decision::Approved, Decision::Denied],
            challenge_required: false,
        }
    }

    /// The minimal fixture used for all canonicalization + hash vector tests.
    fn make_minimal_request() -> ApprovalRequest {
        ApprovalRequest {
            v: 1,
            id: "req_test_001".to_string(),
            created_at: TS_CREATED,
            expires_at: TS_EXPIRES,
            approver: "acc_test_001".to_string(),
            actor: make_minimal_actor(),
            action: make_minimal_action(),
            summary: "push to main".to_string(),
            risk: Risk::High,
            reversible: false,
            context_ciphertext: None,
            request_hash: PLACEHOLDER_HASH,
            constraints: make_minimal_constraints(),
            chain: None,
        }
    }

    // ── Test 1: Canonicalization is spec-correct (the anchor test) ────────────
    //
    // This expected string is derived BY HAND from RFC 8785 rules:
    //   - No whitespace
    //   - Object keys sorted lexicographically by UTF-16 code unit (= byte order for ASCII)
    //   - Numbers in shortest form
    //
    // Top-level keys (JCS order): "action" < "actor" < "expires_at" < "summary"
    //   (a-c-t-i < a-c-t-o; "e" < "s")
    //
    // action keys (JCS order):
    //   "record_schema_version" < "risk" < "surface" < "syntactic"
    //   (r-e < r-i; su-r < su-y)
    //
    // action.syntactic keys (JCS order, only bin+raw present):
    //   "bin" < "raw"
    //
    // actor keys (JCS order): "id" < "kind"
    //
    // action.risk = "high" (Risk::High serializes as "high" per snake_case)
    // action.surface = "command" (Surface::Command serializes as "command")
    const EXPECTED_CANONICAL: &str = concat!(
        r#"{"action":{"record_schema_version":1,"risk":"high","surface":"command","syntactic":{"bin":"git","raw":"git push"}},"#,
        r#""actor":{"id":"machine:x","kind":"claude-code"},"#,
        r#""expires_at":1700003600000,"#,
        r#""summary":"push to main"}"#
    );

    #[test]
    fn canonicalization_is_spec_correct() {
        // This test is the canonicalization anchor: it asserts the JCS output matches the
        // hand-derived expected string, proving the implementation is RFC 8785-correct
        // independent of the hash computation.
        let req = make_minimal_request();
        let canonical = canonical_request_bytes(&req);
        let canonical_str =
            std::str::from_utf8(&canonical).expect("JCS output must be valid UTF-8");

        assert_eq!(
            canonical_str,
            EXPECTED_CANONICAL,
            "canonical_request_bytes must produce RFC 8785 JCS output matching the hand-derived expected string"
        );
    }

    // ── Test 2: Hash = independent SHA-256 of the documented recipe ──────────
    //
    // Re-derives the documented recipe independently in the test body:
    //   SHA-256( b"allw/request-hash/v1" || 0x00 || canonical_request_bytes(req) )
    // This is NOT circular: it independently applies the domain-tag + hash recipe and
    // asserts equality with compute_request_hash, verifying the implementation matches
    // the documented algorithm.

    #[test]
    fn hash_matches_documented_recipe() {
        let req = make_minimal_request();

        // Re-derive the recipe directly in the test (not via compute_request_hash):
        let canonical = canonical_request_bytes(&req);
        let mut hasher = Sha256::new();
        hasher.update(b"allw/request-hash/v1"); // DOMAIN_TAG
        hasher.update([0x00u8]); // SEPARATOR
        hasher.update(&canonical);
        let expected: [u8; 32] = hasher.finalize().into();

        // Now assert compute_request_hash produces the same value:
        let actual = compute_request_hash(&req);
        assert_eq!(
            actual, expected,
            "compute_request_hash must equal SHA-256(DOMAIN_TAG || 0x00 || canonical_bytes)"
        );
    }

    // ── Test 3: Determinism ──────────────────────────────────────────────────

    #[test]
    fn hash_is_deterministic_across_calls() {
        let req = make_minimal_request();
        let h1 = compute_request_hash(&req);
        let h2 = compute_request_hash(&req);
        assert_eq!(h1, h2, "compute_request_hash must be deterministic");
    }

    #[test]
    fn hash_is_deterministic_for_clone() {
        let req = make_minimal_request();
        let req2 = req.clone();
        assert_eq!(
            compute_request_hash(&req),
            compute_request_hash(&req2),
            "cloned ApprovalRequest must hash identically"
        );
    }

    // ── Test 4: Sensitivity — each hashed field changes the hash ─────────────

    #[test]
    fn mutating_summary_changes_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.summary = "different summary".to_string();

        assert_ne!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating summary must change the request_hash"
        );
    }

    #[test]
    fn mutating_actor_id_changes_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.actor.id = "machine:different".to_string();

        assert_ne!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating actor.id must change the request_hash"
        );
    }

    #[test]
    fn mutating_actor_kind_changes_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.actor.kind = "different-kind".to_string();

        assert_ne!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating actor.kind must change the request_hash"
        );
    }

    #[test]
    fn mutating_expires_at_changes_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.expires_at = TS_EXPIRES + 1;

        assert_ne!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating expires_at must change the request_hash"
        );
    }

    #[test]
    fn mutating_action_bin_changes_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.action.syntactic.bin = Some("rm".to_string());

        assert_ne!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating action.syntactic.bin must change the request_hash"
        );
    }

    #[test]
    fn mutating_action_risk_changes_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.action.risk = Risk::Critical;

        assert_ne!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating action.risk must change the request_hash"
        );
    }

    // ── Test 5: Exclusion — excluded fields do NOT change the hash ───────────
    //
    // This is the critical WYSIWYS-scope test: it proves the hash binds exactly the
    // documented subset and nothing else.

    #[test]
    fn mutating_request_id_does_not_change_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.id = "req_different_id".to_string();

        assert_eq!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating request id must NOT change the request_hash (excluded field)"
        );
    }

    #[test]
    fn mutating_created_at_does_not_change_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.created_at = TS_CREATED + 999;

        assert_eq!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating created_at must NOT change the request_hash (excluded field)"
        );
    }

    #[test]
    fn mutating_approver_routing_id_does_not_change_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.approver = "acc_different".to_string();

        assert_eq!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating approver routing ID must NOT change the request_hash (excluded field)"
        );
    }

    #[test]
    fn mutating_reversible_does_not_change_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.reversible = !base.reversible;

        assert_eq!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating reversible must NOT change the request_hash (excluded field)"
        );
    }

    #[test]
    fn mutating_top_level_risk_does_not_change_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        // Top-level risk echoes action.risk; change only the top-level echo
        mutated.risk = Risk::Low;
        // Ensure action.risk is unchanged (so only the excluded field differs)
        assert_eq!(mutated.action.risk, Risk::High);

        assert_eq!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating top-level risk (echo field) must NOT change the request_hash (excluded field)"
        );
    }

    #[test]
    fn mutating_chain_does_not_change_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.chain = Some(vec!["upstream-gate-id-1".to_string()]);

        assert_eq!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating chain must NOT change the request_hash (excluded field)"
        );
    }

    #[test]
    fn mutating_context_ciphertext_does_not_change_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        mutated.context_ciphertext = Some("eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.fake".to_string());

        assert_eq!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating context_ciphertext must NOT change the request_hash (excluded field)"
        );
    }

    #[test]
    fn mutating_actor_attestation_does_not_change_hash() {
        let base = make_minimal_request();
        let base_hash = compute_request_hash(&base);

        let mut mutated = base.clone();
        // Add an attestation payload — this must not affect the hash
        mutated.actor.attestation = Some(vec![0xca, 0xfe, 0xba, 0xbe]);

        assert_eq!(
            compute_request_hash(&mutated),
            base_hash,
            "mutating actor.attestation must NOT change the request_hash (excluded per WYSIWYS design)"
        );
    }

    // ── Test 6: Frozen cross-platform vector ──────────────────────────────────
    //
    // Cross-platform parity anchor — the WASM binding (issue #9) must reproduce this exact
    // value.  If this test fails, the canonicalization changed and DOMAIN_TAG must be bumped
    // to reflect the new version.
    //
    // This value was derived AFTER tests 1 and 2 confirmed the canonicalization is
    // spec-correct and the hash recipe matches the documented algorithm — so this frozen
    // vector is anchored to a verified canonicalization, not an arbitrary snapshot.
    //
    // To regenerate: run `cargo test -p allw-core hash::tests::frozen_cross_platform_vector
    //   -- --nocapture` and capture the printed hex, then verify tests 1 & 2 still pass.

    /// Expected hex for the minimal fixture, computed once after tests 1+2 were green.
    ///
    /// Input:
    /// - DOMAIN_TAG: b"allw/request-hash/v1"
    /// - SEPARATOR: 0x00
    /// - canonical: (see EXPECTED_CANONICAL in this module)
    const FROZEN_HASH_HEX: &str =
        "bf3f3fcb56f5f4a4b26be9ee7f852b379d2b0a23ac8edf3cdaf5a8a1f6a9e2ff";

    #[test]
    fn frozen_cross_platform_vector() {
        let req = make_minimal_request();
        let hash = compute_request_hash(&req);

        // Encode as lowercase hex for a human-readable, portable comparison
        let hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();

        // Printed so `--nocapture` surfaces the value on SUCCESS too (used when regenerating the
        // vector); without this the hex only appears in the assertion message on failure.
        println!("frozen_cross_platform_vector: {hex}");

        assert_eq!(
            hex, FROZEN_HASH_HEX,
            "Cross-platform parity anchor failed. \
             If the canonicalization changed intentionally, bump DOMAIN_TAG and update FROZEN_HASH_HEX. \
             Got: {hex}"
        );
    }
}
