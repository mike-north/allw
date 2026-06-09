//! WYSIWYS binding: canonical `request_hash` computation.
//!
//! The `request_hash` is a SHA-256 digest that binds a [`Verdict`] to the exact content the
//! human was shown in the approval inbox.  Both sides of the protocol compute the same value
//! independently:
//!
//! - The **integrator** computes it (via [`compute_request_hash`]) before sending the
//!   [`ApprovalRequest`] envelope to the relay.
//! - The **device** recomputes it after decrypting the JWE [`ApprovalContext`] and before
//!   presenting the request to the human; the device then covers the hash in its [`Verdict`]
//!   signature.
//! - The **WASM binding** (issue #9) must reproduce the same bytes; the frozen cross-platform
//!   test vector anchors that requirement.
//!
//! # Recipe
//!
//! ```text
//! request_hash = SHA-256( b"allw/request-hash/v2" || 0x00 || JCS(request-hash input) )
//! ```
//!
//! where `JCS(request-hash input)` is the RFC 8785 JSON Canonicalization Scheme encoding of the
//! **request-hash input** (see below), and `0x00` is a single null byte that separates the
//! domain tag from the payload.
//!
//! # Hashed input — the request-hash input (the complete WYSIWYS binding)
//!
//! The hashed object is **one flat JSON object** containing every [`ApprovalContext`] field
//! **plus** the envelope's `expires_at` as a sibling top-level key (NOT nested). This is the
//! complete human-shown payload, so `request_hash` alone is the full WYSIWYS binding — there is
//! **no separate `context_digest`** (resolved in #28).
//!
//! | Field | Why included |
//! |---|---|
//! | `action` | The full [`ActionRecord`] — what the human approved |
//! | `summary` | The human-readable description shown in the inbox |
//! | `actor.id`, `actor.kind` | Actor identity as shown — NOT `attestation` (that is for cryptographic verification, not display) |
//! | `risk` | The risk tier shown to the human |
//! | `reversible` | Whether the action is reversible, as shown |
//! | `constraints` | Allowed decisions + challenge policy the human acts under |
//! | `chain` | Upstream-gate ids (omitted entirely when absent) |
//! | `expires_at` | The deadline shown to the human (read from the envelope, bound here so a tampered deadline fails verification) |
//!
//! # Excluded fields (and rationale)
//!
//! - **`actor.attestation`** — a verification artifact the device checks separately, not shown
//!   content.
//! - **The envelope's other routing/lifecycle fields** (`id`, `created_at`, `approver`, `v`) and
//!   **`context_ciphertext`** — correlation/routing metadata and the opaque ciphertext, not
//!   human-shown content. (`id` is bound separately via the verdict's `request_id`, closing the
//!   no-swap gap — see [`crate::crypto::verify_verdict`].)
//!
//! # Domain tag and versioning
//!
//! `DOMAIN_TAG = b"allw/request-hash/v2"` provides cryptographic domain separation so this
//! hash cannot be confused with any other SHA-256 digest in the system.  The `/v2` suffix is the
//! version knob: the broadened input (every [`ApprovalContext`] field, not the four-field v1
//! subset) is a breaking change from `request-hash/v1`, so the tag bumps with it.
//!
//! # JCS crate
//!
//! Uses `serde_jcs` 0.2.x — RFC 8785 conformant, actively maintained.  The on-the-wire key
//! order is JCS-sorted (lexicographic by UTF-16 code unit), not the declaration order in the
//! Rust structs.  The canonical object's top-level keys (ASCII, so UTF-16 sort = byte sort) are:
//! `action` < `actor` < `chain` < `constraints` < `expires_at` < `reversible` < `risk` <
//! `summary`.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::contract::{ActionRecord, ApprovalContext, Constraints, Risk};

/// Domain separation tag — prefixed to the JCS bytes before hashing.
///
/// The `/v2` suffix is the version knob; it was bumped from `/v1` when the hashed input
/// broadened from the four-field subset to the full [`ApprovalContext`] (plus `expires_at`).
const DOMAIN_TAG: &[u8] = b"allw/request-hash/v2";

/// Null-byte separator between domain tag and payload in the hash input.
const SEPARATOR: u8 = 0x00;

// ── Canonical helper struct ───────────────────────────────────────────────────

/// The flat *request-hash input* serialized for JCS canonicalization.
///
/// Every [`ApprovalContext`] field plus the envelope's `expires_at`, as one flat object.
/// JCS re-sorts keys, so declaration order is irrelevant; the canonical (sorted) top-level
/// order is `action` < `actor` < `chain` < `constraints` < `expires_at` < `reversible` <
/// `risk` < `summary`.
///
/// This type is private; the public API is [`compute_request_hash`] and
/// [`canonical_request_bytes`].
#[derive(Serialize)]
struct CanonicalSubset<'a> {
    action: &'a ActionRecord,
    actor: CanonicalActor<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain: Option<&'a [String]>,
    constraints: &'a Constraints,
    expires_at: i64,
    reversible: bool,
    risk: Risk,
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

/// Returns the RFC 8785 JCS canonical JSON bytes for the *request-hash input* — the full
/// [`ApprovalContext`] `ctx` plus the envelope's `expires_at`, as one flat object.
///
/// This is the payload fed into the hash recipe *before* the domain tag and SHA-256 step.
/// Exposed publicly so:
/// - Tests can assert the canonicalization is spec-correct independently of the hash.
/// - The WASM binding (issue #9) can validate its own canonicalization against the Rust output.
/// - A cross-platform vector can be pinned in tests.
///
/// # Hashed fields
///
/// `action` (full [`ActionRecord`]), `actor.id`, `actor.kind`, `chain`, `constraints`,
/// `expires_at`, `reversible`, `risk`, `summary`. See the module doc for the full rationale and
/// exclusion list.
///
/// # Key order (JCS / RFC 8785)
///
/// Top-level: `action` < `actor` < `chain` < `constraints` < `expires_at` < `reversible` <
/// `risk` < `summary` (`chain` omitted entirely when `None`).
/// Within `actor`: `id` < `kind`.
/// Within `action` / `constraints`: JCS-sorted (depends on their field names).
///
/// # Panics
///
/// Panics only if JCS serialization of the contract types fails, which cannot happen for
/// well-formed in-memory values (the contract types always serialize). The hash is modeled as
/// infallible: [`compute_request_hash`] returns `[u8; 32]`, not a `Result`.
#[must_use]
pub fn canonical_request_bytes(ctx: &ApprovalContext, expires_at: i64) -> Vec<u8> {
    let subset = CanonicalSubset {
        action: &ctx.action,
        actor: CanonicalActor {
            id: &ctx.actor.id,
            kind: &ctx.actor.kind,
        },
        chain: ctx.chain.as_deref(),
        constraints: &ctx.constraints,
        expires_at,
        reversible: ctx.reversible,
        risk: ctx.risk,
        summary: &ctx.summary,
    };
    // serde_jcs::to_vec implements RFC 8785 canonicalization; it sorts object keys
    // lexicographically by UTF-16 code unit and encodes floats per the JCS spec.
    serde_jcs::to_vec(&subset).expect(
        "canonical_request_bytes: JCS serialization must not fail for well-formed contract types",
    )
}

/// Computes the WYSIWYS `request_hash` for the [`ApprovalContext`] `ctx` bound to `expires_at`.
///
/// # Recipe
///
/// ```text
/// request_hash = SHA-256( b"allw/request-hash/v2" || 0x00 || JCS(request-hash input) )
/// ```
///
/// where `JCS(request-hash input)` is the output of [`canonical_request_bytes`].
///
/// # Hashed fields
///
/// `action`, `actor.id`, `actor.kind`, `chain`, `constraints`, `expires_at`, `reversible`,
/// `risk`, `summary`.  See module doc for the full rationale and the excluded-fields list.
///
/// # Domain separation
///
/// `b"allw/request-hash/v2"` ensures this digest cannot collide with any other SHA-256 use in
/// the system.  Bumping the version suffix is the canonicalization version knob.
///
/// # Determinism
///
/// JCS guarantees a stable key order for the same input, so this function is pure and
/// deterministic: identical inputs always produce identical outputs.
#[must_use]
pub fn compute_request_hash(ctx: &ApprovalContext, expires_at: i64) -> [u8; 32] {
    let canonical = canonical_request_bytes(ctx, expires_at);
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
        ActionRecord, Actor, ApprovalContext, Constraints, Decision, Risk, Surface,
        SyntacticSubstrate,
    };
    use sha2::{Digest, Sha256};

    // ── Fixture helpers ───────────────────────────────────────────────────────

    // Fixed Unix millisecond timestamps — never SystemTime::now().
    // 2023-11-14T23:13:20Z
    const TS_EXPIRES: i64 = 1_700_003_600_000;

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

    /// The minimal [`ApprovalContext`] fixture used for all canonicalization + hash vector
    /// tests. Paired with [`TS_EXPIRES`] as the bound `expires_at`.
    fn make_minimal_context() -> ApprovalContext {
        ApprovalContext {
            action: make_minimal_action(),
            summary: "push to main".to_string(),
            actor: make_minimal_actor(),
            risk: Risk::High,
            reversible: false,
            constraints: make_minimal_constraints(),
            chain: None,
        }
    }

    // ── Test 1: Canonicalization is spec-correct (the anchor test) ────────────
    //
    // This expected string is derived BY HAND from RFC 8785 rules for the v2 flat object:
    //   - No whitespace
    //   - Object keys sorted lexicographically by UTF-16 code unit (= byte order for ASCII)
    //   - Numbers in shortest form
    //
    // Top-level keys (JCS order) — `chain` omitted (None in the fixture):
    //   "action" < "actor" < "constraints" < "expires_at" < "reversible" < "risk" < "summary"
    //   (a-c-t-i < a-c-t-o; "c" < "e" < "r"; "reversible" < "risk" since "re" < "ri";
    //    "ri" < "su")
    //
    // action keys (JCS order):
    //   "record_schema_version" < "risk" < "surface" < "syntactic"
    //   (r-e < r-i; su-r < su-y)
    // action.syntactic keys (JCS order, only bin+raw present): "bin" < "raw"
    // actor keys (JCS order): "id" < "kind"
    // constraints keys (JCS order): "allowed_decisions" < "challenge_required"
    //
    // Enum snake_case: Risk::High → "high"; Surface::Command → "command";
    //   Decision::{Approved,Denied} → "approved","denied".
    const EXPECTED_CANONICAL: &str = concat!(
        r#"{"action":{"record_schema_version":1,"risk":"high","surface":"command","syntactic":{"bin":"git","raw":"git push"}},"#,
        r#""actor":{"id":"machine:x","kind":"claude-code"},"#,
        r#""constraints":{"allowed_decisions":["approved","denied"],"challenge_required":false},"#,
        r#""expires_at":1700003600000,"#,
        r#""reversible":false,"#,
        r#""risk":"high","#,
        r#""summary":"push to main"}"#
    );

    #[test]
    fn canonicalization_is_spec_correct() {
        // This test is the canonicalization anchor: it asserts the JCS output matches the
        // hand-derived expected string, proving the implementation is RFC 8785-correct
        // independent of the hash computation.
        let ctx = make_minimal_context();
        let canonical = canonical_request_bytes(&ctx, TS_EXPIRES);
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
    //   SHA-256( b"allw/request-hash/v2" || 0x00 || canonical_request_bytes(&ctx, expires_at) )
    // This is NOT circular: it independently applies the domain-tag + hash recipe and
    // asserts equality with compute_request_hash, verifying the implementation matches
    // the documented algorithm.

    #[test]
    fn hash_matches_documented_recipe() {
        let ctx = make_minimal_context();

        // Re-derive the recipe directly in the test (not via compute_request_hash):
        let canonical = canonical_request_bytes(&ctx, TS_EXPIRES);
        let mut hasher = Sha256::new();
        hasher.update(b"allw/request-hash/v2"); // DOMAIN_TAG
        hasher.update([0x00u8]); // SEPARATOR
        hasher.update(&canonical);
        let expected: [u8; 32] = hasher.finalize().into();

        // Now assert compute_request_hash produces the same value:
        let actual = compute_request_hash(&ctx, TS_EXPIRES);
        assert_eq!(
            actual, expected,
            "compute_request_hash must equal SHA-256(DOMAIN_TAG || 0x00 || canonical_bytes)"
        );
    }

    // ── Test 3: Determinism ──────────────────────────────────────────────────

    #[test]
    fn hash_is_deterministic_across_calls() {
        let ctx = make_minimal_context();
        let h1 = compute_request_hash(&ctx, TS_EXPIRES);
        let h2 = compute_request_hash(&ctx, TS_EXPIRES);
        assert_eq!(h1, h2, "compute_request_hash must be deterministic");
    }

    #[test]
    fn hash_is_deterministic_for_clone() {
        let ctx = make_minimal_context();
        let ctx2 = ctx.clone();
        assert_eq!(
            compute_request_hash(&ctx, TS_EXPIRES),
            compute_request_hash(&ctx2, TS_EXPIRES),
            "cloned ApprovalContext must hash identically"
        );
    }

    // ── Test 4: Sensitivity — each hashed field changes the hash ─────────────
    //
    // The v2 request-hash input binds every ApprovalContext field plus expires_at, so each of
    // these mutations must perturb the hash (docs/contract.md §request_hash).

    #[test]
    fn mutating_summary_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.summary = "different summary".to_string();

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating summary must change the request_hash"
        );
    }

    #[test]
    fn mutating_actor_id_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.actor.id = "machine:different".to_string();

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating actor.id must change the request_hash"
        );
    }

    #[test]
    fn mutating_actor_kind_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.actor.kind = "different-kind".to_string();

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating actor.kind must change the request_hash"
        );
    }

    #[test]
    fn mutating_expires_at_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        assert_ne!(
            // Same context, different bound expires_at.
            compute_request_hash(&base, TS_EXPIRES + 1),
            base_hash,
            "mutating expires_at must change the request_hash"
        );
    }

    #[test]
    fn mutating_action_bin_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.action.syntactic.bin = Some("rm".to_string());

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating action.syntactic.bin must change the request_hash"
        );
    }

    #[test]
    fn mutating_action_risk_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.action.risk = Risk::Critical;

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating action.risk must change the request_hash"
        );
    }

    /// `risk` is now a top-level hashed field (v2), so mutating it must change the hash.
    #[test]
    fn mutating_top_level_risk_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.risk = Risk::Low;

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating risk must change the request_hash (now a v2 hashed field)"
        );
    }

    /// `reversible` is now a hashed field (v2), so mutating it must change the hash.
    #[test]
    fn mutating_reversible_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.reversible = !base.reversible;

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating reversible must change the request_hash (now a v2 hashed field)"
        );
    }

    /// `constraints` is now a hashed field (v2): flipping `challenge_required` must change it.
    #[test]
    fn mutating_constraints_challenge_required_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.constraints.challenge_required = !base.constraints.challenge_required;

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating constraints.challenge_required must change the request_hash (v2 hashed field)"
        );
    }

    /// `constraints.allowed_decisions` is hashed (v2): changing it must change the hash.
    #[test]
    fn mutating_constraints_allowed_decisions_changes_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.constraints.allowed_decisions = vec![Decision::Approved];

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating constraints.allowed_decisions must change the request_hash (v2 hashed field)"
        );
    }

    /// `chain` is now a hashed field (v2): going from absent to present must change the hash.
    #[test]
    fn adding_chain_changes_hash() {
        let base = make_minimal_context(); // chain: None
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.chain = Some(vec!["upstream-gate-id-1".to_string()]);

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "adding chain must change the request_hash (now a v2 hashed field)"
        );
    }

    /// Mutating the contents of an existing `chain` must also change the hash.
    #[test]
    fn mutating_chain_contents_changes_hash() {
        let mut base = make_minimal_context();
        base.chain = Some(vec!["gate-a".to_string()]);
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        mutated.chain = Some(vec!["gate-b".to_string()]);

        assert_ne!(
            compute_request_hash(&mutated, TS_EXPIRES),
            base_hash,
            "mutating chain contents must change the request_hash (v2 hashed field)"
        );
    }

    // ── Test 5: Exclusion — excluded fields do NOT change the hash ───────────
    //
    // This is the critical WYSIWYS-scope test: it proves the hash binds exactly the
    // documented input and nothing else. In v2 the only excluded ApprovalContext-adjacent
    // field is `actor.attestation` (a verification artifact, not shown content); the envelope's
    // routing/lifecycle fields are not part of the ApprovalContext at all and so cannot be
    // mutated here.

    #[test]
    fn mutating_actor_attestation_does_not_change_hash() {
        let base = make_minimal_context();
        let base_hash = compute_request_hash(&base, TS_EXPIRES);

        let mut mutated = base.clone();
        // Add an attestation payload — this must not affect the hash
        mutated.actor.attestation = Some(vec![0xca, 0xfe, 0xba, 0xbe]);

        assert_eq!(
            compute_request_hash(&mutated, TS_EXPIRES),
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
    /// - DOMAIN_TAG: b"allw/request-hash/v2"
    /// - SEPARATOR: 0x00
    /// - canonical: (see EXPECTED_CANONICAL in this module — the v2 flat object)
    const FROZEN_HASH_HEX: &str =
        "809fe4763353e8b10417f118581b510ebfe52b0725d35842f391f3d0c3d47be7";

    #[test]
    fn frozen_cross_platform_vector() {
        let ctx = make_minimal_context();
        let hash = compute_request_hash(&ctx, TS_EXPIRES);

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
