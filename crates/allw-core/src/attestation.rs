//! Actor-key **request attestation** — the *request side* of the trust model
//! (`docs/contract.md` §Invariants #4, §Identity & keys), distinct from verdict signing
//! ([`crate::crypto`], the *approver side*).
//!
//! # What an attestation is
//!
//! Each machine/agent (the **actor**) enrolls an Ed25519 keypair. When it requests approval it
//! signs a domain-tagged structure binding its identity to the **exact request** — concretely the
//! `request_id` ([`ApprovalRequest::id`]) and the `request_hash` the integrator computed over the
//! [`ApprovalContext`]. The signature rides in [`Actor::attestation`] (the reserved field), so
//! after decryption the approver's device can show a *cryptographically-verified* origin
//! ("Claude Code · macbook-pro") instead of spoofable plaintext.
//!
//! An attestation is **request-specific, not a reusable identity token**: it is bound to a single
//! `(request_id, request_hash)`, so it cannot be lifted off one request and replayed onto another.
//! This mirrors the verdict's WYSIWYS binding.
//!
//! # The trust anchor is **root-signed account state**, never the relay
//!
//! The actor's verifying key is *not* trusted because a relay listed it in `GET /actors`. The
//! device-facing entry point [`verify_actor_attestation_with_account_states`] resolves the actor
//! key from a **root-signed account-state document** ([`crate::crypto::AccountState`],
//! `docs/enrollment.md` §Account State): the key is trusted only because it appears, `active` and
//! un-revoked, inside an `allw-account-state+jws` the configured account root signed. A malicious
//! or compromised relay can substitute its own key for an actor id in `/actors`, but it cannot
//! author account state, so it can never drive a `✓ VERIFIED` render. This mirrors how verdict
//! verification chains a device key to the account root ([`crate::crypto::verify_verdict`]) and how
//! [`crate::crypto::verify_verdict_with_account_states`] enforces revocation.
//!
//! The lower-level [`verify_actor_attestation`] verifies an attestation against a *caller-supplied*
//! key; it performs no trust-anchoring and exists only so the account-state path (and tests) can
//! reuse the identical signature/identity/request-binding checks. Surfaces MUST call the
//! account-state-aware entry point.
//!
//! # Signing substrate: a domain-separated EdDSA compact JWS
//!
//! The attestation reuses the **same** hand-rolled EdDSA compact JWS path as verdicts and
//! device-certs ([`crate::crypto`]), with a third `typ` domain separator
//! (`allw-actor-attest+jws`). A compact JWS is three base64url-unpadded parts joined by `.`; the
//! Ed25519 signature covers the ASCII `b64url(header) || "." || b64url(payload)` signing input
//! (RFC 7515 §5.1, RFC 8037). The distinct `typ` means an actor attestation can never be accepted
//! where a verdict or device-cert is expected (or vice versa) — cross-protocol confusion is
//! rejected *before* the signature is even checked.
//!
//! ## Why the JWS string lives in `Actor.attestation: Option<Vec<u8>>`
//!
//! The wire field is `Option<Vec<u8>>` (base64url on the wire — see [`Actor`]). We store the
//! **UTF-8 bytes of the compact JWS string** there. This keeps the contract type untouched while
//! reusing the audited JWS machinery: [`sign_actor_attestation`] produces the bytes,
//! [`verify_actor_attestation`] reads them back, re-parses the compact JWS, and verifies it.
//!
//! # Signed claims — bound to `(account_id, actor_id, actor_kind, request_id, request_hash)`
//!
//! The payload is [`ActorAttestationClaims`]: the `account_id`, the actor's `actor_id`/`actor_kind`,
//! the `request_id`, and the 32-byte `request_hash`. Verification cross-checks the signed
//! `actor_id`/`actor_kind` against the *outer* [`Actor`] the device is about to render (so a
//! tampered plaintext `Actor.id` is detected as a mismatch), the signed `account_id` against the
//! account the device trusts, and the `request_id`/`request_hash` against the values the device
//! recomputed.
//!
//! ## Why bind BOTH `request_id` and `request_hash`
//!
//! `request_hash` deliberately excludes `request_id` (`hash.rs` — it covers only the human-shown
//! content + `expires_at`), so two content-identical requests with *different* ids share one hash.
//! Binding `request_id` too closes the cross-request "no swap" gap the verdict path already closes
//! with its own id+hash binding — an attestation minted for one request cannot be lifted onto a
//! content-identical sibling with a different id.
//!
//! # The `request_hash` is excluded from itself
//!
//! `actor.attestation` is **excluded** from `request_hash` (`hash.rs` — it is a verification
//! artifact, not shown content), so adding/altering the attestation never perturbs the WYSIWYS
//! hash. The attestation binds *to* the hash; it is not bound *by* it. The two are verified
//! separately.
//!
//! # Fail-closed
//!
//! Every path returns `Err` on any failure (`docs/contract.md` §Invariants #6): a missing
//! attestation, a malformed JWS, the wrong `typ`, a signature that does not verify under the
//! enrolled actor key, an account/id/kind that disagrees with the request, a `request_id` or
//! `request_hash` that does not bind the request, an actor absent from (or revoked/inactive in)
//! root-signed account state, or an unverifiable account-state document. There is no permissive
//! default — an unverifiable origin is treated exactly like a forged one.
//!
//! [`ApprovalRequest::id`]: crate::contract::ApprovalRequest::id
//! [`ApprovalContext`]: crate::contract::ApprovalContext

use serde::{Deserialize, Serialize};

use crate::contract::Actor;
use crate::crypto::{
    decode_and_verify_jws, encode_compact_jws, verify_account_state, AccountStateError,
    AccountStateRevocationKind, JwsError, JwsHeader, PublicKey, SigningKeyPair, ALG_EDDSA,
};

/// Schema version of the actor-attestation payload (`docs/enrollment.md` §Actor-Key Enrollment).
const ATTESTATION_V: u32 = 1;

/// `typ` header value for an **actor attestation** JWS (signed by an enrolled actor key).
///
/// Distinct from the verdict (`allw-verdict+jws`), device-cert (`allw-device-cert+jws`), and
/// account-state (`allw-account-state+jws`) `typ`s, so the artifacts can never be confused for one
/// another across the protocol.
pub(crate) const TYP_ACTOR_ATTEST: &str = "allw-actor-attest+jws";

/// The signed claims inside an actor-attestation JWS — the bytes the actor key authenticates.
///
/// Binds the actor's identity (`account_id`, `actor_id`, `actor_kind`) to the **exact request**
/// (`request_id` + `request_hash`). [`verify_actor_attestation`] cross-checks `actor_id`/`actor_kind`
/// against the outer [`Actor`], `account_id` against the trusted account, and `request_id` /
/// `request_hash` against the device-recomputed values.
///
/// `request_hash` serializes as a base64url-unpadded string (JOSE-consistent with the rest of the
/// wire format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorAttestationClaims {
    /// Schema version of the attestation payload (`docs/enrollment.md`).
    pub v: u32,

    /// The account this actor belongs to (binds the attestation to the account namespace, so an
    /// attestation cannot cross account trust domains).
    pub account_id: String,

    /// The attesting actor's stable identity (echoes [`Actor::id`]).
    pub actor_id: String,

    /// The attesting actor's kind (echoes [`Actor::kind`]).
    pub actor_kind: String,

    /// The exact request this attestation answers — equals [`ApprovalRequest::id`]. Bound
    /// separately from `request_hash` (which excludes the id) to stop a lift onto a
    /// content-identical request with a different id (the cross-request "no swap" gap).
    ///
    /// [`ApprovalRequest::id`]: crate::contract::ApprovalRequest::id
    pub request_id: String,

    /// The request this attestation is bound to — the WYSIWYS `request_hash` the integrator
    /// computed over the [`ApprovalContext`](crate::contract::ApprovalContext) (`hash.rs`).
    #[serde(with = "b64_32")]
    pub request_hash: [u8; 32],
}

/// `[u8; 32]` ↔ base64url-unpadded string (local to this module; mirrors the helper in
/// `crypto.rs`).
mod b64_32 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD.decode(&s).map_err(D::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected exactly 32 bytes after base64url decode"))
    }
}

// ── Signing API ────────────────────────────────────────────────────────────────────

/// Signs an actor attestation: builds the [`ActorAttestationClaims`] from the actor identity, the
/// account, the request id, and the request's `request_hash`, encodes+signs an EdDSA compact JWS
/// with the **actor** key, and returns the compact JWS as **UTF-8 bytes** — the value to store in
/// [`Actor::attestation`].
///
/// The JWS header `kid` is the `actor_id` (so the signed key id and the claimed actor id cannot
/// diverge), `typ` is [`TYP_ACTOR_ATTEST`], and `alg` is `EdDSA`.
///
/// # Production key custody
///
/// In production the actor key is hardware-/enrollment-backed and never exposes its seed; the
/// [`SigningKeyPair::from_seed`] used to obtain `actor_key` here is the v1/testing stand-in (see
/// its docs). The wire format does not depend on key custody.
#[must_use]
pub fn sign_actor_attestation(
    account_id: &str,
    actor_id: &str,
    actor_kind: &str,
    request_id: &str,
    request_hash: &[u8; 32],
    actor_key: &SigningKeyPair,
) -> Vec<u8> {
    let claims = ActorAttestationClaims {
        v: ATTESTATION_V,
        account_id: account_id.to_string(),
        actor_id: actor_id.to_string(),
        actor_kind: actor_kind.to_string(),
        request_id: request_id.to_string(),
        request_hash: *request_hash,
    };

    let header = JwsHeader {
        alg: ALG_EDDSA.to_string(),
        typ: TYP_ACTOR_ATTEST.to_string(),
        kid: actor_id.to_string(),
    };

    // The compact JWS is an ASCII string; its UTF-8 bytes are what ride in `Actor.attestation`.
    encode_compact_jws(&header, &claims, actor_key).into_bytes()
}

// ── Verification ──────────────────────────────────────────────────────────────────

/// Why an actor attestation failed verification. Every variant is a **deny** (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The outer [`Actor`] carried no `attestation` — origin is unverifiable (spoofable plaintext).
    Missing,
    /// The attestation bytes were not valid UTF-8 (a compact JWS is an ASCII string).
    NotUtf8,
    /// The compact JWS was structurally malformed, or its `typ`/`alg` was wrong (e.g. a verdict or
    /// device-cert JWS presented as an attestation).
    MalformedJws,
    /// The JWS signature did not verify under the root-anchored actor public key.
    SignatureInvalid,
    /// The signed `kid` did not name the claimed `actor_id` (key-id/identity confusion).
    KidMismatch,
    /// The attestation schema version was not supported.
    UnsupportedVersion,
    /// The signed `account_id` did not match the account the device trusts (cross-account lift).
    AccountMismatch,
    /// The signed `actor_id` did not match the outer [`Actor::id`] the device is rendering
    /// (a spoofed plaintext id over a signature for a different actor).
    ActorIdMismatch,
    /// The signed `actor_kind` did not match the outer [`Actor::kind`].
    ActorKindMismatch,
    /// The signed `request_id` did not match the request the device is rendering — the attestation
    /// was lifted onto a (possibly content-identical) sibling request with a different id.
    RequestIdMismatch,
    /// The signed `request_hash` did not bind the request the device recomputed — the attestation
    /// was lifted from a different request (or the request was tampered).
    RequestHashMismatch,
    /// No root-signed account-state document trusted the actor's key (the actor is not enrolled in
    /// account state, so its origin cannot be root-anchored).
    ActorNotEnrolled,
    /// The actor was present in account state but `inactive` or explicitly revoked — fail-closed.
    ActorRevoked,
    /// A supplied account-state document did not verify against the configured account root.
    AccountStateInvalid,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Missing => "actor attestation is absent (origin is unverifiable plaintext)",
            Self::NotUtf8 => "actor attestation bytes are not valid UTF-8 (expected a compact JWS)",
            Self::MalformedJws => "actor attestation JWS is malformed or has the wrong typ/alg",
            Self::SignatureInvalid => {
                "actor attestation signature did not verify under the root-anchored actor key"
            }
            Self::KidMismatch => "actor attestation JWS kid does not match the signed actor_id",
            Self::UnsupportedVersion => "actor attestation schema version is not supported",
            Self::AccountMismatch => {
                "actor attestation account_id does not match the trusted account"
            }
            Self::ActorIdMismatch => {
                "actor attestation actor_id does not match the rendered actor identity"
            }
            Self::ActorKindMismatch => {
                "actor attestation actor_kind does not match the rendered actor identity"
            }
            Self::RequestIdMismatch => {
                "actor attestation request_id does not match this request (lifted onto another request)"
            }
            Self::RequestHashMismatch => {
                "actor attestation request_hash does not bind this request (lifted/replayed origin)"
            }
            Self::ActorNotEnrolled => {
                "actor is not enrolled in root-signed account state (origin is not root-anchored)"
            }
            Self::ActorRevoked => "actor is revoked or inactive in account state (fail-closed)",
            Self::AccountStateInvalid => {
                "an account-state document did not verify against the configured account root"
            }
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for AttestationError {}

/// Verifies the attestation carried by `actor`, anchoring the actor's key in **root-signed account
/// state** — the device-facing entry point (`docs/enrollment.md` §Account State, §Actor-Key
/// Enrollment).
///
/// This is the function surfaces (the approver/inbox) MUST call to display a `✓ VERIFIED` origin.
/// The actor key is resolved from the highest valid-sequence account-state document the configured
/// account root signed; a relay-supplied `/actors` key NEVER drives a verified origin.
///
/// Returns `Ok(())` only when the attestation is *present, authentic, identity-consistent,
/// request-bound, and root-anchored to an active actor*; **any** failure returns `Err`
/// (fail-closed). The steps:
///
/// 1. **Resolve the trust-anchored key.** Each `account_state` JWS is verified against
///    `account_root` for `account_id` ([`AttestationError::AccountStateInvalid`]); the actor's key
///    is taken from the **highest `sequence`** document, requiring an `active` actor entry that is
///    not revoked ([`AttestationError::ActorNotEnrolled`] / [`AttestationError::ActorRevoked`]).
/// 2. **Signature + identity + request binding.** The attestation is then checked exactly as
///    [`verify_actor_attestation`] does against that root-anchored key.
///
/// # Not authorization
///
/// A successful return means the **origin** is cryptographically verified and root-anchored. It is
/// not, by itself, an approval — the human still decides, and the integrator still composes the
/// final gate ([`crate::crypto::effective_allow`]). A verified origin only lets the inbox render a
/// trusted "who" instead of `⚠ UNVERIFIED`.
///
/// # Errors
///
/// Returns the [`AttestationError`] for the first failing step (see the step list above).
pub fn verify_actor_attestation_with_account_states(
    actor: &Actor,
    account_id: &str,
    request_id: &str,
    request_hash: &[u8; 32],
    account_states: &[&str],
    account_root: &PublicKey,
) -> Result<(), AttestationError> {
    let actor_pubkey =
        resolve_root_anchored_actor_key(actor, account_id, account_states, account_root)?;
    verify_actor_attestation(actor, account_id, request_id, request_hash, &actor_pubkey)
}

/// Resolves the actor's verifying key from the highest valid-sequence root-signed account-state
/// document, fail-closed.
///
/// Mirrors [`crate::crypto::verify_verdict_with_account_states`]'s revocation handling: every
/// document is verified against `account_root`; the actor record is read from the **highest
/// `sequence`** document; same-sequence conflicts fail closed (any one that revokes / marks the
/// actor inactive wins). Returns:
///
/// - [`AttestationError::AccountStateInvalid`] if any document fails to verify;
/// - [`AttestationError::ActorRevoked`] if the highest sequence revokes the actor or its entry is
///   not `active`;
/// - [`AttestationError::ActorNotEnrolled`] if no account state contains the actor.
fn resolve_root_anchored_actor_key(
    actor: &Actor,
    account_id: &str,
    account_states: &[&str],
    account_root: &PublicKey,
) -> Result<PublicKey, AttestationError> {
    let mut best: Option<(u64, Option<[u8; 32]>, bool)> = None;

    for compact in account_states {
        let state = verify_account_state(compact, account_id, account_root)
            .map_err(map_account_state_error)?;

        // Does this document revoke the actor outright?
        let revoked_here = state
            .revocations
            .iter()
            .any(|r| r.kind == AccountStateRevocationKind::Actor && r.id == actor.id);

        // The actor's key in this document, only when present AND active.
        let active_key = state
            .actors
            .iter()
            .find(|a| a.actor_id == actor.id)
            .and_then(|a| {
                if a.status == "active" {
                    Some(a.pubkey)
                } else {
                    None
                }
            });
        // An inactive (present-but-not-active) entry is a fail-closed revocation signal too.
        let inactive_here = state
            .actors
            .iter()
            .any(|a| a.actor_id == actor.id && a.status != "active");
        let revoked_or_inactive = revoked_here || inactive_here;

        match best {
            None => best = Some((state.sequence, active_key, revoked_or_inactive)),
            Some((seq, _, _)) if state.sequence > seq => {
                best = Some((state.sequence, active_key, revoked_or_inactive));
            }
            Some((seq, ref mut key, ref mut revoked)) if state.sequence == seq => {
                // Same-sequence conflicts are fail-closed: a revocation anywhere at the highest
                // sequence wins; an active key is only kept if none of them revoke.
                if active_key.is_some() && key.is_none() {
                    *key = active_key;
                }
                *revoked = *revoked || revoked_or_inactive;
            }
            Some(_) => {}
        }
    }

    match best {
        // The highest-sequence state revokes / deactivates the actor → fail closed.
        Some((_, _, true)) => Err(AttestationError::ActorRevoked),
        // An active, root-anchored key at the highest sequence.
        Some((_, Some(key_bytes), false)) => {
            PublicKey::from_bytes(&key_bytes).map_err(|_| AttestationError::ActorNotEnrolled)
        }
        // No active actor entry anywhere (or no account state at all).
        Some((_, None, false)) | None => Err(AttestationError::ActorNotEnrolled),
    }
}

/// Maps an account-state verification failure to the attestation's fail-closed error.
fn map_account_state_error(_e: AccountStateError) -> AttestationError {
    AttestationError::AccountStateInvalid
}

/// Verifies the attestation carried by `actor` against a **caller-supplied** `actor_pubkey`,
/// binding it to `account_id`, `request_id`, and `request_hash`.
///
/// This is the lower-level check: it performs **no trust-anchoring** of `actor_pubkey`. Surfaces
/// must instead call [`verify_actor_attestation_with_account_states`], which resolves the key from
/// root-signed account state. This function exists so that path (and tests) can reuse the identical
/// signature/identity/request-binding logic against an already-trusted key.
///
/// Returns `Ok(())` only when the attestation is *present, authentic, identity-consistent, and
/// request-bound*; **any** failure returns `Err` (fail-closed, `docs/contract.md` §Invariants #6).
/// The steps:
///
/// 1. **Present.** `actor.attestation` must be `Some` ([`AttestationError::Missing`]).
/// 2. **Compact JWS, right kind.** The bytes must be UTF-8 ([`AttestationError::NotUtf8`]) and a
///    well-formed EdDSA compact JWS with `typ == allw-actor-attest+jws`
///    ([`AttestationError::MalformedJws`]).
/// 3. **Signature.** It must verify under `actor_pubkey` ([`AttestationError::SignatureInvalid`]).
/// 4. **Identity binding.** The signed `kid` must equal the signed `actor_id`
///    ([`AttestationError::KidMismatch`]); the schema `v` must be supported
///    ([`AttestationError::UnsupportedVersion`]); the signed `account_id` must equal `account_id`
///    ([`AttestationError::AccountMismatch`]); the signed `actor_id`/`actor_kind` must equal the
///    outer [`Actor::id`]/[`Actor::kind`] ([`AttestationError::ActorIdMismatch`] /
///    [`AttestationError::ActorKindMismatch`]).
/// 5. **Request binding.** The signed `request_id` must equal `request_id`
///    ([`AttestationError::RequestIdMismatch`]) AND the signed `request_hash` must equal
///    `request_hash` ([`AttestationError::RequestHashMismatch`]) — binding both closes the
///    cross-request no-swap gap.
///
/// # Errors
///
/// Returns the [`AttestationError`] for the first failing step (see the step list above).
pub fn verify_actor_attestation(
    actor: &Actor,
    account_id: &str,
    request_id: &str,
    request_hash: &[u8; 32],
    actor_pubkey: &PublicKey,
) -> Result<(), AttestationError> {
    // ── Step 1: present ──────────────────────────────────────────────────────────
    let bytes = actor
        .attestation
        .as_deref()
        .ok_or(AttestationError::Missing)?;

    // ── Step 2: UTF-8 compact JWS with the actor-attestation typ ────────────────
    let compact = std::str::from_utf8(bytes).map_err(|_| AttestationError::NotUtf8)?;
    let decoded =
        decode_and_verify_jws::<ActorAttestationClaims>(compact, TYP_ACTOR_ATTEST, actor_pubkey)
            // ── Step 3 is folded into decode_and_verify_jws (it verifies the signature) ──
            .map_err(|e| match e {
                JwsError::BadSignature => AttestationError::SignatureInvalid,
                _ => AttestationError::MalformedJws,
            })?;

    let claims = &decoded.claims;

    // ── Step 4: identity binding ────────────────────────────────────────────────
    // The signed kid must name the same actor the claims do (no key-id/identity split).
    if decoded.header.kid != claims.actor_id {
        return Err(AttestationError::KidMismatch);
    }
    if claims.v != ATTESTATION_V {
        return Err(AttestationError::UnsupportedVersion);
    }
    // The signed account must match the account the device trusts (no cross-account lift).
    if claims.account_id != account_id {
        return Err(AttestationError::AccountMismatch);
    }
    // The signed identity must match the OUTER actor the device renders — a tampered plaintext
    // `Actor.id`/`kind` (spoofing a trusted origin over a signature for a different actor) is
    // caught here.
    if claims.actor_id != actor.id {
        return Err(AttestationError::ActorIdMismatch);
    }
    if claims.actor_kind != actor.kind {
        return Err(AttestationError::ActorKindMismatch);
    }

    // ── Step 5: request binding (id AND hash — lift/no-swap protection) ─────────
    if claims.request_id != request_id {
        return Err(AttestationError::RequestIdMismatch);
    }
    if claims.request_hash != *request_hash {
        return Err(AttestationError::RequestHashMismatch);
    }

    Ok(())
}

/// Produces a human-readable **verified-origin** string from an actor's identity, for display in
/// the inbox once [`verify_actor_attestation_with_account_states`] has succeeded (e.g.
/// `"Claude Code · macbook-pro"` rendered from `kind = "claude-code"`, `id = "machine:macbook-pro"`).
///
/// This is **display formatting only** — it performs no verification and must be called *after*
/// verification returns `Ok`. It renders `"{kind} · {id}"`, matching the `docs/contract.md`
/// §Identity & keys example ("Claude Code · macbook-pro").
#[must_use]
pub fn verified_origin_string(actor: &Actor) -> String {
    format!("{} · {}", actor.kind, actor.id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────────
//
// Spec-first: assertions trace to docs/contract.md §Invariants #4 (Requester attestation),
// §Identity & keys, and docs/enrollment.md §Account State / §Actor-Key Enrollment — not to program
// output. All inputs are fixed and deterministic — fixed 32-byte seeds, fixed request_hash bytes —
// never SystemTime/rand.
//
// @see docs/contract.md §Invariants #4, §Identity & keys, §Wire encoding
// @see docs/enrollment.md §Account State, §Actor-Key Enrollment
// @see https://www.rfc-editor.org/rfc/rfc7515 (JSON Web Signature)
// @see https://www.rfc-editor.org/rfc/rfc8037 (CFRG curves in JOSE — EdDSA / Ed25519)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        sign_account_state, AccountState, AccountStateActor, AccountStateRevocation,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // ── Fixed seeds / identities / binding values (never rand) ────────────────────
    const ACTOR_SEED: [u8; 32] = [0x44u8; 32];
    const OTHER_SEED: [u8; 32] = [0x55u8; 32];
    const ROOT_SEED: [u8; 32] = [0x66u8; 32];
    const ACCOUNT_ID: &str = "acct_123";
    const ACTOR_ID: &str = "machine:macbook-pro";
    const ACTOR_KIND: &str = "claude-code";
    const REQUEST_ID: &str = "req-0001";
    const OTHER_REQUEST_ID: &str = "req-0002";
    const REQUEST_HASH: [u8; 32] = [0xABu8; 32];
    const OTHER_REQUEST_HASH: [u8; 32] = [0xCDu8; 32];

    fn actor_key() -> SigningKeyPair {
        SigningKeyPair::from_seed(&ACTOR_SEED)
    }

    fn root_key() -> SigningKeyPair {
        SigningKeyPair::from_seed(&ROOT_SEED)
    }

    /// An [`Actor`] carrying a fresh, correctly-signed attestation over (REQUEST_ID, REQUEST_HASH).
    fn attested_actor() -> Actor {
        let attestation = sign_actor_attestation(
            ACCOUNT_ID,
            ACTOR_ID,
            ACTOR_KIND,
            REQUEST_ID,
            &REQUEST_HASH,
            &actor_key(),
        );
        Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(),
            attestation: Some(attestation),
        }
    }

    /// A root-signed account-state document listing the actor with the given key/status.
    fn signed_account_state(
        sequence: u64,
        actor_pubkey: [u8; 32],
        status: &str,
        revoke_actor: bool,
    ) -> String {
        let revocations = if revoke_actor {
            vec![AccountStateRevocation {
                kind: AccountStateRevocationKind::Actor,
                id: ACTOR_ID.to_string(),
                revoked_at: 1_760_000_000_000,
                reason: Some("test".to_string()),
            }]
        } else {
            Vec::new()
        };
        let state = AccountState {
            v: 1,
            account_id: ACCOUNT_ID.to_string(),
            sequence,
            current_root: root_key().public_key().to_bytes(),
            previous_roots: Vec::new(),
            devices: Vec::new(),
            actors: vec![AccountStateActor {
                actor_id: ACTOR_ID.to_string(),
                kind: ACTOR_KIND.to_string(),
                pubkey: actor_pubkey,
                status: status.to_string(),
            }],
            revocations,
        };
        sign_account_state(&state, &root_key())
    }

    /// The default account-state set: one active document enrolling the real actor key.
    fn enrolled_states() -> Vec<String> {
        vec![signed_account_state(
            1,
            actor_key().public_key().to_bytes(),
            "active",
            false,
        )]
    }

    fn verify(actor: &Actor, states: &[String]) -> Result<(), AttestationError> {
        let refs: Vec<&str> = states.iter().map(String::as_str).collect();
        verify_actor_attestation_with_account_states(
            actor,
            ACCOUNT_ID,
            REQUEST_ID,
            &REQUEST_HASH,
            &refs,
            &root_key().public_key(),
        )
    }

    // ── Round-trip happy path ─────────────────────────────────────────────────────

    /// §Invariants #4 + enrollment §Account State: a freshly signed attestation verifies when the
    /// actor key is root-anchored in account state.
    #[test]
    fn round_trip_verifies_via_account_state() {
        verify(&attested_actor(), &enrolled_states())
            .expect("a correctly-signed, root-anchored attestation must verify");
    }

    /// The attestation bytes are a three-part compact JWS whose protected header declares the
    /// actor-attestation typ (domain separation from verdict / device-cert JWSs).
    #[test]
    fn attestation_is_compact_jws_with_actor_typ() {
        let actor = attested_actor();
        let bytes = actor.attestation.as_deref().unwrap();
        let compact = std::str::from_utf8(bytes).unwrap();
        let parts: Vec<&str> = compact.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS must have three parts");

        #[derive(serde::Deserialize)]
        struct Header {
            alg: String,
            typ: String,
            kid: String,
        }
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: Header = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, TYP_ACTOR_ATTEST);
        assert_eq!(header.kid, ACTOR_ID, "kid names the actor id");
    }

    // ── Trust-anchor: relay/forged key must NOT drive a verified origin (#16 blocker) ──

    /// THE blocker fix: a relay-supplied actor key that is NOT root-anchored cannot mint a verified
    /// origin. Here the attestation is signed by an attacker key and the account state enrolls only
    /// the REAL key — verification fails closed (SignatureInvalid under the root-anchored key).
    #[test]
    fn forged_actor_key_rejected_when_not_root_anchored() {
        // Attestation forged by an attacker key.
        let forged_attestation = sign_actor_attestation(
            ACCOUNT_ID,
            ACTOR_ID,
            ACTOR_KIND,
            REQUEST_ID,
            &REQUEST_HASH,
            &SigningKeyPair::from_seed(&OTHER_SEED),
        );
        let actor = Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(),
            attestation: Some(forged_attestation),
        };
        // Account state still enrolls the REAL key → the forged signature cannot verify.
        let err = verify(&actor, &enrolled_states())
            .expect_err("a forged (non-root-anchored) actor key must not verify");
        assert_eq!(err, AttestationError::SignatureInvalid);
    }

    /// Even a correctly self-signed attestation fails when the account state enrolls a DIFFERENT
    /// key for the actor — the relay cannot substitute its own key for the actor id.
    #[test]
    fn account_state_key_mismatch_rejected() {
        let actor = attested_actor(); // signed by the real ACTOR_SEED
                                      // But account state enrolls the OTHER key as this actor's root-anchored key.
        let states = vec![signed_account_state(
            1,
            SigningKeyPair::from_seed(&OTHER_SEED)
                .public_key()
                .to_bytes(),
            "active",
            false,
        )];
        let err = verify(&actor, &states)
            .expect_err("an attestation not matching the root-anchored key must be rejected");
        assert_eq!(err, AttestationError::SignatureInvalid);
    }

    /// An actor absent from all account-state documents is not root-anchored → ActorNotEnrolled.
    #[test]
    fn actor_absent_from_account_state_rejected() {
        let actor = attested_actor();
        let empty = AccountState {
            v: 1,
            account_id: ACCOUNT_ID.to_string(),
            sequence: 1,
            current_root: root_key().public_key().to_bytes(),
            previous_roots: Vec::new(),
            devices: Vec::new(),
            actors: Vec::new(),
            revocations: Vec::new(),
        };
        let states = vec![sign_account_state(&empty, &root_key())];
        let err = verify(&actor, &states)
            .expect_err("an actor not in account state must not be root-anchored");
        assert_eq!(err, AttestationError::ActorNotEnrolled);
    }

    /// No account state at all → ActorNotEnrolled (fail-closed; there is no trust anchor).
    #[test]
    fn no_account_state_rejected() {
        let err = verify(&attested_actor(), &[])
            .expect_err("with no account state there is no root anchor");
        assert_eq!(err, AttestationError::ActorNotEnrolled);
    }

    /// An actor whose highest-sequence entry is `inactive` is treated as revoked → ActorRevoked.
    #[test]
    fn inactive_actor_rejected() {
        let states = vec![signed_account_state(
            1,
            actor_key().public_key().to_bytes(),
            "inactive",
            false,
        )];
        let err = verify(&attested_actor(), &states)
            .expect_err("an inactive actor must not be shown as verified");
        assert_eq!(err, AttestationError::ActorRevoked);
    }

    /// An explicitly revoked actor at the highest sequence → ActorRevoked, even if an older state
    /// still listed it active (highest-sequence revocation wins).
    #[test]
    fn revoked_actor_rejected_highest_sequence_wins() {
        let older_active =
            signed_account_state(1, actor_key().public_key().to_bytes(), "active", false);
        let newer_revoked =
            signed_account_state(2, actor_key().public_key().to_bytes(), "active", true);
        let err = verify(&attested_actor(), &[older_active, newer_revoked])
            .expect_err("a highest-sequence actor revocation must fail closed");
        assert_eq!(err, AttestationError::ActorRevoked);
    }

    /// A tampered (non-root-signed) account-state document fails closed → AccountStateInvalid.
    #[test]
    fn invalid_account_state_rejected() {
        // Sign the document with the WRONG key (an attacker, not the configured account root).
        let state = AccountState {
            v: 1,
            account_id: ACCOUNT_ID.to_string(),
            sequence: 1,
            current_root: SigningKeyPair::from_seed(&OTHER_SEED)
                .public_key()
                .to_bytes(),
            previous_roots: Vec::new(),
            devices: Vec::new(),
            actors: vec![AccountStateActor {
                actor_id: ACTOR_ID.to_string(),
                kind: ACTOR_KIND.to_string(),
                pubkey: actor_key().public_key().to_bytes(),
                status: "active".to_string(),
            }],
            revocations: Vec::new(),
        };
        let states = vec![sign_account_state(
            &state,
            &SigningKeyPair::from_seed(&OTHER_SEED),
        )];
        let err = verify(&attested_actor(), &states)
            .expect_err("an account-state doc not signed by the trusted root must be rejected");
        assert_eq!(err, AttestationError::AccountStateInvalid);
    }

    // ── Negative: missing / tampered identity / wrong request ─────────────────────

    /// Fail-closed: no attestation present → Missing (not a permissive default).
    #[test]
    fn missing_attestation_rejected() {
        let actor = Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(),
            attestation: None,
        };
        let err =
            verify(&actor, &enrolled_states()).expect_err("an absent attestation must be rejected");
        assert_eq!(err, AttestationError::Missing);
    }

    /// A spoofed OUTER `actor.id` (claiming a trusted origin) over a signature for a different
    /// actor id is detected as an ActorIdMismatch — the core of the "verified origin" guarantee.
    /// Here the spoofed id is the one root-anchored in account state, but the signed id differs.
    #[test]
    fn spoofed_actor_id_rejected() {
        // Attestation legitimately signed for "machine:attacker"; outer actor claims the trusted id.
        let attestation = sign_actor_attestation(
            ACCOUNT_ID,
            "machine:attacker",
            ACTOR_KIND,
            REQUEST_ID,
            &REQUEST_HASH,
            &actor_key(),
        );
        let spoofed = Actor {
            id: ACTOR_ID.to_string(), // outer claims the TRUSTED id…
            kind: ACTOR_KIND.to_string(),
            attestation: Some(attestation), // …but the signature is for "machine:attacker"
        };
        let err = verify(&spoofed, &enrolled_states())
            .expect_err("a spoofed outer actor.id must be rejected");
        assert_eq!(err, AttestationError::ActorIdMismatch);
    }

    /// A spoofed OUTER `actor.kind` is likewise rejected.
    #[test]
    fn spoofed_actor_kind_rejected() {
        let attestation = sign_actor_attestation(
            ACCOUNT_ID,
            ACTOR_ID,
            "untrusted-kind",
            REQUEST_ID,
            &REQUEST_HASH,
            &actor_key(),
        );
        let spoofed = Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(), // outer claims the TRUSTED kind…
            attestation: Some(attestation), // …signature is for "untrusted-kind"
        };
        let err = verify(&spoofed, &enrolled_states())
            .expect_err("a spoofed outer actor.kind must be rejected");
        assert_eq!(err, AttestationError::ActorKindMismatch);
    }

    /// An attestation signed for a DIFFERENT `request_id` (but the SAME `request_hash` — a
    /// content-identical sibling request) must not verify — the cross-request no-swap protection
    /// that binding `request_id` (not just `request_hash`) adds.
    #[test]
    fn wrong_request_id_rejected_no_swap() {
        // Legitimately signed over OTHER_REQUEST_ID but the SAME REQUEST_HASH.
        let attestation = sign_actor_attestation(
            ACCOUNT_ID,
            ACTOR_ID,
            ACTOR_KIND,
            OTHER_REQUEST_ID,
            &REQUEST_HASH,
            &actor_key(),
        );
        let actor = Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(),
            attestation: Some(attestation),
        };
        // Verified against REQUEST_ID (the content-identical sibling) → request_id binding catches it.
        let err = verify(&actor, &enrolled_states())
            .expect_err("an attestation bound to a different request_id must be rejected");
        assert_eq!(err, AttestationError::RequestIdMismatch);
    }

    /// An attestation signed for a DIFFERENT `request_hash` must not verify against this request —
    /// the lift-and-replay protection (request-specific, not a reusable identity token).
    #[test]
    fn altered_request_hash_rejected() {
        // Legitimately signed over OTHER_REQUEST_HASH (with this request's id)…
        let attestation = sign_actor_attestation(
            ACCOUNT_ID,
            ACTOR_ID,
            ACTOR_KIND,
            REQUEST_ID,
            &OTHER_REQUEST_HASH,
            &actor_key(),
        );
        let actor = Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(),
            attestation: Some(attestation),
        };
        // …but verified against REQUEST_HASH (a different request the device is rendering).
        let err = verify(&actor, &enrolled_states())
            .expect_err("an attestation bound to a different request_hash must be rejected");
        assert_eq!(err, AttestationError::RequestHashMismatch);
    }

    /// A signed `account_id` that disagrees with the account the device trusts is a cross-account
    /// lift → AccountMismatch. (Constructed by signing for a different account but enrolling under
    /// the verifier's account so the key resolves.)
    #[test]
    fn cross_account_attestation_rejected() {
        let attestation = sign_actor_attestation(
            "acct_other",
            ACTOR_ID,
            ACTOR_KIND,
            REQUEST_ID,
            &REQUEST_HASH,
            &actor_key(),
        );
        let actor = Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(),
            attestation: Some(attestation),
        };
        let err = verify(&actor, &enrolled_states())
            .expect_err("an attestation for a different account_id must be rejected");
        assert_eq!(err, AttestationError::AccountMismatch);
    }

    /// Tampering a byte of the signature part → SignatureInvalid (fail-closed).
    #[test]
    fn tampered_signature_rejected() {
        let actor = attested_actor();
        let compact = std::str::from_utf8(actor.attestation.as_deref().unwrap())
            .unwrap()
            .to_string();
        let mut parts: Vec<String> = compact.split('.').map(str::to_string).collect();
        let sig = &mut parts[2];
        let last = sig.pop().unwrap();
        sig.push(if last == 'A' { 'B' } else { 'A' });
        let tampered = Actor {
            attestation: Some(parts.join(".").into_bytes()),
            ..actor
        };
        let err = verify(&tampered, &enrolled_states())
            .expect_err("a tampered signature must be rejected");
        assert!(
            matches!(
                err,
                AttestationError::SignatureInvalid | AttestationError::MalformedJws
            ),
            "tampered attestation must be SignatureInvalid or MalformedJws, got {err:?}"
        );
    }

    /// Non-UTF-8 attestation bytes → NotUtf8 (a compact JWS is an ASCII string).
    #[test]
    fn non_utf8_attestation_rejected() {
        let actor = Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(),
            // 0xFF is never valid UTF-8.
            attestation: Some(vec![0xFF, 0xFE, 0xFD]),
        };
        let err = verify(&actor, &enrolled_states())
            .expect_err("non-UTF-8 attestation bytes must be rejected");
        assert_eq!(err, AttestationError::NotUtf8);
    }

    /// Cross-protocol confusion (attestation direction): a structurally-valid JWS with the WRONG
    /// `typ` (a verdict typ, not the actor-attestation typ) is rejected as MalformedJws before any
    /// identity check.
    #[test]
    fn wrong_typ_rejected() {
        // Hand-build a JWS with typ "allw-verdict+jws" over the actor claims, signed by the actor
        // key — same alg/key, wrong domain separator. decode_and_verify_jws must reject the typ.
        let claims = ActorAttestationClaims {
            v: ATTESTATION_V,
            account_id: ACCOUNT_ID.to_string(),
            actor_id: ACTOR_ID.to_string(),
            actor_kind: ACTOR_KIND.to_string(),
            request_id: REQUEST_ID.to_string(),
            request_hash: REQUEST_HASH,
        };
        let header = JwsHeader {
            alg: ALG_EDDSA.to_string(),
            typ: "allw-verdict+jws".to_string(),
            kid: ACTOR_ID.to_string(),
        };
        let compact = encode_compact_jws(&header, &claims, &actor_key());
        let actor = Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(),
            attestation: Some(compact.into_bytes()),
        };
        let err = verify(&actor, &enrolled_states())
            .expect_err("a JWS with the wrong typ must be rejected (cross-protocol confusion)");
        assert_eq!(err, AttestationError::MalformedJws);
    }

    /// Cross-protocol confusion (the OTHER direction): an actor-attestation JWS must NOT verify
    /// where a verdict or device-cert is expected. We confirm the attestation's `typ` is the
    /// actor-attestation domain separator, so `decode_and_verify_jws` with any other expected `typ`
    /// rejects it. (The verdict/cert verifiers in `crypto.rs` use the same `decode_and_verify_jws`,
    /// so a `typ` mismatch is rejected there identically.)
    #[test]
    fn attestation_not_accepted_as_other_typ() {
        let actor = attested_actor();
        let compact = std::str::from_utf8(actor.attestation.as_deref().unwrap())
            .unwrap()
            .to_string();
        // Try to decode the attestation as if it were a verdict JWS → must fail on typ.
        let result = decode_and_verify_jws::<ActorAttestationClaims>(
            &compact,
            "allw-verdict+jws",
            &actor_key().public_key(),
        );
        assert!(
            matches!(result, Err(JwsError::UnexpectedTyp)),
            "an actor-attestation JWS must not verify where a verdict typ is expected"
        );
    }

    /// The signed `kid` must name the signed `actor_id`. Forge a JWS whose header kid disagrees
    /// with the claims actor_id (both checks otherwise pass) → KidMismatch.
    #[test]
    fn kid_actor_id_mismatch_rejected() {
        let claims = ActorAttestationClaims {
            v: ATTESTATION_V,
            account_id: ACCOUNT_ID.to_string(),
            actor_id: ACTOR_ID.to_string(),
            actor_kind: ACTOR_KIND.to_string(),
            request_id: REQUEST_ID.to_string(),
            request_hash: REQUEST_HASH,
        };
        let header = JwsHeader {
            alg: ALG_EDDSA.to_string(),
            typ: TYP_ACTOR_ATTEST.to_string(),
            kid: "machine:other".to_string(), // kid disagrees with claims.actor_id
        };
        let compact = encode_compact_jws(&header, &claims, &actor_key());
        let actor = Actor {
            id: ACTOR_ID.to_string(),
            kind: ACTOR_KIND.to_string(),
            attestation: Some(compact.into_bytes()),
        };
        let err = verify(&actor, &enrolled_states())
            .expect_err("a kid that disagrees with the signed actor_id must be rejected");
        assert_eq!(err, AttestationError::KidMismatch);
    }

    // ── verified_origin_string formatting ─────────────────────────────────────────

    /// §Identity & keys example: the verified origin renders "{kind} · {id}".
    #[test]
    fn verified_origin_string_formats_kind_and_id() {
        let actor = attested_actor();
        assert_eq!(
            verified_origin_string(&actor),
            "claude-code · machine:macbook-pro"
        );
    }
}
