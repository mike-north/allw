//! **Self-certifying accounts**: the account id is derived from the account-root public key,
//! and root-signed **pairing-start authorizations** prove the caller holds that root.
//!
//! See `docs/enrollment.md` §Model (account id derivation, root binding) and
//! `docs/relay-api.md` §3 Pairing.
//!
//! # Why the account id is derived, not chosen
//!
//! An account is a cryptographic object: whoever holds the account-root signing key *is* the
//! account. The relay therefore never trusts an account id on its own. Every root-signed call
//! presents the root public key, and the relay re-derives the id from it with
//! [`account_id_for_root`]. An id that does not derive from the presented root is rejected. The
//! alternative — binding a root to an arbitrary id on first contact (TOFU) — lets anyone who
//! learns an id before its owner first uses it squat it, so it is deliberately not used.
//!
//! ```text
//! account_id = base64url-unpadded( SHA-256( "allw/account-id/v1" || 0x00 || account_root_pub ) )
//! ```
//!
//! The full 256-bit digest is kept (43 base64url characters) — no truncation, so the id carries
//! the full collision resistance of SHA-256 and there is no length/security trade-off to justify.
//! The domain tag and `0x00` separator make the digest unambiguous with every other SHA-256 use in
//! the core (e.g. the `request-hash/v2` WYSIWYS hash).
//!
//! **Root rotation in v1 creates a new account.** Because the id is a function of the root, a new
//! root derives a new id. Keeping an id stable across root rotation is a tracked follow-up, not a
//! v1 property.
//!
//! # Pairing-start authorization
//!
//! `POST /{acct}/pairing/start` hands out a pairing code that enrolls a device on the account, so
//! only the account root may start one. The caller sends the root public key plus a short-lived,
//! root-signed compact JWS (`typ = "allw-pairing-start+jws"`, `kid = account_id`) whose payload is
//! [`PairingStartClaims`]. [`verify_pairing_start_authorization`] checks — fail-closed, in order:
//!
//! 1. the expected account id derives from the presented root ([`PairingStartError::AccountIdMismatch`]);
//! 2. the JWS is well-formed EdDSA with the pairing-start `typ` and a valid root signature
//!    ([`PairingStartError::WrongTyp`] / [`PairingStartError::InvalidSignature`]);
//! 3. the header `kid` and the signed `account_id` both equal the expected account
//!    ([`PairingStartError::AccountMismatch`]);
//! 4. the schema version is supported ([`PairingStartError::UnsupportedVersion`]);
//! 5. the `jti` is a well-formed one-time identifier ([`PairingStartError::InvalidJti`]);
//! 6. the validity window is positive and at most [`PAIRING_START_MAX_LIFETIME_MS`]
//!    ([`PairingStartError::InvalidLifetime`]);
//! 7. it is not issued in the future beyond [`PAIRING_START_MAX_CLOCK_SKEW_MS`]
//!    ([`PairingStartError::NotYetValid`]) and has not expired ([`PairingStartError::Expired`]).
//!
//! **Replay** of a still-fresh authorization is the verifier's stateful duty, like the verdict
//! [`crate::NonceStore`]: the relay records each accepted `jti` until its `expires_at` and rejects a
//! repeat. The core cannot do that statelessly; it guarantees only that an authorization is useless
//! after `expires_at`, which bounds how long a `jti` must be remembered.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{
    decode_and_verify_jws, encode_compact_jws, JwsError, JwsHeader, PublicKey, SigningKeyPair,
    ALG_EDDSA,
};

/// Domain separation tag for deriving an account id from its root public key.
const ACCOUNT_ID_DOMAIN_TAG: &[u8] = b"allw/account-id/v1";

/// Null-byte separator between the account-id domain tag and the root public key.
const ACCOUNT_ID_SEPARATOR: u8 = 0x00;

/// `typ` header value for a pairing-start authorization JWS (signed by the account root key).
/// Distinct from every other allw JWS `typ`, so no other root-signed artifact (a device cert, an
/// account-state document) can be replayed as a pairing-start authorization.
pub(crate) const TYP_PAIRING_START: &str = "allw-pairing-start+jws";

/// The only pairing-start authorization schema version accepted.
const PAIRING_START_VERSION: u32 = 1;

/// Maximum validity window (`expires_at - issued_at`) of a pairing-start authorization: 5 minutes.
///
/// Short on purpose: an intercepted authorization is only useful until it expires, and the relay
/// must remember each accepted `jti` for at most this long to reject replays.
pub const PAIRING_START_MAX_LIFETIME_MS: i64 = 5 * 60 * 1000;

/// Tolerated clock skew between the signer and the verifier: an authorization whose `issued_at` is
/// at most this far in the verifier's future is still accepted. 60 seconds covers ordinary NTP
/// drift between an approver machine and the relay without meaningfully extending the window.
pub const PAIRING_START_MAX_CLOCK_SKEW_MS: i64 = 60 * 1000;

/// Minimum `jti` length. 16 base64url characters carry 96 bits when randomly generated, enough
/// that two honest authorizations never collide inside one 5-minute window.
pub const PAIRING_START_JTI_MIN_LEN: usize = 16;

/// Maximum `jti` length — bounds the per-account replay store the relay keeps.
pub const PAIRING_START_JTI_MAX_LEN: usize = 128;

// ── Account id derivation ────────────────────────────────────────────────────────

/// Derives the self-certifying account id for an account-root public key.
///
/// `base64url-unpadded(SHA-256("allw/account-id/v1" || 0x00 || root_pub))` — always 43 characters
/// of the base64url alphabet, so it is safe as a URL path segment. See the module docs.
#[must_use]
pub fn account_id_for_root(account_root: &PublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ACCOUNT_ID_DOMAIN_TAG);
    hasher.update([ACCOUNT_ID_SEPARATOR]);
    hasher.update(account_root.to_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Error checking an account id against an account-root public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountIdError {
    /// The account id is not the one [`account_id_for_root`] derives from the presented root.
    Mismatch,
}

impl std::fmt::Display for AccountIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mismatch => write!(f, "account id does not derive from the account root key"),
        }
    }
}

impl std::error::Error for AccountIdError {}

/// Checks that `account_id` is exactly the id derived from `account_root`.
///
/// # Errors
///
/// Returns [`AccountIdError::Mismatch`] for any other string, including ids from other roots,
/// legacy free-form ids, and differently-encoded forms of the right digest.
pub fn check_account_id_for_root(
    account_id: &str,
    account_root: &PublicKey,
) -> Result<(), AccountIdError> {
    // Both values are public; a plain comparison leaks nothing secret.
    if account_id == account_id_for_root(account_root) {
        Ok(())
    } else {
        Err(AccountIdError::Mismatch)
    }
}

// ── Pairing-start authorization ──────────────────────────────────────────────────

/// The signed claims inside a pairing-start authorization JWS.
///
/// Timestamps are Unix milliseconds (UTC), matching every other allw claim set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingStartClaims {
    /// Schema version. v1 is the only version accepted.
    pub v: u32,
    /// The account the pairing is being started for — always the id derived from the signing root.
    pub account_id: String,
    /// When the root signed this authorization.
    pub issued_at: i64,
    /// When this authorization stops being accepted (exclusive). At most
    /// [`PAIRING_START_MAX_LIFETIME_MS`] after `issued_at`.
    pub expires_at: i64,
    /// One-time identifier. The verifier rejects a second use while the authorization is fresh.
    pub jti: String,
}

/// Errors producing or verifying a pairing-start authorization. Every variant is a rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingStartError {
    /// The expected account id does not derive from the presented root public key.
    AccountIdMismatch,
    /// The compact JWS was malformed, not EdDSA, or its signature did not verify against the root.
    InvalidSignature,
    /// The JWS `typ` is not `allw-pairing-start+jws` (e.g. another root-signed artifact).
    WrongTyp,
    /// The JWS `kid` or signed `account_id` does not match the expected account.
    AccountMismatch,
    /// The claim-set schema version is not supported.
    UnsupportedVersion,
    /// The `jti` is outside the accepted length or not base64url-alphabet.
    InvalidJti,
    /// `expires_at` is not after `issued_at`, or the window exceeds the maximum lifetime.
    InvalidLifetime,
    /// `issued_at` is further in the future than the tolerated clock skew.
    NotYetValid,
    /// The authorization has expired (`now_ms >= expires_at`).
    Expired,
}

impl std::fmt::Display for PairingStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::AccountIdMismatch => "account id does not derive from the account root key",
            Self::InvalidSignature => "pairing-start authorization JWS did not verify",
            Self::WrongTyp => "pairing-start authorization has the wrong JWS typ",
            Self::AccountMismatch => "pairing-start authorization is for a different account",
            Self::UnsupportedVersion => "unsupported pairing-start authorization version",
            Self::InvalidJti => "pairing-start authorization jti is malformed",
            Self::InvalidLifetime => "pairing-start authorization validity window is invalid",
            Self::NotYetValid => "pairing-start authorization is not yet valid",
            Self::Expired => "pairing-start authorization has expired",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for PairingStartError {}

/// A `jti` is 16–128 characters of the base64url alphabet, so it is safe to store and compare
/// verbatim and bounded in size.
fn jti_is_well_formed(jti: &str) -> bool {
    (PAIRING_START_JTI_MIN_LEN..=PAIRING_START_JTI_MAX_LEN).contains(&jti.len())
        && jti
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The validity window is strictly positive and no longer than the maximum lifetime. Checked
/// arithmetic: extreme timestamps that would overflow are rejected rather than wrapped.
fn lifetime_is_valid(issued_at: i64, expires_at: i64) -> bool {
    matches!(
        expires_at.checked_sub(issued_at),
        Some(lifetime) if lifetime > 0 && lifetime <= PAIRING_START_MAX_LIFETIME_MS
    )
}

/// Signs a pairing-start authorization with the account root, for the account id derived from
/// that root (the caller cannot bind any other id).
///
/// # Errors
///
/// Returns [`PairingStartError::InvalidJti`] or [`PairingStartError::InvalidLifetime`] for inputs
/// the verifier would reject, so a client never sends an authorization that cannot succeed.
pub fn sign_pairing_start_authorization(
    account_root: &SigningKeyPair,
    issued_at: i64,
    expires_at: i64,
    jti: &str,
) -> Result<String, PairingStartError> {
    if !jti_is_well_formed(jti) {
        return Err(PairingStartError::InvalidJti);
    }
    if !lifetime_is_valid(issued_at, expires_at) {
        return Err(PairingStartError::InvalidLifetime);
    }
    let account_id = account_id_for_root(&account_root.public_key());
    let claims = PairingStartClaims {
        v: PAIRING_START_VERSION,
        account_id: account_id.clone(),
        issued_at,
        expires_at,
        jti: jti.to_string(),
    };
    let header = JwsHeader {
        alg: ALG_EDDSA.to_string(),
        typ: TYP_PAIRING_START.to_string(),
        kid: account_id,
    };
    Ok(encode_compact_jws(&header, &claims, account_root))
}

/// Verifies a pairing-start authorization for `expected_account_id` against the presented
/// `account_root`, at verifier time `now_ms`. Returns the verified claims; the caller must then
/// reject a `jti` it has already accepted (see the module docs on replay).
///
/// # Errors
///
/// Returns the first failing check as a [`PairingStartError`], in the order listed in the module
/// docs. There is no success path other than a fully verified, fresh authorization.
pub fn verify_pairing_start_authorization(
    compact: &str,
    expected_account_id: &str,
    account_root: &PublicKey,
    now_ms: i64,
) -> Result<PairingStartClaims, PairingStartError> {
    check_account_id_for_root(expected_account_id, account_root)
        .map_err(|_| PairingStartError::AccountIdMismatch)?;

    let decoded =
        decode_and_verify_jws::<PairingStartClaims>(compact, TYP_PAIRING_START, account_root)
            .map_err(|e| match e {
                JwsError::UnexpectedTyp => PairingStartError::WrongTyp,
                _ => PairingStartError::InvalidSignature,
            })?;
    let claims = decoded.claims;

    if decoded.header.kid != expected_account_id || claims.account_id != expected_account_id {
        return Err(PairingStartError::AccountMismatch);
    }
    if claims.v != PAIRING_START_VERSION {
        return Err(PairingStartError::UnsupportedVersion);
    }
    if !jti_is_well_formed(&claims.jti) {
        return Err(PairingStartError::InvalidJti);
    }
    if !lifetime_is_valid(claims.issued_at, claims.expires_at) {
        return Err(PairingStartError::InvalidLifetime);
    }
    if claims.issued_at > now_ms.saturating_add(PAIRING_START_MAX_CLOCK_SKEW_MS) {
        return Err(PairingStartError::NotYetValid);
    }
    if now_ms >= claims.expires_at {
        return Err(PairingStartError::Expired);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    //! @see docs/enrollment.md §Model (account id derivation, pairing-start authorization)
    //! @see docs/relay-api.md §3 Pairing
    use super::*;
    use crate::crypto::{sign_account_state, AccountState, TYP_DEVICE_CERT};

    const ROOT_SEED: [u8; 32] = [0x11; 32];
    const OTHER_SEED: [u8; 32] = [0x33; 32];
    const ISSUED_AT: i64 = 1_700_000_000_000;
    const EXPIRES_AT: i64 = ISSUED_AT + 120_000;
    const NOW: i64 = ISSUED_AT + 1_000;
    const JTI: &str = "jti_0123456789abcdef";

    /// Frozen account id for the root derived from seed `[0x11; 32]`, computed independently of
    /// this module: `printf 'allw/account-id/v1\0' + <32 root pubkey bytes> | shasum -a 256`,
    /// then base64url-unpadded. A change here is a deliberate domain-tag bump.
    const FROZEN_ACCOUNT_ID_0X11: &str = "hUes5Gso3s5hHMmZjDI-P0tyaD905KSl1B97nsp2VIo";

    fn root() -> SigningKeyPair {
        SigningKeyPair::from_seed(&ROOT_SEED)
    }

    fn account_id() -> String {
        account_id_for_root(&root().public_key())
    }

    fn signed(issued_at: i64, expires_at: i64, jti: &str) -> String {
        sign_pairing_start_authorization(&root(), issued_at, expires_at, jti)
            .expect("valid inputs sign")
    }

    /// Hand-assembles a root-signed pairing-start JWS with arbitrary header/claims, so tests can
    /// reach verifier branches the honest signer refuses to produce.
    fn forge(typ: &str, kid: &str, claims: &PairingStartClaims, key: &SigningKeyPair) -> String {
        forge_with_alg(ALG_EDDSA, typ, kid, claims, key)
    }

    /// Like [`forge`], with an arbitrary header `alg`. The signature is always a genuine Ed25519
    /// signature by `key` over the transmitted `header.payload`, whatever `alg` claims.
    fn forge_with_alg(
        alg: &str,
        typ: &str,
        kid: &str,
        claims: &PairingStartClaims,
        key: &SigningKeyPair,
    ) -> String {
        let header = JwsHeader {
            alg: alg.to_string(),
            typ: typ.to_string(),
            kid: kid.to_string(),
        };
        encode_compact_jws(&header, claims, key)
    }

    fn claims() -> PairingStartClaims {
        PairingStartClaims {
            v: 1,
            account_id: account_id(),
            issued_at: ISSUED_AT,
            expires_at: EXPIRES_AT,
            jti: JTI.to_string(),
        }
    }

    fn verify(compact: &str) -> Result<PairingStartClaims, PairingStartError> {
        verify_pairing_start_authorization(compact, &account_id(), &root().public_key(), NOW)
    }

    #[test]
    fn account_id_matches_frozen_vector() {
        assert_eq!(account_id(), FROZEN_ACCOUNT_ID_0X11);
        assert_eq!(account_id().len(), 43);
    }

    #[test]
    fn account_id_differs_per_root() {
        let other = account_id_for_root(&SigningKeyPair::from_seed(&OTHER_SEED).public_key());
        assert_ne!(other, account_id());
    }

    #[test]
    fn check_account_id_accepts_derived_and_rejects_others() {
        let pk = root().public_key();
        assert_eq!(check_account_id_for_root(&account_id(), &pk), Ok(()));
        let other = account_id_for_root(&SigningKeyPair::from_seed(&OTHER_SEED).public_key());
        assert_eq!(
            check_account_id_for_root(&other, &pk),
            Err(AccountIdError::Mismatch)
        );
        assert_eq!(
            check_account_id_for_root("acct-free-form", &pk),
            Err(AccountIdError::Mismatch)
        );
        // Padded base64 of the right digest is a different string, not an alias.
        let padded = format!("{}=", account_id());
        assert_eq!(
            check_account_id_for_root(&padded, &pk),
            Err(AccountIdError::Mismatch)
        );
    }

    #[test]
    fn valid_authorization_round_trips() {
        let verified = verify(&signed(ISSUED_AT, EXPIRES_AT, JTI)).expect("verifies");
        assert_eq!(verified, claims());
    }

    #[test]
    fn signer_rejects_inputs_the_verifier_would_reject() {
        assert_eq!(
            sign_pairing_start_authorization(&root(), ISSUED_AT, EXPIRES_AT, "short"),
            Err(PairingStartError::InvalidJti)
        );
        assert_eq!(
            sign_pairing_start_authorization(
                &root(),
                ISSUED_AT,
                ISSUED_AT + PAIRING_START_MAX_LIFETIME_MS + 1,
                JTI
            ),
            Err(PairingStartError::InvalidLifetime)
        );
    }

    #[test]
    fn rejects_account_id_not_derived_from_root() {
        let other = account_id_for_root(&SigningKeyPair::from_seed(&OTHER_SEED).public_key());
        let err = verify_pairing_start_authorization(
            &signed(ISSUED_AT, EXPIRES_AT, JTI),
            &other,
            &root().public_key(),
            NOW,
        );
        assert_eq!(err, Err(PairingStartError::AccountIdMismatch));
    }

    #[test]
    fn rejects_signature_from_another_key() {
        // Signed by a different key but claiming this account: the root signature fails.
        let other = SigningKeyPair::from_seed(&OTHER_SEED);
        let forged = forge(TYP_PAIRING_START, &account_id(), &claims(), &other);
        assert_eq!(verify(&forged), Err(PairingStartError::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_payload() {
        let good = signed(ISSUED_AT, EXPIRES_AT, JTI);
        let mut parts: Vec<&str> = good.split('.').collect();
        let mut tampered = claims();
        tampered.jti = "jti_TAMPERED_0123456".to_string();
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered).unwrap());
        parts[1] = &payload;
        assert_eq!(
            verify(&parts.join(".")),
            Err(PairingStartError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_junk_jws() {
        assert_eq!(
            verify("not-a-jws"),
            Err(PairingStartError::InvalidSignature)
        );
        assert_eq!(verify("a.b.c"), Err(PairingStartError::InvalidSignature));
        assert_eq!(verify(""), Err(PairingStartError::InvalidSignature));
    }

    #[test]
    fn rejects_wrong_typ() {
        let forged = forge(TYP_DEVICE_CERT, &account_id(), &claims(), &root());
        assert_eq!(verify(&forged), Err(PairingStartError::WrongTyp));
    }

    #[test]
    fn rejects_non_eddsa_alg() {
        // Control: the same forger with `alg: EdDSA` is accepted, so each rejection below is
        // caused by the header `alg` alone — the root's Ed25519 signature is honest throughout.
        let control = forge_with_alg(
            ALG_EDDSA,
            TYP_PAIRING_START,
            &account_id(),
            &claims(),
            &root(),
        );
        assert_eq!(verify(&control), Ok(claims()));

        for alg in ["none", "HS256", "eddsa", ""] {
            let forged = forge_with_alg(alg, TYP_PAIRING_START, &account_id(), &claims(), &root());
            assert_eq!(
                verify(&forged),
                Err(PairingStartError::InvalidSignature),
                "alg {alg:?}"
            );
            // Pin the branch: the JWS layer rejects on `alg` before checking `typ` or signature.
            assert!(
                matches!(
                    decode_and_verify_jws::<PairingStartClaims>(
                        &forged,
                        TYP_PAIRING_START,
                        &root().public_key()
                    ),
                    Err(JwsError::UnexpectedAlg)
                ),
                "alg {alg:?}"
            );
        }
    }

    #[test]
    fn rejects_other_root_signed_artifact() {
        // A genuine root-signed account-state document is never a pairing-start authorization.
        let state = AccountState {
            v: 1,
            account_id: account_id(),
            sequence: 1,
            current_root: root().public_key().to_bytes(),
            previous_roots: vec![],
            devices: vec![],
            actors: vec![],
            revocations: vec![],
        };
        let compact = sign_account_state(&state, &root());
        assert_eq!(verify(&compact), Err(PairingStartError::WrongTyp));
    }

    #[test]
    fn rejects_wrong_account_id_claim() {
        let mut c = claims();
        c.account_id = "someone-else".to_string();
        let forged = forge(TYP_PAIRING_START, &account_id(), &c, &root());
        assert_eq!(verify(&forged), Err(PairingStartError::AccountMismatch));
    }

    #[test]
    fn rejects_wrong_kid() {
        let forged = forge(TYP_PAIRING_START, "someone-else", &claims(), &root());
        assert_eq!(verify(&forged), Err(PairingStartError::AccountMismatch));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut c = claims();
        c.v = 2;
        let forged = forge(TYP_PAIRING_START, &account_id(), &c, &root());
        assert_eq!(verify(&forged), Err(PairingStartError::UnsupportedVersion));
    }

    #[test]
    fn rejects_malformed_jti() {
        for jti in [
            "short",
            &"x".repeat(PAIRING_START_JTI_MAX_LEN + 1),
            "has spaces in the jti!!",
        ] {
            let mut c = claims();
            c.jti = jti.to_string();
            let forged = forge(TYP_PAIRING_START, &account_id(), &c, &root());
            assert_eq!(verify(&forged), Err(PairingStartError::InvalidJti), "{jti}");
        }
    }

    #[test]
    fn rejects_overlong_lifetime() {
        let mut c = claims();
        c.expires_at = c.issued_at + PAIRING_START_MAX_LIFETIME_MS + 1;
        let forged = forge(TYP_PAIRING_START, &account_id(), &c, &root());
        assert_eq!(verify(&forged), Err(PairingStartError::InvalidLifetime));
    }

    #[test]
    fn accepts_exactly_max_lifetime() {
        let compact = signed(ISSUED_AT, ISSUED_AT + PAIRING_START_MAX_LIFETIME_MS, JTI);
        assert!(verify(&compact).is_ok());
    }

    #[test]
    fn rejects_non_positive_and_overflowing_lifetime() {
        for (issued_at, expires_at) in [
            (ISSUED_AT, ISSUED_AT),
            (ISSUED_AT, ISSUED_AT - 1),
            (i64::MIN, i64::MAX),
        ] {
            let mut c = claims();
            c.issued_at = issued_at;
            c.expires_at = expires_at;
            let forged = forge(TYP_PAIRING_START, &account_id(), &c, &root());
            assert_eq!(
                verify(&forged),
                Err(PairingStartError::InvalidLifetime),
                "{issued_at}..{expires_at}"
            );
        }
    }

    #[test]
    fn rejects_expired_at_and_after_expiry() {
        let compact = signed(ISSUED_AT, EXPIRES_AT, JTI);
        let pk = root().public_key();
        for now in [EXPIRES_AT, EXPIRES_AT + 1] {
            assert_eq!(
                verify_pairing_start_authorization(&compact, &account_id(), &pk, now),
                Err(PairingStartError::Expired),
                "now = {now}"
            );
        }
    }

    #[test]
    fn tolerates_bounded_clock_skew_only() {
        let pk = root().public_key();
        let compact = signed(ISSUED_AT, EXPIRES_AT, JTI);
        // Verifier clock exactly MAX_SKEW behind the signer: still accepted.
        let now = ISSUED_AT - PAIRING_START_MAX_CLOCK_SKEW_MS;
        assert!(verify_pairing_start_authorization(&compact, &account_id(), &pk, now).is_ok());
        // One millisecond further behind: not yet valid.
        assert_eq!(
            verify_pairing_start_authorization(&compact, &account_id(), &pk, now - 1),
            Err(PairingStartError::NotYetValid)
        );
    }
}
