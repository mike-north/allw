//! **Sealing**: encrypt an [`ApprovalContext`] to exactly the devices root-signed account state
//! vouches for, in one core call.
//!
//! See `docs/enrollment.md` §Model (recipient selection rule) and `docs/contract.md` §Invariants
//! (E2EE, fail-closed).
//!
//! # Why one call
//!
//! [`crate::select_recipients`] decides who may read a request and [`crate::encrypt_context`]
//! encrypts to a recipient list. Composing them in a surface (the TS SDK) would hand the recipient
//! keys to code outside the audited core, where a bug or a relay-supplied list could slip in
//! between the two steps. [`seal_context_for_account_state`] does both here: the selected keys
//! never leave the core, and the only way to obtain a ciphertext from this API is through the
//! selection rules.
//!
//! # What the caller gets back
//!
//! The ciphertext, and the account-state `sequence` the recipients were selected from. A caller
//! that persists a sequence floor records that sequence (and passes it as `min_sequence` next time)
//! before it sends the ciphertext anywhere, so a later rollback to an older state is refused.

use rand_core::{CryptoRng, RngCore};

use crate::contract::ApprovalContext;
use crate::jwe::{encrypt_context, ContextRecipient, EncryptError, X25519PublicKey};
use crate::recipients::{select_recipient_set, RecipientSelectionError};

/// An [`ApprovalContext`] encrypted to the root-vouched recipients, plus the account-state
/// sequence that chose them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContext {
    /// The General-JSON JWE, one recipient entry per selected device (`kid` = device id); the
    /// envelope's `context_ciphertext`.
    pub ciphertext: String,
    /// The highest verified account-state sequence the recipients were selected from.
    pub sequence: u64,
}

/// Why a context could not be sealed. Every variant means "nothing was encrypted; do not send".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealContextError {
    /// No recipient set could be selected from the supplied account state.
    Recipients(RecipientSelectionError),
    /// Encryption to the selected recipients was refused. Selection already rejects small-order
    /// keys, so this is defense in depth against the two checks ever diverging.
    Encrypt(EncryptError),
}

impl std::fmt::Display for SealContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recipients(e) => write!(f, "no recipients: {e}"),
            Self::Encrypt(e) => write!(f, "encryption refused: {e}"),
        }
    }
}

impl std::error::Error for SealContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recipients(e) => Some(e),
            Self::Encrypt(e) => Some(e),
        }
    }
}

impl From<RecipientSelectionError> for SealContextError {
    fn from(e: RecipientSelectionError) -> Self {
        Self::Recipients(e)
    }
}

impl From<EncryptError> for SealContextError {
    fn from(e: EncryptError) -> Self {
        Self::Encrypt(e)
    }
}

/// Encrypts `context` to the devices that root-signed account state selects, and nothing else.
///
/// `account_states`, `expected_account_id`, `account_root`, `now_ms` and `min_sequence` are exactly
/// [`crate::select_recipients`]'s inputs and follow its rules. Randomness comes from `rng`, as for
/// [`encrypt_context`].
///
/// # Errors
///
/// [`SealContextError::Recipients`] whenever [`crate::select_recipients`] would fail (including a
/// small-order recipient key), or [`SealContextError::Encrypt`] if encryption refuses the selected
/// set. Either way nothing is returned to send.
pub fn seal_context_for_account_state(
    context: &ApprovalContext,
    account_states: &[&str],
    expected_account_id: &str,
    account_root: &crate::PublicKey,
    now_ms: i64,
    min_sequence: Option<u64>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<SealedContext, SealContextError> {
    let set = select_recipient_set(
        account_states,
        expected_account_id,
        account_root,
        now_ms,
        min_sequence,
    )?;
    let keys: Vec<X25519PublicKey> = set
        .recipients
        .iter()
        .map(|r| X25519PublicKey::from_bytes(&r.encryption_pubkey))
        .collect();
    let recipients: Vec<ContextRecipient<'_>> = set
        .recipients
        .iter()
        .zip(&keys)
        .map(|(r, public_key)| ContextRecipient {
            device_id: &r.device_id,
            public_key,
        })
        .collect();
    Ok(SealedContext {
        ciphertext: encrypt_context(context, &recipients, rng)?,
        sequence: set.sequence,
    })
}

#[cfg(test)]
mod tests {
    //! @see docs/enrollment.md §Model (recipient selection rule)
    //! @see docs/contract.md §Invariants (E2EE; fail-closed)
    //! @see https://www.rfc-editor.org/rfc/rfc7516 §7.2 (General JWE JSON Serialization)
    use super::*;
    use crate::account::account_id_for_root;
    use crate::contract::{ActionRecord, Actor, Constraints, Decision, Facts, Surface};
    use crate::crypto::{
        sign_account_state, AccountState, AccountStateDevice, AccountStateRevocation,
        AccountStateRevocationKind, SigningKeyPair,
    };
    use crate::jwe::{decrypt_context, JweError, X25519KeyPair};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const ROOT_SEED: [u8; 32] = [0x11; 32];
    const RNG_SEED: [u8; 32] = [0x42; 32];
    const NOW_MS: i64 = 1_800_000_000_000;
    const PHONE_SEED: [u8; 32] = [0x01; 32];
    const LAPTOP_SEED: [u8; 32] = [0x02; 32];
    const REVOKED_SEED: [u8; 32] = [0x03; 32];
    /// A key the relay lists (or that was enrolled through pairing) but the root never vouched for.
    const INJECTED_SEED: [u8; 32] = [0xEE; 32];

    fn root() -> SigningKeyPair {
        SigningKeyPair::from_seed(&ROOT_SEED)
    }

    fn account_id() -> String {
        account_id_for_root(&root().public_key())
    }

    fn device(id: &str, seed: &[u8; 32]) -> AccountStateDevice {
        AccountStateDevice {
            device_id: id.to_string(),
            encryption_pubkey: X25519KeyPair::from_seed(seed).public_key().to_bytes(),
            signing_pubkey: [0x01; 32],
            status: "active".to_string(),
            cert_expires_at: None,
        }
    }

    fn signed(sequence: u64, devices: Vec<AccountStateDevice>, revoked: &[&str]) -> String {
        sign_account_state(
            &AccountState {
                v: 1,
                account_id: account_id(),
                sequence,
                current_root: root().public_key().to_bytes(),
                previous_roots: vec![],
                devices,
                actors: vec![],
                revocations: revoked
                    .iter()
                    .map(|id| AccountStateRevocation {
                        kind: AccountStateRevocationKind::Device,
                        id: (*id).to_string(),
                        revoked_at: 1_700_000_000_000,
                        reason: None,
                    })
                    .collect(),
            },
            &root(),
        )
    }

    fn context() -> ApprovalContext {
        ApprovalContext {
            action: ActionRecord {
                record_schema_version: 3,
                surface: Surface::Command,
                facts: Facts {
                    argv: None,
                    cwd: None,
                    server: None,
                    tool: None,
                    params: None,
                    raw: Some("git push --force".to_string()),
                    operation: None,
                    paths: None,
                    diff_summary: None,
                    diff_hash: None,
                },
            },
            summary: "force-push main".to_string(),
            actor: Actor {
                id: "machine:test".to_string(),
                kind: "claude-code".to_string(),
                attestation: None,
            },

            reversible: Some(false),
            constraints: Constraints {
                allowed_decisions: vec![Decision::Approved, Decision::Denied],
                challenge_required: false,
            },
            chain: None,
        }
    }

    fn seal(docs: &[String], min_sequence: Option<u64>) -> Result<SealedContext, SealContextError> {
        let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
        seal_context_for_account_state(
            &context(),
            &refs,
            &account_id(),
            &root().public_key(),
            NOW_MS,
            min_sequence,
            &mut ChaCha20Rng::from_seed(RNG_SEED),
        )
    }

    /// The JWE recipient `kid`s, in order (RFC 7516 §7.2.1 `recipients[].header.kid`).
    fn recipient_kids(ciphertext: &str) -> Vec<String> {
        let jwe: serde_json::Value = serde_json::from_str(ciphertext).expect("JWE is JSON");
        jwe["recipients"]
            .as_array()
            .expect("General JWE has a recipients array")
            .iter()
            .map(|r| r["header"]["kid"].as_str().expect("kid").to_string())
            .collect()
    }

    #[test]
    fn every_selected_device_can_decrypt_the_sealed_context() {
        let docs = [signed(
            4,
            vec![device("phone", &PHONE_SEED), device("laptop", &LAPTOP_SEED)],
            &[],
        )];
        let sealed = seal(&docs, None).expect("seals");
        assert_eq!(sealed.sequence, 4);
        // Selection order is sorted by device id.
        assert_eq!(recipient_kids(&sealed.ciphertext), ["laptop", "phone"]);
        for (id, seed) in [("phone", &PHONE_SEED), ("laptop", &LAPTOP_SEED)] {
            let opened = decrypt_context(&sealed.ciphertext, id, &X25519KeyPair::from_seed(seed))
                .expect("a vouched device decrypts");
            assert_eq!(opened, context());
        }
    }

    #[test]
    fn a_key_the_root_never_vouched_for_gets_no_recipient_entry() {
        // The injected key is not in account state, so it cannot be a recipient whatever the relay
        // lists; it can neither find its own entry nor open another device's.
        let docs = [signed(1, vec![device("phone", &PHONE_SEED)], &[])];
        let sealed = seal(&docs, None).expect("seals");
        assert_eq!(recipient_kids(&sealed.ciphertext), ["phone"]);
        let injected = X25519KeyPair::from_seed(&INJECTED_SEED);
        assert_eq!(
            decrypt_context(&sealed.ciphertext, "injected", &injected),
            Err(JweError::NoRecipientForDevice)
        );
        assert_eq!(
            decrypt_context(&sealed.ciphertext, "phone", &injected),
            Err(JweError::KeyUnwrapFailed)
        );
    }

    #[test]
    fn a_revoked_device_gets_no_recipient_entry() {
        let docs = [signed(
            2,
            vec![device("phone", &PHONE_SEED), device("old", &REVOKED_SEED)],
            &["old"],
        )];
        let sealed = seal(&docs, None).expect("seals");
        assert_eq!(recipient_kids(&sealed.ciphertext), ["phone"]);
        assert_eq!(
            decrypt_context(
                &sealed.ciphertext,
                "old",
                &X25519KeyPair::from_seed(&REVOKED_SEED)
            ),
            Err(JweError::NoRecipientForDevice)
        );
    }

    #[test]
    fn reports_the_highest_sequence_it_selected_from() {
        let docs = [
            signed(7, vec![device("phone", &PHONE_SEED)], &[]),
            signed(9, vec![device("laptop", &LAPTOP_SEED)], &[]),
        ];
        let sealed = seal(&docs, Some(9)).expect("seals at the floor");
        assert_eq!(sealed.sequence, 9);
        assert_eq!(recipient_kids(&sealed.ciphertext), ["laptop"]);
    }

    #[test]
    fn reports_the_selected_sequence_not_the_callers_floor() {
        // A floor below the highest sequence must not leak into the result: the caller persists
        // this value, so reporting the floor would let a later rollback to 3 or 4 through.
        let docs = [signed(5, vec![device("phone", &PHONE_SEED)], &[])];
        assert_eq!(seal(&docs, Some(2)).map(|s| s.sequence), Ok(5));
        assert_eq!(seal(&docs, None).map(|s| s.sequence), Ok(5));
    }

    #[test]
    fn nothing_is_sealed_when_selection_fails() {
        assert_eq!(
            seal(&[], None),
            Err(SealContextError::Recipients(
                RecipientSelectionError::NoAccountState
            ))
        );
        let docs = [signed(3, vec![device("phone", &PHONE_SEED)], &["phone"])];
        assert_eq!(
            seal(&docs, None),
            Err(SealContextError::Recipients(
                RecipientSelectionError::NoActiveRecipients
            ))
        );
        let mut small_order = device("evil", &PHONE_SEED);
        small_order.encryption_pubkey = crate::jwe::X25519_SMALL_ORDER_POINTS[1];
        let docs = [signed(
            3,
            vec![device("phone", &PHONE_SEED), small_order],
            &[],
        )];
        assert_eq!(
            seal(&docs, None),
            Err(SealContextError::Recipients(
                RecipientSelectionError::InvalidEncryptionKey {
                    device_id: "evil".to_string()
                }
            ))
        );
        let docs = [signed(3, vec![device("phone", &PHONE_SEED)], &[])];
        assert_eq!(
            seal(&docs, Some(4)),
            Err(SealContextError::Recipients(
                RecipientSelectionError::BelowSequenceFloor {
                    highest: 3,
                    min_sequence: 4
                }
            ))
        );
    }
}
