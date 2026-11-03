//! **Recipient selection**: which devices an integrator may encrypt an `ApprovalContext` to.
//!
//! See `docs/enrollment.md` §Model (registry vs. signed account state) and `docs/contract.md`
//! §Invariants (E2EE, fail-closed).
//!
//! # Why recipients come from root-signed account state
//!
//! Every device an integrator encrypts to can read the request in plaintext. The relay's device
//! registry (`GET /{acct}/devices`) is routing data: the relay operator — or anyone who got a key
//! enrolled — controls it, so it can never decide who reads a request. The account root already
//! signs the list of devices it vouches for: [`AccountState::devices`], whose `encryption_pubkey`
//! the root holder fills from authenticated enrollment material. [`select_recipients`] reads that
//! list, and only that list.
//!
//! # Rules (fail-closed)
//!
//! - **Every supplied document must verify** against the configured root for the expected account
//!   ([`crate::verify_account_state`]). One bad document fails the whole call
//!   ([`RecipientSelectionError::AccountState`]) rather than being skipped, matching
//!   [`crate::revoked_device_ids`]: silently dropping a document a caller can influence could mask
//!   the newest state.
//! - **Only the highest `sequence` counts.** Lower-sequence documents contribute nothing, so an old
//!   document can neither add a device back nor resurrect a revoked one.
//! - **Recipients are the `active` devices, minus revoked ids.** A device whose `status` is anything
//!   but [`DEVICE_STATUS_ACTIVE`], or whose id has a device revocation in the same document, is not
//!   a recipient.
//! - **Conflicting same-sequence documents narrow, never widen.** When several verified documents
//!   share the highest sequence, a device is a recipient only if *every* one of them lists it as an
//!   active, unrevoked device with the *same* encryption key. This is the confidentiality
//!   counterpart of `revoked_device_ids` taking the union of revocations: a conflict can only remove
//!   readers. A device id listed twice in one document with different keys is likewise excluded.
//! - **Never an empty list.** No document, no remaining recipient, or more than [`MAX_RECIPIENTS`]
//!   is an error — the caller must not encrypt (and so must not send) in any of those cases.
//!
//! The result is sorted by `device_id`, so it is deterministic across platforms.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::{
    verify_account_state, AccountState, AccountStateError, AccountStateRevocationKind,
};

/// The `AccountState` device status that makes a device a recipient. Any other value (for
/// example `"revoked"` or `"pending"`) is not.
pub const DEVICE_STATUS_ACTIVE: &str = "active";

/// The most recipients one request may be encrypted to.
///
/// A personal account has a handful of approver devices. The cap bounds the size of the JWE
/// recipient list and the damage of a mis-authored account state that lists far more devices than
/// any real account has: such a state stops requests (fail-closed) instead of quietly widening who
/// can read them. Raising it is a deliberate contract change.
pub const MAX_RECIPIENTS: usize = 16;

/// One device the integrator may encrypt to: its id (the JWE recipient `kid`) and its X25519
/// encryption public key, exactly as the root signed them in account state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub device_id: String,
    pub encryption_pubkey: [u8; 32],
}

/// Why no recipient set could be selected. Every variant means "do not encrypt, do not send".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientSelectionError {
    /// No account-state document was supplied.
    NoAccountState,
    /// A supplied document did not verify against the root for the expected account.
    AccountState(AccountStateError),
    /// The highest-sequence state leaves no active, unrevoked device.
    NoActiveRecipients,
    /// The highest-sequence state yields more than [`MAX_RECIPIENTS`] recipients.
    TooManyRecipients { count: usize },
}

impl std::fmt::Display for RecipientSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAccountState => write!(f, "no account-state document supplied"),
            Self::AccountState(e) => write!(f, "account state rejected: {e}"),
            Self::NoActiveRecipients => {
                write!(f, "account state has no active, unrevoked device")
            }
            Self::TooManyRecipients { count } => write!(
                f,
                "account state yields {count} recipients, more than the maximum {MAX_RECIPIENTS}"
            ),
        }
    }
}

impl std::error::Error for RecipientSelectionError {}

impl From<AccountStateError> for RecipientSelectionError {
    fn from(e: AccountStateError) -> Self {
        Self::AccountState(e)
    }
}

/// The active, unrevoked devices of one document, keyed by device id. A device id listed with two
/// different keys maps to `None` (ambiguous, so never a recipient).
fn active_devices(state: &AccountState) -> BTreeMap<&str, Option<[u8; 32]>> {
    let revoked: BTreeSet<&str> = state
        .revocations
        .iter()
        .filter(|r| r.kind == AccountStateRevocationKind::Device)
        .map(|r| r.id.as_str())
        .collect();

    let mut devices: BTreeMap<&str, Option<[u8; 32]>> = BTreeMap::new();
    for device in &state.devices {
        if device.status != DEVICE_STATUS_ACTIVE || revoked.contains(device.device_id.as_str()) {
            continue;
        }
        devices
            .entry(device.device_id.as_str())
            .and_modify(|key| {
                if *key != Some(device.encryption_pubkey) {
                    *key = None;
                }
            })
            .or_insert(Some(device.encryption_pubkey));
    }
    devices
}

/// Selects the devices an `ApprovalContext` may be encrypted to, from root-signed account state.
///
/// `account_states` is every account-state document the caller holds (compact JWS); each must
/// verify against `account_root` for `expected_account_id`. See the module docs for the rules.
///
/// # Errors
///
/// [`RecipientSelectionError`] when no document is supplied, any document fails verification, no
/// recipient remains, or more than [`MAX_RECIPIENTS`] remain.
pub fn select_recipients(
    account_states: &[&str],
    expected_account_id: &str,
    account_root: &crate::PublicKey,
) -> Result<Vec<Recipient>, RecipientSelectionError> {
    if account_states.is_empty() {
        return Err(RecipientSelectionError::NoAccountState);
    }

    let mut verified = Vec::with_capacity(account_states.len());
    for compact in account_states {
        verified.push(verify_account_state(
            compact,
            expected_account_id,
            account_root,
        )?);
    }
    let highest = verified
        .iter()
        .map(|state| state.sequence)
        .max()
        .ok_or(RecipientSelectionError::NoAccountState)?;

    let mut current: Option<BTreeMap<&str, Option<[u8; 32]>>> = None;
    for state in verified.iter().filter(|state| state.sequence == highest) {
        let devices = active_devices(state);
        current = Some(match current {
            None => devices,
            // Intersection: keep a device only where this document agrees on the same key.
            Some(mut acc) => {
                acc.retain(|id, key| key.is_some() && devices.get(id) == Some(key));
                acc
            }
        });
    }

    let recipients: Vec<Recipient> = current
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(device_id, key)| {
            key.map(|encryption_pubkey| Recipient {
                device_id: device_id.to_string(),
                encryption_pubkey,
            })
        })
        .collect();

    if recipients.is_empty() {
        return Err(RecipientSelectionError::NoActiveRecipients);
    }
    if recipients.len() > MAX_RECIPIENTS {
        return Err(RecipientSelectionError::TooManyRecipients {
            count: recipients.len(),
        });
    }
    Ok(recipients)
}

#[cfg(test)]
mod tests {
    //! @see docs/enrollment.md §Model (registry vs. signed account state)
    //! @see docs/contract.md §Invariants (E2EE; fail-closed)
    use super::*;
    use crate::account::account_id_for_root;
    use crate::crypto::{
        sign_account_state, AccountStateDevice, AccountStateRevocation, SigningKeyPair,
    };

    const ROOT_SEED: [u8; 32] = [0x11; 32];
    const OTHER_ROOT_SEED: [u8; 32] = [0x33; 32];
    const KEY_A: [u8; 32] = [0xA1; 32];
    const KEY_B: [u8; 32] = [0xB2; 32];
    const KEY_C: [u8; 32] = [0xC3; 32];

    fn root() -> SigningKeyPair {
        SigningKeyPair::from_seed(&ROOT_SEED)
    }

    fn account_id() -> String {
        account_id_for_root(&root().public_key())
    }

    fn device(id: &str, key: [u8; 32], status: &str) -> AccountStateDevice {
        AccountStateDevice {
            device_id: id.to_string(),
            encryption_pubkey: key,
            signing_pubkey: [0x01; 32],
            status: status.to_string(),
            cert_expires_at: None,
        }
    }

    fn revoke(id: &str) -> AccountStateRevocation {
        AccountStateRevocation {
            kind: AccountStateRevocationKind::Device,
            id: id.to_string(),
            revoked_at: 1_700_000_000_000,
            reason: None,
        }
    }

    fn state(
        sequence: u64,
        devices: Vec<AccountStateDevice>,
        revocations: Vec<AccountStateRevocation>,
    ) -> AccountState {
        AccountState {
            v: 1,
            account_id: account_id(),
            sequence,
            current_root: root().public_key().to_bytes(),
            previous_roots: vec![],
            devices,
            actors: vec![],
            revocations,
        }
    }

    fn signed(state: &AccountState) -> String {
        sign_account_state(state, &root())
    }

    fn select(docs: &[String]) -> Result<Vec<Recipient>, RecipientSelectionError> {
        let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
        select_recipients(&refs, &account_id(), &root().public_key())
    }

    fn recipient(id: &str, key: [u8; 32]) -> Recipient {
        Recipient {
            device_id: id.to_string(),
            encryption_pubkey: key,
        }
    }

    #[test]
    fn returns_active_devices_sorted_by_id() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-b", KEY_B, "active"),
                device("dev-a", KEY_A, "active"),
            ],
            vec![],
        ));
        assert_eq!(
            select(&[doc]),
            Ok(vec![recipient("dev-a", KEY_A), recipient("dev-b", KEY_B)])
        );
    }

    #[test]
    fn excludes_devices_that_are_not_active() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "revoked"),
                device("dev-c", KEY_C, "Active"),
            ],
            vec![],
        ));
        assert_eq!(select(&[doc]), Ok(vec![recipient("dev-a", KEY_A)]));
    }

    #[test]
    fn excludes_a_revoked_device_even_if_listed_active() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
            ],
            vec![revoke("dev-b")],
        ));
        assert_eq!(select(&[doc]), Ok(vec![recipient("dev-a", KEY_A)]));
    }

    #[test]
    fn ignores_actor_revocations_with_a_device_id() {
        let mut actor_revocation = revoke("dev-a");
        actor_revocation.kind = AccountStateRevocationKind::Actor;
        let doc = signed(&state(
            1,
            vec![device("dev-a", KEY_A, "active")],
            vec![actor_revocation],
        ));
        assert_eq!(select(&[doc]), Ok(vec![recipient("dev-a", KEY_A)]));
    }

    #[test]
    fn only_the_highest_sequence_counts() {
        let old = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-old", KEY_B, "active"),
            ],
            vec![],
        ));
        let new = signed(&state(2, vec![device("dev-a", KEY_A, "active")], vec![]));
        // Order of the inputs does not matter.
        assert_eq!(
            select(&[new.clone(), old.clone()]),
            Ok(vec![recipient("dev-a", KEY_A)])
        );
        assert_eq!(select(&[old, new]), Ok(vec![recipient("dev-a", KEY_A)]));
    }

    #[test]
    fn a_lower_sequence_cannot_resurrect_a_revoked_device() {
        let old = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
            ],
            vec![],
        ));
        let new = signed(&state(
            2,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
            ],
            vec![revoke("dev-b")],
        ));
        assert_eq!(select(&[old, new]), Ok(vec![recipient("dev-a", KEY_A)]));
    }

    #[test]
    fn equal_sequence_conflicts_narrow_to_agreed_devices() {
        let a = signed(&state(
            3,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
                device("dev-c", KEY_C, "active"),
            ],
            vec![],
        ));
        let b = signed(&state(
            3,
            vec![
                device("dev-a", KEY_A, "active"),
                // Same id, different key: no agreement on who dev-b is.
                device("dev-b", KEY_C, "active"),
                device("dev-c", KEY_C, "active"),
            ],
            // Revoked in one sibling: excluded (the union of revocations).
            vec![revoke("dev-c")],
        ));
        assert_eq!(select(&[a, b]), Ok(vec![recipient("dev-a", KEY_A)]));
    }

    #[test]
    fn equal_sequence_device_missing_from_one_sibling_is_excluded() {
        let a = signed(&state(
            3,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
            ],
            vec![],
        ));
        let b = signed(&state(3, vec![device("dev-a", KEY_A, "active")], vec![]));
        assert_eq!(select(&[a, b]), Ok(vec![recipient("dev-a", KEY_A)]));
    }

    #[test]
    fn a_device_listed_twice_with_different_keys_is_excluded() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
                device("dev-b", KEY_C, "active"),
            ],
            vec![],
        ));
        assert_eq!(select(&[doc]), Ok(vec![recipient("dev-a", KEY_A)]));
    }

    #[test]
    fn a_device_listed_twice_with_the_same_key_is_one_recipient() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-a", KEY_A, "active"),
            ],
            vec![],
        ));
        assert_eq!(select(&[doc]), Ok(vec![recipient("dev-a", KEY_A)]));
    }

    #[test]
    fn rejects_no_account_state() {
        assert_eq!(select(&[]), Err(RecipientSelectionError::NoAccountState));
    }

    #[test]
    fn rejects_state_signed_by_another_root() {
        let other = SigningKeyPair::from_seed(&OTHER_ROOT_SEED);
        let forged = sign_account_state(
            &state(9, vec![device("dev-evil", KEY_C, "active")], vec![]),
            &other,
        );
        assert_eq!(
            select(&[forged]),
            Err(RecipientSelectionError::AccountState(
                AccountStateError::InvalidSignature
            ))
        );
    }

    #[test]
    fn one_bad_document_fails_the_whole_selection() {
        let good = signed(&state(1, vec![device("dev-a", KEY_A, "active")], vec![]));
        let other = SigningKeyPair::from_seed(&OTHER_ROOT_SEED);
        let forged = sign_account_state(&state(9, vec![], vec![]), &other);
        assert_eq!(
            select(&[good, forged]),
            Err(RecipientSelectionError::AccountState(
                AccountStateError::InvalidSignature
            ))
        );
    }

    #[test]
    fn rejects_state_for_another_account() {
        let mut wrong = state(1, vec![device("dev-a", KEY_A, "active")], vec![]);
        wrong.account_id = "some-other-account".to_string();
        assert_eq!(
            select(&[signed(&wrong)]),
            Err(RecipientSelectionError::AccountState(
                AccountStateError::AccountMismatch
            ))
        );
    }

    #[test]
    fn rejects_junk() {
        assert_eq!(
            select(&["not.a.jws".to_string()]),
            Err(RecipientSelectionError::AccountState(
                AccountStateError::InvalidSignature
            ))
        );
    }

    #[test]
    fn rejects_when_every_device_is_revoked() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
            ],
            vec![revoke("dev-a"), revoke("dev-b")],
        ));
        assert_eq!(
            select(&[doc]),
            Err(RecipientSelectionError::NoActiveRecipients)
        );
    }

    #[test]
    fn rejects_a_state_with_no_devices() {
        let doc = signed(&state(1, vec![], vec![]));
        assert_eq!(
            select(&[doc]),
            Err(RecipientSelectionError::NoActiveRecipients)
        );
    }

    #[test]
    fn accepts_exactly_the_maximum_and_rejects_one_more() {
        let devices = |n: usize| -> Vec<AccountStateDevice> {
            (0..n)
                .map(|i| device(&format!("dev-{i:02}"), [i as u8; 32], "active"))
                .collect()
        };
        let at_cap = signed(&state(1, devices(MAX_RECIPIENTS), vec![]));
        assert_eq!(select(&[at_cap]).map(|r| r.len()), Ok(MAX_RECIPIENTS));

        let over = signed(&state(2, devices(MAX_RECIPIENTS + 1), vec![]));
        assert_eq!(
            select(&[over]),
            Err(RecipientSelectionError::TooManyRecipients {
                count: MAX_RECIPIENTS + 1
            })
        );
    }

    #[test]
    fn the_cap_counts_recipients_after_revocation() {
        let mut devices: Vec<AccountStateDevice> = (0..=MAX_RECIPIENTS)
            .map(|i| device(&format!("dev-{i:02}"), [i as u8; 32], "active"))
            .collect();
        devices.push(device("dev-extra", KEY_A, "revoked"));
        let doc = signed(&state(1, devices, vec![revoke("dev-00")]));
        assert_eq!(select(&[doc]).map(|r| r.len()), Ok(MAX_RECIPIENTS));
    }
}
