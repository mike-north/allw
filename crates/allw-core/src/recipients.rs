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
//! - **The input is bounded.** More than [`MAX_ACCOUNT_STATES`] documents is an error
//!   ([`RecipientSelectionError::TooManyAccountStates`]), checked before any signature work.
//! - **Every supplied document must verify** against the configured root for the expected account
//!   ([`crate::verify_account_state`]). One bad document fails the whole call
//!   ([`RecipientSelectionError::AccountState`]) rather than being skipped, matching
//!   [`crate::revoked_device_ids`]: silently dropping a document a caller can influence could mask
//!   the newest state.
//! - **Only the highest `sequence` counts.** Lower-sequence documents contribute nothing, so an old
//!   document can neither add a device back nor resurrect a revoked one.
//! - **The highest sequence must reach the caller's floor.** A caller that has already seen
//!   sequence `n` passes `min_sequence: Some(n)`; if the highest supplied sequence is below it the
//!   call fails ([`RecipientSelectionError::BelowSequenceFloor`]). It never falls back to the older
//!   state, which is exactly what a rollback would serve.
//! - **Recipients are the `active`, unexpired devices, minus revoked ids.** A device whose `status`
//!   is anything but [`DEVICE_STATUS_ACTIVE`], whose id has a device revocation in the same
//!   document, or whose signed `cert_expires_at` is at or before `now_ms`, is not a recipient. An
//!   absent `cert_expires_at` means the root set no expiry.
//! - **Revocation is per document, not permanent.** Only the highest sequence counts, so a later
//!   root-signed document that lists a previously revoked device as active, with no revocation
//!   entry, makes it a recipient again. That is root-authorized: the root holder can always
//!   re-enroll a device, and the signed sequence is the authority.
//! - **Conflicting same-sequence documents narrow, never widen.** When several verified documents
//!   share the highest sequence, a device is a recipient only if *every* one of them lists it as an
//!   active, unrevoked, unexpired device with the *same* encryption key. This is the
//!   confidentiality counterpart of `revoked_device_ids` taking the union of revocations: a
//!   conflict can only remove readers. Within one document the same holds: a device id listed more
//!   than once is a recipient only if *every* entry for it is active and unexpired with the same
//!   key, so a duplicate entry that is not active, has expired, or carries another key excludes it.
//! - **Malformed device entries fail the call.** An empty `device_id` anywhere in a
//!   highest-sequence document ([`RecipientSelectionError::EmptyDeviceId`]), or a small-order
//!   X25519 encryption key on a selected recipient
//!   ([`RecipientSelectionError::InvalidEncryptionKey`], per
//!   [`crate::is_small_order_x25519_public_key`]), means the root signed something no real
//!   enrollment produces; the caller must not guess. A small-order key would make the request
//!   readable by anyone, so it fails the whole call rather than dropping that one device.
//! - **Never an empty list.** No document, no remaining recipient, or more than [`MAX_RECIPIENTS`]
//!   is an error — the caller must not encrypt (and so must not send) in any of those cases.
//!
//! The result is sorted by `device_id`, so it is deterministic across platforms.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::{
    verify_account_state, AccountState, AccountStateError, AccountStateRevocationKind,
};
use crate::jwe::{is_small_order_x25519_public_key, write_untrusted_device_id};

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

/// The most account-state documents one selection may be given.
///
/// The relay serves only the documents at its highest verified sequence, so a real caller holds a
/// few. The cap bounds the signature-verification work a caller-influenced input can demand;
/// exceeding it is an error, never a truncation (dropping documents could drop the newest one).
pub const MAX_ACCOUNT_STATES: usize = 64;

/// One device the integrator may encrypt to: its id (the JWE recipient `kid`) and its X25519
/// encryption public key, exactly as the root signed them in account state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub device_id: String,
    pub encryption_pubkey: [u8; 32],
}

/// Why no recipient set could be selected. Every variant means "do not encrypt, do not send".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecipientSelectionError {
    /// No account-state document was supplied.
    NoAccountState,
    /// More than [`MAX_ACCOUNT_STATES`] documents were supplied.
    TooManyAccountStates { count: usize },
    /// A supplied document did not verify against the root for the expected account.
    AccountState(AccountStateError),
    /// The highest supplied sequence is below the caller's persisted floor (a rollback).
    BelowSequenceFloor { highest: u64, min_sequence: u64 },
    /// A highest-sequence document lists a device with an empty `device_id`.
    EmptyDeviceId,
    /// A selected recipient's encryption key is a small-order X25519 point (readable by anyone).
    InvalidEncryptionKey { device_id: String },
    /// The highest-sequence state leaves no active, unrevoked, unexpired device.
    NoActiveRecipients,
    /// The highest-sequence state yields more than [`MAX_RECIPIENTS`] recipients.
    TooManyRecipients { count: usize },
}

impl std::fmt::Display for RecipientSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAccountState => write!(f, "no account-state document supplied"),
            Self::TooManyAccountStates { count } => write!(
                f,
                "{count} account-state documents supplied, more than the maximum \
                 {MAX_ACCOUNT_STATES}"
            ),
            Self::AccountState(e) => write!(f, "account state rejected: {e}"),
            Self::BelowSequenceFloor {
                highest,
                min_sequence,
            } => write!(
                f,
                "highest account-state sequence {highest} is below the required floor \
                 {min_sequence}"
            ),
            Self::EmptyDeviceId => {
                write!(f, "account state lists a device with an empty device_id")
            }
            Self::InvalidEncryptionKey { device_id } => {
                // The id is root-signed but still untrusted text: escaped and length-capped, as
                // in `EncryptError::LowOrderRecipientKey`.
                f.write_str("account state gives device ")?;
                write_untrusted_device_id(f, device_id)?;
                f.write_str(" a small-order encryption key")
            }
            Self::NoActiveRecipients => {
                write!(
                    f,
                    "account state has no active, unrevoked, unexpired device"
                )
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

/// Every device id in one document at `now_ms`, mapped to the key it may be encrypted to, or to
/// `None` when it is not a recipient. An id is `Some(key)` only if it is not revoked and *every*
/// entry for it is active and unexpired with that same key; any other entry for the id (not active,
/// expired, or another key) makes it `None` — ambiguity never widens the set.
fn active_devices(
    state: &AccountState,
    now_ms: i64,
) -> Result<BTreeMap<&str, Option<[u8; 32]>>, RecipientSelectionError> {
    let revoked: BTreeSet<&str> = state
        .revocations
        .iter()
        .filter(|r| r.kind == AccountStateRevocationKind::Device)
        .map(|r| r.id.as_str())
        .collect();

    let mut devices: BTreeMap<&str, Option<[u8; 32]>> = BTreeMap::new();
    for device in &state.devices {
        if device.device_id.is_empty() {
            return Err(RecipientSelectionError::EmptyDeviceId);
        }
        let expired = device
            .cert_expires_at
            .is_some_and(|expires_at| expires_at <= now_ms);
        let eligible = device.status == DEVICE_STATUS_ACTIVE
            && !expired
            && !revoked.contains(device.device_id.as_str());
        let this_entry = eligible.then_some(device.encryption_pubkey);
        devices
            .entry(device.device_id.as_str())
            .and_modify(|key| {
                if *key != this_entry {
                    *key = None;
                }
            })
            .or_insert(this_entry);
    }
    Ok(devices)
}

/// Selects the devices an `ApprovalContext` may be encrypted to, from root-signed account state.
///
/// - `account_states`: every account-state document the caller holds (compact JWS); each must
///   verify against `account_root` for `expected_account_id`.
/// - `now_ms`: the current Unix time in milliseconds, against which each device's signed
///   `cert_expires_at` is checked.
/// - `min_sequence`: the highest sequence the caller has already accepted, if it persists one; the
///   selection fails rather than use anything older.
///
/// See the module docs for the rules.
///
/// # Errors
///
/// [`RecipientSelectionError`] when no document or too many are supplied, any document fails
/// verification, the highest sequence is below `min_sequence`, a device entry is malformed, no
/// recipient remains, or more than [`MAX_RECIPIENTS`] remain.
pub fn select_recipients(
    account_states: &[&str],
    expected_account_id: &str,
    account_root: &crate::PublicKey,
    now_ms: i64,
    min_sequence: Option<u64>,
) -> Result<Vec<Recipient>, RecipientSelectionError> {
    select_recipient_set(
        account_states,
        expected_account_id,
        account_root,
        now_ms,
        min_sequence,
    )
    .map(|set| set.recipients)
}

/// A selected recipient set together with the account-state `sequence` it was selected from.
///
/// The sequence is what a caller that persists a floor records once it has used this set; it is
/// crate-internal because only [`crate::sealing`] needs it alongside the recipients.
pub(crate) struct RecipientSet {
    pub(crate) recipients: Vec<Recipient>,
    pub(crate) sequence: u64,
}

/// [`select_recipients`], also reporting the highest verified sequence the selection used.
pub(crate) fn select_recipient_set(
    account_states: &[&str],
    expected_account_id: &str,
    account_root: &crate::PublicKey,
    now_ms: i64,
    min_sequence: Option<u64>,
) -> Result<RecipientSet, RecipientSelectionError> {
    if account_states.is_empty() {
        return Err(RecipientSelectionError::NoAccountState);
    }
    if account_states.len() > MAX_ACCOUNT_STATES {
        return Err(RecipientSelectionError::TooManyAccountStates {
            count: account_states.len(),
        });
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
    if let Some(min_sequence) = min_sequence {
        if highest < min_sequence {
            return Err(RecipientSelectionError::BelowSequenceFloor {
                highest,
                min_sequence,
            });
        }
    }

    let mut current: Option<BTreeMap<&str, Option<[u8; 32]>>> = None;
    for state in verified.iter().filter(|state| state.sequence == highest) {
        let devices = active_devices(state, now_ms)?;
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

    if let Some(bad) = recipients
        .iter()
        .find(|r| is_small_order_x25519_public_key(&r.encryption_pubkey))
    {
        return Err(RecipientSelectionError::InvalidEncryptionKey {
            device_id: bad.device_id.clone(),
        });
    }
    if recipients.is_empty() {
        return Err(RecipientSelectionError::NoActiveRecipients);
    }
    if recipients.len() > MAX_RECIPIENTS {
        return Err(RecipientSelectionError::TooManyRecipients {
            count: recipients.len(),
        });
    }
    Ok(RecipientSet {
        recipients,
        sequence: highest,
    })
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

    /// The injected "now" for every selection unless a test passes its own.
    const NOW_MS: i64 = 1_800_000_000_000;

    fn select(docs: &[String]) -> Result<Vec<Recipient>, RecipientSelectionError> {
        select_with(docs, NOW_MS, None)
    }

    fn select_with(
        docs: &[String],
        now_ms: i64,
        min_sequence: Option<u64>,
    ) -> Result<Vec<Recipient>, RecipientSelectionError> {
        let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
        select_recipients(
            &refs,
            &account_id(),
            &root().public_key(),
            now_ms,
            min_sequence,
        )
    }

    fn expiring(id: &str, key: [u8; 32], cert_expires_at: i64) -> AccountStateDevice {
        AccountStateDevice {
            cert_expires_at: Some(cert_expires_at),
            ..device(id, key, "active")
        }
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
    fn a_duplicate_entry_that_is_not_active_excludes_the_device() {
        // Regression: an ineligible duplicate entry used to be skipped, leaving the active entry
        // (possibly with another key) selected. Either order, different or same key.
        for (first, second) in [
            (
                device("dev-b", KEY_B, "active"),
                device("dev-b", KEY_C, "revoked"),
            ),
            (
                device("dev-b", KEY_C, "revoked"),
                device("dev-b", KEY_B, "active"),
            ),
            (
                device("dev-b", KEY_B, "active"),
                device("dev-b", KEY_B, "revoked"),
            ),
        ] {
            let doc = signed(&state(
                1,
                vec![device("dev-a", KEY_A, "active"), first, second],
                vec![],
            ));
            assert_eq!(select(&[doc]), Ok(vec![recipient("dev-a", KEY_A)]));
        }
    }

    #[test]
    fn a_duplicate_entry_that_has_expired_excludes_the_device() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
                expiring("dev-b", KEY_B, NOW_MS),
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
                .map(|i| device(&format!("dev-{i:02}"), [i as u8 + 1; 32], "active"))
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
            .map(|i| device(&format!("dev-{i:02}"), [i as u8 + 1; 32], "active"))
            .collect();
        devices.push(device("dev-extra", KEY_A, "revoked"));
        let doc = signed(&state(1, devices, vec![revoke("dev-00")]));
        assert_eq!(select(&[doc]).map(|r| r.len()), Ok(MAX_RECIPIENTS));
    }

    #[test]
    fn a_higher_sequence_can_add_a_device() {
        let old = signed(&state(1, vec![device("dev-a", KEY_A, "active")], vec![]));
        let new = signed(&state(
            2,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
            ],
            vec![],
        ));
        let expected = Ok(vec![recipient("dev-a", KEY_A), recipient("dev-b", KEY_B)]);
        assert_eq!(select(&[old.clone(), new.clone()]), expected);
        assert_eq!(select(&[new, old]), expected);
    }

    #[test]
    fn a_higher_sequence_can_reinstate_a_revoked_device() {
        // Revocation is per document, not permanent: the root may re-list the device later.
        let revoked = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
            ],
            vec![revoke("dev-b")],
        ));
        let reinstated = signed(&state(
            2,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-b", KEY_B, "active"),
            ],
            vec![],
        ));
        assert_eq!(
            select(&[revoked, reinstated]),
            Ok(vec![recipient("dev-a", KEY_A), recipient("dev-b", KEY_B)])
        );
    }

    #[test]
    fn a_device_is_excluded_at_and_after_its_cert_expiry() {
        const EXPIRES_AT: i64 = 1_800_000_000_000;
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                expiring("dev-b", KEY_B, EXPIRES_AT),
            ],
            vec![],
        ));
        let docs = [doc];
        // One millisecond before expiry the device is still a recipient.
        assert_eq!(
            select_with(&docs, EXPIRES_AT - 1, None),
            Ok(vec![recipient("dev-a", KEY_A), recipient("dev-b", KEY_B)])
        );
        // At the expiry instant, and just past it, it is not.
        assert_eq!(
            select_with(&docs, EXPIRES_AT, None),
            Ok(vec![recipient("dev-a", KEY_A)])
        );
        assert_eq!(
            select_with(&docs, EXPIRES_AT + 1, None),
            Ok(vec![recipient("dev-a", KEY_A)])
        );
    }

    #[test]
    fn rejects_when_every_device_has_expired() {
        let doc = signed(&state(1, vec![expiring("dev-a", KEY_A, NOW_MS)], vec![]));
        assert_eq!(
            select(&[doc]),
            Err(RecipientSelectionError::NoActiveRecipients)
        );
    }

    #[test]
    fn a_sequence_below_the_floor_is_rejected_not_used() {
        let doc = signed(&state(2, vec![device("dev-a", KEY_A, "active")], vec![]));
        let docs = [doc];
        assert_eq!(
            select_with(&docs, NOW_MS, Some(3)),
            Err(RecipientSelectionError::BelowSequenceFloor {
                highest: 2,
                min_sequence: 3
            })
        );
        // At and above the floor the state is used.
        assert_eq!(
            select_with(&docs, NOW_MS, Some(2)),
            Ok(vec![recipient("dev-a", KEY_A)])
        );
        assert_eq!(
            select_with(&docs, NOW_MS, Some(1)),
            Ok(vec![recipient("dev-a", KEY_A)])
        );
    }

    #[test]
    fn accepts_exactly_the_maximum_documents_and_rejects_one_more() {
        let doc = signed(&state(1, vec![device("dev-a", KEY_A, "active")], vec![]));
        let at_cap = vec![doc; MAX_ACCOUNT_STATES];
        assert_eq!(select(&at_cap), Ok(vec![recipient("dev-a", KEY_A)]));

        let mut over = at_cap;
        over.push(over[0].clone());
        assert_eq!(
            select(&over),
            Err(RecipientSelectionError::TooManyAccountStates {
                count: MAX_ACCOUNT_STATES + 1
            })
        );
    }

    #[test]
    fn rejects_a_device_with_an_empty_id() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("", KEY_B, "active"),
            ],
            vec![],
        ));
        assert_eq!(select(&[doc]), Err(RecipientSelectionError::EmptyDeviceId));
    }

    #[test]
    fn rejects_an_empty_id_even_on_a_device_that_is_not_active() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("", KEY_B, "revoked"),
            ],
            vec![],
        ));
        assert_eq!(select(&[doc]), Err(RecipientSelectionError::EmptyDeviceId));
    }

    #[test]
    fn rejects_a_recipient_with_a_small_order_encryption_key() {
        // Every denylisted point, and its bit-255-set twin (X25519 masks bit 255, RFC 7748 §5).
        for point in crate::jwe::X25519_SMALL_ORDER_POINTS {
            let mut high = point;
            high[31] |= 0x80;
            for key in [point, high] {
                let doc = signed(&state(
                    1,
                    vec![
                        device("dev-a", KEY_A, "active"),
                        device("dev-z", key, "active"),
                    ],
                    vec![],
                ));
                assert_eq!(
                    select(&[doc]),
                    Err(RecipientSelectionError::InvalidEncryptionKey {
                        device_id: "dev-z".to_string()
                    }),
                    "{key:02x?}"
                );
            }
        }
    }

    #[test]
    fn the_invalid_key_error_escapes_and_bounds_the_device_id() {
        let payload = format!("x\u{202e}\n\nIMPORTANT: {}", "A".repeat(5_000));
        let msg = RecipientSelectionError::InvalidEncryptionKey { device_id: payload }.to_string();
        assert!(
            !msg.chars().any(char::is_control),
            "raw control char in {msg:?}"
        );
        assert!(!msg.contains('\u{202e}'), "raw bidi override in {msg:?}");
        assert!(
            msg.contains(r"x\u{202e}\n\nIMPORTANT"),
            "id is named, escaped: {msg}"
        );
        assert!(msg.contains('…'), "a long id is visibly truncated: {msg}");
        // 64 chars, each escaped to at most `\u{10ffff}` (10 bytes), plus fixed text.
        assert!(
            msg.len() < 1_024,
            "message is length-bounded: {} bytes",
            msg.len()
        );
    }

    #[test]
    fn a_small_order_key_on_a_device_that_is_not_a_recipient_is_ignored() {
        let doc = signed(&state(
            1,
            vec![
                device("dev-a", KEY_A, "active"),
                device("dev-z", crate::jwe::X25519_SMALL_ORDER_POINTS[0], "revoked"),
            ],
            vec![],
        ));
        assert_eq!(select(&[doc]), Ok(vec![recipient("dev-a", KEY_A)]));
    }
}
