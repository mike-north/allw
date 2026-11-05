//! **Root-holder enrollment authoring**: validating the material a device presents for enrollment,
//! the fingerprint a human compares before vouching for it, and composing the next root-signed
//! account state.
//!
//! See `docs/enrollment.md` §Model and §Interim vouching, and `docs/threat-model.md` (vouching).
//!
//! # Why this lives in the core
//!
//! Every device an account state lists as `active` can read every request sealed to the account
//! ([`crate::select_recipients`]). Deciding *what the next account state is* is therefore as
//! security-critical as verifying one, and more than one surface makes that decision:
//! `allw-approver pair` (adding its own device), the interim `allw-approver vouch` (adding a device
//! with its own keys), and later the enrollment ceremony (#199). They all call
//! [`next_account_state`], so the rules below exist once.
//!
//! # Device material ([`DeviceEnrollment::parse`])
//!
//! A device id and both public keys usually arrive as pasted text, so each is checked before
//! anything uses it:
//!
//! - the **device id** is 1–[`DEVICE_ID_MAX_LEN`] characters of the base64url alphabet
//!   (`A–Z a–z 0–9 - _`). Relay-minted ids are UUIDs, which fit. The rule keeps an id safe as a
//!   URL path segment and as display text;
//! - each **key** is the canonical unpadded base64url encoding of exactly 32 bytes (43 characters
//!   that re-encode to themselves);
//! - the **X25519 encryption key** is a canonical u-coordinate (bit 255 clear, `u < 2^255 - 19`)
//!   and not one of the small-order points ([`crate::X25519_SMALL_ORDER_POINTS`], #248). A
//!   small-order key would make every request sealed to it readable by anyone;
//! - the **Ed25519 signing key** decodes to a curve point, its encoding is canonical, and the point
//!   is not of small order. A small-order key could never produce a strictly verifiable signature.
//!
//! # Fingerprints ([`device_key_fingerprint`])
//!
//! `SHA-256("allw/device-key-fingerprint/v1" || 0x00 || kind || 0x00 || key)`, truncated to the
//! first [`FINGERPRINT_BYTES`] bytes (128 bits). It is shown as 32 lowercase hex digits in eight
//! groups of four. `kind` is `x25519-encryption` or `ed25519-signing`, so the same 32 bytes used as
//! the other kind of key give an unrelated fingerprint.
//!
//! 128 bits is sized against a **deliberate** attacker. A relay or network attacker that wants a
//! human to vouch for its key has to find a key whose fingerprint matches one already shown on the
//! honest device's screen. The honest device made that key itself, so this is a second-preimage
//! search, not a birthday collision: matching all 128 bits takes about 2^128 key generations. A
//! human who compares only some groups gets less (four groups is 2^64, two groups is 2^32, which is
//! feasible), so every surface shows all eight and asks for all eight to match.
//!
//! # The next account state ([`next_account_state`])
//!
//! The root holder fetches the account states the relay serves and composes the next one from them.
//! Fail-closed, in order:
//!
//! 1. at most [`crate::MAX_ACCOUNT_STATES`] documents ([`NextAccountStateError::TooManyAccountStates`]),
//!    and every document verifies against the root for the account ([`NextAccountStateError::AccountState`]);
//! 2. the relay's claimed `max_sequence` is backed by a verified document
//!    ([`NextAccountStateError::UnbackedMaxSequence`]): a relay that admits a higher state exists but
//!    serves none is hiding it;
//! 3. the highest verified sequence is not below this root holder's own floor
//!    ([`NextAccountStateError::BelowFloor`]), the sequence it last published or accepted;
//! 4. every document at the highest sequence is identical ([`NextAccountStateError::ConflictingStates`]),
//!    so the base is unambiguous;
//! 5. the change applies ([`AccountStateChange`]); its own refusals are listed there;
//! 6. the result lists at most [`crate::MAX_RECIPIENTS`] active devices
//!    ([`NextAccountStateError::TooManyDevices`]). Publishing more would make every request fail;
//! 7. the new sequence is `max(highest, floor) + 1`.
//!
//! **Invariant this relies on:** a revoked device's entry stays in `devices[]` next to its
//! `revocations` record. [`NextAccountStateError::KeysRevoked`] recognizes a revoked key pair only
//! through that entry, so a revocation that removed it would let the key pair be listed again under
//! a new id. Whoever authors revocations (#199) must keep the entry.
//!
//! The result ([`NextAccountState`]) carries the ids the change replaced and the resulting active
//! ids, so a surface shows the human what the signed state does before it signs.
//!
//! With no document at all (a new account) the base is empty, and the account id must derive from
//! the root ([`NextAccountStateError::AccountIdMismatch`]). The base's previous roots, actors and
//! revocations are carried forward unchanged. The function returns the *unsigned* state: the
//! caller shows the change to a human where one must confirm it, then signs it with
//! [`crate::sign_account_state`].

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::account::account_id_for_root;
use crate::crypto::{
    verify_account_state, AccountState, AccountStateDevice, AccountStateError,
    AccountStateRevocationKind, PublicKey,
};
use crate::jwe::{is_small_order_x25519_public_key, write_untrusted_device_id};
use crate::recipients::{DEVICE_STATUS_ACTIVE, MAX_ACCOUNT_STATES, MAX_RECIPIENTS};

/// The longest device id [`DeviceEnrollment::parse`] accepts. Relay-minted ids are 36-character
/// UUIDs; 64 leaves room for another minting scheme without letting an id grow unbounded.
pub const DEVICE_ID_MAX_LEN: usize = 64;

/// How many bytes of the SHA-256 digest a [`device_key_fingerprint`] keeps (128 bits). See the
/// module docs for why this resists a deliberate near-collision.
pub const FINGERPRINT_BYTES: usize = 16;

/// Domain tag for [`device_key_fingerprint`]. A change here changes every fingerprint and is a
/// deliberate version bump.
const FINGERPRINT_DOMAIN_TAG: &[u8] = b"allw/device-key-fingerprint/v1";

/// The length of the canonical unpadded base64url encoding of 32 bytes.
const KEY_B64_LEN: usize = 43;

// ── Device material ─────────────────────────────────────────────────────────────────

/// Which of a device's two public keys a value is. It selects the validation rules and is bound
/// into the [`device_key_fingerprint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKeyKind {
    /// The X25519 key requests are encrypted to (the JWE recipient key).
    Encryption,
    /// The Ed25519 key the device signs verdicts with.
    Signing,
}

impl DeviceKeyKind {
    /// The tag bound into the fingerprint.
    fn fingerprint_tag(self) -> &'static [u8] {
        match self {
            Self::Encryption => b"x25519-encryption",
            Self::Signing => b"ed25519-signing",
        }
    }

    /// The name used in error messages.
    fn noun(self) -> &'static str {
        match self {
            Self::Encryption => "encryption key",
            Self::Signing => "signing key",
        }
    }
}

/// Why a device id or key was refused. Every variant means "do not vouch for this device".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceMaterialError {
    /// The device id is empty, longer than [`DEVICE_ID_MAX_LEN`], or has a character outside the
    /// base64url alphabet.
    InvalidDeviceId,
    /// The key is not the canonical unpadded base64url encoding of 32 bytes.
    KeyEncoding(DeviceKeyKind),
    /// The X25519 key is a non-canonical u-coordinate (bit 255 set, or `u >= 2^255 - 19`).
    NonCanonicalEncryptionKey,
    /// The X25519 key is a small-order point (anything sealed to it is readable by anyone).
    SmallOrderEncryptionKey,
    /// The Ed25519 key is not a point on the curve, or its encoding is not canonical.
    InvalidSigningKey,
    /// The Ed25519 key is a small-order point (no signature by it verifies strictly).
    WeakSigningKey,
}

impl std::fmt::Display for DeviceMaterialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDeviceId => write!(
                f,
                "device id must be 1-{DEVICE_ID_MAX_LEN} characters of A-Z, a-z, 0-9, '-' or '_'"
            ),
            Self::KeyEncoding(kind) => write!(
                f,
                "{} must be the canonical unpadded base64url encoding of 32 bytes \
                 ({KEY_B64_LEN} characters)",
                kind.noun()
            ),
            Self::NonCanonicalEncryptionKey => {
                write!(f, "encryption key is not a canonical X25519 public key")
            }
            Self::SmallOrderEncryptionKey => write!(
                f,
                "encryption key is a small-order X25519 point (anyone could read requests \
                 sealed to it)"
            ),
            Self::InvalidSigningKey => write!(f, "signing key is not a valid Ed25519 public key"),
            Self::WeakSigningKey => write!(f, "signing key is a small-order Ed25519 point"),
        }
    }
}

impl std::error::Error for DeviceMaterialError {}

/// A device id and public keys that passed every check in [`DeviceEnrollment::parse`]. Holding
/// one is the proof that the material is well-formed; it does not mean the root vouches for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrollment {
    device_id: String,
    encryption_pubkey: [u8; 32],
    signing_pubkey: [u8; 32],
}

impl DeviceEnrollment {
    /// Validates a device id and its base64url public keys (see the module docs).
    ///
    /// # Errors
    ///
    /// The first failing check, as a [`DeviceMaterialError`]: the id, then the encryption key,
    /// then the signing key.
    pub fn parse(
        device_id: &str,
        encryption_pubkey_b64: &str,
        signing_pubkey_b64: &str,
    ) -> Result<Self, DeviceMaterialError> {
        if !device_id_is_well_formed(device_id) {
            return Err(DeviceMaterialError::InvalidDeviceId);
        }
        let encryption_pubkey = decode_key(encryption_pubkey_b64, DeviceKeyKind::Encryption)?;
        check_encryption_key(&encryption_pubkey)?;
        let signing_pubkey = decode_key(signing_pubkey_b64, DeviceKeyKind::Signing)?;
        check_signing_key(&signing_pubkey)?;
        Ok(Self {
            device_id: device_id.to_string(),
            encryption_pubkey,
            signing_pubkey,
        })
    }

    /// The device id (the JWE recipient `kid` the device is reached by).
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The X25519 encryption public key.
    #[must_use]
    pub fn encryption_pubkey(&self) -> &[u8; 32] {
        &self.encryption_pubkey
    }

    /// The Ed25519 signing public key.
    #[must_use]
    pub fn signing_pubkey(&self) -> &[u8; 32] {
        &self.signing_pubkey
    }

    /// Which of this device's keys are byte-for-byte equal to the given key pair's, encryption
    /// first. Empty when neither matches.
    ///
    /// The root holder uses it to refuse vouching for its **own** keys (#381): a device carrying
    /// the keyfile's encryption or signing key is the keyfile's own device (or a copy of its
    /// secrets) under whatever id it shows, and `pair`, not `vouch`, lists that device. The
    /// comparison is on the parsed 32-byte keys, never on their text.
    #[must_use]
    pub fn shared_key_kinds(
        &self,
        encryption_pubkey: &[u8; 32],
        signing_pubkey: &[u8; 32],
    ) -> Vec<DeviceKeyKind> {
        let mut shared = Vec::new();
        if &self.encryption_pubkey == encryption_pubkey {
            shared.push(DeviceKeyKind::Encryption);
        }
        if &self.signing_pubkey == signing_pubkey {
            shared.push(DeviceKeyKind::Signing);
        }
        shared
    }
}

/// 1–[`DEVICE_ID_MAX_LEN`] characters of the base64url alphabet.
fn device_id_is_well_formed(device_id: &str) -> bool {
    (1..=DEVICE_ID_MAX_LEN).contains(&device_id.len())
        && device_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Decodes a key that must be the canonical unpadded base64url encoding of exactly 32 bytes.
/// Re-encoding guards against a decoder that tolerates non-zero trailing bits.
fn decode_key(text: &str, kind: DeviceKeyKind) -> Result<[u8; 32], DeviceMaterialError> {
    if text.len() != KEY_B64_LEN {
        return Err(DeviceMaterialError::KeyEncoding(kind));
    }
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(DeviceMaterialError::KeyEncoding(kind))?;
    if URL_SAFE_NO_PAD.encode(bytes) != text {
        return Err(DeviceMaterialError::KeyEncoding(kind));
    }
    Ok(bytes)
}

/// An X25519 public key must be a canonical u-coordinate and not of small order.
fn check_encryption_key(key: &[u8; 32]) -> Result<(), DeviceMaterialError> {
    // Small order first: the denylist also matches bit-255 variants, and naming the stronger
    // reason is more useful than "non-canonical".
    if is_small_order_x25519_public_key(key) {
        return Err(DeviceMaterialError::SmallOrderEncryptionKey);
    }
    if !x25519_u_is_canonical(key) {
        return Err(DeviceMaterialError::NonCanonicalEncryptionKey);
    }
    Ok(())
}

/// Whether a little-endian X25519 u-coordinate is canonical: bit 255 clear and `u < p`, with
/// `p = 2^255 - 19` (RFC 7748 §5). X25519 masks bit 255 and reduces mod `p`, so a non-canonical
/// encoding names the same key as a canonical one; key generation never produces one.
fn x25519_u_is_canonical(key: &[u8; 32]) -> bool {
    if key[31] & 0x80 != 0 {
        return false;
    }
    // With bit 255 clear, `u >= p` only for `p..=2^255 - 1`: top byte 0x7f, bytes 1..=30 all 0xff,
    // and the low byte at least 0xed.
    let at_least_p = key[31] == 0x7f && key[1..31].iter().all(|&b| b == 0xff) && key[0] >= 0xed;
    !at_least_p
}

/// An Ed25519 public key must decode to a point, encode canonically, and not be of small order.
fn check_signing_key(key: &[u8; 32]) -> Result<(), DeviceMaterialError> {
    let point =
        VerifyingKey::from_bytes(key).map_err(|_| DeviceMaterialError::InvalidSigningKey)?;
    // Decompression reduces a non-canonical y mod p, so compare the re-compressed point with the
    // input: a non-canonical encoding names the same point under a second spelling.
    if point.to_edwards().compress().to_bytes() != *key {
        return Err(DeviceMaterialError::InvalidSigningKey);
    }
    if point.is_weak() {
        return Err(DeviceMaterialError::WeakSigningKey);
    }
    Ok(())
}

/// The human-comparable fingerprint of a device public key (see the module docs): 32 lowercase hex
/// digits in eight space-separated groups of four, e.g. `3f2a 91c0 …`.
///
/// It fingerprints the 32 bytes as given; validate them with [`DeviceEnrollment::parse`] first.
#[must_use]
pub fn device_key_fingerprint(kind: DeviceKeyKind, key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN_TAG);
    hasher.update([0x00]);
    hasher.update(kind.fingerprint_tag());
    hasher.update([0x00]);
    hasher.update(key);
    let digest = hasher.finalize();
    let hex: String = digest[..FINGERPRINT_BYTES]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    hex.as_bytes()
        .chunks(4)
        .map(|group| std::str::from_utf8(group).expect("hex digits are ASCII"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── The next account state ──────────────────────────────────────────────────────────

/// A change the root holder makes to its account state. Only adding a device exists today; the
/// enrollment ceremony (#199) adds rotation and revocation here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccountStateChange {
    /// List a device as `active`, so requests are sealed to it.
    ///
    /// - The id must not be revoked in the base state ([`NextAccountStateError::DeviceRevoked`]).
    /// - The id must not already be listed with other keys
    ///   ([`NextAccountStateError::DeviceKeyMismatch`]): replacing a device's keys is a key
    ///   rotation, which belongs to the enrollment ceremony (#199).
    /// - The id must not already be active with these keys ([`NextAccountStateError::AlreadyActive`]);
    ///   an entry with these keys that is not active is replaced by an active one.
    /// - Entries under **other** ids with the same key pair are dropped (#378), so one key pair has
    ///   exactly one entry. Re-running `pair` registers a new relay id for the same keys, and this
    ///   retires the old one.
    /// - The key pair must not belong to a revoked id ([`NextAccountStateError::KeysRevoked`]):
    ///   otherwise a revoked device could come back under a new name. The check finds the key pair
    ///   through the revoked device's `devices[]` entry, so **a revocation must keep that entry**
    ///   alongside its `revocations` record. Any revocation author (#199) has to keep this
    ///   invariant; dropping the entry would let the revoked key pair back in under a new id.
    /// - Neither key may be shared with a device that has different other key
    ///   ([`NextAccountStateError::KeyConflict`]); no honest enrollment produces that.
    AddDevice(DeviceEnrollment),
}

/// Why no next account state was composed. Every variant means "do not sign, do not publish".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NextAccountStateError {
    /// More than [`MAX_ACCOUNT_STATES`] documents were supplied.
    TooManyAccountStates { count: usize },
    /// A supplied document did not verify against the root for the expected account.
    AccountState(AccountStateError),
    /// There is no account state yet and the account id does not derive from the root.
    AccountIdMismatch,
    /// The relay claims a higher sequence than any verified document it served.
    UnbackedMaxSequence { max_sequence: u64, highest: u64 },
    /// The highest verified sequence is below the root holder's floor (a rollback).
    BelowFloor { highest: u64, floor: u64 },
    /// Documents at the highest sequence differ.
    ConflictingStates { sequence: u64 },
    /// The device id is revoked in the current account state.
    DeviceRevoked { device_id: String },
    /// The device id is already listed with different keys (a rotation, #199's job).
    DeviceKeyMismatch { device_id: String },
    /// The device id is already active with these keys; there is nothing to change.
    AlreadyActive { device_id: String },
    /// This key pair is listed under a revoked device id.
    KeysRevoked { device_id: String },
    /// One of the keys is listed for another device together with a different other key.
    KeyConflict { device_id: String },
    /// The result would list more than [`MAX_RECIPIENTS`] active devices.
    TooManyDevices { count: usize },
    /// The next sequence does not fit in a `u64`.
    SequenceOverflow,
}

impl std::fmt::Display for NextAccountStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyAccountStates { count } => write!(
                f,
                "{count} account-state documents supplied, more than the maximum \
                 {MAX_ACCOUNT_STATES}"
            ),
            Self::AccountState(e) => write!(f, "account state rejected: {e}"),
            Self::AccountIdMismatch => {
                write!(f, "account id does not derive from the account root key")
            }
            Self::UnbackedMaxSequence {
                max_sequence,
                highest,
            } => write!(
                f,
                "relay reports account-state sequence {max_sequence} but serves no verified \
                 document at it (highest verified: {highest})"
            ),
            Self::BelowFloor { highest, floor } => write!(
                f,
                "relay serves account-state sequence {highest}, below the {floor} this root \
                 holder already accepted (rollback)"
            ),
            Self::ConflictingStates { sequence } => write!(
                f,
                "relay serves differing account-state documents at sequence {sequence}; resolve \
                 them before changing the account state"
            ),
            Self::DeviceRevoked { device_id } => {
                f.write_str("device ")?;
                write_untrusted_device_id(f, device_id)?;
                f.write_str(" is revoked in the current account state")
            }
            Self::DeviceKeyMismatch { device_id } => {
                f.write_str("device ")?;
                write_untrusted_device_id(f, device_id)?;
                f.write_str(
                    " is already listed with different keys; replacing a device's keys is a key \
                     rotation, which the enrollment ceremony (#199) will handle",
                )
            }
            Self::AlreadyActive { device_id } => {
                f.write_str("device ")?;
                write_untrusted_device_id(f, device_id)?;
                f.write_str(" is already active with these keys")
            }
            Self::KeysRevoked { device_id } => {
                f.write_str("these keys belong to revoked device ")?;
                write_untrusted_device_id(f, device_id)
            }
            Self::KeyConflict { device_id } => {
                f.write_str("one of these keys is already listed for device ")?;
                write_untrusted_device_id(f, device_id)?;
                f.write_str(" together with a different key")
            }
            Self::TooManyDevices { count } => write!(
                f,
                "the account state would list {count} active devices, more than the maximum \
                 {MAX_RECIPIENTS}"
            ),
            Self::SequenceOverflow => write!(f, "account-state sequence overflow"),
        }
    }
}

impl std::error::Error for NextAccountStateError {}

impl From<AccountStateError> for NextAccountStateError {
    fn from(e: AccountStateError) -> Self {
        Self::AccountState(e)
    }
}

/// The next account state [`next_account_state`] composed, with what the change does to the base
/// that a human confirming it must see.
///
/// A root holder signs [`NextAccountState::state`] only after showing the
/// [`replaced_device_ids`](NextAccountState::replaced_device_ids) and the resulting
/// [`active_device_ids`](NextAccountState::active_device_ids): an add can silently retire another
/// id (#378), and the confirmation must not hide that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextAccountState {
    state: AccountState,
    replaced_device_ids: Vec<String>,
}

impl NextAccountState {
    /// The unsigned next state, ready for [`crate::sign_account_state`].
    pub fn state(&self) -> &AccountState {
        &self.state
    }

    /// Consume the result, keeping only the unsigned state.
    pub fn into_state(self) -> AccountState {
        self.state
    }

    /// Ids of base entries the change removed because they carried the added device's exact key
    /// pair under another id (#378), in base order. Empty when nothing was replaced. These ids stop
    /// receiving requests once the state is published.
    pub fn replaced_device_ids(&self) -> &[String] {
        &self.replaced_device_ids
    }

    /// Ids of every `active` device in the next state, in state order: exactly the devices
    /// integrators will seal requests to once it is published.
    pub fn active_device_ids(&self) -> impl Iterator<Item = &str> {
        self.state
            .devices
            .iter()
            .filter(|d| d.status == DEVICE_STATUS_ACTIVE)
            .map(|d| d.device_id.as_str())
    }
}

/// Composes the next (unsigned) account state from the documents the relay serves.
///
/// - `account_states`: every compact account-state JWS the relay served for the account.
/// - `relay_max_sequence`: the highest sequence the relay says it holds (`0` when it holds none).
/// - `floor`: the highest sequence this root holder already published or accepted (`0` if none).
///
/// See the module docs for the rules and [`AccountStateChange`] for each change's. The result also
/// names what the change replaced ([`NextAccountState`]), so a caller can show it before signing.
///
/// # Errors
///
/// The first failing rule, as a [`NextAccountStateError`].
pub fn next_account_state(
    account_states: &[&str],
    relay_max_sequence: u64,
    floor: u64,
    expected_account_id: &str,
    account_root: &PublicKey,
    change: &AccountStateChange,
) -> Result<NextAccountState, NextAccountStateError> {
    if account_states.len() > MAX_ACCOUNT_STATES {
        return Err(NextAccountStateError::TooManyAccountStates {
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
    let highest = verified.iter().map(|s| s.sequence).max().unwrap_or(0);
    if relay_max_sequence > highest {
        return Err(NextAccountStateError::UnbackedMaxSequence {
            max_sequence: relay_max_sequence,
            highest,
        });
    }
    if highest < floor {
        return Err(NextAccountStateError::BelowFloor { highest, floor });
    }
    let mut at_highest = verified.into_iter().filter(|s| s.sequence == highest);
    let base = match at_highest.next() {
        Some(first) => {
            if at_highest.any(|other| other != first) {
                return Err(NextAccountStateError::ConflictingStates { sequence: highest });
            }
            first
        }
        None => {
            // No document at all: a new account, which only the root's own account id can have.
            if account_id_for_root(account_root) != expected_account_id {
                return Err(NextAccountStateError::AccountIdMismatch);
            }
            AccountState {
                v: 1,
                account_id: expected_account_id.to_string(),
                sequence: 0,
                current_root: account_root.to_bytes(),
                previous_roots: vec![],
                devices: vec![],
                actors: vec![],
                revocations: vec![],
            }
        }
    };

    let (mut next, replaced_device_ids) = match change {
        AccountStateChange::AddDevice(device) => add_device(base, device)?,
    };

    let active = next
        .devices
        .iter()
        .filter(|d| d.status == DEVICE_STATUS_ACTIVE)
        .count();
    if active > MAX_RECIPIENTS {
        return Err(NextAccountStateError::TooManyDevices { count: active });
    }
    next.sequence = highest
        .max(floor)
        .checked_add(1)
        .ok_or(NextAccountStateError::SequenceOverflow)?;
    Ok(NextAccountState {
        state: next,
        replaced_device_ids,
    })
}

/// Applies [`AccountStateChange::AddDevice`] to `base` (see its docs for the rules).
/// Apply [`AccountStateChange::AddDevice`]; returns the new state and the ids it replaced (#378).
fn add_device(
    mut base: AccountState,
    device: &DeviceEnrollment,
) -> Result<(AccountState, Vec<String>), NextAccountStateError> {
    let revoked = |id: &str| {
        base.revocations
            .iter()
            .any(|r| r.kind == AccountStateRevocationKind::Device && r.id == id)
    };
    if revoked(device.device_id()) {
        return Err(NextAccountStateError::DeviceRevoked {
            device_id: device.device_id.clone(),
        });
    }
    for entry in &base.devices {
        let same_enc = entry.encryption_pubkey == device.encryption_pubkey;
        let same_sig = entry.signing_pubkey == device.signing_pubkey;
        if entry.device_id == device.device_id {
            if !(same_enc && same_sig) {
                return Err(NextAccountStateError::DeviceKeyMismatch {
                    device_id: device.device_id.clone(),
                });
            }
            if entry.status == DEVICE_STATUS_ACTIVE {
                return Err(NextAccountStateError::AlreadyActive {
                    device_id: device.device_id.clone(),
                });
            }
        } else if same_enc && same_sig {
            if revoked(&entry.device_id) {
                return Err(NextAccountStateError::KeysRevoked {
                    device_id: entry.device_id.clone(),
                });
            }
        } else if same_enc || same_sig {
            return Err(NextAccountStateError::KeyConflict {
                device_id: entry.device_id.clone(),
            });
        }
    }
    // Every remaining entry with this id or this key pair has these exact keys: replace them all
    // with one active entry. Entries under other ids are reported, so the change is never silent.
    let mut replaced = Vec::new();
    base.devices.retain(|entry| {
        let keep = entry.device_id != device.device_id
            && !(entry.encryption_pubkey == device.encryption_pubkey
                && entry.signing_pubkey == device.signing_pubkey);
        if !keep && entry.device_id != device.device_id {
            replaced.push(entry.device_id.clone());
        }
        keep
    });
    base.devices.push(AccountStateDevice {
        device_id: device.device_id.clone(),
        encryption_pubkey: device.encryption_pubkey,
        signing_pubkey: device.signing_pubkey,
        status: DEVICE_STATUS_ACTIVE.to_string(),
        cert_expires_at: None,
    });
    Ok((base, replaced))
}

#[cfg(test)]
mod tests {
    //! @see docs/enrollment.md §Model, §Interim vouching
    //! @see https://datatracker.ietf.org/doc/html/rfc7748#section-5 (X25519 u-coordinate encoding)
    //! @see https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.3 (Ed25519 point decoding)
    use super::*;
    use crate::crypto::{sign_account_state, AccountStateRevocation, SigningKeyPair};
    use crate::jwe::{X25519KeyPair, X25519_SMALL_ORDER_POINTS};

    const ROOT_SEED: [u8; 32] = [0x11; 32];
    const OTHER_ROOT_SEED: [u8; 32] = [0x33; 32];

    fn root() -> SigningKeyPair {
        SigningKeyPair::from_seed(&ROOT_SEED)
    }

    fn account_id() -> String {
        account_id_for_root(&root().public_key())
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Real public keys derived from `seed`, as a device would generate them.
    fn keys(seed: u8) -> ([u8; 32], [u8; 32]) {
        let enc = X25519KeyPair::from_seed(&[seed; 32])
            .public_key()
            .to_bytes();
        let sig = SigningKeyPair::from_seed(&[seed.wrapping_add(0x40); 32])
            .public_key()
            .to_bytes();
        (enc, sig)
    }

    fn enrollment(id: &str, seed: u8) -> DeviceEnrollment {
        let (enc, sig) = keys(seed);
        DeviceEnrollment::parse(id, &b64(&enc), &b64(&sig)).expect("valid material")
    }

    fn entry(id: &str, seed: u8, status: &str) -> AccountStateDevice {
        let (enc, sig) = keys(seed);
        AccountStateDevice {
            device_id: id.to_string(),
            encryption_pubkey: enc,
            signing_pubkey: sig,
            status: status.to_string(),
            cert_expires_at: None,
        }
    }

    fn revocation(id: &str) -> AccountStateRevocation {
        AccountStateRevocation {
            kind: AccountStateRevocationKind::Device,
            id: id.to_string(),
            revoked_at: 1_700_000_000_000,
            reason: None,
        }
    }

    fn state(sequence: u64, devices: Vec<AccountStateDevice>) -> AccountState {
        AccountState {
            v: 1,
            account_id: account_id(),
            sequence,
            current_root: root().public_key().to_bytes(),
            previous_roots: vec![],
            devices,
            actors: vec![],
            revocations: vec![],
        }
    }

    fn signed(state: &AccountState) -> String {
        sign_account_state(state, &root())
    }

    fn next(
        docs: &[String],
        max: u64,
        floor: u64,
        device: DeviceEnrollment,
    ) -> Result<AccountState, NextAccountStateError> {
        next_full(docs, max, floor, device).map(NextAccountState::into_state)
    }

    fn next_full(
        docs: &[String],
        max: u64,
        floor: u64,
        device: DeviceEnrollment,
    ) -> Result<NextAccountState, NextAccountStateError> {
        let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
        next_account_state(
            &refs,
            max,
            floor,
            &account_id(),
            &root().public_key(),
            &AccountStateChange::AddDevice(device),
        )
    }

    // ── Device material ──

    #[test]
    fn accepts_real_device_material() {
        let (enc, sig) = keys(1);
        let device = DeviceEnrollment::parse(
            "0f8c1e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
            &b64(&enc),
            &b64(&sig),
        )
        .expect("valid");
        assert_eq!(device.encryption_pubkey(), &enc);
        assert_eq!(device.signing_pubkey(), &sig);
    }

    #[test]
    fn shared_key_kinds_compares_each_key_separately() {
        let (enc, sig) = keys(1);
        let (other_enc, other_sig) = keys(2);
        let device = DeviceEnrollment::parse("dev-1", &b64(&enc), &b64(&sig)).expect("valid");
        assert_eq!(device.shared_key_kinds(&other_enc, &other_sig), vec![]);
        assert_eq!(
            device.shared_key_kinds(&enc, &other_sig),
            vec![DeviceKeyKind::Encryption]
        );
        assert_eq!(
            device.shared_key_kinds(&other_enc, &sig),
            vec![DeviceKeyKind::Signing]
        );
        assert_eq!(
            device.shared_key_kinds(&enc, &sig),
            vec![DeviceKeyKind::Encryption, DeviceKeyKind::Signing]
        );
    }

    #[test]
    fn refuses_malformed_device_ids() {
        let (enc, sig) = keys(1);
        for id in [
            "",
            &"a".repeat(DEVICE_ID_MAX_LEN + 1),
            "dev 1",
            "dev/1",
            "dev\n1",
            "dev\u{202e}1",
            "dév",
        ] {
            assert_eq!(
                DeviceEnrollment::parse(id, &b64(&enc), &b64(&sig)),
                Err(DeviceMaterialError::InvalidDeviceId),
                "{id:?}"
            );
        }
        assert!(
            DeviceEnrollment::parse(&"a".repeat(DEVICE_ID_MAX_LEN), &b64(&enc), &b64(&sig)).is_ok()
        );
    }

    #[test]
    fn refuses_non_canonical_and_wrong_length_base64url() {
        let (enc, sig) = keys(1);
        let good_enc = b64(&enc);
        let mut trailing = good_enc.clone().into_bytes();
        // The last symbol carries 2 spare bits; flipping one gives a second spelling of 32 bytes.
        let last = trailing.pop().expect("non-empty");
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let idx = alphabet
            .iter()
            .position(|&c| c == last)
            .expect("b64url symbol");
        trailing.push(alphabet[idx ^ 1]);
        let trailing = String::from_utf8(trailing).expect("ascii");
        for bad in [
            format!("{good_enc}="),                       // padded
            good_enc[..42].to_string(),                   // too short
            format!("{good_enc}A"),                       // too long
            good_enc.replace('-', "+").replace('_', "/"), // standard alphabet
            trailing,                                     // non-zero trailing bits
            b64(&[1u8; 31]),                              // 31 bytes
            b64(&[1u8; 33]),                              // 33 bytes
        ] {
            if bad == good_enc {
                continue; // the alphabet swap is a no-op when the key has no '-' or '_'
            }
            assert_eq!(
                DeviceEnrollment::parse("dev-1", &bad, &b64(&sig)),
                Err(DeviceMaterialError::KeyEncoding(DeviceKeyKind::Encryption)),
                "{bad:?}"
            );
            assert_eq!(
                DeviceEnrollment::parse("dev-1", &good_enc, &bad),
                Err(DeviceMaterialError::KeyEncoding(DeviceKeyKind::Signing)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn refuses_small_order_encryption_keys() {
        let (_, sig) = keys(1);
        for point in X25519_SMALL_ORDER_POINTS {
            assert_eq!(
                DeviceEnrollment::parse("dev-1", &b64(&point), &b64(&sig)),
                Err(DeviceMaterialError::SmallOrderEncryptionKey)
            );
            let mut high = point;
            high[31] |= 0x80;
            assert_eq!(
                DeviceEnrollment::parse("dev-1", &b64(&high), &b64(&sig)),
                Err(DeviceMaterialError::SmallOrderEncryptionKey)
            );
        }
    }

    #[test]
    fn refuses_non_canonical_encryption_keys() {
        let (enc, sig) = keys(1);
        let mut high_bit = enc;
        high_bit[31] |= 0x80;
        // p + 3 = 2^255 - 16: bit 255 clear but u >= p (and not on the small-order list).
        let mut p_plus_3 = [0xff; 32];
        p_plus_3[0] = 0xf0;
        p_plus_3[31] = 0x7f;
        for bad in [high_bit, p_plus_3] {
            assert_eq!(
                DeviceEnrollment::parse("dev-1", &b64(&bad), &b64(&sig)),
                Err(DeviceMaterialError::NonCanonicalEncryptionKey)
            );
        }
        // p - 1 is the largest canonical u.
        let mut p_minus_1 = [0xff; 32];
        p_minus_1[0] = 0xec;
        p_minus_1[31] = 0x7f;
        assert!(x25519_u_is_canonical(&p_minus_1));
    }

    #[test]
    fn refuses_invalid_signing_keys() {
        let (enc, _) = keys(1);
        // y = 2 is not the y-coordinate of a curve point.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        assert!(
            VerifyingKey::from_bytes(&not_a_point).is_err(),
            "fixture is off-curve"
        );
        assert_eq!(
            DeviceEnrollment::parse("dev-1", &b64(&enc), &b64(&not_a_point)),
            Err(DeviceMaterialError::InvalidSigningKey)
        );
        // y = p + 1 is a non-canonical spelling of y = 1 (the identity).
        let mut non_canonical = [0xff; 32];
        non_canonical[0] = 0xee;
        non_canonical[31] = 0x7f;
        assert_eq!(
            DeviceEnrollment::parse("dev-1", &b64(&enc), &b64(&non_canonical)),
            Err(DeviceMaterialError::InvalidSigningKey)
        );
        // The identity (y = 1) is a valid, canonical, small-order point.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            DeviceEnrollment::parse("dev-1", &b64(&enc), &b64(&identity)),
            Err(DeviceMaterialError::WeakSigningKey)
        );
    }

    // ── Fingerprints ──

    #[test]
    fn fingerprint_is_eight_groups_of_four_hex() {
        let (enc, _) = keys(1);
        let fp = device_key_fingerprint(DeviceKeyKind::Encryption, &enc);
        let groups: Vec<&str> = fp.split(' ').collect();
        assert_eq!(groups.len(), 8);
        assert!(groups.iter().all(|g| g.len() == 4
            && g.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())));
    }

    #[test]
    fn fingerprint_matches_an_independent_computation() {
        // Independently: printf 'allw/device-key-fingerprint/v1\0x25519-encryption\0' followed
        // by 32 zero bytes | shasum -a 256, first 32 hex digits.
        let fp = device_key_fingerprint(DeviceKeyKind::Encryption, &[0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(b"allw/device-key-fingerprint/v1\0x25519-encryption\0");
        hasher.update([0u8; 32]);
        let hex: String = hasher.finalize()[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(fp.replace(' ', ""), hex);
    }

    #[test]
    fn fingerprint_binds_the_key_kind() {
        let key = [7u8; 32];
        assert_ne!(
            device_key_fingerprint(DeviceKeyKind::Encryption, &key),
            device_key_fingerprint(DeviceKeyKind::Signing, &key)
        );
    }

    // ── next_account_state ──

    #[test]
    fn first_state_lists_the_device_at_sequence_one() {
        let next = next(&[], 0, 0, enrollment("dev-1", 1)).expect("composes");
        assert_eq!(next.sequence, 1);
        assert_eq!(next.account_id, account_id());
        assert_eq!(next.current_root, root().public_key().to_bytes());
        assert_eq!(next.devices, vec![entry("dev-1", 1, "active")]);
    }

    #[test]
    fn adds_a_device_and_carries_the_rest_forward() {
        let mut base = state(4, vec![entry("dev-a", 1, "active")]);
        base.revocations = vec![revocation("dev-old")];
        let next = next(&[signed(&base)], 4, 3, enrollment("dev-b", 2)).expect("composes");
        assert_eq!(next.sequence, 5);
        assert_eq!(
            next.devices,
            vec![entry("dev-a", 1, "active"), entry("dev-b", 2, "active")]
        );
        assert_eq!(next.revocations, base.revocations);
    }

    #[test]
    fn sequence_is_above_the_floor_when_the_floor_is_higher() {
        // The relay serves 4; this root holder published 4 already (floor 4): next is 5. A floor
        // above the relay's highest is a rollback, refused below.
        let base = state(4, vec![]);
        assert_eq!(
            next(&[signed(&base)], 4, 4, enrollment("dev-b", 2))
                .expect("composes")
                .sequence,
            5
        );
    }

    #[test]
    fn refuses_a_document_that_does_not_verify() {
        let other = SigningKeyPair::from_seed(&OTHER_ROOT_SEED);
        let forged = sign_account_state(&state(2, vec![]), &other);
        assert_eq!(
            next(&[forged], 2, 0, enrollment("dev-b", 2)),
            Err(NextAccountStateError::AccountState(
                AccountStateError::InvalidSignature
            ))
        );
    }

    #[test]
    fn refuses_too_many_documents() {
        let doc = signed(&state(1, vec![]));
        let docs = vec![doc; MAX_ACCOUNT_STATES + 1];
        assert_eq!(
            next(&docs, 1, 0, enrollment("dev-b", 2)),
            Err(NextAccountStateError::TooManyAccountStates {
                count: MAX_ACCOUNT_STATES + 1
            })
        );
    }

    #[test]
    fn refuses_an_unbacked_max_sequence() {
        let doc = signed(&state(3, vec![]));
        assert_eq!(
            next(&[doc], 4, 0, enrollment("dev-b", 2)),
            Err(NextAccountStateError::UnbackedMaxSequence {
                max_sequence: 4,
                highest: 3
            })
        );
        // No documents at all, yet a claimed sequence.
        assert_eq!(
            next(&[], 1, 0, enrollment("dev-b", 2)),
            Err(NextAccountStateError::UnbackedMaxSequence {
                max_sequence: 1,
                highest: 0
            })
        );
    }

    #[test]
    fn refuses_a_state_below_the_floor() {
        let doc = signed(&state(3, vec![]));
        assert_eq!(
            next(&[doc], 3, 5, enrollment("dev-b", 2)),
            Err(NextAccountStateError::BelowFloor {
                highest: 3,
                floor: 5
            })
        );
        assert_eq!(
            next(&[], 0, 1, enrollment("dev-b", 2)),
            Err(NextAccountStateError::BelowFloor {
                highest: 0,
                floor: 1
            })
        );
    }

    #[test]
    fn refuses_disagreeing_siblings_at_the_highest_sequence() {
        let a = signed(&state(3, vec![entry("dev-a", 1, "active")]));
        let b = signed(&state(3, vec![entry("dev-x", 9, "active")]));
        let low = signed(&state(2, vec![]));
        assert_eq!(
            next(&[a.clone(), b, low.clone()], 3, 0, enrollment("dev-b", 2)),
            Err(NextAccountStateError::ConflictingStates { sequence: 3 })
        );
        // Identical siblings and a lower document are fine; only the highest is the base.
        let next = next(&[a.clone(), a, low], 3, 0, enrollment("dev-b", 2)).expect("composes");
        assert_eq!(next.devices.len(), 2);
    }

    #[test]
    fn refuses_a_revoked_device_id() {
        let mut base = state(2, vec![]);
        base.revocations = vec![revocation("dev-b")];
        assert_eq!(
            next(&[signed(&base)], 2, 0, enrollment("dev-b", 2)),
            Err(NextAccountStateError::DeviceRevoked {
                device_id: "dev-b".to_string()
            })
        );
    }

    #[test]
    fn refuses_the_same_id_with_different_keys() {
        for status in ["active", "pending"] {
            let base = state(2, vec![entry("dev-b", 1, status)]);
            let err = next(&[signed(&base)], 2, 0, enrollment("dev-b", 2)).unwrap_err();
            assert_eq!(
                err,
                NextAccountStateError::DeviceKeyMismatch {
                    device_id: "dev-b".to_string()
                },
                "{status}"
            );
            assert!(
                err.to_string().contains("#199"),
                "names rotation as #199's job"
            );
        }
    }

    #[test]
    fn refuses_an_id_already_active_with_these_keys() {
        let base = state(2, vec![entry("dev-b", 2, "active")]);
        assert_eq!(
            next(&[signed(&base)], 2, 0, enrollment("dev-b", 2)),
            Err(NextAccountStateError::AlreadyActive {
                device_id: "dev-b".to_string()
            })
        );
    }

    #[test]
    fn reactivates_an_inactive_entry_with_these_keys() {
        let base = state(2, vec![entry("dev-b", 2, "pending")]);
        let next = next(&[signed(&base)], 2, 0, enrollment("dev-b", 2)).expect("composes");
        assert_eq!(next.devices, vec![entry("dev-b", 2, "active")]);
    }

    #[test]
    fn replaces_the_same_keys_under_another_id_issue_378() {
        // A re-pair: the relay mints a new id for the same keyfile keys. The old entry goes, so
        // one key pair has exactly one entry; other devices are untouched.
        let base = state(
            2,
            vec![
                entry("dev-old", 1, "active"),
                entry("dev-phone", 3, "active"),
                entry("dev-older", 1, "pending"),
            ],
        );
        let next = next(&[signed(&base)], 2, 0, enrollment("dev-new", 1)).expect("composes");
        assert_eq!(
            next.devices,
            vec![
                entry("dev-phone", 3, "active"),
                entry("dev-new", 1, "active")
            ]
        );
    }

    #[test]
    fn reports_every_id_it_replaces_issue_378() {
        // Review-387 F1: the replacement must be visible to whoever confirms the state. Both the
        // active and the pending entry under other ids carry the added keys, so both are reported;
        // the unrelated phone is not.
        let base = state(
            2,
            vec![
                entry("dev-old", 1, "active"),
                entry("dev-phone", 3, "active"),
                entry("dev-older", 1, "pending"),
            ],
        );
        let result = next_full(&[signed(&base)], 2, 0, enrollment("dev-new", 1)).expect("composes");
        assert_eq!(result.replaced_device_ids(), ["dev-old", "dev-older"]);
        assert_eq!(
            result.active_device_ids().collect::<Vec<_>>(),
            ["dev-phone", "dev-new"]
        );
    }

    #[test]
    fn a_plain_add_replaces_nothing() {
        let base = state(1, vec![entry("dev-a", 1, "active")]);
        let result = next_full(&[signed(&base)], 1, 0, enrollment("dev-b", 2)).expect("composes");
        assert!(result.replaced_device_ids().is_empty());
        assert_eq!(
            result.active_device_ids().collect::<Vec<_>>(),
            ["dev-a", "dev-b"]
        );
    }

    #[test]
    fn reactivating_an_entry_is_not_a_replacement() {
        // The same id with the same keys, not active: it comes back, and no other id is retired.
        let base = state(1, vec![entry("dev-b", 2, "pending")]);
        let result = next_full(&[signed(&base)], 1, 0, enrollment("dev-b", 2)).expect("composes");
        assert!(result.replaced_device_ids().is_empty());
        assert_eq!(result.active_device_ids().collect::<Vec<_>>(), ["dev-b"]);
    }

    #[test]
    fn two_consecutive_re_pairs_keep_one_entry_issue_378() {
        let first = next(&[], 0, 0, enrollment("dev-1", 1)).expect("first pair");
        let second = next(&[signed(&first)], 1, 1, enrollment("dev-2", 1)).expect("re-pair");
        let third = next(&[signed(&second)], 2, 2, enrollment("dev-3", 1)).expect("re-pair");
        assert_eq!(third.sequence, 3);
        assert_eq!(third.devices, vec![entry("dev-3", 1, "active")]);
    }

    #[test]
    fn refuses_keys_that_belong_to_a_revoked_id() {
        let mut base = state(2, vec![entry("dev-gone", 1, "revoked")]);
        base.revocations = vec![revocation("dev-gone")];
        assert_eq!(
            next(&[signed(&base)], 2, 0, enrollment("dev-new", 1)),
            Err(NextAccountStateError::KeysRevoked {
                device_id: "dev-gone".to_string()
            })
        );
    }

    #[test]
    fn refuses_a_key_shared_with_another_device() {
        let (enc, sig) = keys(1);
        let (_, other_sig) = keys(2);
        let (other_enc, _) = keys(2);
        for (e, s) in [(enc, other_sig), (other_enc, sig)] {
            let base = state(
                2,
                vec![AccountStateDevice {
                    device_id: "dev-a".to_string(),
                    encryption_pubkey: e,
                    signing_pubkey: s,
                    status: "active".to_string(),
                    cert_expires_at: None,
                }],
            );
            assert_eq!(
                next(&[signed(&base)], 2, 0, enrollment("dev-b", 1)),
                Err(NextAccountStateError::KeyConflict {
                    device_id: "dev-a".to_string()
                })
            );
        }
    }

    #[test]
    fn refuses_more_active_devices_than_can_be_recipients() {
        let devices: Vec<_> = (0..MAX_RECIPIENTS)
            .map(|i| {
                entry(
                    &format!("dev-{i}"),
                    u8::try_from(i + 10).expect("small"),
                    "active",
                )
            })
            .collect();
        let base = state(2, devices);
        assert_eq!(
            next(&[signed(&base)], 2, 0, enrollment("dev-extra", 1)),
            Err(NextAccountStateError::TooManyDevices {
                count: MAX_RECIPIENTS + 1
            })
        );
    }

    #[test]
    fn refuses_a_sequence_overflow() {
        let base = state(u64::MAX, vec![]);
        assert_eq!(
            next(&[signed(&base)], u64::MAX, 0, enrollment("dev-b", 2)),
            Err(NextAccountStateError::SequenceOverflow)
        );
    }

    #[test]
    fn refuses_a_new_account_whose_id_does_not_derive_from_the_root() {
        let other = account_id_for_root(&SigningKeyPair::from_seed(&OTHER_ROOT_SEED).public_key());
        assert_eq!(
            next_account_state(
                &[],
                0,
                0,
                &other,
                &root().public_key(),
                &AccountStateChange::AddDevice(enrollment("dev-b", 2)),
            ),
            Err(NextAccountStateError::AccountIdMismatch)
        );
    }

    #[test]
    fn error_messages_escape_device_ids() {
        let err = NextAccountStateError::DeviceRevoked {
            device_id: "x\u{1b}[2J\nok".to_string(),
        };
        let text = err.to_string();
        assert!(!text.contains('\u{1b}') && !text.contains('\n'), "{text}");
    }
}
