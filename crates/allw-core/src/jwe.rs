//! E2EE approval-context encryption: a multi-recipient JOSE **JWE**. See `docs/contract.md`.
//!
//! This module enforces the **E2EE** invariant (`docs/contract.md` §Invariants #1): the
//! [`ApprovalContext`] the human is shown is encrypted to one or more device X25519 public keys
//! and is decryptable *only* on those devices. The relay routes the resulting ciphertext (the
//! envelope's `context_ciphertext`) and never sees the plaintext.
//!
//! # Format: multi-recipient JWE, General JSON Serialization (RFC 7516 §7.2.1)
//!
//! One [`ApprovalContext`] is serialized to JSON and encrypted **once** under a random 256-bit
//! content-encryption key (CEK) with `enc = "A256GCM"` (RFC 7518 §5.3). For **each** recipient
//! device the CEK is wrapped independently with `alg = "ECDH-ES+A256KW"` (RFC 7518 §4.6 + §4.4):
//!
//! 1. Generate an **ephemeral** X25519 keypair (one per recipient).
//! 2. `Z = ECDH(ephemeral_secret, device_static_public)` (X25519 — RFC 8037 OKP).
//! 3. `KEK = ConcatKDF(SHA-256, Z, keydatalen = 256, OtherInfo)` (RFC 7518 §4.6.2; the exact
//!    `OtherInfo` byte layout is documented at [`concat_kdf_other_info`]).
//! 4. `encrypted_key = AES-256-KeyWrap(KEK, CEK)` (A256KW / RFC 3394).
//!
//! The ephemeral public key travels in that recipient's per-recipient (unprotected) header as
//! `epk`. The shared protected header carries only `enc` (so it is byte-identical across all
//! recipients and is the GCM AAD). The output object is:
//!
//! ```json
//! {
//!   "protected": "<b64url({\"enc\":\"A256GCM\"})>",
//!   "recipients": [
//!     {
//!       "header": {
//!         "alg": "ECDH-ES+A256KW",
//!         "kid": "<device_id>",
//!         "epk": { "kty": "OKP", "crv": "X25519", "x": "<b64url(ephemeral_pub)>" }
//!       },
//!       "encrypted_key": "<b64url(wrapped_cek)>"
//!     }
//!   ],
//!   "iv": "<b64url(iv)>",
//!   "ciphertext": "<b64url(ct)>",
//!   "tag": "<b64url(tag)>"
//! }
//! ```
//!
//! AAD is `ASCII(BASE64URL(UTF8(protected_header_json)))` per RFC 7516 §5.1 — the *transmitted*
//! base64url protected-header bytes are authenticated, so tampering with `protected` (which also
//! carries `enc`) breaks GCM verification.
//!
//! # Randomness is injected (no OS RNG in the core)
//!
//! [`encrypt_context`] takes the CEK, IV, and every ephemeral secret from a caller-supplied
//! `rng: CryptoRng + RngCore`. The core never links `getrandom`, keeping it deterministic and
//! wasm-friendly (`docs/architecture.md`); the WASM/SDK surface supplies a real CSPRNG.
//!
//! # Keys
//!
//! The device's long-term **encryption** key ([`X25519KeyPair`]) is distinct from its Ed25519
//! **signing** key ([`crate::crypto::SigningKeyPair`]). In production it lives in
//! Secure Enclave / StrongBox and never leaves hardware; [`X25519KeyPair::from_seed`] is for
//! v1/tests only. Static ECDH in v1 (no per-message forward secrecy — deferred).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_kw::KekAes256;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::contract::ApprovalContext;

// ── JOSE constant strings (RFC 7518) ────────────────────────────────────────────

/// Content-encryption algorithm: AES-256-GCM (RFC 7518 §5.3).
const ENC_A256GCM: &str = "A256GCM";

/// Per-recipient key-management algorithm: ECDH-ES with A256KW (RFC 7518 §4.6 + §4.4).
const ALG_ECDH_ES_A256KW: &str = "ECDH-ES+A256KW";

/// `epk` key type for X25519 — Octet Key Pair (RFC 8037).
const EPK_KTY_OKP: &str = "OKP";

/// `epk` curve — X25519 (RFC 8037).
const EPK_CRV_X25519: &str = "X25519";

/// AlgorithmID value for Concat KDF: for `ECDH-ES+A256KW` the derived key is used **with the
/// key-wrap algorithm**, so the AlgorithmID is `"A256KW"` (RFC 7518 §4.6.2), *not* `enc`.
const CONCAT_KDF_ALG_ID: &[u8] = b"A256KW";

// ── Byte-length constants ────────────────────────────────────────────────────────

/// AES-256 content-encryption key length (bytes).
const CEK_LEN: usize = 32;

/// AES-GCM IV length (bytes) — 96 bits, the JWE-mandated GCM nonce size (RFC 7518 §5.3).
const IV_LEN: usize = 12;

/// X25519 public/secret key length (bytes).
const X25519_LEN: usize = 32;

/// Derived KEK length (bytes) — 256 bits (A256KW).
const KEK_LEN: usize = 32;

// ── Key abstractions ─────────────────────────────────────────────────────────────

/// A device's long-term **X25519 encryption** keypair (private scalar + derived public key).
///
/// Wraps [`x25519_dalek::StaticSecret`] so the dalek types never leak into this crate's public
/// API. This is the key the JWE encrypts *to*; it is **distinct** from the device's Ed25519
/// [`SigningKeyPair`](crate::crypto::SigningKeyPair) used for verdicts.
///
/// # Production key custody
///
/// In production this scalar lives in **Secure Enclave / StrongBox** and never leaves hardware.
/// [`from_seed`](Self::from_seed) exists for v1 and tests only — a hardware-backed key never
/// exposes its seed.
pub struct X25519KeyPair {
    secret: StaticSecret,
}

impl X25519KeyPair {
    /// Constructs a keypair from a fixed 32-byte seed (the clamped X25519 scalar input).
    ///
    /// Deterministic by design (no RNG): the same seed always yields the same key, keeping the
    /// core wasm-friendly and test vectors reproducible. **Not** for production key generation —
    /// see the type-level docs on key custody.
    #[must_use]
    pub fn from_seed(seed: &[u8; X25519_LEN]) -> Self {
        Self {
            secret: StaticSecret::from(*seed),
        }
    }

    /// Returns the corresponding [`X25519PublicKey`].
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            inner: XPublicKey::from(&self.secret),
        }
    }

    /// ECDH against `their_public` → the 32-byte shared secret `Z`.
    fn diffie_hellman(&self, their_public: &XPublicKey) -> [u8; X25519_LEN] {
        self.secret.diffie_hellman(their_public).to_bytes()
    }
}

/// An X25519 public key (the Montgomery-u coordinate, 32 bytes).
///
/// Wraps [`x25519_dalek::PublicKey`] so the dalek type stays out of the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519PublicKey {
    inner: XPublicKey,
}

impl X25519PublicKey {
    /// Reconstructs a public key from its 32-byte encoding.
    ///
    /// X25519 accepts any 32-byte string as a public key (RFC 7748), so this is infallible.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; X25519_LEN]) -> Self {
        Self {
            inner: XPublicKey::from(*bytes),
        }
    }

    /// Returns the 32-byte encoding of this public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X25519_LEN] {
        self.inner.to_bytes()
    }
}

/// A recipient of an encrypted [`ApprovalContext`]: a device id paired with its X25519 public key.
///
/// Borrowing (`&'a`) avoids cloning device ids / keys for the common case where the caller already
/// holds them.
pub struct ContextRecipient<'a> {
    /// The recipient device's id — becomes the `kid` in that recipient's JWE header.
    pub device_id: &'a str,
    /// The recipient device's long-term X25519 public key (the CEK is wrapped to it).
    pub public_key: &'a X25519PublicKey,
}

// ── Errors ─────────────────────────────────────────────────────────────────────

/// Why decrypting a [`ApprovalContext`] JWE failed. Every variant is a clean failure (no panic);
/// per the fail-closed invariant the caller treats any `Err` as "cannot read context".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JweError {
    /// The outer JSON, a base64url field, or a required member was missing / malformed.
    Malformed,
    /// A recipient `header.alg` was not `"ECDH-ES+A256KW"`.
    UnsupportedAlg,
    /// The protected header `enc` was not `"A256GCM"`.
    UnsupportedEnc,
    /// No recipient entry carried a `kid` matching the requested device id.
    NoRecipientForDevice,
    /// The recipient's `epk` was not a well-formed `{kty:"OKP",crv:"X25519",x:<32 bytes>}`.
    BadEpk,
    /// AES Key Wrap unwrap of `encrypted_key` failed (wrong KEK → wrong device key).
    KeyUnwrapFailed,
    /// AES-256-GCM authentication/decryption failed (wrong CEK, or tampered iv/ct/tag/AAD).
    DecryptionFailed,
    /// The decrypted plaintext was not a valid JSON [`ApprovalContext`].
    InvalidPlaintext,
}

impl std::fmt::Display for JweError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Malformed => "JWE JSON is malformed or missing a required member",
            Self::UnsupportedAlg => "recipient alg is not ECDH-ES+A256KW",
            Self::UnsupportedEnc => "protected header enc is not A256GCM",
            Self::NoRecipientForDevice => "no recipient header kid matches the requested device id",
            Self::BadEpk => "recipient epk is not a valid OKP/X25519 public key",
            Self::KeyUnwrapFailed => "AES key-wrap unwrap of the encrypted_key failed",
            Self::DecryptionFailed => "AES-256-GCM authentication/decryption failed",
            Self::InvalidPlaintext => "decrypted plaintext is not a valid ApprovalContext",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for JweError {}

// ── Wire shape (serde) ───────────────────────────────────────────────────────────

/// The shared JWE protected header — only `enc` (so it is identical across all recipients and
/// makes a stable AAD).
#[derive(Debug, Serialize, Deserialize)]
struct ProtectedHeader {
    enc: String,
}

/// An `epk` (ephemeral public key) JWK — RFC 8037 OKP/X25519.
#[derive(Debug, Serialize, Deserialize)]
struct EpkJwk {
    kty: String,
    crv: String,
    /// base64url-unpadded X25519 public key (the JWK `x` parameter).
    x: String,
}

/// A per-recipient unprotected header: key-management `alg`, recipient `kid`, and the `epk`.
#[derive(Debug, Serialize, Deserialize)]
struct RecipientHeader {
    alg: String,
    kid: String,
    epk: EpkJwk,
}

/// One recipient entry: its header plus the wrapped CEK.
#[derive(Debug, Serialize, Deserialize)]
struct RecipientEntry {
    header: RecipientHeader,
    /// base64url-unpadded AES-KW-wrapped CEK.
    encrypted_key: String,
}

/// The General JWE JSON Serialization object (RFC 7516 §7.2.1).
#[derive(Debug, Serialize, Deserialize)]
struct GeneralJwe {
    /// base64url-unpadded protected header JSON.
    protected: String,
    recipients: Vec<RecipientEntry>,
    /// base64url-unpadded 96-bit IV.
    iv: String,
    /// base64url-unpadded GCM ciphertext.
    ciphertext: String,
    /// base64url-unpadded 128-bit GCM tag.
    tag: String,
}

// ── Concat KDF OtherInfo (RFC 7518 §4.6.2) ───────────────────────────────────────

/// Builds the Concat KDF `OtherInfo` for deriving the A256KW KEK (RFC 7518 §4.6.2, NIST SP
/// 800-56A §5.8.1.2).
///
/// `OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo || SuppPrivInfo`, where the
/// first three are **length-prefixed** (a 4-byte big-endian length of the *value*, then the value)
/// and `SuppPubInfo` is the keydatalen used **directly** (not length-prefixed). For
/// `ECDH-ES+A256KW` with an empty `apu`/`apv` and a 256-bit derived key, the exact byte layout is:
///
/// ```text
/// AlgorithmID  : 00 00 00 06  41 32 35 36 4B 57     # len(6) || "A256KW"
/// PartyUInfo   : 00 00 00 00                        # len(0) || (empty apu)
/// PartyVInfo   : 00 00 00 00                        # len(0) || (empty apv)
/// SuppPubInfo  : 00 00 01 00                        # keydatalen = 256 (bits), 32-bit big-endian
/// SuppPrivInfo : (absent / empty)
/// ```
///
/// Total = 11 + 4 + 4 + 4 = 23 bytes.
fn concat_kdf_other_info() -> Vec<u8> {
    // 4-byte big-endian length-prefixed datum (`AlgorithmID`, `PartyUInfo`, `PartyVInfo`).
    fn push_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
        // Values here are tiny constants; the cast cannot truncate.
        let len = u32::try_from(value.len()).expect("OtherInfo datum length fits in u32");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(value);
    }

    let mut info = Vec::new();
    // AlgorithmID = len || "A256KW"
    push_len_prefixed(&mut info, CONCAT_KDF_ALG_ID);
    // PartyUInfo = len(0)  (apu is empty)
    push_len_prefixed(&mut info, &[]);
    // PartyVInfo = len(0)  (apv is empty)
    push_len_prefixed(&mut info, &[]);
    // SuppPubInfo = keydatalen in BITS as a 32-bit big-endian integer, appended DIRECTLY
    // (NOT length-prefixed) per RFC 7518 §4.6.2. 256 → 00 00 01 00.
    let keydatalen_bits: u32 = (KEK_LEN as u32) * 8;
    info.extend_from_slice(&keydatalen_bits.to_be_bytes());
    // SuppPrivInfo is empty (omitted entirely).
    info
}

/// Derives the 256-bit KEK from the ECDH shared secret `z` via Concat KDF with SHA-256.
fn derive_kek(z: &[u8; X25519_LEN]) -> [u8; KEK_LEN] {
    let other_info = concat_kdf_other_info();
    let mut kek = [0u8; KEK_LEN];
    // For a 256-bit output and SHA-256 (256-bit) digest, this is a single-round derivation and
    // cannot fail (output length is well within the Concat KDF maximum).
    concat_kdf::derive_key_into::<Sha256>(z, &other_info, &mut kek)
        .expect("Concat KDF derivation of a 256-bit key must not fail");
    kek
}

// ── Encryption ─────────────────────────────────────────────────────────────────

/// Encrypts `context` to one or more recipient devices, returning a General JWE JSON string
/// suitable for the envelope's `context_ciphertext`.
///
/// The [`ApprovalContext`] is JSON-serialized and encrypted **once** under a fresh random CEK
/// (`enc = "A256GCM"`); the CEK is then wrapped independently for each recipient via
/// `ECDH-ES+A256KW` against that device's X25519 public key. See the module docs for the wire
/// shape and the Concat KDF `OtherInfo` layout.
///
/// All randomness (CEK, IV, and each recipient's ephemeral secret) is drawn from `rng`, so the
/// output is fully determined by the inputs plus the RNG state — the core never touches an OS RNG.
///
/// # Panics
///
/// Panics only on internal invariants that cannot occur for well-formed inputs: serializing the
/// (in-memory, always-serializable) [`ApprovalContext`] to JSON, AES-GCM encryption of an
/// in-memory buffer, or AES-KW wrapping a 32-byte CEK. These are programming-error guards, not
/// input-dependent failures.
#[must_use]
pub fn encrypt_context(
    context: &ApprovalContext,
    recipients: &[ContextRecipient<'_>],
    rng: &mut (impl RngCore + CryptoRng),
) -> String {
    // Plaintext = JSON-serialized ApprovalContext. The contract types always serialize.
    let plaintext = serde_json::to_vec(context)
        .expect("ApprovalContext must serialize to JSON (infallible for contract types)");

    // ── Protected header (shared) and its base64url form (the GCM AAD per RFC 7516 §5.1) ──
    let protected = ProtectedHeader {
        enc: ENC_A256GCM.to_string(),
    };
    let protected_json = serde_json::to_vec(&protected)
        .expect("ProtectedHeader must serialize (infallible for a fixed struct)");
    let protected_b64 = URL_SAFE_NO_PAD.encode(&protected_json);

    // ── Random CEK + IV from the injected RNG ──
    let mut cek = [0u8; CEK_LEN];
    rng.fill_bytes(&mut cek);
    let mut iv = [0u8; IV_LEN];
    rng.fill_bytes(&mut iv);

    // ── A256GCM content encryption (once). AAD = ASCII(b64url(protected)). ──
    let cipher =
        Aes256Gcm::new_from_slice(&cek).expect("Aes256Gcm accepts a 32-byte key (CEK_LEN is 32)");
    let nonce = Nonce::from_slice(&iv);
    let gcm_out = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: protected_b64.as_bytes(),
            },
        )
        .expect("AES-256-GCM encryption of an in-memory buffer must not fail");
    // RustCrypto returns ciphertext || tag (16-byte GCM tag appended).
    let split = gcm_out.len() - 16;
    let (ciphertext, tag) = gcm_out.split_at(split);

    // ── Per-recipient ECDH-ES+A256KW wrapping of the CEK ──
    let mut entries = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        // Fresh ephemeral X25519 secret per recipient, seeded from the injected RNG.
        let mut eph_seed = [0u8; X25519_LEN];
        rng.fill_bytes(&mut eph_seed);
        let eph_secret = StaticSecret::from(eph_seed);
        let eph_public = XPublicKey::from(&eph_secret);

        // Z = ECDH(ephemeral_secret, device_static_public)
        let z = eph_secret
            .diffie_hellman(&recipient.public_key.inner)
            .to_bytes();
        // KEK = ConcatKDF(SHA-256, Z, 256, OtherInfo)
        let kek_bytes = derive_kek(&z);
        // encrypted_key = AES-256-KeyWrap(KEK, CEK)
        let kek = KekAes256::from(kek_bytes);
        let wrapped = kek
            .wrap_vec(&cek)
            .expect("AES-KW wrap of a 32-byte CEK (8-byte aligned) must not fail");

        entries.push(RecipientEntry {
            header: RecipientHeader {
                alg: ALG_ECDH_ES_A256KW.to_string(),
                kid: recipient.device_id.to_string(),
                epk: EpkJwk {
                    kty: EPK_KTY_OKP.to_string(),
                    crv: EPK_CRV_X25519.to_string(),
                    x: URL_SAFE_NO_PAD.encode(eph_public.to_bytes()),
                },
            },
            encrypted_key: URL_SAFE_NO_PAD.encode(&wrapped),
        });
    }

    let jwe = GeneralJwe {
        protected: protected_b64,
        recipients: entries,
        iv: URL_SAFE_NO_PAD.encode(iv),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        tag: URL_SAFE_NO_PAD.encode(tag),
    };

    serde_json::to_string(&jwe)
        .expect("GeneralJwe must serialize to JSON (infallible for string-only fields)")
}

// ── Decryption ─────────────────────────────────────────────────────────────────

/// Decodes a base64url-unpadded field, mapping any error to [`JweError::Malformed`].
fn b64(field: &str) -> Result<Vec<u8>, JweError> {
    URL_SAFE_NO_PAD
        .decode(field)
        .map_err(|_| JweError::Malformed)
}

/// Decrypts a General JWE `jwe` for the device identified by `device_id`, using its
/// [`X25519KeyPair`], and returns the recovered [`ApprovalContext`].
///
/// Steps (mirrors [`encrypt_context`] in reverse):
///
/// 1. Parse the General JWE JSON and the base64url protected header; require `enc == "A256GCM"`.
/// 2. Find the recipient whose `kid == device_id` ([`JweError::NoRecipientForDevice`]); require
///    its `alg == "ECDH-ES+A256KW"`.
/// 3. `Z = ECDH(device_static_secret, recipient.epk)`; `KEK = ConcatKDF(SHA-256, Z, 256, …)`.
/// 4. `CEK = AES-256-KeyUnwrap(KEK, encrypted_key)` ([`JweError::KeyUnwrapFailed`]).
/// 5. AES-256-GCM-decrypt `ciphertext`/`tag` with `iv` and `AAD = ASCII(b64url(protected))`
///    ([`JweError::DecryptionFailed`]).
/// 6. Parse the plaintext JSON into an [`ApprovalContext`] ([`JweError::InvalidPlaintext`]).
///
/// # Errors
///
/// Returns the first matching [`JweError`] variant (see the step list above). A wrong device key
/// surfaces as [`JweError::KeyUnwrapFailed`] or [`JweError::DecryptionFailed`] — never a panic.
pub fn decrypt_context(
    jwe: &str,
    device_id: &str,
    device_key: &X25519KeyPair,
) -> Result<ApprovalContext, JweError> {
    // ── Step 1: parse the General JWE + protected header ──
    let parsed: GeneralJwe = serde_json::from_str(jwe).map_err(|_| JweError::Malformed)?;

    let protected_json = b64(&parsed.protected)?;
    let protected: ProtectedHeader =
        serde_json::from_slice(&protected_json).map_err(|_| JweError::Malformed)?;
    if protected.enc != ENC_A256GCM {
        return Err(JweError::UnsupportedEnc);
    }

    // ── Step 2: select the recipient entry for this device ──
    let recipient = parsed
        .recipients
        .iter()
        .find(|r| r.header.kid == device_id)
        .ok_or(JweError::NoRecipientForDevice)?;
    if recipient.header.alg != ALG_ECDH_ES_A256KW {
        return Err(JweError::UnsupportedAlg);
    }

    // The epk must be a well-formed OKP/X25519 public key.
    if recipient.header.epk.kty != EPK_KTY_OKP || recipient.header.epk.crv != EPK_CRV_X25519 {
        return Err(JweError::BadEpk);
    }
    let epk_bytes: [u8; X25519_LEN] = b64(&recipient.header.epk.x)?
        .try_into()
        .map_err(|_| JweError::BadEpk)?;
    let epk = XPublicKey::from(epk_bytes);

    // ── Step 3: Z = ECDH(device_secret, epk); KEK = ConcatKDF(SHA-256, Z, …) ──
    let z = device_key.diffie_hellman(&epk);
    let kek_bytes = derive_kek(&z);

    // ── Step 4: unwrap the CEK ──
    let wrapped = b64(&recipient.encrypted_key)?;
    let kek = KekAes256::from(kek_bytes);
    let cek = kek
        .unwrap_vec(&wrapped)
        .map_err(|_| JweError::KeyUnwrapFailed)?;
    if cek.len() != CEK_LEN {
        // A valid unwrap of a correctly-formed JWE yields exactly 32 bytes; anything else is a
        // malformed/forged encrypted_key.
        return Err(JweError::KeyUnwrapFailed);
    }

    // ── Step 5: AES-256-GCM decrypt with AAD = ASCII(b64url(protected)) ──
    let iv = b64(&parsed.iv)?;
    if iv.len() != IV_LEN {
        return Err(JweError::Malformed);
    }
    let mut combined = b64(&parsed.ciphertext)?;
    combined.extend_from_slice(&b64(&parsed.tag)?); // RustCrypto expects ciphertext || tag

    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|_| JweError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: parsed.protected.as_bytes(),
            },
        )
        .map_err(|_| JweError::DecryptionFailed)?;

    // ── Step 6: parse the plaintext back into an ApprovalContext ──
    serde_json::from_slice(&plaintext).map_err(|_| JweError::InvalidPlaintext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────────
//
// Spec-first: assertions trace to the JWE design in this module's docs + docs/contract.md
// (§Invariants #1 E2EE, §Identity & keys, §Wire encoding → context_ciphertext) and the cited
// RFCs — NOT to captured program output. All randomness comes from a fixed-seed ChaCha20Rng so
// every test is deterministic; no SystemTime / OS RNG anywhere.
//
// @see docs/contract.md §Invariants #1, §Identity & keys, §Wire encoding → context_ciphertext
// @see https://www.rfc-editor.org/rfc/rfc7516 (JWE)
// @see https://www.rfc-editor.org/rfc/rfc7518 (JWA — §4.4 A256KW, §4.6 ECDH-ES, §5.3 A256GCM)
// @see https://www.rfc-editor.org/rfc/rfc8037 (OKP / X25519 in JOSE)
// @see https://www.rfc-editor.org/rfc/rfc3394 (AES Key Wrap)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        ActionRecord, Actor, Constraints, Decision, Risk, Surface, SyntacticSubstrate,
    };
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use serde_json::Value;

    // ── Fixed seeds (never rand / SystemTime) ────────────────────────────────────
    const RNG_SEED: [u8; 32] = [0x42; 32];
    const DEV1_SEED: [u8; 32] = [0x01; 32];
    const DEV2_SEED: [u8; 32] = [0x02; 32];
    const DEV3_SEED: [u8; 32] = [0x03; 32];
    const WRONG_SEED: [u8; 32] = [0xEE; 32];

    const DEV1_ID: &str = "dev_alpha";
    const DEV2_ID: &str = "dev_beta";
    const DEV3_ID: &str = "dev_gamma";

    // Distinctive plaintext markers that must NEVER appear in the ciphertext.
    const SUMMARY_MARKER: &str = "FORCE-PUSH-TO-MAIN-SECRET-SUMMARY";
    const RAW_MARKER: &str = "git push --force origin main # SECRET-RAW";

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(RNG_SEED)
    }

    fn device(seed: &[u8; 32]) -> X25519KeyPair {
        X25519KeyPair::from_seed(seed)
    }

    /// The standard plaintext context, carrying the distinctive plaintext markers.
    fn make_context() -> ApprovalContext {
        ApprovalContext {
            action: ActionRecord {
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
                    raw: Some(RAW_MARKER.to_string()),
                },
                risk: Risk::Critical,
                capabilities: None,
                scope: None,
            },
            summary: SUMMARY_MARKER.to_string(),
            actor: Actor {
                id: "machine:macbook-pro".to_string(),
                kind: "claude-code".to_string(),
                attestation: None,
            },
            risk: Risk::Critical,
            reversible: false,
            constraints: Constraints {
                allowed_decisions: vec![Decision::Approved, Decision::Denied],
                challenge_required: true,
            },
            chain: None,
        }
    }

    /// Encrypt the standard context to a single device with a fresh fixed-seed RNG.
    fn encrypt_to_one() -> String {
        let dev_pub = device(&DEV1_SEED).public_key();
        let recipients = [ContextRecipient {
            device_id: DEV1_ID,
            public_key: &dev_pub,
        }];
        encrypt_context(&make_context(), &recipients, &mut rng())
    }

    // ── Round-trip: single recipient ──────────────────────────────────────────────

    /// A context encrypted to one device decrypts (with that device's key) to the original.
    #[test]
    fn round_trip_single_recipient() {
        let jwe = encrypt_to_one();
        let recovered =
            decrypt_context(&jwe, DEV1_ID, &device(&DEV1_SEED)).expect("must decrypt for dev1");
        assert_eq!(
            recovered,
            make_context(),
            "decrypt must yield the original context"
        );
    }

    // ── Round-trip: multiple recipients (one ciphertext, per-device wrapped CEK) ──

    /// Encrypting to 3 devices lets EACH device recover the SAME original context.
    #[test]
    fn round_trip_multi_recipient_all_decrypt() {
        let p1 = device(&DEV1_SEED).public_key();
        let p2 = device(&DEV2_SEED).public_key();
        let p3 = device(&DEV3_SEED).public_key();
        let recipients = [
            ContextRecipient {
                device_id: DEV1_ID,
                public_key: &p1,
            },
            ContextRecipient {
                device_id: DEV2_ID,
                public_key: &p2,
            },
            ContextRecipient {
                device_id: DEV3_ID,
                public_key: &p3,
            },
        ];
        let jwe = encrypt_context(&make_context(), &recipients, &mut rng());

        for (id, seed) in [
            (DEV1_ID, &DEV1_SEED),
            (DEV2_ID, &DEV2_SEED),
            (DEV3_ID, &DEV3_SEED),
        ] {
            let recovered = decrypt_context(&jwe, id, &device(seed))
                .unwrap_or_else(|e| panic!("device {id} must decrypt: {e}"));
            assert_eq!(
                recovered,
                make_context(),
                "device {id} must recover the original context"
            );
        }
    }

    /// The single ciphertext is shared: there is exactly one `ciphertext`/`iv`/`tag` and one
    /// `encrypted_key` per recipient (RFC 7516 §7.2.1 — content encrypted once, CEK wrapped N×).
    #[test]
    fn multi_recipient_shares_one_ciphertext_with_per_device_wrapped_cek() {
        let p1 = device(&DEV1_SEED).public_key();
        let p2 = device(&DEV2_SEED).public_key();
        let recipients = [
            ContextRecipient {
                device_id: DEV1_ID,
                public_key: &p1,
            },
            ContextRecipient {
                device_id: DEV2_ID,
                public_key: &p2,
            },
        ];
        let jwe = encrypt_context(&make_context(), &recipients, &mut rng());
        let val: Value = serde_json::from_str(&jwe).unwrap();

        assert_eq!(val["recipients"].as_array().unwrap().len(), 2);
        // Distinct wrapped CEKs (distinct ephemeral keys → distinct KEKs → distinct wraps).
        let ek0 = val["recipients"][0]["encrypted_key"].as_str().unwrap();
        let ek1 = val["recipients"][1]["encrypted_key"].as_str().unwrap();
        assert_ne!(
            ek0, ek1,
            "each recipient wraps the shared CEK under its own KEK"
        );
        // Distinct epks per recipient.
        let epk0 = val["recipients"][0]["header"]["epk"]["x"].as_str().unwrap();
        let epk1 = val["recipients"][1]["header"]["epk"]["x"].as_str().unwrap();
        assert_ne!(
            epk0, epk1,
            "each recipient gets its own ephemeral public key"
        );
    }

    // ── E2EE: the relay cannot read the plaintext ────────────────────────────────

    /// docs/contract.md §Invariants #1: the JWE string must NOT contain any plaintext content —
    /// neither the human-shown summary nor the raw command. Proves the content is encrypted.
    #[test]
    fn ciphertext_does_not_leak_plaintext() {
        let jwe = encrypt_to_one();
        assert!(
            !jwe.contains(SUMMARY_MARKER),
            "JWE must not contain the plaintext summary (E2EE — relay sees only ciphertext)"
        );
        assert!(
            !jwe.contains(RAW_MARKER),
            "JWE must not contain the plaintext raw command (E2EE)"
        );
        // The structural field names are fine; the action's secret substring must be absent.
        assert!(
            !jwe.contains("--force"),
            "no fragment of the raw command may appear in the JWE"
        );
    }

    /// A party holding NO device key (i.e. not a recipient at all) cannot decrypt: asking for a
    /// device id that was never a recipient fails with NoRecipientForDevice.
    #[test]
    fn non_recipient_party_cannot_decrypt() {
        let jwe = encrypt_to_one();
        let err = decrypt_context(&jwe, "dev_outsider", &device(&WRONG_SEED))
            .expect_err("a party with no recipient slot must not decrypt");
        assert_eq!(err, JweError::NoRecipientForDevice);
    }

    // ── Wrong device / wrong key ──────────────────────────────────────────────────

    /// A device id that is not among the recipients → NoRecipientForDevice (clean, no panic).
    #[test]
    fn wrong_device_id_not_a_recipient() {
        let p1 = device(&DEV1_SEED).public_key();
        let recipients = [ContextRecipient {
            device_id: DEV1_ID,
            public_key: &p1,
        }];
        let jwe = encrypt_context(&make_context(), &recipients, &mut rng());

        let err = decrypt_context(&jwe, DEV2_ID, &device(&DEV2_SEED))
            .expect_err("a non-recipient device id must fail");
        assert_eq!(err, JweError::NoRecipientForDevice);
    }

    /// Right `kid`, WRONG secret: a device whose id matches a recipient slot but whose key is a
    /// different secret derives a different KEK → fails cleanly (unwrap or GCM), never panics.
    #[test]
    fn right_id_wrong_key_fails_cleanly() {
        let p1 = device(&DEV1_SEED).public_key();
        let recipients = [ContextRecipient {
            device_id: DEV1_ID,
            public_key: &p1,
        }];
        let jwe = encrypt_context(&make_context(), &recipients, &mut rng());

        // Same id (DEV1_ID), but the holder presents a DIFFERENT secret key.
        let err = decrypt_context(&jwe, DEV1_ID, &device(&WRONG_SEED))
            .expect_err("right id but wrong key must fail");
        assert!(
            matches!(err, JweError::KeyUnwrapFailed | JweError::DecryptionFailed),
            "wrong key must fail at unwrap or GCM, got {err:?}"
        );
    }

    // ── Tamper detection ──────────────────────────────────────────────────────────

    /// Flipping a byte in the ciphertext → GCM auth failure (DecryptionFailed) for the right key.
    #[test]
    fn tampered_ciphertext_detected() {
        let jwe = encrypt_to_one();
        let mut val: Value = serde_json::from_str(&jwe).unwrap();

        let ct = val["ciphertext"].as_str().unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(ct).unwrap();
        bytes[0] ^= 0x01; // flip one bit
        val["ciphertext"] = Value::String(URL_SAFE_NO_PAD.encode(&bytes));
        let tampered = serde_json::to_string(&val).unwrap();

        let err = decrypt_context(&tampered, DEV1_ID, &device(&DEV1_SEED))
            .expect_err("tampered ciphertext must fail GCM auth");
        assert_eq!(err, JweError::DecryptionFailed);
    }

    /// Flipping a byte in the GCM tag → DecryptionFailed.
    #[test]
    fn tampered_tag_detected() {
        let jwe = encrypt_to_one();
        let mut val: Value = serde_json::from_str(&jwe).unwrap();

        let tag = val["tag"].as_str().unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(tag).unwrap();
        bytes[0] ^= 0x01;
        val["tag"] = Value::String(URL_SAFE_NO_PAD.encode(&bytes));
        let tampered = serde_json::to_string(&val).unwrap();

        let err = decrypt_context(&tampered, DEV1_ID, &device(&DEV1_SEED))
            .expect_err("tampered tag must fail GCM auth");
        assert_eq!(err, JweError::DecryptionFailed);
    }

    /// Tampering the protected header (the GCM AAD) → DecryptionFailed. Here we re-encode a
    /// protected header with an *extra* member so the b64url AAD bytes differ but `enc` is still
    /// A256GCM (so it passes the enc check and reaches the GCM step).
    #[test]
    fn tampered_protected_aad_detected() {
        let jwe = encrypt_to_one();
        let mut val: Value = serde_json::from_str(&jwe).unwrap();

        // A different-but-valid protected header with enc still A256GCM.
        let forged = serde_json::json!({ "enc": "A256GCM", "x": "tampered" });
        let forged_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        val["protected"] = Value::String(forged_b64);
        let tampered = serde_json::to_string(&val).unwrap();

        let err = decrypt_context(&tampered, DEV1_ID, &device(&DEV1_SEED))
            .expect_err("tampered AAD (protected header) must fail GCM auth");
        assert_eq!(err, JweError::DecryptionFailed);
    }

    /// Flipping a byte in a recipient's wrapped CEK → KeyUnwrapFailed (RFC 3394 integrity check).
    #[test]
    fn tampered_encrypted_key_detected() {
        let jwe = encrypt_to_one();
        let mut val: Value = serde_json::from_str(&jwe).unwrap();

        let ek = val["recipients"][0]["encrypted_key"].as_str().unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(ek).unwrap();
        bytes[0] ^= 0x01;
        val["recipients"][0]["encrypted_key"] = Value::String(URL_SAFE_NO_PAD.encode(&bytes));
        let tampered = serde_json::to_string(&val).unwrap();

        let err = decrypt_context(&tampered, DEV1_ID, &device(&DEV1_SEED))
            .expect_err("tampered encrypted_key must fail key unwrap");
        assert_eq!(err, JweError::KeyUnwrapFailed);
    }

    // ── Determinism given a fixed RNG (proves no hidden OS-RNG use) ───────────────

    /// Two encryptions with two freshly-seeded IDENTICAL ChaCha20Rng instances produce byte-
    /// identical JWE output. If the core reached for an OS RNG anywhere, this would diverge.
    #[test]
    fn deterministic_given_fixed_rng() {
        let dev_pub = device(&DEV1_SEED).public_key();
        let recipients = [ContextRecipient {
            device_id: DEV1_ID,
            public_key: &dev_pub,
        }];

        let a = encrypt_context(&make_context(), &recipients, &mut rng());
        let b = encrypt_context(&make_context(), &recipients, &mut rng());
        assert_eq!(
            a, b,
            "fixed-seed RNG must yield identical JWE bytes (no hidden OS RNG)"
        );
    }

    // ── Structural assertions (RFC 7516 §7.2.1 + RFC 7518 + RFC 8037) ─────────────

    /// The JWE JSON has the General-serialization shape: a `protected` header that decodes to
    /// `{"enc":"A256GCM"}`, a `recipients` array (one per device, each `ECDH-ES+A256KW` with a
    /// `kid` and an OKP/X25519 `epk`), and top-level `iv`/`ciphertext`/`tag`.
    #[test]
    fn jwe_has_general_serialization_structure() {
        let p1 = device(&DEV1_SEED).public_key();
        let p2 = device(&DEV2_SEED).public_key();
        let recipients = [
            ContextRecipient {
                device_id: DEV1_ID,
                public_key: &p1,
            },
            ContextRecipient {
                device_id: DEV2_ID,
                public_key: &p2,
            },
        ];
        let jwe = encrypt_context(&make_context(), &recipients, &mut rng());
        let val: Value = serde_json::from_str(&jwe).unwrap();

        // protected → {"enc":"A256GCM"}
        let protected_b64 = val["protected"]
            .as_str()
            .expect("protected must be a string");
        let protected: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected_b64).unwrap()).unwrap();
        assert_eq!(protected["enc"], serde_json::json!("A256GCM"));
        // The protected header carries ONLY enc (no per-recipient alg leaks into it).
        assert!(
            protected.get("alg").is_none(),
            "alg is per-recipient, not in protected"
        );

        // recipients: one per device, each with alg/kid/epk.
        let recips = val["recipients"]
            .as_array()
            .expect("recipients must be an array");
        assert_eq!(recips.len(), 2);
        for (entry, expected_id) in recips.iter().zip([DEV1_ID, DEV2_ID]) {
            assert_eq!(entry["header"]["alg"], serde_json::json!("ECDH-ES+A256KW"));
            assert_eq!(entry["header"]["kid"], serde_json::json!(expected_id));
            assert_eq!(entry["header"]["epk"]["kty"], serde_json::json!("OKP"));
            assert_eq!(entry["header"]["epk"]["crv"], serde_json::json!("X25519"));
            // epk.x decodes to exactly 32 bytes.
            let x = entry["header"]["epk"]["x"].as_str().unwrap();
            assert_eq!(
                URL_SAFE_NO_PAD.decode(x).unwrap().len(),
                32,
                "epk.x is a 32-byte key"
            );
            assert!(
                entry.get("encrypted_key").is_some(),
                "each recipient carries encrypted_key"
            );
        }

        // Top-level iv / ciphertext / tag, correctly sized.
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(val["iv"].as_str().unwrap())
                .unwrap()
                .len(),
            IV_LEN
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(val["tag"].as_str().unwrap())
                .unwrap()
                .len(),
            16
        );
        assert!(!val["ciphertext"].as_str().unwrap().is_empty());
    }

    // ── enc / alg negative checks ────────────────────────────────────────────────

    /// A JWE whose protected `enc` is not A256GCM → UnsupportedEnc (before any crypto).
    #[test]
    fn unsupported_enc_rejected() {
        let jwe = encrypt_to_one();
        let mut val: Value = serde_json::from_str(&jwe).unwrap();
        let forged = serde_json::json!({ "enc": "A128GCM" });
        val["protected"] =
            Value::String(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap()));
        let bad = serde_json::to_string(&val).unwrap();

        let err = decrypt_context(&bad, DEV1_ID, &device(&DEV1_SEED))
            .expect_err("non-A256GCM enc must be rejected");
        assert_eq!(err, JweError::UnsupportedEnc);
    }

    /// A recipient whose `alg` is not ECDH-ES+A256KW → UnsupportedAlg.
    #[test]
    fn unsupported_alg_rejected() {
        let jwe = encrypt_to_one();
        let mut val: Value = serde_json::from_str(&jwe).unwrap();
        val["recipients"][0]["header"]["alg"] = serde_json::json!("RSA-OAEP");
        let bad = serde_json::to_string(&val).unwrap();

        let err = decrypt_context(&bad, DEV1_ID, &device(&DEV1_SEED))
            .expect_err("non-ECDH-ES+A256KW alg must be rejected");
        assert_eq!(err, JweError::UnsupportedAlg);
    }

    /// A recipient whose `epk` is not OKP/X25519 → BadEpk.
    #[test]
    fn bad_epk_kty_rejected() {
        let jwe = encrypt_to_one();
        let mut val: Value = serde_json::from_str(&jwe).unwrap();
        val["recipients"][0]["header"]["epk"]["kty"] = serde_json::json!("EC");
        let bad = serde_json::to_string(&val).unwrap();

        let err = decrypt_context(&bad, DEV1_ID, &device(&DEV1_SEED))
            .expect_err("non-OKP epk must be rejected");
        assert_eq!(err, JweError::BadEpk);
    }

    /// An `epk.x` that does not decode to 32 bytes → BadEpk.
    #[test]
    fn bad_epk_wrong_length_rejected() {
        let jwe = encrypt_to_one();
        let mut val: Value = serde_json::from_str(&jwe).unwrap();
        val["recipients"][0]["header"]["epk"]["x"] =
            Value::String(URL_SAFE_NO_PAD.encode([0u8; 16])); // 16 bytes, not 32
        let bad = serde_json::to_string(&val).unwrap();

        let err = decrypt_context(&bad, DEV1_ID, &device(&DEV1_SEED))
            .expect_err("a 16-byte epk must be rejected");
        assert_eq!(err, JweError::BadEpk);
    }

    /// Garbage (non-JSON) input → Malformed (clean, no panic).
    #[test]
    fn malformed_json_rejected() {
        let err = decrypt_context("not-json", DEV1_ID, &device(&DEV1_SEED))
            .expect_err("non-JSON must be rejected");
        assert_eq!(err, JweError::Malformed);
    }

    // ── Key abstraction sanity ────────────────────────────────────────────────────

    /// from_seed is deterministic and the public key round-trips through bytes.
    #[test]
    fn x25519_public_key_round_trips_through_bytes() {
        let pk = device(&DEV1_SEED).public_key();
        let restored = X25519PublicKey::from_bytes(&pk.to_bytes());
        assert_eq!(
            pk, restored,
            "X25519 public key must round-trip through its bytes"
        );
    }

    // ── Concat KDF OtherInfo known-answer (RFC 7518 §4.6.2) ──────────────────────

    /// The OtherInfo byte layout is asserted against the hand-derived bytes from RFC 7518 §4.6.2
    /// (NIST SP 800-56A §5.8.1.2) for ECDH-ES+A256KW with empty apu/apv and a 256-bit key:
    ///
    /// ```text
    /// 00 00 00 06 41 32 35 36 4B 57   AlgorithmID = len(6) || "A256KW"
    /// 00 00 00 00                     PartyUInfo  = len(0)
    /// 00 00 00 00                     PartyVInfo  = len(0)
    /// 00 00 01 00                     SuppPubInfo = keydatalen 256 (direct, not len-prefixed)
    /// ```
    ///
    /// This is a structural KAT for OtherInfo (the per-message Z is random, so a full KEK KAT is
    /// not fixed; the structure is what the RFC pins).
    #[test]
    fn concat_kdf_other_info_matches_rfc7518() {
        let expected: &[u8] = &[
            0x00, 0x00, 0x00, 0x06, // AlgorithmID length = 6
            0x41, 0x32, 0x35, 0x36, 0x4B, 0x57, // "A256KW"
            0x00, 0x00, 0x00, 0x00, // PartyUInfo length = 0
            0x00, 0x00, 0x00, 0x00, // PartyVInfo length = 0
            0x00, 0x00, 0x01, 0x00, // SuppPubInfo = keydatalen 256, 32-bit big-endian
        ];
        assert_eq!(
            concat_kdf_other_info(),
            expected,
            "Concat KDF OtherInfo must match the RFC 7518 §4.6.2 byte layout for ECDH-ES+A256KW"
        );
    }

    /// Full KEK known-answer test for a FIXED shared secret `Z = [0x07; 32]`.
    ///
    /// The expected KEK was computed INDEPENDENTLY (Python `hashlib`), implementing the NIST
    /// SP 800-56A / RFC 7518 §4.6.2 single-round Concat KDF by hand:
    /// `KEK = SHA-256( 0x00000001 || Z || OtherInfo )` with the OtherInfo bytes asserted in
    /// [`concat_kdf_other_info_matches_rfc7518`]. This makes [`derive_kek`] non-tautological — it
    /// catches any byte-order / round-counter / OtherInfo-placement bug in the derivation.
    ///
    /// Reference KEK (hex): dbe8dfe245edbd15590f521cd727ffe430c15edb9721e221839ee3128cde8529
    #[test]
    fn derive_kek_known_answer() {
        let z = [0x07u8; X25519_LEN];
        let expected: [u8; KEK_LEN] = [
            0xdb, 0xe8, 0xdf, 0xe2, 0x45, 0xed, 0xbd, 0x15, 0x59, 0x0f, 0x52, 0x1c, 0xd7, 0x27,
            0xff, 0xe4, 0x30, 0xc1, 0x5e, 0xdb, 0x97, 0x21, 0xe2, 0x21, 0x83, 0x9e, 0xe3, 0x12,
            0x8c, 0xde, 0x85, 0x29,
        ];
        assert_eq!(
            derive_kek(&z),
            expected,
            "Concat KDF KEK must match the independently hand-computed SP 800-56A value"
        );
    }
}
