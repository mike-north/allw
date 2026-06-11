//! Verdict signing + verification (Ed25519 / EdDSA compact JWS). See `docs/contract.md`.
//!
//! This module is the keystone of the **verifiable verdict** invariant
//! (`docs/contract.md` §Invariants #2): a verdict is a signed artifact any party can verify
//! *without trusting the relay*, cryptographically bound to the exact request. It also
//! enforces **fail-closed** (#6): every code path here returns `Err` — never a permissive
//! default — on any failure, and the only success is an *authenticated, bound, fresh,
//! approved* decision.
//!
//! # Signing substrate: hand-rolled EdDSA compact JWS
//!
//! The verdict signature is a literal **EdDSA compact JWS** (RFC 7515 + RFC 8037), built by
//! hand on [`ed25519_dalek`]. We do not use josekit / jsonwebtoken: those depend on OpenSSL
//! or ring and cannot target `wasm32`, but the on-machine surfaces (hook, SDK) MUST run as
//! WASM under `node` (`docs/architecture.md` — WASM-local is a hard constraint). `ed25519-dalek`
//! is pure Rust and compiles to `wasm32`.
//!
//! A compact JWS is three base64url-unpadded parts joined by `.`:
//!
//! ```text
//! b64url(protected_header_json) || "." || b64url(payload_json) || "." || b64url(signature)
//! ```
//!
//! The **signing input** is the ASCII string `b64url(header) || "." || b64url(payload)`, and
//! the Ed25519 signature covers exactly those ASCII bytes (RFC 7515 §5.1). This is
//! *sign-what-you-send*: the transmitted base64url payload bytes are authoritative, so no JCS
//! canonicalization is required on the JWS payload (unlike the `request_hash` in `hash.rs`,
//! whose two independent producers each canonicalize from plaintext).
//!
//! # Two JWS types, domain-separated by `typ`
//!
//! 1. **Verdict JWS** — signed by the **device** key. `typ = "allw-verdict+jws"`,
//!    `kid = <device_id>`. Payload = [`VerdictClaims`].
//! 2. **Device-cert JWS** — signed by the **account root** key, binding a device key to the
//!    account. `typ = "allw-device-cert+jws"`, `kid = <account_id>`. Payload = [`DeviceCertClaims`].
//!
//! The distinct `typ` values prevent a verdict JWS from being accepted where a device-cert is
//! expected (or vice versa) — cross-protocol confusion is rejected before signature checks.
//!
//! # Keys
//!
//! In production, device keys live in **Secure Enclave / StrongBox** (biometric-gated) and the
//! account root key lives in an **HSM-class** store; neither ever leaves hardware. The
//! [`SigningKeyPair::from_seed`] constructor here is for v1/testing and key-derivation glue
//! only — it takes raw seed bytes, which a hardware-backed key never exposes.
//!
//! # Verification is not authorization
//!
//! A successful [`verify_verdict`] means *authenticated + bound + fresh + approved* — it is
//! **still not** authorization. The core never returns "allow" (`docs/contract.md`
//! §Invariants #5). The caller composes the final decision via [`effective_allow`]:
//! `allow = approved ∧ verified ∧ policy ∧ other_gates`. A verdict can only ever **tighten**.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::contract::{ApprovalContext, ApprovalRequest, Approver, Decision, Verdict};

// ── JWS `typ` domain separators ─────────────────────────────────────────────────

/// `typ` header value for a verdict JWS (signed by a device key).
const TYP_VERDICT: &str = "allw-verdict+jws";

/// `typ` header value for a device-cert JWS (signed by the account root key).
const TYP_DEVICE_CERT: &str = "allw-device-cert+jws";

/// The only signature algorithm accepted: EdDSA over Ed25519 (RFC 8037).
const ALG_EDDSA: &str = "EdDSA";

// ── Key abstractions ────────────────────────────────────────────────────────────

/// An Ed25519 signing keypair (private key material + derived public key).
///
/// Wraps [`ed25519_dalek::SigningKey`] rather than re-exporting it, so the dalek types never
/// leak into this crate's public API (callers depend on the contract, not on a specific
/// curve library version).
///
/// # Production key custody
///
/// In production a device's signing key lives in **Secure Enclave / StrongBox** with
/// biometric-gated signing, and the account root key lives in an **HSM-class** store; the
/// private bytes never leave hardware. [`from_seed`](Self::from_seed) exists for v1 and tests
/// only — a hardware-backed key never exposes its seed.
pub struct SigningKeyPair {
    inner: SigningKey,
}

impl SigningKeyPair {
    /// Constructs a keypair from a fixed 32-byte seed.
    ///
    /// Deterministic by design (no RNG): the same seed always yields the same key. This keeps
    /// the core wasm-friendly (no `getrandom`) and test vectors reproducible. **Not** for
    /// production key generation — see the type-level docs on key custody.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(seed),
        }
    }

    /// Returns the corresponding [`PublicKey`] (Ed25519 verifying key).
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Signs `msg` and returns the raw 64-byte Ed25519 signature.
    fn sign_bytes(&self, msg: &[u8]) -> [u8; 64] {
        self.inner.sign(msg).to_bytes()
    }
}

/// An Ed25519 public (verifying) key.
///
/// Wraps [`ed25519_dalek::VerifyingKey`] so the dalek type stays out of the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    inner: VerifyingKey,
}

impl PublicKey {
    /// Reconstructs a public key from its 32-byte compressed Edwards-point encoding.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::InvalidPublicKey`] if the bytes are not a valid Ed25519 point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        VerifyingKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(|_| KeyError::InvalidPublicKey)
    }

    /// Returns the 32-byte compressed encoding of this public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Verifies a raw 64-byte Ed25519 `sig` over `msg`. Returns `true` iff valid.
    ///
    /// Uses `verify_strict` (not `verify`): it rejects non-canonical `S` and small-order
    /// public keys, giving signature-malleability resistance and stronger cross-implementation
    /// verification consensus — important for the "any party can verify" invariant.
    fn verify_bytes(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let signature = Signature::from_bytes(sig);
        self.inner.verify_strict(msg, &signature).is_ok()
    }
}

/// Error constructing a key from raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The 32 bytes are not a valid Ed25519 public key (point not on the curve).
    InvalidPublicKey,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid Ed25519 public key encoding"),
        }
    }
}

impl std::error::Error for KeyError {}

// ── JWS protected header ─────────────────────────────────────────────────────────

/// A JWS protected header (the `{"alg","typ","kid"}` object).
///
/// `alg` is always `"EdDSA"`; `typ` is one of [`TYP_VERDICT`] / [`TYP_DEVICE_CERT`]; `kid`
/// identifies the signing key (device id or account id).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwsHeader {
    alg: String,
    typ: String,
    kid: String,
}

// ── Claim sets (JWS payloads) ────────────────────────────────────────────────────

/// The signed claims inside a **verdict** JWS — the bytes the device signature authenticates.
///
/// These claims (not the outer [`Verdict`] plaintext fields) are authoritative.
/// [`verify_verdict`] cross-checks every outer field against the matching claim.
///
/// Binary fields (`request_hash`, `nonce`) serialize as base64url-unpadded strings, consistent
/// with the rest of the wire format. `challenge_response` is included (and therefore signed)
/// only when present.
///
/// See `docs/contract.md` §Lifecycle step 5 and §Wire encoding → verdict signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictClaims {
    /// The [`ApprovalRequest::id`] this verdict responds to.
    pub request_id: String,

    /// WYSIWYS binding — SHA-256 of the exact plaintext the human saw (`hash.rs`).
    #[serde(with = "b64_32")]
    pub request_hash: [u8; 32],

    /// The human's decision.
    pub decision: Decision,

    /// Time the decision was made — Unix milliseconds (UTC).
    pub decided_at: i64,

    /// Anti-replay nonce, unique per verdict. Checked against a [`NonceStore`] on verify.
    #[serde(with = "b64_vec")]
    pub nonce: Vec<u8>,

    /// Number-match challenge response. Signed (and present) only when a challenge was required.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub challenge_response: Option<String>,
}

/// The signed claims inside a **device-cert** JWS — binds a device key to an account.
///
/// Signed by the account root key, so a verifier holding only the account root public key can
/// transitively trust any device key the root has certified.
///
/// See `docs/contract.md` §Identity & keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertClaims {
    /// The account this device belongs to.
    pub account_id: String,

    /// The device being certified.
    pub device_id: String,

    /// The device's Ed25519 verifying key (32-byte compressed encoding).
    #[serde(with = "b64_32")]
    pub device_pubkey: [u8; 32],

    /// Issuance time — Unix milliseconds (UTC).
    pub issued_at: i64,

    /// Optional expiry — Unix milliseconds (UTC). `None` means the cert does not expire in v1.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<i64>,
}

// ── base64url serde helpers (local to this module) ───────────────────────────────

/// `[u8; 32]` ↔ base64url-unpadded string.
mod b64_32 {
    use super::URL_SAFE_NO_PAD;
    use base64::Engine;
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

/// `Vec<u8>` ↔ base64url-unpadded string.
mod b64_vec {
    use super::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        URL_SAFE_NO_PAD.decode(&s).map_err(D::Error::custom)
    }
}

// ── Compact JWS encode/decode ────────────────────────────────────────────────────

/// Low-level error decoding or verifying a compact JWS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwsError {
    /// The compact serialization did not have exactly three `.`-separated parts.
    MalformedStructure,
    /// A base64url part failed to decode.
    InvalidBase64,
    /// The protected header was not valid JSON / not the expected shape.
    InvalidHeader,
    /// The payload was not valid JSON for the expected claim type.
    InvalidPayload,
    /// `alg` was not `"EdDSA"`.
    UnexpectedAlg,
    /// `typ` did not match the expected value for this JWS kind.
    UnexpectedTyp,
    /// The Ed25519 signature did not verify against the signing input.
    BadSignature,
}

impl std::fmt::Display for JwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::MalformedStructure => "compact JWS must have exactly three '.'-separated parts",
            Self::InvalidBase64 => "compact JWS part is not valid base64url",
            Self::InvalidHeader => "compact JWS protected header is not valid JSON",
            Self::InvalidPayload => "compact JWS payload is not valid JSON for the expected claims",
            Self::UnexpectedAlg => "compact JWS alg is not EdDSA",
            Self::UnexpectedTyp => "compact JWS typ does not match the expected value",
            Self::BadSignature => "compact JWS Ed25519 signature did not verify",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for JwsError {}

/// Encodes and signs a compact JWS from a header and a serializable payload.
///
/// Returns `b64url(header) || "." || b64url(payload) || "." || b64url(sig)`, where `sig` is the
/// Ed25519 signature over the ASCII signing input `b64url(header) || "." || b64url(payload)`.
fn encode_compact_jws<T: Serialize>(
    header: &JwsHeader,
    payload: &T,
    key: &SigningKeyPair,
) -> String {
    // serde_json on these small structs cannot fail; expect is a hard programming-error guard.
    let header_json =
        serde_json::to_vec(header).expect("JwsHeader must serialize (infallible for valid header)");
    let payload_json =
        serde_json::to_vec(payload).expect("JWS payload must serialize (infallible for claims)");

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = key.sign_bytes(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    format!("{signing_input}.{sig_b64}")
}

/// The decoded, signature-verified parts of a compact JWS.
struct DecodedJws<T> {
    header: JwsHeader,
    claims: T,
}

/// Decodes a compact JWS, checks `alg`/`typ`, and verifies the signature against `key`.
///
/// On success the returned [`DecodedJws`] is authenticated: the signature covered exactly the
/// header+payload bytes present in `compact`.
fn decode_and_verify_jws<T: for<'de> Deserialize<'de>>(
    compact: &str,
    expected_typ: &str,
    key: &PublicKey,
) -> Result<DecodedJws<T>, JwsError> {
    let mut parts = compact.split('.');
    let header_b64 = parts.next().ok_or(JwsError::MalformedStructure)?;
    let payload_b64 = parts.next().ok_or(JwsError::MalformedStructure)?;
    let sig_b64 = parts.next().ok_or(JwsError::MalformedStructure)?;
    if parts.next().is_some() {
        // A fourth segment means this is not a valid compact serialization.
        return Err(JwsError::MalformedStructure);
    }

    let header_json = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| JwsError::InvalidBase64)?;
    let payload_json = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| JwsError::InvalidBase64)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| JwsError::InvalidBase64)?;

    let header: JwsHeader =
        serde_json::from_slice(&header_json).map_err(|_| JwsError::InvalidHeader)?;
    if header.alg != ALG_EDDSA {
        return Err(JwsError::UnexpectedAlg);
    }
    if header.typ != expected_typ {
        return Err(JwsError::UnexpectedTyp);
    }

    // Ed25519 signatures are exactly 64 bytes.
    let sig: [u8; 64] = sig_bytes.try_into().map_err(|_| JwsError::BadSignature)?;

    // Verify over the ASCII signing input — the *transmitted* header.payload bytes.
    let signing_input = format!("{header_b64}.{payload_b64}");
    if !key.verify_bytes(signing_input.as_bytes(), &sig) {
        return Err(JwsError::BadSignature);
    }

    // Only decode claims after the signature is proven, so we never trust unsigned bytes.
    let claims: T = serde_json::from_slice(&payload_json).map_err(|_| JwsError::InvalidPayload)?;

    Ok(DecodedJws { header, claims })
}

// ── Signing API ──────────────────────────────────────────────────────────────────

/// An unsigned verdict: every [`Verdict`] field except the crypto-derived `sig`/`device_cert`.
///
/// Making the signing input an explicit type (rather than a partially-built `Verdict`) keeps it
/// unambiguous what is signed: [`sign_verdict`] derives the [`VerdictClaims`] from these fields
/// plus the `nonce`, signs them, and assembles the final [`Verdict`].
pub struct UnsignedVerdict {
    /// Protocol/schema version.
    pub v: u32,
    /// The [`ApprovalRequest::id`] this verdict responds to.
    pub request_id: String,
    /// WYSIWYS binding hash (echoes the request's `request_hash`).
    pub request_hash: [u8; 32],
    /// The human's decision.
    pub decision: Decision,
    /// Decision time — Unix milliseconds (UTC).
    pub decided_at: i64,
    /// Account + device identity of the signer.
    pub approver: Approver,
    /// Optional free-form note from the approver.
    pub note: Option<String>,
    /// Number-match challenge response, when a challenge was required.
    pub challenge_response: Option<String>,
}

/// Signs a verdict: builds the [`VerdictClaims`], encodes+signs an EdDSA compact JWS with the
/// **device** key, and returns a fully populated [`Verdict`] whose `sig` is that JWS.
///
/// The `nonce` is the per-verdict anti-replay value; it is signed (inside the claims) and later
/// checked against a [`NonceStore`] on verify. `device_cert` is the device→root certificate
/// JWS (from [`issue_device_cert`]); pass `Some` so verifiers can chain to the account root.
///
/// The JWS header `kid` is taken from `unsigned.approver.device_id` (not a separate parameter),
/// so the signed `kid` and the outer verdict's device id cannot diverge — [`verify_verdict`]
/// requires `kid == approver.device_id`, and deriving both from one source removes the chance to
/// build a self-inconsistent verdict.
#[must_use]
pub fn sign_verdict(
    unsigned: &UnsignedVerdict,
    device_key: &SigningKeyPair,
    nonce: &[u8],
    device_cert: Option<String>,
) -> Verdict {
    let claims = VerdictClaims {
        request_id: unsigned.request_id.clone(),
        request_hash: unsigned.request_hash,
        decision: unsigned.decision,
        decided_at: unsigned.decided_at,
        nonce: nonce.to_vec(),
        challenge_response: unsigned.challenge_response.clone(),
    };

    let header = JwsHeader {
        alg: ALG_EDDSA.to_string(),
        typ: TYP_VERDICT.to_string(),
        kid: unsigned.approver.device_id.clone(),
    };

    let sig = encode_compact_jws(&header, &claims, device_key);

    Verdict {
        v: unsigned.v,
        request_id: unsigned.request_id.clone(),
        request_hash: unsigned.request_hash,
        decision: unsigned.decision,
        decided_at: unsigned.decided_at,
        approver: unsigned.approver.clone(),
        note: unsigned.note.clone(),
        challenge_response: unsigned.challenge_response.clone(),
        sig,
        device_cert,
    }
}

/// Issues a device certificate: an EdDSA compact JWS, signed by the **account root** key,
/// binding `device_pubkey` to `(account_id, device_id)`.
///
/// Verifiers need only the account root public key: a valid device-cert lets them trust the
/// device key it certifies (`docs/contract.md` §Identity & keys).
#[must_use]
pub fn issue_device_cert(
    account_root: &SigningKeyPair,
    account_id: &str,
    device_id: &str,
    device_pubkey: &PublicKey,
    issued_at: i64,
    expires_at: Option<i64>,
) -> String {
    let claims = DeviceCertClaims {
        account_id: account_id.to_string(),
        device_id: device_id.to_string(),
        device_pubkey: device_pubkey.to_bytes(),
        issued_at,
        expires_at,
    };

    let header = JwsHeader {
        alg: ALG_EDDSA.to_string(),
        typ: TYP_DEVICE_CERT.to_string(),
        kid: account_id.to_string(),
    };

    encode_compact_jws(&header, &claims, account_root)
}

// ── Anti-replay nonce store ──────────────────────────────────────────────────────

/// An anti-replay store for verdict nonces, owned by the integrator.
///
/// `docs/contract.md` lists the integrator-side nonce store as an open decision; v1 ships this
/// trait plus an in-memory implementation. A production store would persist nonces and expire
/// them (e.g. past the request window) so the set cannot grow without bound.
pub trait NonceStore {
    /// Records `nonce` as seen. Returns `true` if it was previously **unseen** (and is now
    /// recorded), `false` if it was already present (a replay).
    fn check_and_insert(&mut self, nonce: &[u8]) -> bool;
}

/// A simple in-memory [`NonceStore`] backed by a `HashSet`.
///
/// v1 / single-process default. Nonces accumulate for the lifetime of the store; persistence
/// and expiry are deferred (see the [`NonceStore`] docs).
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    seen: HashSet<Vec<u8>>,
}

impl InMemoryNonceStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }
}

impl NonceStore for InMemoryNonceStore {
    fn check_and_insert(&mut self, nonce: &[u8]) -> bool {
        self.seen.insert(nonce.to_vec())
    }
}

// ── Verification ─────────────────────────────────────────────────────────────────

/// The result of a successful [`verify_verdict`]: an *authenticated, bound, fresh, approved*
/// decision.
///
/// This is **not** authorization. The caller still composes the final allow decision via
/// [`effective_allow`] (`docs/contract.md` §Invariants #5, §checklist step 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedVerdict {
    /// The decision that was verified (always [`Decision::Approved`] on success — a non-approved
    /// but authenticated decision returns [`VerifyError::NotApproved`]).
    pub decision: Decision,
    /// The device that signed the verdict (from the verified device cert / verdict header).
    pub device_id: String,
    /// The full approver identity (account + device).
    pub approver: Approver,
    /// The decision time — Unix milliseconds (UTC), taken from the signed claims.
    pub decided_at: i64,
    /// The signed anti-replay nonce, returned so bindings can thread freshness into their own
    /// long-lived stores after the core has authenticated the verdict.
    pub nonce: Vec<u8>,
}

/// Why a verdict failed verification. Every variant is a **deny** (fail-closed).
///
/// Variants are ordered to mirror the `docs/contract.md` §Verification checklist steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Step 1 — no `device_cert` was present, so the device key cannot be chained to the root.
    MissingDeviceCert,
    /// Step 1 — the device-cert JWS did not verify against the account root key (or was malformed).
    CertSignatureInvalid,
    /// Step 1 — the cert's `account_id` does not match the verdict's `approver.account_id`.
    CertAccountMismatch,
    /// Step 1 — the cert's `device_id` does not match the verdict's `approver.device_id`.
    CertDeviceMismatch,
    /// Step 1 — the cert has expired (`now_ms > expires_at`).
    CertExpired,
    /// Step 2 — the verdict JWS signature did not verify against the certified device key.
    VerdictSignatureInvalid,
    /// Step 2 — the verdict JWS was structurally malformed, or its `kid`/`typ`/`alg` was wrong.
    MalformedJws,
    /// Step 3 — an outer [`Verdict`] field disagreed with the signed claim of the same name.
    ClaimsMismatch {
        /// The field whose outer value diverged from the signed claim.
        field: &'static str,
    },
    /// Step 4 — the signed `request_id` does not match `request.id`. The verdict was signed for a
    /// different request (possibly one that renders identically — see the no-swap invariant).
    RequestIdMismatch,
    /// Step 4 — the signed `request_hash` does not bind to `request.request_hash`.
    RequestHashMismatch,
    /// Step 5 — `now_ms` is past `request.expires_at`.
    Expired,
    /// Step 5 — `decided_at` is outside `[request.created_at, request.expires_at]`.
    DecidedAtOutOfWindow,
    /// Step 6 — the nonce was already seen (replay).
    Replay,
    /// Step 7 — a challenge was required but no (non-empty) challenge response was present.
    ChallengeMissing,
    /// Step 8 — the verdict is authenticated and bound, but the human did **not** approve.
    ///
    /// This is distinct from any crypto error: it is a *verified* denial / expiry / abort, not
    /// a forgery. Carries the decision so the caller can record the verified human "no".
    NotApproved {
        /// The authenticated non-approving decision.
        decision: Decision,
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDeviceCert => {
                write!(
                    f,
                    "verdict has no device_cert; cannot chain device key to account root"
                )
            }
            Self::CertSignatureInvalid => {
                write!(f, "device cert did not verify against the account root key")
            }
            Self::CertAccountMismatch => {
                write!(
                    f,
                    "device cert account_id does not match the verdict approver"
                )
            }
            Self::CertDeviceMismatch => {
                write!(
                    f,
                    "device cert device_id does not match the verdict approver"
                )
            }
            Self::CertExpired => write!(f, "device cert has expired"),
            Self::VerdictSignatureInvalid => {
                write!(
                    f,
                    "verdict signature did not verify against the certified device key"
                )
            }
            Self::MalformedJws => {
                write!(f, "verdict JWS is malformed or has the wrong typ/kid/alg")
            }
            Self::ClaimsMismatch { field } => {
                write!(
                    f,
                    "outer verdict field '{field}' disagrees with the signed claim"
                )
            }
            Self::RequestIdMismatch => {
                write!(
                    f,
                    "signed request_id does not match request.id (verdict bound to a different request)"
                )
            }
            Self::RequestHashMismatch => {
                write!(
                    f,
                    "signed request_hash does not match the request (WYSIWYS binding broken)"
                )
            }
            Self::Expired => write!(f, "request has expired (now > expires_at)"),
            Self::DecidedAtOutOfWindow => {
                write!(f, "decided_at is outside [created_at, expires_at]")
            }
            Self::Replay => write!(f, "verdict nonce was already seen (replay)"),
            Self::ChallengeMissing => {
                write!(
                    f,
                    "a challenge was required but no challenge response was present"
                )
            }
            Self::NotApproved { decision } => {
                write!(
                    f,
                    "verified human decision was not 'approved': {decision:?}"
                )
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verifies a [`Verdict`] against the request it answers and the approver's account root key,
/// returning a [`VerifiedVerdict`] only when the verdict is authenticated, bound, fresh, and
/// approved.
///
/// Fail-closed: **any** failure returns `Err` (`docs/contract.md` §Invariants #6). The steps
/// map one-to-one onto the `docs/contract.md` §Verification checklist:
///
/// 1. **Device cert → root** (checklist #1). Requires `verdict.device_cert`
///    ([`VerifyError::MissingDeviceCert`]); verifies its JWS against `approver_root`
///    ([`VerifyError::CertSignatureInvalid`]); checks `typ`, the signed header `kid` and
///    `account_id` ([`VerifyError::CertAccountMismatch`]) and `device_id`
///    ([`VerifyError::CertDeviceMismatch`]); enforces `expires_at` if set
///    ([`VerifyError::CertExpired`]). Yields the certified device public key.
/// 2. **Verdict signature** (checklist #1). Parses `verdict.sig` as a verdict JWS, checks
///    `typ`/`kid == approver.device_id`, and verifies it with the device key from step 1
///    ([`VerifyError::VerdictSignatureInvalid`] / [`VerifyError::MalformedJws`]).
/// 3. **Claims ↔ outer consistency** (checklist #2). Each outer field
///    (`request_id`, `decision`, `decided_at`, `request_hash`, `challenge_response`) must equal
///    its signed claim ([`VerifyError::ClaimsMismatch`]).
/// 4. **Binds the EXACT request — id AND hash** (checklist #2). `claims.request_id == request.id`
///    ([`VerifyError::RequestIdMismatch`]) AND `claims.request_hash` equals the hash recomputed
///    locally from the [`ApprovalContext`] + the envelope's `expires_at` (via
///    [`crate::hash::compute_request_hash`]) ([`VerifyError::RequestHashMismatch`]). The id check
///    is essential because `request_hash` excludes `id`, so it alone cannot distinguish two
///    requests that render identically — this is the "no swap" half of the binding invariant.
/// 5. **Freshness / window** (checklist #4). `now_ms <= request.expires_at`
///    ([`VerifyError::Expired`]); `created_at <= decided_at <= expires_at`
///    ([`VerifyError::DecidedAtOutOfWindow`]).
/// 6. **Anti-replay** (checklist #4). The nonce must be unseen in `nonce_store`
///    ([`VerifyError::Replay`]).
/// 7. **Challenge** (checklist #5). If `context.constraints.challenge_required`, a non-empty
///    `challenge_response` must be present in both the claims and the outer verdict
///    ([`VerifyError::ChallengeMissing`]).
///
///    **v1 limitation:** only the *presence* of a signed challenge response is checked. The
///    number-match *value* is not validated against an expected challenge, because the
///    expected-challenge derivation is not yet specified. See the inline `TODO`.
/// 8. **Decision gate** (checklist #3 / #6). If `claims.decision != Approved`, returns
///    [`VerifyError::NotApproved`] — an authenticated denial/expiry, distinct from a forgery.
///    Otherwise returns `Ok`.
///
/// # Not authorization
///
/// A successful return means *authenticated + bound + fresh + approved*. It is **still not**
/// authorization — the core never returns "allow". The caller composes the final decision via
/// [`effective_allow`]: `allow = approved ∧ verified ∧ policy ∧ other_gates`. A verdict can
/// only ever tighten access (`docs/contract.md` §Invariants #5, §checklist step 6).
///
/// # Errors
///
/// Returns the [`VerifyError`] for the first failing checklist step (see the step list above).
pub fn verify_verdict(
    verdict: &Verdict,
    request: &ApprovalRequest,
    context: &ApprovalContext,
    approver_root: &PublicKey,
    nonce_store: &mut dyn NonceStore,
    now_ms: i64,
) -> Result<VerifiedVerdict, VerifyError> {
    // ── Step 1: device cert chains to the account root ───────────────────────────
    let cert_compact = verdict
        .device_cert
        .as_deref()
        .ok_or(VerifyError::MissingDeviceCert)?;

    let cert: DecodedJws<DeviceCertClaims> =
        decode_and_verify_jws(cert_compact, TYP_DEVICE_CERT, approver_root)
            .map_err(|_| VerifyError::CertSignatureInvalid)?;

    // The cert's signed `kid` must name the account it certifies (docs: device-cert uses
    // `kid: <account_id>`). Checking it rejects key-id confusion before we trust the claims.
    if cert.header.kid != cert.claims.account_id {
        return Err(VerifyError::CertAccountMismatch);
    }
    if cert.claims.account_id != verdict.approver.account_id {
        return Err(VerifyError::CertAccountMismatch);
    }
    if cert.claims.device_id != verdict.approver.device_id {
        return Err(VerifyError::CertDeviceMismatch);
    }
    if let Some(expires_at) = cert.claims.expires_at {
        if now_ms > expires_at {
            return Err(VerifyError::CertExpired);
        }
    }

    // The certified device key — the *only* key trusted to have signed the verdict. A bad
    // encoding here means the cert (though root-signed) carries an invalid key → reject.
    let device_key = PublicKey::from_bytes(&cert.claims.device_pubkey)
        .map_err(|_| VerifyError::CertSignatureInvalid)?;

    // ── Step 2: verdict signature verifies under the certified device key ─────────
    let verdict_jws: DecodedJws<VerdictClaims> =
        decode_and_verify_jws(&verdict.sig, TYP_VERDICT, &device_key).map_err(|e| match e {
            JwsError::BadSignature => VerifyError::VerdictSignatureInvalid,
            _ => VerifyError::MalformedJws,
        })?;

    // The header kid must name the same device the cert certified.
    if verdict_jws.header.kid != verdict.approver.device_id {
        return Err(VerifyError::MalformedJws);
    }

    let claims = &verdict_jws.claims;

    // ── Step 3: outer fields must equal the signed claims ────────────────────────
    if claims.request_id != verdict.request_id {
        return Err(VerifyError::ClaimsMismatch {
            field: "request_id",
        });
    }
    if claims.decision != verdict.decision {
        return Err(VerifyError::ClaimsMismatch { field: "decision" });
    }
    if claims.decided_at != verdict.decided_at {
        return Err(VerifyError::ClaimsMismatch {
            field: "decided_at",
        });
    }
    if claims.request_hash != verdict.request_hash {
        return Err(VerifyError::ClaimsMismatch {
            field: "request_hash",
        });
    }
    // The outer challenge_response must equal the signed one — the plaintext field is otherwise
    // tamperable without breaking the signature (would corrupt downstream logging/UX).
    if claims.challenge_response != verdict.challenge_response {
        return Err(VerifyError::ClaimsMismatch {
            field: "challenge_response",
        });
    }

    // ── Step 4: bind to the EXACT request — id AND hash (no swap) ─────────────────
    // `request_hash` deliberately excludes `id` (it covers only the human-shown content), so two
    // content-identical requests with different ids share a hash. Checking `request.id` closes the
    // swap gap: a verdict signed for one request cannot be accepted for another that merely renders
    // identically (contract.md §Invariants #2 — "bound to the exact request, no swap").
    if claims.request_id != request.id {
        return Err(VerifyError::RequestIdMismatch);
    }
    // Recompute the WYSIWYS hash from the plaintext context the integrator holds (plus the
    // envelope's expires_at) and bind the signed claim to it. The device computed and signed the
    // same value from the decrypted ApprovalContext (#28 / request-hash/v2).
    let expected = crate::hash::compute_request_hash(context, request.expires_at);
    if claims.request_hash != expected {
        return Err(VerifyError::RequestHashMismatch);
    }

    // ── Step 5: freshness / decision window ──────────────────────────────────────
    if now_ms > request.expires_at {
        return Err(VerifyError::Expired);
    }
    if claims.decided_at < request.created_at || claims.decided_at > request.expires_at {
        return Err(VerifyError::DecidedAtOutOfWindow);
    }

    // ── Step 6: anti-replay ──────────────────────────────────────────────────────
    if !nonce_store.check_and_insert(&claims.nonce) {
        return Err(VerifyError::Replay);
    }

    // ── Step 7: challenge presence (value validation deferred) ───────────────────
    if context.constraints.challenge_required {
        // TODO(#follow-up): validate challenge value — match the signed challenge_response
        // against the expected number-match challenge once that derivation is specced. v1
        // only proves a challenge response was signed, not that it is the *correct* one.
        let claim_present = claims
            .challenge_response
            .as_deref()
            .is_some_and(|s| !s.is_empty());
        let outer_present = verdict
            .challenge_response
            .as_deref()
            .is_some_and(|s| !s.is_empty());
        if !(claim_present && outer_present) {
            return Err(VerifyError::ChallengeMissing);
        }
    }

    // ── Step 8: decision gate ────────────────────────────────────────────────────
    if claims.decision != Decision::Approved {
        return Err(VerifyError::NotApproved {
            decision: claims.decision,
        });
    }

    Ok(VerifiedVerdict {
        decision: Decision::Approved,
        device_id: verdict.approver.device_id.clone(),
        approver: verdict.approver.clone(),
        decided_at: claims.decided_at,
        nonce: claims.nonce.clone(),
    })
}

/// Composes the final allow decision from the verified human decision and all other gates.
///
/// `allow = verified_human_approved ∧ policy_allows ∧ other_gates`.
///
/// This is the integrator's composition step (`docs/contract.md` §Invariants #5, §checklist
/// step 6). The core **never returns "allow" by itself**: [`verify_verdict`] contributes only a
/// *verified human decision*, and a verdict can only ever **tighten** — every gate must agree
/// for the result to be `true`. There is intentionally no way to express "the verdict alone
/// grants access."
#[must_use]
pub fn effective_allow(
    verified_human_approved: bool,
    policy_allows: bool,
    other_gates: bool,
) -> bool {
    verified_human_approved && policy_allows && other_gates
}

// ── Tests ─────────────────────────────────────────────────────────────────────────
//
// Spec-first: assertions trace to the docs/contract.md §Verification checklist, not to program
// output. All inputs are fixed and deterministic — fixed 32-byte seeds, fixed i64 ms
// timestamps, fixed nonces — never SystemTime/rand.
//
// @see docs/contract.md §Verification checklist, §Invariants, §Identity & keys, §Wire encoding
// @see https://www.rfc-editor.org/rfc/rfc7515 (JSON Web Signature)
// @see https://www.rfc-editor.org/rfc/rfc8037 (CFRG curves in JOSE — EdDSA / Ed25519)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        ActionRecord, Actor, ApprovalContext, ApprovalRequest, Constraints, Risk, Surface,
        SyntacticSubstrate,
    };
    use crate::hash::compute_request_hash;

    // ── Fixed seeds (never rand) ──────────────────────────────────────────────────
    const ROOT_SEED: [u8; 32] = [0x11u8; 32];
    const DEVICE_SEED: [u8; 32] = [0x22u8; 32];
    const OTHER_ROOT_SEED: [u8; 32] = [0x33u8; 32];

    // ── Fixed identities ──────────────────────────────────────────────────────────
    const ACCOUNT_ID: &str = "acc_test_01";
    const DEVICE_ID: &str = "dev_test_01";
    const REQUEST_ID: &str = "req_test_01";

    // ── Fixed timestamps (Unix ms, never SystemTime::now()) ───────────────────────
    // 2023-11-14T22:13:20Z
    const TS_CREATED: i64 = 1_700_000_000_000;
    // 2023-11-14T23:13:20Z (+1h)
    const TS_EXPIRES: i64 = 1_700_003_600_000;
    // 2023-11-14T22:30:00Z (inside the window)
    const TS_DECIDED: i64 = 1_700_001_000_000;
    // A "now" comfortably inside the window.
    const NOW_OK: i64 = 1_700_001_500_000;

    // ── Fixed binding values ──────────────────────────────────────────────────────
    // A hash that deliberately does NOT match the canonical hash of the standard context, used
    // for "bound to a different request" negative tests.
    const OTHER_REQUEST_HASH: [u8; 32] = [0xCD; 32];
    const NONCE: &[u8] = &[0x01, 0x02, 0x03, 0x04];

    // ── Builders ──────────────────────────────────────────────────────────────────

    fn root_key() -> SigningKeyPair {
        SigningKeyPair::from_seed(&ROOT_SEED)
    }

    fn device_key() -> SigningKeyPair {
        SigningKeyPair::from_seed(&DEVICE_SEED)
    }

    fn make_approver() -> Approver {
        Approver {
            account_id: ACCOUNT_ID.to_string(),
            device_id: DEVICE_ID.to_string(),
        }
    }

    fn make_action() -> ActionRecord {
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
                raw: Some("git push --force".to_string()),
            },
            risk: Risk::High,
            capabilities: None,
            scope: None,
        }
    }

    /// Builds the relay-visible envelope (no `request_hash`, no human-shown context).
    fn make_request() -> ApprovalRequest {
        ApprovalRequest {
            v: 1,
            id: REQUEST_ID.to_string(),
            created_at: TS_CREATED,
            expires_at: TS_EXPIRES,
            approver: ACCOUNT_ID.to_string(),
            context_ciphertext: None,
        }
    }

    /// Builds the human-shown [`ApprovalContext`] with the given challenge requirement.
    fn make_context(challenge_required: bool) -> ApprovalContext {
        ApprovalContext {
            action: make_action(),
            summary: "Force-push to main".to_string(),
            actor: Actor {
                id: "machine:test".to_string(),
                kind: "claude-code".to_string(),
                attestation: None,
            },
            risk: Risk::High,
            reversible: false,
            constraints: Constraints {
                allowed_decisions: vec![Decision::Approved, Decision::Denied],
                challenge_required,
            },
            chain: None,
        }
    }

    /// The canonical WYSIWYS hash of the standard context bound to [`TS_EXPIRES`]. This is the
    /// value a correctly-signed verdict must carry so [`verify_verdict`] accepts it.
    fn canonical_hash(challenge_required: bool) -> [u8; 32] {
        compute_request_hash(&make_context(challenge_required), TS_EXPIRES)
    }

    /// A device cert signed by `root`, certifying the standard device key, no expiry.
    fn make_cert(root: &SigningKeyPair) -> String {
        issue_device_cert(
            root,
            ACCOUNT_ID,
            DEVICE_ID,
            &device_key().public_key(),
            TS_CREATED,
            None,
        )
    }

    /// Builds an unsigned verdict for `decision` bound to `request_hash`, with optional
    /// challenge response.
    fn make_unsigned(
        decision: Decision,
        request_hash: [u8; 32],
        challenge_response: Option<String>,
    ) -> UnsignedVerdict {
        UnsignedVerdict {
            v: 1,
            request_id: REQUEST_ID.to_string(),
            request_hash,
            decision,
            decided_at: TS_DECIDED,
            approver: make_approver(),
            note: None,
            challenge_response,
        }
    }

    /// A fully signed, approved verdict bound to the canonical hash of the standard context
    /// (challenge not required), with a cert from the real root.
    fn make_signed_approved() -> Verdict {
        let cert = make_cert(&root_key());
        sign_verdict(
            &make_unsigned(Decision::Approved, canonical_hash(false), None),
            &device_key(),
            NONCE,
            Some(cert),
        )
    }

    // ── Round-trip happy path ─────────────────────────────────────────────────────

    /// checklist #1–#6: a freshly signed, approved verdict verifies under the account root.
    #[test]
    fn round_trip_happy_path_verifies() {
        let verdict = make_signed_approved();
        let request = make_request();
        let context = make_context(false);
        let root_pub = root_key().public_key();
        let mut store = InMemoryNonceStore::new();

        let verified = verify_verdict(&verdict, &request, &context, &root_pub, &mut store, NOW_OK)
            .expect("must verify");

        assert_eq!(verified.decision, Decision::Approved);
        assert_eq!(verified.device_id, DEVICE_ID);
        assert_eq!(verified.approver, make_approver());
        assert_eq!(verified.decided_at, TS_DECIDED);
    }

    /// The signed `sig` is a three-part compact JWS, and the protected header declares the
    /// verdict typ (docs/contract.md §Wire encoding → verdict signature).
    #[test]
    fn signed_verdict_sig_is_compact_jws_with_verdict_typ() {
        let verdict = make_signed_approved();
        let parts: Vec<&str> = verdict.sig.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS must have three parts");

        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: JwsHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, TYP_VERDICT);
        assert_eq!(header.kid, DEVICE_ID);
    }

    // ── Cert chains to root, not device pubkey directly ───────────────────────────

    /// checklist #1: the verifier uses ONLY the account root; a different root → cert invalid.
    #[test]
    fn cert_signed_by_different_root_fails_cert_signature() {
        // Cert is signed by the REAL root, but we verify against a DIFFERENT root pubkey.
        let verdict = make_signed_approved();
        let request = make_request();
        let context = make_context(false);
        let wrong_root_pub = SigningKeyPair::from_seed(&OTHER_ROOT_SEED).public_key();
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &wrong_root_pub,
            &mut store,
            NOW_OK,
        )
        .expect_err("a cert not signed by the trusted root must fail");
        assert_eq!(err, VerifyError::CertSignatureInvalid);
    }

    /// The verifier never gets the device key directly — only the root-signed cert carries it.
    /// A cert whose claimed account_id differs from the verdict's approver → CertAccountMismatch.
    #[test]
    fn cert_account_mismatch_detected() {
        let cert = issue_device_cert(
            &root_key(),
            "acc_OTHER",
            DEVICE_ID,
            &device_key().public_key(),
            TS_CREATED,
            None,
        );
        let verdict = sign_verdict(
            &make_unsigned(Decision::Approved, canonical_hash(false), None),
            &device_key(),
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("account mismatch must fail");
        assert_eq!(err, VerifyError::CertAccountMismatch);
    }

    /// An expired device cert → CertExpired (checklist #1).
    #[test]
    fn expired_cert_detected() {
        let cert = issue_device_cert(
            &root_key(),
            ACCOUNT_ID,
            DEVICE_ID,
            &device_key().public_key(),
            TS_CREATED,
            Some(TS_DECIDED), // cert expires before NOW_OK
        );
        let verdict = sign_verdict(
            &make_unsigned(Decision::Approved, canonical_hash(false), None),
            &device_key(),
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("expired cert must fail");
        assert_eq!(err, VerifyError::CertExpired);
    }

    /// A missing device cert → MissingDeviceCert (checklist #1, fail-closed).
    #[test]
    fn missing_device_cert_detected() {
        let verdict = sign_verdict(
            &make_unsigned(Decision::Approved, canonical_hash(false), None),
            &device_key(),
            NONCE,
            None, // no cert
        );
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("missing cert must fail");
        assert_eq!(err, VerifyError::MissingDeviceCert);
    }

    // ── Tamper tests ──────────────────────────────────────────────────────────────

    /// Flipping a byte of the verdict JWS signature → VerdictSignatureInvalid (checklist #1).
    #[test]
    fn tampered_verdict_signature_detected() {
        let mut verdict = make_signed_approved();

        // Flip the last base64url char of the signature part.
        let mut parts: Vec<String> = verdict.sig.split('.').map(str::to_string).collect();
        let sig_part = &mut parts[2];
        let last = sig_part.pop().unwrap();
        // Pick a different valid base64url char.
        let replacement = if last == 'A' { 'B' } else { 'A' };
        sig_part.push(replacement);
        verdict.sig = parts.join(".");

        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("tampered signature must fail");
        assert!(
            matches!(
                err,
                VerifyError::VerdictSignatureInvalid | VerifyError::MalformedJws
            ),
            "tampered verdict signature must be VerdictSignatureInvalid or MalformedJws, got {err:?}"
        );
    }

    /// Mutating outer `verdict.decision` so it diverges from the signed claim →
    /// ClaimsMismatch{field:"decision"} (checklist #2).
    #[test]
    fn outer_decision_mismatch_detected() {
        let mut verdict = make_signed_approved();
        verdict.decision = Decision::Denied; // claim still says Approved

        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("outer/claim decision mismatch must fail");
        assert_eq!(err, VerifyError::ClaimsMismatch { field: "decision" });
    }

    /// Mutating outer `verdict.request_hash` so it diverges from the signed claim →
    /// ClaimsMismatch{field:"request_hash"} (checklist #2).
    #[test]
    fn outer_request_hash_mismatch_detected() {
        let mut verdict = make_signed_approved();
        verdict.request_hash = OTHER_REQUEST_HASH; // claim still says REQUEST_HASH

        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("outer/claim request_hash mismatch must fail");
        assert_eq!(
            err,
            VerifyError::ClaimsMismatch {
                field: "request_hash"
            }
        );
    }

    /// A verdict whose SIGNED request_hash binds a DIFFERENT request → RequestHashMismatch
    /// (checklist #2). Here outer and claim agree (both OTHER_REQUEST_HASH), but neither
    /// matches the request being verified (REQUEST_HASH).
    #[test]
    fn signed_request_hash_not_matching_request_detected() {
        let cert = make_cert(&root_key());
        let verdict = sign_verdict(
            &make_unsigned(Decision::Approved, OTHER_REQUEST_HASH, None),
            &device_key(),
            NONCE,
            Some(cert),
        );
        // Request is bound to REQUEST_HASH, not OTHER_REQUEST_HASH.
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("verdict bound to a different request must fail");
        assert_eq!(err, VerifyError::RequestHashMismatch);
    }

    /// Tampering the device-cert payload (without re-signing) → CertSignatureInvalid (checklist #1).
    #[test]
    fn tampered_device_cert_payload_detected() {
        let mut verdict = make_signed_approved();
        let cert = verdict.device_cert.take().unwrap();

        // Replace the cert payload (middle part) with a different, validly-encoded payload
        // claiming a different account — but leave the original root signature in place.
        let mut parts: Vec<String> = cert.split('.').map(str::to_string).collect();
        let forged = DeviceCertClaims {
            account_id: ACCOUNT_ID.to_string(),
            device_id: DEVICE_ID.to_string(),
            device_pubkey: device_key().public_key().to_bytes(),
            issued_at: TS_CREATED + 999, // changed → signature no longer covers it
            expires_at: None,
        };
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        verdict.device_cert = Some(parts.join("."));

        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("tampered cert payload must fail");
        assert_eq!(err, VerifyError::CertSignatureInvalid);
    }

    // ── No-swap: bind to the exact request id, not just identical content ─────────

    /// "No swap" (contract.md §Invariants #2): a verdict legitimately signed for request A
    /// (a different `id`, but identical hashed content) must NOT verify against a
    /// content-identical request B. `request_hash` excludes `id`, so only the `request_id`
    /// check distinguishes them.
    #[test]
    fn verdict_for_content_identical_request_rejected_by_id() {
        let cert = make_cert(&root_key());
        let unsigned = UnsignedVerdict {
            v: 1,
            request_id: "req_OTHER".to_string(), // signed for a DIFFERENT request id...
            request_hash: canonical_hash(false), // ...but identical hashed content
            decision: Decision::Approved,
            decided_at: TS_DECIDED,
            approver: make_approver(),
            note: None,
            challenge_response: None,
        };
        let verdict = sign_verdict(&unsigned, &device_key(), NONCE, Some(cert));

        // Request B: different id, SAME request_hash (renders identically).
        let request = make_request();
        let context = make_context(false); // id == REQUEST_ID
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("a verdict for a different (content-identical) request must be rejected");
        assert_eq!(err, VerifyError::RequestIdMismatch);
    }

    /// The outer `challenge_response` must equal the signed claim: tampering the plaintext field
    /// (without re-signing) is detected as `ClaimsMismatch` (checklist #2 — outer ↔ claims).
    #[test]
    fn tampered_outer_challenge_response_detected() {
        let cert = make_cert(&root_key());
        let mut verdict = sign_verdict(
            &make_unsigned(
                Decision::Approved,
                canonical_hash(true),
                Some("42".to_string()),
            ),
            &device_key(),
            NONCE,
            Some(cert),
        );
        verdict.challenge_response = Some("99".to_string()); // tamper the OUTER field only

        let request = make_request();
        let context = make_context(true);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("tampered outer challenge_response must fail");
        assert_eq!(
            err,
            VerifyError::ClaimsMismatch {
                field: "challenge_response"
            }
        );
    }

    /// A device cert whose signed header `kid` disagrees with its `account_id` is rejected even
    /// though the root signature is valid — guards against key-id confusion.
    #[test]
    fn cert_with_mismatched_kid_rejected() {
        let header = JwsHeader {
            alg: ALG_EDDSA.to_string(),
            typ: TYP_DEVICE_CERT.to_string(),
            kid: "wrong-account".to_string(), // != claims.account_id
        };
        let claims = DeviceCertClaims {
            account_id: ACCOUNT_ID.to_string(),
            device_id: DEVICE_ID.to_string(),
            device_pubkey: device_key().public_key().to_bytes(),
            issued_at: TS_CREATED,
            expires_at: None,
        };
        let cert = encode_compact_jws(&header, &claims, &root_key());
        let verdict = sign_verdict(
            &make_unsigned(Decision::Approved, canonical_hash(false), None),
            &device_key(),
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("cert with mismatched kid must fail");
        assert_eq!(err, VerifyError::CertAccountMismatch);
    }

    // ── Decision gate: verified non-approvals are NotApproved, not crypto errors ──

    /// checklist #3: an authenticated DENIED verdict → NotApproved{Denied} (NOT a crypto error).
    /// Proves we distinguish a verified human "no" from a forgery.
    #[test]
    fn authenticated_denial_returns_not_approved() {
        let cert = make_cert(&root_key());
        let verdict = sign_verdict(
            &make_unsigned(Decision::Denied, canonical_hash(false), None),
            &device_key(),
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("a denial must not be Ok");
        assert_eq!(
            err,
            VerifyError::NotApproved {
                decision: Decision::Denied
            },
            "a verified denial must return NotApproved, not a crypto error"
        );
    }

    /// Same for an authenticated EXPIRED decision → NotApproved{Expired}.
    #[test]
    fn authenticated_expired_decision_returns_not_approved() {
        let cert = make_cert(&root_key());
        let verdict = sign_verdict(
            &make_unsigned(Decision::Expired, canonical_hash(false), None),
            &device_key(),
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("an expired decision must not be Ok");
        assert_eq!(
            err,
            VerifyError::NotApproved {
                decision: Decision::Expired
            }
        );
    }

    /// And for an authenticated ABORTED decision → NotApproved{Aborted}.
    #[test]
    fn authenticated_aborted_decision_returns_not_approved() {
        let cert = make_cert(&root_key());
        let verdict = sign_verdict(
            &make_unsigned(Decision::Aborted, canonical_hash(false), None),
            &device_key(),
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("an aborted decision must not be Ok");
        assert_eq!(
            err,
            VerifyError::NotApproved {
                decision: Decision::Aborted
            }
        );
    }

    // ── Expiry / window ───────────────────────────────────────────────────────────

    /// checklist #4: now_ms past the request expiry → Expired.
    #[test]
    fn now_past_expiry_detected() {
        let verdict = make_signed_approved();
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            TS_EXPIRES + 1, // now is past expiry
        )
        .expect_err("now past expiry must fail");
        assert_eq!(err, VerifyError::Expired);
    }

    /// checklist #4: decided_at before created_at → DecidedAtOutOfWindow.
    #[test]
    fn decided_at_before_created_detected() {
        let cert = make_cert(&root_key());
        let mut unsigned = make_unsigned(Decision::Approved, canonical_hash(false), None);
        unsigned.decided_at = TS_CREATED - 1; // before the window opens
        let verdict = sign_verdict(&unsigned, &device_key(), NONCE, Some(cert));
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("decided_at before created_at must fail");
        assert_eq!(err, VerifyError::DecidedAtOutOfWindow);
    }

    /// checklist #4: decided_at after expires_at → DecidedAtOutOfWindow.
    #[test]
    fn decided_at_after_expiry_detected() {
        let cert = make_cert(&root_key());
        let mut unsigned = make_unsigned(Decision::Approved, canonical_hash(false), None);
        unsigned.decided_at = TS_EXPIRES + 1; // after the window closes
        let verdict = sign_verdict(&unsigned, &device_key(), NONCE, Some(cert));
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        // Use a now that is itself past expiry-free: pick now == decided_at so the Expired check
        // (now <= expires_at) would also trip; instead verify the window check independently by
        // choosing now within range but decided_at out of range is impossible if now>expiry.
        // Here decided_at > expires_at, and we must keep now <= expires_at to reach the window
        // check — but decided_at > expires_at with now <= expires_at is the exact case.
        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            TS_EXPIRES, // now == expires_at, so Expired (now>expiry) does NOT trip
        )
        .expect_err("decided_at after expires_at must fail");
        assert_eq!(err, VerifyError::DecidedAtOutOfWindow);
    }

    // ── Anti-replay ───────────────────────────────────────────────────────────────

    /// checklist #4: verifying the same verdict twice with one store → first Ok, second Replay.
    #[test]
    fn replay_detected_on_second_verification() {
        let verdict = make_signed_approved();
        let request = make_request();
        let context = make_context(false);
        let root_pub = root_key().public_key();
        let mut store = InMemoryNonceStore::new();

        let first = verify_verdict(&verdict, &request, &context, &root_pub, &mut store, NOW_OK);
        assert!(first.is_ok(), "first verification must succeed");

        let err = verify_verdict(&verdict, &request, &context, &root_pub, &mut store, NOW_OK)
            .expect_err("second verification with the same nonce must fail");
        assert_eq!(err, VerifyError::Replay);
    }

    // ── Challenge ─────────────────────────────────────────────────────────────────

    /// checklist #5: challenge required but no challenge_response → ChallengeMissing.
    #[test]
    fn challenge_required_but_missing_detected() {
        // Verdict bound to the challenge-required context's hash (so the request_hash binding
        // passes and we reach the challenge check), but with NO challenge_response.
        let cert = make_cert(&root_key());
        let verdict = sign_verdict(
            &make_unsigned(Decision::Approved, canonical_hash(true), None),
            &device_key(),
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(true);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("missing required challenge response must fail");
        assert_eq!(err, VerifyError::ChallengeMissing);
    }

    /// checklist #5: challenge required AND a present signed challenge_response → passes.
    #[test]
    fn challenge_required_and_present_passes() {
        let cert = make_cert(&root_key());
        let verdict = sign_verdict(
            &make_unsigned(
                Decision::Approved,
                canonical_hash(true),
                Some("42".to_string()),
            ),
            &device_key(),
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(true);
        let mut store = InMemoryNonceStore::new();

        let verified = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect("present challenge response must pass");
        assert_eq!(verified.decision, Decision::Approved);
    }

    /// An empty challenge response is treated as missing (presence must be non-empty).
    #[test]
    fn challenge_required_empty_response_treated_as_missing() {
        let cert = make_cert(&root_key());
        let verdict = sign_verdict(
            &make_unsigned(
                Decision::Approved,
                canonical_hash(true),
                Some(String::new()),
            ),
            &device_key(),
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(true);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("an empty challenge response must be treated as missing");
        assert_eq!(err, VerifyError::ChallengeMissing);
    }

    // ── effective_allow truth table ───────────────────────────────────────────────

    /// docs/contract.md §Invariants #5: allow is the AND of all gates. The verdict alone never
    /// grants access — every gate must be true.
    #[test]
    fn effective_allow_truth_table() {
        assert!(effective_allow(true, true, true), "all gates true → allow");

        // Any single gate false ⇒ deny.
        assert!(
            !effective_allow(false, true, true),
            "unverified/unapproved ⇒ deny"
        );
        assert!(!effective_allow(true, false, true), "policy deny ⇒ deny");
        assert!(
            !effective_allow(true, true, false),
            "other gate false ⇒ deny"
        );
        assert!(!effective_allow(false, false, false), "all false ⇒ deny");
    }

    // ── is_human_approved is unaffected by the sig-type change ────────────────────

    /// is_human_approved still reads `decision` only — independent of the new JWS `sig` field.
    #[test]
    fn is_human_approved_reads_decision_after_sig_change() {
        let mut verdict = make_signed_approved();
        assert!(verdict.is_human_approved());

        verdict.decision = Decision::Denied;
        assert!(!verdict.is_human_approved());
    }

    // ── Key abstraction sanity ────────────────────────────────────────────────────

    /// from_seed is deterministic and public_key round-trips through bytes.
    #[test]
    fn public_key_round_trips_through_bytes() {
        let pk = device_key().public_key();
        let bytes = pk.to_bytes();
        let restored = PublicKey::from_bytes(&bytes).expect("valid key bytes must round-trip");
        assert_eq!(pk, restored);
    }

    /// A device cert issued for one key must not validate a verdict signed by a different key.
    /// (Defense-in-depth: proves the device pubkey in the cert is actually used.)
    #[test]
    fn verdict_signed_by_uncertified_key_fails_signature() {
        // Cert certifies the standard device key...
        let cert = make_cert(&root_key());
        // ...but the verdict is signed by a DIFFERENT device key.
        let imposter = SigningKeyPair::from_seed(&[0x99u8; 32]);
        let verdict = sign_verdict(
            &make_unsigned(Decision::Approved, canonical_hash(false), None),
            &imposter,
            NONCE,
            Some(cert),
        );
        let request = make_request();
        let context = make_context(false);
        let mut store = InMemoryNonceStore::new();

        let err = verify_verdict(
            &verdict,
            &request,
            &context,
            &root_key().public_key(),
            &mut store,
            NOW_OK,
        )
        .expect_err("verdict signed by an uncertified key must fail");
        assert_eq!(err, VerifyError::VerdictSignatureInvalid);
    }
}
