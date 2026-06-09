//! # allw-wasm
//!
//! WASM (`wasm-bindgen`) bindings that expose [`allw-core`](allw_core) to the TypeScript SDK and
//! the Claude Code hook. This crate is a **thin shell**: it parses JSON inputs, calls the audited
//! core, and serializes JSON outputs. It adds **no** crypto or contract logic of its own — and is
//! the *only* place `wasm-bindgen` lives (the core stays binding-agnostic so it can also target
//! UniFFI for native apps). See `docs/architecture.md` — WASM-local is a hard constraint
//! (`napi`/native binaries are avoided so enterprise allowlisting / Santa / MDM cannot block the
//! local surface), and the same `.wasm` is browser/worker-capable.
//!
//! # The JSON-string FFI contract
//!
//! Every exported function takes and returns **strings**, not structured JS objects. The strings
//! are the exact serde wire types from the core (the same byte-identical JSON every surface
//! shares — `docs/contract.md` §Wire encoding), so the contract is language-agnostic and there is
//! no second type definition to drift. Concretely:
//!
//! - `context_json` — a JSON [`ApprovalContext`](allw_core::ApprovalContext).
//! - `request_json` — a JSON [`ApprovalRequest`](allw_core::ApprovalRequest) envelope.
//! - `verdict_json` — a JSON [`Verdict`](allw_core::Verdict).
//! - 32-byte / arbitrary binary values — **base64url-unpadded** strings (JOSE-consistent),
//!   identical to how the core's wire types encode them.
//!
//! # Errors surface as JS exceptions
//!
//! Each function returns `Result<_, JsError>`. On bad input (malformed JSON, a non-base64url key,
//! a verdict that fails verification, …) the `Err` becomes a **thrown JS `Error`** whose message
//! is the underlying core error's `Display`. So in TypeScript a failed `verify_verdict` (denied,
//! tampered, expired, replayed, …) is a `throw`, not a falsy return — matching the fail-closed
//! invariant (`docs/contract.md` §Invariants #6) at the language boundary.
//!
//! # `expires_at` / `now_ms` are `f64`
//!
//! JS numbers are IEEE-754 doubles, so the millisecond timestamps cross the boundary as `f64` and
//! are converted to the core's `i64`. Integers up to `Number.MAX_SAFE_INTEGER` (2^53 − 1) are
//! represented exactly; that is ~year 287396, far beyond any real `expires_at`, so no precision is
//! lost in practice. A non-integer or out-of-`i64`-range value is rejected with a `JsError`.

use allw_core::{
    compute_request_hash as core_compute_request_hash, decrypt_context as core_decrypt_context,
    encrypt_context as core_encrypt_context, verify_verdict as core_verify_verdict,
    ApprovalContext, ApprovalRequest, ContextRecipient, PublicKey, Verdict, X25519KeyPair,
    X25519PublicKey,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ── Shared helpers ────────────────────────────────────────────────────────────────

/// Parses a JSON string into a deserializable type, mapping a parse error to a `JsError`
/// whose message names `what` (e.g. "ApprovalContext") so JS callers get an actionable throw.
fn parse_json<T: for<'de> Deserialize<'de>>(json: &str, what: &str) -> Result<T, JsError> {
    serde_json::from_str(json).map_err(|e| JsError::new(&format!("invalid {what} JSON: {e}")))
}

/// Serializes a value to a JSON string, mapping the (practically infallible) error to a `JsError`.
fn to_json<T: Serialize>(value: &T, what: &str) -> Result<String, JsError> {
    serde_json::to_string(value)
        .map_err(|e| JsError::new(&format!("failed to serialize {what}: {e}")))
}

/// Decodes a base64url-unpadded string into exactly 32 bytes (the encoding used by every binary
/// wire field). Errors if the string is not valid base64url or does not decode to 32 bytes.
fn decode_b64_32(s: &str, what: &str) -> Result<[u8; 32], JsError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| JsError::new(&format!("{what} is not valid base64url: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("{what} must decode to exactly 32 bytes")))
}

/// Converts a JS-number millisecond timestamp (`f64`) to the core's `i64`, rejecting non-integer
/// or out-of-range values rather than silently truncating.
fn ms_to_i64(ms: f64, what: &str) -> Result<i64, JsError> {
    if !ms.is_finite() || ms.fract() != 0.0 {
        return Err(JsError::new(&format!(
            "{what} must be a finite integer number of milliseconds, got {ms}"
        )));
    }
    // i64 range as f64 bounds. Using the f64 literals avoids precision surprises at the edges.
    if ms < i64::MIN as f64 || ms > i64::MAX as f64 {
        return Err(JsError::new(&format!(
            "{what} is out of the i64 range: {ms}"
        )));
    }
    Ok(ms as i64)
}

// ── compute_request_hash ────────────────────────────────────────────────────────────

/// Computes the WYSIWYS `request_hash` for an [`ApprovalContext`](allw_core::ApprovalContext)
/// bound to `expires_at`, returning the 32-byte digest as a **base64url-unpadded** string.
///
/// This must reproduce the exact value the Rust core produces (`request-hash/v2`); the
/// cross-platform test vector anchors that parity.
///
/// # Errors
///
/// Throws if `context_json` is not a valid `ApprovalContext`, or `expires_at` is not an in-range
/// integer millisecond value.
#[wasm_bindgen]
pub fn compute_request_hash(context_json: &str, expires_at: f64) -> Result<String, JsError> {
    let ctx: ApprovalContext = parse_json(context_json, "ApprovalContext")?;
    let expires_at = ms_to_i64(expires_at, "expires_at")?;
    let hash = core_compute_request_hash(&ctx, expires_at);
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Returns the RFC 8785 JCS canonical bytes for the request-hash input (the
/// [`ApprovalContext`](allw_core::ApprovalContext) plus `expires_at`) as a **base64url-unpadded**
/// string. The hash is `SHA-256(domain_tag || 0x00 || <these bytes>)`; exposing the pre-hash bytes
/// is handy for debugging cross-platform canonicalization parity.
///
/// # Errors
///
/// Throws if `context_json` is not a valid `ApprovalContext`, or `expires_at` is not an in-range
/// integer millisecond value.
#[wasm_bindgen]
pub fn canonical_request_bytes_b64(context_json: &str, expires_at: f64) -> Result<String, JsError> {
    let ctx: ApprovalContext = parse_json(context_json, "ApprovalContext")?;
    let expires_at = ms_to_i64(expires_at, "expires_at")?;
    let bytes = allw_core::canonical_request_bytes(&ctx, expires_at);
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

// ── encrypt_context ──────────────────────────────────────────────────────────────────

/// One recipient device for [`encrypt_context`]: a device id and its X25519 public key
/// (base64url-unpadded, 32 bytes). Matches the core's
/// [`ContextRecipient`](allw_core::ContextRecipient).
#[derive(Deserialize)]
struct WasmRecipient {
    device_id: String,
    /// The recipient device's X25519 public key, base64url-unpadded (32 bytes).
    public_key_b64: String,
}

/// Encrypts an [`ApprovalContext`](allw_core::ApprovalContext) to one or more recipient devices,
/// returning the General-JSON-Serialization JWE string (suitable for the envelope's
/// `context_ciphertext`).
///
/// `recipients_json` is a JSON array of `{ "device_id": string, "public_key_b64": string }`, where
/// `public_key_b64` is the recipient's X25519 public key as a base64url-unpadded 32-byte string.
/// Randomness (CEK, IV, per-recipient ephemeral secrets) is drawn from the platform CSPRNG
/// ([`OsRng`] → `crypto.getRandomValues` / node webcrypto on wasm), so the core never links an OS
/// RNG itself.
///
/// # Errors
///
/// Throws if `context_json` / `recipients_json` are not valid JSON, a `public_key_b64` is not a
/// 32-byte base64url value, or `recipients` is empty (a JWE no device could decrypt).
#[wasm_bindgen]
pub fn encrypt_context(context_json: &str, recipients_json: &str) -> Result<String, JsError> {
    let ctx: ApprovalContext = parse_json(context_json, "ApprovalContext")?;
    let recipients: Vec<WasmRecipient> = parse_json(recipients_json, "recipients")?;

    if recipients.is_empty() {
        // The core panics on empty recipients; surface it as a clean JS throw instead.
        return Err(JsError::new(
            "encrypt_context requires at least one recipient",
        ));
    }

    // Decode every public key first so a bad key is a clean error, then borrow into the core's
    // borrowing `ContextRecipient` shape.
    let keys: Vec<X25519PublicKey> = recipients
        .iter()
        .map(|r| {
            let bytes = decode_b64_32(&r.public_key_b64, "recipient public_key_b64")?;
            Ok(X25519PublicKey::from_bytes(&bytes))
        })
        .collect::<Result<_, JsError>>()?;

    let core_recipients: Vec<ContextRecipient<'_>> = recipients
        .iter()
        .zip(keys.iter())
        .map(|(r, key)| ContextRecipient {
            device_id: &r.device_id,
            public_key: key,
        })
        .collect();

    Ok(core_encrypt_context(&ctx, &core_recipients, &mut OsRng))
}

// ── decrypt_context ──────────────────────────────────────────────────────────────────

/// Decrypts a General-JSON JWE `jwe` for `device_id` using that device's X25519 secret key
/// (`device_secret_b64`, base64url-unpadded 32 bytes), returning the recovered
/// [`ApprovalContext`](allw_core::ApprovalContext) as a JSON string.
///
/// Provided for SDK/device completeness (the device recomputes `request_hash` from this plaintext).
///
/// # Errors
///
/// Throws if `device_secret_b64` is not a 32-byte base64url value, or the JWE cannot be decrypted
/// for `device_id` (wrong key, tampered ciphertext, malformed JWE, …) — the message is the core
/// [`JweError`](allw_core::JweError) `Display`.
#[wasm_bindgen]
pub fn decrypt_context(
    jwe: &str,
    device_id: &str,
    device_secret_b64: &str,
) -> Result<String, JsError> {
    let seed = decode_b64_32(device_secret_b64, "device_secret_b64")?;
    let key = X25519KeyPair::from_seed(&seed);
    let ctx = core_decrypt_context(jwe, device_id, &key)
        .map_err(|e| JsError::new(&format!("decrypt_context failed: {e}")))?;
    to_json(&ctx, "ApprovalContext")
}

// ── verify_verdict ───────────────────────────────────────────────────────────────────

/// The successful result of [`verify_verdict`] — an *authenticated, bound, fresh, approved*
/// decision. Serialized to JSON for the JS caller.
///
/// **Not authorization.** A successful return means the human approved and the verdict verified;
/// the caller still composes `allow = approved ∧ verified ∧ policy ∧ other_gates`
/// (`docs/contract.md` §Invariants #5). `approved` is always `true` here — a *verified* denial /
/// expiry is reported as a thrown error, not `approved: false`.
#[derive(Serialize)]
struct VerifyResult {
    /// Always `true` on success (a verified non-approval throws instead).
    approved: bool,
    /// The device that signed the verdict.
    device_id: String,
    /// The decision time — Unix milliseconds (UTC).
    decided_at: i64,
}

/// Verifies a [`Verdict`](allw_core::Verdict) against the request it answers, the human-shown
/// context, and the approver's account-root Ed25519 public key.
///
/// On success returns a JSON `{ "approved": true, "device_id": string, "decided_at": number }`.
/// Uses a fresh single-shot [`InMemoryNonceStore`](allw_core::InMemoryNonceStore) — anti-replay
/// across calls is the integrator's responsibility (a persistent store), not this stateless
/// binding's.
///
/// # Errors
///
/// Throws on **any** verification failure (fail-closed): a verified denial/expiry/abort, a bad
/// signature, a broken WYSIWYS binding, an expired/out-of-window decision, etc. The thrown
/// message is the core [`VerifyError`](allw_core::VerifyError) `Display`, so callers can
/// distinguish a verified "no" from a forgery by inspecting the message. Also throws if any input
/// JSON is invalid, the root key is not a 32-byte base64url value, or `now_ms` is out of range.
#[wasm_bindgen]
pub fn verify_verdict(
    verdict_json: &str,
    request_json: &str,
    context_json: &str,
    approver_root_pubkey_b64: &str,
    now_ms: f64,
) -> Result<String, JsError> {
    let verdict: Verdict = parse_json(verdict_json, "Verdict")?;
    let request: ApprovalRequest = parse_json(request_json, "ApprovalRequest")?;
    let context: ApprovalContext = parse_json(context_json, "ApprovalContext")?;
    let root_bytes = decode_b64_32(approver_root_pubkey_b64, "approver_root_pubkey_b64")?;
    let root = PublicKey::from_bytes(&root_bytes).map_err(|e| {
        JsError::new(&format!(
            "approver_root_pubkey_b64 is not a valid Ed25519 key: {e}"
        ))
    })?;
    let now_ms = ms_to_i64(now_ms, "now_ms")?;

    let mut nonce_store = allw_core::InMemoryNonceStore::new();
    let verified = core_verify_verdict(
        &verdict,
        &request,
        &context,
        &root,
        &mut nonce_store,
        now_ms,
    )
    .map_err(|e| JsError::new(&format!("verify_verdict failed: {e}")))?;

    to_json(
        &VerifyResult {
            approved: true,
            device_id: verified.device_id,
            decided_at: verified.decided_at,
        },
        "VerifyResult",
    )
}
