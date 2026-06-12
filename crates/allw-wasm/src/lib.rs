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
    action_from_command as core_action_from_command,
    action_from_mcp_tool_call as core_action_from_mcp_tool_call,
    compute_request_hash as core_compute_request_hash, decrypt_context as core_decrypt_context,
    encrypt_context as core_encrypt_context, evaluate as core_evaluate,
    evaluate_for_actor as core_evaluate_for_actor, issue_device_cert as core_issue_device_cert,
    sign_policy_rule as core_sign_policy_rule, sign_verdict as core_sign_verdict,
    verify_policy_rule_with_expected_account as core_verify_policy_rule_with_expected_account,
    verify_verdict_with_expected_account as core_verify_verdict_with_expected_account,
    ActionRecord, Actor, ApprovalContext, ApprovalRequest, Approver, CommandContext,
    ContextRecipient, Decision, PolicyRule, PolicyRuleScope, PublicKey, SigningKeyPair,
    UnsignedPolicyRule, UnsignedVerdict, Verdict, X25519KeyPair, X25519PublicKey,
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

/// Decodes a base64url-unpadded string into a byte vector of arbitrary length (e.g. a verdict
/// nonce). Errors if the string is not valid base64url.
fn decode_b64_vec(s: &str, what: &str) -> Result<Vec<u8>, JsError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| JsError::new(&format!("{what} is not valid base64url: {e}")))
}

/// JS `Number.MAX_SAFE_INTEGER` = 2^53 − 1. Integer `f64`s within `±MAX_SAFE_INTEGER` are the
/// exact integer the caller intended; beyond it, distinct integers collapse onto the same `f64`,
/// so an `ms.fract() == 0.0` value there is NOT necessarily the millisecond count JS meant.
const JS_MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Converts a JS-number millisecond timestamp (`f64`) to the core's `i64`, rejecting non-integer
/// or unsafe-magnitude values rather than silently truncating or accepting a precision-lost value.
fn ms_to_i64(ms: f64, what: &str) -> Result<i64, JsError> {
    if !ms.is_finite() || ms.fract() != 0.0 {
        return Err(JsError::new(&format!(
            "{what} must be a finite integer number of milliseconds, got {ms}"
        )));
    }
    // Bound to ±MAX_SAFE_INTEGER (not the wider i64 range): only there is the f64→i64 conversion
    // guaranteed exact, so we never accept a value JS could not represent precisely. ~year 287396
    // in ms — far beyond any real timestamp.
    if ms.abs() > JS_MAX_SAFE_INTEGER {
        return Err(JsError::new(&format!(
            "{what} exceeds JS safe-integer range (±2^53-1); not exactly representable: {ms}"
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
    /// The signed anti-replay nonce, base64url-unpadded, for SDK/client-level replay stores.
    nonce_b64: String,
}

/// Verifies a [`Verdict`](allw_core::Verdict) against the request it answers, the human-shown
/// context, and the approver's account-root Ed25519 public key.
///
/// On success returns a JSON
/// `{ "approved": true, "device_id": string, "decided_at": number, "nonce_b64": string }`.
/// Uses a fresh single-shot [`InMemoryNonceStore`](allw_core::InMemoryNonceStore), then returns the
/// verified nonce so SDK/client code can enforce cross-call replay protection in a long-lived
/// store.
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
    verify_verdict_impl(
        verdict_json,
        request_json,
        context_json,
        approver_root_pubkey_b64,
        now_ms,
        None,
    )
}

/// Verifies a verdict like [`verify_verdict`], additionally requiring the certified account id to
/// equal `expected_account_id`. This is for multi-account verifiers that already know which account
/// they intended to verify under and want to fail closed on a wrong root/account pairing.
#[wasm_bindgen]
pub fn verify_verdict_for_account(
    verdict_json: &str,
    request_json: &str,
    context_json: &str,
    approver_root_pubkey_b64: &str,
    now_ms: f64,
    expected_account_id: &str,
) -> Result<String, JsError> {
    if expected_account_id.is_empty() {
        return Err(JsError::new("expected_account_id is required"));
    }
    verify_verdict_impl(
        verdict_json,
        request_json,
        context_json,
        approver_root_pubkey_b64,
        now_ms,
        Some(expected_account_id),
    )
}

fn verify_verdict_impl(
    verdict_json: &str,
    request_json: &str,
    context_json: &str,
    approver_root_pubkey_b64: &str,
    now_ms: f64,
    expected_account_id: Option<&str>,
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
    let verified = core_verify_verdict_with_expected_account(
        &verdict,
        &request,
        &context,
        &root,
        &mut nonce_store,
        now_ms,
        expected_account_id,
    )
    .map_err(|e| JsError::new(&format!("verify_verdict failed: {e}")))?;

    to_json(
        &VerifyResult {
            approved: true,
            device_id: verified.device_id,
            decided_at: verified.decided_at,
            nonce_b64: URL_SAFE_NO_PAD.encode(verified.nonce),
        },
        "VerifyResult",
    )
}

// ── sign_verdict ──────────────────────────────────────────────────────────────────────

/// The signing input for [`sign_verdict`]: every [`Verdict`](allw_core::Verdict) field except the
/// crypto-derived `sig`/`device_cert`. Mirrors the core
/// [`UnsignedVerdict`](allw_core::UnsignedVerdict); `request_hash` is a base64url-unpadded 32-byte
/// string (the wire encoding) and `decided_at` is an integer millisecond timestamp.
#[derive(Deserialize)]
struct WasmUnsignedVerdict {
    v: u32,
    request_id: String,
    /// WYSIWYS binding hash — base64url-unpadded 32 bytes (echoes the request's `request_hash`).
    request_hash: String,
    decision: Decision,
    decided_at: i64,
    approver: Approver,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    challenge_response: Option<String>,
}

/// Signs a verdict with the approver's **device** Ed25519 key and returns the full
/// [`Verdict`](allw_core::Verdict) JSON (its `sig` is an EdDSA compact JWS). This is the approver
/// device's half of the round-trip — the integrator counterpart is [`verify_verdict`].
///
/// - `unsigned_json` — a JSON [`WasmUnsignedVerdict`] (the verdict fields the human decided).
/// - `device_seed_b64` — the device signing-key seed, base64url-unpadded 32 bytes. **v0 stand-in:**
///   a software-held seed; production device keys live in Secure Enclave / StrongBox and never
///   serialize (`docs/contract.md` §Identity & keys).
/// - `nonce_b64` — the per-verdict anti-replay nonce, base64url-unpadded. The decoder is
///   length-agnostic, but anti-replay security depends on a **high-entropy** nonce: callers (the
///   SDK, #12) MUST generate **≥16 cryptographically-random bytes** per verdict. It is signed into
///   the claims and checked against a [`NonceStore`](allw_core::NonceStore) on verify.
/// - `device_cert` — the device→account-root certificate JWS (from [`issue_device_cert`]); pass an
///   empty string for none, though [`verify_verdict`] requires one to chain the device key to root.
///
/// # Errors
///
/// Throws if any JSON/seed/nonce input is malformed (invalid JSON, a non-32-byte seed, a
/// non-base64url nonce, or a `request_hash` that is not 32 base64url bytes).
#[wasm_bindgen]
pub fn sign_verdict(
    unsigned_json: &str,
    device_seed_b64: &str,
    nonce_b64: &str,
    device_cert: &str,
) -> Result<String, JsError> {
    let u: WasmUnsignedVerdict = parse_json(unsigned_json, "UnsignedVerdict")?;
    let request_hash = decode_b64_32(&u.request_hash, "request_hash")?;
    let seed = decode_b64_32(device_seed_b64, "device_seed_b64")?;
    let nonce = decode_b64_vec(nonce_b64, "nonce_b64")?;
    let device_key = SigningKeyPair::from_seed(&seed);

    let unsigned = UnsignedVerdict {
        v: u.v,
        request_id: u.request_id,
        request_hash,
        decision: u.decision,
        decided_at: u.decided_at,
        approver: u.approver,
        note: u.note,
        challenge_response: u.challenge_response,
    };

    // An empty `device_cert` means "no cert" — though a verifiable verdict needs one.
    let cert = if device_cert.is_empty() {
        None
    } else {
        Some(device_cert.to_string())
    };

    let verdict: Verdict = core_sign_verdict(&unsigned, &device_key, &nonce, cert);
    to_json(&verdict, "Verdict")
}

// ── issue_device_cert ─────────────────────────────────────────────────────────────────

/// Issues a device certificate — an EdDSA compact JWS signed by the **account-root** key binding a
/// device public key to `(account_id, device_id)` — returned as the compact JWS string. A verifier
/// holding only the account-root key can then trust the device key it certifies
/// (`docs/contract.md` §Identity & keys), which is why a verdict's `device_cert` is required.
///
/// - `account_root_seed_b64` — the account-root signing seed, base64url-unpadded 32 bytes.
/// - `device_pubkey_b64` — the device Ed25519 public key being certified, base64url-unpadded 32 bytes.
/// - `issued_at` / `expires_at` — Unix-millisecond timestamps; `expires_at` may be omitted (no expiry).
///
/// # Errors
///
/// Throws if a seed/pubkey is not a 32-byte base64url value, the device pubkey is not a valid
/// Ed25519 key, or a timestamp is not an in-range integer millisecond value.
#[wasm_bindgen]
pub fn issue_device_cert(
    account_root_seed_b64: &str,
    account_id: &str,
    device_id: &str,
    device_pubkey_b64: &str,
    issued_at: f64,
    expires_at: Option<f64>,
) -> Result<String, JsError> {
    let root_seed = decode_b64_32(account_root_seed_b64, "account_root_seed_b64")?;
    let account_root = SigningKeyPair::from_seed(&root_seed);
    let device_pubkey_bytes = decode_b64_32(device_pubkey_b64, "device_pubkey_b64")?;
    let device_pubkey = PublicKey::from_bytes(&device_pubkey_bytes).map_err(|e| {
        JsError::new(&format!(
            "device_pubkey_b64 is not a valid Ed25519 key: {e}"
        ))
    })?;
    let issued_at = ms_to_i64(issued_at, "issued_at")?;
    let expires_at = match expires_at {
        Some(ms) => Some(ms_to_i64(ms, "expires_at")?),
        None => None,
    };

    Ok(core_issue_device_cert(
        &account_root,
        account_id,
        device_id,
        &device_pubkey,
        issued_at,
        expires_at,
    ))
}

// ── policy rules ──────────────────────────────────────────────────────────────────────

/// Signs an unsigned [`PolicyRule`](allw_core::PolicyRule) payload with a device Ed25519 key,
/// returning the full signed policy rule JSON. This is the lower-level rule-emission helper for
/// manual policies; the approval-derived affordance should use [`policy_rule_from_approval`].
///
/// # Errors
///
/// Throws if `unsigned_rule_json` is not a valid [`UnsignedPolicyRule`](allw_core::UnsignedPolicyRule)
/// or the device seed is not a 32-byte base64url value. `device_cert` is the
/// account-root-signed certificate for this device; pass an empty string only to construct an
/// intentionally unverifiable rule for negative tests.
#[wasm_bindgen]
pub fn sign_policy_rule(
    unsigned_rule_json: &str,
    device_id: &str,
    device_seed_b64: &str,
    device_cert: &str,
) -> Result<String, JsError> {
    let unsigned: UnsignedPolicyRule = parse_json(unsigned_rule_json, "UnsignedPolicyRule")?;
    let seed = decode_b64_32(device_seed_b64, "device_seed_b64")?;
    let device_key = SigningKeyPair::from_seed(&seed);
    let cert = if device_cert.is_empty() {
        None
    } else {
        Some(device_cert.to_string())
    };
    let rule = core_sign_policy_rule(&unsigned, device_id, &device_key, cert);
    to_json(&rule, "PolicyRule")
}

/// Emits a signed allow [`PolicyRule`](allw_core::PolicyRule) from an approved action and a
/// syntactic scope choice. This preserves the primitive's one-shot verdict invariant: standing
/// autonomy is encoded as a signed policy rule, not as extra scope on a verdict.
///
/// `scope_json` is a [`PolicyRuleScope`](allw_core::PolicyRuleScope), for example
/// `{ "kind": "exact_call" }` or `{ "kind": "mcp_param_equals", "path": "list" }`.
///
/// # Errors
///
/// Throws if actor/action/scope JSON is malformed, `created_at` is not a safe integer millisecond
/// timestamp, or the device seed is not a 32-byte base64url value.
#[wasm_bindgen]
#[allow(
    clippy::too_many_arguments,
    reason = "wasm-bindgen exports a positional JS FFI"
)]
pub fn policy_rule_from_approval(
    id: &str,
    account_id: &str,
    actor_json: &str,
    action_json: &str,
    scope_json: &str,
    created_at: f64,
    device_id: &str,
    device_seed_b64: &str,
    device_cert: &str,
) -> Result<String, JsError> {
    let actor: Actor = parse_json(actor_json, "Actor")?;
    let action: ActionRecord = parse_json(action_json, "ActionRecord")?;
    let scope: PolicyRuleScope = parse_json(scope_json, "PolicyRuleScope")?;
    let created_at = ms_to_i64(created_at, "created_at")?;
    let seed = decode_b64_32(device_seed_b64, "device_seed_b64")?;
    let device_key = SigningKeyPair::from_seed(&seed);

    let unsigned =
        UnsignedPolicyRule::from_approval(id, account_id, &actor, &action, scope, created_at)
            .map_err(|e| JsError::new(&format!("policy_rule_from_approval failed: {e}")))?;
    let cert = if device_cert.is_empty() {
        None
    } else {
        Some(device_cert.to_string())
    };
    let rule = core_sign_policy_rule(&unsigned, device_id, &device_key, cert);
    to_json(&rule, "PolicyRule")
}

/// Verifies signed policy rules and evaluates them against one action. Returns a
/// [`PolicyEvaluation`](allw_core::PolicyEvaluation) JSON object.
///
/// `signed_rules_json` is a JSON array of signed [`PolicyRule`](allw_core::PolicyRule) objects.
/// All supplied rules are verified by chaining their embedded device certs to
/// `account_root_pubkey_b64`; any invalid rule throws rather than being ignored, so callers fail
/// closed on policy tampering.
///
/// # Errors
///
/// Throws if the action/actor/rules JSON is malformed, the account-root public key is not a valid
/// Ed25519 key, `now_ms` is not a safe integer millisecond timestamp, or any signed policy rule
/// fails verification.
#[wasm_bindgen]
pub fn evaluate_policy(
    action_json: &str,
    actor_json: Option<String>,
    signed_rules_json: &str,
    account_root_pubkey_b64: &str,
    now_ms: f64,
) -> Result<String, JsError> {
    evaluate_policy_impl(
        action_json,
        actor_json,
        signed_rules_json,
        account_root_pubkey_b64,
        now_ms,
        None,
    )
}

/// Evaluates policy like [`evaluate_policy`], additionally requiring every signed rule's account id
/// and device certificate to match `expected_account_id`.
#[wasm_bindgen]
pub fn evaluate_policy_for_account(
    action_json: &str,
    actor_json: Option<String>,
    signed_rules_json: &str,
    account_root_pubkey_b64: &str,
    now_ms: f64,
    expected_account_id: &str,
) -> Result<String, JsError> {
    if expected_account_id.is_empty() {
        return Err(JsError::new("expected_account_id is required"));
    }
    evaluate_policy_impl(
        action_json,
        actor_json,
        signed_rules_json,
        account_root_pubkey_b64,
        now_ms,
        Some(expected_account_id),
    )
}

fn evaluate_policy_impl(
    action_json: &str,
    actor_json: Option<String>,
    signed_rules_json: &str,
    account_root_pubkey_b64: &str,
    now_ms: f64,
    expected_account_id: Option<&str>,
) -> Result<String, JsError> {
    let action: ActionRecord = parse_json(action_json, "ActionRecord")?;
    let actor: Option<Actor> = actor_json
        .as_deref()
        .map(|json| parse_json(json, "Actor"))
        .transpose()?;
    let rules: Vec<PolicyRule> = parse_json(signed_rules_json, "PolicyRule[]")?;
    let root_pubkey_bytes = decode_b64_32(account_root_pubkey_b64, "account_root_pubkey_b64")?;
    let root_pubkey = PublicKey::from_bytes(&root_pubkey_bytes).map_err(|e| {
        JsError::new(&format!(
            "account_root_pubkey_b64 is not a valid Ed25519 key: {e}"
        ))
    })?;
    let now_ms = ms_to_i64(now_ms, "now_ms")?;
    let verified = rules
        .iter()
        .map(|rule| {
            core_verify_policy_rule_with_expected_account(
                rule,
                &root_pubkey,
                now_ms,
                expected_account_id,
            )
            .map_err(|e| JsError::new(&format!("verify_policy_rule failed: {e}")))
        })
        .collect::<Result<Vec<_>, JsError>>()?;

    let evaluation = match actor.as_ref() {
        Some(actor) => core_evaluate_for_actor(actor, &action, &verified),
        None => core_evaluate(&action, &verified),
    };
    to_json(&evaluation, "PolicyEvaluation")
}

// ── key derivation (v0 software keys) ──────────────────────────────────────────────────

/// Derives the Ed25519 **public** (verifying) key for a 32-byte signing seed, returned as a
/// base64url-unpadded string — used to register a device/account signing key with the relay.
///
/// **v0 stand-in:** seeds are software-held; production signing keys are hardware-backed and never
/// leave the device.
///
/// # Errors
///
/// Throws if `seed_b64` is not a 32-byte base64url value.
#[wasm_bindgen]
pub fn ed25519_public_key(seed_b64: &str) -> Result<String, JsError> {
    let seed = decode_b64_32(seed_b64, "seed_b64")?;
    let pubkey = SigningKeyPair::from_seed(&seed).public_key();
    Ok(URL_SAFE_NO_PAD.encode(pubkey.to_bytes()))
}

/// Derives the X25519 **public** key for a 32-byte secret seed, returned as a base64url-unpadded
/// string — used to register a device's encryption key (a recipient for [`encrypt_context`]).
///
/// **v0 stand-in:** seeds are software-held; production encryption keys are hardware-backed.
///
/// # Errors
///
/// Throws if `seed_b64` is not a 32-byte base64url value.
#[wasm_bindgen]
pub fn x25519_public_key(seed_b64: &str) -> Result<String, JsError> {
    let seed = decode_b64_32(seed_b64, "seed_b64")?;
    let pubkey = X25519KeyPair::from_seed(&seed).public_key();
    Ok(URL_SAFE_NO_PAD.encode(pubkey.to_bytes()))
}

// ── ActionRecord builders (the hook's syntactic substrate) ──────────────────────────────

/// Builds an [`ActionRecord`](allw_core::ActionRecord) from a raw shell command line, returning it
/// as JSON. This is the **command** surface (`docs/policy-seam.md` §The three tiers, T1): the core
/// tokenizes the command (POSIX word-splitting), captures the syntactic substrate (bin / argv /
/// flags / positionals / cwd / host / env-refs), and assigns a coarse v1 risk tier. The semantic
/// `capabilities`/`scope` slots stay `null` (reserved for T3). The Claude Code hook calls this to
/// reduce a pending `Bash` tool call into the matchable record it submits for approval.
///
/// - `command_line` — the raw shell command (e.g. `"rm -rf build"`).
/// - `cwd` — the working directory at invocation, or `None` if the caller didn't capture it.
///
/// # Errors
///
/// Throws if the command string has unmatched quotes / invalid shell syntax
/// ([`CommandError::InvalidShellSyntax`](allw_core::CommandError)) — fail-closed at the boundary, so
/// the hook denies rather than guessing at a malformed command.
#[wasm_bindgen]
pub fn action_from_command(command_line: &str, cwd: Option<String>) -> Result<String, JsError> {
    let ctx = CommandContext { cwd };
    let record = core_action_from_command(command_line, &ctx)
        .map_err(|e| JsError::new(&format!("action_from_command failed: {e}")))?;
    to_json(&record, "ActionRecord")
}

/// Builds an [`ActionRecord`](allw_core::ActionRecord) for an MCP tool call, returning it as JSON.
/// This is the **mcp_tool_call** surface (`docs/policy-seam.md` §The three tiers, T1): the core
/// preserves the `server`/`tool`/`params` verbatim (so instance-distinguishing values stay
/// matchable) and assigns a coarse v1 risk tier from the tool name. The hook calls this to reduce a
/// pending `mcp__<server>__<tool>` call into the record it submits for approval.
///
/// - `server` — the MCP server name (e.g. `"omnifocus"`).
/// - `tool` — the tool name within that server (e.g. `"delete_project"`).
/// - `params_json` — the tool-call parameters as a JSON value (any JSON: object, array, primitive).
///
/// # Errors
///
/// Throws if `params_json` is not valid JSON — fail-closed: the hook denies rather than submitting a
/// record built from unparseable parameters.
#[wasm_bindgen]
pub fn action_from_mcp_tool_call(
    server: &str,
    tool: &str,
    params_json: &str,
) -> Result<String, JsError> {
    let params: serde_json::Value = parse_json(params_json, "MCP tool params")?;
    let record = core_action_from_mcp_tool_call(server, tool, params);
    to_json(&record, "ActionRecord")
}
