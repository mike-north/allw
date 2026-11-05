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
//! Messages are diagnostics only; **never classify a failure by its message.** Untrusted input
//! (e.g. a relay-delivered verdict) is echoed into parse errors, so any substring can be forged.
//! The one failure a caller may act on, a *verified* non-approval from `verify_verdict` /
//! `verify_verdict_with_account_states`, is reported structurally: the thrown `Error` carries own
//! properties `kind: "not_approved"` and `decision` (`"denied"` | `"expired"` | `"aborted"`), the
//! decision taken from the **signed claims**. No other error carries `kind`.
//!
//! # `expires_at` / `now_ms` are `f64`
//!
//! JS numbers are IEEE-754 doubles, so the millisecond timestamps cross the boundary as `f64` and
//! are converted to the core's `i64`. Integers up to `Number.MAX_SAFE_INTEGER` (2^53 − 1) are
//! represented exactly; that is ~year 287396, far beyond any real `expires_at`, so no precision is
//! lost in practice. A non-integer or out-of-`i64`-range value is rejected with a `JsError`.

use allw_core::{
    account_id_for_root as core_account_id_for_root,
    action_from_agent_tool_call as core_action_from_agent_tool_call,
    action_from_agent_tool_call_with_raw as core_action_from_agent_tool_call_with_raw,
    action_from_argv as core_action_from_argv, action_from_command as core_action_from_command,
    action_from_file_edit as core_action_from_file_edit,
    action_from_mcp_tool_call as core_action_from_mcp_tool_call,
    action_from_powershell_command as core_action_from_powershell_command,
    check_account_id_for_root as core_check_account_id_for_root,
    compute_request_hash as core_compute_request_hash, decrypt_context as core_decrypt_context,
    derive_number_match_challenge as core_derive_number_match_challenge,
    device_key_fingerprint as core_device_key_fingerprint, display_model as core_display_model,
    encrypt_context as core_encrypt_context, escape_for_display as core_escape_for_display,
    evaluate as core_evaluate, evaluate_for_actor as core_evaluate_for_actor,
    is_small_order_x25519_public_key as core_is_small_order_x25519_public_key,
    issue_device_cert as core_issue_device_cert, next_account_state as core_next_account_state,
    revoked_device_ids as core_revoked_device_ids,
    seal_context_for_account_state as core_seal_context_for_account_state,
    select_recipients as core_select_recipients, sign_account_state as core_sign_account_state,
    sign_actor_attestation as core_sign_actor_attestation,
    sign_pairing_start_authorization as core_sign_pairing_start_authorization,
    sign_policy_rule as core_sign_policy_rule, sign_verdict as core_sign_verdict,
    verified_origin_string as core_verified_origin_string,
    verify_account_state as core_verify_account_state,
    verify_actor_attestation_with_account_states as core_verify_actor_attestation_with_account_states,
    verify_pairing_start_authorization as core_verify_pairing_start_authorization,
    verify_policy_rule as core_verify_policy_rule,
    verify_policy_rule_for_account as core_verify_policy_rule_for_account,
    verify_policy_rule_with_account_states as core_verify_policy_rule_with_account_states,
    verify_policy_rule_with_account_states_for_account as core_verify_policy_rule_with_account_states_for_account,
    verify_verdict as core_verify_verdict,
    verify_verdict_for_account as core_verify_verdict_for_account,
    verify_verdict_provenance as core_verify_verdict_provenance,
    verify_verdict_with_account_states as core_verify_verdict_with_account_states,
    verify_verdict_with_account_states_for_account as core_verify_verdict_with_account_states_for_account,
    AccountState, AccountStateChange, ActionRecord, Actor, ApprovalContext, ApprovalRequest,
    Approver, CommandContext, CommandError, ContextRecipient, Decision, DeviceEnrollment,
    DeviceKeyKind, PolicyRule, PolicyRuleScope, PublicKey, SigningKeyPair, UnsignedPolicyRule,
    UnsignedVerdict, Verdict, VerifyError, X25519KeyPair, X25519PublicKey,
    X25519_SMALL_ORDER_POINTS,
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

/// Parses the JSON array of compact account-state JWS strings that the SDK passes through. The
/// core owns all signature/sequence semantics; this helper only turns JS strings into borrowed
/// `&str`s for the thin-shell call.
fn parse_account_states_json(account_states_json: &str) -> Result<Vec<String>, JsError> {
    parse_json(account_states_json, "account state JWS array")
}

/// Normalizes the optional verifier account constraint exposed to JavaScript. `undefined`/`null`
/// already arrive as `None`; an empty string is treated the same way so blank config values do not
/// turn the optional defense-in-depth guard into an accidental reject-everything mode.
fn expected_account_id_constraint(expected_account_id: Option<&str>) -> Option<&str> {
    expected_account_id.filter(|account_id| !account_id.is_empty())
}

/// Converts a required compact-JWS device certificate into the core's optional shape. The core
/// supports `None` for negative tests; the public WASM signing boundary rejects the empty-string
/// foot-gun so production JS callers cannot silently emit unverifiable artifacts.
fn required_device_cert(device_cert: &str) -> Result<String, JsError> {
    if device_cert.is_empty() {
        return Err(JsError::new(
            "device_cert must not be empty; mint one with issue_device_cert before signing",
        ));
    }
    Ok(device_cert.to_string())
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

/// Derives the four-digit number-match challenge for a request hash.
///
/// `request_hash_b64` must be the base64url-unpadded 32-byte WYSIWYS request hash returned by
/// [`compute_request_hash`]. The returned string is zero-padded decimal and is what a challenged
/// approval must sign as `challenge_response`.
///
/// # Errors
///
/// Throws if `request_hash_b64` is not 32 base64url bytes.
#[wasm_bindgen]
pub fn derive_number_match_challenge(request_hash_b64: &str) -> Result<String, JsError> {
    let request_hash = decode_b64_32(request_hash_b64, "request_hash_b64")?;
    Ok(core_derive_number_match_challenge(&request_hash))
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
/// 32-byte base64url value, `recipients` is empty (a JWE no device could decrypt), or a recipient's
/// public key is a small-order X25519 point (the message names that device id). The core returns
/// these as errors, never panics, so the WASM instance stays usable after a throw.
#[wasm_bindgen]
pub fn encrypt_context(context_json: &str, recipients_json: &str) -> Result<String, JsError> {
    let ctx: ApprovalContext = parse_json(context_json, "ApprovalContext")?;
    let recipients: Vec<WasmRecipient> = parse_json(recipients_json, "recipients")?;

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

    core_encrypt_context(&ctx, &core_recipients, &mut OsRng)
        .map_err(|e| JsError::new(&e.to_string()))
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

/// The `kind` a structured verify error carries when the verdict is authenticated, bound and fresh
/// but the human did not approve (core [`VerifyError::NotApproved`]).
const NOT_APPROVED_KIND: &str = "not_approved";

/// The wire string of a **non-approving** decision, or `None` for `Approved`. The structured
/// not-approved error can therefore never report `approved`, even if the core misreported one.
fn non_approval_wire(decision: Decision) -> Option<&'static str> {
    match decision {
        Decision::Approved => None,
        Decision::Denied => Some("denied"),
        Decision::Expired => Some("expired"),
        Decision::Aborted => Some("aborted"),
    }
}

/// Maps a core verification failure to the value `verify_verdict*` throws.
///
/// [`VerifyError::NotApproved`] becomes a JS `Error` with own properties
/// `kind: "not_approved"` and `decision` (the signed non-approving decision from the claims). Every
/// other failure is a plain `Error` with no `kind`, which callers must treat as unverifiable. The
/// message (`"{function} failed: {error}"`) is diagnostic text and is never a classification
/// channel: untrusted input is echoed into some messages, so a substring can be forged.
fn verify_failure(function: &str, error: VerifyError) -> JsValue {
    let message = format!("{function} failed: {error}");
    let signed_non_approval = match error {
        VerifyError::NotApproved { decision } => non_approval_wire(decision),
        _ => None,
    };
    match signed_non_approval {
        Some(decision) => {
            let thrown = js_sys::Error::new(&message);
            // Setting an own property on a fresh `Error` cannot fail; if it ever did, the error
            // would lack `kind` and callers would fail closed to an unverifiable denial.
            let _ = js_sys::Reflect::set(&thrown, &"kind".into(), &NOT_APPROVED_KIND.into());
            let _ = js_sys::Reflect::set(&thrown, &"decision".into(), &decision.into());
            thrown.into()
        }
        None => JsError::new(&message).into(),
    }
}

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
    /// The approver's note from the **signed claims** (omitted when absent). Audit records take
    /// the note from here, never from the unverified outer verdict (`docs/contract.md`).
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// Verifies a [`Verdict`](allw_core::Verdict) against the request it answers, the human-shown
/// context, and the approver's account-root Ed25519 public key.
///
/// On success returns a JSON
/// `{ "approved": true, "device_id": string, "decided_at": number, "nonce_b64": string, "note"?: string }`
/// (`note` is the signed note, present only when the verdict carries one).
/// Uses a fresh single-shot [`InMemoryNonceStore`](allw_core::InMemoryNonceStore), then returns the
/// verified nonce so SDK/client code can enforce cross-call replay protection in a long-lived
/// store.
///
/// # Errors
///
/// Throws on **any** verification failure (fail-closed): a verified denial/expiry/abort, a bad
/// signature, a broken WYSIWYS binding, an expired/out-of-window decision, an optional
/// `expected_account_id` mismatch, etc. The thrown message is the core
/// [`VerifyError`](allw_core::VerifyError) `Display`, for diagnostics only. A verified "no" is
/// distinguished from a forgery **only** by the structured error (see [`verify_failure`]): an
/// `Error` with `kind: "not_approved"` and the signed `decision`. Also throws (unclassified) if any
/// input JSON is invalid, the root key is not a 32-byte base64url value, or `now_ms` is out of
/// range.
#[wasm_bindgen]
pub fn verify_verdict(
    verdict_json: &str,
    request_json: &str,
    context_json: &str,
    approver_root_pubkey_b64: &str,
    now_ms: f64,
    expected_account_id: Option<String>,
) -> Result<String, JsValue> {
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
    let verified = match expected_account_id_constraint(expected_account_id.as_deref()) {
        Some(expected) => core_verify_verdict_for_account(
            &verdict,
            &request,
            &context,
            &root,
            &mut nonce_store,
            now_ms,
            expected,
        ),
        None => core_verify_verdict(
            &verdict,
            &request,
            &context,
            &root,
            &mut nonce_store,
            now_ms,
        ),
    }
    .map_err(|e| verify_failure("verify_verdict", e))?;

    to_json(
        &VerifyResult {
            approved: true,
            device_id: verified.device_id,
            decided_at: verified.decided_at,
            nonce_b64: URL_SAFE_NO_PAD.encode(verified.nonce),
            note: verified.note,
        },
        "VerifyResult",
    )
    .map_err(JsValue::from)
}

/// Verifies a [`Verdict`](allw_core::Verdict) exactly like [`verify_verdict`], but additionally
/// rejects verdicts signed by a device revoked in the highest-sequence valid root-signed account
/// state supplied by the caller.
///
/// `account_states_json` is a JSON array of compact `allw-account-state+jws` strings. The core
/// validates every supplied state against `approver_root_pubkey_b64`; malformed, wrong-account, or
/// wrong-root state fails closed instead of being ignored. Callers must persist monotonic account
/// state themselves: passing only stale state can make stale trust look current.
///
/// # Errors
///
/// Throws on any ordinary verdict verification failure, any invalid account-state JWS, or a
/// highest-sequence account state that revokes the verdict-signing device.
#[wasm_bindgen]
pub fn verify_verdict_with_account_states(
    verdict_json: &str,
    request_json: &str,
    context_json: &str,
    approver_root_pubkey_b64: &str,
    now_ms: f64,
    account_states_json: &str,
    expected_account_id: Option<String>,
) -> Result<String, JsValue> {
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
    let account_states = parse_account_states_json(account_states_json)?;
    let account_state_refs: Vec<&str> = account_states.iter().map(String::as_str).collect();

    let mut nonce_store = allw_core::InMemoryNonceStore::new();
    let verified = match expected_account_id_constraint(expected_account_id.as_deref()) {
        Some(expected) => core_verify_verdict_with_account_states_for_account(
            &verdict,
            &request,
            &context,
            &root,
            &mut nonce_store,
            now_ms,
            &account_state_refs,
            expected,
        ),
        None => core_verify_verdict_with_account_states(
            &verdict,
            &request,
            &context,
            &root,
            &mut nonce_store,
            now_ms,
            &account_state_refs,
        ),
    }
    .map_err(|e| verify_failure("verify_verdict_with_account_states", e))?;

    to_json(
        &VerifyResult {
            approved: true,
            device_id: verified.device_id,
            decided_at: verified.decided_at,
            nonce_b64: URL_SAFE_NO_PAD.encode(verified.nonce),
            note: verified.note,
        },
        "VerifyResult",
    )
    .map_err(JsValue::from)
}

// ── verify_verdict_provenance ─────────────────────────────────────────────────────────

/// The successful result of [`verify_verdict_provenance`]: who signed the verdict. **Not** a
/// verified human decision — see the core
/// [`VerdictProvenance`](allw_core::VerdictProvenance).
#[derive(Serialize)]
struct ProvenanceResult {
    /// The certified device that signed the verdict.
    device_id: String,
    /// The signed decision time, Unix ms. The device certificate was unexpired at it.
    decided_at: i64,
}

/// Checks a verdict's provenance without the plaintext: signed for `request_id`, with a
/// `decided_at` inside `[created_at, expires_at]` (the request envelope's window), by a device of
/// `account_id` certified by the account root, and not revoked in `account_states_json`. The
/// relay's gate before it records a verdict (see the core
/// [`verify_verdict_provenance`](allw_core::verify_verdict_provenance) for the exact checks).
///
/// - `account_states_json` — a JSON array of compact `allw-account-state+jws` strings; `[]` skips
///   the revocation check. Every document must verify against the root, or the check fails closed.
///
/// Returns `{ device_id, decided_at }` JSON. This is **not** approval: the request hash, replay
/// and decision are unchecked; only [`verify_verdict`] yields a verified decision.
///
/// # Errors
///
/// Throws on any failed check (the message is the core [`VerifyError`] `Display`, for diagnostics
/// only), on invalid `verdict_json` / `account_states_json`, on a root key that is not a 32-byte
/// base64url Ed25519 key, or on a `created_at` / `expires_at` that is not an integer in range.
#[wasm_bindgen]
pub fn verify_verdict_provenance(
    verdict_json: &str,
    request_id: &str,
    created_at: f64,
    expires_at: f64,
    account_id: &str,
    account_root_pubkey_b64: &str,
    account_states_json: &str,
) -> Result<String, JsValue> {
    let verdict: Verdict = parse_json(verdict_json, "Verdict")?;
    let root_bytes = decode_b64_32(account_root_pubkey_b64, "account_root_pubkey_b64")?;
    let root = PublicKey::from_bytes(&root_bytes).map_err(|e| {
        JsError::new(&format!(
            "account_root_pubkey_b64 is not a valid Ed25519 key: {e}"
        ))
    })?;
    let created_at = ms_to_i64(created_at, "created_at")?;
    let expires_at = ms_to_i64(expires_at, "expires_at")?;
    let account_states = parse_account_states_json(account_states_json)?;
    let account_state_refs: Vec<&str> = account_states.iter().map(String::as_str).collect();

    let provenance = core_verify_verdict_provenance(
        &verdict,
        request_id,
        created_at,
        expires_at,
        account_id,
        &root,
        &account_state_refs,
    )
    .map_err(|e| {
        JsValue::from(JsError::new(&format!(
            "verify_verdict_provenance failed: {e}"
        )))
    })?;

    to_json(
        &ProvenanceResult {
            device_id: provenance.device_id,
            decided_at: provenance.decided_at,
        },
        "ProvenanceResult",
    )
    .map_err(JsValue::from)
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
/// - `device_cert` — the device→account-root certificate JWS (from [`issue_device_cert`]); required
///   so the signed verdict can chain the device key to the account root.
///
/// # Errors
///
/// Throws if any JSON/seed/nonce input is malformed (invalid JSON, a non-32-byte seed, a
/// non-base64url nonce, a `request_hash` that is not 32 base64url bytes, or `device_cert` is empty).
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

    let cert = required_device_cert(device_cert)?;

    let verdict: Verdict = core_sign_verdict(&unsigned, &device_key, &nonce, Some(cert))
        .map_err(|e| JsError::new(&format!("sign_verdict failed: {e}")))?;
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

// ── account state ───────────────────────────────────────────────────────────────────

/// Signs a root-authored [`AccountState`](allw_core::AccountState), returning an
/// `allw-account-state+jws` compact JWS string. This is a test/development helper for the SDK
/// surface; production account-state issuance belongs to account-owner enrollment flows.
///
/// # Errors
///
/// Throws if `state_json` is not a valid `AccountState` JSON document or
/// `account_root_seed_b64` is not a 32-byte base64url seed.
#[wasm_bindgen]
pub fn sign_account_state(
    state_json: &str,
    account_root_seed_b64: &str,
) -> Result<String, JsError> {
    let state: AccountState = parse_json(state_json, "AccountState")?;
    let seed = decode_b64_32(account_root_seed_b64, "account_root_seed_b64")?;
    let account_root = SigningKeyPair::from_seed(&seed);
    Ok(core_sign_account_state(&state, &account_root))
}

/// Verifies a root-signed account-state JWS for `expected_account_id`, returning the verified
/// [`AccountState`](allw_core::AccountState) JSON. Wrong account ids, wrong roots, invalid
/// signatures, and unsupported versions all fail closed.
///
/// # Errors
///
/// Throws if `account_root_pubkey_b64` is not a valid Ed25519 public key or the account-state JWS
/// does not verify against that root for `expected_account_id`.
#[wasm_bindgen]
pub fn verify_account_state(
    account_state_jws: &str,
    expected_account_id: &str,
    account_root_pubkey_b64: &str,
) -> Result<String, JsError> {
    let root_bytes = decode_b64_32(account_root_pubkey_b64, "account_root_pubkey_b64")?;
    let root = PublicKey::from_bytes(&root_bytes).map_err(|e| {
        JsError::new(&format!(
            "account_root_pubkey_b64 is not a valid Ed25519 key: {e}"
        ))
    })?;
    let state = core_verify_account_state(account_state_jws, expected_account_id, &root)
        .map_err(|e| JsError::new(&format!("verify_account_state failed: {e}")))?;
    to_json(&state, "AccountState")
}

/// Resolves the set of device ids revoked in the **highest-sequence** verified root-signed
/// account-state document(s) among `account_states_json`, returned as a JSON array of strings.
///
/// This is the sender-side counterpart to [`verify_verdict_with_account_states`]'s revocation
/// enforcement (issue #204 fix 1): the SDK calls this **before** encrypting a new request so a
/// device the account owner already revoked never receives the plaintext `ApprovalContext` in
/// the first place — closing the gap where a revoked device could still read every new request
/// up until its next verdict submission was rejected. The set/parse/verify logic stays here
/// (thin-shell); the caller only needs to drop matching `device_id`s from the recipient list it
/// builds for [`encrypt_context`].
///
/// `account_states_json` is a JSON array of compact `allw-account-state+jws` strings, exactly
/// like [`verify_verdict_with_account_states`]. An empty array resolves to an empty (no known
/// revocations) result rather than an error, so the filter is a no-op when the caller has no
/// account-state material yet.
///
/// # Errors
///
/// Throws if `account_states_json` is not valid JSON, `account_root_pubkey_b64` is not a valid
/// Ed25519 key, or any supplied account-state JWS fails to verify for `expected_account_id`
/// against that root (wrong account, wrong root, bad signature, unsupported version) — a bad
/// document is never silently dropped, since that could mask a real revocation.
#[wasm_bindgen]
pub fn revoked_device_ids(
    account_states_json: &str,
    expected_account_id: &str,
    account_root_pubkey_b64: &str,
) -> Result<String, JsError> {
    let root_bytes = decode_b64_32(account_root_pubkey_b64, "account_root_pubkey_b64")?;
    let root = PublicKey::from_bytes(&root_bytes).map_err(|e| {
        JsError::new(&format!(
            "account_root_pubkey_b64 is not a valid Ed25519 key: {e}"
        ))
    })?;
    let account_states = parse_account_states_json(account_states_json)?;
    let account_state_refs: Vec<&str> = account_states.iter().map(String::as_str).collect();

    let ids = core_revoked_device_ids(&account_state_refs, expected_account_id, &root)
        .map_err(|e| JsError::new(&format!("revoked_device_ids failed: {e}")))?;
    let mut ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    // Sort for a deterministic wire result (a `HashSet` has no defined iteration order).
    ids.sort_unstable();
    to_json(&ids, "revoked device ids")
}

/// One recipient chosen by [`select_recipients`]: the device id and its X25519 encryption public
/// key (base64url-unpadded, 32 bytes), as the account root signed them in account state.
#[derive(Serialize)]
struct WasmSelectedRecipient<'a> {
    device_id: &'a str,
    encryption_pubkey: String,
}

/// Converts an optional JS sequence floor to the core's `u64`. `undefined`/`null` arrive as `None`
/// (no floor persisted yet); anything else must be a non-negative integer in JS safe-integer range,
/// so a floor can never be rounded down into accepting an older state.
fn sequence_floor_from_f64(min_sequence: Option<f64>) -> Result<Option<u64>, JsError> {
    let Some(n) = min_sequence else {
        return Ok(None);
    };
    if !n.is_finite() || n.fract() != 0.0 || n < 0.0 || n > JS_MAX_SAFE_INTEGER {
        return Err(JsError::new(&format!(
            "min_sequence must be a non-negative safe integer, got {n}"
        )));
    }
    Ok(Some(n as u64))
}

/// Selects the devices an `ApprovalContext` may be encrypted to from root-signed account state
/// (core [`select_recipients`](allw_core::select_recipients)), returned as a JSON array of
/// `{ "device_id": string, "encryption_pubkey": string }` sorted by `device_id`.
///
/// - `account_states_json`: a JSON array of compact `allw-account-state+jws` documents. Only the
///   highest-sequence documents count; recipients are their `active`, unrevoked devices whose
///   signed `cert_expires_at` is after `now_ms`, narrowed to the devices every same-sequence
///   sibling agrees on.
/// - `now_ms`: the current Unix time in integer milliseconds (never negative).
/// - `min_sequence`: the caller's persisted sequence floor, or `undefined`/`null` for none.
///
/// # Errors
///
/// Throws — never returns an empty array — when `account_root_pubkey_b64` is not a valid Ed25519
/// key, `now_ms` or `min_sequence` is out of range, the array is malformed, empty or longer than
/// `MAX_ACCOUNT_STATES` (64), any document fails verification, the highest sequence is below
/// `min_sequence`, a device entry is malformed, no recipient remains, or more than
/// `MAX_RECIPIENTS` (16) remain.
#[wasm_bindgen]
pub fn select_recipients(
    account_states_json: &str,
    expected_account_id: &str,
    account_root_pubkey_b64: &str,
    now_ms: f64,
    min_sequence: Option<f64>,
) -> Result<String, JsError> {
    let root = parse_account_root_pubkey(account_root_pubkey_b64)?;
    let now_ms = ms_to_i64(now_ms, "now_ms")?;
    // A Unix-ms clock is never negative; a negative one would read every expiry as in the future.
    if now_ms < 0 {
        return Err(JsError::new(&format!(
            "now_ms must be a non-negative Unix millisecond timestamp, got {now_ms}"
        )));
    }
    let min_sequence = sequence_floor_from_f64(min_sequence)?;
    let account_states = parse_account_states_json(account_states_json)?;
    let account_state_refs: Vec<&str> = account_states.iter().map(String::as_str).collect();

    let recipients = core_select_recipients(
        &account_state_refs,
        expected_account_id,
        &root,
        now_ms,
        min_sequence,
    )
    .map_err(|e| JsError::new(&format!("select_recipients failed: {e}")))?;
    let wire: Vec<WasmSelectedRecipient<'_>> = recipients
        .iter()
        .map(|r| WasmSelectedRecipient {
            device_id: &r.device_id,
            encryption_pubkey: URL_SAFE_NO_PAD.encode(r.encryption_pubkey),
        })
        .collect();
    to_json(&wire, "selected recipients")
}

// ── seal_context_for_account_state ───────────────────────────────────────────────────

/// The JSON shape [`seal_context_for_account_state`] returns.
#[derive(Serialize)]
struct WasmSealedContext<'a> {
    ciphertext: &'a str,
    sequence: u64,
}

/// Encrypts an [`ApprovalContext`](allw_core::ApprovalContext) to exactly the devices root-signed
/// account state selects (core
/// [`seal_context_for_account_state`](allw_core::seal_context_for_account_state)), returning JSON
/// `{ "ciphertext": string, "sequence": number }`.
///
/// The selected recipient keys never cross into JavaScript: the only way to get a ciphertext here
/// is through the core's selection rules ([`select_recipients`]). `sequence` is the highest
/// verified account-state sequence the recipients came from; a caller that persists a floor records
/// it before sending the ciphertext. Randomness comes from the platform CSPRNG, as for
/// [`encrypt_context`].
///
/// # Errors
///
/// Throws, with nothing encrypted, on any [`select_recipients`] error (same inputs, same rules), a
/// malformed `context_json`, or a selected sequence above JS safe-integer range (it could not be
/// persisted exactly as a floor).
#[wasm_bindgen]
pub fn seal_context_for_account_state(
    context_json: &str,
    account_states_json: &str,
    expected_account_id: &str,
    account_root_pubkey_b64: &str,
    now_ms: f64,
    min_sequence: Option<f64>,
) -> Result<String, JsError> {
    let context: ApprovalContext = parse_json(context_json, "ApprovalContext")?;
    let root = parse_account_root_pubkey(account_root_pubkey_b64)?;
    let now_ms = ms_to_i64(now_ms, "now_ms")?;
    if now_ms < 0 {
        return Err(JsError::new(&format!(
            "now_ms must be a non-negative Unix millisecond timestamp, got {now_ms}"
        )));
    }
    let min_sequence = sequence_floor_from_f64(min_sequence)?;
    let account_states = parse_account_states_json(account_states_json)?;
    let account_state_refs: Vec<&str> = account_states.iter().map(String::as_str).collect();

    let sealed = core_seal_context_for_account_state(
        &context,
        &account_state_refs,
        expected_account_id,
        &root,
        now_ms,
        min_sequence,
        &mut OsRng,
    )
    .map_err(|e| JsError::new(&format!("seal_context_for_account_state failed: {e}")))?;
    // The floor round-trips through a JS number; refuse a sequence it cannot hold exactly.
    if sealed.sequence > JS_MAX_SAFE_SEQUENCE {
        return Err(JsError::new(&format!(
            "selected account-state sequence {} exceeds JS safe-integer range (2^53-1)",
            sealed.sequence
        )));
    }
    to_json(
        &WasmSealedContext {
            ciphertext: &sealed.ciphertext,
            sequence: sealed.sequence,
        },
        "sealed context",
    )
}

/// `Number.MAX_SAFE_INTEGER` as a `u64`: the largest sequence a JS caller can persist exactly.
const JS_MAX_SAFE_SEQUENCE: u64 = (1 << 53) - 1;

// ── self-certifying account id + pairing-start authorization ────────────────────────

/// Decodes and validates an account-root Ed25519 public key argument.
fn parse_account_root_pubkey(account_root_pubkey_b64: &str) -> Result<PublicKey, JsError> {
    let root_bytes = decode_b64_32(account_root_pubkey_b64, "account_root_pubkey_b64")?;
    PublicKey::from_bytes(&root_bytes).map_err(|e| {
        JsError::new(&format!(
            "account_root_pubkey_b64 is not a valid Ed25519 key: {e}"
        ))
    })
}

// ── Root-holder enrollment authoring (#379, #381) ───────────────────────────────────

/// Converts a JS-number account-state sequence to `u64`, refusing anything that is not a
/// non-negative safe integer.
fn sequence_from_f64(n: f64, what: &str) -> Result<u64, JsError> {
    if !n.is_finite() || n.fract() != 0.0 || n < 0.0 || n > JS_MAX_SAFE_INTEGER {
        return Err(JsError::new(&format!(
            "{what} must be a non-negative safe integer, got {n}"
        )));
    }
    Ok(n as u64)
}

/// Validates a device id and its public keys exactly as the core does before vouching for them
/// (core [`DeviceEnrollment::parse`](allw_core::DeviceEnrollment::parse)): a 1-64 character
/// base64url-alphabet id, canonical unpadded base64url keys of 32 bytes, a canonical X25519 key
/// that is not small-order, and a canonical, non-small-order Ed25519 point.
///
/// # Errors
///
/// Throws naming the first value that fails.
#[wasm_bindgen]
pub fn check_device_enrollment(
    device_id: &str,
    encryption_pubkey_b64: &str,
    signing_pubkey_b64: &str,
) -> Result<(), JsError> {
    DeviceEnrollment::parse(device_id, encryption_pubkey_b64, signing_pubkey_b64)
        .map(|_| ())
        .map_err(|e| JsError::new(&format!("invalid device material: {e}")))
}

/// Which of a pasted device's keys equal another key pair's (core
/// [`DeviceEnrollment::shared_key_kinds`](allw_core::DeviceEnrollment::shared_key_kinds)), as a
/// JSON array of `"encryption"` / `"signing"`; `[]` when neither matches. `allw-approver vouch`
/// passes the keyfile's own public keys (derived from its seeds by the core) and refuses on any
/// match (#381). The device's values are validated exactly as [`check_device_enrollment`] does
/// and compared as parsed 32-byte keys, never as text.
///
/// # Errors
///
/// Throws if the device material is invalid or either other key does not decode to 32 bytes.
#[wasm_bindgen]
pub fn shared_device_keys(
    device_id: &str,
    encryption_pubkey_b64: &str,
    signing_pubkey_b64: &str,
    other_encryption_pubkey_b64: &str,
    other_signing_pubkey_b64: &str,
) -> Result<String, JsError> {
    let device = DeviceEnrollment::parse(device_id, encryption_pubkey_b64, signing_pubkey_b64)
        .map_err(|e| JsError::new(&format!("invalid device material: {e}")))?;
    let other_encryption = decode_b64_32(other_encryption_pubkey_b64, "other_encryption_pubkey")?;
    let other_signing = decode_b64_32(other_signing_pubkey_b64, "other_signing_pubkey")?;
    let kinds: Vec<&str> = device
        .shared_key_kinds(&other_encryption, &other_signing)
        .into_iter()
        .map(|kind| match kind {
            DeviceKeyKind::Encryption => "encryption",
            DeviceKeyKind::Signing => "signing",
        })
        .collect();
    to_json(&kinds, "shared device keys")
}

/// The human-comparable fingerprint of a device public key (core
/// [`device_key_fingerprint`](allw_core::device_key_fingerprint)): 32 lowercase hex digits in
/// eight space-separated groups of four. `kind` is `"encryption"` (X25519) or `"signing"`
/// (Ed25519); the kind is bound into the fingerprint.
///
/// # Errors
///
/// Throws if `kind` is neither value or `key_b64` does not decode to 32 bytes.
#[wasm_bindgen]
pub fn device_key_fingerprint(kind: &str, key_b64: &str) -> Result<String, JsError> {
    let kind = match kind {
        "encryption" => DeviceKeyKind::Encryption,
        "signing" => DeviceKeyKind::Signing,
        other => {
            return Err(JsError::new(&format!(
                "kind must be \"encryption\" or \"signing\", got {other:?}"
            )))
        }
    };
    let key = decode_b64_32(key_b64, "key_b64")?;
    Ok(core_device_key_fingerprint(kind, &key))
}

/// A change to the account state, as JavaScript passes it to [`next_account_state`]. Tagged by
/// `kind` so the enrollment ceremony (#199) can add rotation and revocation without a new export.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WasmAccountStateChange {
    AddDevice {
        device_id: String,
        encryption_pubkey: String,
        signing_pubkey: String,
    },
}

/// The result of [`next_account_state`], as JSON. `state_json` is the unsigned `AccountState`
/// exactly as the core serialized it, passed unchanged to [`sign_account_state`] so the signed
/// bytes are never re-encoded in JavaScript. The id lists are what a human confirming the change
/// must see (core [`NextAccountState`](allw_core::NextAccountState)).
#[derive(Serialize)]
struct WasmNextAccountState<'a> {
    state_json: String,
    sequence: u64,
    /// Ids of entries retired because they carried the added key pair under another id (#378).
    replaced_device_ids: &'a [String],
    /// Every active device id in the next state: the request recipients once it is published.
    active_device_ids: Vec<&'a str>,
}

/// Composes the next **unsigned** root-signed account state (core
/// [`next_account_state`](allw_core::next_account_state)). Every surface that changes account
/// state (`allw-approver pair` and `vouch`) goes through this, so the composition rules exist once.
///
/// Returns JSON `{ state_json, sequence, replaced_device_ids, active_device_ids }`: `state_json`
/// is the `AccountState` JSON for [`sign_account_state`], and the two id lists are what the change
/// does, for the caller to show before it signs.
///
/// - `account_states_json`: a JSON array of the compact account-state JWS the relay served.
/// - `relay_max_sequence`: the relay's claimed highest sequence (`0` when it holds none).
/// - `floor`: the highest sequence this root holder already published or accepted (`0` if none).
/// - `change_json`: `{"kind":"add_device","device_id":…,"encryption_pubkey":…,"signing_pubkey":…}`.
///
/// # Errors
///
/// Throws on malformed input, invalid device material, or any composition refusal (a document
/// that does not verify, an unbacked max sequence, a rollback below `floor`, disagreeing siblings,
/// a revoked or conflicting device, too many devices), and if the new sequence is not a JS safe
/// integer.
#[wasm_bindgen]
pub fn next_account_state(
    account_states_json: &str,
    relay_max_sequence: f64,
    floor: f64,
    expected_account_id: &str,
    account_root_pubkey_b64: &str,
    change_json: &str,
) -> Result<String, JsError> {
    let account_states = parse_account_states_json(account_states_json)?;
    let refs: Vec<&str> = account_states.iter().map(String::as_str).collect();
    let relay_max_sequence = sequence_from_f64(relay_max_sequence, "relay_max_sequence")?;
    let floor = sequence_from_f64(floor, "floor")?;
    let root = parse_account_root_pubkey(account_root_pubkey_b64)?;
    let change = match parse_json::<WasmAccountStateChange>(change_json, "account-state change")? {
        WasmAccountStateChange::AddDevice {
            device_id,
            encryption_pubkey,
            signing_pubkey,
        } => AccountStateChange::AddDevice(
            DeviceEnrollment::parse(&device_id, &encryption_pubkey, &signing_pubkey)
                .map_err(|e| JsError::new(&format!("invalid device material: {e}")))?,
        ),
    };
    let next = core_next_account_state(
        &refs,
        relay_max_sequence,
        floor,
        expected_account_id,
        &root,
        &change,
    )
    .map_err(|e| JsError::new(&format!("next_account_state refused: {e}")))?;
    let sequence = next.state().sequence;
    if sequence > JS_MAX_SAFE_SEQUENCE {
        return Err(JsError::new(&format!(
            "next account-state sequence {sequence} exceeds JS safe-integer range (2^53-1)"
        )));
    }
    to_json(
        &WasmNextAccountState {
            state_json: to_json(next.state(), "AccountState")?,
            sequence,
            replaced_device_ids: next.replaced_device_ids(),
            active_device_ids: next.active_device_ids().collect(),
        },
        "next account state",
    )
}

/// Derives the self-certifying account id for an account-root public key
/// (`docs/enrollment.md` §Model): `base64url(SHA-256("allw/account-id/v1" || 0x00 || root))`.
///
/// # Errors
///
/// Throws if `account_root_pubkey_b64` is not a valid base64url Ed25519 public key.
#[wasm_bindgen]
pub fn account_id_for_root(account_root_pubkey_b64: &str) -> Result<String, JsError> {
    let root = parse_account_root_pubkey(account_root_pubkey_b64)?;
    Ok(core_account_id_for_root(&root))
}

/// Checks that `account_id` is exactly the id derived from `account_root_pubkey_b64`. Returns
/// nothing on success.
///
/// # Errors
///
/// Throws if the public key is malformed or the account id does not derive from it.
#[wasm_bindgen]
pub fn check_account_id_for_root(
    account_id: &str,
    account_root_pubkey_b64: &str,
) -> Result<(), JsError> {
    let root = parse_account_root_pubkey(account_root_pubkey_b64)?;
    core_check_account_id_for_root(account_id, &root)
        .map_err(|e| JsError::new(&format!("check_account_id_for_root failed: {e}")))
}

/// Signs an `allw-pairing-start+jws` authorization with the account root, for the account id
/// derived from that root. `jti` must be 16–128 base64url characters (generate it randomly);
/// `expires_at - issued_at` must be in `(0, 5 min]`.
///
/// # Errors
///
/// Throws if the seed is malformed, a timestamp is not an in-range integer, or the `jti` /
/// validity window would be rejected by the verifier.
#[wasm_bindgen]
pub fn sign_pairing_start_authorization(
    account_root_seed_b64: &str,
    issued_at: f64,
    expires_at: f64,
    jti: &str,
) -> Result<String, JsError> {
    let seed = decode_b64_32(account_root_seed_b64, "account_root_seed_b64")?;
    let account_root = SigningKeyPair::from_seed(&seed);
    let issued_at = ms_to_i64(issued_at, "issued_at")?;
    let expires_at = ms_to_i64(expires_at, "expires_at")?;
    core_sign_pairing_start_authorization(&account_root, issued_at, expires_at, jti)
        .map_err(|e| JsError::new(&format!("sign_pairing_start_authorization failed: {e}")))
}

/// Verifies an `allw-pairing-start+jws` authorization for `expected_account_id` against the
/// presented account root at `now_ms`, returning the verified
/// [`PairingStartClaims`](allw_core::PairingStartClaims) JSON. The caller must still reject a
/// replayed `jti` (the relay keeps each accepted `jti` until its `expires_at`).
///
/// # Errors
///
/// Throws if the public key is malformed, the account id does not derive from it, or the
/// authorization fails any check (signature, `typ`, account, version, `jti`, lifetime, freshness).
#[wasm_bindgen]
pub fn verify_pairing_start_authorization(
    authorization: &str,
    expected_account_id: &str,
    account_root_pubkey_b64: &str,
    now_ms: f64,
) -> Result<String, JsError> {
    let root = parse_account_root_pubkey(account_root_pubkey_b64)?;
    let now_ms = ms_to_i64(now_ms, "now_ms")?;
    let claims =
        core_verify_pairing_start_authorization(authorization, expected_account_id, &root, now_ms)
            .map_err(|e| {
                JsError::new(&format!("verify_pairing_start_authorization failed: {e}"))
            })?;
    to_json(&claims, "PairingStartClaims")
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
/// account-root-signed certificate for this device and must not be empty.
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
    let cert = required_device_cert(device_cert)?;
    let rule = core_sign_policy_rule(&unsigned, device_id, &device_key, Some(cert));
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
/// timestamp, the device seed is not a 32-byte base64url value, or `device_cert` is empty.
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
    let cert = required_device_cert(device_cert)?;
    let rule = core_sign_policy_rule(&unsigned, device_id, &device_key, Some(cert));
    to_json(&rule, "PolicyRule")
}

/// Verifies one signed [`PolicyRule`](allw_core::PolicyRule) against an account root and the
/// caller-supplied account-state JWS set. A highest-sequence revocation for the rule-signing
/// device rejects the rule even when its embedded device certificate still chains to the root.
///
/// # Errors
///
/// Throws if the rule JSON is malformed, the root key is invalid, any account-state JWS is invalid
/// for the rule account/root, `expected_account_id` does not match the rule account, or the rule
/// fails certificate/signature/revocation verification.
#[wasm_bindgen]
pub fn verify_policy_rule_with_account_states(
    rule_json: &str,
    account_root_pubkey_b64: &str,
    now_ms: f64,
    account_states_json: &str,
    expected_account_id: Option<String>,
) -> Result<String, JsError> {
    let rule: PolicyRule = parse_json(rule_json, "PolicyRule")?;
    let root_pubkey_bytes = decode_b64_32(account_root_pubkey_b64, "account_root_pubkey_b64")?;
    let root_pubkey = PublicKey::from_bytes(&root_pubkey_bytes).map_err(|e| {
        JsError::new(&format!(
            "account_root_pubkey_b64 is not a valid Ed25519 key: {e}"
        ))
    })?;
    let now_ms = ms_to_i64(now_ms, "now_ms")?;
    let account_states = parse_account_states_json(account_states_json)?;
    let account_state_refs: Vec<&str> = account_states.iter().map(String::as_str).collect();

    let verified = match expected_account_id_constraint(expected_account_id.as_deref()) {
        Some(expected) => core_verify_policy_rule_with_account_states_for_account(
            &rule,
            &root_pubkey,
            now_ms,
            &account_state_refs,
            expected,
        ),
        None => core_verify_policy_rule_with_account_states(
            &rule,
            &root_pubkey,
            now_ms,
            &account_state_refs,
        ),
    }
    .map_err(|e| {
        JsError::new(&format!(
            "verify_policy_rule_with_account_states failed: {e}"
        ))
    })?;
    to_json(&verified, "VerifiedPolicyRule")
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
/// Ed25519 key, `now_ms` is not a safe integer millisecond timestamp, an optional
/// `expected_account_id` does not match a rule account, or any signed policy rule fails
/// verification.
#[wasm_bindgen]
pub fn evaluate_policy(
    action_json: &str,
    actor_json: Option<String>,
    signed_rules_json: &str,
    account_root_pubkey_b64: &str,
    now_ms: f64,
    expected_account_id: Option<String>,
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
            match expected_account_id_constraint(expected_account_id.as_deref()) {
                Some(expected) => {
                    core_verify_policy_rule_for_account(rule, &root_pubkey, now_ms, expected)
                }
                None => core_verify_policy_rule(rule, &root_pubkey, now_ms),
            }
            .map_err(|e| JsError::new(&format!("verify_policy_rule failed: {e}")))
        })
        .collect::<Result<Vec<_>, JsError>>()?;

    let evaluation = match actor.as_ref() {
        Some(actor) => core_evaluate_for_actor(actor, &action, &verified),
        None => core_evaluate(&action, &verified),
    };
    to_json(&evaluation, "PolicyEvaluation")
}

/// Verifies signed policy rules with account-state revocation enforcement and evaluates them
/// against one action. This is the account-state-aware twin of [`evaluate_policy`]: every supplied
/// rule must verify under the account root and must not have been signed by a revoked device.
///
/// # Errors
///
/// Throws if action/actor/rules/account-state JSON is malformed, the root key is invalid,
/// `now_ms` is unsafe, an optional `expected_account_id` does not match a rule account, or any
/// signed rule fails verification.
#[wasm_bindgen]
pub fn evaluate_policy_with_account_states(
    action_json: &str,
    actor_json: Option<String>,
    signed_rules_json: &str,
    account_root_pubkey_b64: &str,
    now_ms: f64,
    account_states_json: &str,
    expected_account_id: Option<String>,
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
    let account_states = parse_account_states_json(account_states_json)?;
    let account_state_refs: Vec<&str> = account_states.iter().map(String::as_str).collect();
    let verified = rules
        .iter()
        .map(|rule| {
            match expected_account_id_constraint(expected_account_id.as_deref()) {
                Some(expected) => core_verify_policy_rule_with_account_states_for_account(
                    rule,
                    &root_pubkey,
                    now_ms,
                    &account_state_refs,
                    expected,
                ),
                None => core_verify_policy_rule_with_account_states(
                    rule,
                    &root_pubkey,
                    now_ms,
                    &account_state_refs,
                ),
            }
            .map_err(|e| {
                JsError::new(&format!(
                    "verify_policy_rule_with_account_states failed: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, JsError>>()?;

    let evaluation = match actor.as_ref() {
        Some(actor) => core_evaluate_for_actor(actor, &action, &verified),
        None => core_evaluate(&action, &verified),
    };
    to_json(&evaluation, "PolicyEvaluation")
}

// ── actor attestation (verified request origin, issue #16) ──────────────────────────────

/// Signs an **actor attestation** binding the actor identity to a request's `request_id` +
/// `request_hash`, and returns the attestation as a **base64url-unpadded** string — the value to
/// place in the envelope's `ApprovalContext.actor.attestation` (the wire encoding of that
/// `Option<Vec<u8>>` field). This is the *request side* of the trust model (`docs/contract.md`
/// §Invariants #4), distinct from verdict signing.
///
/// The attestation is an EdDSA compact JWS over `(account_id, actor_id, actor_kind, request_id,
/// request_hash)`, so it is **request-specific** — bound to both the request id and its WYSIWYS
/// hash, not a reusable identity token.
///
/// - `account_id` — the account namespace the attestation binds to.
/// - `actor_id` / `actor_kind` — the actor identity being attested (echoed in the signed claims).
/// - `request_id` — the envelope id this attestation answers (binds id, not just hash).
/// - `request_hash_b64` — the WYSIWYS `request_hash`, base64url-unpadded 32 bytes (from
///   [`compute_request_hash`]).
/// - `actor_seed_b64` — the actor signing-key seed, base64url-unpadded 32 bytes. **v0 stand-in:**
///   a software-held seed; production actor keys are enrollment-/hardware-backed and never
///   serialize.
///
/// # Errors
///
/// Throws if `request_hash_b64` is not 32 base64url bytes, or `actor_seed_b64` is not a 32-byte
/// base64url value.
#[wasm_bindgen]
pub fn sign_actor_attestation(
    account_id: &str,
    actor_id: &str,
    actor_kind: &str,
    request_id: &str,
    request_hash_b64: &str,
    actor_seed_b64: &str,
) -> Result<String, JsError> {
    let request_hash = decode_b64_32(request_hash_b64, "request_hash_b64")?;
    let seed = decode_b64_32(actor_seed_b64, "actor_seed_b64")?;
    let actor_key = SigningKeyPair::from_seed(&seed);
    let attestation = core_sign_actor_attestation(
        account_id,
        actor_id,
        actor_kind,
        request_id,
        &request_hash,
        &actor_key,
    );
    Ok(URL_SAFE_NO_PAD.encode(attestation))
}

/// The successful result of [`verify_actor_attestation`] — a cryptographically-**verified origin**.
/// Serialized to JSON for the JS caller.
///
/// **Not authorization.** A verified origin only lets the inbox render a trusted "who" (instead of
/// `⚠ UNVERIFIED`); the human still decides and the integrator still composes the final gate.
#[derive(Serialize)]
struct OriginResult {
    /// Always `true` on success (a failed verification throws instead of returning `false`).
    verified: bool,
    /// The actor id, echoed from the verified attestation.
    actor_id: String,
    /// The actor kind, echoed from the verified attestation.
    actor_kind: String,
    /// A human-readable verified-origin string (`"{kind} · {id}"`) for inbox display.
    origin: String,
}

/// Verifies the attestation carried by an [`Actor`](allw_core::Actor) against a request's
/// `request_id` + `request_hash`, resolving the actor's verifying key from **root-signed account
/// state** (`docs/enrollment.md` §Account State) — NOT from a relay-supplied registry. The actor
/// key is trusted only because it appears, `active` and un-revoked, in an account-state document
/// that the configured account root signed; a malicious relay cannot substitute its own key for an
/// actor id and forge a verified origin.
///
/// On success returns a JSON
/// `{ "verified": true, "actor_id": string, "actor_kind": string, "origin": string }`.
///
/// `actor_json` is the JSON `Actor` `{ id, kind, attestation? }` from the decrypted
/// `ApprovalContext` (its `attestation` is a base64url-unpadded string when present).
/// `account_states_json` is a JSON array of compact `allw-account-state+jws` strings — the core
/// resolves the actor key from the highest valid sequence and rejects revoked/inactive actors.
///
/// # Errors
///
/// Throws on **any** verification failure (fail-closed, `docs/contract.md` §Invariants #6): a
/// missing attestation, a malformed/wrong-`typ` JWS, a signature that does not verify under the
/// root-anchored key, a spoofed actor id/kind, a wrong `request_id`/`request_hash`, an actor not
/// present (or revoked/inactive) in account state, or any invalid account-state JWS. Also throws if
/// `actor_json` is not a valid `Actor`, `request_hash_b64` is not 32 base64url bytes, or
/// `account_root_pubkey_b64` is not a valid Ed25519 key. The thrown message is the core
/// [`AttestationError`](allw_core::AttestationError) `Display`, so a caller can distinguish *why*
/// the origin is unverified.
#[wasm_bindgen]
pub fn verify_actor_attestation(
    actor_json: &str,
    account_id: &str,
    request_id: &str,
    request_hash_b64: &str,
    account_states_json: &str,
    account_root_pubkey_b64: &str,
) -> Result<String, JsError> {
    let actor: Actor = parse_json(actor_json, "Actor")?;
    let request_hash = decode_b64_32(request_hash_b64, "request_hash_b64")?;
    let root_bytes = decode_b64_32(account_root_pubkey_b64, "account_root_pubkey_b64")?;
    let account_root = PublicKey::from_bytes(&root_bytes).map_err(|e| {
        JsError::new(&format!(
            "account_root_pubkey_b64 is not a valid Ed25519 key: {e}"
        ))
    })?;
    let account_states = parse_account_states_json(account_states_json)?;
    let account_state_refs: Vec<&str> = account_states.iter().map(String::as_str).collect();

    core_verify_actor_attestation_with_account_states(
        &actor,
        account_id,
        request_id,
        &request_hash,
        &account_state_refs,
        &account_root,
    )
    .map_err(|e| JsError::new(&format!("verify_actor_attestation failed: {e}")))?;

    // Only after verification succeeds do we format the (now-trusted) origin string.
    let origin = core_verified_origin_string(&actor);
    to_json(
        &OriginResult {
            verified: true,
            actor_id: actor.id,
            actor_kind: actor.kind,
            origin,
        },
        "OriginResult",
    )
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

/// Maps a core command-builder refusal to the value `action_from_command` /
/// `action_from_powershell_command` throw: a JS `Error` with the message
/// `"{function} failed: {error}"` and an own property `kind`, the core's stable
/// [`CommandError::code`](allw_core::CommandError::code) (`invalid_shell_syntax`, `no_command`,
/// `no_program`, `empty_program`). Callers classify on `kind`, never on the message; every refusal
/// is a deny (fail-closed). A thrown value without a `kind` is still a refusal.
fn command_failure(function: &str, error: &CommandError) -> JsValue {
    let thrown = js_sys::Error::new(&format!("{function} failed: {error}"));
    // Setting an own property on a fresh `Error` cannot fail; if it ever did, the error would lack
    // `kind` and the caller would still deny.
    let _ = js_sys::Reflect::set(&thrown, &"kind".into(), &error.code().into());
    thrown.into()
}

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
/// Throws (see `command_failure`: an `Error` with a `kind`) if the command string has unmatched
/// quotes / invalid shell syntax (`kind: "invalid_shell_syntax"`), or runs no program: blank
/// (`no_command`), only assignments or operators (`no_program`), or an empty program word
/// (`empty_program`), #376. Fail-closed at the boundary: the caller denies rather than guessing at
/// a malformed command or asking a human to approve nothing.
#[wasm_bindgen]
pub fn action_from_command(command_line: &str, cwd: Option<String>) -> Result<String, JsValue> {
    let ctx = CommandContext { cwd };
    let record = core_action_from_command(command_line, &ctx)
        .map_err(|e| command_failure("action_from_command", &e))?;
    Ok(to_json(&record, "ActionRecord")?)
}

/// Builds an [`ActionRecord`](allw_core::ActionRecord) from a raw **PowerShell** command line,
/// returning it as JSON (the `command` surface, for a host's PowerShell tool). `raw` is the exact
/// line; argv is always a plain whitespace split of it; risk is at least `Medium`, or at least
/// `High` for a compound, escaped or dynamic-execution line. See
/// [`allw_core::powershell`](allw_core::powershell) for the rules.
///
/// No PowerShell line is refused for its syntax, so a valid PowerShell command is never denied for
/// its quoting.
///
/// # Errors
///
/// Throws (an `Error` with a `kind`, as [`action_from_command`]) only for a line that runs no
/// program (#376): blank (`no_command`), only separators or literal assignments (`no_program`), or
/// an empty-string program (`empty_program`).
#[wasm_bindgen]
pub fn action_from_powershell_command(
    command_line: &str,
    cwd: Option<String>,
) -> Result<String, JsValue> {
    let ctx = CommandContext { cwd };
    let record = core_action_from_powershell_command(command_line, &ctx)
        .map_err(|e| command_failure("action_from_powershell_command", &e))?;
    Ok(to_json(&record, "ActionRecord")?)
}

/// Builds an [`ActionRecord`](allw_core::ActionRecord) from a **pre-tokenized** argv, returning it
/// as JSON. This is the **command** surface for callers that already hold a canonical execution
/// plan and must bind it verbatim — an agent runtime that stores the exact `argv` it will later
/// execute (`docs/openclaw-integration.md` §5.1). Re-tokenizing such a caller's command text with
/// [`action_from_command`] risks binding a *different* token vector than the one that runs, which
/// would break the WYSIWYS guarantee that the verdict is bound to the exact action.
///
/// - `argv_json` — JSON array of the canonical argument tokens.
/// - `raw` — the original command text as the upstream gate renders it, or `undefined`/`null` when
///   the caller has none. Recorded verbatim and used (only) to extract `env_refs` names; it is
///   **never** re-tokenized.
/// - `cwd` — the working directory the command is bound to, or `undefined`/`null` when unbound.
///
/// # Errors
///
/// Throws if `argv_json` is not a JSON array of strings (a plain `Error`, no `kind`) — fail-closed:
/// the caller denies rather than submitting a record built from an unparseable plan. Also throws,
/// with a `kind` as [`action_from_command`], for an argv with no program (#376): empty
/// (`no_command`), an empty program word (`empty_program`), or only assignments (`no_program`).
#[wasm_bindgen]
pub fn action_from_argv(
    argv_json: &str,
    raw: Option<String>,
    cwd: Option<String>,
) -> Result<String, JsValue> {
    let argv: Vec<String> = parse_json(argv_json, "command argv")?;
    let ctx = CommandContext { cwd };
    let record = core_action_from_argv(&argv, raw.as_deref(), &ctx)
        .map_err(|e| command_failure("action_from_argv", &e))?;
    Ok(to_json(&record, "ActionRecord")?)
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

/// Builds an [`ActionRecord`](allw_core::ActionRecord) for an agent-runtime/plugin-owned tool
/// call, returning it as JSON. This is the **agent_tool_call** surface
/// (`docs/openclaw-integration.md` §5.2, `docs/policy-seam.md` §Structure vs. data in the
/// ActionRecord): a tool call gated by the harness rather than served by an MCP server. It reuses
/// the same `(server, tool, params)` function-identity substrate as `mcp_tool_call` — `server`
/// holds the gating provider id (e.g. a plugin id), not an MCP server name — but is tagged with a
/// **distinct surface** so an `mcp_tool_call`-scoped policy rule never matches it, even when the
/// `(server, tool)` pair is identical.
///
/// - `server` — the gating provider identity (e.g. `"openclaw"`).
/// - `tool` — the tool name within that provider (e.g. `"deploy_service"`).
/// - `params_json` — the tool-call parameters as a JSON value, or `undefined`/`null` when the
///   caller has no structured parameters to offer (e.g. OpenClaw plugin permission requests
///   expose only prose to the reviewer — do not synthesize a params value in that case).
///
/// # Errors
///
/// Throws if `params_json` is present but not valid JSON — fail-closed: the hook denies rather
/// than submitting a record built from unparseable parameters.
#[wasm_bindgen]
pub fn action_from_agent_tool_call(
    server: &str,
    tool: &str,
    params_json: Option<String>,
) -> Result<String, JsError> {
    let params: Option<serde_json::Value> = params_json
        .map(|json_str| parse_json(&json_str, "agent tool params"))
        .transpose()?;
    let record = core_action_from_agent_tool_call(server, tool, params);
    to_json(&record, "ActionRecord")
}

/// Builds an [`ActionRecord`](allw_core::ActionRecord) for an agent-runtime/plugin-owned tool
/// call, returning it as JSON, with an **explicit** `raw` override instead of the synthesized
/// `"<server>.<tool>(...)"` display. Use this when the caller already holds human-authored
/// reviewer prose for the action (e.g. an OpenClaw plugin permission request's
/// `description`/`detail` — `docs/openclaw-integration.md` §5.2: `syntactic.raw` = `description`,
/// plus `detail` when present); use [`action_from_agent_tool_call`] when no such prose exists.
///
/// `raw` is bound **verbatim** — it is never re-derived from `params_json`.
///
/// - `server` — the gating provider identity (e.g. `"openclaw"`).
/// - `tool` — the tool name within that provider (e.g. `"deploy_service"`).
/// - `raw` — the reviewer-facing prose to bind verbatim as `syntactic.raw`.
/// - `params_json` — the tool-call parameters as a JSON value, or `undefined`/`null` when the
///   caller has no structured parameters to offer.
///
/// # Errors
///
/// Throws if `params_json` is present but not valid JSON — fail-closed: the hook denies rather
/// than submitting a record built from unparseable parameters.
#[wasm_bindgen]
pub fn action_from_agent_tool_call_with_raw(
    server: &str,
    tool: &str,
    raw: &str,
    params_json: Option<String>,
) -> Result<String, JsError> {
    let params: Option<serde_json::Value> = params_json
        .map(|json_str| parse_json(&json_str, "agent tool params"))
        .transpose()?;
    let record = core_action_from_agent_tool_call_with_raw(server, tool, raw, params);
    to_json(&record, "ActionRecord")
}

/// Builds an [`ActionRecord`](allw_core::ActionRecord) for a file edit, returning it as JSON.
/// This is the **file_edit** surface (`docs/policy-seam.md` §The three tiers, T1): the core
/// preserves the operation kind, target paths, compact diff summary, and a hash of the full edit
/// bytes. The hook calls this for Codex `apply_patch` and Claude Code `Edit`/`Write`/`MultiEdit`
/// tool calls so file writes cannot bypass human approval by avoiding the command surface.
///
/// - `operation` — the edit operation kind, e.g. `"patch"`, `"edit"`, `"write"`, `"multi_edit"`.
/// - `paths_json` — JSON array of target path strings.
/// - `diff_summary` — one-line human-facing summary of the change.
/// - `diff_bytes` — full edit payload whose SHA-256 hash is bound into the record.
///
/// # Errors
///
/// Throws if `paths_json` is not a JSON array of strings or if it is empty — fail-closed: a file
/// edit with unknown targets is denied rather than summarized generically.
#[wasm_bindgen]
pub fn action_from_file_edit(
    operation: &str,
    paths_json: &str,
    diff_summary: &str,
    diff_bytes: &str,
) -> Result<String, JsError> {
    let paths: Vec<String> = parse_json(paths_json, "file edit paths")?;
    if paths.is_empty() {
        return Err(JsError::new("file edit paths must not be empty"));
    }
    let record = core_action_from_file_edit(operation, &paths, diff_summary, diff_bytes);
    to_json(&record, "ActionRecord")
}

// ── Small-order X25519 keys (#248) ────────────────────────────────────────────────

/// Returns the core's static denylist of small-order X25519 public keys as a JSON array of
/// base64url-unpadded strings ([`X25519_SMALL_ORDER_POINTS`](allw_core::X25519_SMALL_ORDER_POINTS)).
/// A key matching an entry (ignoring bit 255) can never be a valid encryption target; components
/// that register device keys can reject it up front.
#[wasm_bindgen]
pub fn x25519_small_order_points() -> Result<String, JsError> {
    let encoded: Vec<String> = X25519_SMALL_ORDER_POINTS
        .iter()
        .map(|p| URL_SAFE_NO_PAD.encode(p))
        .collect();
    to_json(&encoded, "small-order point list")
}

/// Whether `public_key_b64` (a base64url-unpadded 32-byte X25519 public key) is a small-order
/// point that [`encrypt_context`] would refuse.
///
/// # Errors
///
/// Throws if `public_key_b64` is not 32 base64url bytes.
#[wasm_bindgen]
pub fn is_small_order_x25519_public_key(public_key_b64: &str) -> Result<bool, JsError> {
    let bytes = decode_b64_32(public_key_b64, "public_key_b64")?;
    Ok(core_is_small_order_x25519_public_key(&bytes))
}

// ── Display safety (#246) ─────────────────────────────────────────────────────────

/// Builds the escaped display model for an approval context — the only form in which approver
/// surfaces may show the context's untrusted text to a human.
///
/// `context_json` is a JSON [`ApprovalContext`](allw_core::ApprovalContext) (the decrypted
/// plaintext). Returns a JSON [`DisplayModel`](allw_core::DisplayModel): every string escaped with
/// the core notation (`\x1b`, `\r`, `⟨U+202E⟩`, …) plus `has_hidden_or_control_chars`. Display
/// only — the request hash is still computed over `context_json` itself.
///
/// # Errors
///
/// Throws if `context_json` is not a valid `ApprovalContext`.
#[wasm_bindgen]
pub fn display_model(context_json: &str) -> Result<String, JsError> {
    let ctx: ApprovalContext = parse_json(context_json, "ApprovalContext")?;
    to_json(&core_display_model(&ctx), "DisplayModel")
}

/// Escapes one untrusted string for display, using the same notation as [`display_model`]. For
/// untrusted text outside the context (relay-supplied request ids, relay error strings, log lines).
#[wasm_bindgen]
pub fn escape_for_display(text: &str) -> String {
    core_escape_for_display(text)
}
