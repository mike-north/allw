//! UniFFI bindings for native Swift/Kotlin apps.
//!
//! This crate is intentionally a thin shell over `allw-core`, matching the WASM crate's
//! JSON-string boundary so native apps consume the same canonical wire types as TypeScript.

use allw_core::{
    action_from_command as core_action_from_command,
    compute_request_hash as core_compute_request_hash, issue_device_cert as core_issue_device_cert,
    sign_verdict as core_sign_verdict, verify_verdict as core_verify_verdict, ApprovalContext,
    ApprovalRequest, Approver, CommandContext, Decision, InMemoryNonceStore, PublicKey,
    SigningKeyPair, UnsignedVerdict, Verdict, X25519KeyPair,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AllwFfiError {
    #[error("{details}")]
    Failure { details: String },
}

impl AllwFfiError {
    fn failure(message: impl Into<String>) -> Self {
        Self::Failure {
            details: message.into(),
        }
    }
}

#[derive(Deserialize)]
struct UnsignedVerdictJson {
    v: u32,
    request_id: String,
    request_hash: String,
    decision: Decision,
    decided_at: i64,
    approver: Approver,
    note: Option<String>,
    challenge_response: Option<String>,
    device_cert: Option<String>,
}

#[derive(Serialize)]
struct DeviceKeysJson {
    device_signing_pubkey_b64: String,
    device_encryption_pubkey_b64: String,
}

#[derive(Serialize)]
struct VerifiedVerdictJson {
    decision: Decision,
    device_id: String,
    approver: Approver,
    decided_at: i64,
    nonce_b64: String,
}

fn parse_json<T: for<'de> Deserialize<'de>>(json: &str, what: &str) -> Result<T, AllwFfiError> {
    serde_json::from_str(json)
        .map_err(|e| AllwFfiError::failure(format!("invalid {what} JSON: {e}")))
}

fn to_json<T: Serialize>(value: &T, what: &str) -> Result<String, AllwFfiError> {
    serde_json::to_string(value)
        .map_err(|e| AllwFfiError::failure(format!("failed to serialize {what}: {e}")))
}

fn decode_b64_32(value: &str, what: &str) -> Result<[u8; 32], AllwFfiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| AllwFfiError::failure(format!("{what} is not valid base64url: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| AllwFfiError::failure(format!("{what} must decode to exactly 32 bytes")))
}

/// Decode a 32-byte **secret seed** from base64url, scrubbing the copies this function owns.
///
/// Seed material (signing/encryption device seeds, the account root seed) crosses the FFI as a
/// base64 string and is decoded here into bytes that key derivation reads. Unlike [`decode_b64_32`]
/// (used for *public* values — pubkeys, request hashes), this wraps the decoded `Vec<u8>` and the
/// returned `[u8; 32]` in [`Zeroizing`] so both the heap buffer and the stack array are wiped on
/// drop (issue #90). The caller must keep the result in a `Zeroizing` binding (not copy the inner
/// `[u8; 32]` out) for the returned-seed guarantee to hold.
///
/// Scope of the guarantee: only the buffers owned here are scrubbed. The **caller-owned base64
/// `&str`** (still live after this returns) and any **scratch buffers allocated internally by the
/// base64 decoder** are outside our control and are *not* wiped. Callers holding the seed string
/// must zeroize it themselves; full end-to-end scrubbing arrives with the native key-custody story
/// (Secure Enclave / StrongBox, #23), where seeds never materialize as host strings at all.
fn decode_seed_b64_32(value: &str, what: &str) -> Result<Zeroizing<[u8; 32]>, AllwFfiError> {
    // `Zeroizing<Vec<u8>>` wipes the heap-decoded bytes when this function returns, regardless of
    // which branch (Ok/Err) is taken.
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|e| AllwFfiError::failure(format!("{what} is not valid base64url: {e}")))?,
    );
    if bytes.len() != 32 {
        return Err(AllwFfiError::failure(format!(
            "{what} must decode to exactly 32 bytes"
        )));
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn decode_b64_vec(value: &str, what: &str) -> Result<Vec<u8>, AllwFfiError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| AllwFfiError::failure(format!("{what} is not valid base64url: {e}")))
}

#[uniffi::export]
pub fn action_from_command_json(command: String, cwd: String) -> Result<String, AllwFfiError> {
    let ctx = CommandContext {
        cwd: if cwd.is_empty() { None } else { Some(cwd) },
    };
    let action = core_action_from_command(&command, &ctx)
        .map_err(|e| AllwFfiError::failure(format!("failed to build command action: {e}")))?;
    to_json(&action, "ActionRecord")
}

#[uniffi::export]
pub fn compute_request_hash_b64(
    context_json: String,
    expires_at: i64,
) -> Result<String, AllwFfiError> {
    let context: ApprovalContext = parse_json(&context_json, "ApprovalContext")?;
    Ok(URL_SAFE_NO_PAD.encode(core_compute_request_hash(&context, expires_at)))
}

/// Derive a device's public signing (Ed25519) and encryption (X25519) keys from two seeds.
///
/// **The two seeds MUST be independently random.** `device_signing_seed_b64` and
/// `device_encryption_seed_b64` key separate cryptosystems; deriving both from the same seed
/// couples the signing and encryption keypairs and is a real-enrollment defect. The smoke tests
/// (`tests/smoke.swift`, `tests/Smoke.kt`, `tests/ffi_smoke.rs`) pass one seed for both **purely for
/// brevity** — that shortcut must never be copied into device enrollment, which must draw two
/// independent 32-byte random seeds (see `docs/enrollment.md`).
///
/// Both decoded seeds are scrubbed from memory on drop ([`Zeroizing`], issue #90).
#[uniffi::export]
pub fn derive_device_keys_json(
    device_signing_seed_b64: String,
    device_encryption_seed_b64: String,
) -> Result<String, AllwFfiError> {
    let signing_seed = decode_seed_b64_32(&device_signing_seed_b64, "device_signing_seed_b64")?;
    let encryption_seed =
        decode_seed_b64_32(&device_encryption_seed_b64, "device_encryption_seed_b64")?;
    let signing_key = SigningKeyPair::from_seed(&signing_seed);
    let encryption_key = X25519KeyPair::from_seed(&encryption_seed);
    to_json(
        &DeviceKeysJson {
            device_signing_pubkey_b64: URL_SAFE_NO_PAD.encode(signing_key.public_key().to_bytes()),
            device_encryption_pubkey_b64: URL_SAFE_NO_PAD
                .encode(encryption_key.public_key().to_bytes()),
        },
        "device keys",
    )
}

#[uniffi::export]
pub fn derive_signing_pubkey_b64(signing_seed_b64: String) -> Result<String, AllwFfiError> {
    let seed = decode_seed_b64_32(&signing_seed_b64, "signing_seed_b64")?;
    Ok(URL_SAFE_NO_PAD.encode(SigningKeyPair::from_seed(&seed).public_key().to_bytes()))
}

#[uniffi::export]
pub fn issue_device_cert_json(
    account_root_seed_b64: String,
    account_id: String,
    device_id: String,
    device_pubkey_b64: String,
    issued_at: i64,
    expires_at: i64,
) -> Result<String, AllwFfiError> {
    let account_seed = decode_seed_b64_32(&account_root_seed_b64, "account_root_seed_b64")?;
    let device_pubkey_bytes = decode_b64_32(&device_pubkey_b64, "device_pubkey_b64")?;
    let account_root = SigningKeyPair::from_seed(&account_seed);
    let device_pubkey = PublicKey::from_bytes(&device_pubkey_bytes)
        .map_err(|e| AllwFfiError::failure(format!("invalid device_pubkey_b64: {e}")))?;
    Ok(core_issue_device_cert(
        &account_root,
        &account_id,
        &device_id,
        &device_pubkey,
        issued_at,
        Some(expires_at),
    ))
}

#[uniffi::export]
pub fn sign_verdict_json(
    unsigned_verdict_json: String,
    device_seed_b64: String,
    nonce_b64: String,
) -> Result<String, AllwFfiError> {
    let unsigned_json: UnsignedVerdictJson = parse_json(&unsigned_verdict_json, "UnsignedVerdict")?;
    let device_seed = decode_seed_b64_32(&device_seed_b64, "device_seed_b64")?;
    let nonce = decode_b64_vec(&nonce_b64, "nonce_b64")?;
    let request_hash = decode_b64_32(&unsigned_json.request_hash, "request_hash")?;
    let unsigned = UnsignedVerdict {
        v: unsigned_json.v,
        request_id: unsigned_json.request_id,
        request_hash,
        decision: unsigned_json.decision,
        decided_at: unsigned_json.decided_at,
        approver: unsigned_json.approver,
        note: unsigned_json.note,
        challenge_response: unsigned_json.challenge_response,
    };
    let device_key = SigningKeyPair::from_seed(&device_seed);
    let verdict = core_sign_verdict(&unsigned, &device_key, &nonce, unsigned_json.device_cert);
    to_json(&verdict, "Verdict")
}

#[uniffi::export]
pub fn verify_verdict_json(
    verdict_json: String,
    request_json: String,
    context_json: String,
    account_root_pubkey_b64: String,
    now_ms: i64,
) -> Result<String, AllwFfiError> {
    let verdict: Verdict = parse_json(&verdict_json, "Verdict")?;
    let request: ApprovalRequest = parse_json(&request_json, "ApprovalRequest")?;
    let context: ApprovalContext = parse_json(&context_json, "ApprovalContext")?;
    let account_root_bytes = decode_b64_32(&account_root_pubkey_b64, "account_root_pubkey_b64")?;
    let account_root = PublicKey::from_bytes(&account_root_bytes)
        .map_err(|e| AllwFfiError::failure(format!("invalid account_root_pubkey_b64: {e}")))?;
    let mut nonce_store = InMemoryNonceStore::new();
    let verified = core_verify_verdict(
        &verdict,
        &request,
        &context,
        &account_root,
        &mut nonce_store,
        now_ms,
    )
    .map_err(|e| AllwFfiError::failure(format!("verify_verdict failed: {e}")))?;
    to_json(
        &VerifiedVerdictJson {
            decision: verified.decision,
            device_id: verified.device_id,
            approver: verified.approver,
            decided_at: verified.decided_at,
            nonce_b64: URL_SAFE_NO_PAD.encode(verified.nonce),
        },
        "VerifiedVerdict",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid 32-byte seed decodes into a `Zeroizing<[u8; 32]>` whose bytes match the input.
    /// The return type itself is the proof the scrubbing wrapper is wired (issue #90): if the
    /// signature regressed to a bare `[u8; 32]`, the binding below would fail to type-check.
    #[test]
    fn decode_seed_b64_32_accepts_32_bytes_and_wraps_in_zeroizing() {
        let raw = [3_u8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(raw);

        let seed: Zeroizing<[u8; 32]> = decode_seed_b64_32(&encoded, "seed").unwrap();

        assert_eq!(*seed, raw, "decoded seed bytes must round-trip the input");
    }

    /// A seed that decodes to the wrong number of bytes is rejected — apps must see an explicit
    /// error, never silent key derivation from truncated/padded material. Mirrors the FFI-level
    /// negative test in `tests/ffi_smoke.rs`, but pins the helper's own boundary directly.
    #[test]
    fn decode_seed_b64_32_rejects_wrong_length() {
        let too_short = URL_SAFE_NO_PAD.encode([0_u8; 16]);
        let too_long = URL_SAFE_NO_PAD.encode([0_u8; 33]);

        assert!(
            decode_seed_b64_32(&too_short, "seed").is_err(),
            "16-byte seed must be rejected"
        );
        assert!(
            decode_seed_b64_32(&too_long, "seed").is_err(),
            "33-byte seed must be rejected"
        );
    }

    /// Non-base64url input is rejected with an error, not a panic.
    #[test]
    fn decode_seed_b64_32_rejects_invalid_base64() {
        assert!(
            decode_seed_b64_32("not valid base64 !!!", "seed").is_err(),
            "invalid base64url seed must be rejected"
        );
    }
}
