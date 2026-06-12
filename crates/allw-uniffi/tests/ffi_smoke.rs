//! Rust-side smoke tests for the UniFFI surface.
//!
//! These pin the native binding contract before Swift/Kotlin generation is tested: the FFI layer
//! takes core JSON wire strings, returns core JSON wire strings, and keeps crypto in allw-core.
//!
//! Negative tests exercise every rejection path that real apps rely on for fail-closed behavior
//! (per ENG_TEAM_INSTRUCTIONS §14): tampered verdict, malformed JSON, wrong-length seed base64.

use allw_uniffi::{
    action_from_command_json, compute_request_hash_b64, derive_device_keys_json,
    derive_signing_pubkey_b64, issue_device_cert_json, sign_verdict_json, verify_verdict_json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

const DEVICE_SEED: [u8; 32] = [7; 32];
const ACCOUNT_SEED: [u8; 32] = [11; 32];

/// Build a complete sign→verify fixture and return (verdict_json, request_json, context_json,
/// account_root_pubkey_b64, now_ms).
fn build_signed_verdict() -> (String, String, String, String, i64) {
    let device_seed = URL_SAFE_NO_PAD.encode(DEVICE_SEED);
    let account_seed = URL_SAFE_NO_PAD.encode(ACCOUNT_SEED);

    let device_keys: serde_json::Value = serde_json::from_str(
        &derive_device_keys_json(device_seed.clone(), device_seed.clone()).unwrap(),
    )
    .unwrap();
    let device_signing_pubkey = device_keys["device_signing_pubkey_b64"].as_str().unwrap();
    let account_root_pubkey = derive_signing_pubkey_b64(account_seed.clone()).unwrap();

    let device_cert = issue_device_cert_json(
        account_seed,
        "acct-1".to_string(),
        "dev-1".to_string(),
        device_signing_pubkey.to_string(),
        1_700_000_000_000,
        4_102_444_800_000,
    )
    .unwrap();

    let action: serde_json::Value = serde_json::from_str(
        &action_from_command_json("git status".to_string(), "/repo".to_string()).unwrap(),
    )
    .unwrap();
    let context = json!({
        "action": action,
        "summary": "check repo status",
        "actor": { "id": "actor-1", "kind": "agent" },
        "risk": "low",
        "reversible": true,
        "constraints": { "allowed_decisions": ["approved", "denied"], "challenge_required": false }
    });
    let request_hash = compute_request_hash_b64(context.to_string(), 4_102_444_800_000).unwrap();

    let request = json!({
        "v": 1,
        "id": "req-1",
        "created_at": 1_700_000_000_000_i64,
        "expires_at": 4_102_444_800_000_i64,
        "approver": "acct-1",
        "context_ciphertext": "opaque-jwe"
    });
    let nonce = URL_SAFE_NO_PAD.encode([9_u8; 16]);
    let unsigned = json!({
        "v": 1,
        "request_id": "req-1",
        "request_hash": request_hash,
        "decision": "approved",
        "decided_at": 1_700_000_001_000_i64,
        "approver": { "account_id": "acct-1", "device_id": "dev-1" },
        "device_cert": device_cert
    });

    let verdict = sign_verdict_json(unsigned.to_string(), device_seed, nonce).unwrap();
    (
        verdict,
        request.to_string(),
        context.to_string(),
        account_root_pubkey,
        1_700_000_002_000,
    )
}

#[test]
fn command_action_and_request_hash_round_trip_over_json_strings() {
    let action = action_from_command_json("git status".to_string(), "/repo".to_string()).unwrap();
    let context = json!({
        "action": serde_json::from_str::<serde_json::Value>(&action).unwrap(),
        "summary": "check repo status",
        "actor": { "id": "actor-1", "kind": "agent" },
        "risk": "low",
        "reversible": true,
        "constraints": { "allowed_decisions": ["approved", "denied"], "challenge_required": false }
    });

    let hash = compute_request_hash_b64(context.to_string(), 4_102_444_800_000).unwrap();

    assert_eq!(hash.len(), 43);
}

#[test]
fn sign_and_verify_verdict_through_uniffi_json_surface() {
    let device_seed = URL_SAFE_NO_PAD.encode(DEVICE_SEED);
    let account_seed = URL_SAFE_NO_PAD.encode(ACCOUNT_SEED);
    let device_keys = serde_json::from_str::<serde_json::Value>(
        &derive_device_keys_json(device_seed.clone(), device_seed.clone()).unwrap(),
    )
    .unwrap();
    let device_signing_pubkey = device_keys["device_signing_pubkey_b64"].as_str().unwrap();
    let account_root_pubkey = derive_signing_pubkey_b64(account_seed.clone()).unwrap();
    let device_cert = issue_device_cert_json(
        account_seed.clone(),
        "acct-1".to_string(),
        "dev-1".to_string(),
        device_signing_pubkey.to_string(),
        1_700_000_000_000,
        4_102_444_800_000,
    )
    .unwrap();
    let action = serde_json::from_str::<serde_json::Value>(
        &action_from_command_json("git status".to_string(), "/repo".to_string()).unwrap(),
    )
    .unwrap();
    let context = json!({
        "action": action,
        "summary": "check repo status",
        "actor": { "id": "actor-1", "kind": "agent" },
        "risk": "low",
        "reversible": true,
        "constraints": { "allowed_decisions": ["approved", "denied"], "challenge_required": false }
    });
    let request_hash = compute_request_hash_b64(context.to_string(), 4_102_444_800_000).unwrap();
    let request = json!({
        "v": 1,
        "id": "req-1",
        "created_at": 1_700_000_000_000_i64,
        "expires_at": 4_102_444_800_000_i64,
        "approver": "acct-1",
        "context_ciphertext": "opaque-jwe"
    });
    let nonce = URL_SAFE_NO_PAD.encode([9_u8; 16]);
    let unsigned = json!({
        "v": 1,
        "request_id": "req-1",
        "request_hash": request_hash,
        "decision": "approved",
        "decided_at": 1_700_000_001_000_i64,
        "approver": { "account_id": "acct-1", "device_id": "dev-1" },
        "device_cert": device_cert
    });

    let verdict = sign_verdict_json(unsigned.to_string(), device_seed, nonce).unwrap();
    let verified = verify_verdict_json(
        verdict,
        request.to_string(),
        context.to_string(),
        account_root_pubkey,
        1_700_000_002_000,
    )
    .unwrap();

    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&verified).unwrap()["device_id"],
        "dev-1"
    );
}

// ---------------------------------------------------------------------------
// Negative tests (PM merge-blockers — ENG_TEAM_INSTRUCTIONS §14)
// ---------------------------------------------------------------------------

/// A tampered request_hash in a signed verdict must be rejected by verify_verdict_json with Err,
/// not silently accepted.  This exercises the Result→exception marshal path apps depend on for
/// fail-closed behavior.
#[test]
fn tampered_request_hash_returns_err_not_ok() {
    let (verdict_json, request_json, context_json, account_root_pubkey, now_ms) =
        build_signed_verdict();

    // Mutate the `request_hash` field inside the signed verdict JSON.
    let mut verdict: serde_json::Value = serde_json::from_str(&verdict_json).unwrap();
    let tampered_hash = URL_SAFE_NO_PAD.encode([0xde, 0xad, 0xbe, 0xef].repeat(8));
    verdict["request_hash"] = json!(tampered_hash);

    let result = verify_verdict_json(
        verdict.to_string(),
        request_json,
        context_json,
        account_root_pubkey,
        now_ms,
    );

    assert!(
        result.is_err(),
        "verify_verdict_json must return Err for a tampered request_hash; got Ok"
    );
}

/// Malformed (non-JSON) input to verify_verdict_json must return a clean Err, never panic.
/// Panics would abort the host process — apps cannot catch them and fail-closed falls apart.
#[test]
fn malformed_json_verdict_returns_clean_err_not_panic() {
    let (_, request_json, context_json, account_root_pubkey, now_ms) = build_signed_verdict();

    let result = verify_verdict_json(
        "NOT VALID JSON {{{".to_string(),
        request_json,
        context_json,
        account_root_pubkey,
        now_ms,
    );

    assert!(
        result.is_err(),
        "verify_verdict_json must return Err for malformed JSON verdict; got Ok"
    );
    // The error message must be a coherent string (not an internal panic message).
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        !err_msg.is_empty(),
        "error message should be non-empty on malformed input"
    );
}

/// A wrong-length seed (not 32 bytes when decoded) must return Err from derive_device_keys_json
/// — and from every other seed-consuming export.  Apps that receive a truncated or padded seed
/// from their keychain integration must see an explicit error, not silent key derivation from
/// wrong material.
#[test]
fn wrong_length_seed_base64_returns_err() {
    // 16 bytes of base64url — valid base64 but decodes to 16 bytes, not 32.
    let short_seed = URL_SAFE_NO_PAD.encode([0_u8; 16]);

    let result_keys = derive_device_keys_json(short_seed.clone(), short_seed.clone());
    assert!(
        result_keys.is_err(),
        "derive_device_keys_json must return Err for a 16-byte seed; got Ok"
    );

    let result_sign = derive_signing_pubkey_b64(short_seed.clone());
    assert!(
        result_sign.is_err(),
        "derive_signing_pubkey_b64 must return Err for a 16-byte seed; got Ok"
    );
}
