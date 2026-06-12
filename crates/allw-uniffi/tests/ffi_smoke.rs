//! Rust-side smoke tests for the UniFFI surface.
//!
//! These pin the native binding contract before Swift/Kotlin generation is tested: the FFI layer
//! takes core JSON wire strings, returns core JSON wire strings, and keeps crypto in allw-core.

use allw_uniffi::{
    action_from_command_json, compute_request_hash_b64, derive_device_keys_json,
    derive_signing_pubkey_b64, issue_device_cert_json, sign_verdict_json, verify_verdict_json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

const DEVICE_SEED: [u8; 32] = [7; 32];
const ACCOUNT_SEED: [u8; 32] = [11; 32];

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
