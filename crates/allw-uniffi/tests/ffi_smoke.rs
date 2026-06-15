//! Rust-side smoke tests for the UniFFI surface.
//!
//! These pin the native binding contract before Swift/Kotlin generation is tested: the FFI layer
//! takes core JSON wire strings, returns core JSON wire strings, and keeps crypto in allw-core.
//!
//! Negative tests exercise every rejection path that real apps rely on for fail-closed behavior
//! (per ENG_TEAM_INSTRUCTIONS §14): tampered verdict, malformed JSON, wrong-length seed base64.

use allw_core::{
    compute_request_hash, encrypt_context, sign_account_state, sign_actor_attestation,
    AccountState, AccountStateActor, ActionRecord, Actor, ApprovalContext, Constraints,
    ContextRecipient, Decision, Risk, SigningKeyPair, Surface, SyntacticSubstrate, X25519KeyPair,
};
use allw_uniffi::{
    action_from_command_json, compute_request_hash_b64, derive_device_keys_json,
    derive_signing_pubkey_b64, issue_device_cert_json, prepare_approval_json, sign_verdict_json,
    verify_verdict_json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
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

// ---------------------------------------------------------------------------
// prepare_approval_json — decrypt + recompute WYSIWYS hash + verify attestation
// (issue #140, parent #23). Fixtures are built with allw-core directly (the FFI
// surface does not expose encryption), then exercised over the JSON string boundary.
//
// Spec-first: assertions trace to docs/contract.md (§Invariants #1 E2EE, #4 actor
// attestation, #6 fail-closed; §WYSIWYS) and docs/enrollment.md §Account State —
// never to captured program output. All randomness is a fixed-seed ChaCha20Rng and
// all identities/seeds are constants, so every test is deterministic.
//
// @see docs/contract.md §Invariants #1/#4/#6, §WYSIWYS, §Identity & keys
// @see docs/enrollment.md §Account State, §Actor-Key Enrollment
// ---------------------------------------------------------------------------

const PREP_RNG_SEED: [u8; 32] = [0x42; 32];
const DEVICE_ENC_SEED: [u8; 32] = [0x21; 32];
const ACTOR_SEED: [u8; 32] = [0x44; 32];
const ROOT_SEED: [u8; 32] = [0x66; 32];
const WRONG_ENC_SEED: [u8; 32] = [0xEE; 32];

const PREP_DEVICE_ID: &str = "dev-prepare";
const PREP_ACCOUNT_ID: &str = "acct-prepare";
const PREP_REQUEST_ID: &str = "req-prepare-0001";
const PREP_ACTOR_ID: &str = "machine:macbook-pro";
const PREP_ACTOR_KIND: &str = "claude-code";
const PREP_EXPIRES_AT: i64 = 4_102_444_800_000;

fn prep_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed(PREP_RNG_SEED)
}

fn actor_key() -> SigningKeyPair {
    SigningKeyPair::from_seed(&ACTOR_SEED)
}

fn root_key() -> SigningKeyPair {
    SigningKeyPair::from_seed(&ROOT_SEED)
}

/// Build the canonical [`ApprovalContext`] carrying an actor attestation bound to
/// `(PREP_REQUEST_ID, request_hash)`. The attestation's request_hash is computed over THIS context
/// + PREP_EXPIRES_AT, so it binds the exact request the device recomputes.
fn make_attested_context() -> ApprovalContext {
    // First build the context WITHOUT attestation to compute the request_hash it binds to —
    // attestation is excluded from request_hash (hash.rs), so adding it later does not perturb it.
    let mut context = ApprovalContext {
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
                raw: Some("git push --force origin main".to_string()),
                operation: None,
                paths: None,
                diff_summary: None,
                diff_hash: None,
            },
            risk: Risk::Critical,
            capabilities: None,
            scope: None,
        },
        summary: "force push to main".to_string(),
        actor: Actor {
            id: PREP_ACTOR_ID.to_string(),
            kind: PREP_ACTOR_KIND.to_string(),
            attestation: None,
        },
        risk: Risk::Critical,
        reversible: false,
        constraints: Constraints {
            allowed_decisions: vec![Decision::Approved, Decision::Denied],
            challenge_required: true,
        },
        chain: None,
    };

    let request_hash = compute_request_hash(&context, PREP_EXPIRES_AT);
    context.actor.attestation = Some(sign_actor_attestation(
        PREP_ACCOUNT_ID,
        PREP_ACTOR_ID,
        PREP_ACTOR_KIND,
        PREP_REQUEST_ID,
        &request_hash,
        &actor_key(),
    ));
    context
}

/// Encrypt `context` to the prepare device under a fixed-seed RNG, returning the JWE string.
fn encrypt_to_prep_device(context: &ApprovalContext) -> String {
    let dev_pub = X25519KeyPair::from_seed(&DEVICE_ENC_SEED).public_key();
    let recipients = [ContextRecipient {
        device_id: PREP_DEVICE_ID,
        public_key: &dev_pub,
    }];
    encrypt_context(context, &recipients, &mut prep_rng())
}

/// A root-signed account-state document enrolling the real actor key as active.
fn enrolled_account_states() -> Vec<String> {
    let state = AccountState {
        v: 1,
        account_id: PREP_ACCOUNT_ID.to_string(),
        sequence: 1,
        current_root: root_key().public_key().to_bytes(),
        previous_roots: Vec::new(),
        devices: Vec::new(),
        actors: vec![AccountStateActor {
            actor_id: PREP_ACTOR_ID.to_string(),
            kind: PREP_ACTOR_KIND.to_string(),
            pubkey: actor_key().public_key().to_bytes(),
            status: "active".to_string(),
        }],
        revocations: Vec::new(),
    };
    vec![sign_account_state(&state, &root_key())]
}

fn account_root_pubkey_b64() -> String {
    URL_SAFE_NO_PAD.encode(root_key().public_key().to_bytes())
}

/// Call `prepare_approval_json` with the standard prepare device + account material.
fn call_prepare(
    jwe: String,
    device_enc_seed: [u8; 32],
    account_states: Vec<String>,
) -> Result<serde_json::Value, allw_uniffi::AllwFfiError> {
    prepare_approval_json(
        jwe,
        PREP_DEVICE_ID.to_string(),
        URL_SAFE_NO_PAD.encode(device_enc_seed),
        PREP_REQUEST_ID.to_string(),
        PREP_ACCOUNT_ID.to_string(),
        PREP_EXPIRES_AT,
        account_states,
        account_root_pubkey_b64(),
    )
    .map(|s| serde_json::from_str(&s).expect("prepare output must be valid JSON"))
}

/// Happy path: a valid envelope decrypts, the device recomputes the WYSIWYS hash, and the
/// root-anchored attestation verifies → attestation_verified = true with the correct hash + expiry.
#[test]
fn prepare_happy_path_decrypts_verifies_and_hashes() {
    let context = make_attested_context();
    let jwe = encrypt_to_prep_device(&context);
    let expected_hash = URL_SAFE_NO_PAD.encode(compute_request_hash(&context, PREP_EXPIRES_AT));

    let out = call_prepare(jwe, DEVICE_ENC_SEED, enrolled_account_states())
        .expect("a valid envelope with a root-anchored attestation must prepare");

    // The device-computed hash must equal the spec hash over the decrypted context + expires_at.
    assert_eq!(
        out["request_hash_b64"], expected_hash,
        "prepare must recompute the WYSIWYS request_hash device-side"
    );
    assert_eq!(
        out["expires_at"], PREP_EXPIRES_AT,
        "prepare must echo the envelope expires_at as the core-verified deadline"
    );
    assert_eq!(
        out["attestation_verified"], true,
        "a root-anchored, request-bound attestation must verify"
    );
    // The decrypted context round-trips: the human-shown summary is present in context_json.
    let context_json = out["context_json"]
        .as_str()
        .expect("context_json is a string");
    assert!(
        context_json.contains("force push to main"),
        "the decrypted ApprovalContext must carry the human-shown summary"
    );
}

/// The number-match challenge code is derived from the recomputed hash when the context requires
/// one, and equals the standalone `derive_number_match_challenge_b64` over the same hash (the
/// surface gets the full WYSIWYS payload from one prepare call, not a second round-trip).
#[test]
fn prepare_derives_number_match_challenge_when_required() {
    let context = make_attested_context(); // challenge_required = true
    let jwe = encrypt_to_prep_device(&context);
    let request_hash_b64 = URL_SAFE_NO_PAD.encode(compute_request_hash(&context, PREP_EXPIRES_AT));
    let expected_code =
        allw_uniffi::derive_number_match_challenge_b64(request_hash_b64).expect("derive code");

    let out = call_prepare(jwe, DEVICE_ENC_SEED, enrolled_account_states())
        .expect("a challenge-required context must prepare");

    assert_eq!(
        out["challenge_code"], expected_code,
        "prepare must derive the same challenge code as the standalone core derivation"
    );
}

/// Decrypted-but-unverifiable origin: the context decrypts authentically, but no account state
/// enrolls the actor → attestation_verified = false (NOT an error). The contract lets the surface
/// render a deny-only unverified row; only decrypt/hash failure returns Err.
#[test]
fn prepare_unverified_attestation_is_not_an_error() {
    let context = make_attested_context();
    let jwe = encrypt_to_prep_device(&context);

    // No account state at all → the actor is not root-anchored.
    let out = call_prepare(jwe, DEVICE_ENC_SEED, Vec::new())
        .expect("a decryptable envelope must prepare even when the origin is unverifiable");

    assert_eq!(
        out["attestation_verified"], false,
        "an actor absent from account state must be reported unverified, not raised as an error"
    );
    // Crucially the plaintext is still returned so the human can see (and deny-only) the request.
    let context_json = out["context_json"]
        .as_str()
        .expect("context_json is a string");
    assert!(
        context_json.contains("force push to main"),
        "the decrypted context must still be returned for a deny-only unverified render"
    );
}

/// Tampered ciphertext: flipping a byte of the JWE ciphertext fails GCM auth → Err (fail-closed,
/// no partial state). This is the "tampered context ⇒ deny" acceptance case.
#[test]
fn prepare_tampered_ciphertext_returns_err() {
    let context = make_attested_context();
    let jwe = encrypt_to_prep_device(&context);

    let mut val: serde_json::Value = serde_json::from_str(&jwe).unwrap();
    let ct = val["ciphertext"].as_str().unwrap();
    let mut bytes = URL_SAFE_NO_PAD.decode(ct).unwrap();
    bytes[0] ^= 0x01;
    val["ciphertext"] = json!(URL_SAFE_NO_PAD.encode(&bytes));
    let tampered = serde_json::to_string(&val).unwrap();

    let result = call_prepare(tampered, DEVICE_ENC_SEED, enrolled_account_states());
    assert!(
        result.is_err(),
        "a tampered ciphertext must fail GCM auth and return Err, never a partial prepared state"
    );
}

/// Wrong device key: a device whose encryption seed does not match the recipient cannot derive the
/// CEK → Err (fail-closed). A wrong key must never yield a prepared payload.
#[test]
fn prepare_wrong_device_key_returns_err() {
    let context = make_attested_context();
    let jwe = encrypt_to_prep_device(&context);

    let result = call_prepare(jwe, WRONG_ENC_SEED, enrolled_account_states());
    assert!(
        result.is_err(),
        "a wrong device encryption key must fail decryption and return Err"
    );
}

/// Malformed JWE input: non-JWE JSON returns a clean Err (a coherent message), never a panic —
/// a panic would abort the host process and break fail-closed handling.
#[test]
fn prepare_malformed_jwe_returns_clean_err_not_panic() {
    let result = call_prepare(
        "NOT A JWE {{{".to_string(),
        DEVICE_ENC_SEED,
        enrolled_account_states(),
    );
    let err = result.expect_err("malformed JWE input must return Err");
    assert!(
        !format!("{err}").is_empty(),
        "the error message must be a coherent non-empty string, not an internal panic"
    );
}

/// Wrong-length device encryption seed: a 16-byte seed is rejected before any crypto → Err.
#[test]
fn prepare_wrong_length_seed_returns_err() {
    let context = make_attested_context();
    let jwe = encrypt_to_prep_device(&context);

    let result = prepare_approval_json(
        jwe,
        PREP_DEVICE_ID.to_string(),
        URL_SAFE_NO_PAD.encode([0u8; 16]), // 16 bytes, not 32
        PREP_REQUEST_ID.to_string(),
        PREP_ACCOUNT_ID.to_string(),
        PREP_EXPIRES_AT,
        enrolled_account_states(),
        account_root_pubkey_b64(),
    );
    assert!(
        result.is_err(),
        "a 16-byte device encryption seed must be rejected with Err"
    );
}

/// Cross-request lift: an attestation legitimately bound to a DIFFERENT request_id (the device
/// passes a mismatched request_id) must report unverified — the no-swap protection surfaces as a
/// false, fail-closed result rather than a spuriously-verified origin.
#[test]
fn prepare_attestation_bound_to_other_request_is_unverified() {
    let context = make_attested_context();
    let jwe = encrypt_to_prep_device(&context);

    // Same envelope, but the device verifies against a different request_id than the one the
    // attestation was signed over.
    let out = prepare_approval_json(
        jwe,
        PREP_DEVICE_ID.to_string(),
        URL_SAFE_NO_PAD.encode(DEVICE_ENC_SEED),
        "req-some-other-id".to_string(),
        PREP_ACCOUNT_ID.to_string(),
        PREP_EXPIRES_AT,
        enrolled_account_states(),
        account_root_pubkey_b64(),
    )
    .map(|s| serde_json::from_str::<serde_json::Value>(&s).unwrap())
    .expect("decryption still succeeds; only the origin is unverifiable");

    assert_eq!(
        out["attestation_verified"], false,
        "an attestation bound to a different request_id must not verify (cross-request no-swap)"
    );
}
