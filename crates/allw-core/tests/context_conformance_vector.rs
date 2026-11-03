//! Shared cross-platform vector for the v1 device-side context checks (#296).
//!
//! `tests/fixtures/context_conformance_vector.json` is consumed by both this test (the Rust core)
//! and `packages/sdk/test/context-conformance-vector.test.mjs` (the compiled `.wasm`). Each case
//! seals a patched context to a fixed device and decrypts it as that device, so the vector covers
//! the device's real open path, not just the check in isolation.
//!
//! Spec-first: every expected value is written by hand from `docs/contract.md` §Device-side
//! context checks. There is no regenerate mode; a mismatch is either a bug or a deliberate rule
//! change that must be reviewed by hand.
//!
//! @see ../../../docs/contract.md
//! @see ../../../docs/policy-seam.md

use std::path::PathBuf;

use allw_core::{
    decrypt_context, encrypt_context, ApprovalContext, ContextRecipient, JweError, X25519KeyPair,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Deserialize)]
struct Case {
    class: String,
    set: Map<String, Value>,
    expected: String,
    expected_error: Option<String>,
}

#[derive(Deserialize)]
struct Vector {
    device_id: String,
    device_x25519_seed_b64: String,
    base_context: Value,
    cases: Vec<Case>,
}

fn load_vector() -> Vector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/context_conformance_vector.json");
    let raw = std::fs::read_to_string(&path).expect("read context_conformance_vector.json");
    serde_json::from_str(&raw).expect("parse context_conformance_vector.json")
}

/// Writes each `dotted.path → value` of `set` into a copy of `base`.
fn patched(base: &Value, set: &Map<String, Value>) -> Value {
    let mut context = base.clone();
    for (path, value) in set {
        let mut target = &mut context;
        let mut keys = path.split('.').peekable();
        while let Some(key) = keys.next() {
            if keys.peek().is_none() {
                target[key] = value.clone();
            } else {
                target = &mut target[key];
            }
        }
    }
    context
}

#[test]
fn every_case_in_the_shared_vector_is_accepted_or_refused_as_specified() {
    let vector = load_vector();
    assert!(vector.cases.len() >= 10);

    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&vector.device_x25519_seed_b64)
        .expect("seed is base64url")
        .try_into()
        .expect("seed is 32 bytes");
    let device = X25519KeyPair::from_seed(&seed);
    let public_key = device.public_key();
    let recipients = [ContextRecipient {
        device_id: &vector.device_id,
        public_key: &public_key,
    }];
    let mut rng = ChaCha20Rng::seed_from_u64(296);

    for case in &vector.cases {
        let json = patched(&vector.base_context, &case.set);
        let context: ApprovalContext = serde_json::from_value(json)
            .unwrap_or_else(|e| panic!("{}: the patched context must parse: {e}", case.class));
        let jwe = encrypt_context(&context, &recipients, &mut rng).expect("seal to the device");
        let opened = decrypt_context(&jwe, &vector.device_id, &device);

        match case.expected.as_str() {
            "accepted" => {
                assert_eq!(opened.as_ref(), Ok(&context), "{}", case.class);
                assert_eq!(context.check_v1_conformance(), Ok(()), "{}", case.class);
            }
            "refused" => {
                let expected = case
                    .expected_error
                    .as_deref()
                    .unwrap_or_else(|| panic!("{}: a refusal names its error", case.class));
                let violation = context
                    .check_v1_conformance()
                    .expect_err(&format!("{} must be refused", case.class));
                assert_eq!(violation.to_string(), expected, "{}", case.class);
                assert_eq!(
                    opened,
                    Err(JweError::ContractViolation(violation)),
                    "{}: the device's open path refuses it",
                    case.class
                );
            }
            other => panic!("{}: unknown expectation {other:?}", case.class),
        }
    }
}
