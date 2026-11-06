//! Shared removed-field behavior: Rust and WASM ignore unknown fields consistently after #406.
//! Expected outcomes follow docs/contract.md §Unknown fields and optional assertions; there is no
//! compatibility mode. Old signatures cannot verify against the new hash domain.

use std::path::PathBuf;

use allw_core::{
    decrypt_context, encrypt_context, ApprovalContext, ContextRecipient, X25519KeyPair,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Deserialize)]
struct Case {
    class: String,
    expected: String,
    set: Map<String, Value>,
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
        assert_eq!(case.expected, "accepted", "{}", case.class);
        let json = patched(&vector.base_context, &case.set);
        let context: ApprovalContext = serde_json::from_value(json)
            .unwrap_or_else(|e| panic!("{}: the patched context must parse: {e}", case.class));
        let jwe = encrypt_context(&context, &recipients, &mut rng).expect("seal to the device");
        let opened = decrypt_context(&jwe, &vector.device_id, &device);

        assert_eq!(opened.as_ref(), Ok(&context), "{}", case.class);
    }
}
