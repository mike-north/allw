//! Shared Rust/WASM vector for the small-order X25519 public-key denylist (#248).
//!
//! `tests/fixtures/x25519_small_order.json` lists, **by hand**, the seven canonical small-order
//! encodings from libsodium's `has_small_order` table (hex copied from the libsodium source;
//! base64url is the unpadded encoding of the same bytes). This test pins three things against it:
//!
//! 1. The core denylist [`X25519_SMALL_ORDER_POINTS`] is exactly the fixture list, in order.
//! 2. **The denylist matches what `encrypt_context` rejects:** every listed point, and its
//!    bit-255-set variant (X25519 ignores bit 255, RFC 7748 §5), is reported small-order by
//!    [`is_small_order_x25519_public_key`] **and** makes [`encrypt_context`] fail with
//!    [`EncryptError::LowOrderRecipientKey`] naming the device. The `not_small_order` entries
//!    (2, the base point 9, and p + 2) pass both checks.
//! 3. A scan of every 32-byte little-endian integer in `0..=256` and `p - 4 ..= p + 4` agrees: a key is
//!    on the denylist **iff** encryption to it is refused. This guards against the denylist and the
//!    ECDH contributory check drifting apart in either direction.
//!
//! The same fixture is fed through the compiled `.wasm` by
//! `packages/sdk/test/encrypt-low-order.test.mjs`, so the relay can adopt the WASM-exported
//! denylist knowing it rejects exactly what the core refuses to encrypt to.
//!
//! @see https://datatracker.ietf.org/doc/html/rfc7748#section-6.1 (all-zero shared-secret check)
//! @see https://cr.yp.to/ecdh.html#validate (the small-order points of Curve25519)
//! @see https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
//!   (`has_small_order` — the source of the fixture list)

use std::path::PathBuf;

use allw_core::{
    encrypt_context, is_small_order_x25519_public_key, ApprovalContext, ContextRecipient,
    EncryptError, X25519PublicKey, X25519_SMALL_ORDER_POINTS,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;

#[derive(Deserialize)]
struct Point {
    name: String,
    hex: String,
    b64url: String,
}

#[derive(Deserialize)]
struct Fixture {
    small_order: Vec<Point>,
    not_small_order: Vec<Point>,
}

fn fixture() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("x25519_small_order.json");
    let text = std::fs::read_to_string(&path).expect("read the x25519 small-order fixture");
    serde_json::from_str(&text).expect("parse the x25519 small-order fixture")
}

fn bytes_of(point: &Point) -> [u8; 32] {
    let from_hex: Vec<u8> = (0..point.hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&point.hex[i..i + 2], 16).expect("fixture hex"))
        .collect();
    let from_b64 = URL_SAFE_NO_PAD
        .decode(&point.b64url)
        .expect("fixture base64url");
    assert_eq!(
        from_hex, from_b64,
        "{}: hex and base64url encode the same bytes",
        point.name
    );
    from_hex.try_into().expect("fixture points are 32 bytes")
}

fn with_high_bit(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[31] |= 0x80;
    bytes
}

fn context() -> ApprovalContext {
    serde_json::from_value(serde_json::json!({
        "action": {
            "record_schema_version": 1,
            "surface": "command",
            "syntactic": { "argv": ["git", "status"], "raw": "git status" },
            "risk": "low"
        },
        "summary": "check git status",
        "actor": { "id": "machine:ci", "kind": "claude-code" },
        "risk": "low",
        "reversible": true,
        "constraints": { "allowed_decisions": ["approved", "denied"], "challenge_required": false }
    }))
    .expect("a valid ApprovalContext")
}

/// Encrypt the fixed context to a single recipient holding `key`.
fn encrypt_to(device_id: &str, key: [u8; 32]) -> Result<String, EncryptError> {
    let public_key = X25519PublicKey::from_bytes(&key);
    encrypt_context(
        &context(),
        &[ContextRecipient {
            device_id,
            public_key: &public_key,
        }],
        &mut ChaCha20Rng::seed_from_u64(248),
    )
}

#[test]
fn core_denylist_is_exactly_the_libsodium_list() {
    let listed: Vec<[u8; 32]> = fixture().small_order.iter().map(bytes_of).collect();
    assert_eq!(listed.as_slice(), &X25519_SMALL_ORDER_POINTS[..]);
}

#[test]
fn every_denylisted_point_and_its_high_bit_variant_is_refused_by_encrypt_context() {
    for point in fixture().small_order {
        let bytes = bytes_of(&point);
        for (label, key) in [("canonical", bytes), ("bit 255 set", with_high_bit(bytes))] {
            assert!(
                is_small_order_x25519_public_key(&key),
                "{} ({label}) is on the denylist",
                point.name
            );
            assert_eq!(
                encrypt_to("dev-small-order", key),
                Err(EncryptError::LowOrderRecipientKey {
                    device_id: "dev-small-order".to_string()
                }),
                "{} ({label}) is refused by encrypt_context",
                point.name
            );
        }
    }
}

#[test]
fn non_small_order_controls_pass_both_checks() {
    for point in fixture().not_small_order {
        let key = bytes_of(&point);
        assert!(
            !is_small_order_x25519_public_key(&key),
            "{} is not on the denylist",
            point.name
        );
        assert!(
            encrypt_to("dev-ok", key).is_ok(),
            "{} is accepted by encrypt_context",
            point.name
        );
    }
}

/// Little-endian 32-byte encoding of `p + delta` for p = 2^255 - 19 (`delta` small, either sign).
fn p_plus(delta: i32) -> [u8; 32] {
    // p = 0x7fff…ffed, little-endian: ed ff … ff 7f.
    let mut out = [0xffu8; 32];
    out[0] = 0xed;
    out[31] = 0x7f;
    let mut carry = delta;
    for byte in out.iter_mut() {
        let v = i32::from(*byte) + carry;
        *byte = u8::try_from(v.rem_euclid(256)).expect("rem_euclid(256) fits in a byte");
        carry = v.div_euclid(256);
    }
    out
}

#[test]
fn denylist_agrees_with_encrypt_context_across_small_and_near_p_encodings() {
    let mut candidates: Vec<[u8; 32]> = (0u16..=256)
        .map(|n| {
            let mut key = [0u8; 32];
            key[..2].copy_from_slice(&n.to_le_bytes());
            key
        })
        .collect();
    candidates.extend((-4..=4).map(p_plus));

    for key in candidates {
        let denylisted = is_small_order_x25519_public_key(&key);
        let refused = matches!(
            encrypt_to("dev-scan", key),
            Err(EncryptError::LowOrderRecipientKey { .. })
        );
        assert_eq!(
            denylisted,
            refused,
            "denylist and encrypt_context disagree on {}",
            URL_SAFE_NO_PAD.encode(key)
        );
    }
}
