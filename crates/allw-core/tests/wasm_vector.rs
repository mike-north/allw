//! Shared cross-platform test vector for the WASM bindings (issue #9).
//!
//! This integration test owns a **single committed fixture**
//! (`tests/fixtures/wasm_vector.json`) that both the Rust core and the WASM/TS surface assert
//! against, so the two implementations can never drift: the Rust side verifies the fixture is
//! current (this file), and the node test (`packages/sdk/test/wasm.test.mjs`) feeds the same
//! fixture through the compiled `.wasm`.
//!
//! The fixture carries:
//! - the `ApprovalContext` (byte-identical to the `hash::tests::make_minimal_context` fixture) and
//!   its bound `expires_at`,
//! - the expected `request_hash` (hex **and** base64url-unpadded) — the hex equals the core's
//!   `request-hash/v2` frozen vector,
//! - a known-good signed `Verdict`, its envelope `ApprovalRequest`, the human-shown
//!   `ApprovalContext` (again, as the verifier consumes it), the approver **account-root** Ed25519
//!   public key (base64url-unpadded), and a `now_ms` inside the decision window.
//!
//! # Regenerating
//!
//! The fixture is reproducible from fixed seeds. To regenerate after an intentional change:
//!
//! ```sh
//! REGEN_WASM_VECTOR=1 cargo test -p allw-core --test wasm_vector
//! ```
//!
//! Then re-run without the env var; the guard test must pass. Spec-first: the expected hash is the
//! frozen `request-hash/v2` vector, not a captured snapshot — if a code change alters it, that is a
//! deliberate `DOMAIN_TAG` bump, mirrored here and in `hash.rs`.
//!
//! @see docs/contract.md §Wire encoding, §Verification checklist
//! @see crates/allw-core/src/hash.rs (FROZEN_HASH_HEX — the same value)

use std::path::PathBuf;

use allw_core::{
    compute_request_hash, issue_device_cert, sign_verdict, ActionRecord, Actor, ApprovalContext,
    ApprovalRequest, Approver, Constraints, Decision, Risk, SigningKeyPair, Surface,
    SyntacticSubstrate, UnsignedVerdict,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

// ── Fixed seeds / identities / timestamps (never rand / SystemTime) ───────────────
const ROOT_SEED: [u8; 32] = [0x11u8; 32];
const DEVICE_SEED: [u8; 32] = [0x22u8; 32];

const ACCOUNT_ID: &str = "acc_wasm_vector_01";
const DEVICE_ID: &str = "dev_wasm_vector_01";
const REQUEST_ID: &str = "req_wasm_vector_01";

// Bound expires_at — MUST equal the `expires_at` used by hash::tests so the request_hash matches
// the frozen `request-hash/v2` vector. 2023-11-14T23:13:20Z.
const TS_EXPIRES: i64 = 1_700_003_600_000;
// created_at < decided_at < expires_at; now_ms inside the window.
const TS_CREATED: i64 = 1_700_000_000_000;
const TS_DECIDED: i64 = 1_700_001_000_000;
const NOW_MS: i64 = 1_700_001_500_000;

// Fixed anti-replay nonce (deterministic fixture).
const NONCE: &[u8] = &[0xA1, 0xB2, 0xC3, 0xD4];

// ── The committed fixture shape ───────────────────────────────────────────────────

/// The on-disk fixture. All JSON-typed members are serialized contract wire types (as compact
/// JSON strings), so the node test can pass them straight into the WASM functions.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct WasmVector {
    /// JSON `ApprovalContext` — byte-identical to `hash::tests::make_minimal_context`.
    context_json: String,
    /// The bound deadline (Unix ms) the `request_hash` covers.
    expires_at: i64,
    /// Expected `request_hash` as lowercase hex (equals `hash.rs` FROZEN_HASH_HEX).
    expected_request_hash_hex: String,
    /// Expected `request_hash` as base64url-unpadded (the WASM `compute_request_hash` return shape).
    expected_request_hash_b64: String,
    /// JSON `Verdict` — a known-good, signed, approved verdict bound to the context above.
    verdict_json: String,
    /// JSON `ApprovalRequest` envelope this verdict answers.
    request_json: String,
    /// Approver **account-root** Ed25519 public key, base64url-unpadded (the verify trust anchor).
    approver_root_pubkey_b64: String,
    /// A `now_ms` inside `[created_at, expires_at]` so the fixture verdict verifies.
    now_ms: i64,
}

// ── Builders (mirror hash::tests::make_minimal_context exactly) ───────────────────

/// The minimal action — `bin` + `raw` only, matching the hash-vector fixture so the computed
/// `request_hash` equals the frozen `request-hash/v2` value.
fn make_minimal_context() -> ApprovalContext {
    ApprovalContext {
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
                raw: Some("git push".to_string()),
                operation: None,
                paths: None,
                diff_summary: None,
                diff_hash: None,
            },
            risk: Risk::High,
            capabilities: None,
            scope: None,
        },
        summary: "push to main".to_string(),
        actor: Actor {
            id: "machine:x".to_string(),
            kind: "claude-code".to_string(),
            attestation: None,
        },
        risk: Risk::High,
        reversible: false,
        constraints: Constraints {
            allowed_decisions: vec![Decision::Approved, Decision::Denied],
            challenge_required: false,
        },
        chain: None,
    }
}

fn make_request() -> ApprovalRequest {
    ApprovalRequest {
        v: 1,
        id: REQUEST_ID.to_string(),
        created_at: TS_CREATED,
        expires_at: TS_EXPIRES,
        approver: ACCOUNT_ID.to_string(),
        context_ciphertext: None,
    }
}

/// Builds the full vector deterministically from the fixed seeds. Pure — no IO, no RNG.
fn build_vector() -> WasmVector {
    let context = make_minimal_context();
    let request_hash = compute_request_hash(&context, TS_EXPIRES);
    let hex = request_hash
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let root = SigningKeyPair::from_seed(&ROOT_SEED);
    let device = SigningKeyPair::from_seed(&DEVICE_SEED);

    // Device cert: account root certifies the device key (no expiry).
    let cert = issue_device_cert(
        &root,
        ACCOUNT_ID,
        DEVICE_ID,
        &device.public_key(),
        TS_CREATED,
        None,
    );

    let unsigned = UnsignedVerdict {
        v: 1,
        request_id: REQUEST_ID.to_string(),
        request_hash,
        decision: Decision::Approved,
        decided_at: TS_DECIDED,
        approver: Approver {
            account_id: ACCOUNT_ID.to_string(),
            device_id: DEVICE_ID.to_string(),
        },
        note: None,
        challenge_response: None,
    };
    let verdict = sign_verdict(&unsigned, &device, NONCE, Some(cert));

    WasmVector {
        context_json: serde_json::to_string(&context).expect("context serializes"),
        expires_at: TS_EXPIRES,
        expected_request_hash_hex: hex,
        expected_request_hash_b64: URL_SAFE_NO_PAD.encode(request_hash),
        verdict_json: serde_json::to_string(&verdict).expect("verdict serializes"),
        request_json: serde_json::to_string(&make_request()).expect("request serializes"),
        approver_root_pubkey_b64: URL_SAFE_NO_PAD.encode(root.public_key().to_bytes()),
        now_ms: NOW_MS,
    }
}

fn fixture_path() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/allw-core; the fixture lives under tests/fixtures.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("wasm_vector.json")
}

// ── The guard test (and regenerator) ──────────────────────────────────────────────

/// Asserts the committed fixture is current: it must byte-match a freshly built vector, and its
/// expected hash must equal the frozen `request-hash/v2` vector. When `REGEN_WASM_VECTOR=1`, it
/// (re)writes the fixture instead — the reproducible-build path.
#[test]
fn committed_fixture_is_current() {
    let fresh = build_vector();
    let path = fixture_path();

    if std::env::var_os("REGEN_WASM_VECTOR").is_some() {
        let pretty = serde_json::to_string_pretty(&fresh).expect("vector serializes");
        std::fs::write(&path, format!("{pretty}\n")).expect("write fixture");
        eprintln!("regenerated {}", path.display());
        return;
    }

    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing fixture {} ({e}); regenerate with REGEN_WASM_VECTOR=1 cargo test -p allw-core --test wasm_vector",
            path.display()
        )
    });
    let committed: WasmVector =
        serde_json::from_str(&raw).expect("committed fixture is valid WasmVector JSON");

    assert_eq!(
        committed, fresh,
        "committed wasm_vector.json is stale — regenerate with \
         REGEN_WASM_VECTOR=1 cargo test -p allw-core --test wasm_vector"
    );
}

/// Independent anchor: the fixture's expected hash equals the frozen `request-hash/v2` hex from
/// `hash.rs`. If `hash.rs` bumps `DOMAIN_TAG`, this catches the drift (and the fixture must be
/// regenerated). Spec-first — the value is the documented frozen vector, not a captured snapshot.
#[test]
fn fixture_hash_equals_frozen_vector() {
    // The same value asserted by hash::tests::frozen_cross_platform_vector.
    const FROZEN_HASH_HEX: &str =
        "809fe4763353e8b10417f118581b510ebfe52b0725d35842f391f3d0c3d47be7";

    let context = make_minimal_context();
    let hash = compute_request_hash(&context, TS_EXPIRES);
    let hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex, FROZEN_HASH_HEX,
        "fixture context must hash to the frozen request-hash/v2 vector"
    );
}
