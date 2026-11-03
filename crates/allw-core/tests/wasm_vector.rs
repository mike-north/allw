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
//! It also carries the self-certifying account-id vector (`account_id_for_root` of the approver
//! root) and a root-signed pairing-start authorization, so the WASM surface proves it derives the
//! same id and signs/verifies the same `allw-pairing-start+jws` bytes as the core.
//!
//! And a root-signed account-state set with the recipients the selection rules allow, so the WASM
//! `select_recipients` is checked against the same hand-derived answer as the core.
//!
//! @see docs/contract.md §Wire encoding, §Verification checklist
//! @see docs/enrollment.md §Model (account id derivation, pairing-start authorization)
//! @see crates/allw-core/src/hash.rs (FROZEN_HASH_HEX — the same value)
//! @see crates/allw-core/src/recipients.rs (the recipient-selection rules)

use std::path::PathBuf;

use allw_core::{
    account_id_for_root, action_from_agent_tool_call, compute_request_hash, issue_device_cert,
    select_recipients, sign_account_state, sign_pairing_start_authorization, sign_verdict,
    AccountState, AccountStateDevice, AccountStateRevocation, AccountStateRevocationKind,
    ActionRecord, Actor, ApprovalContext, ApprovalRequest, Approver, Constraints, Decision,
    PublicKey, Recipient, Risk, SigningKeyPair, Surface, SyntacticSubstrate, UnsignedVerdict,
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

// Pairing-start authorization window (2-minute lifetime) and a verifier time inside it.
const TS_PAIRING_ISSUED: i64 = 1_700_000_000_000;
const TS_PAIRING_EXPIRES: i64 = 1_700_000_120_000;
const PAIRING_NOW_MS: i64 = 1_700_000_001_000;
const PAIRING_JTI: &str = "jti_wasm_vector_01";

/// X25519 encryption keys of the recipient-vector devices (any 32 bytes serve as test keys).
const RECIPIENT_KEY_A: [u8; 32] = [0xA1; 32];
const RECIPIENT_KEY_B: [u8; 32] = [0xB2; 32];
const RECIPIENT_KEY_C: [u8; 32] = [0xC3; 32];
const RECIPIENT_KEY_D: [u8; 32] = [0xD4; 32];
const RECIPIENT_KEY_E: [u8; 32] = [0xE5; 32];
const RECIPIENT_REVOKED_AT: i64 = 1_700_000_500_000;

/// Account id derived from the approver root (seed `[0x11; 32]`), computed independently of the
/// core: `SHA-256("allw/account-id/v1" || 0x00 || root_pubkey)` via `shasum -a 256`, then
/// base64url-unpadded. Matches `account::tests::FROZEN_ACCOUNT_ID_0X11`.
const FROZEN_ACCOUNT_ID: &str = "hUes5Gso3s5hHMmZjDI-P0tyaD905KSl1B97nsp2VIo";

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

    /// JSON `ApprovalContext` whose `action` is an `agent_tool_call` record (issue #194) — same
    /// shape as `context_json` but for the new surface, so the WASM/TS surface can prove it
    /// computes byte-identical `request_hash` bytes for `agent_tool_call` too, not only
    /// `command`. Built via [`action_from_agent_tool_call`] so the fixture exercises the real
    /// builder, not a hand-assembled record.
    agent_tool_call_context_json: String,
    /// Expected `request_hash` for `agent_tool_call_context_json` (bound to the same
    /// `expires_at` above), as base64url-unpadded — the WASM `compute_request_hash` return shape.
    agent_tool_call_expected_request_hash_b64: String,

    /// Self-certifying account id derived from `approver_root_pubkey_b64` (`account_id_for_root`).
    expected_account_id_for_root: String,
    /// `allw-pairing-start+jws` signed by the approver root for the derived account id.
    pairing_start_authorization: String,
    /// The authorization's signed `issued_at` / `expires_at` (Unix ms) and `jti`.
    pairing_start_issued_at: i64,
    pairing_start_expires_at: i64,
    pairing_start_jti: String,
    /// A verifier time inside the authorization's validity window.
    pairing_start_now_ms: i64,

    /// JSON array of root-signed account-state JWS for `expected_account_id_for_root` (see
    /// [`recipient_account_states`]): a stale sequence-1 document plus two sequence-2 siblings.
    recipient_account_states_json: String,
    /// JSON array of `{ device_id, encryption_pubkey }` the selection rules allow for that set,
    /// written from the rules (not captured from `select_recipients`).
    expected_recipients_json: String,
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

/// An `agent_tool_call` counterpart to [`make_minimal_context`] (issue #194) — same summary,
/// actor, risk, constraints; only `action` differs (built via [`action_from_agent_tool_call`]
/// instead of the hand-assembled command record) so the two fixtures isolate the surface
/// difference precisely.
fn make_agent_tool_call_context() -> ApprovalContext {
    ApprovalContext {
        action: action_from_agent_tool_call("openclaw", "deploy_service", None),
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

fn recipient_device(id: &str, key: [u8; 32], status: &str) -> AccountStateDevice {
    AccountStateDevice {
        device_id: id.to_string(),
        encryption_pubkey: key,
        signing_pubkey: [0x01; 32],
        status: status.to_string(),
        cert_expires_at: None,
    }
}

/// The recipient vector's account-state set, exercising each selection rule once:
/// - sequence 1 (stale): lists `dev-old`, which must not be selected;
/// - sequence 2: `dev-a` and `dev-d` active; `dev-b` active but revoked; `dev-c` not active;
///   `dev-e` active in only one of the two sequence-2 siblings (a conflict, so excluded).
fn recipient_account_states(root: &SigningKeyPair) -> Vec<String> {
    let account_id = account_id_for_root(&root.public_key());
    let state = |sequence: u64, devices: Vec<AccountStateDevice>, revoked: &[&str]| AccountState {
        v: 1,
        account_id: account_id.clone(),
        sequence,
        current_root: root.public_key().to_bytes(),
        previous_roots: vec![],
        devices,
        actors: vec![],
        revocations: revoked
            .iter()
            .map(|id| AccountStateRevocation {
                kind: AccountStateRevocationKind::Device,
                id: (*id).to_string(),
                revoked_at: RECIPIENT_REVOKED_AT,
                reason: None,
            })
            .collect(),
    };
    let stale = state(
        1,
        vec![
            recipient_device("dev-a", RECIPIENT_KEY_A, "active"),
            recipient_device("dev-old", RECIPIENT_KEY_E, "active"),
        ],
        &[],
    );
    let current = state(
        2,
        vec![
            recipient_device("dev-a", RECIPIENT_KEY_A, "active"),
            recipient_device("dev-b", RECIPIENT_KEY_B, "active"),
            recipient_device("dev-c", RECIPIENT_KEY_C, "revoked"),
            recipient_device("dev-d", RECIPIENT_KEY_D, "active"),
            recipient_device("dev-e", RECIPIENT_KEY_E, "active"),
        ],
        &["dev-b"],
    );
    let sibling = state(
        2,
        vec![
            recipient_device("dev-a", RECIPIENT_KEY_A, "active"),
            recipient_device("dev-b", RECIPIENT_KEY_B, "active"),
            recipient_device("dev-d", RECIPIENT_KEY_D, "active"),
        ],
        &["dev-b"],
    );
    [stale, current, sibling]
        .iter()
        .map(|s| sign_account_state(s, root))
        .collect()
}

/// The recipients the rules allow for [`recipient_account_states`]: exactly `dev-a` and `dev-d`,
/// sorted by device id.
fn expected_recipients() -> Vec<Recipient> {
    vec![
        Recipient {
            device_id: "dev-a".to_string(),
            encryption_pubkey: RECIPIENT_KEY_A,
        },
        Recipient {
            device_id: "dev-d".to_string(),
            encryption_pubkey: RECIPIENT_KEY_D,
        },
    ]
}

/// The WASM `select_recipients` wire shape for a recipient list.
fn recipients_wire_json(recipients: &[Recipient]) -> String {
    let wire: Vec<serde_json::Value> = recipients
        .iter()
        .map(|r| {
            serde_json::json!({
                "device_id": r.device_id,
                "encryption_pubkey": URL_SAFE_NO_PAD.encode(r.encryption_pubkey),
            })
        })
        .collect();
    serde_json::to_string(&wire).expect("recipients serialize")
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

    let agent_tool_call_context = make_agent_tool_call_context();
    let agent_tool_call_request_hash = compute_request_hash(&agent_tool_call_context, TS_EXPIRES);

    WasmVector {
        context_json: serde_json::to_string(&context).expect("context serializes"),
        expires_at: TS_EXPIRES,
        expected_request_hash_hex: hex,
        expected_request_hash_b64: URL_SAFE_NO_PAD.encode(request_hash),
        verdict_json: serde_json::to_string(&verdict).expect("verdict serializes"),
        request_json: serde_json::to_string(&make_request()).expect("request serializes"),
        approver_root_pubkey_b64: URL_SAFE_NO_PAD.encode(root.public_key().to_bytes()),
        now_ms: NOW_MS,
        agent_tool_call_context_json: serde_json::to_string(&agent_tool_call_context)
            .expect("agent_tool_call context serializes"),
        agent_tool_call_expected_request_hash_b64: URL_SAFE_NO_PAD
            .encode(agent_tool_call_request_hash),
        expected_account_id_for_root: account_id_for_root(&root.public_key()),
        pairing_start_authorization: sign_pairing_start_authorization(
            &root,
            TS_PAIRING_ISSUED,
            TS_PAIRING_EXPIRES,
            PAIRING_JTI,
        )
        .expect("fixture pairing-start inputs are valid"),
        pairing_start_issued_at: TS_PAIRING_ISSUED,
        pairing_start_expires_at: TS_PAIRING_EXPIRES,
        pairing_start_jti: PAIRING_JTI.to_string(),
        pairing_start_now_ms: PAIRING_NOW_MS,
        recipient_account_states_json: serde_json::to_string(&recipient_account_states(&root))
            .expect("account states serialize"),
        expected_recipients_json: recipients_wire_json(&expected_recipients()),
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

/// WYSIWYS coverage for the `agent_tool_call` surface (issue #194): re-derive the hash for
/// `agent_tool_call_context_json` independently of [`build_vector`] and assert it equals the
/// committed fixture's `agent_tool_call_expected_request_hash_b64` — the same cross-check
/// `fixture_hash_equals_frozen_vector` performs for the command surface, so a WASM/TS
/// implementation replaying the fixture proves it hashes `agent_tool_call` records identically to
/// the Rust core, not just `command` ones.
#[test]
fn agent_tool_call_fixture_hash_matches_independent_recompute() {
    let context = make_agent_tool_call_context();
    let hash = compute_request_hash(&context, TS_EXPIRES);

    let raw = std::fs::read_to_string(fixture_path()).expect("fixture must exist for this test");
    let committed: WasmVector =
        serde_json::from_str(&raw).expect("committed fixture is valid WasmVector JSON");

    assert_eq!(
        URL_SAFE_NO_PAD.encode(hash),
        committed.agent_tool_call_expected_request_hash_b64,
        "an independently recomputed agent_tool_call request_hash must match the committed fixture"
    );
}

/// The `agent_tool_call` and `command` fixtures differ only in `action.surface` /
/// `action.syntactic` — proving `surface` is actually hashed (not silently ignored) and that the
/// two surfaces produce different `request_hash` values despite sharing the same summary, actor,
/// risk, and constraints.
#[test]
fn agent_tool_call_and_command_fixtures_hash_differently() {
    let command_hash = compute_request_hash(&make_minimal_context(), TS_EXPIRES);
    let agent_tool_call_hash = compute_request_hash(&make_agent_tool_call_context(), TS_EXPIRES);

    assert_ne!(
        command_hash, agent_tool_call_hash,
        "changing action.surface (and its syntactic substrate) must change request_hash"
    );
}

/// The fixture's account id equals the independently computed frozen derivation — spec-first,
/// so the WASM surface replaying `expected_account_id_for_root` is checked against the spec value,
/// not a captured output.
#[test]
fn fixture_account_id_equals_frozen_vector() {
    let raw = std::fs::read_to_string(fixture_path()).expect("fixture must exist for this test");
    let committed: WasmVector =
        serde_json::from_str(&raw).expect("committed fixture is valid WasmVector JSON");
    assert_eq!(committed.expected_account_id_for_root, FROZEN_ACCOUNT_ID);
}

/// The core's `select_recipients` over the fixture's account-state set returns exactly the
/// recipients the rules allow (`dev-a`, `dev-d`); the node test checks the WASM surface returns
/// the fixture's `expected_recipients_json` for the same set.
#[test]
fn fixture_recipients_follow_the_selection_rules() {
    let raw = std::fs::read_to_string(fixture_path()).expect("fixture must exist for this test");
    let committed: WasmVector =
        serde_json::from_str(&raw).expect("committed fixture is valid WasmVector JSON");
    let docs: Vec<String> = serde_json::from_str(&committed.recipient_account_states_json)
        .expect("account-state array parses");
    let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
    let root_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&committed.approver_root_pubkey_b64)
        .expect("root pubkey decodes")
        .try_into()
        .expect("root pubkey is 32 bytes");
    let root = PublicKey::from_bytes(&root_bytes).expect("root pubkey is valid");

    let selected = select_recipients(&refs, &committed.expected_account_id_for_root, &root)
        .expect("fixture state yields recipients");
    assert_eq!(selected, expected_recipients());
    assert_eq!(
        committed.expected_recipients_json,
        recipients_wire_json(&selected)
    );
}
