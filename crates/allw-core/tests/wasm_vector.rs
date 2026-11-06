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
//!   `request-hash/v4` frozen vector,
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
//! frozen `request-hash/v4` vector, not a captured snapshot — if a code change alters it, that is a
//! deliberate `DOMAIN_TAG` bump, mirrored here and in `hash.rs`.
//!
//! It also carries the self-certifying account-id vector (`account_id_for_root` of the approver
//! root) and a root-signed pairing-start authorization, so the WASM surface proves it derives the
//! same id and signs/verifies the same `allw-pairing-start+jws` bytes as the core.
//!
//! And a root-signed account-state set with the recipients the selection rules allow, so the WASM
//! `select_recipients` is checked against the same hand-derived answer as the core.
//!
//! And the verified-non-approval cases (#311): genuinely signed `denied` / `expired` / `aborted`
//! verdicts, which must verify to `NotApproved` with the **signed** decision, and forged verdicts
//! whose outer `decision` was rewritten and whose fields echo the old message marker, which must
//! never classify as a verified non-approval. The WASM side checks the structured
//! `kind: "not_approved"` error for each.
//!
//! And the verdict-provenance cases (#245): verdicts the relay's plaintext-free
//! `verify_verdict_provenance` must accept (naming the signing device) or reject, so the relay's
//! WASM gate is checked against the same hand-written answers as the core.
//!
//! @see docs/contract.md §Wire encoding, §Verification checklist
//! @see docs/enrollment.md §Model (account id derivation, pairing-start authorization)
//! @see crates/allw-core/src/hash.rs (FROZEN_HASH_HEX — the same value)
//! @see crates/allw-core/src/recipients.rs (the recipient-selection rules)
//! @see crates/allw-core/src/sealing.rs (encrypting to the selected recipients)

use std::path::PathBuf;

use allw_core::verify_verdict_provenance;
use allw_core::{
    account_id_for_root, action_from_agent_tool_call, compute_request_hash, decrypt_context,
    issue_device_cert, seal_context_for_account_state, select_recipients, sign_account_state,
    sign_pairing_start_authorization, sign_verdict, verify_verdict, AccountState,
    AccountStateDevice, AccountStateRevocation, AccountStateRevocationKind, ActionRecord, Actor,
    ApprovalContext, ApprovalRequest, Approver, Constraints, Decision, Facts, InMemoryNonceStore,
    JweError, PublicKey, Recipient, SigningKeyPair, Surface, UnsignedVerdict, Verdict, VerifyError,
    X25519KeyPair,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

// ── Fixed seeds / identities / timestamps (never rand / SystemTime) ───────────────
const ROOT_SEED: [u8; 32] = [0x11u8; 32];
const DEVICE_SEED: [u8; 32] = [0x22u8; 32];

/// The fixture account is always the canonical identity of its signing root.
fn account_id() -> String {
    allw_core::account_id_for_root(&SigningKeyPair::from_seed(&ROOT_SEED).public_key())
}
const DEVICE_ID: &str = "dev_wasm_vector_01";
const REQUEST_ID: &str = "req_wasm_vector_01";

// Bound expires_at — MUST equal the `expires_at` used by hash::tests so the request_hash matches
// the frozen `request-hash/v4` vector. 2023-11-14T23:13:20Z.
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
const RECIPIENT_KEY_F: [u8; 32] = [0xF6; 32];
const RECIPIENT_KEY_G: [u8; 32] = [0x17; 32];
const RECIPIENT_REVOKED_AT: i64 = 1_700_000_500_000;
/// The selection time for the recipient vector: `dev-f`'s cert expires exactly now (excluded),
/// `dev-g`'s one millisecond later (still a recipient).
const RECIPIENT_NOW_MS: i64 = 1_800_000_000_000;
/// The caller's persisted floor for the recipient vector: the current sequence, so it is met.
const RECIPIENT_MIN_SEQUENCE: u64 = 2;

// Seal vector: devices whose X25519 keys come from known seeds, so both platforms can open the
// sealed context and confirm a key the root never vouched for cannot.
const SEAL_PHONE_SEED: [u8; 32] = [0x51; 32];
const SEAL_LAPTOP_SEED: [u8; 32] = [0x52; 32];
const SEAL_REVOKED_SEED: [u8; 32] = [0x53; 32];
const SEAL_INJECTED_SEED: [u8; 32] = [0x5E; 32];
const SEAL_EXPIRED_SEED: [u8; 32] = [0x54; 32];
/// The seal set's current sequence (and the floor the vector seals with).
const SEAL_SEQUENCE: u64 = 3;

/// Account id derived from the approver root (seed `[0x11; 32]`), computed independently of the
/// core: `SHA-256("allw/account-id/v1" || 0x00 || root_pubkey)` via `shasum -a 256`, then
/// base64url-unpadded. Matches `account::tests::FROZEN_ACCOUNT_ID_0X11`.
const FROZEN_ACCOUNT_ID: &str = "hUes5Gso3s5hHMmZjDI-P0tyaD905KSl1B97nsp2VIo";

// Fixed anti-replay nonce (deterministic fixture).
const NONCE: &[u8] = &[0xA1, 0xB2, 0xC3, 0xD4];

// Signed-note verdict (S15, #251): its own nonce and a note with non-ASCII text, so the vector
// proves the note is signed as exact UTF-8 on both surfaces.
const NOTED_NONCE: &[u8] = &[0xE5, 0xF6, 0x07, 0x18];
const NOTE: &str = "ok for staging only — not prod";

// Verified-non-approval verdicts (#311): one signed per non-approving decision, each with its own
// nonce.
const DENIED_NONCE: &[u8] = &[0x31, 0x32, 0x33, 0x34];
const EXPIRED_NONCE: &[u8] = &[0x41, 0x42, 0x43, 0x44];
const ABORTED_NONCE: &[u8] = &[0x51, 0x52, 0x53, 0x54];

// Verdict-provenance cases (#245): a second certified device, a key no certificate vouches for,
// another request id, and the sequence of the account state that revokes the fixture device.
const SECOND_DEVICE_SEED: [u8; 32] = [0x23u8; 32];
const SECOND_DEVICE_ID: &str = "dev_wasm_vector_02";
const UNCERTIFIED_SEED: [u8; 32] = [0x2Fu8; 32];
const OTHER_REQUEST_ID: &str = "req_wasm_vector_02";
const PROVENANCE_REVOKING_SEQUENCE: u64 = 7;

/// The text the SDK once matched in a verify error's message to decide a failure was a verified
/// non-approval (the core's `NotApproved` `Display` prefix). Forged cases echo it through fields
/// serde quotes back in its parse error, so a message-matching classifier is fooled.
const NOT_APPROVED_MESSAGE_MARKER: &str = "verified human decision was not 'approved'";

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

    /// JSON `Verdict` identical in shape to `verdict_json` but carrying an approver `note`, signed
    /// into the claims (S15, #251) with nonce `noted_verdict_nonce_b64`. The WASM `sign_verdict`
    /// must reproduce it byte-for-byte from the same seed, and rewriting the note must fail verify.
    noted_verdict_json: String,
    /// The `note` signed into `noted_verdict_json`.
    noted_verdict_note: String,
    /// The anti-replay nonce signed into `noted_verdict_json`, base64url-unpadded.
    noted_verdict_nonce_b64: String,
    /// JSON array of root-signed account-state JWS for `expected_account_id_for_root` (see
    /// [`recipient_account_states`]): a stale sequence-1 document plus two sequence-2 siblings.
    recipient_account_states_json: String,
    /// JSON array of `{ device_id, encryption_pubkey }` the selection rules allow for that set,
    /// written from the rules (not captured from `select_recipients`).
    expected_recipients_json: String,
    /// The `now_ms` the recipient selection runs at (cert-expiry boundary).
    recipient_now_ms: i64,
    /// The `min_sequence` floor the recipient selection runs with.
    recipient_min_sequence: u64,

    /// JSON array of root-signed account-state JWS for sealing (see [`seal_account_states`]).
    seal_account_states_json: String,
    /// JSON object `{ device_id: x25519_seed_b64 }` for every device in the seal set, including the
    /// revoked `old`, the `expired` one and the never-vouched `injected` (stale sequence only).
    seal_x25519_seeds_json: String,
    /// JSON array of the device ids the seal must encrypt to, written from the rules.
    seal_expected_recipient_ids_json: String,
    /// The sequence the seal must report (and the floor it runs with).
    seal_sequence: u64,

    /// Genuinely signed non-approvals, bound to `context_json` / `request_json`. Each must verify
    /// to `NotApproved` carrying `signed_decision`; WASM throws `kind: "not_approved"` with it.
    not_approved_verdicts: Vec<NotApprovedCase>,
    /// Verdicts derived from the signed `denied` one by rewriting the outer `decision` and echoing
    /// [`NOT_APPROVED_MESSAGE_MARKER`] through other fields. None may classify as a verified
    /// non-approval: each fails to parse or fails verification with some other error, and WASM
    /// throws an error with no `kind`.
    forged_not_approved_verdicts: Vec<ForgedNotApprovedCase>,

    /// The account id the provenance cases are checked for (the fixture verdicts' account).
    provenance_account_id: String,
    /// The request window (`created_at`, `expires_at`, Unix ms) the provenance cases are checked
    /// in: the relay passes the request row's values.
    provenance_created_at: i64,
    provenance_expires_at: i64,
    /// Verdict-provenance cases (#245), each checked with `approver_root_pubkey_b64`.
    provenance_cases: Vec<ProvenanceCase>,
    /// Root-signed aliases must fail on every surface; the derived account is a valid control.
    self_certifying_cases: Vec<SelfCertifyingCase>,
}

/// Signed account/certificate relationships for verdict and provenance verification.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct SelfCertifyingCase {
    account_id: String,
    verdict_json: String,
    /// None for the canonical account, otherwise the documented root-binding rejection.
    expected_error: Option<String>,
}

/// Construct genuine signatures, so failure proves account binding rather than signature rejection.
fn self_certifying_cases(
    root: &SigningKeyPair,
    unsigned: &UnsignedVerdict,
) -> Vec<SelfCertifyingCase> {
    let canonical = account_id_for_root(&root.public_key());
    let other = account_id_for_root(&SigningKeyPair::from_seed(&[0x33; 32]).public_key());
    let device = SigningKeyPair::from_seed(&DEVICE_SEED);
    [
        canonical.clone(),
        other,
        "legacy-account".into(),
        String::new(),
        format!("{canonical}="),
    ]
    .into_iter()
    .map(|account| {
        let cert = issue_device_cert(
            root,
            &account,
            DEVICE_ID,
            &device.public_key(),
            TS_CREATED,
            None,
        );
        let mut verdict = clone_unsigned(unsigned);
        verdict.approver.account_id = account.clone();
        let verdict = sign_verdict(&verdict, &device, NONCE, Some(cert)).unwrap();
        SelfCertifyingCase {
            expected_error: (account != canonical)
                .then(|| "account id does not derive from the account root key".into()),
            account_id: account,
            verdict_json: serde_json::to_string(&verdict).unwrap(),
        }
    })
    .collect()
}

/// One `verify_verdict_provenance` case.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ProvenanceCase {
    name: String,
    /// JSON `Verdict` as the device sent it.
    verdict_json: String,
    /// The request id the relay checks it for (the frame's `request_id`).
    request_id: String,
    /// JSON array of account-state JWS the relay holds (`[]` for none).
    account_states_json: String,
    /// The signing device the check reports when it passes; `None` when it must be rejected.
    /// Written from the rules, not captured from the function.
    expected_device_id: Option<String>,
    /// For a rejected case, the `Display` of the `VerifyError` the rules call for, so the WASM side
    /// can match the specific reason. `None` when the case passes.
    expected_error: Option<String>,
}

/// A signed verdict whose human decision is not `approved`.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct NotApprovedCase {
    name: String,
    /// JSON `Verdict` signed by the fixture device.
    verdict_json: String,
    /// The non-approving decision in the **signed claims** (wire form: `denied`/`expired`/`aborted`).
    signed_decision: String,
}

/// A relay-forged verdict that must be unclassified (never a verified decision).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ForgedNotApprovedCase {
    name: String,
    /// JSON for the forged verdict. Not always a valid `Verdict` (some fields have the wrong type).
    verdict_json: String,
    /// The outer `decision` the forger wrote (what a classifier reading the outer verdict sees).
    outer_decision: String,
    /// Whether the verify error message contains [`NOT_APPROVED_MESSAGE_MARKER`], i.e. a
    /// message-substring classifier would be fooled. Written by hand from serde's error format.
    message_echoes_marker: bool,
}

// ── Builders (mirror hash::tests::make_minimal_context exactly) ───────────────────

/// The minimal action — `bin` + `raw` only, matching the hash-vector fixture so the computed
/// `request_hash` equals the frozen `request-hash/v4` value.
fn make_minimal_context() -> ApprovalContext {
    ApprovalContext {
        action: ActionRecord {
            record_schema_version: 3,
            surface: Surface::Command,
            facts: Facts {
                argv: None,
                cwd: None,
                server: None,
                tool: None,
                params: None,
                raw: Some("git push".to_string()),
                operation: None,
                paths: None,
                diff_summary: None,
                diff_hash: None,
            },
        },
        summary: "push to main".to_string(),
        actor: Actor {
            id: "machine:x".to_string(),
            kind: "claude-code".to_string(),
            attestation: None,
        },

        reversible: Some(false),
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

        reversible: Some(false),
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

fn expiring_recipient_device(id: &str, key: [u8; 32], cert_expires_at: i64) -> AccountStateDevice {
    AccountStateDevice {
        cert_expires_at: Some(cert_expires_at),
        ..recipient_device(id, key, "active")
    }
}

/// The recipient vector's account-state set, exercising each selection rule once:
/// - sequence 1 (stale): lists `dev-old`, which must not be selected;
/// - sequence 2: `dev-a` and `dev-d` active; `dev-b` active but revoked; `dev-c` not active;
///   `dev-e` active in only one of the two sequence-2 siblings (a conflict, so excluded);
///   `dev-f` whose cert expires at [`RECIPIENT_NOW_MS`] (excluded) and `dev-g` whose cert expires
///   one millisecond later (selected).
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
            expiring_recipient_device("dev-f", RECIPIENT_KEY_F, RECIPIENT_NOW_MS),
            expiring_recipient_device("dev-g", RECIPIENT_KEY_G, RECIPIENT_NOW_MS + 1),
        ],
        &["dev-b"],
    );
    let sibling = state(
        2,
        vec![
            recipient_device("dev-a", RECIPIENT_KEY_A, "active"),
            recipient_device("dev-b", RECIPIENT_KEY_B, "active"),
            recipient_device("dev-d", RECIPIENT_KEY_D, "active"),
            expiring_recipient_device("dev-f", RECIPIENT_KEY_F, RECIPIENT_NOW_MS),
            expiring_recipient_device("dev-g", RECIPIENT_KEY_G, RECIPIENT_NOW_MS + 1),
        ],
        &["dev-b"],
    );
    [stale, current, sibling]
        .iter()
        .map(|s| sign_account_state(s, root))
        .collect()
}

/// The recipients the rules allow for [`recipient_account_states`] at [`RECIPIENT_NOW_MS`]:
/// exactly `dev-a`, `dev-d` and `dev-g`, sorted by device id.
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
        Recipient {
            device_id: "dev-g".to_string(),
            encryption_pubkey: RECIPIENT_KEY_G,
        },
    ]
}

fn x25519_device(id: &str, seed: &[u8; 32]) -> AccountStateDevice {
    recipient_device(
        id,
        X25519KeyPair::from_seed(seed).public_key().to_bytes(),
        "active",
    )
}

/// The seal vector's account-state set:
/// - sequence 2 (stale): lists `injected`, which must get no recipient entry;
/// - sequence 3: `phone` and `laptop` active; `old` active but revoked, and `expired` whose cert
///   expires at [`RECIPIENT_NOW_MS`] (neither gets an entry).
fn seal_account_states(root: &SigningKeyPair) -> Vec<String> {
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
        SEAL_SEQUENCE - 1,
        vec![
            x25519_device("phone", &SEAL_PHONE_SEED),
            x25519_device("injected", &SEAL_INJECTED_SEED),
        ],
        &[],
    );
    let current = state(
        SEAL_SEQUENCE,
        vec![
            x25519_device("phone", &SEAL_PHONE_SEED),
            x25519_device("laptop", &SEAL_LAPTOP_SEED),
            x25519_device("old", &SEAL_REVOKED_SEED),
            AccountStateDevice {
                cert_expires_at: Some(RECIPIENT_NOW_MS),
                ..x25519_device("expired", &SEAL_EXPIRED_SEED)
            },
        ],
        &["old"],
    );
    [stale, current]
        .iter()
        .map(|s| sign_account_state(s, root))
        .collect()
}

fn seal_x25519_seeds_json() -> String {
    let seeds: serde_json::Map<String, serde_json::Value> = [
        ("phone", SEAL_PHONE_SEED),
        ("laptop", SEAL_LAPTOP_SEED),
        ("old", SEAL_REVOKED_SEED),
        ("injected", SEAL_INJECTED_SEED),
        ("expired", SEAL_EXPIRED_SEED),
    ]
    .iter()
    .map(|(id, seed)| ((*id).to_string(), URL_SAFE_NO_PAD.encode(seed).into()))
    .collect();
    serde_json::to_string(&seeds).expect("seeds serialize")
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
        approver: account_id(),
        context_ciphertext: None,
    }
}

/// Builds the full vector deterministically from the fixed seeds. Pure — no IO, no RNG.
fn build_vector() -> WasmVector {
    let context = make_minimal_context();
    let request_hash = compute_request_hash(&context, TS_EXPIRES);
    // Pin the independently authored JCS/hash anchor before regenerating any signed fixture.
    assert_eq!(
        URL_SAFE_NO_PAD.encode(request_hash),
        "1nYYX408B0ajV2NJhPPUXroHC9FZQyW0Jne8Oekw7Yg"
    );
    let hex = request_hash
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let root = SigningKeyPair::from_seed(&ROOT_SEED);
    let device = SigningKeyPair::from_seed(&DEVICE_SEED);

    // Device cert: account root certifies the device key (no expiry).
    let cert = issue_device_cert(
        &root,
        account_id().as_str(),
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
            account_id: account_id(),
            device_id: DEVICE_ID.to_string(),
        },
        note: None,
        challenge_response: None,
    };
    let noted_unsigned = UnsignedVerdict {
        note: Some(NOTE.to_string()),
        ..clone_unsigned(&unsigned)
    };
    let noted_verdict = sign_verdict(&noted_unsigned, &device, NOTED_NONCE, Some(cert.clone()))
        .expect("note within cap");
    let sign_non_approval = |decision: Decision, nonce: &[u8]| {
        let non_approval = UnsignedVerdict {
            decision,
            ..clone_unsigned(&unsigned)
        };
        sign_verdict(&non_approval, &device, nonce, Some(cert.clone())).expect("note within cap")
    };
    let denied = sign_non_approval(Decision::Denied, DENIED_NONCE);
    let not_approved_verdicts = vec![
        not_approved_case("signed denied", &denied, "denied"),
        not_approved_case(
            "signed expired",
            &sign_non_approval(Decision::Expired, EXPIRED_NONCE),
            "expired",
        ),
        not_approved_case(
            "signed aborted",
            &sign_non_approval(Decision::Aborted, ABORTED_NONCE),
            "aborted",
        ),
    ];
    let forged_not_approved_verdicts = forged_not_approved_cases(&denied);
    let provenance_cases = provenance_cases(&root, &unsigned, &cert, &denied);
    let verdict = sign_verdict(&unsigned, &device, NONCE, Some(cert)).expect("note within cap");

    let agent_tool_call_context = make_agent_tool_call_context();
    let agent_tool_call_request_hash = compute_request_hash(&agent_tool_call_context, TS_EXPIRES);
    // Hand-authored agent-tool JCS anchor, independently hashed in Python before signing.
    assert_eq!(
        URL_SAFE_NO_PAD.encode(agent_tool_call_request_hash),
        "tjlMBBEWsnG5F8BxDcisd4jjpsU6NAm9lRpKldhLl4Y"
    );

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
        noted_verdict_json: serde_json::to_string(&noted_verdict).expect("verdict serializes"),
        noted_verdict_note: NOTE.to_string(),
        noted_verdict_nonce_b64: URL_SAFE_NO_PAD.encode(NOTED_NONCE),
        recipient_account_states_json: serde_json::to_string(&recipient_account_states(&root))
            .expect("account states serialize"),
        expected_recipients_json: recipients_wire_json(&expected_recipients()),
        recipient_now_ms: RECIPIENT_NOW_MS,
        recipient_min_sequence: RECIPIENT_MIN_SEQUENCE,
        seal_account_states_json: serde_json::to_string(&seal_account_states(&root))
            .expect("account states serialize"),
        seal_x25519_seeds_json: seal_x25519_seeds_json(),
        // Spec (recipients.rs rules): the stale `injected`, the revoked `old` and the `expired`
        // device are excluded; recipients are sorted by device id.
        seal_expected_recipient_ids_json: r#"["laptop","phone"]"#.to_string(),
        seal_sequence: SEAL_SEQUENCE,
        not_approved_verdicts,
        forged_not_approved_verdicts,
        provenance_account_id: account_id(),
        provenance_created_at: TS_CREATED,
        provenance_expires_at: TS_EXPIRES,
        provenance_cases,
        self_certifying_cases: self_certifying_cases(&root, &unsigned),
    }
}

/// The provenance cases (#245), one per relay-table row: a genuine verdict and a genuine denial
/// pass; a verdict from a second certified device passes naming that device (telling it apart
/// from the socket's device is the relay's own check); a junk signature, a key no certificate
/// vouches for, a verdict replayed for another request, a revoked device, a decision outside the
/// request window on either side, and an expired certificate backdated to before the request are
/// rejected. Each rejection's error is written from the rules ([`provenance_expected_error`]).
fn provenance_cases(
    root: &SigningKeyPair,
    unsigned: &UnsignedVerdict,
    cert: &str,
    denied: &Verdict,
) -> Vec<ProvenanceCase> {
    let device = SigningKeyPair::from_seed(&DEVICE_SEED);
    let case =
        |name: &str, verdict: &Verdict, request_id: &str, states: &[String], ok: Option<&str>| {
            ProvenanceCase {
                name: name.to_string(),
                verdict_json: serde_json::to_string(verdict).expect("verdict serializes"),
                request_id: request_id.to_string(),
                account_states_json: serde_json::to_string(states).expect("states serialize"),
                expected_device_id: ok.map(str::to_string),
                expected_error: match ok {
                    Some(_) => None,
                    None => Some(provenance_expected_error(name).to_string()),
                },
            }
        };
    // The genuine device signing at `decided_at` under a certificate expiring at `cert_expires_at`.
    let signed_at = |decided_at: i64, cert_expires_at: Option<i64>| {
        let cert = issue_device_cert(
            root,
            account_id().as_str(),
            DEVICE_ID,
            &device.public_key(),
            TS_CREATED - 10_000,
            cert_expires_at,
        );
        sign_verdict(
            &UnsignedVerdict {
                decided_at,
                ..clone_unsigned(unsigned)
            },
            &device,
            NONCE,
            Some(cert),
        )
        .expect("note within cap")
    };
    let genuine =
        sign_verdict(unsigned, &device, NONCE, Some(cert.to_string())).expect("note within cap");

    let mut junk = genuine.clone();
    junk.sig = "not-a-jws".to_string();

    let uncertified = sign_verdict(
        unsigned,
        &SigningKeyPair::from_seed(&UNCERTIFIED_SEED),
        NONCE,
        Some(cert.to_string()),
    )
    .expect("note within cap");

    let second_key = SigningKeyPair::from_seed(&SECOND_DEVICE_SEED);
    let second_cert = issue_device_cert(
        root,
        account_id().as_str(),
        SECOND_DEVICE_ID,
        &second_key.public_key(),
        TS_CREATED,
        None,
    );
    let second = sign_verdict(
        &UnsignedVerdict {
            approver: Approver {
                account_id: account_id(),
                device_id: SECOND_DEVICE_ID.to_string(),
            },
            ..clone_unsigned(unsigned)
        },
        &second_key,
        NONCE,
        Some(second_cert),
    )
    .expect("note within cap");

    let revoking = sign_account_state(
        &AccountState {
            v: 1,
            account_id: account_id(),
            sequence: PROVENANCE_REVOKING_SEQUENCE,
            current_root: root.public_key().to_bytes(),
            previous_roots: vec![],
            devices: vec![],
            actors: vec![],
            revocations: vec![AccountStateRevocation {
                kind: AccountStateRevocationKind::Device,
                id: DEVICE_ID.to_string(),
                revoked_at: TS_CREATED,
                reason: None,
            }],
        },
        root,
    );

    vec![
        case("genuine", &genuine, REQUEST_ID, &[], Some(DEVICE_ID)),
        case("genuine denial", denied, REQUEST_ID, &[], Some(DEVICE_ID)),
        case(
            "second certified device",
            &second,
            REQUEST_ID,
            &[],
            Some(SECOND_DEVICE_ID),
        ),
        case("junk signature", &junk, REQUEST_ID, &[], None),
        case("uncertified key", &uncertified, REQUEST_ID, &[], None),
        case(
            "replayed for another request",
            &genuine,
            OTHER_REQUEST_ID,
            &[],
            None,
        ),
        case("revoked device", &genuine, REQUEST_ID, &[revoking], None),
        case(
            "decided before the request was created",
            &signed_at(TS_CREATED - 1, None),
            REQUEST_ID,
            &[],
            None,
        ),
        case(
            "decided after the request expires",
            &signed_at(TS_EXPIRES + 1, None),
            REQUEST_ID,
            &[],
            None,
        ),
        // A device whose certificate has expired backdates its decision to while the certificate
        // was valid; the window (not the certificate) is what rejects it.
        case(
            "expired cert backdated before the request",
            &signed_at(TS_CREATED - 1_000, Some(TS_CREATED - 500)),
            REQUEST_ID,
            &[],
            None,
        ),
    ]
}

/// The error the rules call for, per rejected provenance case (written by hand, not captured).
fn provenance_expected_error(name: &str) -> VerifyError {
    match name {
        "junk signature" => VerifyError::MalformedJws,
        "uncertified key" => VerifyError::VerdictSignatureInvalid,
        "replayed for another request" => VerifyError::RequestIdMismatch,
        "revoked device" => VerifyError::DeviceRevoked,
        "decided before the request was created"
        | "decided after the request expires"
        | "expired cert backdated before the request" => VerifyError::DecidedAtOutOfWindow,
        other => panic!("no expected error written for provenance case {other:?}"),
    }
}

fn not_approved_case(name: &str, verdict: &Verdict, signed_decision: &str) -> NotApprovedCase {
    NotApprovedCase {
        name: name.to_string(),
        verdict_json: serde_json::to_string(verdict).expect("verdict serializes"),
        signed_decision: signed_decision.to_string(),
    }
}

/// The forged cases: the signed `denied` verdict with its outer `decision` rewritten and the
/// marker echoed via `v`, `request_id`, `decided_at` or `decision` itself, plus a rewrite with no
/// marker at all.
fn forged_not_approved_cases(denied: &Verdict) -> Vec<ForgedNotApprovedCase> {
    let base = serde_json::to_value(denied).expect("verdict serializes");
    let forge = |name: &str, outer: &str, field: Option<&str>, echoes: bool| {
        let mut value = base.clone();
        value["decision"] = outer.into();
        if let Some(field) = field {
            value[field] = NOT_APPROVED_MESSAGE_MARKER.into();
        }
        ForgedNotApprovedCase {
            name: name.to_string(),
            verdict_json: serde_json::to_string(&value).expect("forged verdict serializes"),
            outer_decision: value["decision"].as_str().expect("string").to_string(),
            message_echoes_marker: echoes,
        }
    };
    vec![
        // serde: `invalid type: string "…", expected u32` quotes the value.
        forge("outer approved, marker in v", "approved", Some("v"), true),
        forge("outer aborted, marker in v", "aborted", Some("v"), true),
        forge("outer expired, marker in v", "expired", Some("v"), true),
        // serde: `invalid type: string "…", expected i64` quotes the value.
        forge(
            "outer approved, marker in decided_at",
            "approved",
            Some("decided_at"),
            true,
        ),
        // serde: `unknown variant `…`` quotes the value. The outer decision *is* the marker.
        forge(
            "marker as the decision",
            NOT_APPROVED_MESSAGE_MARKER,
            None,
            true,
        ),
        // Parses; the core rejects the request id (its message does not quote it).
        forge(
            "outer approved, marker in request_id",
            "approved",
            Some("request_id"),
            false,
        ),
        // Parses; the core rejects the outer decision as disagreeing with the signed one.
        forge(
            "outer approved over a signed denial",
            "approved",
            None,
            false,
        ),
    ]
}

/// `UnsignedVerdict` is not `Clone`; copy it field-by-field for the noted variant.
fn clone_unsigned(u: &UnsignedVerdict) -> UnsignedVerdict {
    UnsignedVerdict {
        v: u.v,
        request_id: u.request_id.clone(),
        request_hash: u.request_hash,
        decision: u.decision,
        decided_at: u.decided_at,
        approver: u.approver.clone(),
        note: u.note.clone(),
        challenge_response: u.challenge_response.clone(),
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
/// expected hash must equal the frozen `request-hash/v4` vector. When `REGEN_WASM_VECTOR=1`, it
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

/// Independent anchor: the fixture's expected hash equals the frozen `request-hash/v4` hex from
/// `hash.rs`. If `hash.rs` bumps `DOMAIN_TAG`, this catches the drift (and the fixture must be
/// regenerated). Spec-first — the value is the documented frozen vector, not a captured snapshot.
#[test]
fn fixture_hash_equals_frozen_vector() {
    // The same value asserted by hash::tests::frozen_cross_platform_vector.
    const FROZEN_HASH_HEX: &str =
        "d676185f8d3c0746a357634984f3d45eba070bd1594325b42677bc39e930ed88";

    let context = make_minimal_context();
    let hash = compute_request_hash(&context, TS_EXPIRES);
    let hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex, FROZEN_HASH_HEX,
        "fixture context must hash to the frozen request-hash/v4 vector"
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
/// `action.facts` — proving `surface` is actually hashed (not silently ignored) and that the
/// two surfaces produce different `request_hash` values despite sharing the same summary, actor,
/// risk, and constraints.
#[test]
fn agent_tool_call_and_command_fixtures_hash_differently() {
    let command_hash = compute_request_hash(&make_minimal_context(), TS_EXPIRES);
    let agent_tool_call_hash = compute_request_hash(&make_agent_tool_call_context(), TS_EXPIRES);

    assert_ne!(
        command_hash, agent_tool_call_hash,
        "changing action.surface (and its facts substrate) must change request_hash"
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

/// The committed noted verdict verifies under the fixture's root, and rewriting, stripping, or
/// adding a note on the shared vector is rejected as a claims mismatch (S15, #251). The WASM side
/// replays the same checks in `packages/sdk/test/wasm.test.mjs`.
///
/// @see docs/contract.md §Wire encoding → verdict signature
#[test]
fn fixture_noted_verdict_binds_its_note() {
    let raw = std::fs::read_to_string(fixture_path()).expect("fixture must exist for this test");
    let v: WasmVector =
        serde_json::from_str(&raw).expect("committed fixture is valid WasmVector JSON");
    let request: ApprovalRequest = serde_json::from_str(&v.request_json).unwrap();
    let context: ApprovalContext = serde_json::from_str(&v.context_json).unwrap();
    let root = SigningKeyPair::from_seed(&ROOT_SEED).public_key();
    let verify = |verdict: &Verdict| {
        verify_verdict(
            verdict,
            &request,
            &context,
            &root,
            &mut InMemoryNonceStore::new(),
            v.now_ms,
        )
    };

    let noted: Verdict = serde_json::from_str(&v.noted_verdict_json).unwrap();
    assert_eq!(noted.note.as_deref(), Some(v.noted_verdict_note.as_str()));
    verify(&noted).expect("the committed noted verdict must verify");

    let note_mismatch = VerifyError::ClaimsMismatch { field: "note" };
    let mut tampered = noted.clone();
    tampered.note = Some("ok for prod".to_string());
    assert_eq!(verify(&tampered).unwrap_err(), note_mismatch);

    let mut removed = noted;
    removed.note = None;
    assert_eq!(verify(&removed).unwrap_err(), note_mismatch);

    let mut added: Verdict = serde_json::from_str(&v.verdict_json).unwrap();
    added.note = Some("injected".to_string());
    assert_eq!(verify(&added).unwrap_err(), note_mismatch);
}

/// The core's `select_recipients` over the fixture's account-state set returns exactly the
/// recipients the rules allow (`dev-a`, `dev-d`, `dev-g`); the node test checks the WASM surface returns
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

    assert_eq!(committed.recipient_now_ms, RECIPIENT_NOW_MS);
    assert_eq!(committed.recipient_min_sequence, RECIPIENT_MIN_SEQUENCE);
    let selected = select_recipients(
        &refs,
        &committed.expected_account_id_for_root,
        &root,
        committed.recipient_now_ms,
        Some(committed.recipient_min_sequence),
    )
    .expect("fixture state yields recipients");
    assert_eq!(selected, expected_recipients());
    assert_eq!(
        committed.expected_recipients_json,
        recipients_wire_json(&selected)
    );
}

/// Sealing the fixture's seal set encrypts to exactly `laptop` and `phone`, each of which can open
/// it; the revoked `old`, the `expired` device and the never-vouched `injected` get no recipient
/// entry, and the reported sequence is the selected one whatever floor is passed. The node test
/// runs the same check through the WASM export.
#[test]
fn fixture_seal_encrypts_only_to_vouched_devices() {
    let raw = std::fs::read_to_string(fixture_path()).expect("fixture must exist for this test");
    let committed: WasmVector =
        serde_json::from_str(&raw).expect("committed fixture is valid WasmVector JSON");
    let docs: Vec<String> =
        serde_json::from_str(&committed.seal_account_states_json).expect("seal states parse");
    let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
    let root_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&committed.approver_root_pubkey_b64)
        .expect("root pubkey decodes")
        .try_into()
        .expect("root pubkey is 32 bytes");
    let root = PublicKey::from_bytes(&root_bytes).expect("root pubkey is valid");
    let context: ApprovalContext =
        serde_json::from_str(&committed.context_json).expect("context parses");
    assert_eq!(committed.seal_sequence, SEAL_SEQUENCE);

    let sealed = seal_context_for_account_state(
        &context,
        &refs,
        &committed.expected_account_id_for_root,
        &root,
        committed.recipient_now_ms,
        Some(committed.seal_sequence),
        &mut ChaCha20Rng::from_seed([0x42; 32]),
    )
    .expect("fixture seal set yields recipients");
    assert_eq!(sealed.sequence, committed.seal_sequence);

    let seeds: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&committed.seal_x25519_seeds_json).expect("seeds parse");
    let key = |id: &str| -> X25519KeyPair {
        let seed: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&seeds[id])
            .expect("seed decodes")
            .try_into()
            .expect("seed is 32 bytes");
        X25519KeyPair::from_seed(&seed)
    };
    let expected: Vec<String> = serde_json::from_str(&committed.seal_expected_recipient_ids_json)
        .expect("expected ids parse");
    for id in &expected {
        assert_eq!(
            decrypt_context(&sealed.ciphertext, id, &key(id)).as_ref(),
            Ok(&context),
            "{id} must open the sealed context"
        );
    }
    // RFC 7516 §7.2.1: exactly one `recipients[]` entry per selected device, nothing else.
    let jwe: serde_json::Value = serde_json::from_str(&sealed.ciphertext).expect("JWE is JSON");
    let kids: Vec<&str> = jwe["recipients"]
        .as_array()
        .expect("General JWE has a recipients array")
        .iter()
        .map(|r| r["header"]["kid"].as_str().expect("kid"))
        .collect();
    assert_eq!(kids, expected);
    for id in ["old", "injected", "expired"] {
        assert_eq!(
            decrypt_context(&sealed.ciphertext, id, &key(id)),
            Err(JweError::NoRecipientForDevice),
            "{id} must get no recipient entry"
        );
    }

    // The sequence is the selected one, never the caller's floor: same with a lower floor or none.
    for floor in [Some(1), None] {
        let resealed = seal_context_for_account_state(
            &context,
            &refs,
            &committed.expected_account_id_for_root,
            &root,
            committed.recipient_now_ms,
            floor,
            &mut ChaCha20Rng::from_seed([0x42; 32]),
        )
        .expect("a lower floor still seals");
        assert_eq!(resealed.sequence, SEAL_SEQUENCE, "floor {floor:?}");
    }
}

/// The verified-non-approval vector (#311): each genuinely signed non-approval verifies to
/// `NotApproved` carrying the signed decision, and no forged case does, whatever its outer
/// `decision` or echoed text. The WASM side (`packages/sdk/test/wasm.test.mjs`) checks the
/// structured `kind: "not_approved"` error for the same cases.
///
/// @see docs/contract.md §Verification checklist (step 8: a verified non-approval)
#[test]
fn fixture_not_approved_cases_follow_the_signed_claims() {
    let raw = std::fs::read_to_string(fixture_path()).expect("fixture must exist for this test");
    let v: WasmVector =
        serde_json::from_str(&raw).expect("committed fixture is valid WasmVector JSON");
    let request: ApprovalRequest = serde_json::from_str(&v.request_json).unwrap();
    let context: ApprovalContext = serde_json::from_str(&v.context_json).unwrap();
    let root = SigningKeyPair::from_seed(&ROOT_SEED).public_key();
    let verify = |verdict: &Verdict| {
        verify_verdict(
            verdict,
            &request,
            &context,
            &root,
            &mut InMemoryNonceStore::new(),
            v.now_ms,
        )
    };

    let signed: Vec<(&str, Decision)> = v
        .not_approved_verdicts
        .iter()
        .map(|case| {
            let verdict: Verdict = serde_json::from_str(&case.verdict_json).unwrap();
            match verify(&verdict) {
                Err(VerifyError::NotApproved { decision }) => {
                    (case.signed_decision.as_str(), decision)
                }
                other => panic!("{}: expected NotApproved, got {other:?}", case.name),
            }
        })
        .collect();
    assert_eq!(
        signed,
        vec![
            ("denied", Decision::Denied),
            ("expired", Decision::Expired),
            ("aborted", Decision::Aborted),
        ]
    );

    assert_eq!(v.forged_not_approved_verdicts.len(), 7);
    for case in &v.forged_not_approved_verdicts {
        match serde_json::from_str::<Verdict>(&case.verdict_json) {
            Err(parse_error) => assert_eq!(
                parse_error
                    .to_string()
                    .contains(NOT_APPROVED_MESSAGE_MARKER),
                case.message_echoes_marker,
                "{}: does the parse error echo the marker",
                case.name
            ),
            Ok(verdict) => {
                assert!(!case.message_echoes_marker, "{}: parsed", case.name);
                let error = verify(&verdict).expect_err("a forged verdict never verifies");
                assert!(
                    !matches!(error, VerifyError::NotApproved { .. }),
                    "{}: must not be a verified non-approval, got {error:?}",
                    case.name
                );
                assert!(!error.to_string().contains(NOT_APPROVED_MESSAGE_MARKER));
            }
        }
    }
}

/// Each provenance case gives the hand-written answer: the named device, or the specific error the
/// rules say (`docs/relay-api.md` §4, the relay's table in #245).
#[test]
fn fixture_provenance_cases_follow_the_rules() {
    let raw = std::fs::read_to_string(fixture_path()).expect("fixture must exist for this test");
    let v: WasmVector =
        serde_json::from_str(&raw).expect("committed fixture is valid WasmVector JSON");
    let root = SigningKeyPair::from_seed(&ROOT_SEED).public_key();
    assert_eq!(v.provenance_cases.len(), 10);
    for case in &v.provenance_cases {
        let verdict: Verdict = serde_json::from_str(&case.verdict_json).unwrap();
        let states: Vec<String> = serde_json::from_str(&case.account_states_json).unwrap();
        let state_refs: Vec<&str> = states.iter().map(String::as_str).collect();
        let result = verify_verdict_provenance(
            &verdict,
            &case.request_id,
            v.provenance_created_at,
            v.provenance_expires_at,
            &v.provenance_account_id,
            &root,
            &state_refs,
        );
        match &case.expected_device_id {
            Some(device_id) => {
                let got = result.unwrap_or_else(|e| panic!("{}: must pass, got {e:?}", case.name));
                assert_eq!(&got.device_id, device_id, "{}", case.name);
                assert_eq!(got.decided_at, TS_DECIDED, "{}", case.name);
            }
            None => {
                let expected = provenance_expected_error(&case.name);
                assert_eq!(result.as_ref().err(), Some(&expected), "{}", case.name);
                assert_eq!(
                    case.expected_error.as_deref(),
                    Some(expected.to_string().as_str()),
                    "{}: the fixture carries the expected error",
                    case.name
                );
            }
        }
    }
}

/// Rust and WASM consume identical genuine signatures with spec-derived success/error expectations.
/// @see docs/enrollment.md §Self-Certifying Account Id.
#[test]
fn fixture_self_certifying_accounts() {
    let vector = build_vector();
    let root = SigningKeyPair::from_seed(&ROOT_SEED).public_key();
    for case in vector.self_certifying_cases {
        let verdict: Verdict = serde_json::from_str(&case.verdict_json).unwrap();
        let result = verify_verdict(
            &verdict,
            &make_request(),
            &make_minimal_context(),
            &root,
            &mut InMemoryNonceStore::new(),
            NOW_MS,
        );
        let provenance = verify_verdict_provenance(
            &verdict,
            REQUEST_ID,
            TS_CREATED,
            TS_EXPIRES,
            &case.account_id,
            &root,
            &[],
        );
        if let Some(error) = case.expected_error {
            assert_eq!(result.unwrap_err(), VerifyError::AccountIdMismatch);
            assert_eq!(provenance.unwrap_err(), VerifyError::AccountIdMismatch);
            assert_eq!(VerifyError::AccountIdMismatch.to_string(), error);
        } else {
            result.unwrap();
            provenance.unwrap();
        }
    }
}
