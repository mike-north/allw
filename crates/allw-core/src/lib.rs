//! # allw-core
//!
//! Core types and crypto for the allw approval primitive:
//!
//! ```text
//! requestApproval(ActionRecord) -> Verdict + AuditRecord     [over an E2EE channel]
//! ```
//!
//! This crate is the **single audited implementation** shared by every surface — native
//! apps (via UniFFI), and the TypeScript SDK / relay / hook (via WASM). Security-critical
//! logic lives here once; per-platform code is UI, notifications, and key storage only.
//!
//! See `docs/contract.md` and `docs/architecture.md`.
//!
//! **Status:** contract wire types landed (serde-backed, JOSE-consistent binary encoding,
//! i64 ms timestamps). WYSIWYS request_hash implemented. Append-only audit hash-chain landed
//! (`AuditChain`, `AuditEntryInput`, `AuditChainError`, `compute_record_hash`). Verdict signing
//! and verification landed via an EdDSA compact JWS over Ed25519. JWE context E2EE landed
//! (multi-recipient JOSE JWE — `ECDH-ES+A256KW` X25519 → A256GCM; see [`jwe`]). Actor-key request
//! attestation landed (verified request origin, bound to `request_id` + `request_hash`, with the
//! actor key anchored in root-signed account state; see [`attestation`]). Display escaping landed:
//! untrusted context text reaches approver screens only through [`display_model`] /
//! [`escape_for_display`] (see [`display`]).

pub mod account;
pub mod attestation;
pub mod audit;
pub mod command;
pub mod contract;
pub mod crypto;
pub mod display;
pub mod enrollment;
pub mod file_edit;
pub mod hash;
pub mod jwe;
pub mod mcp;
pub mod powershell;
pub mod recipients;
pub mod sealing;

pub use account::{
    account_id_for_root, check_account_id_for_root, sign_pairing_start_authorization,
    verify_pairing_start_authorization, AccountIdError, PairingStartClaims, PairingStartError,
    PAIRING_START_JTI_MAX_LEN, PAIRING_START_JTI_MIN_LEN, PAIRING_START_MAX_CLOCK_SKEW_MS,
    PAIRING_START_MAX_LIFETIME_MS,
};
pub use attestation::{
    sign_actor_attestation, verified_origin_string, verify_actor_attestation,
    verify_actor_attestation_with_account_states, ActorAttestationClaims, AttestationError,
};
pub use audit::{
    compute_record_hash, AuditChain, AuditChainError, AuditEntryInput, GENESIS_PREV_HASH,
};
pub use command::{action_from_argv, action_from_command, CommandContext, CommandError};
pub use contract::{
    ActionRecord, Actor, ApprovalContext, ApprovalRequest, Approver, AuditRecord, Constraints,
    ContextViolation, Decision, PolicyBlock, PolicyDecision, ReservedField, Risk, Surface,
    SyntacticSubstrate, Verdict,
};
pub use crypto::{
    derive_number_match_challenge, effective_allow, issue_device_cert, revoked_device_ids,
    sign_account_state, sign_verdict, verify_account_state, verify_verdict,
    verify_verdict_for_account, verify_verdict_provenance, verify_verdict_with_account_states,
    verify_verdict_with_account_states_for_account, AccountState, AccountStateActor,
    AccountStateDevice, AccountStateError, AccountStatePreviousRoot, AccountStateRevocation,
    AccountStateRevocationKind, DeviceCertClaims, InMemoryNonceStore, JwsError, KeyError,
    NonceStore, PublicKey, SignVerdictError, SigningKeyPair, UnsignedVerdict, VerdictClaims,
    VerdictProvenance, VerifiedVerdict, VerifyError, MAX_NOTE_BYTES,
};
pub use display::{
    display_model, escape_for_display, has_hidden_or_control_chars, is_combining_mark,
    is_hidden_or_control_char, is_variation_selector, DisplayModel, DisplaySubstrate, CRLF_MARKER,
    MAX_STACKED_COMBINING_MARKS, TAB_MARKER,
};
pub use enrollment::{
    device_key_fingerprint, next_account_state, AccountStateChange, DeviceEnrollment,
    DeviceKeyKind, DeviceMaterialError, NextAccountState, NextAccountStateError, DEVICE_ID_MAX_LEN,
    FINGERPRINT_BYTES,
};
pub use file_edit::action_from_file_edit;
pub use hash::{canonical_request_bytes, compute_request_hash};
pub use jwe::{
    decrypt_context, encrypt_context, is_small_order_x25519_public_key, ContextRecipient,
    EncryptError, JweError, X25519KeyPair, X25519PublicKey, X25519_SMALL_ORDER_POINTS,
};
pub use mcp::{
    action_from_agent_tool_call, action_from_agent_tool_call_with_raw, action_from_mcp_tool_call,
};
pub use powershell::action_from_powershell_command;
pub use recipients::{
    select_recipients, Recipient, RecipientSelectionError, DEVICE_STATUS_ACTIVE,
    MAX_ACCOUNT_STATES, MAX_RECIPIENTS,
};
pub use sealing::{seal_context_for_account_state, SealContextError, SealedContext};
