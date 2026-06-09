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
//! (multi-recipient JOSE JWE — `ECDH-ES+A256KW` X25519 → A256GCM; see [`jwe`]).

pub mod audit;
pub mod command;
pub mod contract;
pub mod crypto;
pub mod hash;
pub mod jwe;
pub mod mcp;

pub use audit::{
    compute_record_hash, AuditChain, AuditChainError, AuditEntryInput, GENESIS_PREV_HASH,
};
pub use command::{action_from_argv, action_from_command, CommandContext, CommandError};
pub use contract::{
    ActionRecord, Actor, ApprovalContext, ApprovalRequest, Approver, AuditRecord, Constraints,
    Decision, PolicyBlock, PolicyDecision, Risk, Surface, SyntacticSubstrate, Verdict,
};
pub use crypto::{
    effective_allow, issue_device_cert, sign_verdict, verify_verdict, DeviceCertClaims,
    InMemoryNonceStore, JwsError, KeyError, NonceStore, PublicKey, SigningKeyPair, UnsignedVerdict,
    VerdictClaims, VerifiedVerdict, VerifyError,
};
pub use hash::{canonical_request_bytes, compute_request_hash};
pub use jwe::{
    decrypt_context, encrypt_context, ContextRecipient, JweError, X25519KeyPair, X25519PublicKey,
};
pub use mcp::action_from_mcp_tool_call;
