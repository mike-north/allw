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
//! i64 ms timestamps). Crypto (JWE/JWS) and audit hash-chain construction are TODO.

pub mod audit;
pub mod contract;
pub mod crypto;

pub use contract::{
    ActionRecord, Actor, ApprovalRequest, Approver, AuditRecord, Constraints, Decision,
    PolicyBlock, PolicyDecision, Risk, Surface, SyntacticSubstrate, Verdict,
};
