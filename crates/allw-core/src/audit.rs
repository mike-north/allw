//! Append-only, hash-chained audit records. See `docs/contract.md`.
//!
//! TODO:
//! - `AuditRecord` type (request + verdict + actor/approver + `ActionRecord` + `context_digest`).
//! - Hash-chain construction (`prev_hash` / `record_hash`).
//! - Reserved `policy` block `{ decision, rule_id?, tier, schema_version }` (v1 writes `escalate`).
//! - Periodic head-hash anchoring for non-repudiation.
