//! E2EE + signing primitives (JOSE). See `docs/contract.md`.
//!
//! Substrate (shared with vaultkeeper): JWE over X25519 ECDH for context; JWS over Ed25519
//! for verdicts and policy rules. Static ECDH for v1; forward secrecy later.
//!
//! TODO:
//! - Device key management (keys live in Secure Enclave / StrongBox / OS keystore; never exported).
//! - JWE encrypt/decrypt of approval context to device key(s).
//! - JWS verdict signing (device key, biometric-gated) and verification.
//! - Device-cert chain binding a device key to the account root.
