//! Shared cross-platform vector for the command builders' no-program refusal (#376).
//!
//! `tests/fixtures/command_refusal_vector.json` is consumed by both this test (the Rust core) and
//! `packages/sdk/test/command-refusal-vector.test.mjs` (the compiled `.wasm`), so the core and every
//! TypeScript surface refuse the same lines with the same code. Spec-first: the cases are written by
//! hand from `docs/policy-seam.md` §Command lines that run no program.

use std::path::PathBuf;

use allw_core::{action_from_command, action_from_powershell_command, CommandContext};
use serde::Deserialize;

#[derive(Deserialize)]
struct Refused {
    class: String,
    builder: String,
    command: String,
    code: String,
    message: String,
}

#[derive(Deserialize)]
struct Accepted {
    class: String,
    builder: String,
    command: String,
}

#[derive(Deserialize)]
struct Vector {
    cases: Vec<Refused>,
    accepted: Vec<Accepted>,
}

fn load_vector() -> Vector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/command_refusal_vector.json");
    let raw = std::fs::read_to_string(&path).expect("read command_refusal_vector.json");
    serde_json::from_str(&raw).expect("parse command_refusal_vector.json")
}

fn build(builder: &str, command: &str) -> Result<allw_core::ActionRecord, allw_core::CommandError> {
    let ctx = CommandContext::default();
    match builder {
        "posix" => action_from_command(command, &ctx),
        "powershell" => action_from_powershell_command(command, &ctx),
        other => panic!("unknown builder {other:?}"),
    }
}

#[test]
fn every_refusal_case_is_refused_with_its_code_and_message() {
    let vector = load_vector();
    assert!(vector.cases.len() >= 10);
    for case in &vector.cases {
        let label = format!("{} ({}: {:?})", case.class, case.builder, case.command);
        let err =
            build(&case.builder, &case.command).expect_err(&format!("{label} must be refused"));
        assert_eq!(err.code(), case.code, "{label}");
        assert_eq!(err.to_string(), case.message, "{label}");
    }
}

#[test]
fn every_accepted_case_builds_a_record() {
    let vector = load_vector();
    assert!(!vector.accepted.is_empty());
    for case in &vector.accepted {
        let result = build(&case.builder, &case.command);
        assert!(
            result.is_ok(),
            "{} ({}: {:?}) must build: {result:?}",
            case.class,
            case.builder,
            case.command
        );
    }
}
