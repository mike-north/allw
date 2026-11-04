//! Shared cross-platform vector for the PowerShell command builder (#298).
//!
//! `tests/fixtures/powershell_vector.json` is consumed by both this test (the Rust core) and
//! `packages/sdk/test/powershell-vector.test.mjs` (the compiled `.wasm`), so the core and every
//! TypeScript surface agree on how a PowerShell line becomes an `ActionRecord`.
//!
//! Spec-first: every expected value is written by hand from the rules in
//! `crates/allw-core/src/powershell.rs`. There is no regenerate mode; a mismatch is either a bug or a
//! deliberate rule change that must be reviewed by hand.
//!
//! @see https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_quoting_rules

use std::path::PathBuf;

use allw_core::{action_from_powershell_command, CommandContext};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    class: String,
    command: String,
    cwd: Option<String>,
    risk: String,
    bin: String,
    argv: Vec<String>,
}

#[derive(Deserialize)]
struct Vector {
    cases: Vec<Case>,
}

fn load_vector() -> Vector {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/powershell_vector.json");
    let raw = std::fs::read_to_string(&path).expect("read powershell_vector.json");
    serde_json::from_str(&raw).expect("parse powershell_vector.json")
}

#[test]
fn every_case_in_the_shared_vector_builds_the_expected_record() {
    let vector = load_vector();
    assert!(vector.cases.len() >= 5);
    for case in vector.cases {
        let ctx = CommandContext {
            cwd: case.cwd.clone(),
        };
        let record = action_from_powershell_command(&case.command, &ctx)
            .unwrap_or_else(|e| panic!("{}: must build: {e}", case.class));
        let json = serde_json::to_value(&record).expect("serialize ActionRecord");
        assert_eq!(json["surface"], "command", "{}", case.class);
        assert_eq!(json["risk"], case.risk.as_str(), "{}", case.class);
        assert_eq!(
            json["syntactic"]["raw"],
            case.command.as_str(),
            "{}",
            case.class
        );
        assert_eq!(
            json["syntactic"]["bin"],
            case.bin.as_str(),
            "{}",
            case.class
        );
        assert_eq!(
            json["syntactic"]["argv"],
            serde_json::json!(case.argv),
            "{}",
            case.class
        );
        match &case.cwd {
            Some(cwd) => assert_eq!(json["syntactic"]["cwd"], cwd.as_str(), "{}", case.class),
            None => assert!(json["syntactic"]["cwd"].is_null(), "{}", case.class),
        }
    }
}
