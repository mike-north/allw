//! Shared Rust ↔ WASM vectors for command risk classification (#268).
//!
//! `tests/fixtures/command_risk_vectors.json` lists commands with a hand-derived expected `risk`
//! and `bin`. Each expected value comes from the module-doc risk table in
//! `crates/allw-core/src/command/risk.rs` and the rule in `docs/policy-seam.md` §ActionRecord: risk is
//! classified on the program that actually runs (leading `NAME=value` assignments, wrappers and
//! `sh -c` never lower it), while `bin` stays `argv[0]`. The same file is fed through the compiled
//! WASM by `packages/sdk/test/command-risk-vectors.test.mjs`, so the two surfaces cannot drift.
//!
//! The fixture is append-only and hand-written. It is never regenerated from program output.
//!
//! @see docs/policy-seam.md §ActionRecord
//! @see crates/allw-core/src/command/risk.rs (module doc)

use std::path::PathBuf;

use allw_core::{action_from_command, CommandContext};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    command: String,
    risk: String,
    bin: String,
    why: String,
}

fn load() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("command_risk_vectors.json");
    let text = std::fs::read_to_string(&path).expect("command risk vector fixture is committed");
    serde_json::from_str(&text).expect("command risk vector fixture is valid JSON")
}

#[test]
fn every_vector_has_the_expected_risk_and_bin() {
    let fixture = load();
    assert!(!fixture.cases.is_empty(), "fixture has cases");
    let mut failures = Vec::new();
    for case in &fixture.cases {
        let record = action_from_command(&case.command, &CommandContext::default())
            .unwrap_or_else(|e| panic!("`{}` tokenizes: {e:?}", case.command));
        // Risk serializes as its lowercase wire name ("low" | "medium" | "high" | "critical").
        let risk = serde_json::to_value(record.risk).expect("risk serializes");
        if risk != case.risk.as_str() {
            failures.push(format!(
                "`{}`: risk {risk}, want {} ({})",
                case.command, case.risk, case.why
            ));
        }
        let bin = record.syntactic.bin.unwrap_or_default();
        if bin != case.bin {
            failures.push(format!(
                "`{}`: bin {bin:?}, want {:?}",
                case.command, case.bin
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "vector mismatches:\n{}",
        failures.join("\n")
    );
}
