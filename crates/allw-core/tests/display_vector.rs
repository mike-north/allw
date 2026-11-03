//! Shared cross-platform vector for display escaping (#246).
//!
//! `tests/fixtures/display_vector.json` is consumed by both this test (the Rust core) and
//! `packages/sdk/test/wasm.test.mjs` (the compiled `.wasm`), so the two can never disagree about
//! how untrusted text is shown to a human. It covers each escaped character class, one mixed
//! string, one full `display_model` case, and per-surface `raw_lines` cases (which line endings and
//! TABs are structure).
//!
//! Spec-first: every expected value in the fixture is written by hand from the notation documented
//! in `crates/allw-core/src/display.rs`. There is deliberately no regenerate mode — a mismatch here
//! is a bug in the implementation or a deliberate notation change that must be reviewed by hand.
//!
//! @see https://www.unicode.org/reports/tr9/ §2 (explicit bidi formatting characters)
//! @see docs/threat-model.md R3 (WYSIWYS completeness)
//! @see docs/contract.md §Invariants #3 (WYSIWYS)

use std::path::PathBuf;

use allw_core::{
    compute_request_hash, display_model, escape_for_display, has_hidden_or_control_chars,
    ApprovalContext,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct EscapeCase {
    class: String,
    input: String,
    escaped: String,
    has_hidden_or_control_chars: bool,
}

#[derive(Deserialize)]
struct DisplayModelCase {
    context: serde_json::Value,
    expected: serde_json::Value,
}

#[derive(Deserialize)]
struct RawLinesCase {
    class: String,
    surface: String,
    raw: String,
    raw_lines: Vec<String>,
    has_hidden_or_control_chars: bool,
}

#[derive(Deserialize)]
struct Vector {
    escape_cases: Vec<EscapeCase>,
    display_model_case: DisplayModelCase,
    raw_lines_cases: Vec<RawLinesCase>,
}

/// A minimal context on `surface` whose only substrate field is `raw`.
fn raw_context(surface: &str, raw: &str) -> ApprovalContext {
    serde_json::from_value(serde_json::json!({
        "action": {
            "record_schema_version": 1,
            "surface": surface,
            "syntactic": { "raw": raw },
            "risk": "high"
        },
        "summary": "s",
        "actor": { "id": "machine:ci", "kind": "claude-code" },
        "risk": "high",
        "reversible": false,
        "constraints": { "allowed_decisions": ["approved", "denied"], "challenge_required": false }
    }))
    .expect("a valid ApprovalContext")
}

fn load() -> Vector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/display_vector.json");
    let text = std::fs::read_to_string(&path).expect("display vector fixture is committed");
    serde_json::from_str(&text).expect("display vector fixture is valid JSON")
}

#[test]
fn every_escape_case_matches_the_vector() {
    let vector = load();
    assert!(vector.escape_cases.len() >= 10, "vector covers every class");
    for case in &vector.escape_cases {
        assert_eq!(
            escape_for_display(&case.input),
            case.escaped,
            "class: {}",
            case.class
        );
        assert_eq!(
            has_hidden_or_control_chars(&case.input),
            case.has_hidden_or_control_chars,
            "class: {}",
            case.class
        );
        assert!(
            !has_hidden_or_control_chars(&case.escaped),
            "escaped output must itself be clean: {}",
            case.class
        );
    }
}

#[test]
fn display_model_case_matches_the_vector() {
    let vector = load();
    let ctx: ApprovalContext = serde_json::from_value(vector.display_model_case.context)
        .expect("vector context is a valid ApprovalContext");
    let model = serde_json::to_value(display_model(&ctx)).expect("model serializes");
    assert_eq!(model, vector.display_model_case.expected);
}

#[test]
fn display_model_case_hash_binds_the_raw_bytes() {
    // Display escaping is display-only: the request hash of the vector context is unaffected by
    // building its display model.
    let vector = load();
    let ctx: ApprovalContext = serde_json::from_value(vector.display_model_case.context)
        .expect("vector context is a valid ApprovalContext");
    let before = compute_request_hash(&ctx, 1_700_003_600_000);
    let _ = display_model(&ctx);
    assert_eq!(compute_request_hash(&ctx, 1_700_003_600_000), before);
}

#[test]
fn every_raw_lines_case_matches_the_vector() {
    let vector = load();
    assert!(!vector.raw_lines_cases.is_empty());
    for case in &vector.raw_lines_cases {
        let model = display_model(&raw_context(&case.surface, &case.raw));
        assert_eq!(
            model.syntactic.raw_lines.as_ref(),
            Some(&case.raw_lines),
            "class: {}",
            case.class
        );
        assert_eq!(
            model.has_hidden_or_control_chars, case.has_hidden_or_control_chars,
            "class: {}",
            case.class
        );
    }
}
