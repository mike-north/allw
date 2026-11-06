//! Outcome contract for opaque command capture: spelling belongs to the caller, not allw.
//! @see docs/action-record.md — Command capture; docs/contract.md — Unknown fields.
use allw_core::{action_from_argv, action_from_command, CommandContext};
use serde_json::json;

/// Punctuation, shell-looking syntax and PowerShell lines are data, even when no shell would run
/// a program. A line builder must never manufacture an execution vector or inferred facts.
#[test]
fn lines_are_byte_faithful_and_never_infer_fields() {
    let ctx = CommandContext {
        cwd: Some("/caller directory".into()),
    };
    for line in [
        "# comment",
        "FOO=1",
        "&&",
        "''",
        "'unmatched",
        "echo $(id); # comment\nrm -rf x",
        "`id` > out",
        "$env:X = 'x'; & Remove-Item C:\\a -Recurse",
        "echo\r\nnext\u{202e}",
    ] {
        let record = action_from_command(line, &ctx).expect("nonblank text must be carried");
        assert_eq!(
            serde_json::to_value(record).unwrap(),
            json!({
                "record_schema_version": 3, "surface": "command",
                "facts": {"raw": line, "cwd": "/caller directory"}
            }),
            "{line:?}"
        );
    }
}

/// Even an empty word or assignment-looking element is a caller fact; only a vector with zero
/// elements is empty. Quoting is an approver responsibility and never changes these values.
#[test]
fn argv_is_supplied_not_interpreted() {
    for argv in [
        vec![""],
        vec!["FOO=1"],
        vec!["&&"],
        vec!["", "a b", "$HOME", "'", "\n"],
    ] {
        let argv: Vec<String> = argv.into_iter().map(str::to_owned).collect();
        let record =
            action_from_argv(&argv, Some("opaque original"), &CommandContext::default()).unwrap();
        assert_eq!(
            serde_json::to_value(record).unwrap(),
            json!({
                "record_schema_version": 3, "surface": "command",
                "facts": {"raw": "opaque original", "argv": argv}
            })
        );
    }
}

/// Empty presentation is refused without learning the meaning of any nonblank line.
#[test]
fn empty_inputs_fail_closed() {
    let ctx = CommandContext::default();
    for line in ["", " \t\r\n", "\u{a0}\u{3000}"] {
        assert_eq!(
            action_from_command(line, &ctx).unwrap_err().code(),
            "no_command"
        );
    }
    assert_eq!(
        action_from_argv(&[], Some("not a substitute for argv"), &ctx)
            .unwrap_err()
            .code(),
        "no_command"
    );
}

/// Removed parsing-only fields obey the existing unknown-field contract: no retention, rendering
/// or hashing of a legacy scanner's guesses. Known malformed fields remain errors.
#[test]
fn removed_fields_are_ignored_and_known_malformed_fields_are_refused() {
    let raw = json!({"raw": "ssh $HOST", "cwd": "/repo", "argv": ["ssh", "$HOST"],
        "bin": {"malformed": true}, "flags": false, "positionals": 4, "env_refs": "HOME", "host": [1]});
    let substrate: allw_core::Facts = serde_json::from_value(raw).unwrap();
    assert_eq!(
        serde_json::to_value(substrate).unwrap(),
        json!({"raw": "ssh $HOST", "cwd": "/repo", "argv": ["ssh", "$HOST"]})
    );
    for malformed in [
        json!({"argv": "ssh"}),
        json!({"argv": [4]}),
        json!({"raw": []}),
        json!({"cwd": 1}),
    ] {
        assert!(serde_json::from_value::<allw_core::Facts>(malformed).is_err());
    }
}

/// Contract/JCS anchors were independently calculated with Python, never captured from core output.
/// The request anchor is shared with WASM; audit hashing is Rust-owned and has no surface API.
#[test]
fn independently_pinned_request_and_audit_digests() {
    use allw_core::{
        canonical_request_bytes, compute_record_hash, compute_request_hash, ApprovalContext,
        AuditRecord,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/opaque_hash_vector.json")).unwrap();
    let mut input: serde_json::Value =
        serde_json::from_str(vector["request_canonical"].as_str().unwrap()).unwrap();
    let expires = input
        .as_object_mut()
        .unwrap()
        .remove("expires_at")
        .unwrap()
        .as_i64()
        .unwrap();
    let context: ApprovalContext = serde_json::from_value(input).unwrap();
    assert_eq!(
        String::from_utf8(canonical_request_bytes(&context, expires)).unwrap(),
        vector["request_canonical"]
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(compute_request_hash(&context, expires)),
        vector["request_hash_b64"]
    );
    let record: AuditRecord = serde_json::from_value(vector["audit"].clone()).unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(compute_record_hash(&record)),
        vector["audit_hash_b64"]
    );
}
