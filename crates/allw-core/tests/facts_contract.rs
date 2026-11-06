//! Wire-name contract for opaque caller facts, independent of Rust member names.
//! @see docs/action-record.md and docs/contract.md — Unknown fields and request_hash.
use allw_core::{action_from_command, display_model, ApprovalContext, CommandContext};
use serde_json::json;

/// Current writers expose only facts; old names never alias the required current member.
#[test]
fn facts_is_required_and_old_key_is_only_an_unknown_field() {
    let action = action_from_command("git push", &CommandContext::default()).unwrap();
    assert_eq!(
        serde_json::to_value(&action).unwrap(),
        json!({
            "record_schema_version": 3, "surface": "command", "facts": {"raw": "git push"}
        })
    );
    let mut wire = json!({
        "action": {"record_schema_version": 3, "surface": "command", "facts": {"raw": "git push"}},
        "summary": "Publish", "actor": {"id": "script", "kind": "script"},
        "constraints": {"allowed_decisions": ["approved", "denied"], "challenge_required": false}
    });
    let ctx: ApprovalContext = serde_json::from_value(wire.clone()).unwrap();
    let model = serde_json::to_value(display_model(&ctx)).unwrap();
    assert_eq!(
        model["facts"],
        json!({"raw": "git push", "raw_lines": ["git push"]})
    );
    assert!(model.get("syntactic").is_none());
    // Unknown fields keep serde's ignore behavior, even when malformed; they cannot override facts.
    wire["action"]["syntactic"] = json!(false);
    assert_eq!(
        serde_json::from_value::<ApprovalContext>(wire.clone()).unwrap(),
        ctx
    );
    wire["action"].as_object_mut().unwrap().remove("facts");
    assert!(serde_json::from_value::<ApprovalContext>(wire.clone()).is_err());
    wire["action"]["facts"] = json!({"raw": []});
    assert!(serde_json::from_value::<ApprovalContext>(wire).is_err());
}
