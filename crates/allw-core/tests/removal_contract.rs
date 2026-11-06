//! Contract outcomes for #406: the caller supplies facts, never a danger tier.
//! @see docs/contract.md §ApprovalContext and §request_hash.

use allw_core::{compute_request_hash, ApprovalContext};
use serde_json::json;

/// A caller need not assert reversibility. Old danger/policy slots are unknown JSON fields,
/// following serde's existing ignore-unknown contract rather than creating a compatibility mode.
#[test]
fn facts_only_context_and_optional_caller_assertion() {
    let wire = json!({
        "action": {"record_schema_version": 3, "surface": "command", "syntactic": {"raw": "git push"}},
        "summary": "Publish commits", "actor": {"id": "script", "kind": "script"},
        "constraints": {"allowed_decisions": ["approved", "denied"], "challenge_required": false}
    });
    let ctx: ApprovalContext =
        serde_json::from_value(wire.clone()).expect("facts-only context is valid");
    let encoded = serde_json::to_value(&ctx).unwrap();
    assert!(encoded.get("risk").is_none());
    assert!(encoded.get("reversible").is_none());
    for field in ["risk", "capabilities", "scope"] {
        assert!(encoded["action"].get(field).is_none());
    }
    let hash = compute_request_hash(&ctx, 1_800_000_060_000);
    for assertion in [true, false] {
        let mut asserted = wire.clone();
        asserted["reversible"] = json!(assertion);
        let asserted: ApprovalContext = serde_json::from_value(asserted).unwrap();
        assert_ne!(hash, compute_request_hash(&asserted, 1_800_000_060_000));
    }
    let mut unknown = wire;
    unknown["risk"] = json!("critical");
    unknown["action"]["risk"] = json!("high");
    unknown["action"]["capabilities"] = json!([]);
    unknown["action"]["scope"] = json!({});
    let ignored: ApprovalContext = serde_json::from_value(unknown).unwrap();
    assert_eq!(ctx, ignored);
    assert_ne!(hash, compute_request_hash(&ctx, 1_800_000_060_001));
}

/// Every displayed caller fact and lifecycle value is signed indirectly through request_hash.
#[test]
fn every_shown_fact_changes_hash() {
    let base = json!({
        "action": {"record_schema_version": 3, "surface": "command", "syntactic": {
            "raw": "git push", "argv": ["git", "push"], "cwd": "/repo",
            "server": "server", "tool": "tool", "params": {"x": 1}, "operation": "write",
            "paths": ["a"], "diff_summary": "edit", "diff_hash": "digest"
        }}, "summary": "Publish", "actor": {"id": "script", "kind": "script"},
        "reversible": true, "chain": ["upstream"],
        "constraints": {"allowed_decisions": ["approved", "denied"], "challenge_required": false}
    });
    let ctx: ApprovalContext = serde_json::from_value(base.clone()).unwrap();
    let hash = compute_request_hash(&ctx, 1_800_000_060_000);
    // Sign the fully populated context with a fixed fixture device. Each mutation below must
    // fail real verdict verification, not merely produce a different standalone hash.
    use allw_core::{
        sign_verdict, verify_verdict, ApprovalRequest, InMemoryNonceStore, PublicKey,
        SigningKeyPair, UnsignedVerdict, Verdict, VerifyError,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/wasm_vector.json")).unwrap();
    let template: Verdict =
        serde_json::from_str(fixture["verdict_json"].as_str().unwrap()).unwrap();
    let mut request: ApprovalRequest =
        serde_json::from_str(fixture["request_json"].as_str().unwrap()).unwrap();
    request.created_at = 1_800_000_000_000;
    request.expires_at = 1_800_000_060_000;
    let root: [u8; 32] = URL_SAFE_NO_PAD
        .decode(fixture["approver_root_pubkey_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let root = PublicKey::from_bytes(&root).unwrap();
    let verdict = sign_verdict(
        &UnsignedVerdict {
            v: 1,
            request_id: request.id.clone(),
            request_hash: hash,
            decision: allw_core::Decision::Approved,
            decided_at: 1_800_000_001_000,
            approver: template.approver,
            note: None,
            challenge_response: None,
        },
        &SigningKeyPair::from_seed(&[0x22; 32]),
        &[0x33; 16],
        template.device_cert,
    )
    .unwrap();
    let verify = |context: &ApprovalContext, request: &ApprovalRequest| {
        verify_verdict(
            &verdict,
            request,
            context,
            &root,
            &mut InMemoryNonceStore::default(),
            1_800_000_002_000,
        )
    };
    assert!(
        verify(&ctx, &request).is_ok(),
        "unmutated control must verify"
    );
    let mut later = request.clone();
    later.expires_at += 1;
    assert!(matches!(
        verify(&ctx, &later),
        Err(VerifyError::RequestHashMismatch)
    ));
    for (path, value) in [
        ("summary", json!("different")),
        ("actor.id", json!("other")),
        ("actor.kind", json!("other")),
        ("chain", json!(["other"])),
        ("reversible", json!(false)),
        ("reversible", json!(null)),
        ("constraints.challenge_required", json!(true)),
        ("constraints.allowed_decisions", json!(["denied"])),
        ("action.surface", json!("agent_tool_call")),
        ("action.syntactic.raw", json!("other")),
        ("action.syntactic.argv", json!(["other"])),
        ("action.syntactic.cwd", json!("other")),
        ("action.syntactic.server", json!("other")),
        ("action.syntactic.tool", json!("other")),
        ("action.syntactic.params", json!({"x": 2})),
        ("action.syntactic.operation", json!("other")),
        ("action.syntactic.paths", json!(["other"])),
        ("action.syntactic.diff_summary", json!("other")),
        ("action.syntactic.diff_hash", json!("other")),
    ] {
        let mut changed = base.clone();
        let mut target = &mut changed;
        let keys: Vec<_> = path.split('.').collect();
        for key in &keys[..keys.len() - 1] {
            target = &mut target[*key];
        }
        target[keys[keys.len() - 1]] = value;
        let changed: ApprovalContext = serde_json::from_value(changed).unwrap();
        assert_ne!(
            hash,
            compute_request_hash(&changed, 1_800_000_060_000),
            "{path}"
        );
        assert!(
            matches!(
                verify(&changed, &request),
                Err(VerifyError::RequestHashMismatch)
            ),
            "{path}"
        );
    }
}

/// An old signed receipt remains evidence, but cannot verify against the new canonical contract.
#[test]
fn old_verdict_is_preserved_but_unverifiable_under_new_hash() {
    use allw_core::{verify_verdict, InMemoryNonceStore, PublicKey, VerifyError};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    for legacy in [
        include_str!("fixtures/legacy_wire_v2.json"),
        include_str!("fixtures/legacy_wire_v3.json"),
    ] {
        let old: serde_json::Value = serde_json::from_str(legacy).unwrap();
        let verdict = serde_json::from_str(old["verdict_json"].as_str().unwrap()).unwrap();
        let request = serde_json::from_str(old["request_json"].as_str().unwrap()).unwrap();
        let context = serde_json::from_str(old["context_json"].as_str().unwrap()).unwrap();
        let root: [u8; 32] = URL_SAFE_NO_PAD
            .decode(old["approver_root_pubkey_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let root = PublicKey::from_bytes(&root).unwrap();
        assert!(matches!(
            verify_verdict(
                &verdict,
                &request,
                &context,
                &root,
                &mut InMemoryNonceStore::default(),
                old["now_ms"].as_i64().unwrap()
            ),
            Err(VerifyError::RequestHashMismatch)
        ));
        assert!(old["context_json"].as_str().unwrap().contains("bin"));
    }
}

/// A legacy receipt stays readable evidence; its original hash cannot verify under audit v2.
/// The fixture's old v1 hash was independently calculated over the specified ASCII-key JCS input.
#[test]
fn legacy_audit_is_readable_without_claiming_new_format_verification() {
    use allw_core::{compute_record_hash, AuditRecord};
    let raw = include_str!("fixtures/legacy_audit_v1.json");
    let old: AuditRecord = serde_json::from_str(raw).unwrap();
    assert_eq!(old.action.syntactic.raw.as_deref(), Some("git push"));
    assert!(!old.sig.is_empty());
    assert_ne!(old.record_hash, compute_record_hash(&old));
    // No migration/writer runs: the original artifact retains the old fields and signature.
    let original: serde_json::Value = serde_json::from_str(raw).unwrap();
    assert_eq!(original["action"]["risk"], "high");
    assert_eq!(original["policy"]["decision"], "escalate");
    assert_eq!(original["sig"].as_str(), Some(old.sig.as_str()));
}
