use allw_core::{
    action_from_argv, action_from_mcp_tool_call, evaluate, evaluate_for_actor, sign_policy_rule,
    verify_policy_rule, Actor, Approver, CommandContext, Decision, PolicyDecision, PolicyEffect,
    PolicyPredicate, PolicyProvenance, PolicyRuleScope, PolicyTier, Risk, SigningKeyPair, Surface,
    SyntacticSubstrate, UnsignedPolicyRule, Verdict,
};
use serde_json::json;

const DEVICE_SEED: [u8; 32] = [0x42; 32];
const OTHER_DEVICE_SEED: [u8; 32] = [0x24; 32];

fn actor() -> Actor {
    Actor {
        id: "machine:macbook".to_string(),
        kind: "claude-code".to_string(),
        attestation: None,
    }
}

fn device_key() -> SigningKeyPair {
    SigningKeyPair::from_seed(&DEVICE_SEED)
}

fn signed(rule: UnsignedPolicyRule) -> allw_core::VerifiedPolicyRule {
    let key = device_key();
    let signed = sign_policy_rule(&rule, "device:phone", &key);
    verify_policy_rule(&signed, &key.public_key()).expect("test rule must verify")
}

fn git_force_action() -> allw_core::ActionRecord {
    let argv = ["git", "push", "--force", "origin", "main"].map(String::from);
    action_from_argv(&argv, &CommandContext::default())
}

fn command_action_with_syntactic(syntactic: SyntacticSubstrate) -> allw_core::ActionRecord {
    allw_core::ActionRecord {
        record_schema_version: 1,
        surface: Surface::Command,
        syntactic,
        risk: Risk::High,
        capabilities: None,
        scope: None,
    }
}

#[test]
fn precedence_is_deny_then_ask_then_allow_and_no_match_escalates() {
    let action = git_force_action();
    let actor = actor();

    let allow_git = signed(UnsignedPolicyRule {
        id: "allow-git".to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate::command_bin("git"),
        effect: PolicyEffect::Allow,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: 1_700_000_000_000,
        expires_at: None,
    });
    let ask_force = signed(UnsignedPolicyRule {
        id: "ask-force".to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate::command_bin("git")
            .with_flag("--force")
            .with_args_any_glob("*force*"),
        effect: PolicyEffect::Ask,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: 1_700_000_000_000,
        expires_at: None,
    });
    let deny_force = signed(UnsignedPolicyRule {
        id: "deny-force".to_string(),
        subject: allw_core::ActorMatcher::Id {
            id: "machine:macbook".to_string(),
        },
        predicate: PolicyPredicate::command_bin("git").with_args_any_glob("*force*"),
        effect: PolicyEffect::Deny,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: 1_700_000_000_000,
        expires_at: None,
    });

    let decision = evaluate_for_actor(&actor, &action, &[allow_git.clone(), ask_force.clone()]);
    assert_eq!(decision.decision, PolicyDecision::Escalate);
    assert_eq!(decision.rule_id.as_deref(), Some("ask-force"));

    let decision = evaluate_for_actor(&actor, &action, &[allow_git, ask_force, deny_force]);
    assert_eq!(decision.decision, PolicyDecision::Deny);
    assert_eq!(decision.rule_id.as_deref(), Some("deny-force"));

    let unrelated = action_from_mcp_tool_call("github", "list_issues", json!({}));
    assert_eq!(evaluate(&unrelated, &[]).decision, PolicyDecision::Escalate);
}

#[test]
fn signed_policy_rule_rejects_tampering_and_wrong_device_key() {
    let key = device_key();
    let other_key = SigningKeyPair::from_seed(&OTHER_DEVICE_SEED);
    let unsigned = UnsignedPolicyRule {
        id: "allow-ls".to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate::command_bin("ls"),
        effect: PolicyEffect::Allow,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: 1_700_000_000_000,
        expires_at: None,
    };

    let mut signed_rule = sign_policy_rule(&unsigned, "device:phone", &key);
    verify_policy_rule(&signed_rule, &key.public_key()).expect("freshly signed rule verifies");

    assert!(
        verify_policy_rule(&signed_rule, &other_key.public_key()).is_err(),
        "a different device key must not verify the signed rule"
    );

    signed_rule.effect = PolicyEffect::Deny;
    assert!(
        verify_policy_rule(&signed_rule, &key.public_key()).is_err(),
        "changing policy fields after signing must invalidate the rule"
    );
}

#[test]
fn from_approval_exact_call_round_trips_and_allows_only_the_same_command() {
    let actor = actor();
    let action = git_force_action();
    let unsigned = UnsignedPolicyRule::from_approval(
        "approval-exact",
        &actor,
        &action,
        PolicyRuleScope::ExactCall,
        1_700_000_000_000,
    )
    .expect("tokenized command can emit an exact-call rule");
    assert_eq!(unsigned.provenance, PolicyProvenance::FromApproval);
    assert_eq!(unsigned.tier, PolicyTier::Syntactic);
    assert_eq!(unsigned.effect, PolicyEffect::Allow);

    let key = device_key();
    let signed_rule = sign_policy_rule(&unsigned, "device:phone", &key);
    let json = serde_json::to_string(&signed_rule).expect("policy rule serializes");
    let round_tripped = serde_json::from_str(&json).expect("policy rule deserializes");
    let verified =
        verify_policy_rule(&round_tripped, &key.public_key()).expect("round trip verifies");

    assert_eq!(
        evaluate_for_actor(&actor, &action, std::slice::from_ref(&verified)).decision,
        PolicyDecision::Allow
    );

    let changed_argv = ["git", "push", "--force-with-lease", "origin", "main"].map(String::from);
    let changed_action = action_from_argv(&changed_argv, &CommandContext::default());
    assert_eq!(
        evaluate_for_actor(&actor, &changed_action, &[verified]).decision,
        PolicyDecision::Escalate,
        "an exact-call rule must not widen into a scoped verdict"
    );
}

#[test]
fn from_approval_exact_call_uses_raw_command_when_argv_is_unavailable() {
    let actor = actor();
    let action = command_action_with_syntactic(SyntacticSubstrate {
        bin: None,
        argv: None,
        flags: None,
        positionals: None,
        cwd: None,
        host: None,
        env_refs: None,
        server: None,
        tool: None,
        params: None,
        raw: Some("git push --force origin main".to_string()),
    });
    let verified = signed(
        UnsignedPolicyRule::from_approval(
            "approval-raw-exact",
            &actor,
            &action,
            PolicyRuleScope::ExactCall,
            1_700_000_000_000,
        )
        .expect("raw command text is enough to emit an exact-call rule"),
    );

    assert_eq!(
        evaluate_for_actor(&actor, &action, std::slice::from_ref(&verified)).decision,
        PolicyDecision::Allow,
        "the exact-call rule should match the raw command it was emitted from"
    );

    let changed_action = command_action_with_syntactic(SyntacticSubstrate {
        raw: Some("git push --force-with-lease origin main".to_string()),
        ..action.syntactic
    });
    assert_eq!(
        evaluate_for_actor(&actor, &changed_action, &[verified]).decision,
        PolicyDecision::Escalate,
        "raw-only exact-call rules must not widen to every command"
    );
}

#[test]
fn from_approval_exact_call_rejects_unrepresentable_command_shape() {
    let actor = actor();
    let action = command_action_with_syntactic(SyntacticSubstrate {
        bin: Some("git".to_string()),
        argv: None,
        flags: None,
        positionals: None,
        cwd: None,
        host: None,
        env_refs: None,
        server: None,
        tool: None,
        params: None,
        raw: None,
    });

    assert!(
        UnsignedPolicyRule::from_approval(
            "approval-bin-only",
            &actor,
            &action,
            PolicyRuleScope::ExactCall,
            1_700_000_000_000,
        )
        .is_err(),
        "a bin-only command cannot safely become an exact-call allow rule"
    );
}

#[test]
fn from_approval_mcp_param_rule_allows_matching_future_call_only() {
    let actor = actor();
    let action = action_from_mcp_tool_call(
        "omnifocus",
        "delete_project",
        json!({ "project_id": "abc", "list": "Agent Inbox" }),
    );
    let verified = signed(
        UnsignedPolicyRule::from_approval(
            "approval-param",
            &actor,
            &action,
            PolicyRuleScope::McpParamEquals {
                path: "list".to_string(),
            },
            1_700_000_000_000,
        )
        .expect("MCP param rule can be emitted from an MCP action"),
    );

    let matching = action_from_mcp_tool_call(
        "omnifocus",
        "delete_project",
        json!({ "project_id": "other", "list": "Agent Inbox" }),
    );
    let different_list = action_from_mcp_tool_call(
        "omnifocus",
        "delete_project",
        json!({ "project_id": "abc", "list": "Someday" }),
    );

    assert_eq!(
        evaluate_for_actor(&actor, &matching, std::slice::from_ref(&verified)).decision,
        PolicyDecision::Allow
    );
    assert_eq!(
        evaluate_for_actor(&actor, &different_list, &[verified]).decision,
        PolicyDecision::Escalate
    );
}

#[test]
fn syntactic_policy_ignores_reserved_semantic_fields() {
    let mut action = git_force_action();
    action.capabilities = Some(vec![json!({ "capability": "filesystem.delete" })]);
    action.scope = Some(json!({ "path": "/tmp" }));

    let verified = signed(UnsignedPolicyRule {
        id: "allow-git".to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate::command_bin("git"),
        effect: PolicyEffect::Allow,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: 1_700_000_000_000,
        expires_at: None,
    });

    assert_eq!(
        evaluate(&action, &[verified]).decision,
        PolicyDecision::Allow,
        "T1 must not infer from or depend on capabilities/scope; those are T3-only"
    );
}

#[test]
fn verdict_wire_shape_stays_one_shot_and_scope_free() {
    let verdict = Verdict {
        v: 1,
        request_id: "req-1".to_string(),
        request_hash: [0x11; 32],
        decision: Decision::Approved,
        decided_at: 1_700_000_000_000,
        approver: Approver {
            account_id: "acct".to_string(),
            device_id: "device:phone".to_string(),
        },
        note: None,
        challenge_response: None,
        sig: "header.payload.signature".to_string(),
        device_cert: None,
    };

    let json = serde_json::to_value(verdict).expect("verdict serializes");
    assert!(json.get("scope").is_none());
    assert!(json.get("rule_id").is_none());
    assert!(json.get("policy_rule").is_none());
}
