use allw_core::{
    action_from_argv, action_from_mcp_tool_call, evaluate, evaluate_for_actor, issue_device_cert,
    sign_policy_rule, sign_verdict, verify_policy_rule, verify_policy_rule_with_expected_account,
    Actor, Approver, CommandContext, Decision, PolicyDecision, PolicyEffect, PolicyPredicate,
    PolicyProvenance, PolicyRuleError, PolicyRuleScope, PolicyTier, Risk, SigningKeyPair, Surface,
    SyntacticSubstrate, UnsignedPolicyRule, UnsignedVerdict, Verdict,
};
use serde_json::json;

const DEVICE_SEED: [u8; 32] = [0x42; 32];
const OTHER_DEVICE_SEED: [u8; 32] = [0x24; 32];
const ROOT_SEED: [u8; 32] = [0x07; 32];
const OTHER_ROOT_SEED: [u8; 32] = [0x08; 32];
const ACCOUNT_ID: &str = "acct-policy";
const OTHER_ACCOUNT_ID: &str = "acct-other";
const DEVICE_ID: &str = "device:phone";
const OTHER_DEVICE_ID: &str = "device:watch";
const CREATED_AT: i64 = 1_700_000_000_000;
const NOW_OK: i64 = CREATED_AT + 1_000;

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

fn root_key() -> SigningKeyPair {
    SigningKeyPair::from_seed(&ROOT_SEED)
}

fn other_root_key() -> SigningKeyPair {
    SigningKeyPair::from_seed(&OTHER_ROOT_SEED)
}

fn device_cert() -> String {
    issue_device_cert(
        &root_key(),
        ACCOUNT_ID,
        DEVICE_ID,
        &device_key().public_key(),
        CREATED_AT,
        None,
    )
}

fn expired_device_cert() -> String {
    issue_device_cert(
        &root_key(),
        ACCOUNT_ID,
        DEVICE_ID,
        &device_key().public_key(),
        CREATED_AT,
        Some(CREATED_AT + 500),
    )
}

fn signed(rule: UnsignedPolicyRule) -> allw_core::VerifiedPolicyRule {
    let key = device_key();
    let signed = sign_policy_rule(&rule, DEVICE_ID, &key, Some(device_cert()));
    verify_policy_rule(&signed, &root_key().public_key(), NOW_OK).expect("test rule must verify")
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
        account_id: ACCOUNT_ID.to_string(),
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
        account_id: ACCOUNT_ID.to_string(),
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
        account_id: ACCOUNT_ID.to_string(),
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
        account_id: ACCOUNT_ID.to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate::command_bin("ls"),
        effect: PolicyEffect::Allow,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: 1_700_000_000_000,
        expires_at: None,
    };

    let mut signed_rule = sign_policy_rule(&unsigned, DEVICE_ID, &key, Some(device_cert()));
    verify_policy_rule(&signed_rule, &root_key().public_key(), NOW_OK)
        .expect("freshly signed rule verifies");

    let forged = sign_policy_rule(&unsigned, DEVICE_ID, &other_key, Some(device_cert()));
    assert!(
        verify_policy_rule(&forged, &root_key().public_key(), NOW_OK).is_err(),
        "a policy rule signed by an uncertified device key must not verify"
    );

    signed_rule.effect = PolicyEffect::Deny;
    assert!(
        verify_policy_rule(&signed_rule, &root_key().public_key(), NOW_OK).is_err(),
        "changing policy fields after signing must invalidate the rule"
    );
}

#[test]
fn signed_policy_rule_requires_account_root_cert_chain_and_matching_kid() {
    let unsigned = UnsignedPolicyRule {
        id: "allow-ls".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate::command_bin("ls"),
        effect: PolicyEffect::Allow,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: CREATED_AT,
        expires_at: None,
    };

    let valid = sign_policy_rule(&unsigned, DEVICE_ID, &device_key(), Some(device_cert()));
    assert_eq!(
        verify_policy_rule(&valid, &other_root_key().public_key(), NOW_OK),
        Err(PolicyRuleError::CertSignatureInvalid),
        "a policy rule must not verify under the wrong account root"
    );

    let wrong_account = UnsignedPolicyRule {
        account_id: OTHER_ACCOUNT_ID.to_string(),
        ..unsigned.clone()
    };
    let wrong_account_rule = sign_policy_rule(
        &wrong_account,
        DEVICE_ID,
        &device_key(),
        Some(device_cert()),
    );
    assert_eq!(
        verify_policy_rule(&wrong_account_rule, &root_key().public_key(), NOW_OK),
        Err(PolicyRuleError::CertAccountMismatch),
        "the signed policy account_id must match the certified account"
    );

    let wrong_kid = sign_policy_rule(
        &unsigned,
        OTHER_DEVICE_ID,
        &device_key(),
        Some(device_cert()),
    );
    assert_eq!(
        verify_policy_rule(&wrong_kid, &root_key().public_key(), NOW_OK),
        Err(PolicyRuleError::CertDeviceMismatch),
        "the policy JWS kid must match the certified device id"
    );

    let missing_cert = sign_policy_rule(&unsigned, DEVICE_ID, &device_key(), None);
    assert_eq!(
        verify_policy_rule(&missing_cert, &root_key().public_key(), NOW_OK),
        Err(PolicyRuleError::MissingDeviceCert),
        "policy rules must carry a device cert so verification chains to the account root"
    );

    let expired_cert_rule = sign_policy_rule(
        &unsigned,
        DEVICE_ID,
        &device_key(),
        Some(expired_device_cert()),
    );
    assert_eq!(
        verify_policy_rule(&expired_cert_rule, &root_key().public_key(), NOW_OK),
        Err(PolicyRuleError::CertExpired),
        "policy rules must reject expired device certs on the policy verification path"
    );

    assert!(
        verify_policy_rule_with_expected_account(
            &valid,
            &root_key().public_key(),
            NOW_OK,
            Some(ACCOUNT_ID),
        )
        .is_ok(),
        "matching expected account must preserve policy verification"
    );
    assert_eq!(
        verify_policy_rule_with_expected_account(
            &valid,
            &root_key().public_key(),
            NOW_OK,
            Some(OTHER_ACCOUNT_ID),
        ),
        Err(PolicyRuleError::CertAccountMismatch),
        "a caller-supplied expected account must fail closed when it does not match the rule"
    );
}

#[test]
fn signed_policy_rule_rejects_cross_typ_jws_confusion() {
    let unsigned = UnsignedPolicyRule {
        id: "allow-ls".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate::command_bin("ls"),
        effect: PolicyEffect::Allow,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: CREATED_AT,
        expires_at: None,
    };

    let verdict = sign_verdict(
        &UnsignedVerdict {
            v: 1,
            request_id: "req-policy-confusion".to_string(),
            request_hash: [0x11; 32],
            decision: Decision::Approved,
            decided_at: CREATED_AT,
            approver: Approver {
                account_id: ACCOUNT_ID.to_string(),
                device_id: DEVICE_ID.to_string(),
            },
            note: None,
            challenge_response: None,
        },
        &device_key(),
        &[0x01, 0x02, 0x03, 0x04],
        Some(device_cert()),
    );
    let mut rule = sign_policy_rule(&unsigned, DEVICE_ID, &device_key(), Some(device_cert()));
    rule.sig = verdict.sig;

    assert_eq!(
        verify_policy_rule(&rule, &root_key().public_key(), NOW_OK),
        Err(PolicyRuleError::UnexpectedTyp),
        "a verdict JWS must not be accepted as a policy-rule JWS"
    );
}

#[test]
fn signed_policy_rule_rejects_unenforced_expiry_and_bounds() {
    let key = device_key();
    let base = UnsignedPolicyRule {
        id: "allow-git".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate::command_bin("git"),
        effect: PolicyEffect::Allow,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: 1_700_000_000_000,
        expires_at: None,
    };

    let mut expiring = base.clone();
    expiring.expires_at = Some(1_700_000_060_000);
    let signed_expiring = sign_policy_rule(&expiring, DEVICE_ID, &key, Some(device_cert()));
    assert_eq!(
        verify_policy_rule(&signed_expiring, &root_key().public_key(), NOW_OK),
        Err(PolicyRuleError::UnsupportedBounds),
        "expires_at must not silently no-op until evaluate has a clock"
    );

    let mut bounded = base;
    bounded.bounds = Some(json!({ "max_uses": 1 }));
    let signed_bounded = sign_policy_rule(&bounded, DEVICE_ID, &key, Some(device_cert()));
    assert_eq!(
        verify_policy_rule(&signed_bounded, &root_key().public_key(), NOW_OK),
        Err(PolicyRuleError::UnsupportedBounds),
        "bounds must not silently no-op until evaluate has usage state"
    );
}

#[test]
fn signed_policy_rule_rejects_empty_predicate() {
    let key = device_key();
    let empty_match = UnsignedPolicyRule {
        id: "empty-predicate".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate {
            surface: None,
            command: None,
            mcp: None,
        },
        effect: PolicyEffect::Allow,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: 1_700_000_000_000,
        expires_at: None,
    };
    let signed_empty = sign_policy_rule(&empty_match, DEVICE_ID, &key, Some(device_cert()));

    assert_eq!(
        verify_policy_rule(&signed_empty, &root_key().public_key(), NOW_OK),
        Err(PolicyRuleError::EmptyPredicate),
        "a signed manual policy with an empty predicate must not become a match-everything allow"
    );
}

#[test]
fn args_any_glob_matches_structured_tokens_not_raw_or_substrings() {
    let rule = signed(UnsignedPolicyRule {
        id: "allow-build-dir".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        subject: allw_core::ActorMatcher::Any,
        predicate: PolicyPredicate::command_bin("rm").with_args_any_glob("build"),
        effect: PolicyEffect::Allow,
        bounds: None,
        provenance: PolicyProvenance::Manual,
        tier: PolicyTier::Syntactic,
        created_at: 1_700_000_000_000,
        expires_at: None,
    });

    let exact_token = ["rm", "-rf", "build"].map(String::from);
    let exact_token_action = action_from_argv(&exact_token, &CommandContext::default());
    assert_eq!(
        evaluate(&exact_token_action, std::slice::from_ref(&rule)).decision,
        PolicyDecision::Allow,
        "a non-glob pattern matches the exact structured token"
    );

    let prefixed_token = ["rm", "-rf", "build-prod"].map(String::from);
    let prefixed_token_action = action_from_argv(&prefixed_token, &CommandContext::default());
    assert_eq!(
        evaluate(&prefixed_token_action, std::slice::from_ref(&rule)).decision,
        PolicyDecision::Escalate,
        "a non-glob pattern must not substring-match another token"
    );

    let raw_only = command_action_with_syntactic(SyntacticSubstrate {
        bin: Some("rm".to_string()),
        argv: None,
        flags: None,
        positionals: None,
        cwd: None,
        host: None,
        env_refs: None,
        server: None,
        tool: None,
        params: None,
        raw: Some("rm -rf build".to_string()),
    });
    assert_eq!(
        evaluate(&raw_only, &[rule]).decision,
        PolicyDecision::Escalate,
        "args_any_globs must not match across raw shell text"
    );
}

#[test]
fn from_approval_exact_call_round_trips_and_allows_only_the_same_command() {
    let actor = actor();
    let action = git_force_action();
    let unsigned = UnsignedPolicyRule::from_approval(
        "approval-exact",
        ACCOUNT_ID,
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
    let signed_rule = sign_policy_rule(&unsigned, DEVICE_ID, &key, Some(device_cert()));
    let json = serde_json::to_string(&signed_rule).expect("policy rule serializes");
    let round_tripped = serde_json::from_str(&json).expect("policy rule deserializes");
    let verified = verify_policy_rule(&round_tripped, &root_key().public_key(), NOW_OK)
        .expect("round trip verifies");

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
            ACCOUNT_ID,
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
            ACCOUNT_ID,
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
            ACCOUNT_ID,
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
        account_id: ACCOUNT_ID.to_string(),
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
