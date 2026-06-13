//! T1 syntactic policy rules for deciding whether an action can proceed locally.
//!
//! The policy layer runs **before** the human approval primitive. This module intentionally
//! implements only the v1 syntactic tier from `docs/policy-seam.md`: command names, argv/glob
//! checks, flags, MCP tool names, and MCP parameter equality/glob checks. It never reads or
//! infers from the reserved semantic `capabilities` / `scope` fields; those belong to the
//! deferred T3 engine.

use serde::{Deserialize, Serialize};

use crate::contract::{ActionRecord, Actor, PolicyDecision, Surface};
use crate::crypto::{
    account_state_revokes_device, decode_and_verify_jws, encode_compact_jws,
    verify_certified_device, DeviceCertError, JwsError, JwsHeader, PublicKey, SigningKeyPair,
    ALG_EDDSA,
};

const POLICY_SCHEMA_VERSION: u32 = 1;
const TYP_POLICY_RULE: &str = "allw-policy-rule+jws";

/// Which actor a rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ActorMatcher {
    /// Any actor may match this rule.
    Any,
    /// Only the actor with this stable ID may match.
    Id { id: String },
}

impl ActorMatcher {
    fn matches(&self, actor: Option<&Actor>) -> bool {
        match self {
            Self::Any => true,
            Self::Id { id } => actor.is_some_and(|actor| actor.id == *id),
        }
    }
}

/// The rule effect. `Ask` maps to [`PolicyDecision::Escalate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Ask,
    Deny,
}

/// Why a rule exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProvenance {
    Manual,
    FromApproval,
}

/// Policy tier that produced the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTier {
    Syntactic,
    Semantic,
}

/// Rule-scope choices the approver UI can derive from a syntactic action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PolicyRuleScope {
    /// Match this exact command argv or MCP params payload.
    ExactCall,
    /// Match the command binary or MCP server/tool regardless of arguments.
    CommandOrToolAnyArgs,
    /// Match an MCP tool call only when the value at `path` equals the approved call's value.
    McpParamEquals { path: String },
    /// Match a command when any structured argv/positional token satisfies this pattern.
    ArgsAnyGlob { pattern: String },
}

/// A syntactic predicate over an [`ActionRecord`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPredicate {
    /// Surface guard. When present, a different surface never matches.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub surface: Option<Surface>,

    /// Command-surface matcher.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub command: Option<CommandMatcher>,

    /// MCP tool-call matcher.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mcp: Option<McpMatcher>,
}

impl PolicyPredicate {
    /// Match any command action with the given binary name.
    #[must_use]
    pub fn command_bin(bin: &str) -> Self {
        Self {
            surface: Some(Surface::Command),
            command: Some(CommandMatcher {
                bin: Some(bin.to_string()),
                ..CommandMatcher::default()
            }),
            mcp: None,
        }
    }

    /// Match an MCP tool call by server and tool.
    #[must_use]
    pub fn mcp_tool(server: &str, tool: &str) -> Self {
        Self {
            surface: Some(Surface::McpToolCall),
            command: None,
            mcp: Some(McpMatcher {
                server: Some(server.to_string()),
                tool: Some(tool.to_string()),
                ..McpMatcher::default()
            }),
        }
    }

    /// Require a command flag token to be present exactly.
    #[must_use]
    pub fn with_flag(mut self, flag: &str) -> Self {
        let command = self.command.get_or_insert_with(CommandMatcher::default);
        command.flags.push(flag.to_string());
        self
    }

    /// Require at least one structured argument token to match this exact string or glob pattern.
    #[must_use]
    pub fn with_args_any_glob(mut self, pattern: &str) -> Self {
        let command = self.command.get_or_insert_with(CommandMatcher::default);
        command.args_any_globs.push(pattern.to_string());
        self
    }

    fn matches(&self, action: &ActionRecord) -> bool {
        if self
            .surface
            .is_some_and(|surface| surface != action.surface)
        {
            return false;
        }
        if let Some(command) = &self.command {
            if action.surface != Surface::Command || !command.matches(action) {
                return false;
            }
        }
        if let Some(mcp) = &self.mcp {
            if action.surface != Surface::McpToolCall || !mcp.matches(action) {
                return false;
            }
        }
        true
    }

    fn is_empty(&self) -> bool {
        self.surface.is_none() && self.command.is_none() && self.mcp.is_none()
    }
}

/// Command-surface T1 matcher.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CommandMatcher {
    /// Exact binary name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bin: Option<String>,

    /// Exact full argv vector, including the binary.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub argv_exact: Option<Vec<String>>,

    /// Exact raw command string, used only when an integrator cannot provide argv.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub raw_exact: Option<String>,

    /// Required flag tokens.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub flags: Vec<String>,

    /// Exact/glob patterns; each pattern must match at least one structured syntactic token.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub args_any_globs: Vec<String>,
}

impl CommandMatcher {
    fn matches(&self, action: &ActionRecord) -> bool {
        let syntactic = &action.syntactic;
        if self
            .bin
            .as_ref()
            .is_some_and(|bin| syntactic.bin.as_ref() != Some(bin))
        {
            return false;
        }
        if self
            .argv_exact
            .as_ref()
            .is_some_and(|argv| syntactic.argv.as_ref() != Some(argv))
        {
            return false;
        }
        if self
            .raw_exact
            .as_ref()
            .is_some_and(|raw| syntactic.raw.as_ref() != Some(raw))
        {
            return false;
        }
        if !self.flags.is_empty() {
            let Some(action_flags) = &syntactic.flags else {
                return false;
            };
            if !self.flags.iter().all(|flag| action_flags.contains(flag)) {
                return false;
            }
        }
        if !self.args_any_globs.is_empty() {
            let candidates = command_candidates(action);
            if !self.args_any_globs.iter().all(|pattern| {
                candidates
                    .iter()
                    .any(|candidate| string_matches_pattern(candidate, pattern))
            }) {
                return false;
            }
        }
        true
    }
}

/// MCP tool-call T1 matcher.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct McpMatcher {
    /// Exact MCP server name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub server: Option<String>,

    /// Exact MCP tool name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool: Option<String>,

    /// Exact params value, used for "this exact call".
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub params_exact: Option<serde_json::Value>,

    /// Parameter-level matchers derived from the approved call.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub params: Vec<ParamMatcher>,
}

impl McpMatcher {
    fn matches(&self, action: &ActionRecord) -> bool {
        let syntactic = &action.syntactic;
        if self
            .server
            .as_ref()
            .is_some_and(|server| syntactic.server.as_ref() != Some(server))
        {
            return false;
        }
        if self
            .tool
            .as_ref()
            .is_some_and(|tool| syntactic.tool.as_ref() != Some(tool))
        {
            return false;
        }
        if self
            .params_exact
            .as_ref()
            .is_some_and(|params| syntactic.params.as_ref() != Some(params))
        {
            return false;
        }
        self.params
            .iter()
            .all(|matcher| matcher.matches(syntactic.params.as_ref()))
    }
}

/// Matcher for one MCP params path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParamMatcher {
    /// Dot-separated object path. Empty string means the whole params value.
    pub path: String,

    /// Required JSON value at the path.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub equals: Option<serde_json::Value>,

    /// Required string glob at the path.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub string_glob: Option<String>,
}

impl ParamMatcher {
    fn matches(&self, params: Option<&serde_json::Value>) -> bool {
        let Some(value) = params.and_then(|params| json_path(params, &self.path)) else {
            return false;
        };
        if self
            .equals
            .as_ref()
            .is_some_and(|expected| value != expected)
        {
            return false;
        }
        if let Some(pattern) = &self.string_glob {
            let Some(actual) = value.as_str() else {
                return false;
            };
            if !string_matches_pattern(actual, pattern) {
                return false;
            }
        }
        true
    }
}

/// A policy rule before it is signed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnsignedPolicyRule {
    pub id: String,
    /// Account whose root must certify the device key that signed this standing rule.
    pub account_id: String,
    pub subject: ActorMatcher,
    #[serde(rename = "match")]
    pub predicate: PolicyPredicate,
    pub effect: PolicyEffect,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bounds: Option<serde_json::Value>,
    pub provenance: PolicyProvenance,
    pub tier: PolicyTier,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<i64>,
}

impl UnsignedPolicyRule {
    /// Build the rule emitted by the "approve and don't ask again" affordance.
    pub fn from_approval(
        id: &str,
        account_id: &str,
        actor: &Actor,
        action: &ActionRecord,
        scope: PolicyRuleScope,
        created_at: i64,
    ) -> Result<Self, PolicyRuleBuildError> {
        Ok(Self {
            id: id.to_string(),
            account_id: account_id.to_string(),
            subject: ActorMatcher::Id {
                id: actor.id.clone(),
            },
            predicate: predicate_from_approval(action, scope)?,
            effect: PolicyEffect::Allow,
            bounds: None,
            provenance: PolicyProvenance::FromApproval,
            tier: PolicyTier::Syntactic,
            created_at,
            expires_at: None,
        })
    }
}

/// A signed policy rule. The signature covers every field except `sig`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    /// Account whose root must certify the device key that signed this standing rule.
    pub account_id: String,
    pub subject: ActorMatcher,
    #[serde(rename = "match")]
    pub predicate: PolicyPredicate,
    pub effect: PolicyEffect,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bounds: Option<serde_json::Value>,
    pub provenance: PolicyProvenance,
    pub tier: PolicyTier,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<i64>,
    /// Device-key compact JWS over the unsigned rule payload.
    pub sig: String,
    /// Account-root-signed certificate binding the signing device key to `account_id`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub device_cert: Option<String>,
}

impl PolicyRule {
    fn unsigned(&self) -> UnsignedPolicyRule {
        UnsignedPolicyRule {
            id: self.id.clone(),
            account_id: self.account_id.clone(),
            subject: self.subject.clone(),
            predicate: self.predicate.clone(),
            effect: self.effect,
            bounds: self.bounds.clone(),
            provenance: self.provenance,
            tier: self.tier,
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

/// A policy rule whose device-key signature has been verified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedPolicyRule {
    pub rule: PolicyRule,
    pub device_id: String,
}

/// Result of policy evaluation for one action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub rule_id: Option<String>,
    pub tier: PolicyTier,
    pub schema_version: u32,
}

/// Errors returned while verifying a signed policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRuleError {
    MissingDeviceCert,
    CertSignatureInvalid,
    CertAccountMismatch,
    ExpectedAccountMismatch,
    CertDeviceMismatch,
    CertExpired,
    AccountStateInvalid,
    DeviceRevoked,
    MalformedJws,
    UnexpectedAlg,
    UnexpectedTyp,
    BadSignature,
    PayloadMismatch,
    UnsupportedBounds,
    EmptyPredicate,
}

impl std::fmt::Display for PolicyRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDeviceCert => write!(
                f,
                "policy rule has no device_cert; cannot chain device key to account root"
            ),
            Self::CertSignatureInvalid => {
                write!(
                    f,
                    "policy-rule device cert did not verify against the account root key"
                )
            }
            Self::CertAccountMismatch => {
                write!(f, "policy-rule device cert account_id does not match rule")
            }
            Self::ExpectedAccountMismatch => {
                write!(
                    f,
                    "policy-rule account_id does not match expected account_id"
                )
            }
            Self::CertDeviceMismatch => {
                write!(f, "policy-rule JWS kid does not match the certified device")
            }
            Self::CertExpired => write!(f, "policy-rule device cert has expired"),
            Self::AccountStateInvalid => write!(f, "account state is invalid"),
            Self::DeviceRevoked => {
                write!(f, "policy-rule signing device is revoked by account state")
            }
            Self::MalformedJws => write!(f, "malformed policy-rule JWS"),
            Self::UnexpectedAlg => write!(f, "unexpected policy-rule JWS alg"),
            Self::UnexpectedTyp => write!(f, "unexpected policy-rule JWS typ"),
            Self::BadSignature => write!(f, "invalid policy-rule signature"),
            Self::PayloadMismatch => write!(f, "policy-rule JWS payload does not match outer rule"),
            Self::UnsupportedBounds => write!(
                f,
                "policy-rule expires_at/bounds are unsupported or matcher limits are exceeded"
            ),
            Self::EmptyPredicate => write!(f, "policy-rule predicate must constrain the action"),
        }
    }
}

impl std::error::Error for PolicyRuleError {}

/// Errors returned while deriving a standing policy rule from a one-shot approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRuleBuildError {
    UnrepresentableExactCommand,
    UnsupportedFileEditPolicyScope,
}

impl std::fmt::Display for PolicyRuleBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnrepresentableExactCommand => write!(
                f,
                "exact command policy requires either argv or raw command text"
            ),
            Self::UnsupportedFileEditPolicyScope => write!(
                f,
                "file_edit approval-derived policy scopes require file path/diff matchers"
            ),
        }
    }
}

impl std::error::Error for PolicyRuleBuildError {}

/// Sign a policy rule with a device key.
#[must_use]
pub fn sign_policy_rule(
    rule: &UnsignedPolicyRule,
    device_id: &str,
    device_key: &SigningKeyPair,
    device_cert: Option<String>,
) -> PolicyRule {
    let header = JwsHeader {
        alg: ALG_EDDSA.to_string(),
        typ: TYP_POLICY_RULE.to_string(),
        kid: device_id.to_string(),
    };
    let sig = encode_compact_jws(&header, rule, device_key);
    PolicyRule {
        id: rule.id.clone(),
        account_id: rule.account_id.clone(),
        subject: rule.subject.clone(),
        predicate: rule.predicate.clone(),
        effect: rule.effect,
        bounds: rule.bounds.clone(),
        provenance: rule.provenance,
        tier: rule.tier,
        created_at: rule.created_at,
        expires_at: rule.expires_at,
        sig,
        device_cert,
    }
}

/// Verify a signed policy rule against an account root, chaining through its device certificate.
pub fn verify_policy_rule(
    rule: &PolicyRule,
    account_root: &PublicKey,
    now_ms: i64,
) -> Result<VerifiedPolicyRule, PolicyRuleError> {
    verify_policy_rule_with_account_states(rule, account_root, now_ms, &[])
}

/// Verify a signed policy rule against an account root, additionally requiring the rule's account
/// namespace to match `expected_account_id`.
///
/// This is defense-in-depth for multi-account verifiers that know the account they intended to
/// verify independently of the root key they were handed.
pub fn verify_policy_rule_for_account(
    rule: &PolicyRule,
    account_root: &PublicKey,
    now_ms: i64,
    expected_account_id: &str,
) -> Result<VerifiedPolicyRule, PolicyRuleError> {
    verify_policy_rule_with_account_states_for_account(
        rule,
        account_root,
        now_ms,
        &[],
        expected_account_id,
    )
}

/// Verify a signed policy rule and reject rules signed by devices revoked in account state.
///
/// When multiple valid account-state documents are supplied, the highest `sequence` wins.
///
/// Callers must supply all known account-state documents, or at least their durably stored highest
/// sequence. Persisting monotonic state across verification calls is the integrator's
/// responsibility; passing only a stale document can make stale trust material look current.
pub fn verify_policy_rule_with_account_states(
    rule: &PolicyRule,
    account_root: &PublicKey,
    now_ms: i64,
    account_states: &[&str],
) -> Result<VerifiedPolicyRule, PolicyRuleError> {
    verify_policy_rule_with_account_states_impl(rule, account_root, now_ms, account_states, None)
}

/// Verify a signed policy rule like [`verify_policy_rule_with_account_states`], additionally
/// requiring the rule's account namespace to match `expected_account_id`.
pub fn verify_policy_rule_with_account_states_for_account(
    rule: &PolicyRule,
    account_root: &PublicKey,
    now_ms: i64,
    account_states: &[&str],
    expected_account_id: &str,
) -> Result<VerifiedPolicyRule, PolicyRuleError> {
    verify_policy_rule_with_account_states_impl(
        rule,
        account_root,
        now_ms,
        account_states,
        Some(expected_account_id),
    )
}

fn verify_policy_rule_with_account_states_impl(
    rule: &PolicyRule,
    account_root: &PublicKey,
    now_ms: i64,
    account_states: &[&str],
    expected_account_id: Option<&str>,
) -> Result<VerifiedPolicyRule, PolicyRuleError> {
    if expected_account_id.is_some_and(|expected| expected != rule.account_id) {
        return Err(PolicyRuleError::ExpectedAccountMismatch);
    }

    let cert = rule
        .device_cert
        .as_deref()
        .ok_or(PolicyRuleError::MissingDeviceCert)?;
    let certified = verify_certified_device(cert, &rule.account_id, account_root, now_ms).map_err(
        |e| match e {
            DeviceCertError::SignatureInvalid => PolicyRuleError::CertSignatureInvalid,
            DeviceCertError::AccountMismatch => PolicyRuleError::CertAccountMismatch,
            DeviceCertError::CertExpired => PolicyRuleError::CertExpired,
        },
    )?;
    if account_state_revokes_device(
        account_states,
        &rule.account_id,
        account_root,
        &certified.device_id,
    )
    .map_err(|_| PolicyRuleError::AccountStateInvalid)?
    {
        return Err(PolicyRuleError::DeviceRevoked);
    }

    let decoded = decode_and_verify_jws::<UnsignedPolicyRule>(
        &rule.sig,
        TYP_POLICY_RULE,
        &certified.public_key,
    )
    .map_err(policy_jws_error)?;
    if decoded.header.kid != certified.device_id {
        return Err(PolicyRuleError::CertDeviceMismatch);
    }
    if decoded.claims != rule.unsigned() {
        return Err(PolicyRuleError::PayloadMismatch);
    }
    if rule.expires_at.is_some() || rule.bounds.is_some() {
        return Err(PolicyRuleError::UnsupportedBounds);
    }
    if predicate_has_over_budget_pattern(&rule.predicate) {
        return Err(PolicyRuleError::UnsupportedBounds);
    }
    if rule.predicate.is_empty() {
        return Err(PolicyRuleError::EmptyPredicate);
    }
    Ok(VerifiedPolicyRule {
        rule: rule.clone(),
        device_id: certified.device_id,
    })
}

/// Evaluate policy rules without actor context. Only `ActorMatcher::Any` rules can match.
#[must_use]
pub fn evaluate(action: &ActionRecord, rules: &[VerifiedPolicyRule]) -> PolicyEvaluation {
    evaluate_inner(None, action, rules)
}

/// Evaluate policy rules with actor context.
#[must_use]
pub fn evaluate_for_actor(
    actor: &Actor,
    action: &ActionRecord,
    rules: &[VerifiedPolicyRule],
) -> PolicyEvaluation {
    evaluate_inner(Some(actor), action, rules)
}

fn evaluate_inner(
    actor: Option<&Actor>,
    action: &ActionRecord,
    rules: &[VerifiedPolicyRule],
) -> PolicyEvaluation {
    if action_has_over_budget_match_input(action) {
        return PolicyEvaluation {
            decision: PolicyDecision::Escalate,
            rule_id: None,
            tier: PolicyTier::Syntactic,
            schema_version: POLICY_SCHEMA_VERSION,
        };
    }

    let mut best: Option<(u8, &VerifiedPolicyRule)> = None;
    for verified in rules {
        let rule = &verified.rule;
        if rule.tier != PolicyTier::Syntactic {
            continue;
        }
        if !rule.subject.matches(actor) || !rule.predicate.matches(action) {
            continue;
        }
        let rank = match rule.effect {
            PolicyEffect::Deny => 3,
            PolicyEffect::Ask => 2,
            PolicyEffect::Allow => 1,
        };
        if best.is_none_or(|(best_rank, _)| rank > best_rank) {
            best = Some((rank, verified));
        }
    }

    let Some((_, verified)) = best else {
        return PolicyEvaluation {
            decision: PolicyDecision::Escalate,
            rule_id: None,
            tier: PolicyTier::Syntactic,
            schema_version: POLICY_SCHEMA_VERSION,
        };
    };

    let rule = &verified.rule;
    PolicyEvaluation {
        decision: match rule.effect {
            PolicyEffect::Allow => PolicyDecision::Allow,
            PolicyEffect::Ask => PolicyDecision::Escalate,
            PolicyEffect::Deny => PolicyDecision::Deny,
        },
        rule_id: Some(rule.id.clone()),
        tier: PolicyTier::Syntactic,
        schema_version: POLICY_SCHEMA_VERSION,
    }
}

fn predicate_from_approval(
    action: &ActionRecord,
    scope: PolicyRuleScope,
) -> Result<PolicyPredicate, PolicyRuleBuildError> {
    if action.surface == Surface::FileEdit {
        return Err(PolicyRuleBuildError::UnsupportedFileEditPolicyScope);
    }
    match scope {
        PolicyRuleScope::ExactCall => exact_call_predicate(action),
        PolicyRuleScope::CommandOrToolAnyArgs => Ok(command_or_tool_predicate(action)),
        PolicyRuleScope::McpParamEquals { path } => Ok(mcp_param_equals_predicate(action, &path)),
        PolicyRuleScope::ArgsAnyGlob { pattern } => {
            let mut predicate = command_or_tool_predicate(action);
            if action.surface == Surface::Command {
                predicate = predicate.with_args_any_glob(&pattern);
            }
            Ok(predicate)
        }
    }
}

fn exact_call_predicate(action: &ActionRecord) -> Result<PolicyPredicate, PolicyRuleBuildError> {
    match action.surface {
        Surface::Command => {
            let mut matcher = CommandMatcher::default();
            matcher.bin.clone_from(&action.syntactic.bin);
            if let Some(argv) = &action.syntactic.argv {
                matcher.argv_exact = Some(argv.clone());
            } else if let Some(raw) = &action.syntactic.raw {
                matcher.raw_exact = Some(raw.clone());
            } else {
                return Err(PolicyRuleBuildError::UnrepresentableExactCommand);
            }
            Ok(PolicyPredicate {
                surface: Some(Surface::Command),
                command: Some(matcher),
                mcp: None,
            })
        }
        Surface::McpToolCall => Ok(PolicyPredicate {
            surface: Some(Surface::McpToolCall),
            command: None,
            mcp: Some(McpMatcher {
                server: action.syntactic.server.clone(),
                tool: action.syntactic.tool.clone(),
                params_exact: action.syntactic.params.clone(),
                params: Vec::new(),
            }),
        }),
        // File-edit policy matchers are reserved for the next policy-schema expansion. A scoped
        // approval still narrows to the file-edit surface instead of widening to commands/MCP.
        Surface::FileEdit => Ok(PolicyPredicate {
            surface: Some(Surface::FileEdit),
            command: None,
            mcp: None,
        }),
    }
}

fn command_or_tool_predicate(action: &ActionRecord) -> PolicyPredicate {
    match action.surface {
        Surface::Command => PolicyPredicate {
            surface: Some(Surface::Command),
            command: Some(CommandMatcher {
                bin: action.syntactic.bin.clone(),
                ..CommandMatcher::default()
            }),
            mcp: None,
        },
        Surface::McpToolCall => PolicyPredicate {
            surface: Some(Surface::McpToolCall),
            command: None,
            mcp: Some(McpMatcher {
                server: action.syntactic.server.clone(),
                tool: action.syntactic.tool.clone(),
                ..McpMatcher::default()
            }),
        },
        Surface::FileEdit => PolicyPredicate {
            surface: Some(Surface::FileEdit),
            command: None,
            mcp: None,
        },
    }
}

fn mcp_param_equals_predicate(action: &ActionRecord, path: &str) -> PolicyPredicate {
    let equals = action
        .syntactic
        .params
        .as_ref()
        .and_then(|params| json_path(params, path))
        .cloned();
    PolicyPredicate {
        surface: Some(Surface::McpToolCall),
        command: None,
        mcp: Some(McpMatcher {
            server: action.syntactic.server.clone(),
            tool: action.syntactic.tool.clone(),
            params: vec![ParamMatcher {
                path: path.to_string(),
                equals,
                string_glob: None,
            }],
            ..McpMatcher::default()
        }),
    }
}

fn command_candidates(action: &ActionRecord) -> Vec<&str> {
    let mut candidates = Vec::new();
    if let Some(argv) = &action.syntactic.argv {
        candidates.extend(argv.iter().map(String::as_str));
    }
    if let Some(positionals) = &action.syntactic.positionals {
        candidates.extend(positionals.iter().map(String::as_str));
    }
    // Deliberately exclude raw shell text: glob matching must stay token-anchored and must not
    // span whitespace, shell metacharacters, or parser-visible token boundaries.
    candidates
}

fn predicate_has_over_budget_pattern(predicate: &PolicyPredicate) -> bool {
    predicate.command.as_ref().is_some_and(|command| {
        command
            .args_any_globs
            .iter()
            .any(|pattern| pattern.len() > MAX_PATTERN_MATCH_BYTES)
    }) || predicate.mcp.as_ref().is_some_and(|mcp| {
        mcp.params.iter().any(|matcher| {
            matcher
                .string_glob
                .as_ref()
                .is_some_and(|pattern| pattern.len() > MAX_PATTERN_MATCH_BYTES)
        })
    })
}

fn action_has_over_budget_match_input(action: &ActionRecord) -> bool {
    match action.surface {
        Surface::Command => command_candidates(action)
            .iter()
            .any(|candidate| candidate.len() > MAX_PATTERN_MATCH_BYTES),
        Surface::McpToolCall => action
            .syntactic
            .params
            .as_ref()
            .is_some_and(json_has_over_budget_string),
        Surface::FileEdit => {
            let syntactic = &action.syntactic;
            syntactic.paths.as_ref().is_some_and(|paths| {
                paths
                    .iter()
                    .any(|path| path.len() > MAX_PATTERN_MATCH_BYTES)
            }) || syntactic
                .diff_summary
                .as_ref()
                .is_some_and(|summary| summary.len() > MAX_PATTERN_MATCH_BYTES)
                || syntactic
                    .diff_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() > MAX_PATTERN_MATCH_BYTES)
                || syntactic
                    .raw
                    .as_ref()
                    .is_some_and(|raw| raw.len() > MAX_PATTERN_MATCH_BYTES)
        }
    }
}

fn json_has_over_budget_string(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => value.len() > MAX_PATTERN_MATCH_BYTES,
        serde_json::Value::Array(values) => values.iter().any(json_has_over_budget_string),
        serde_json::Value::Object(entries) => entries.values().any(json_has_over_budget_string),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            false
        }
    }
}

fn json_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    if path.is_empty() {
        return Some(value);
    }
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

// Bound signed policy matcher work: the glob engine is O(pattern * value). Oversized signed
// patterns are rejected at verification time, and oversized action values escalate before rule
// matching so a deny rule cannot be bypassed by padding the offending token.
const MAX_PATTERN_MATCH_BYTES: usize = 4096;

fn string_matches_pattern(value: &str, pattern: &str) -> bool {
    if value.len() > MAX_PATTERN_MATCH_BYTES || pattern.len() > MAX_PATTERN_MATCH_BYTES {
        return false;
    }

    if pattern.contains('*') || pattern.contains('?') {
        glob_matches(value, pattern)
    } else {
        value == pattern
    }
}

fn glob_matches(value: &str, pattern: &str) -> bool {
    let value = value.chars().collect::<Vec<_>>();
    let pattern = pattern.chars().collect::<Vec<_>>();
    let mut value_idx = 0;
    let mut pattern_idx = 0;
    let mut last_star_idx = None;
    let mut value_idx_after_star = 0;

    while value_idx < value.len() {
        if pattern_idx < pattern.len()
            && (pattern[pattern_idx] == '?' || pattern[pattern_idx] == value[value_idx])
        {
            value_idx += 1;
            pattern_idx += 1;
        } else if pattern_idx < pattern.len() && pattern[pattern_idx] == '*' {
            // Record the star and first let it match zero chars; if the suffix later fails, the
            // fallback branch below extends this same star one char at a time.
            last_star_idx = Some(pattern_idx);
            pattern_idx += 1;
            value_idx_after_star = value_idx;
        } else if let Some(star_idx) = last_star_idx {
            pattern_idx = star_idx + 1;
            value_idx_after_star += 1;
            value_idx = value_idx_after_star;
        } else {
            return false;
        }
    }

    pattern[pattern_idx..].iter().all(|ch| *ch == '*')
}

fn policy_jws_error(err: JwsError) -> PolicyRuleError {
    match err {
        JwsError::MalformedStructure
        | JwsError::InvalidBase64
        | JwsError::InvalidHeader
        | JwsError::InvalidPayload => PolicyRuleError::MalformedJws,
        JwsError::UnexpectedAlg => PolicyRuleError::UnexpectedAlg,
        JwsError::UnexpectedTyp => PolicyRuleError::UnexpectedTyp,
        JwsError::BadSignature => PolicyRuleError::BadSignature,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{glob_matches, string_matches_pattern};

    #[test]
    fn glob_matches_preserves_star_and_question_mark_semantics() {
        assert!(glob_matches("--force", "*force*"));
        assert!(glob_matches("build-prod", "build-????"));
        assert!(!glob_matches("build-prod", "build-???"));
    }

    #[test]
    fn glob_matches_pins_edge_case_semantics() {
        assert!(
            glob_matches("abc", "abc*"),
            "trailing star matches an empty suffix"
        );
        assert!(
            glob_matches("abc", "*bc"),
            "leading star can consume a prefix"
        );
        assert!(
            !glob_matches("", "*?"),
            "star-question still requires one code point"
        );
        assert!(
            glob_matches("abc", "***"),
            "consecutive stars collapse to match any value"
        );
        assert!(glob_matches("", ""), "empty pattern matches empty value");
        assert!(
            !glob_matches("abc", ""),
            "empty pattern does not match a non-empty value"
        );
        assert!(
            glob_matches("café", "caf?"),
            "question mark matches one Unicode code point"
        );
    }

    #[test]
    fn string_matches_pattern_rejects_inputs_over_the_matcher_ceiling() {
        let oversized = "a".repeat(4097);

        assert!(
            !string_matches_pattern(&oversized, &oversized),
            "over-cap exact patterns fail closed instead of spending verifier budget"
        );
    }

    #[test]
    fn glob_matches_pathological_non_match_is_bounded() {
        // A naive recursive wildcard matcher explores exponentially many partitions here before
        // it can prove that the trailing `b` is impossible. Policy rules are signed, but verifier
        // work must still remain bounded for a self-foot-gun or compromised device.
        let value = "a".repeat(24);
        let pattern = format!("{}b", "*a".repeat(24));

        let started = Instant::now();
        assert!(!glob_matches(&value, &pattern));
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "pathological policy globs must complete within a bounded verifier budget"
        );
    }
}
