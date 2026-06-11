//! T1 syntactic policy rules for deciding whether an action can proceed locally.
//!
//! The policy layer runs **before** the human approval primitive. This module intentionally
//! implements only the v1 syntactic tier from `docs/policy-seam.md`: command names, argv/glob
//! checks, flags, MCP tool names, and MCP parameter equality/glob checks. It never reads or
//! infers from the reserved semantic `capabilities` / `scope` fields; those belong to the
//! deferred T3 engine.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

use crate::contract::{ActionRecord, Actor, PolicyDecision, Surface};
use crate::crypto::{PublicKey, SigningKeyPair};

const POLICY_SCHEMA_VERSION: u32 = 1;
const TYP_POLICY_RULE: &str = "allw-policy-rule+jws";
const ALG_EDDSA: &str = "EdDSA";

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
    /// Match a command when any argv/positional/raw token satisfies this glob.
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

    /// Require at least one syntactic argument token to match this substring/glob pattern.
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

    /// Substring/glob patterns; each pattern must match at least one syntactic token.
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
        actor: &Actor,
        action: &ActionRecord,
        scope: PolicyRuleScope,
        created_at: i64,
    ) -> Result<Self, PolicyRuleBuildError> {
        Ok(Self {
            id: id.to_string(),
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
}

impl PolicyRule {
    fn unsigned(&self) -> UnsignedPolicyRule {
        UnsignedPolicyRule {
            id: self.id.clone(),
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
    MalformedJws,
    UnexpectedAlg,
    UnexpectedTyp,
    BadSignature,
    PayloadMismatch,
}

impl std::fmt::Display for PolicyRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedJws => write!(f, "malformed policy-rule JWS"),
            Self::UnexpectedAlg => write!(f, "unexpected policy-rule JWS alg"),
            Self::UnexpectedTyp => write!(f, "unexpected policy-rule JWS typ"),
            Self::BadSignature => write!(f, "invalid policy-rule signature"),
            Self::PayloadMismatch => write!(f, "policy-rule JWS payload does not match outer rule"),
        }
    }
}

impl std::error::Error for PolicyRuleError {}

/// Errors returned while deriving a standing policy rule from a one-shot approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRuleBuildError {
    UnrepresentableExactCommand,
}

impl std::fmt::Display for PolicyRuleBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnrepresentableExactCommand => write!(
                f,
                "exact command policy requires either argv or raw command text"
            ),
        }
    }
}

impl std::error::Error for PolicyRuleBuildError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyJwsHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// Sign a policy rule with a device key.
#[must_use]
pub fn sign_policy_rule(
    rule: &UnsignedPolicyRule,
    device_id: &str,
    device_key: &SigningKeyPair,
) -> PolicyRule {
    let header = PolicyJwsHeader {
        alg: ALG_EDDSA.to_string(),
        typ: TYP_POLICY_RULE.to_string(),
        kid: device_id.to_string(),
    };
    let sig = encode_compact_jws(&header, rule, device_key);
    PolicyRule {
        id: rule.id.clone(),
        subject: rule.subject.clone(),
        predicate: rule.predicate.clone(),
        effect: rule.effect,
        bounds: rule.bounds.clone(),
        provenance: rule.provenance,
        tier: rule.tier,
        created_at: rule.created_at,
        expires_at: rule.expires_at,
        sig,
    }
}

/// Verify a signed policy rule against the expected device public key.
pub fn verify_policy_rule(
    rule: &PolicyRule,
    device_public_key: &PublicKey,
) -> Result<VerifiedPolicyRule, PolicyRuleError> {
    let decoded = decode_and_verify_policy_jws(&rule.sig, device_public_key)?;
    if decoded.claims != rule.unsigned() {
        return Err(PolicyRuleError::PayloadMismatch);
    }
    Ok(VerifiedPolicyRule {
        rule: rule.clone(),
        device_id: decoded.header.kid,
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
    if let Some(raw) = &action.syntactic.raw {
        candidates.push(raw.as_str());
    }
    candidates
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

fn string_matches_pattern(value: &str, pattern: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') {
        glob_matches(value, pattern)
    } else {
        value.contains(pattern)
    }
}

fn glob_matches(value: &str, pattern: &str) -> bool {
    fn inner(value: &[char], pattern: &[char]) -> bool {
        match pattern {
            [] => value.is_empty(),
            ['*', rest @ ..] => {
                inner(value, rest) || (!value.is_empty() && inner(&value[1..], pattern))
            }
            ['?', rest @ ..] => !value.is_empty() && inner(&value[1..], rest),
            [head, rest @ ..] => value.first() == Some(head) && inner(&value[1..], rest),
        }
    }
    let value = value.chars().collect::<Vec<_>>();
    let pattern = pattern.chars().collect::<Vec<_>>();
    inner(&value, &pattern)
}

fn encode_compact_jws<T: Serialize>(
    header: &PolicyJwsHeader,
    claims: &T,
    key: &SigningKeyPair,
) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(header).expect("PolicyJwsHeader must serialize without failure"),
    );
    let claims_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("policy claims must serialize"));
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = key.sign_bytes(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    format!("{signing_input}.{sig_b64}")
}

struct DecodedPolicyJws {
    header: PolicyJwsHeader,
    claims: UnsignedPolicyRule,
}

fn decode_and_verify_policy_jws(
    compact: &str,
    key: &PublicKey,
) -> Result<DecodedPolicyJws, PolicyRuleError> {
    let mut parts = compact.split('.');
    let header_b64 = parts.next().ok_or(PolicyRuleError::MalformedJws)?;
    let claims_b64 = parts.next().ok_or(PolicyRuleError::MalformedJws)?;
    let sig_b64 = parts.next().ok_or(PolicyRuleError::MalformedJws)?;
    if parts.next().is_some() {
        return Err(PolicyRuleError::MalformedJws);
    }

    let header_json = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| PolicyRuleError::MalformedJws)?;
    let header: PolicyJwsHeader =
        serde_json::from_slice(&header_json).map_err(|_| PolicyRuleError::MalformedJws)?;
    if header.alg != ALG_EDDSA {
        return Err(PolicyRuleError::UnexpectedAlg);
    }
    if header.typ != TYP_POLICY_RULE {
        return Err(PolicyRuleError::UnexpectedTyp);
    }

    let sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| PolicyRuleError::MalformedJws)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| PolicyRuleError::BadSignature)?;
    let signing_input = format!("{header_b64}.{claims_b64}");
    if !key.verify_bytes(signing_input.as_bytes(), &sig) {
        return Err(PolicyRuleError::BadSignature);
    }

    let claims_json = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| PolicyRuleError::MalformedJws)?;
    let claims = serde_json::from_slice(&claims_json).map_err(|_| PolicyRuleError::MalformedJws)?;
    Ok(DecodedPolicyJws { header, claims })
}
