//! Builders for [`ActionRecord`]s sharing the MCP-style `(server, tool, params)` function-identity
//! substrate: the **`mcp_tool_call`** and **`agent_tool_call`** surfaces.
//!
//! `agent_tool_call` is an agent-runtime or plugin-owned tool call gated by the harness rather
//! than by an MCP server (`docs/openclaw-integration.md` §5.2). It reuses the exact same
//! `(server, tool, params)` fields as `mcp_tool_call` — `server` holds the gating provider id
//! instead of an MCP server name — so both builders share one reduction path
//! ([`build_tool_call_action`]) and differ only in the `surface` tag they stamp. Keeping them
//! distinct surfaces (rather than one builder always emitting `mcp_tool_call`) is deliberate: a
//! policy rule or registry scoped to `mcp_tool_call` must never silently match a tool call no MCP
//! server ever served (`docs/policy-seam.md` §Structure vs. data in the ActionRecord).
//!
//! **Scope:** syntactic substrate only (T1). No capability inference, no semantic enrichment.
//! The `capabilities` and `scope` fields of every produced `ActionRecord` are always `None`;
//! they are reserved for the T3 semantic tier. See `docs/policy-seam.md` §The three tiers.
//!
//! # `raw` display format
//!
//! The `syntactic.raw` field is set to:
//!
//! ```text
//! <server>.<tool>(<compact-json-params>)
//! ```
//!
//! or, when there are no params (`agent_tool_call` with `params = None`):
//!
//! ```text
//! <server>.<tool>()
//! ```
//!
//! where `<compact-json-params>` is the params value serialised with
//! [`serde_json::to_string`] (no extra whitespace). Examples:
//!
//! - `omnifocus.delete_project({"project_id":"abc","list":"Agent Inbox"})`
//! - `github.list_repos({})`
//! - `files.read_file(["path/to/file"])`
//! - `openclaw.deploy_service()`
//!
//! The format is intended for display and fallback pattern matching only; the canonical,
//! matchable params form lives in `syntactic.params` as a structured [`serde_json::Value`].
//!
//! # Risk heuristic (v1)
//!
//! A coarse, name-based risk tier is assigned from the tool name:
//!
//! | Tool name prefix                   | [`Risk`] assigned |
//! |------------------------------------|-------------------|
//! | starts with `delete`, `remove`, or `drop` | `High`     |
//! | starts with `destroy`, `truncate`, or `purge` | `High` |
//! | starts with `kill`, `terminate`, or `wipe` | `High`   |
//! | all other tools                    | `Medium`          |
//!
//! Matching is **case-insensitive** and **prefix-only** (a tool named `"remotely_nice"` does
//! **not** match `remove`). The heuristic is intentionally conservative: when in doubt, choose
//! `Medium` over `Low`. `Low` and `Critical` are not assigned by this heuristic; callers may
//! override the returned `ActionRecord` if they have richer signal.
//!
//! **TODO:** T3 will replace this with capability-derived risk once the semantic engine lands
//! (`docs/policy-seam.md` §The three tiers, T3 column).

use crate::contract::{ActionRecord, Risk, Surface, SyntacticSubstrate};

/// Build an [`ActionRecord`] for an MCP tool call, populating only the syntactic substrate.
///
/// # Arguments
///
/// * `server` – MCP server name (e.g. `"omnifocus"`).
/// * `tool`   – Tool name within the server (e.g. `"delete_project"`).
/// * `params` – Tool call parameters as a [`serde_json::Value`]. Any JSON value is accepted
///   (object, array, null, primitive). All **keys and values are preserved** (no normalisation,
///   no dropping of any field), so instance-distinguishing values like `{"list": "Agent Inbox"}`
///   survive a serde round-trip and remain matchable by policy rules of the form
///   `params.list == "Agent Inbox"` (see `docs/policy-seam.md` §The approval → rule bridge).
///   Object **key order is not guaranteed** (serde_json's default `Map` sorts keys) and must not
///   be relied upon — it is not semantically meaningful for `Value` equality or key lookup.
///
/// # Returns
///
/// An [`ActionRecord`] with:
///
/// - `surface = Surface::McpToolCall`
/// - `record_schema_version = 1`
/// - `syntactic.server`, `syntactic.tool`, `syntactic.params` populated from the arguments
/// - `syntactic.raw` set to `"<server>.<tool>(<compact-json-params>)"` (see module-level docs)
/// - All command-surface syntactic fields (`bin`, `argv`, `flags`, `positionals`, `cwd`,
///   `host`, `env_refs`) set to `None`
/// - `risk` assigned by the v1 name-based heuristic (see module-level docs)
/// - `capabilities = None` and `scope = None` (reserved for T3; see `docs/policy-seam.md`)
///
/// # Example
///
/// ```rust
/// use allw_core::mcp::action_from_mcp_tool_call;
/// use allw_core::contract::Surface;
/// use serde_json::json;
///
/// let record = action_from_mcp_tool_call(
///     "omnifocus",
///     "delete_project",
///     json!({ "project_id": "abc", "list": "Agent Inbox" }),
/// );
///
/// assert_eq!(record.surface, Surface::McpToolCall);
/// assert_eq!(record.syntactic.server.as_deref(), Some("omnifocus"));
/// assert_eq!(record.syntactic.tool.as_deref(), Some("delete_project"));
/// ```
pub fn action_from_mcp_tool_call(
    server: &str,
    tool: &str,
    params: serde_json::Value,
) -> ActionRecord {
    build_tool_call_action(Surface::McpToolCall, server, tool, Some(params))
}

/// Build an [`ActionRecord`] for an agent-runtime/plugin-owned tool call gated by the harness
/// rather than an MCP server (`docs/openclaw-integration.md` §5.2), populating only the syntactic
/// substrate. Shares [`build_tool_call_action`] with [`action_from_mcp_tool_call`] — the two
/// differ only in the `surface` tag stamped on the record.
///
/// # Arguments
///
/// * `server` – the gating provider identity (e.g. an OpenClaw plugin id). Reuses the
///   `mcp_tool_call` function-identity slot; it is **not** an MCP server name.
/// * `tool`   – the tool name within that provider.
/// * `params` – tool call parameters, if any structured form is available. `None` when the
///   caller has no structured parameters to offer (e.g. OpenClaw plugin permission requests
///   expose only prose to the reviewer — `docs/openclaw-integration.md` §5.2 — so the bridge must
///   pass `None` rather than synthesizing a params value).
///
/// # Returns
///
/// An [`ActionRecord`] with:
///
/// - `surface = Surface::AgentToolCall`
/// - `record_schema_version = 1`
/// - `syntactic.server`, `syntactic.tool` populated from the arguments; `syntactic.params` set
///   only when `params` is `Some`
/// - `syntactic.raw` set to `"<server>.<tool>(<compact-json-params>)"`, or `"<server>.<tool>()"`
///   when `params` is `None` (see module-level docs)
/// - All command-surface and file-edit-surface syntactic fields set to `None`
/// - `risk` assigned by the v1 name-based heuristic (see module-level docs) — identical to
///   `mcp_tool_call`; T3 will replace this with capability-derived risk
/// - `capabilities = None` and `scope = None` (reserved for T3; see `docs/policy-seam.md`)
///
/// # Example
///
/// ```rust
/// use allw_core::mcp::action_from_agent_tool_call;
/// use allw_core::contract::Surface;
///
/// let record = action_from_agent_tool_call("openclaw", "deploy_service", None);
///
/// assert_eq!(record.surface, Surface::AgentToolCall);
/// assert_eq!(record.syntactic.server.as_deref(), Some("openclaw"));
/// assert_eq!(record.syntactic.tool.as_deref(), Some("deploy_service"));
/// assert!(record.syntactic.params.is_none());
/// ```
pub fn action_from_agent_tool_call(
    server: &str,
    tool: &str,
    params: Option<serde_json::Value>,
) -> ActionRecord {
    build_tool_call_action(Surface::AgentToolCall, server, tool, params)
}

/// Shared syntactic-substrate reduction for the `mcp_tool_call` and `agent_tool_call` surfaces.
///
/// Both surfaces reduce to the same `(server, tool, params)` function-identity shape
/// (`docs/policy-seam.md` §Structure vs. data in the ActionRecord); only the `surface` tag
/// differs. Kept private so the two public builders above cannot drift apart on risk heuristic,
/// `raw` formatting, or which fields are populated.
fn build_tool_call_action(
    surface: Surface,
    server: &str,
    tool: &str,
    params: Option<serde_json::Value>,
) -> ActionRecord {
    // A serde_json::Value always serializes; surface any unexpected failure rather than
    // silently emitting a `raw` that disagrees with `syntactic.params`.
    let raw = match &params {
        Some(value) => {
            let compact_params = serde_json::to_string(value)
                .expect("serde_json::Value always serializes to a string");
            format!("{server}.{tool}({compact_params})")
        }
        None => format!("{server}.{tool}()"),
    };
    let risk = v1_risk_from_tool_name(tool);

    ActionRecord {
        record_schema_version: 1,
        surface,
        syntactic: SyntacticSubstrate {
            // command-surface fields — all None for mcp_tool_call / agent_tool_call
            bin: None,
            argv: None,
            flags: None,
            positionals: None,
            cwd: None,
            host: None,
            env_refs: None,
            // shared function-identity fields
            server: Some(server.to_string()),
            tool: Some(tool.to_string()),
            params,
            // file_edit-surface fields — always None here
            operation: None,
            paths: None,
            diff_summary: None,
            diff_hash: None,
            // cross-surface display/fallback field
            raw: Some(raw),
        },
        risk,
        // T3 semantic fields — reserved; MUST be None in v1
        capabilities: None,
        scope: None,
    }
}

/// Assign a coarse [`Risk`] tier from the tool name (v1 heuristic).
///
/// Matching is case-insensitive prefix matching. See the module-level doc table for the full
/// mapping. When no prefix matches, returns [`Risk::Medium`] (fail toward caution).
fn v1_risk_from_tool_name(tool: &str) -> Risk {
    /// Prefixes whose matching tools are classified as `High` risk.
    const HIGH_PREFIXES: &[&str] = &[
        "delete",
        "remove",
        "drop",
        "destroy",
        "truncate",
        "purge",
        "kill",
        "terminate",
        "wipe",
    ];

    let lower = tool.to_lowercase();
    for prefix in HIGH_PREFIXES {
        if lower.starts_with(prefix) {
            return Risk::High;
        }
    }
    Risk::Medium
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::Surface;
    use serde_json::json;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build the canonical representative record used across multiple tests:
    /// server="omnifocus", tool="delete_project",
    /// params={"project_id":"abc","list":"Agent Inbox"}.
    fn representative_record() -> ActionRecord {
        // Key order here is irrelevant — `Value` equality and key lookup are order-independent,
        // and tests must not depend on serde_json's serialization ordering.
        action_from_mcp_tool_call(
            "omnifocus",
            "delete_project",
            json!({ "project_id": "abc", "list": "Agent Inbox" }),
        )
    }

    // ── surface and identity fields ───────────────────────────────────────────

    /// Surface must be McpToolCall and schema version must be 1.
    #[test]
    fn surface_is_mcp_tool_call_and_schema_version_is_1() {
        let r = representative_record();
        assert_eq!(r.surface, Surface::McpToolCall);
        assert_eq!(r.record_schema_version, 1);
    }

    /// server and tool must be populated from the arguments.
    #[test]
    fn server_and_tool_are_set() {
        let r = representative_record();
        assert_eq!(r.syntactic.server.as_deref(), Some("omnifocus"));
        assert_eq!(r.syntactic.tool.as_deref(), Some("delete_project"));
    }

    /// params must equal the input serde_json::Value exactly (verbatim preservation).
    #[test]
    fn params_equal_input_exactly() {
        let input = json!({ "list": "Agent Inbox", "project_id": "abc" });
        let r = action_from_mcp_tool_call("omnifocus", "delete_project", input.clone());
        assert_eq!(
            r.syntactic.params.as_ref(),
            Some(&input),
            "params must equal the input serde_json::Value exactly"
        );
    }

    // ── params preserved verbatim through serde round-trip ────────────────────

    /// policy-seam.md §The approval → rule bridge: instance-distinguishing params such as
    /// `{"list": "Agent Inbox"}` must survive a full serde JSON round-trip so that policy rules
    /// of the form `params.list == "Agent Inbox"` can match against them.
    ///
    /// Also validates a nested structure with an array: {"nested": {"a": [1,2,3]}, "n": 42}.
    #[test]
    fn params_preserved_verbatim_through_serde_round_trip() {
        let original_params =
            json!({ "list": "Agent Inbox", "nested": { "a": [1, 2, 3] }, "n": 42 });
        let record = action_from_mcp_tool_call("omnifocus", "get_tasks", original_params.clone());

        // Round-trip the entire ActionRecord through JSON serialization and deserialization.
        let serialised =
            serde_json::to_string(&record).expect("ActionRecord must be serialisable to JSON");
        let deserialised: ActionRecord =
            serde_json::from_str(&serialised).expect("JSON must deserialise back to ActionRecord");

        assert_eq!(
            deserialised.syntactic.params.as_ref(),
            Some(&original_params),
            "params must deep-equal the original after a full serde round-trip \
             (policy-seam.md §The approval → rule bridge: params.list == \"Agent Inbox\" \
             must remain matchable)"
        );
    }

    // ── raw display format ────────────────────────────────────────────────────

    /// The raw field must match the documented display format:
    ///   "<server>.<tool>(<compact-json-params>)"
    ///
    /// The expected `raw` is built from the SAME params via `serde_json::to_string`, so this test
    /// asserts the wrapping format and compactness WITHOUT assuming any serde_json key order
    /// (it stays correct even if `preserve_order` is later enabled).
    #[test]
    fn raw_matches_documented_display_format() {
        let params = json!({ "project_id": "abc", "list": "Agent Inbox" });
        let r = action_from_mcp_tool_call("omnifocus", "delete_project", params.clone());
        let expected_raw = format!(
            "omnifocus.delete_project({})",
            serde_json::to_string(&params).unwrap()
        );
        assert_eq!(
            r.syntactic.raw.as_deref(),
            Some(expected_raw.as_str()),
            "raw must be '<server>.<tool>(<compact-json-params>)' (compact, no whitespace)"
        );
    }

    /// raw must use compact JSON (no spaces), not pretty-printed.
    #[test]
    fn raw_uses_compact_json_not_pretty_printed() {
        let r = representative_record();
        let raw = r.syntactic.raw.as_deref().expect("raw must be Some");
        assert!(
            !raw.contains('\n') && !raw.contains("  "),
            "raw must use compact (not pretty-printed) JSON; got: {raw}"
        );
    }

    // ── reserved / None fields ────────────────────────────────────────────────

    /// capabilities and scope MUST be None in v1 (policy-seam.md §forward-compat req #3).
    #[test]
    fn capabilities_and_scope_are_none() {
        let r = representative_record();
        assert!(
            r.capabilities.is_none(),
            "capabilities MUST be None in v1 (policy-seam.md §forward-compat req #3)"
        );
        assert!(
            r.scope.is_none(),
            "scope MUST be None in v1 (policy-seam.md §forward-compat req #3)"
        );
    }

    /// Command-surface fields must all be None for an mcp_tool_call record.
    #[test]
    fn command_surface_fields_are_none() {
        let r = representative_record();
        assert!(
            r.syntactic.bin.is_none(),
            "bin must be None for mcp_tool_call surface"
        );
        assert!(
            r.syntactic.argv.is_none(),
            "argv must be None for mcp_tool_call surface"
        );
        assert!(
            r.syntactic.flags.is_none(),
            "flags must be None for mcp_tool_call surface"
        );
        assert!(
            r.syntactic.positionals.is_none(),
            "positionals must be None for mcp_tool_call surface"
        );
        assert!(
            r.syntactic.cwd.is_none(),
            "cwd must be None for mcp_tool_call surface"
        );
        assert!(
            r.syntactic.host.is_none(),
            "host must be None for mcp_tool_call surface"
        );
        assert!(
            r.syntactic.env_refs.is_none(),
            "env_refs must be None for mcp_tool_call surface"
        );
    }

    // ── determinism ──────────────────────────────────────────────────────────

    /// Same inputs must produce identical ActionRecords (the builder is purely deterministic).
    #[test]
    fn deterministic_same_inputs_produce_identical_records() {
        let params = json!({ "list": "Agent Inbox", "project_id": "abc" });
        let r1 = action_from_mcp_tool_call("omnifocus", "delete_project", params.clone());
        let r2 = action_from_mcp_tool_call("omnifocus", "delete_project", params);
        assert_eq!(
            r1, r2,
            "same inputs must produce identical ActionRecords (determinism)"
        );
    }

    // ── risk heuristic ────────────────────────────────────────────────────────

    /// Tools with destructive-prefix names must be assigned Risk::High.
    /// Heuristic: case-insensitive prefix match against the HIGH_PREFIXES list
    /// (delete, remove, drop, destroy, truncate, purge, kill, terminate, wipe).
    #[test]
    fn risk_high_for_destructive_tool_names() {
        // Each entry: (tool_name, expected_risk, human_rationale)
        let cases: &[(&str, &str)] = &[
            ("delete_project", "delete* prefix → High"),
            ("DELETE_ALL", "case-insensitive delete* → High"),
            ("remove_item", "remove* prefix → High"),
            ("drop_table", "drop* prefix → High"),
            ("destroy_workspace", "destroy* prefix → High"),
            ("truncate_log", "truncate* prefix → High"),
            ("purge_cache", "purge* prefix → High"),
            ("kill_process", "kill* prefix → High"),
            ("terminate_session", "terminate* prefix → High"),
            ("wipe_device", "wipe* prefix → High"),
        ];

        for (tool, rationale) in cases {
            let r = action_from_mcp_tool_call("server", tool, json!({}));
            assert_eq!(
                r.risk,
                Risk::High,
                "tool '{}' should be High risk ({})",
                tool,
                rationale
            );
        }
    }

    /// Non-destructive tools must be assigned Risk::Medium (the default).
    #[test]
    fn risk_medium_for_benign_tool_names() {
        let benign_tools = [
            "list_projects",
            "get_task",
            "create_note",
            "update_title",
            "search",
            "read_file",
            "send_message",
            // "remotely_nice" must NOT match "remove" — prefix-only matching
            "remotely_nice",
        ];

        for tool in benign_tools {
            let r = action_from_mcp_tool_call("server", tool, json!({}));
            assert_eq!(
                r.risk,
                Risk::Medium,
                "tool '{}' should be Medium risk (benign/non-destructive)",
                tool
            );
        }
    }

    /// "remotely_nice" must NOT match the "remove" prefix — the heuristic is prefix-only.
    #[test]
    fn prefix_only_matching_does_not_match_mid_word() {
        let r = action_from_mcp_tool_call("server", "remotely_nice", json!({}));
        assert_eq!(
            r.risk,
            Risk::Medium,
            "'remotely_nice' must NOT match the 'remove' prefix — prefix-only heuristic"
        );
    }

    // ── edge cases ────────────────────────────────────────────────────────────

    /// Empty params object {} must be preserved verbatim (not dropped or replaced).
    #[test]
    fn empty_params_object_preserved() {
        let r = action_from_mcp_tool_call("server", "list_items", json!({}));
        assert_eq!(
            r.syntactic.params,
            Some(json!({})),
            "empty params object must be preserved verbatim"
        );
        // raw must contain the empty object, not omit params
        let raw = r.syntactic.raw.as_deref().expect("raw must be Some");
        assert!(
            raw.ends_with("({})"),
            "raw for empty params must end with '({{}})'; got: {raw}"
        );
    }

    /// Params that are a non-object JSON value (an array) must be preserved as-is.
    ///
    /// policy-seam.md does not restrict params to objects — the field is typed as
    /// serde_json::Value and must accept any valid JSON.
    #[test]
    fn non_object_params_array_preserved() {
        let array_params = json!(["file1.txt", "file2.txt"]);
        let r = action_from_mcp_tool_call("server", "list_files", array_params.clone());
        assert_eq!(
            r.syntactic.params,
            Some(array_params),
            "array params must be preserved verbatim (params is typed as serde_json::Value, \
             not restricted to objects)"
        );
    }

    /// Params that survive a round-trip for the array case.
    #[test]
    fn non_object_params_array_preserved_through_round_trip() {
        let array_params = json!(["file1.txt", "file2.txt"]);
        let record = action_from_mcp_tool_call("server", "list_files", array_params.clone());

        let serialised = serde_json::to_string(&record).expect("ActionRecord must be serialisable");
        let deserialised: ActionRecord =
            serde_json::from_str(&serialised).expect("must deserialise back");

        assert_eq!(
            deserialised.syntactic.params,
            Some(array_params),
            "array params must survive a serde round-trip"
        );
    }

    // ── action_from_agent_tool_call ──────────────────────────────────────────────

    /// Surface must be AgentToolCall (not McpToolCall) and schema version must be 1 — the
    /// distinct-surface tag is the whole point of the `agent_tool_call` surface
    /// (docs/openclaw-integration.md §5.2).
    #[test]
    fn agent_tool_call_surface_is_agent_tool_call_and_schema_version_is_1() {
        let r = action_from_agent_tool_call("openclaw", "deploy_service", None);
        assert_eq!(r.surface, Surface::AgentToolCall);
        assert_ne!(
            r.surface,
            Surface::McpToolCall,
            "agent_tool_call must never be tagged mcp_tool_call"
        );
        assert_eq!(r.record_schema_version, 1);
    }

    /// server and tool must be populated from the arguments, exactly like `mcp_tool_call`.
    #[test]
    fn agent_tool_call_server_and_tool_are_set() {
        let r = action_from_agent_tool_call("openclaw", "deploy_service", None);
        assert_eq!(r.syntactic.server.as_deref(), Some("openclaw"));
        assert_eq!(r.syntactic.tool.as_deref(), Some("deploy_service"));
    }

    /// docs/openclaw-integration.md §5.2: `syntactic.params` is absent (not `null`) when the
    /// caller has no structured parameters to offer.
    #[test]
    fn agent_tool_call_params_absent_when_none() {
        let r = action_from_agent_tool_call("openclaw", "deploy_service", None);
        assert!(
            r.syntactic.params.is_none(),
            "params must be None when the caller passes None"
        );
        let val: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert!(
            val["syntactic"].get("params").is_none(),
            "params: None must be omitted from JSON, not serialized as null"
        );
    }

    /// `params` is preserved verbatim when a caller does have structured parameters — the
    /// builder does not force `agent_tool_call` calls to be paramless, only allows it.
    #[test]
    fn agent_tool_call_params_preserved_when_some() {
        let params = json!({ "target": "prod" });
        let r = action_from_agent_tool_call("openclaw", "deploy_service", Some(params.clone()));
        assert_eq!(r.syntactic.params, Some(params));
    }

    /// raw must be `"<server>.<tool>()"` when params is None (see module-level doc format).
    #[test]
    fn agent_tool_call_raw_uses_empty_parens_when_params_absent() {
        let r = action_from_agent_tool_call("openclaw", "deploy_service", None);
        assert_eq!(
            r.syntactic.raw.as_deref(),
            Some("openclaw.deploy_service()")
        );
    }

    /// raw must be `"<server>.<tool>(<compact-json-params>)"` when params is Some, matching
    /// `mcp_tool_call`'s format exactly.
    #[test]
    fn agent_tool_call_raw_matches_mcp_format_when_params_present() {
        let params = json!({ "target": "prod" });
        let r = action_from_agent_tool_call("openclaw", "deploy_service", Some(params.clone()));
        let expected_raw = format!(
            "openclaw.deploy_service({})",
            serde_json::to_string(&params).unwrap()
        );
        assert_eq!(r.syntactic.raw.as_deref(), Some(expected_raw.as_str()));
    }

    /// Command-surface and file-edit-surface fields must all be None for an agent_tool_call
    /// record, exactly like `mcp_tool_call`.
    #[test]
    fn agent_tool_call_command_and_file_edit_fields_are_none() {
        let r = action_from_agent_tool_call("openclaw", "deploy_service", None);
        assert!(r.syntactic.bin.is_none());
        assert!(r.syntactic.argv.is_none());
        assert!(r.syntactic.flags.is_none());
        assert!(r.syntactic.positionals.is_none());
        assert!(r.syntactic.cwd.is_none());
        assert!(r.syntactic.host.is_none());
        assert!(r.syntactic.env_refs.is_none());
        assert!(r.syntactic.operation.is_none());
        assert!(r.syntactic.paths.is_none());
        assert!(r.syntactic.diff_summary.is_none());
        assert!(r.syntactic.diff_hash.is_none());
    }

    /// capabilities and scope MUST be None in v1, same forward-compat requirement as every
    /// other surface (policy-seam.md §forward-compat req #3).
    #[test]
    fn agent_tool_call_capabilities_and_scope_are_none() {
        let r = action_from_agent_tool_call("openclaw", "deploy_service", None);
        assert!(r.capabilities.is_none());
        assert!(r.scope.is_none());
    }

    /// The risk heuristic is shared verbatim with `mcp_tool_call` (same tool-name prefixes).
    #[test]
    fn agent_tool_call_shares_risk_heuristic_with_mcp_tool_call() {
        let destructive = action_from_agent_tool_call("openclaw", "delete_deployment", None);
        assert_eq!(destructive.risk, Risk::High);

        let benign = action_from_agent_tool_call("openclaw", "deploy_service", None);
        assert_eq!(benign.risk, Risk::Medium);
    }

    /// Same inputs (including the `None` params) must produce identical ActionRecords.
    #[test]
    fn agent_tool_call_deterministic_same_inputs_produce_identical_records() {
        let r1 = action_from_agent_tool_call("openclaw", "deploy_service", None);
        let r2 = action_from_agent_tool_call("openclaw", "deploy_service", None);
        assert_eq!(r1, r2);
    }

    /// An `agent_tool_call` record must survive a full serde round-trip, including the
    /// omitted-when-None `params` field.
    #[test]
    fn agent_tool_call_action_record_round_trips_through_json() {
        let record = action_from_agent_tool_call("openclaw", "deploy_service", None);
        let serialised = serde_json::to_string(&record).expect("ActionRecord must serialise");
        let deserialised: ActionRecord =
            serde_json::from_str(&serialised).expect("ActionRecord must deserialise");
        assert_eq!(record, deserialised);
    }

    /// An `mcp_tool_call` record and an `agent_tool_call` record built from the identical
    /// `(server, tool)` pair must differ ONLY in `surface` — everything else about the shared
    /// function-identity substrate stays byte-identical, matching the "reuses the (server, tool)
    /// pair" decision in docs/policy-seam.md and docs/openclaw-integration.md §5.2.
    #[test]
    fn agent_tool_call_and_mcp_tool_call_share_identical_substrate_except_surface() {
        let params = json!({ "list": "Agent Inbox" });
        let mcp = action_from_mcp_tool_call("shared-name", "shared-tool", params.clone());
        let agent = action_from_agent_tool_call("shared-name", "shared-tool", Some(params));

        assert_ne!(mcp.surface, agent.surface);
        assert_eq!(agent.surface, Surface::AgentToolCall);
        assert_eq!(mcp.surface, Surface::McpToolCall);
        assert_eq!(mcp.syntactic.server, agent.syntactic.server);
        assert_eq!(mcp.syntactic.tool, agent.syntactic.tool);
        assert_eq!(mcp.syntactic.params, agent.syntactic.params);
        assert_eq!(mcp.syntactic.raw, agent.syntactic.raw);
        assert_eq!(mcp.risk, agent.risk);
    }
}
