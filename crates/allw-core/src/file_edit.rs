//! Build [`ActionRecord`]s for file-edit tool calls — T1 syntactic substrate only.
//!
//! The relay and approver must treat file edits as first-class actions, not as an MCP/command
//! approximation. This surface captures the paths being changed, the edit operation kind, and a
//! compact diff summary plus hash. The full edit bytes are also stored in `syntactic.raw` so the
//! approver can show the exact content the human is signing over.

use crate::contract::{ActionRecord, Risk, Surface, SyntacticSubstrate};
use base64::Engine;
use sha2::{Digest, Sha256};

/// Build an [`ActionRecord`] for a file-edit operation.
pub fn action_from_file_edit(
    operation: &str,
    paths: &[String],
    diff_summary: &str,
    diff_bytes: &str,
) -> ActionRecord {
    let mut hasher = Sha256::new();
    hasher.update(diff_bytes.as_bytes());
    let diff_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    ActionRecord {
        record_schema_version: 1,
        surface: Surface::FileEdit,
        syntactic: SyntacticSubstrate {
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
            raw: Some(diff_bytes.to_string()),
            operation: Some(operation.to_string()),
            paths: Some(paths.to_vec()),
            diff_summary: Some(diff_summary.to_string()),
            diff_hash: Some(diff_hash),
        },
        risk: Risk::High,
        capabilities: None,
        scope: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_edit_record_captures_paths_operation_summary_and_hash() {
        let diff = "*** Begin Patch\n*** Update File: src/app.ts\n@@\n-old\n+new\n*** End Patch\n";
        let record =
            action_from_file_edit("patch", &["src/app.ts".to_string()], "patch 1 file", diff);

        assert_eq!(record.surface, Surface::FileEdit);
        assert_eq!(record.record_schema_version, 1);
        assert_eq!(record.syntactic.operation.as_deref(), Some("patch"));
        assert_eq!(
            record.syntactic.paths.as_deref(),
            Some(&["src/app.ts".to_string()][..])
        );
        assert_eq!(
            record.syntactic.diff_summary.as_deref(),
            Some("patch 1 file")
        );
        assert_eq!(
            record.syntactic.diff_hash.as_deref().map(str::len),
            Some(43)
        );
        assert_eq!(
            record.syntactic.raw.as_deref(),
            Some(diff),
            "raw must carry the exact patch/edit text for WYSIWYS rendering"
        );
        assert_eq!(record.risk, Risk::High);
        assert!(record.capabilities.is_none());
        assert!(record.scope.is_none());
    }
}
