//! Capture caller-described command inputs without interpreting a command language.
//!
//! A line is opaque text: no program, argv, environment references or target host can be inferred
//! from it. A supplied argv is an independent caller fact, retained verbatim alongside optional
//! original text. Approvers quote argv for display and show every supplied form; neither builder
//! decides what executes, whether it is dangerous, or whether it should be allowed.
//!
//! @see docs/action-record.md — Command capture; docs/contract.md — WYSIWYS.
use crate::contract::{ActionRecord, Surface, SyntacticSubstrate};

/// Record shape for caller facts after removal of interpretation and derived fields.
/// Older artifacts remain readable but use different request/audit hash domains.
pub const RECORD_SCHEMA_VERSION: u32 = 3;

/// Caller-supplied execution context; the builder never derives it from a command.
#[derive(Debug, Clone, Default)]
pub struct CommandContext {
    /// Directory asserted by the caller; absence means the directory is not bound.
    pub cwd: Option<String>,
}

/// A command capture refusal. Callers must deny when there is no input to present.
#[derive(Debug, PartialEq)]
pub enum CommandError {
    /// No argv elements, or command text that is empty or entirely Unicode whitespace.
    NoCommand,
}

impl CommandError {
    /// Stable refusal code exposed by bindings; callers never classify on diagnostic text.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoCommand => "no_command",
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCommand => write!(f, "command line contains no command"),
        }
    }
}
impl std::error::Error for CommandError {}

/// Record a nonblank line exactly as supplied, for any command language.
///
/// Quotes, comments, substitutions, operators and newlines carry no special meaning here. The
/// resulting record has raw text and optional cwd, never an inferred argv or program identity.
/// Returns [`CommandError::NoCommand`] only for empty or whitespace-only text.
pub fn action_from_command(
    command_line: &str,
    ctx: &CommandContext,
) -> Result<ActionRecord, CommandError> {
    if command_line.trim().is_empty() {
        return Err(CommandError::NoCommand);
    }
    Ok(build_record(None, Some(command_line.to_owned()), ctx))
}

/// Record a caller-supplied argv and optional original text without inspecting word meanings.
///
/// Only a vector with no elements is refused. Empty, assignment-looking or operator-looking words
/// remain caller facts. `raw`, when supplied, is a separate opaque field; it neither replaces argv
/// nor causes it to be reparsed. Approvers show both forms and warn when their display forms differ.
pub fn action_from_argv(
    argv: &[String],
    raw: Option<&str>,
    ctx: &CommandContext,
) -> Result<ActionRecord, CommandError> {
    if argv.is_empty() {
        return Err(CommandError::NoCommand);
    }
    Ok(build_record(
        Some(argv.to_vec()),
        raw.map(str::to_owned),
        ctx,
    ))
}

/// Assemble only the caller facts this module owns; tool identities and edits have other builders.
fn build_record(
    argv: Option<Vec<String>>,
    raw: Option<String>,
    ctx: &CommandContext,
) -> ActionRecord {
    ActionRecord {
        record_schema_version: RECORD_SCHEMA_VERSION,
        surface: Surface::Command,
        syntactic: SyntacticSubstrate {
            argv,
            cwd: ctx.cwd.clone(),
            raw,
            server: None,
            tool: None,
            params: None,
            operation: None,
            paths: None,
            diff_summary: None,
            diff_hash: None,
        },
    }
}
