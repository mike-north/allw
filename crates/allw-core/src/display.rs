//! # Display safety: visible escaping of untrusted approval text
//!
//! Every string an approver surface shows the human — the summary, the actor, every syntactic
//! substrate field — is **attacker-influenced plaintext**. WYSIWYS (`docs/contract.md`
//! §Invariants #3) binds the verdict to the exact bytes the human saw, but that guarantee is only
//! as strong as the rendering: a string carrying `ESC [2K` + `CR` can erase and repaint its own
//! terminal line, a bidi override (U+202E) can reorder what a browser shows, and zero-width
//! characters can hide text entirely. The hash is then correct for the real bytes while the human
//! approved something else (`docs/threat-model.md` R3; Trojan Source, CVE-2021-42574).
//!
//! Deciding how untrusted text reaches the human is therefore a trust decision, and it lives here,
//! once, in the audited core. Surfaces (the CLI approver, the web approver, and later the native
//! apps) render the [`DisplayModel`] this module returns and never implement their own escaping.
//!
//! # What is escaped
//!
//! [`is_hidden_or_control_char`] is the single definition. It covers:
//!
//! - **C0 controls** U+0000–U+001F (ESC, CR, LF, TAB, …) and **DEL** U+007F;
//! - **C1 controls** U+0080–U+009F;
//! - **bidi controls** U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069 (Unicode TR9 §2);
//! - **zero-width / invisible** U+200B–U+200D, U+2060, U+FEFF;
//! - the rest of Unicode's `Default_Ignorable_Code_Point` set (soft hyphen U+00AD, U+034F, Hangul
//!   fillers, U+2061–U+2064 invisible operators, U+206A–U+206F, tag characters U+E0000–U+E007F,
//!   …) **except variation selectors**, which only pick a glyph form (emoji presentation) and
//!   cannot hide or reorder text; and
//! - **line/paragraph separators** U+2028, U+2029 and the interlinear-annotation controls
//!   U+FFF9–U+FFFB, which break or hide lines in some renderers.
//!
//! # Notation
//!
//! - TAB, LF, CR render as `\t`, `\n`, `\r`.
//! - Every other C0 control and DEL renders as `\xHH` with lowercase hex (ESC → `\x1b`).
//! - Everything else renders as `⟨U+XXXX⟩` with at least four uppercase hex digits
//!   (U+202E → `⟨U+202E⟩`, U+E0041 → `⟨U+E0041⟩`).
//!
//! The notation is not injective against *literal* text: a string containing the four printable
//! characters `\x1b` displays the same as one containing an ESC byte. That is why every model
//! carries [`DisplayModel::has_hidden_or_control_chars`] — surfaces show a warning whenever an
//! escape was applied, so the human always knows when what they read is a stand-in for a byte they
//! cannot see.
//!
//! # Display-only
//!
//! Escaping never feeds the `request_hash`. The hash is computed over the original
//! [`ApprovalContext`] (see [`crate::hash`]); [`display_model`] borrows that context immutably and
//! returns a separate value. The escaped strings are a *rendering* of the hashed bytes, never a
//! substitute for them, and a [`DisplayModel`] must never be hashed, signed, or sent anywhere.
//!
//! # Layout stays in the surfaces
//!
//! This module returns escaped *fields*, not laid-out screens. How a surface composes them — which
//! field becomes the headline, how argv tokens are quoted, when a `raw`/`argv` divergence line is
//! shown — remains surface code (#246 non-goals). The invariant this module establishes is
//! narrower and load-bearing: no untrusted string reaches a screen except through
//! [`escape_for_display`].

use std::fmt::Write as _;

use serde::Serialize;

use crate::contract::{ApprovalContext, Risk, Surface, SyntacticSubstrate};

/// Whether `c` must be rendered as a visible escape rather than shown as itself.
///
/// This is the one definition of "hidden or control character" every surface relies on; see the
/// module docs for the classes it covers and why.
pub fn is_hidden_or_control_char(c: char) -> bool {
    matches!(
        c,
        // C0 controls, DEL, C1 controls.
        '\u{0000}'..='\u{001F}'
            | '\u{007F}'
            | '\u{0080}'..='\u{009F}'
            // Soft hyphen; combining grapheme joiner.
            | '\u{00AD}'
            | '\u{034F}'
            // Arabic letter mark (bidi).
            | '\u{061C}'
            // Hangul choseong/jungseong fillers; Khmer inherent vowels; Mongolian vowel separator.
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180E}'
            // ZWSP, ZWNJ, ZWJ, LRM, RLM.
            | '\u{200B}'..='\u{200F}'
            // Line separator, paragraph separator.
            | '\u{2028}'
            | '\u{2029}'
            // LRE, RLE, PDF, LRO, RLO.
            | '\u{202A}'..='\u{202E}'
            // Word joiner, invisible operators, isolates (LRI, RLI, FSI, PDI), deprecated format
            // controls.
            | '\u{2060}'..='\u{206F}'
            // Hangul filler; halfwidth Hangul filler.
            | '\u{3164}'
            | '\u{FFA0}'
            // Byte-order mark / zero-width no-break space.
            | '\u{FEFF}'
            // Unassigned default-ignorables; interlinear annotation anchor/separator/terminator.
            | '\u{FFF0}'..='\u{FFFB}'
            // Shorthand format controls; musical symbol format controls.
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            // Tag characters and the surrounding default-ignorable planes (variation selectors
            // U+E0100–U+E01EF are deliberately excluded).
            | '\u{E0000}'..='\u{E00FF}'
            | '\u{E01F0}'..='\u{E0FFF}'
    )
}

/// Whether `text` contains any character [`escape_for_display`] would escape.
pub fn has_hidden_or_control_chars(text: &str) -> bool {
    text.chars().any(is_hidden_or_control_char)
}

/// Render `text` for display, replacing every hidden or control character with a visible escape.
///
/// Printable text (including all ordinary non-ASCII letters, emoji, and variation selectors) passes
/// through unchanged. The output never contains a character for which
/// [`is_hidden_or_control_char`] is true, and escaping is idempotent: escaping already-escaped
/// output returns it unchanged.
///
/// # Examples
///
/// ```
/// use allw_core::escape_for_display;
///
/// assert_eq!(escape_for_display("a\u{1b}[2K\rb"), "a\\x1b[2K\\rb");
/// assert_eq!(escape_for_display("abc\u{202E}def"), "abc⟨U+202E⟩def");
/// assert_eq!(escape_for_display("git status"), "git status");
/// ```
pub fn escape_for_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        push_escaped(&mut out, c);
    }
    out
}

/// Append `c` to `out`, escaped if it is hidden or a control character.
fn push_escaped(out: &mut String, c: char) {
    if !is_hidden_or_control_char(c) {
        out.push(c);
        return;
    }
    match c {
        '\t' => out.push_str("\\t"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\u{0000}'..='\u{001F}' | '\u{007F}' => {
            // Writing to a String is infallible.
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        }
        _ => {
            let _ = write!(out, "⟨U+{:04X}⟩", u32::from(c));
        }
    }
}

/// The escaped syntactic substrate of an action: each field of [`SyntacticSubstrate`], rendered
/// for display.
///
/// A field is present exactly when the source substrate field is present, so a surface can apply
/// the same "show it whenever it is hash-bound" rules it applies today. This is deliberately a
/// different type from [`SyntacticSubstrate`]: its strings are a rendering of hashed bytes and must
/// never be fed back into hashing, matching, or a wire message.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisplaySubstrate {
    /// Escaped `bin`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bin: Option<String>,
    /// Escaped `argv`, one entry per token (token boundaries are preserved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    /// Escaped `flags`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<String>>,
    /// Escaped `positionals`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub positionals: Option<Vec<String>>,
    /// Escaped working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Escaped remote host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Escaped environment-variable names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_refs: Option<Vec<String>>,
    /// Escaped server / gating-provider id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Escaped tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// `params` as compact JSON, escaped. JSON already writes C0 controls inside strings as
    /// `\uXXXX`; every other hidden character is escaped with this module's notation. Object keys
    /// appear in sorted order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params_json: Option<String>,
    /// `params` as indented JSON, one escaped display line per entry. JSON strings cannot contain a
    /// raw line feed, so the line breaks here are purely structural.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params_json_lines: Option<Vec<String>>,
    /// Escaped file-edit operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Escaped file-edit paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Escaped file-edit diff summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_summary: Option<String>,
    /// Escaped file-edit diff hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_hash: Option<String>,
    /// Escaped `raw`, as a single display line (a line feed renders as `\n`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// For `file_edit` only: `raw` split on line feeds, each line escaped. The line feeds of a
    /// multi-line edit are its structure, not hidden content, so they do not set
    /// [`DisplayModel::has_hidden_or_control_chars`]; anything else in a line (including a CR from
    /// CRLF endings) does. Absent for every other surface, where a line feed in `raw` is content
    /// and is escaped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_lines: Option<Vec<String>>,
}

/// Everything an approver shows the human about one approval request, already escaped.
///
/// Built by [`display_model`] from the decrypted [`ApprovalContext`] — the same value the device
/// hashes — so what is rendered is exactly what is bound into `request_hash`, minus nothing and plus
/// only visible escapes. Envelope metadata the surface also shows (`request_id`, `expires_at`, the
/// recomputed `request_hash`, the number-match code, the attestation outcome) is not part of the
/// context and is out of scope here; untrusted text among it goes through [`escape_for_display`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisplayModel {
    /// The action's surface (a closed enum — safe to show as-is).
    pub surface: Surface,
    /// Coarse risk tier.
    pub risk: Risk,
    /// Whether the action can be undone.
    pub reversible: bool,
    /// Escaped human-readable summary.
    pub summary: String,
    /// Escaped actor id.
    pub actor_id: String,
    /// Escaped actor kind.
    pub actor_kind: String,
    /// The actor as one label, `"<id> (<kind>)"`, both parts escaped.
    pub actor_label: String,
    /// The escaped syntactic substrate (`cwd` lives here as [`DisplaySubstrate::cwd`]).
    pub syntactic: DisplaySubstrate,
    /// Escaped upstream-gate ids.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<String>>,
    /// True when any string in the context contained a character that had to be escaped. Surfaces
    /// must show a prominent warning when this is set.
    pub has_hidden_or_control_chars: bool,
}

/// Escapes strings while remembering whether any escape was applied.
#[derive(Default)]
struct Escaper {
    found: bool,
}

impl Escaper {
    fn text(&mut self, s: &str) -> String {
        self.found |= has_hidden_or_control_chars(s);
        escape_for_display(s)
    }

    fn opt(&mut self, s: Option<&String>) -> Option<String> {
        s.map(|s| self.text(s))
    }

    fn list(&mut self, v: Option<&Vec<String>>) -> Option<Vec<String>> {
        v.map(|v| v.iter().map(|s| self.text(s)).collect())
    }

    /// Record whether any string (key or value) anywhere in a JSON value needs escaping. Needed for
    /// `params` because JSON serialization rewrites C0 controls as `\uXXXX` before escaping sees
    /// them.
    fn scan_json(&mut self, value: &serde_json::Value) {
        match value {
            serde_json::Value::String(s) => self.found |= has_hidden_or_control_chars(s),
            serde_json::Value::Array(items) => items.iter().for_each(|v| self.scan_json(v)),
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    self.found |= has_hidden_or_control_chars(k);
                    self.scan_json(v);
                }
            }
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
    }

    fn substrate(&mut self, surface: Surface, s: &SyntacticSubstrate) -> DisplaySubstrate {
        let (params_json, params_json_lines) = match &s.params {
            Some(params) => {
                self.scan_json(params);
                (
                    Some(escape_for_display(&params.to_string())),
                    Some(
                        serde_json::to_string_pretty(params)
                            .unwrap_or_else(|_| params.to_string())
                            .split('\n')
                            .map(escape_for_display)
                            .collect(),
                    ),
                )
            }
            None => (None, None),
        };

        let (raw, raw_lines) = match (&s.raw, surface) {
            (Some(raw), Surface::FileEdit) => {
                let lines = raw.split('\n').map(|line| self.text(line)).collect();
                (Some(escape_for_display(raw)), Some(lines))
            }
            (Some(raw), _) => (Some(self.text(raw)), None),
            (None, _) => (None, None),
        };

        DisplaySubstrate {
            bin: self.opt(s.bin.as_ref()),
            argv: self.list(s.argv.as_ref()),
            flags: self.list(s.flags.as_ref()),
            positionals: self.list(s.positionals.as_ref()),
            cwd: self.opt(s.cwd.as_ref()),
            host: self.opt(s.host.as_ref()),
            env_refs: self.list(s.env_refs.as_ref()),
            server: self.opt(s.server.as_ref()),
            tool: self.opt(s.tool.as_ref()),
            params_json,
            params_json_lines,
            operation: self.opt(s.operation.as_ref()),
            paths: self.list(s.paths.as_ref()),
            diff_summary: self.opt(s.diff_summary.as_ref()),
            diff_hash: self.opt(s.diff_hash.as_ref()),
            raw,
            raw_lines,
        }
    }
}

/// Build the escaped [`DisplayModel`] for an approval context.
///
/// Borrows `context` immutably: the hashed value is never altered, so `request_hash` is the same
/// before and after (asserted in this module's tests).
pub fn display_model(context: &ApprovalContext) -> DisplayModel {
    let mut esc = Escaper::default();
    let summary = esc.text(&context.summary);
    let actor_id = esc.text(&context.actor.id);
    let actor_kind = esc.text(&context.actor.kind);
    let actor_label = format!("{actor_id} ({actor_kind})");
    let syntactic = esc.substrate(context.action.surface, &context.action.syntactic);
    let chain = esc.list(context.chain.as_ref());
    DisplayModel {
        surface: context.action.surface,
        risk: context.risk,
        reversible: context.reversible,
        summary,
        actor_id,
        actor_kind,
        actor_label,
        syntactic,
        chain,
        has_hidden_or_control_chars: esc.found,
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for display escaping. Expected strings are written by hand from the notation in
    //! the module docs, never captured from program output.
    //!
    //! @see https://www.unicode.org/reports/tr9/ §2 (explicit bidi formatting characters)
    //! @see https://www.unicode.org/Public/UCD/latest/ucd/DerivedCoreProperties.txt
    //!      (Default_Ignorable_Code_Point)
    //! @see docs/threat-model.md R3 (WYSIWYS completeness)

    use super::*;
    use crate::contract::{ActionRecord, Actor, Constraints, Decision};
    use crate::hash::compute_request_hash;

    const EXPIRES_AT: i64 = 1_700_003_600_000;

    fn context_with(surface: Surface, syntactic: SyntacticSubstrate) -> ApprovalContext {
        ApprovalContext {
            action: ActionRecord {
                record_schema_version: 1,
                surface,
                syntactic,
                risk: Risk::High,
                capabilities: None,
                scope: None,
            },
            summary: "delete a directory".to_string(),
            actor: Actor {
                id: "machine:ci".to_string(),
                kind: "claude-code".to_string(),
                attestation: None,
            },
            risk: Risk::High,
            reversible: false,
            constraints: Constraints {
                allowed_decisions: vec![Decision::Approved, Decision::Denied],
                challenge_required: false,
            },
            chain: None,
        }
    }

    fn empty_substrate() -> SyntacticSubstrate {
        SyntacticSubstrate {
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
            operation: None,
            paths: None,
            diff_summary: None,
            diff_hash: None,
            raw: None,
        }
    }

    /// The #246 spoof: erase the line, return the cursor, repaint a benign command.
    const SPOOF: &str = "rm -rf ~/x; : \u{1b}[2K\rgit status";

    #[test]
    fn ascii_controls_use_short_notation() {
        assert_eq!(escape_for_display("a\tb\nc\rd"), "a\\tb\\nc\\rd");
        assert_eq!(escape_for_display("\u{0}\u{1b}\u{7f}"), "\\x00\\x1b\\x7f");
        assert_eq!(escape_for_display("\u{1f}"), "\\x1f");
    }

    #[test]
    fn spoof_payload_is_fully_visible() {
        assert_eq!(
            escape_for_display(SPOOF),
            "rm -rf ~/x; : \\x1b[2K\\rgit status"
        );
        assert!(has_hidden_or_control_chars(SPOOF));
    }

    #[test]
    fn c1_controls_use_codepoint_notation() {
        assert_eq!(
            escape_for_display("\u{80}\u{85}\u{9b}\u{9f}"),
            "⟨U+0080⟩⟨U+0085⟩⟨U+009B⟩⟨U+009F⟩"
        );
    }

    #[test]
    fn every_listed_bidi_control_is_escaped() {
        for (c, expected) in [
            ('\u{061C}', "⟨U+061C⟩"),
            ('\u{200E}', "⟨U+200E⟩"),
            ('\u{200F}', "⟨U+200F⟩"),
            ('\u{202A}', "⟨U+202A⟩"),
            ('\u{202B}', "⟨U+202B⟩"),
            ('\u{202C}', "⟨U+202C⟩"),
            ('\u{202D}', "⟨U+202D⟩"),
            ('\u{202E}', "⟨U+202E⟩"),
            ('\u{2066}', "⟨U+2066⟩"),
            ('\u{2067}', "⟨U+2067⟩"),
            ('\u{2068}', "⟨U+2068⟩"),
            ('\u{2069}', "⟨U+2069⟩"),
        ] {
            assert_eq!(escape_for_display(&c.to_string()), expected, "{c:?}");
        }
    }

    #[test]
    fn every_listed_zero_width_character_is_escaped() {
        for (c, expected) in [
            ('\u{200B}', "⟨U+200B⟩"),
            ('\u{200C}', "⟨U+200C⟩"),
            ('\u{200D}', "⟨U+200D⟩"),
            ('\u{2060}', "⟨U+2060⟩"),
            ('\u{FEFF}', "⟨U+FEFF⟩"),
        ] {
            assert_eq!(escape_for_display(&c.to_string()), expected, "{c:?}");
        }
    }

    #[test]
    fn additional_invisible_characters_are_escaped() {
        assert_eq!(escape_for_display("\u{AD}"), "⟨U+00AD⟩");
        assert_eq!(escape_for_display("\u{2028}\u{2029}"), "⟨U+2028⟩⟨U+2029⟩");
        assert_eq!(escape_for_display("\u{3164}"), "⟨U+3164⟩");
        // Tag characters can smuggle invisible ASCII ("A" = U+E0041).
        assert_eq!(escape_for_display("x\u{E0041}"), "x⟨U+E0041⟩");
    }

    #[test]
    fn boundaries_of_each_range_are_exact() {
        // Just outside each range stays printable.
        for c in [
            '\u{20}', '\u{7E}', '\u{A0}', '\u{2027}', '\u{202F}', '\u{2070}', '\u{FEFE}',
        ] {
            assert!(!is_hidden_or_control_char(c), "{c:?} must not be escaped");
        }
    }

    #[test]
    fn ordinary_unicode_and_variation_selectors_pass_through() {
        for text in [
            "git status",
            "naïve café",
            "日本語",
            "שלום",
            "✅",
            "⚠\u{FE0F}",
            "a\u{E0100}",
        ] {
            assert_eq!(escape_for_display(text), text);
            assert!(!has_hidden_or_control_chars(text), "{text:?}");
        }
    }

    #[test]
    fn escaping_is_idempotent() {
        let once = escape_for_display(SPOOF);
        assert_eq!(escape_for_display(&once), once);
        assert!(!has_hidden_or_control_chars(&once));
    }

    #[test]
    fn display_model_escapes_every_context_string_and_sets_the_flag() {
        let mut ctx = context_with(
            Surface::Command,
            SyntacticSubstrate {
                bin: Some("rm".to_string()),
                argv: Some(vec!["rm".into(), "-rf".into(), "~/x\u{1b}[2K".into()]),
                flags: Some(vec!["-rf".into()]),
                positionals: Some(vec!["~/x\u{1b}[2K".into()]),
                cwd: Some("/repo\u{202E}".to_string()),
                host: Some("h\u{200B}".to_string()),
                env_refs: Some(vec!["HOME\u{7f}".into()]),
                raw: Some(SPOOF.to_string()),
                ..empty_substrate()
            },
        );
        ctx.summary = "harmless\rcheck".to_string();
        ctx.actor.id = "machine:\u{202E}ci".to_string();
        ctx.actor.kind = "kind\u{0}".to_string();
        ctx.chain = Some(vec!["gate\u{9b}".to_string()]);

        let model = display_model(&ctx);
        assert!(model.has_hidden_or_control_chars);
        assert_eq!(model.summary, "harmless\\rcheck");
        assert_eq!(model.actor_id, "machine:⟨U+202E⟩ci");
        assert_eq!(model.actor_kind, "kind\\x00");
        assert_eq!(model.actor_label, "machine:⟨U+202E⟩ci (kind\\x00)");
        assert_eq!(model.chain, Some(vec!["gate⟨U+009B⟩".to_string()]));
        let s = &model.syntactic;
        assert_eq!(s.bin.as_deref(), Some("rm"));
        assert_eq!(
            s.argv,
            Some(vec!["rm".into(), "-rf".into(), "~/x\\x1b[2K".into()])
        );
        assert_eq!(s.positionals, Some(vec!["~/x\\x1b[2K".into()]));
        assert_eq!(s.cwd.as_deref(), Some("/repo⟨U+202E⟩"));
        assert_eq!(s.host.as_deref(), Some("h⟨U+200B⟩"));
        assert_eq!(s.env_refs, Some(vec!["HOME\\x7f".into()]));
        assert_eq!(
            s.raw.as_deref(),
            Some("rm -rf ~/x; : \\x1b[2K\\rgit status")
        );
        assert_eq!(s.raw_lines, None, "raw_lines is file_edit only");
    }

    #[test]
    fn clean_context_does_not_set_the_flag() {
        let ctx = context_with(
            Surface::Command,
            SyntacticSubstrate {
                bin: Some("git".into()),
                argv: Some(vec!["git".into(), "status".into()]),
                raw: Some("git status".into()),
                ..empty_substrate()
            },
        );
        let model = display_model(&ctx);
        assert!(!model.has_hidden_or_control_chars);
        assert_eq!(model.actor_label, "machine:ci (claude-code)");
        assert_eq!(model.syntactic.raw.as_deref(), Some("git status"));
    }

    #[test]
    fn each_field_alone_sets_the_flag() {
        // One negative case per field: a hidden character anywhere must raise the warning.
        type Mutator = fn(&mut ApprovalContext);
        let cases: [(&str, Mutator); 8] = [
            ("summary", |c| c.summary.push('\u{202E}')),
            ("actor.id", |c| c.actor.id.push('\u{1b}')),
            ("actor.kind", |c| c.actor.kind.push('\u{200B}')),
            ("chain", |c| c.chain = Some(vec!["\r".into()])),
            ("cwd", |c| c.action.syntactic.cwd = Some("\u{85}".into())),
            ("tool", |c| {
                c.action.syntactic.tool = Some("t\u{2066}".into())
            }),
            ("server", |c| {
                c.action.syntactic.server = Some("\u{FEFF}s".into())
            }),
            ("diff_hash", |c| {
                c.action.syntactic.diff_hash = Some("\u{0}".into())
            }),
        ];
        for (name, mutate) in cases {
            let mut ctx = context_with(Surface::Command, empty_substrate());
            assert!(!display_model(&ctx).has_hidden_or_control_chars);
            mutate(&mut ctx);
            assert!(display_model(&ctx).has_hidden_or_control_chars, "{name}");
        }
    }

    #[test]
    fn params_are_rendered_as_escaped_json_and_scanned_for_the_flag() {
        let ctx = context_with(
            Surface::McpToolCall,
            SyntacticSubstrate {
                server: Some("fs".into()),
                tool: Some("write".into()),
                params: Some(serde_json::json!({
                    "path": "/tmp/a\u{202E}txt",
                    "body": "x\u{1b}y",
                })),
                ..empty_substrate()
            },
        );
        let model = display_model(&ctx);
        assert!(model.has_hidden_or_control_chars);
        // Sorted keys; JSON escapes ESC as \u001b; the bidi override gets display notation.
        assert_eq!(
            model.syntactic.params_json.as_deref(),
            Some(r#"{"body":"x\u001by","path":"/tmp/a⟨U+202E⟩txt"}"#)
        );
        assert_eq!(
            model.syntactic.params_json_lines,
            Some(vec![
                "{".to_string(),
                r#"  "body": "x\u001by","#.to_string(),
                r#"  "path": "/tmp/a⟨U+202E⟩txt""#.to_string(),
                "}".to_string(),
            ])
        );
    }

    #[test]
    fn hidden_characters_in_a_params_key_set_the_flag() {
        let ctx = context_with(
            Surface::McpToolCall,
            SyntacticSubstrate {
                params: Some(serde_json::json!({ "pa\u{200B}th": 1 })),
                ..empty_substrate()
            },
        );
        assert!(display_model(&ctx).has_hidden_or_control_chars);
    }

    #[test]
    fn clean_params_do_not_set_the_flag() {
        let ctx = context_with(
            Surface::McpToolCall,
            SyntacticSubstrate {
                params: Some(serde_json::json!({ "path": "/tmp/a", "n": [1, true, null] })),
                ..empty_substrate()
            },
        );
        assert!(!display_model(&ctx).has_hidden_or_control_chars);
    }

    #[test]
    fn file_edit_lines_split_on_line_feed_without_flagging_it() {
        let ctx = context_with(
            Surface::FileEdit,
            SyntacticSubstrate {
                operation: Some("patch".into()),
                paths: Some(vec!["src/a.rs".into()]),
                raw: Some("-old\n+new".into()),
                ..empty_substrate()
            },
        );
        let model = display_model(&ctx);
        assert!(!model.has_hidden_or_control_chars);
        assert_eq!(
            model.syntactic.raw_lines,
            Some(vec!["-old".to_string(), "+new".to_string()])
        );
        assert_eq!(model.syntactic.raw.as_deref(), Some("-old\\n+new"));
    }

    #[test]
    fn file_edit_cr_and_bidi_inside_a_line_set_the_flag() {
        let ctx = context_with(
            Surface::FileEdit,
            SyntacticSubstrate {
                raw: Some("-old\r\n+ne\u{202E}w".into()),
                ..empty_substrate()
            },
        );
        let model = display_model(&ctx);
        assert!(model.has_hidden_or_control_chars);
        assert_eq!(
            model.syntactic.raw_lines,
            Some(vec!["-old\\r".to_string(), "+ne⟨U+202E⟩w".to_string()])
        );
    }

    #[test]
    fn command_raw_line_feed_is_content_and_sets_the_flag() {
        let ctx = context_with(
            Surface::Command,
            SyntacticSubstrate {
                raw: Some("echo hi\nrm -rf /".into()),
                ..empty_substrate()
            },
        );
        let model = display_model(&ctx);
        assert!(model.has_hidden_or_control_chars);
        assert_eq!(model.syntactic.raw.as_deref(), Some("echo hi\\nrm -rf /"));
    }

    #[test]
    fn display_model_never_changes_the_request_hash() {
        let ctx = context_with(
            Surface::Command,
            SyntacticSubstrate {
                raw: Some(SPOOF.to_string()),
                ..empty_substrate()
            },
        );
        let before = compute_request_hash(&ctx, EXPIRES_AT);
        let model = display_model(&ctx);
        let after = compute_request_hash(&ctx, EXPIRES_AT);
        assert_eq!(before, after);

        // The hash binds the real bytes, not their display form: substituting the escaped text
        // yields a different hash.
        let mut displayed = ctx.clone();
        displayed.action.syntactic.raw = model.syntactic.raw.clone();
        assert_ne!(compute_request_hash(&displayed, EXPIRES_AT), before);
    }

    #[test]
    fn model_serializes_with_snake_case_enums_and_omits_absent_fields() {
        let ctx = context_with(
            Surface::AgentToolCall,
            SyntacticSubstrate {
                server: Some("plugin".into()),
                tool: Some("t".into()),
                ..empty_substrate()
            },
        );
        let json = serde_json::to_value(display_model(&ctx)).expect("model serializes");
        assert_eq!(json["surface"], "agent_tool_call");
        assert_eq!(json["risk"], "high");
        assert_eq!(json["has_hidden_or_control_chars"], false);
        assert_eq!(
            json["syntactic"],
            serde_json::json!({ "server": "plugin", "tool": "t" })
        );
        assert!(json.get("chain").is_none());
    }
}
