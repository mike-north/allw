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
//!   …), with variation selectors handled by context (below);
//! - **line/paragraph separators** U+2028, U+2029 and the interlinear-annotation controls
//!   U+FFF9–U+FFFB, which break or hide lines in some renderers; and
//! - **U+2800 BRAILLE PATTERN BLANK**, which renders as an empty cell but is neither whitespace nor
//!   default-ignorable, so `rm⠀-rf⠀/` would otherwise read as three tokens.
//!
//! ## Variation selectors
//!
//! Variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF, Mongolian U+180B–U+180D and U+180F) are
//! invisible, and a run of them can encode an arbitrary hidden payload (each selector carries a
//! byte — "emoji smuggling"). A selector after ASCII has no glyph to select, so `main` + U+FE0F
//! looks exactly like `main`. A selector is therefore escaped **unless** it is
//!
//! - the **first** selector directly after a non-ASCII base character that is itself shown as-is
//!   (not escaped, not a selector, not a combining diacritical mark), as in `⚠️` (U+26A0 U+FE0F) or a
//!   CJK ideographic variation sequence; or
//! - U+FE0F inside an emoji keycap: ASCII `0`–`9`, `#` or `*`, then U+FE0F, then U+20E3 (`1️⃣`).
//!
//! Every other selector — the second and later in a run, one after ASCII, one after a combining
//! mark — is escaped and sets the flag. A legitimate emoji or CJK sequence therefore never warns,
//! and a smuggling run can carry at most one hidden selector per visible base character.
//!
//! # Structure inside multi-line content
//!
//! `raw` is multi-line content: a shell command with a heredoc, or a file edit. In
//! [`DisplaySubstrate::raw_lines`] a line feed is **structure** (the content is split on it), a TAB
//! renders as [`TAB_MARKER`], and a CR directly before a line feed renders as [`CRLF_MARKER`].
//! None of these set the flag: once ESC and lone CRs are escaped, a TAB or a line ending cannot
//! overwrite or hide anything, and flagging every Go edit or heredoc commit would train humans to
//! ignore the warning. Everywhere else — single-line fields (argv tokens, `bin`, flags, `cwd`, ids,
//! the summary) and the single-line [`DisplaySubstrate::raw`] — TAB, LF and CR are escaped and set
//! the flag, because they have no business there.
//!
//! # Notation
//!
//! - TAB, LF, CR render as `\t`, `\n`, `\r`.
//! - Every other C0 control and DEL renders as `\xHH` with lowercase hex (ESC → `\x1b`).
//! - Everything else renders as `⟨U+XXXX⟩` with at least four uppercase hex digits
//!   (U+202E → `⟨U+202E⟩`, U+E0041 → `⟨U+E0041⟩`).
//! - In `raw_lines` only: TAB → [`TAB_MARKER`], CR before LF → [`CRLF_MARKER`] (no flag).
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
            // Braille pattern blank: an empty-looking cell that is neither whitespace nor
            // default-ignorable.
            | '\u{2800}'
            // Tag characters and the surrounding default-ignorable planes (variation selectors
            // U+E0100–U+E01EF are handled by context; see `is_variation_selector`).
            | '\u{E0000}'..='\u{E00FF}'
            | '\u{E01F0}'..='\u{E0FFF}'
    )
}

/// Whether `c` is a variation selector (U+FE00–U+FE0F, U+E0100–U+E01EF, Mongolian U+180B–U+180D,
/// U+180F).
///
/// Variation selectors are escaped by context rather than unconditionally: the first selector after
/// a non-ASCII base shows as-is (emoji presentation, CJK variants); every other one is escaped. See
/// the module docs, "Variation selectors".
pub fn is_variation_selector(c: char) -> bool {
    matches!(
        c,
        '\u{180B}'..='\u{180D}' | '\u{180F}' | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
    )
}

/// The combining-diacritical-mark blocks. A variation selector after one of these has no base glyph
/// of its own to select, so it is escaped like one after ASCII. This is a block-level check, not the
/// full `Mn`/`Me` category; it exists so a run of accents cannot each carry a hidden selector.
fn is_combining_diacritic(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE20}'..='\u{FE2F}'
    )
}

/// Whether a variation selector directly after `prev` selects a glyph form of it (and so is shown
/// as-is when it is the first selector after it).
fn is_variation_base(prev: char) -> bool {
    !prev.is_ascii()
        && !is_hidden_or_control_char(prev)
        && !is_variation_selector(prev)
        && !is_combining_diacritic(prev)
}

/// Where the text being escaped sits, which decides whether TAB is structure.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Context {
    /// A single-line field: every hidden or control character is escaped and flagged.
    SingleLine,
    /// One line of multi-line content: TAB is structure.
    ContentLine,
}

/// How a TAB inside multi-line content ([`DisplaySubstrate::raw_lines`]) is shown: a visible arrow
/// padded to four columns, so indentation stays readable. It does not set the flag.
pub const TAB_MARKER: &str = "→   ";

/// How a CR directly before a line feed (a CRLF line ending) is shown at the end of a
/// [`DisplaySubstrate::raw_lines`] entry. It does not set the flag; a CR anywhere else is escaped
/// as `\r` and does.
pub const CRLF_MARKER: &str = "␍";

/// Escape `text` into `out`, returning whether any flagged escape was applied.
///
/// This is the single escaping engine: [`escape_for_display`], [`has_hidden_or_control_chars`] and
/// the [`DisplayModel`] builder all go through it, so the flag and the rendering can never disagree.
fn escape_into(out: &mut String, text: &str, context: Context) -> bool {
    let mut flagged = false;
    let mut prev: Option<char> = None;
    // Whether the previous character was a selector shown as-is (so the next one would be a run).
    let mut prev_selector_shown = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let mut selector_shown = false;
        if c == '\t' && context == Context::ContentLine {
            out.push_str(TAB_MARKER);
        } else if is_hidden_or_control_char(c) {
            push_escaped(out, c);
            flagged = true;
        } else if is_variation_selector(c) {
            let after_base = !prev_selector_shown && prev.is_some_and(is_variation_base);
            let keycap = c == '\u{FE0F}'
                && prev.is_some_and(|p| p.is_ascii_digit() || p == '#' || p == '*')
                && chars.peek() == Some(&'\u{20E3}');
            if after_base || keycap {
                out.push(c);
                selector_shown = true;
            } else {
                push_codepoint(out, c);
                flagged = true;
            }
        } else {
            out.push(c);
        }
        prev = Some(c);
        prev_selector_shown = selector_shown;
    }
    flagged
}

/// Whether `text` contains any character [`escape_for_display`] would escape (including a
/// variation selector outside the allowed contexts).
pub fn has_hidden_or_control_chars(text: &str) -> bool {
    escape_into(
        &mut String::with_capacity(text.len()),
        text,
        Context::SingleLine,
    )
}

/// Render `text` for display, replacing every hidden or control character with a visible escape.
///
/// Printable text (including all ordinary non-ASCII letters, emoji, and a variation selector in an
/// allowed position) passes through unchanged. The output never contains a character for which
/// [`is_hidden_or_control_char`] is true, and escaping is idempotent: escaping already-escaped
/// output returns it unchanged. This is the single-line rendering: TAB, LF and CR are escaped.
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
    escape_into(&mut out, text, Context::SingleLine);
    out
}

/// Append the visible escape for a hidden or control character `c`.
fn push_escaped(out: &mut String, c: char) {
    match c {
        '\t' => out.push_str("\\t"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\u{0000}'..='\u{001F}' | '\u{007F}' => {
            // Writing to a String is infallible.
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        }
        _ => push_codepoint(out, c),
    }
}

/// Append `c` in `⟨U+XXXX⟩` notation.
fn push_codepoint(out: &mut String, c: char) {
    // Writing to a String is infallible.
    let _ = write!(out, "⟨U+{:04X}⟩", u32::from(c));
}

/// Render multi-line content as display lines: split on LF (structure), show a CR directly before
/// an LF as [`CRLF_MARKER`] and a TAB as [`TAB_MARKER`] (both unflagged), and escape everything
/// else as a single-line field would. Returns the lines and whether any flagged escape was applied.
fn content_lines(text: &str) -> (Vec<String>, bool) {
    let mut flagged = false;
    let segments: Vec<&str> = text.split('\n').collect();
    let last = segments.len() - 1;
    let lines = segments
        .iter()
        .enumerate()
        .map(|(i, segment)| {
            // Only a CR that is followed by an LF is a line ending; a trailing CR on the final
            // segment (no LF after it) is an ordinary CR and is escaped.
            let (body, crlf) = match segment.strip_suffix('\r') {
                Some(body) if i < last => (body, true),
                _ => (*segment, false),
            };
            let mut line = String::with_capacity(body.len());
            flagged |= escape_into(&mut line, body, Context::ContentLine);
            if crlf {
                line.push_str(CRLF_MARKER);
            }
            line
        })
        .collect();
    (lines, flagged)
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
    /// Escaped `raw`, as a single display line (TAB, LF and CR render as `\t`, `\n`, `\r`). For
    /// a compact one-line rendering, such as a headline repeated next to the decision prompt. The
    /// flag is computed from [`Self::raw_lines`], not from this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// `raw` as multi-line content, present whenever `raw` is: split on line feeds, each line
    /// escaped. Line feeds, TABs (shown as [`TAB_MARKER`]) and a CR directly before a line feed
    /// (shown as [`CRLF_MARKER`]) are structure and do not set
    /// [`DisplayModel::has_hidden_or_control_chars`]; anything else that is escaped does. This is
    /// the field a surface prints as the full action (a multi-line command as continuation lines, a
    /// file edit as its content).
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
        let mut out = String::with_capacity(s.len());
        self.found |= escape_into(&mut out, s, Context::SingleLine);
        out
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

    fn substrate(&mut self, s: &SyntacticSubstrate) -> DisplaySubstrate {
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

        let (raw, raw_lines) = match &s.raw {
            Some(raw) => {
                let (lines, flagged) = content_lines(raw);
                self.found |= flagged;
                (Some(escape_for_display(raw)), Some(lines))
            }
            None => (None, None),
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
    let syntactic = esc.substrate(&context.action.syntactic);
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
    fn ordinary_unicode_and_legitimate_variation_sequences_pass_through() {
        for text in [
            "git status",
            "naïve café",
            "日本語",
            "שלום",
            "✅",
            // Emoji presentation: one VS-16 after a non-ASCII base.
            "⚠\u{FE0F} careful",
            // Keycap: ASCII digit/#/*, VS-16, combining enclosing keycap.
            "1\u{FE0F}\u{20E3} #\u{FE0F}\u{20E3} *\u{FE0F}\u{20E3}",
            // CJK ideographic variation sequence (葛 + VS-17).
            "\u{845B}\u{E0100}",
            // Mongolian free variation selector after a Mongolian letter.
            "\u{1820}\u{180B}",
        ] {
            assert_eq!(escape_for_display(text), text);
            assert!(!has_hidden_or_control_chars(text), "{text:?}");
        }
    }

    #[test]
    fn a_variation_selector_run_is_escaped_after_the_first() {
        // "Emoji smuggling": bytes encoded as selectors after one emoji. Only the first is shown.
        let text = "Looks fine \u{1F600}\u{FE0F}\u{FE01}\u{E0100}\u{E01EF}";
        assert_eq!(
            escape_for_display(text),
            "Looks fine \u{1F600}\u{FE0F}⟨U+FE01⟩⟨U+E0100⟩⟨U+E01EF⟩"
        );
        assert!(has_hidden_or_control_chars(text));
    }

    #[test]
    fn a_variation_selector_after_ascii_is_escaped() {
        // `main` + VS-16 looks exactly like `main`.
        assert_eq!(escape_for_display("main\u{FE0F}"), "main⟨U+FE0F⟩");
        assert!(has_hidden_or_control_chars("main\u{FE0F}"));
        // A selector with no base at all, and VS-15 inside a would-be keycap, are escaped too.
        assert_eq!(escape_for_display("\u{FE0F}"), "⟨U+FE0F⟩");
        assert_eq!(escape_for_display("1\u{FE0E}\u{20E3}"), "1⟨U+FE0E⟩\u{20E3}");
        // VS-16 after a keycap digit without the enclosing keycap is just a selector after ASCII.
        assert_eq!(escape_for_display("1\u{FE0F}"), "1⟨U+FE0F⟩");
    }

    #[test]
    fn a_variation_selector_after_a_hidden_or_combining_character_is_escaped() {
        assert_eq!(escape_for_display("\u{200B}\u{FE0F}"), "⟨U+200B⟩⟨U+FE0F⟩");
        // A run of accents cannot each carry one hidden selector.
        assert_eq!(escape_for_display("e\u{0301}\u{FE01}"), "e\u{0301}⟨U+FE01⟩");
    }

    #[test]
    fn braille_pattern_blank_is_escaped() {
        assert_eq!(
            escape_for_display("rm\u{2800}-rf\u{2800}/"),
            "rm⟨U+2800⟩-rf⟨U+2800⟩/"
        );
        assert!(has_hidden_or_control_chars("main\u{2800}"));
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
        assert_eq!(
            s.raw_lines,
            Some(vec!["rm -rf ~/x; : \\x1b[2K\\rgit status".to_string()]),
            "a lone CR inside a line is escaped, not treated as a line ending"
        );
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
            Some(vec!["-old␍".to_string(), "+ne⟨U+202E⟩w".to_string()])
        );
    }

    fn raw_model(surface: Surface, raw: &str) -> DisplayModel {
        display_model(&context_with(
            surface,
            SyntacticSubstrate {
                raw: Some(raw.into()),
                ..empty_substrate()
            },
        ))
    }

    #[test]
    fn a_go_file_edit_with_tabs_and_crlf_does_not_warn() {
        let model = raw_model(
            Surface::FileEdit,
            "func main() {\r\n\tfmt.Println(\"hi\")\r\n}",
        );
        assert!(!model.has_hidden_or_control_chars);
        assert_eq!(
            model.syntactic.raw_lines,
            Some(vec![
                "func main() {␍".to_string(),
                "→   fmt.Println(\"hi\")␍".to_string(),
                "}".to_string(),
            ])
        );
    }

    #[test]
    fn a_heredoc_commit_command_is_multi_line_content_and_does_not_warn() {
        let raw = "git commit -m \"$(cat <<'EOF'\nfix: a thing\n\n\tdetail\nEOF\n)\"";
        let model = raw_model(Surface::Command, raw);
        assert!(!model.has_hidden_or_control_chars);
        assert_eq!(
            model.syntactic.raw_lines,
            Some(vec![
                "git commit -m \"$(cat <<'EOF'".to_string(),
                "fix: a thing".to_string(),
                String::new(),
                "→   detail".to_string(),
                "EOF".to_string(),
                ")\"".to_string(),
            ])
        );
        // The single-line form still shows every separator.
        assert_eq!(
            model.syntactic.raw.as_deref(),
            Some("git commit -m \"$(cat <<'EOF'\\nfix: a thing\\n\\n\\tdetail\\nEOF\\n)\"")
        );
    }

    #[test]
    fn an_esc_cr_spoof_inside_multi_line_content_still_warns() {
        for surface in [Surface::Command, Surface::FileEdit] {
            let model = raw_model(surface, "echo ok\nrm -rf ~/x; : \u{1b}[2K\rgit status");
            assert!(model.has_hidden_or_control_chars, "{surface:?}");
            assert_eq!(
                model.syntactic.raw_lines,
                Some(vec![
                    "echo ok".to_string(),
                    "rm -rf ~/x; : \\x1b[2K\\rgit status".to_string(),
                ])
            );
        }
    }

    #[test]
    fn a_trailing_cr_with_no_line_feed_after_it_warns() {
        let model = raw_model(Surface::Command, "ls\r");
        assert!(model.has_hidden_or_control_chars);
        assert_eq!(model.syntactic.raw_lines, Some(vec!["ls\\r".to_string()]));
    }

    #[test]
    fn tab_lf_and_cr_in_single_line_fields_still_warn() {
        type Mutator = fn(&mut ApprovalContext);
        let cases: [(&str, Mutator); 5] = [
            ("argv", |c| {
                c.action.syntactic.argv = Some(vec!["rm\t-rf".into()])
            }),
            ("bin", |c| c.action.syntactic.bin = Some("rm\n".into())),
            ("flags", |c| {
                c.action.syntactic.flags = Some(vec!["-f\r".into()])
            }),
            ("cwd", |c| c.action.syntactic.cwd = Some("/tmp\t".into())),
            ("summary", |c| c.summary.push('\n')),
        ];
        for (name, mutate) in cases {
            let mut ctx = context_with(Surface::Command, empty_substrate());
            mutate(&mut ctx);
            assert!(display_model(&ctx).has_hidden_or_control_chars, "{name}");
        }
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
