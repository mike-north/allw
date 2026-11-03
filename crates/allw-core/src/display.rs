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
//! invisible, and each one can carry a hidden byte ("emoji smuggling"): one selector after every
//! bullet, em dash or accented letter of an ordinary message exfiltrates a secret, and a selector
//! after ASCII makes `main` + U+FE0F look exactly like `main`. A selector is therefore shown as-is
//! only directly after a base its range actually defines variants for:
//!
//! - **U+FE0E / U+FE0F** after a non-ASCII base listed in Unicode `emoji-variation-sequences.txt`
//!   (Emoji 16.0; `EMOJI_VARIATION_BASES`), as in `⚠️` or `❤️`; or U+FE0F inside an emoji keycap
//!   (ASCII `0`–`9`, `#` or `*`, then U+FE0F, then U+20E3, as in `1️⃣`);
//! - **U+E0100–U+E01EF** (ideographic variation selectors) after a `Unified_Ideograph`, as in a
//!   CJK ideographic variation sequence;
//! - **U+180B–U+180D, U+180F** after a Mongolian-block character (U+1800–U+18AF).
//!
//! U+FE00–U+FE0D are always escaped, and so is every selector anywhere else — after ASCII, after
//! punctuation or a letter outside those tables, after any combining mark (General_Category `Mn` or
//! `Me`, including the Mongolian-block marks), or after another selector. An escaped selector sets
//! the flag.
//!
//! **Accepted residual.** A shown selector still carries a little information, because a base may
//! take more than one selector: about 1 bit per listed emoji (U+FE0E or U+FE0F), and up to about one
//! byte per CJK ideograph (240 ideographic selectors). Hiding a payload this way needs a matching run
//! of emoji or CJK text in the request; plain prose with bullets, dashes, quotes or non-CJK letters
//! can no longer carry one. This residual is a deliberate trade-off against warning on every emoji
//! and every CJK variant form (`docs/threat-model.md` R3).
//!
//! ## Stacked combining marks
//!
//! A combining mark (General_Category `Mn` or `Me`, [`is_combining_mark`]) draws on the character
//! before it. A few are ordinary (`é` decomposed is `e` + U+0301), but dozens stacked on one base
//! ("zalgo" text) overflow the line box and can paint over the line above or below, such as the
//! `cwd:` or origin line of an approval card. So at most [`MAX_STACKED_COMBINING_MARKS`] (2)
//! consecutive combining marks are shown; the third and every later mark of the same run render as
//! `⟨U+XXXX⟩` and set the flag. A run is counted over the input: any character that is not a
//! combining mark ends it, and a variation selector (also `Mn`) counts toward it.
//!
//! **Accepted false positives.** A few scripts legitimately stack three or more marks on one base:
//! Tibetan stacks with vowel signs (`ཧཱུྃ`), Hebrew with points and cantillation marks, and some
//! Indic clusters. These warn and show their later marks escaped. That fails safe (the human is
//! warned and still sees every code point), and such text is rare in commands and tool calls.
//!
//! # Structure inside multi-line content
//!
//! `raw` is multi-line content: a shell command with a heredoc, or a file edit. In
//! [`DisplaySubstrate::raw_lines`] a line feed is **structure** (the content is split on it) and a
//! TAB renders as [`TAB_MARKER`]; neither sets the flag. Once ESC and lone CRs are escaped, a TAB
//! or a line feed cannot overwrite or hide anything, and flagging every Go edit or heredoc commit
//! would train humans to ignore the warning.
//!
//! A CR directly before a line feed is structure **only for a file edit**, where CRLF line endings
//! are ordinary content: it renders as [`CRLF_MARKER`] without setting the flag. On every other
//! surface `raw` is executed (by a shell, or as a tool's input), and there a CR before LF is data,
//! not a line ending: in bash, `cd ../scratch` + CR + LF + `rm -rf -- *` fails the `cd` (the target
//! is `../scratch` + CR) and runs the `rm` in the original directory. So outside a file edit that
//! CR is escaped as `\r` and sets the flag, like any other CR.
//!
//! Everywhere else — single-line fields (argv tokens, `bin`, flags, `cwd`, ids, the summary) and
//! the single-line [`DisplaySubstrate::raw`] — TAB, LF and CR are escaped and set the flag, because
//! they have no business there.
//!
//! # Notation
//!
//! - TAB, LF, CR render as `\t`, `\n`, `\r`.
//! - Every other C0 control and DEL renders as `\xHH` with lowercase hex (ESC → `\x1b`).
//! - Everything else renders as `⟨U+XXXX⟩` with at least four uppercase hex digits
//!   (U+202E → `⟨U+202E⟩`, U+E0041 → `⟨U+E0041⟩`).
//! - In `raw_lines` only: TAB → [`TAB_MARKER`], and in a file edit CR before LF →
//!   [`CRLF_MARKER`] (no flag).
//!
//! The notation is not injective against *literal* text: a string containing the four printable
//! characters `\x1b` displays the same as one containing an ESC byte. That is why every model
//! carries [`DisplayModel::has_hidden_or_control_chars`] — surfaces show a warning whenever an
//! escape was applied, so the human always knows when what they read is a stand-in for a byte they
//! cannot see.
//!
//! The two structure markers are not injective either, and they **never** set the flag: a line
//! containing the literal text `→   ` displays exactly like one with a TAB, and a file-edit line
//! ending in a literal `␍` displays exactly like a CRLF ending. This is accepted because neither
//! substitution changes what the content does in a way the human could be misled about: a TAB and
//! four characters of indentation are both whitespace to a reader, and a CRLF ending is shown only
//! for file content, where it is not executed. The hash still binds the real bytes.
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

/// How many combining marks in a row one base may carry before the rest are escaped. Two covers
/// ordinary accented text, including Vietnamese letters with two diacritics (`ệ` decomposed is `e`
/// U+0323 U+0302); more lets a stack of marks overflow its line (see the module docs, "Stacked
/// combining marks").
pub const MAX_STACKED_COMBINING_MARKS: usize = 2;

/// Whether `c` is a combining mark: General_Category `Mn` or `Me` (Unicode 16.0.0), which draws on
/// the character before it instead of taking its own cell.
pub fn is_combining_mark(c: char) -> bool {
    COMBINING_MARK_RANGES
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Whether `c` is a `Unified_Ideograph` (Unicode 16.0.0 `PropList.txt`): the only bases after
/// which an ideographic variation selector (U+E0100–U+E01EF) is shown.
///
/// @see https://www.unicode.org/Public/16.0.0/ucd/PropList.txt
fn is_unified_ideograph(c: char) -> bool {
    matches!(
        c,
        '\u{3400}'..='\u{4DBF}'
            | '\u{4E00}'..='\u{9FFF}'
            | '\u{FA0E}'..='\u{FA0F}'
            | '\u{FA11}'
            | '\u{FA13}'..='\u{FA14}'
            | '\u{FA1F}'
            | '\u{FA21}'
            | '\u{FA23}'..='\u{FA24}'
            | '\u{FA27}'..='\u{FA29}'
            | '\u{20000}'..='\u{2A6DF}'
            | '\u{2A700}'..='\u{2B739}'
            | '\u{2B740}'..='\u{2B81D}'
            | '\u{2B820}'..='\u{2CEA1}'
            | '\u{2CEB0}'..='\u{2EBE0}'
            | '\u{2EBF0}'..='\u{2EE5D}'
            | '\u{30000}'..='\u{3134A}'
            | '\u{31350}'..='\u{323AF}'
    )
}

/// Whether the variation selector `c`, between `prev` and `next`, is shown as-is rather than
/// escaped. Each selector range has its own allowed bases (see the module docs, "Variation
/// selectors"); a base is never itself a selector, a combining mark or a hidden character, so a
/// selector directly after another selector or after any combining mark is always escaped.
fn selector_is_shown(c: char, prev: Option<char>, next: Option<char>) -> bool {
    let Some(base) = prev.filter(|&p| {
        !is_variation_selector(p) && !is_combining_mark(p) && !is_hidden_or_control_char(p)
    }) else {
        return false;
    };
    match c {
        '\u{FE0E}' | '\u{FE0F}' => {
            EMOJI_VARIATION_BASES.binary_search(&base).is_ok()
                || (c == '\u{FE0F}'
                    && (base.is_ascii_digit() || base == '#' || base == '*')
                    && next == Some('\u{20E3}'))
        }
        '\u{E0100}'..='\u{E01EF}' => is_unified_ideograph(base),
        '\u{180B}'..='\u{180D}' | '\u{180F}' => ('\u{1800}'..='\u{18AF}').contains(&base),
        // U+FE00–U+FE0D (math, Myanmar, Phags-pa standardized variants): never shown.
        _ => false,
    }
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

/// How a CR directly before a line feed (a CRLF line ending) in a **file edit** is shown at the end
/// of a [`DisplaySubstrate::raw_lines`] entry. It does not set the flag. Any other CR — including a
/// CR before LF in a command or another executed surface — is escaped as `\r` and does.
pub const CRLF_MARKER: &str = "␍";

/// Escape `text` into `out`, returning whether any flagged escape was applied.
///
/// This is the single escaping engine: [`escape_for_display`], [`has_hidden_or_control_chars`] and
/// the [`DisplayModel`] builder all go through it, so the flag and the rendering can never disagree.
fn escape_into(out: &mut String, text: &str, context: Context) -> bool {
    let mut flagged = false;
    let mut prev: Option<char> = None;
    // Consecutive combining marks in the input so far, this one included (0 for any other char).
    let mut marks_in_run = 0usize;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        marks_in_run = if is_combining_mark(c) {
            marks_in_run + 1
        } else {
            0
        };
        if c == '\t' && context == Context::ContentLine {
            out.push_str(TAB_MARKER);
        } else if is_hidden_or_control_char(c) {
            push_escaped(out, c);
            flagged = true;
        } else if marks_in_run > MAX_STACKED_COMBINING_MARKS {
            push_codepoint(out, c);
            flagged = true;
        } else if is_variation_selector(c) {
            if selector_is_shown(c, prev, chars.peek().copied()) {
                out.push(c);
            } else {
                push_codepoint(out, c);
                flagged = true;
            }
        } else {
            out.push(c);
        }
        prev = Some(c);
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

/// Render multi-line content as display lines: split on LF (structure), show a TAB as
/// [`TAB_MARKER`] (unflagged), and escape everything else as a single-line field would. When
/// `crlf_is_structure` (file edits only), a CR directly before an LF is shown as [`CRLF_MARKER`]
/// without setting the flag; otherwise it is escaped as `\r` and flagged. Returns the lines and
/// whether any flagged escape was applied.
fn content_lines(text: &str, crlf_is_structure: bool) -> (Vec<String>, bool) {
    let mut flagged = false;
    let segments: Vec<&str> = text.split('\n').collect();
    let last = segments.len() - 1;
    let lines = segments
        .iter()
        .enumerate()
        .map(|(i, segment)| {
            // Only a CR that is followed by an LF is a line ending, and only in file content; a
            // trailing CR on the final segment (no LF after it) is an ordinary CR and is escaped.
            let (body, crlf) = match segment.strip_suffix('\r') {
                Some(body) if crlf_is_structure && i < last => (body, true),
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
    /// escaped. Line feeds and TABs (shown as [`TAB_MARKER`]) are structure and do not set
    /// [`DisplayModel::has_hidden_or_control_chars`]; in a file edit only, neither does a CR
    /// directly before a line feed (shown as [`CRLF_MARKER`]). Anything else that is escaped does,
    /// including a CR before LF in a command. This is
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

        let (raw, raw_lines) = match &s.raw {
            Some(raw) => {
                // CRLF is a line ending only in file content; everywhere else `raw` is executed and
                // a CR before LF is data (see the module docs).
                let (lines, flagged) = content_lines(raw, surface == Surface::FileEdit);
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

/// The non-ASCII bases of the emoji variation sequences: every code point listed with U+FE0E/U+FE0F
/// in Unicode `emoji-variation-sequences.txt`, **Emoji Version 16.0** (Unicode 16.0.0, file dated
/// 2024-05-01; each listed base has both the text and the emoji style). Sorted for binary search.
///
/// The file's ASCII bases (`#`, `*`, `0`–`9`) are deliberately left out: a selector after ASCII is
/// shown only in the full keycap form (`1` U+FE0F U+20E3), handled separately.
///
/// @see https://www.unicode.org/Public/16.0.0/ucd/emoji/emoji-variation-sequences.txt
/// @see https://www.unicode.org/reports/tr51/#def_emoji_presentation_sequence
#[rustfmt::skip]
const EMOJI_VARIATION_BASES: [char; 359] = [
    '\u{00A9}', '\u{00AE}', '\u{203C}', '\u{2049}', '\u{2122}', '\u{2139}', '\u{2194}',
    '\u{2195}', '\u{2196}', '\u{2197}', '\u{2198}', '\u{2199}', '\u{21A9}', '\u{21AA}',
    '\u{231A}', '\u{231B}', '\u{2328}', '\u{23CF}', '\u{23E9}', '\u{23EA}', '\u{23EB}',
    '\u{23EC}', '\u{23ED}', '\u{23EE}', '\u{23EF}', '\u{23F0}', '\u{23F1}', '\u{23F2}',
    '\u{23F3}', '\u{23F8}', '\u{23F9}', '\u{23FA}', '\u{24C2}', '\u{25AA}', '\u{25AB}',
    '\u{25B6}', '\u{25C0}', '\u{25FB}', '\u{25FC}', '\u{25FD}', '\u{25FE}', '\u{2600}',
    '\u{2601}', '\u{2602}', '\u{2603}', '\u{2604}', '\u{260E}', '\u{2611}', '\u{2614}',
    '\u{2615}', '\u{2618}', '\u{261D}', '\u{2620}', '\u{2622}', '\u{2623}', '\u{2626}',
    '\u{262A}', '\u{262E}', '\u{262F}', '\u{2638}', '\u{2639}', '\u{263A}', '\u{2640}',
    '\u{2642}', '\u{2648}', '\u{2649}', '\u{264A}', '\u{264B}', '\u{264C}', '\u{264D}',
    '\u{264E}', '\u{264F}', '\u{2650}', '\u{2651}', '\u{2652}', '\u{2653}', '\u{265F}',
    '\u{2660}', '\u{2663}', '\u{2665}', '\u{2666}', '\u{2668}', '\u{267B}', '\u{267E}',
    '\u{267F}', '\u{2692}', '\u{2693}', '\u{2694}', '\u{2695}', '\u{2696}', '\u{2697}',
    '\u{2699}', '\u{269B}', '\u{269C}', '\u{26A0}', '\u{26A1}', '\u{26A7}', '\u{26AA}',
    '\u{26AB}', '\u{26B0}', '\u{26B1}', '\u{26BD}', '\u{26BE}', '\u{26C4}', '\u{26C5}',
    '\u{26C8}', '\u{26CE}', '\u{26CF}', '\u{26D1}', '\u{26D3}', '\u{26D4}', '\u{26E9}',
    '\u{26EA}', '\u{26F0}', '\u{26F1}', '\u{26F2}', '\u{26F3}', '\u{26F4}', '\u{26F5}',
    '\u{26F7}', '\u{26F8}', '\u{26F9}', '\u{26FA}', '\u{26FD}', '\u{2702}', '\u{2705}',
    '\u{2708}', '\u{2709}', '\u{270A}', '\u{270B}', '\u{270C}', '\u{270D}', '\u{270F}',
    '\u{2712}', '\u{2714}', '\u{2716}', '\u{271D}', '\u{2721}', '\u{2728}', '\u{2733}',
    '\u{2734}', '\u{2744}', '\u{2747}', '\u{274C}', '\u{274E}', '\u{2753}', '\u{2754}',
    '\u{2755}', '\u{2757}', '\u{2763}', '\u{2764}', '\u{2795}', '\u{2796}', '\u{2797}',
    '\u{27A1}', '\u{27B0}', '\u{27BF}', '\u{2934}', '\u{2935}', '\u{2B05}', '\u{2B06}',
    '\u{2B07}', '\u{2B1B}', '\u{2B1C}', '\u{2B50}', '\u{2B55}', '\u{3030}', '\u{303D}',
    '\u{3297}', '\u{3299}', '\u{1F004}', '\u{1F170}', '\u{1F171}', '\u{1F17E}', '\u{1F17F}',
    '\u{1F202}', '\u{1F21A}', '\u{1F22F}', '\u{1F237}', '\u{1F30D}', '\u{1F30E}', '\u{1F30F}',
    '\u{1F315}', '\u{1F31C}', '\u{1F321}', '\u{1F324}', '\u{1F325}', '\u{1F326}', '\u{1F327}',
    '\u{1F328}', '\u{1F329}', '\u{1F32A}', '\u{1F32B}', '\u{1F32C}', '\u{1F336}', '\u{1F378}',
    '\u{1F37D}', '\u{1F393}', '\u{1F396}', '\u{1F397}', '\u{1F399}', '\u{1F39A}', '\u{1F39B}',
    '\u{1F39E}', '\u{1F39F}', '\u{1F3A7}', '\u{1F3AC}', '\u{1F3AD}', '\u{1F3AE}', '\u{1F3C2}',
    '\u{1F3C4}', '\u{1F3C6}', '\u{1F3CA}', '\u{1F3CB}', '\u{1F3CC}', '\u{1F3CD}', '\u{1F3CE}',
    '\u{1F3D4}', '\u{1F3D5}', '\u{1F3D6}', '\u{1F3D7}', '\u{1F3D8}', '\u{1F3D9}', '\u{1F3DA}',
    '\u{1F3DB}', '\u{1F3DC}', '\u{1F3DD}', '\u{1F3DE}', '\u{1F3DF}', '\u{1F3E0}', '\u{1F3ED}',
    '\u{1F3F3}', '\u{1F3F5}', '\u{1F3F7}', '\u{1F408}', '\u{1F415}', '\u{1F41F}', '\u{1F426}',
    '\u{1F43F}', '\u{1F441}', '\u{1F442}', '\u{1F446}', '\u{1F447}', '\u{1F448}', '\u{1F449}',
    '\u{1F44D}', '\u{1F44E}', '\u{1F453}', '\u{1F46A}', '\u{1F47D}', '\u{1F4A3}', '\u{1F4B0}',
    '\u{1F4B3}', '\u{1F4BB}', '\u{1F4BF}', '\u{1F4CB}', '\u{1F4DA}', '\u{1F4DF}', '\u{1F4E4}',
    '\u{1F4E5}', '\u{1F4E6}', '\u{1F4EA}', '\u{1F4EB}', '\u{1F4EC}', '\u{1F4ED}', '\u{1F4F7}',
    '\u{1F4F9}', '\u{1F4FA}', '\u{1F4FB}', '\u{1F4FD}', '\u{1F508}', '\u{1F50D}', '\u{1F512}',
    '\u{1F513}', '\u{1F549}', '\u{1F54A}', '\u{1F550}', '\u{1F551}', '\u{1F552}', '\u{1F553}',
    '\u{1F554}', '\u{1F555}', '\u{1F556}', '\u{1F557}', '\u{1F558}', '\u{1F559}', '\u{1F55A}',
    '\u{1F55B}', '\u{1F55C}', '\u{1F55D}', '\u{1F55E}', '\u{1F55F}', '\u{1F560}', '\u{1F561}',
    '\u{1F562}', '\u{1F563}', '\u{1F564}', '\u{1F565}', '\u{1F566}', '\u{1F567}', '\u{1F56F}',
    '\u{1F570}', '\u{1F573}', '\u{1F574}', '\u{1F575}', '\u{1F576}', '\u{1F577}', '\u{1F578}',
    '\u{1F579}', '\u{1F587}', '\u{1F58A}', '\u{1F58B}', '\u{1F58C}', '\u{1F58D}', '\u{1F590}',
    '\u{1F5A5}', '\u{1F5A8}', '\u{1F5B1}', '\u{1F5B2}', '\u{1F5BC}', '\u{1F5C2}', '\u{1F5C3}',
    '\u{1F5C4}', '\u{1F5D1}', '\u{1F5D2}', '\u{1F5D3}', '\u{1F5DC}', '\u{1F5DD}', '\u{1F5DE}',
    '\u{1F5E1}', '\u{1F5E3}', '\u{1F5E8}', '\u{1F5EF}', '\u{1F5F3}', '\u{1F5FA}', '\u{1F610}',
    '\u{1F687}', '\u{1F68D}', '\u{1F691}', '\u{1F694}', '\u{1F698}', '\u{1F6AD}', '\u{1F6B2}',
    '\u{1F6B9}', '\u{1F6BA}', '\u{1F6BC}', '\u{1F6CB}', '\u{1F6CD}', '\u{1F6CE}', '\u{1F6CF}',
    '\u{1F6E0}', '\u{1F6E1}', '\u{1F6E2}', '\u{1F6E3}', '\u{1F6E4}', '\u{1F6E5}', '\u{1F6E9}',
    '\u{1F6F0}', '\u{1F6F3}',
];

/// The code points whose General_Category is `Mn` (nonspacing mark) or `Me` (enclosing mark), as
/// inclusive ranges, from Unicode **16.0.0** `extracted/DerivedGeneralCategory.txt` (dated
/// 2024-04-30), with adjacent ranges merged. Sorted for binary search. Includes the variation
/// selectors, which are `Mn`.
///
/// @see https://www.unicode.org/Public/16.0.0/ucd/extracted/DerivedGeneralCategory.txt
#[rustfmt::skip]
const COMBINING_MARK_RANGES: [(char, char); 354] = [
    ('\u{0300}', '\u{036F}'), ('\u{0483}', '\u{0489}'), ('\u{0591}', '\u{05BD}'),
    ('\u{05BF}', '\u{05BF}'), ('\u{05C1}', '\u{05C2}'), ('\u{05C4}', '\u{05C5}'),
    ('\u{05C7}', '\u{05C7}'), ('\u{0610}', '\u{061A}'), ('\u{064B}', '\u{065F}'),
    ('\u{0670}', '\u{0670}'), ('\u{06D6}', '\u{06DC}'), ('\u{06DF}', '\u{06E4}'),
    ('\u{06E7}', '\u{06E8}'), ('\u{06EA}', '\u{06ED}'), ('\u{0711}', '\u{0711}'),
    ('\u{0730}', '\u{074A}'), ('\u{07A6}', '\u{07B0}'), ('\u{07EB}', '\u{07F3}'),
    ('\u{07FD}', '\u{07FD}'), ('\u{0816}', '\u{0819}'), ('\u{081B}', '\u{0823}'),
    ('\u{0825}', '\u{0827}'), ('\u{0829}', '\u{082D}'), ('\u{0859}', '\u{085B}'),
    ('\u{0897}', '\u{089F}'), ('\u{08CA}', '\u{08E1}'), ('\u{08E3}', '\u{0902}'),
    ('\u{093A}', '\u{093A}'), ('\u{093C}', '\u{093C}'), ('\u{0941}', '\u{0948}'),
    ('\u{094D}', '\u{094D}'), ('\u{0951}', '\u{0957}'), ('\u{0962}', '\u{0963}'),
    ('\u{0981}', '\u{0981}'), ('\u{09BC}', '\u{09BC}'), ('\u{09C1}', '\u{09C4}'),
    ('\u{09CD}', '\u{09CD}'), ('\u{09E2}', '\u{09E3}'), ('\u{09FE}', '\u{09FE}'),
    ('\u{0A01}', '\u{0A02}'), ('\u{0A3C}', '\u{0A3C}'), ('\u{0A41}', '\u{0A42}'),
    ('\u{0A47}', '\u{0A48}'), ('\u{0A4B}', '\u{0A4D}'), ('\u{0A51}', '\u{0A51}'),
    ('\u{0A70}', '\u{0A71}'), ('\u{0A75}', '\u{0A75}'), ('\u{0A81}', '\u{0A82}'),
    ('\u{0ABC}', '\u{0ABC}'), ('\u{0AC1}', '\u{0AC5}'), ('\u{0AC7}', '\u{0AC8}'),
    ('\u{0ACD}', '\u{0ACD}'), ('\u{0AE2}', '\u{0AE3}'), ('\u{0AFA}', '\u{0AFF}'),
    ('\u{0B01}', '\u{0B01}'), ('\u{0B3C}', '\u{0B3C}'), ('\u{0B3F}', '\u{0B3F}'),
    ('\u{0B41}', '\u{0B44}'), ('\u{0B4D}', '\u{0B4D}'), ('\u{0B55}', '\u{0B56}'),
    ('\u{0B62}', '\u{0B63}'), ('\u{0B82}', '\u{0B82}'), ('\u{0BC0}', '\u{0BC0}'),
    ('\u{0BCD}', '\u{0BCD}'), ('\u{0C00}', '\u{0C00}'), ('\u{0C04}', '\u{0C04}'),
    ('\u{0C3C}', '\u{0C3C}'), ('\u{0C3E}', '\u{0C40}'), ('\u{0C46}', '\u{0C48}'),
    ('\u{0C4A}', '\u{0C4D}'), ('\u{0C55}', '\u{0C56}'), ('\u{0C62}', '\u{0C63}'),
    ('\u{0C81}', '\u{0C81}'), ('\u{0CBC}', '\u{0CBC}'), ('\u{0CBF}', '\u{0CBF}'),
    ('\u{0CC6}', '\u{0CC6}'), ('\u{0CCC}', '\u{0CCD}'), ('\u{0CE2}', '\u{0CE3}'),
    ('\u{0D00}', '\u{0D01}'), ('\u{0D3B}', '\u{0D3C}'), ('\u{0D41}', '\u{0D44}'),
    ('\u{0D4D}', '\u{0D4D}'), ('\u{0D62}', '\u{0D63}'), ('\u{0D81}', '\u{0D81}'),
    ('\u{0DCA}', '\u{0DCA}'), ('\u{0DD2}', '\u{0DD4}'), ('\u{0DD6}', '\u{0DD6}'),
    ('\u{0E31}', '\u{0E31}'), ('\u{0E34}', '\u{0E3A}'), ('\u{0E47}', '\u{0E4E}'),
    ('\u{0EB1}', '\u{0EB1}'), ('\u{0EB4}', '\u{0EBC}'), ('\u{0EC8}', '\u{0ECE}'),
    ('\u{0F18}', '\u{0F19}'), ('\u{0F35}', '\u{0F35}'), ('\u{0F37}', '\u{0F37}'),
    ('\u{0F39}', '\u{0F39}'), ('\u{0F71}', '\u{0F7E}'), ('\u{0F80}', '\u{0F84}'),
    ('\u{0F86}', '\u{0F87}'), ('\u{0F8D}', '\u{0F97}'), ('\u{0F99}', '\u{0FBC}'),
    ('\u{0FC6}', '\u{0FC6}'), ('\u{102D}', '\u{1030}'), ('\u{1032}', '\u{1037}'),
    ('\u{1039}', '\u{103A}'), ('\u{103D}', '\u{103E}'), ('\u{1058}', '\u{1059}'),
    ('\u{105E}', '\u{1060}'), ('\u{1071}', '\u{1074}'), ('\u{1082}', '\u{1082}'),
    ('\u{1085}', '\u{1086}'), ('\u{108D}', '\u{108D}'), ('\u{109D}', '\u{109D}'),
    ('\u{135D}', '\u{135F}'), ('\u{1712}', '\u{1714}'), ('\u{1732}', '\u{1733}'),
    ('\u{1752}', '\u{1753}'), ('\u{1772}', '\u{1773}'), ('\u{17B4}', '\u{17B5}'),
    ('\u{17B7}', '\u{17BD}'), ('\u{17C6}', '\u{17C6}'), ('\u{17C9}', '\u{17D3}'),
    ('\u{17DD}', '\u{17DD}'), ('\u{180B}', '\u{180D}'), ('\u{180F}', '\u{180F}'),
    ('\u{1885}', '\u{1886}'), ('\u{18A9}', '\u{18A9}'), ('\u{1920}', '\u{1922}'),
    ('\u{1927}', '\u{1928}'), ('\u{1932}', '\u{1932}'), ('\u{1939}', '\u{193B}'),
    ('\u{1A17}', '\u{1A18}'), ('\u{1A1B}', '\u{1A1B}'), ('\u{1A56}', '\u{1A56}'),
    ('\u{1A58}', '\u{1A5E}'), ('\u{1A60}', '\u{1A60}'), ('\u{1A62}', '\u{1A62}'),
    ('\u{1A65}', '\u{1A6C}'), ('\u{1A73}', '\u{1A7C}'), ('\u{1A7F}', '\u{1A7F}'),
    ('\u{1AB0}', '\u{1ACE}'), ('\u{1B00}', '\u{1B03}'), ('\u{1B34}', '\u{1B34}'),
    ('\u{1B36}', '\u{1B3A}'), ('\u{1B3C}', '\u{1B3C}'), ('\u{1B42}', '\u{1B42}'),
    ('\u{1B6B}', '\u{1B73}'), ('\u{1B80}', '\u{1B81}'), ('\u{1BA2}', '\u{1BA5}'),
    ('\u{1BA8}', '\u{1BA9}'), ('\u{1BAB}', '\u{1BAD}'), ('\u{1BE6}', '\u{1BE6}'),
    ('\u{1BE8}', '\u{1BE9}'), ('\u{1BED}', '\u{1BED}'), ('\u{1BEF}', '\u{1BF1}'),
    ('\u{1C2C}', '\u{1C33}'), ('\u{1C36}', '\u{1C37}'), ('\u{1CD0}', '\u{1CD2}'),
    ('\u{1CD4}', '\u{1CE0}'), ('\u{1CE2}', '\u{1CE8}'), ('\u{1CED}', '\u{1CED}'),
    ('\u{1CF4}', '\u{1CF4}'), ('\u{1CF8}', '\u{1CF9}'), ('\u{1DC0}', '\u{1DFF}'),
    ('\u{20D0}', '\u{20F0}'), ('\u{2CEF}', '\u{2CF1}'), ('\u{2D7F}', '\u{2D7F}'),
    ('\u{2DE0}', '\u{2DFF}'), ('\u{302A}', '\u{302D}'), ('\u{3099}', '\u{309A}'),
    ('\u{A66F}', '\u{A672}'), ('\u{A674}', '\u{A67D}'), ('\u{A69E}', '\u{A69F}'),
    ('\u{A6F0}', '\u{A6F1}'), ('\u{A802}', '\u{A802}'), ('\u{A806}', '\u{A806}'),
    ('\u{A80B}', '\u{A80B}'), ('\u{A825}', '\u{A826}'), ('\u{A82C}', '\u{A82C}'),
    ('\u{A8C4}', '\u{A8C5}'), ('\u{A8E0}', '\u{A8F1}'), ('\u{A8FF}', '\u{A8FF}'),
    ('\u{A926}', '\u{A92D}'), ('\u{A947}', '\u{A951}'), ('\u{A980}', '\u{A982}'),
    ('\u{A9B3}', '\u{A9B3}'), ('\u{A9B6}', '\u{A9B9}'), ('\u{A9BC}', '\u{A9BD}'),
    ('\u{A9E5}', '\u{A9E5}'), ('\u{AA29}', '\u{AA2E}'), ('\u{AA31}', '\u{AA32}'),
    ('\u{AA35}', '\u{AA36}'), ('\u{AA43}', '\u{AA43}'), ('\u{AA4C}', '\u{AA4C}'),
    ('\u{AA7C}', '\u{AA7C}'), ('\u{AAB0}', '\u{AAB0}'), ('\u{AAB2}', '\u{AAB4}'),
    ('\u{AAB7}', '\u{AAB8}'), ('\u{AABE}', '\u{AABF}'), ('\u{AAC1}', '\u{AAC1}'),
    ('\u{AAEC}', '\u{AAED}'), ('\u{AAF6}', '\u{AAF6}'), ('\u{ABE5}', '\u{ABE5}'),
    ('\u{ABE8}', '\u{ABE8}'), ('\u{ABED}', '\u{ABED}'), ('\u{FB1E}', '\u{FB1E}'),
    ('\u{FE00}', '\u{FE0F}'), ('\u{FE20}', '\u{FE2F}'), ('\u{101FD}', '\u{101FD}'),
    ('\u{102E0}', '\u{102E0}'), ('\u{10376}', '\u{1037A}'), ('\u{10A01}', '\u{10A03}'),
    ('\u{10A05}', '\u{10A06}'), ('\u{10A0C}', '\u{10A0F}'), ('\u{10A38}', '\u{10A3A}'),
    ('\u{10A3F}', '\u{10A3F}'), ('\u{10AE5}', '\u{10AE6}'), ('\u{10D24}', '\u{10D27}'),
    ('\u{10D69}', '\u{10D6D}'), ('\u{10EAB}', '\u{10EAC}'), ('\u{10EFC}', '\u{10EFF}'),
    ('\u{10F46}', '\u{10F50}'), ('\u{10F82}', '\u{10F85}'), ('\u{11001}', '\u{11001}'),
    ('\u{11038}', '\u{11046}'), ('\u{11070}', '\u{11070}'), ('\u{11073}', '\u{11074}'),
    ('\u{1107F}', '\u{11081}'), ('\u{110B3}', '\u{110B6}'), ('\u{110B9}', '\u{110BA}'),
    ('\u{110C2}', '\u{110C2}'), ('\u{11100}', '\u{11102}'), ('\u{11127}', '\u{1112B}'),
    ('\u{1112D}', '\u{11134}'), ('\u{11173}', '\u{11173}'), ('\u{11180}', '\u{11181}'),
    ('\u{111B6}', '\u{111BE}'), ('\u{111C9}', '\u{111CC}'), ('\u{111CF}', '\u{111CF}'),
    ('\u{1122F}', '\u{11231}'), ('\u{11234}', '\u{11234}'), ('\u{11236}', '\u{11237}'),
    ('\u{1123E}', '\u{1123E}'), ('\u{11241}', '\u{11241}'), ('\u{112DF}', '\u{112DF}'),
    ('\u{112E3}', '\u{112EA}'), ('\u{11300}', '\u{11301}'), ('\u{1133B}', '\u{1133C}'),
    ('\u{11340}', '\u{11340}'), ('\u{11366}', '\u{1136C}'), ('\u{11370}', '\u{11374}'),
    ('\u{113BB}', '\u{113C0}'), ('\u{113CE}', '\u{113CE}'), ('\u{113D0}', '\u{113D0}'),
    ('\u{113D2}', '\u{113D2}'), ('\u{113E1}', '\u{113E2}'), ('\u{11438}', '\u{1143F}'),
    ('\u{11442}', '\u{11444}'), ('\u{11446}', '\u{11446}'), ('\u{1145E}', '\u{1145E}'),
    ('\u{114B3}', '\u{114B8}'), ('\u{114BA}', '\u{114BA}'), ('\u{114BF}', '\u{114C0}'),
    ('\u{114C2}', '\u{114C3}'), ('\u{115B2}', '\u{115B5}'), ('\u{115BC}', '\u{115BD}'),
    ('\u{115BF}', '\u{115C0}'), ('\u{115DC}', '\u{115DD}'), ('\u{11633}', '\u{1163A}'),
    ('\u{1163D}', '\u{1163D}'), ('\u{1163F}', '\u{11640}'), ('\u{116AB}', '\u{116AB}'),
    ('\u{116AD}', '\u{116AD}'), ('\u{116B0}', '\u{116B5}'), ('\u{116B7}', '\u{116B7}'),
    ('\u{1171D}', '\u{1171D}'), ('\u{1171F}', '\u{1171F}'), ('\u{11722}', '\u{11725}'),
    ('\u{11727}', '\u{1172B}'), ('\u{1182F}', '\u{11837}'), ('\u{11839}', '\u{1183A}'),
    ('\u{1193B}', '\u{1193C}'), ('\u{1193E}', '\u{1193E}'), ('\u{11943}', '\u{11943}'),
    ('\u{119D4}', '\u{119D7}'), ('\u{119DA}', '\u{119DB}'), ('\u{119E0}', '\u{119E0}'),
    ('\u{11A01}', '\u{11A0A}'), ('\u{11A33}', '\u{11A38}'), ('\u{11A3B}', '\u{11A3E}'),
    ('\u{11A47}', '\u{11A47}'), ('\u{11A51}', '\u{11A56}'), ('\u{11A59}', '\u{11A5B}'),
    ('\u{11A8A}', '\u{11A96}'), ('\u{11A98}', '\u{11A99}'), ('\u{11C30}', '\u{11C36}'),
    ('\u{11C38}', '\u{11C3D}'), ('\u{11C3F}', '\u{11C3F}'), ('\u{11C92}', '\u{11CA7}'),
    ('\u{11CAA}', '\u{11CB0}'), ('\u{11CB2}', '\u{11CB3}'), ('\u{11CB5}', '\u{11CB6}'),
    ('\u{11D31}', '\u{11D36}'), ('\u{11D3A}', '\u{11D3A}'), ('\u{11D3C}', '\u{11D3D}'),
    ('\u{11D3F}', '\u{11D45}'), ('\u{11D47}', '\u{11D47}'), ('\u{11D90}', '\u{11D91}'),
    ('\u{11D95}', '\u{11D95}'), ('\u{11D97}', '\u{11D97}'), ('\u{11EF3}', '\u{11EF4}'),
    ('\u{11F00}', '\u{11F01}'), ('\u{11F36}', '\u{11F3A}'), ('\u{11F40}', '\u{11F40}'),
    ('\u{11F42}', '\u{11F42}'), ('\u{11F5A}', '\u{11F5A}'), ('\u{13440}', '\u{13440}'),
    ('\u{13447}', '\u{13455}'), ('\u{1611E}', '\u{16129}'), ('\u{1612D}', '\u{1612F}'),
    ('\u{16AF0}', '\u{16AF4}'), ('\u{16B30}', '\u{16B36}'), ('\u{16F4F}', '\u{16F4F}'),
    ('\u{16F8F}', '\u{16F92}'), ('\u{16FE4}', '\u{16FE4}'), ('\u{1BC9D}', '\u{1BC9E}'),
    ('\u{1CF00}', '\u{1CF2D}'), ('\u{1CF30}', '\u{1CF46}'), ('\u{1D167}', '\u{1D169}'),
    ('\u{1D17B}', '\u{1D182}'), ('\u{1D185}', '\u{1D18B}'), ('\u{1D1AA}', '\u{1D1AD}'),
    ('\u{1D242}', '\u{1D244}'), ('\u{1DA00}', '\u{1DA36}'), ('\u{1DA3B}', '\u{1DA6C}'),
    ('\u{1DA75}', '\u{1DA75}'), ('\u{1DA84}', '\u{1DA84}'), ('\u{1DA9B}', '\u{1DA9F}'),
    ('\u{1DAA1}', '\u{1DAAF}'), ('\u{1E000}', '\u{1E006}'), ('\u{1E008}', '\u{1E018}'),
    ('\u{1E01B}', '\u{1E021}'), ('\u{1E023}', '\u{1E024}'), ('\u{1E026}', '\u{1E02A}'),
    ('\u{1E08F}', '\u{1E08F}'), ('\u{1E130}', '\u{1E136}'), ('\u{1E2AE}', '\u{1E2AE}'),
    ('\u{1E2EC}', '\u{1E2EF}'), ('\u{1E4EC}', '\u{1E4EF}'), ('\u{1E5EE}', '\u{1E5EF}'),
    ('\u{1E8D0}', '\u{1E8D6}'), ('\u{1E944}', '\u{1E94A}'), ('\u{E0100}', '\u{E01EF}'),
];

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
            // Emoji and text presentation: VS-16 / VS-15 after a listed emoji variation base.
            "⚠\u{FE0F} careful ❤\u{FE0F} ©\u{FE0E}",
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
        let text = "Looks fine ❤\u{FE0F}\u{FE0F}\u{FE01}\u{E0100}\u{E01EF}";
        assert_eq!(
            escape_for_display(text),
            "Looks fine ❤\u{FE0F}⟨U+FE0F⟩⟨U+FE01⟩⟨U+E0100⟩⟨U+E01EF⟩"
        );
        assert!(has_hidden_or_control_chars(text));
    }

    #[test]
    fn a_variation_selector_after_ordinary_non_ascii_text_is_escaped() {
        // Each of these bases defines no variation sequence for the selector after it, so a
        // selector there is a hidden byte (the round-2 review's exfiltration channel).
        for (base, name) in [
            ('\u{2022}', "bullet"),
            ('\u{2014}', "em dash"),
            ('\u{201C}', "left double quotation mark"),
            ('\u{2026}', "ellipsis"),
            ('\u{00A0}', "no-break space"),
            ('\u{0434}', "Cyrillic de"),
            ('\u{0E48}', "Thai tone mark mai ek"),
            ('\u{093F}', "Devanagari vowel sign i"),
            ('\u{05B0}', "Hebrew point sheva"),
            (
                '\u{1F600}',
                "grinning face (emoji with no variation sequence)",
            ),
        ] {
            for selector in ['\u{FE0F}', '\u{FE0E}', '\u{FE01}', '\u{E0100}', '\u{180B}'] {
                let text = format!("a{base}{selector}");
                let expected = format!("a{base}⟨U+{:04X}⟩", u32::from(selector));
                assert_eq!(escape_for_display(&text), expected, "{name} + {selector:?}");
                assert!(has_hidden_or_control_chars(&text), "{name} + {selector:?}");
            }
        }
    }

    #[test]
    fn each_selector_range_is_shown_only_after_its_own_bases() {
        // An ideographic selector after an emoji, and VS-16 after an ideograph, are escaped.
        assert_eq!(escape_for_display("❤\u{E0100}"), "❤⟨U+E0100⟩");
        assert_eq!(escape_for_display("\u{845B}\u{FE0F}"), "\u{845B}⟨U+FE0F⟩");
        // U+FE00–U+FE0D are never shown, even after an ideograph or an emoji base.
        assert_eq!(escape_for_display("\u{845B}\u{FE00}"), "\u{845B}⟨U+FE00⟩");
        assert_eq!(escape_for_display("❤\u{FE0D}"), "❤⟨U+FE0D⟩");
        // A Mongolian selector after Latin is escaped; after a Mongolian letter only the first shows.
        assert_eq!(escape_for_display("a\u{180B}"), "a⟨U+180B⟩");
        assert_eq!(
            escape_for_display("\u{1820}\u{180B}\u{180C}"),
            "\u{1820}\u{180B}⟨U+180C⟩"
        );
    }

    #[test]
    fn a_secret_hidden_one_selector_per_bullet_is_fully_escaped() {
        // The round-2 repro: one selector after each bullet of a status line.
        let secret = "sk-live-4f9a2b7c1d";
        let mut text = String::from("Status: done ");
        for byte in secret.bytes() {
            text.push('\u{2022}');
            text.push(char::from_u32(0xE0100 + u32::from(byte)).expect("valid selector"));
        }
        let escaped = escape_for_display(&text);
        assert!(has_hidden_or_control_chars(&text));
        assert!(!escaped.chars().any(is_variation_selector), "{escaped}");
        assert_eq!(escaped.matches("⟨U+E01").count(), secret.len());
    }

    /// Regression (#271): dozens of combining marks stacked on one base overflow the line and can
    /// paint over neighbouring lines. Only the first two are shown; the rest are escaped and warn.
    #[test]
    fn stacked_combining_marks_beyond_two_are_escaped_and_warn() {
        let text = format!("ok{}{}", "\u{0336}".repeat(5), "\u{0301}".repeat(50));
        let expected = format!(
            "ok\u{0336}\u{0336}{}{}",
            "⟨U+0336⟩".repeat(3),
            "⟨U+0301⟩".repeat(50)
        );
        assert_eq!(escape_for_display(&text), expected);
        assert!(has_hidden_or_control_chars(&text));
        // Escaping is idempotent: the output's runs are already within the limit.
        assert_eq!(escape_for_display(&expected), expected);
        assert!(!has_hidden_or_control_chars(&expected));
    }

    #[test]
    fn ordinary_accented_text_does_not_warn() {
        // Decomposed é (one mark) and Vietnamese ệ (two marks), each on its own base.
        for text in [
            "cafe\u{0301}",
            "Vi\u{0323}\u{0302}t Nam",
            "a\u{0301}\u{0301}b\u{0301}\u{0301}",
        ] {
            assert_eq!(escape_for_display(text), text);
            assert!(!has_hidden_or_control_chars(text), "{text:?}");
        }
    }

    #[test]
    fn a_selector_after_any_combining_mark_is_escaped() {
        // U+18A9 is a Mongolian-block combining mark: inside U+1800–U+18AF, but not a base.
        assert_eq!(
            escape_for_display("\u{1820}\u{18A9}\u{180B}"),
            "\u{1820}\u{18A9}⟨U+180B⟩"
        );
        // A combining mark outside the combining-diacritic blocks (Thai, Hebrew, Devanagari).
        for mark in ['\u{0E48}', '\u{05B4}', '\u{093C}'] {
            let text = format!("x{mark}\u{FE0F}");
            assert_eq!(escape_for_display(&text), format!("x{mark}⟨U+FE0F⟩"));
        }
    }

    /// The table is sorted, non-overlapping and merged, so the binary search is exact.
    #[test]
    fn combining_mark_ranges_are_sorted_and_disjoint() {
        for (lo, hi) in COMBINING_MARK_RANGES {
            assert!(lo <= hi, "{lo:?}..={hi:?}");
        }
        for pair in COMBINING_MARK_RANGES.windows(2) {
            let (_, prev_hi) = pair[0];
            let (next_lo, _) = pair[1];
            assert!(
                u32::from(prev_hi) + 1 < u32::from(next_lo),
                "{pair:?} overlap or touch"
            );
        }
    }

    /// Spot checks against General_Category in Unicode 16.0.0 `UnicodeData.txt`.
    #[test]
    fn is_combining_mark_matches_the_general_category() {
        // Mn or Me.
        for c in [
            '\u{0300}',
            '\u{036F}',
            '\u{0483}',
            '\u{0489}',
            '\u{05B4}',
            '\u{093C}',
            '\u{0E48}',
            '\u{1885}',
            '\u{18A9}',
            '\u{20DD}',
            '\u{20E3}',
            '\u{3099}',
            '\u{FE0F}',
            '\u{FE20}',
            '\u{1E944}',
            '\u{E0100}',
            '\u{E01EF}',
        ] {
            assert!(is_combining_mark(c), "{c:?} is Mn/Me");
        }
        // Not marks: letters, a spacing mark (Mc), an emoji modifier (Sk), a format control (Cf).
        for c in [
            'e',
            '\u{0903}',
            '\u{0E33}',
            '\u{1F3FB}',
            '\u{200D}',
            '\u{2022}',
            '\u{FFFD}',
        ] {
            assert!(!is_combining_mark(c), "{c:?} is not Mn/Me");
        }
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
        assert_eq!(escape_for_display("e\u{0301}\u{FE0F}"), "e\u{0301}⟨U+FE0F⟩");
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
    fn a_crlf_line_ending_in_a_command_is_escaped_and_warns() {
        // The cloud-review repro: bash reads `../scratch` + CR as the `cd` target, the `cd` fails,
        // and `rm` runs in the original directory.
        for surface in [
            Surface::Command,
            Surface::McpToolCall,
            Surface::AgentToolCall,
        ] {
            let model = raw_model(surface, "cd ../scratch\r\nrm -rf -- *");
            assert!(model.has_hidden_or_control_chars, "{surface:?}");
            assert_eq!(
                model.syntactic.raw_lines,
                Some(vec![
                    "cd ../scratch\\r".to_string(),
                    "rm -rf -- *".to_string()
                ]),
                "{surface:?}"
            );
        }
    }

    #[test]
    fn a_tab_in_a_command_stays_unflagged_structure() {
        let model = raw_model(Surface::Command, "printf 'a\tb'\n\techo indented");
        assert!(!model.has_hidden_or_control_chars);
        assert_eq!(
            model.syntactic.raw_lines,
            Some(vec![
                "printf 'a→   b'".to_string(),
                "→   echo indented".to_string()
            ])
        );
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
