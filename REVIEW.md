VERDICT: BLOCK

Independent adversarial review of PR #259 (head `b02c97f`, "core display_model with visible escaping"). Nothing
was edited or pushed on the PR branch and nothing was posted to GitHub.

Overall: the core escaping engine is careful and mostly correct. The emoji-base table matches Unicode 16.0 exactly,
the Default_Ignorable set is complete, and both surfaces print only the model. One reproduced, unflagged WYSIWYS
divergence comes from the PR's own "CRLF is structure" rule. It is cheap to fix and should be fixed before merge.

## Findings (most severe first)

### 1. BLOCKER: a CRLF line ending in a `command` raw is unflagged "structure", but the shell treats `\r` as data

- **Where:** `crates/allw-core/src/display.rs:57-66` (module docs), `:317-343` (`content_lines`). Same rationale in
  `docs/threat-model.md` (the `raw` bullet: "once ESC and lone CRs are escaped they cannot overwrite or hide
  anything").
- **Failure scenario:** the agent sends `raw = "cd ../scratch\r\nrm -rf -- *"` on the `command` surface.
  `display_model` returns `raw_lines = ["cd ../scratch␍", "rm -rf -- *"]` with
  `has_hidden_or_control_chars = false`. The CLI prints:
  ```
    Action:     cd ../scratch␍
              │ rm -rf -- *
  ```
  It shows no warning anywhere. In bash, the `cd` target is `$'../scratch\r'`, which does not exist, so `cd` fails.
  `rm -rf -- *` then runs in the **original** working directory. The human approved "wipe the scratch dir"; the
  hash binds a command that wipes the current directory. The same trick turns `cd /safe\r\nmake clean` and similar
  sequences into actions in the wrong directory. A CRLF heredoc delimiter also changes where the heredoc ends.
- **REPRODUCED (twice):**
  1. Core/CLI: called the built `renderRequest` (via `prepareRequest` with the real WASM core) on that context.
     Output as above, `flag=false`. The only hint is the `Deciding on: cd ../scratch\r\nrm -rf -- *` line, where
     `\r\n` reads like an ordinary line ending to most people.
  2. Semantics: in a scratch tree, from `crlf/precious/` I ran `bash -c $'cd ../scratch\r\nrm -rf -- *\n'`. Bash
     printed `cd: $'../scratch\r': No such file or directory`, `precious/important.txt` was deleted, and
     `scratch/junk` survived.
- **Suggested fix:** keep the unflagged `␍` marker only for `Surface::FileEdit`, where CRLF content is legitimate.
  For `command` (and any surface that is executed by a shell), escape a CR before LF as `\r` and set the flag.
  Commands with CRLF endings are effectively never legitimate on POSIX shells. `content_lines` needs a
  `crlf_is_structure: bool` (or the surface) passed in. Add a direct negative test, e.g.
  `raw_model(Surface::Command, "cd x\r\nrm -rf *")` must flag, plus a CLI test and a shared-vector entry. Update the
  threat-model bullet, which currently says a CR before LF "cannot overwrite or hide anything".

### 2. should-fix: terminal soft-wrap defeats the "no line can pass for a field label" guarantee (actor/summary/any single-line field)

- **Where:** `packages/approver/src/lib/render.ts:343-349` (Actor and the VERIFIED/UNVERIFIED line), `:282-294`
  (`│` continuation rationale), `docs/threat-model.md` ("A multi-line command prints its further lines behind a `│`
  marker, so none can pass for a field label").
- **Failure scenario:** spaces are printable and never escaped, and the renderer does not wrap or truncate. An
  attacker-controlled single-line field padded with spaces to the terminal width forces the terminal to wrap. The
  wrapped tail then starts at column 0 as its own visual row. With `actor.kind = <54 spaces> + "              ✓
  VERIFIED origin — claude-code · machine:ci" + <30 spaces>`, an 80-column terminal shows:
  ```
    Actor:      machine:ci (
                ✓ VERIFIED origin — claude-code · machine:ci
          )
                ⚠ UNVERIFIED — origin is unauthenticated plaintext (#16)
  ```
  with `has_hidden_or_control_chars = false`. The real UNVERIFIED line is still printed, but now it contradicts a
  forged VERIFIED line in exactly the place a VERIFIED line would appear. The same technique can forge
  `Cwd:`/`Action:`-style rows from `summary`, `cwd`, or a `raw` line. It also bypasses the `│` marker on
  continuation lines, because a soft-wrapped row of a `│` line carries no marker.
- **REPRODUCED:** called the built `renderRequest` with that actor and hard-wrapped the output at 80 columns, as a
  terminal would. Output as above, `flag=false`. Not run in a live TTY, but wrapping behaviour is standard.
- **Suggested fix (design call; see D2):** the CLI should own wrapping. Wrap each printed field to
  `process.stdout.columns` itself and prefix every wrapped row with a continuation marker (e.g. `│`/`↪`). Or have the
  core escape or collapse long whitespace runs (e.g. render more than N consecutive spaces as `⟨N spaces⟩` and set
  the flag). Today the web approver is unaffected: labels are `<strong>` elements and `<pre>` does not wrap.

### 3. should-fix (pre-existing, but this PR claims CLI/web parity of what is shown): the web approver omits hash-bound fields the CLI shows

- **Where:** `packages/web-approver/src/runtime.ts:243-262` (`CoreDisplayModel` declares only argv/cwd/raw/
  raw_lines/server/tool/params_json_lines), `:322-348` (`kind` maps every non-MCP surface, including `file_edit`,
  to `command`), `packages/web-approver/src/index.ts:580-602` (`exactPlaintext`).
- **Failure scenario:** the web card never shows `bin`, `flags`, `positionals`, `host`, `env_refs`, `chain`, or a
  file edit's `operation`/`paths`/`diff_summary`/`diff_hash`. A `file_edit` renders as `argv: \nraw: <content>`
  with the target **path** missing. A `command` with `host: "prod-db"` or `env_refs: ["AWS_SECRET_ACCESS_KEY"]`
  looks identical to a local one. The web also has no raw/argv divergence warning. Both forms appear in the
  `<pre>`, but the `<h3>` headline shows only `raw`, which may be the benign half. The CLI shows all of these
  (render.ts `substrateDetailLines`). The runtime doc comment also says file_edit renders "as an Unknown action",
  which is no longer what the code does: it now always attaches a `command`.
- **REPRODUCED:** by reading the code only (the mapping drops these fields by construction). Not run in the
  browser.
- **Suggested fix:** consume the full `DisplaySubstrate` in the web runtime and render the same labeled lines as
  the CLI, including the divergence warning. Or file a follow-up and correct the doc comment and threat-model
  parity claims now.

### 4. nit: the literal structure markers `→   ` and `␍` are not injective and never flag

- **Where:** `display.rs:227-234`.
- **Failure scenario:** a raw line containing the literal text `→   ` displays exactly like a TAB, and the literal
  `␍` at the end of a line displays like a CRLF ending, both unflagged. The module docs acknowledge this
  non-injectivity for `\x1b`, and that case is always paired with the flag. These markers are not. The impact is
  low: the literal bytes are what the hash binds, and finding 1 is the case that actually changes behaviour.
- **Suggested fix:** document it next to the `\x1b` note, or flag a literal U+240D at line end.

### 5. nit: unbounded combining-mark runs are not flagged

- **Where:** `display.rs` (no Mn/Me handling outside the variation-selector rule).
- **Failure scenario:** a run of hundreds of combining marks (Zalgo) after one base passes unflagged. In fonts that
  stack marks, the web `<h3>` headline has no overflow clipping (`.approval-card h3` in `public/styles.css`), so the
  marks can paint over the card's meta lines or plaintext. Enclosing or overlay marks (U+20E0, U+0338) can also add
  misleading glyphs (`--force⃠`).
- **REPRODUCED?** No. In headless Chromium with this container's fonts, the marks collapse onto one position and
  did not overflow (screenshot taken; the `<pre>` has `overflow: auto` anyway). Reasoned only, and font-dependent.
- **Suggested fix:** in the core, flag (and optionally escape) a base followed by more than ~4 combining marks.
  Add `overflow-wrap:anywhere; overflow:hidden` to the h3.

### 6. nit: hash-bound `capabilities` / `scope` are neither displayed nor flagged

- **Where:** `display.rs:544-564` (`display_model`), with the fields at `contract.rs:231,238`.
- **Failure scenario:** both fields are "MUST be None in v1", but a malicious integrator can set them. They are
  hashed (`ApprovalContext` → JCS) and invisible on every surface. Today nothing consumes them, so this is not
  exploitable. The first consumer would inherit an unreviewed WYSIWYS gap.
- **Suggested fix:** have the device reject (fail closed) a context with non-null `capabilities`/`scope` in v1, or
  set the flag and render them as escaped JSON.

### 7. nit: no direct test for the CLI fatal-error "details withheld" fallback

- **Where:** `packages/approver/src/cli.ts:166-173`.
- **Failure scenario:** the branch that withholds error text when the core cannot load has no test. The equivalent
  web path does (`controller.test.mjs:557`).
- **Suggested fix:** add a test that makes `loadWasm` fail and asserts the withheld text and the absence of raw
  ESC.

### 8. nit: list joins are ambiguous

- **Where:** `render.ts:240,264,357` (`env_refs`, `paths`, `chain` joined with `", "`); web `index.ts:591`
  (`server.tool`).
- **Failure scenario:** `paths: ["a, /etc/passwd"]` renders the same as `["a", "/etc/passwd"]`. On the web,
  `server "fs.delete"` + `tool "x"` renders the same as `server "fs"` + `tool "delete.x"` (the CLI uses ` :: `).
  These cases are pre-existing.
- **Suggested fix:** quote list items with `quoteToken`, and use ` :: ` on the web.

## Design decisions for Mike

- **D1 (finding 1):** should "CRLF is structure" be per surface? I recommend: FileEdit yes; command no (flag it).
  Related: should a TAB in a *command* stay unflagged? TAB is harmless to bash word splitting, and the marker is
  visible, so I would keep it unflagged.
- **D2 (finding 2):** should the CLI take ownership of wrapping (terminal-width-aware, with a marker on every
  wrapped row), or should the core treat long whitespace runs as suspicious and flag them? The first is more
  robust. The second keeps logic in the core but invites false positives on aligned text.
- **D3 (finding 3):** is web parity in scope for #246 or a follow-up? The web currently shows less hash-bound
  context than the CLI. That predates this PR, but the threat-model checklist now reads as if both surfaces were
  equivalent.
- **D4:** accepted residual of variation selectors after listed emoji and CJK ideographs (about 1 bit per emoji,
  about 1 byte per ideograph). This is documented. I agree it is reasonable, given that prose can no longer carry a
  payload.

## What I tried that held up

- **Gate on PR head:** `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo check --locked`, and `cargo test --locked` all pass. On the TS side, `pnpm install`, `build:wasm`,
  `pnpm -r build`, `typecheck` and `lint` pass. In `pnpm -r test`, approver passes 97/97, web-approver 287/287,
  hook 72/72, relay 138/138, and sdk passes. codex-hook hit the known flaky subprocess test once (end-to-end
  timeout deny). Re-run result: see the gate note at the end. The `build:wasm` step needed a local `wasm-opt`
  (npm `binaryen@120`) because the container could not download binaryen from GitHub. That is an environment
  problem, not a PR problem.
- **Emoji table:** `EMOJI_VARIATION_BASES` (359 entries) is strictly sorted, so `binary_search` is valid. It is
  set-equal to every non-ASCII base in Unicode 16.0 `emoji-variation-sequences.txt` (diffed against the downloaded
  file).
- **Default_Ignorable coverage:** every range of `Default_Ignorable_Code_Point` is escaped, with variation
  selectors handled by context. Bidi (TR9) and C0/C1/DEL are covered, as are U+2028/2029, U+FFF9–FFFB and U+2800.
- **Variation-selector context:** selectors after ASCII, after other selectors, after combining marks, after
  hidden characters, after TAB (`prev` is still the TAB, so the selector is escaped), U+FE00–FE0D anywhere,
  cross-range (VS16 after an ideograph, IVS after an emoji), keycap without U+20E3, and VS15 inside a keycap are
  all escaped and flagged.
- **Flag/render agreement:** a single engine (`escape_into`) drives both the rendering and the flag. `params` are
  scanned on the parsed values, so JSON's own `\u001b` rewriting cannot hide a control character from the flag.
  Keys are scanned too.
- **WYSIWYS:** `display_model` borrows the context immutably, and the hash is computed by the core from the same
  `contextJson` the model is built from. The raw/argv divergence decision is taken on raw bytes, not on escaped
  text. Duplicate struct keys are rejected by serde, and duplicate `params` keys resolve to last-wins in both the
  hash and the display, so they stay consistent.
- **Relay text into the terminal:** every `watch` log line, every `pair` line, the fatal error line, the request id
  (`displayRequestId`), and origin and reason strings all go through `escape_for_display`. The only `console.*`
  calls on untrusted data are the wrapped loggers and the pre-rendered block.
- **Relay text into the DOM:** every write uses `textContent`/`createTextNode`; there is no `innerHTML`. The card
  text comes only from the core model. The verification-failed reason and the outage banner are escaped, or
  withheld when the runtime has no escaper.
- **Line structure:** in single-line fields (argv/bin/flags/cwd/summary/ids/chain), TAB, LF and CR are escaped and
  flagged. A lone CR, or a trailing CR with no LF after it, inside `raw` is escaped and flagged. `params_json_lines`
  cannot contain a raw LF. CLI continuation lines carry `│`, and the web joins them with `   │ `.
- **Thin shell:** the TS code contains no escaping logic. Both surfaces call WASM `display_model` and
  `escape_for_display`. UniFFI exposes the same two functions. The shared vector is asserted in Rust and through
  WASM.
