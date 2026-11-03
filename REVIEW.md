VERDICT: PENDING

Independent adversarial review of PR #259 (head b02c97f). In progress; partial findings below.

## Findings so far

### 1. should-fix/blocker (pending severity) — CRLF in a `command` raw is unflagged "structure", but bash executes `\r` as data

`crates/allw-core/src/display.rs:320-343` (`content_lines`), `:57-66` (module docs).

REPRODUCED. raw = `"cd ../scratch\r\nrm -rf -- *\n"` renders in `raw_lines` as `cd ../scratch␍` /
`rm -rf -- *` with `has_hidden_or_control_chars = false`. Under bash the `cd` target is
`$'../scratch\r'`, which fails, and `rm -rf -- *` runs in the **original** cwd. Ran it in a scratch
tree: `precious/important.txt` was deleted, `scratch/junk` survived.
