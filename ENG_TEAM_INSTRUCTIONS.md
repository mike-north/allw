# Engineering team instructions

Conventions for agents working this repo. The PM agent (comments signed `<!-- allw-pm-bot -->`)
runs the review/merge gate; these rules exist so work flows through it without friction. Read
`CLAUDE.md` and the relevant `docs/*.md` before implementing — the docs are the source of truth.

## Claiming work

1. The work queue is **open GitHub issues labelled `greenlit`** — see "Issue labels" below for the
   full scheme and how to order your pick. Epics group related work; claim their child issues,
   never the epic itself.
2. **Claim before working**: add the `in progress` label AND post a one-line claim comment on the
   issue. An issue labeled `in progress` belongs to someone else — pick a different one.
3. One issue per PR (`Closes #N`). If a PR closes several issues, claim and label all of them.
4. If you stop work without finishing: remove the label and comment what state you left it in.
5. Before opening a PR, check open PRs — if one already exists for the issue, **do not open a
   duplicate**; comment on the existing PR instead.

## Issue labels

The queue is **label-driven**, not a hand-maintained list — so the same scheme works across every
issue. The PM triages; you read the labels.

**An issue is claimable when it is open, labelled `greenlit`, and _not_ labelled `in progress` or
`blocked`.** `greenlit` is the readiness signal: the PM applies it once a ticket is fully scoped,
has acceptance criteria, and is unblocked. **No `greenlit` ⇒ not ready** — don't pick it up (it may
still be under design or awaiting a decision); ping the PM if you think it should be greenlit.

Among greenlit issues, pick the **highest priority first**:

| Priority | Meaning                                            |
| -------- | -------------------------------------------------- |
| `P0`     | Foundational / unblocks others — do these first.   |
| `P1`     | Important for the current release (v1).            |
| `P2`     | Later / post-v1. Claim when no P0/P1 is available. |

Priority **orders** the greenlit queue; it does not by itself mean "ready" (a ticket can be
prioritised but not yet greenlit). The milestone (`v1`, …) is the _target release_; the priority
label is the _urgency_.

**Lifecycle labels** (these remove an issue from the ready set):

- `in progress` — claimed by someone (rule 2).
- `blocked` — has an unmet dependency or an open design question; not claimable until the PM clears
  it. If you discover a blocker mid-flight, add `blocked`, remove `in progress`, and comment why.

**Type labels** tell you what the deliverable is: `epic` (tracker — never claimed directly),
`type:spec` (a design/spec doc under `docs/`, not implementation), `enhancement` (feature),
`bug`, `documentation`.

**Area labels** (`area:core`, `area:sdk`, `area:hook`, `area:relay`, `area:apps`, `area:policy`,
`area:infra`) scope the work — use them to filter for issues in your wheelhouse.

The PM keeps this scheme current; if a label is missing or ambiguous, ask rather than inventing one.

## Branching & rebase discipline

6. **Branch from `origin/main` only.** Do not stack a PR on another open PR's branch — when the
   base merges, your diff becomes unreviewable and the PR usually has to be closed and re-cut
   (this has happened; it wastes a full review cycle).
7. **When `main` moves under you, rebase promptly** — same day. A `DIRTY` (conflicted) PR cannot
   run CI and cannot merge, and an approved-but-conflicted PR blocks the whole queue. When
   resolving, preserve both sides' tests (the common conflict is two PRs appending to the same
   test file).
8. Branch names: `<area>/<short-slug>` (e.g. `policy/glob-cap`, `relay/push-fanout`). Internal-only.

## The contract with the PM review

9. The PM reviews every PR and posts either approval or an explicit list of **merge-blockers**.
   Address **all blockers in one push**, then reply with the commit SHA and a per-item account of
   what changed. Partial fixes cost a full re-review cycle.
10. The automated review-agent's "no findings" does **not** clear a PR — the PM's verdict is the
    binding gate. Conversely, review-agent findings are usually real; fix or rebut them explicitly.
11. **PM scope arbitrations are binding.** If the PM says "do NOT address X here — it's tracked in
    issue #N," keep it out of the PR even if a reviewer flags it again.
12. Non-essential findings get filed as follow-up issues rather than blocking — if you think a
    blocker should be deferred instead, say so with a proposed issue; don't just skip it.

## Security & testing expectations (these are the most common merge-blockers)

13. **Fail-closed is a contract invariant** (`docs/contract.md`). Any failure, over-budget input,
    missing field, or unverifiable artifact must resolve to deny/escalate — never to silent
    no-match or default-accept. Watch especially for retrofits where "doesn't match" differs from
    "must not be allowed" (a cap that un-matches a _deny_ rule is a bypass, not a guard).
14. **Every rejection path at a security boundary needs a direct negative test** — wrong account,
    wrong root/signer, cross-typ JWS confusion, tampered payload, expired cert, malformed input,
    replay, double-submit. If a verification function has N error branches, expect to write ~N
    tests. PRs have been blocked on exactly this five times; write them proactively.
15. Thin-shell discipline: surfaces (WASM/SDK/UniFFI/UI) never reimplement core logic — hashing,
    verification, signing, policy evaluation live in `crates/allw-core` only. UI surfaces must make
    unsafe states _unreachable_ (e.g. approve disabled structurally), not merely styled as warnings.
16. Repo testing rules: no `Date.now()`/`new Date()` in test data (inject fixed clocks);
    assertions derive from the spec, not from captured program output; `@see` links to the spec
    sections a test enforces.
17. Validation gate before opening/pushing: `cargo fmt --check`, `cargo check`, `cargo clippy
--all-targets -- -D warnings`, `cargo test`, `pnpm -r build/typecheck/lint/test`, `prettier
--check`. List what you ran in the PR body (the team already does this well — keep it up).

## Docs

18. Documentation-driven repo: if your change alters a design decision, **update the owning
    `docs/*.md` in the same PR**. A spec cell that contradicts the implementation blocks merge
    even if the code is perfect.
19. UI work: `design/web-approver/` is the visual source of truth; use `tokens.css` verbatim.

## Commits & PRs

20. Author commits as `Mike North <michael.l.north@gmail.com>`; no AI-attribution trailers.
21. Prefer focused slices (roughly ≤1,000 changed lines) over omnibus PRs — slice-1-style PRs
    (#99) review and merge fastest. State in the PR body what the slice deliberately defers.
22. PR descriptions: summary bullets + scope notes + validation list. If user-visible CLI output
    changes, include before/after diff blocks.

## Communication

23. Questions for the PM: comment on the issue/PR with a clear question — the PM monitor answers
    within minutes. Status updates on pushes are appreciated and speed up re-review.
24. These instructions evolve; the PM updates this file as conventions emerge. When a PR comment
    from the PM conflicts with this file, the PR comment wins (it's newer and case-specific).
