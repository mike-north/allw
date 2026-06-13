# Web Approver Audit History Flow Notes

Issue #95 covers the read-only audit surface for proving who approved what, when. This prototype
uses the shared `design/web-approver/inbox/tokens.css` visual language and treats the history view
as a trust receipt backed by the tamper-evident audit chain in `docs/contract.md`.

## Timeline of decisions

The primary surface is a dense timeline of approved, denied, expired, and aborted decisions. It
supports filtering by actor, surface, decision, and date without hiding verification status. Rows
show actor identity, machine, syntactic surface, decision, and chain position so the history is
scannable before opening a detail view.

Behavior notes:

- Keep the surface read-only. There are no retry, approve-again, or mutate-history actions.
- Do not let filters suppress integrity warnings. A broken chain remains visually prominent in
  matching rows and the global chain cue.
- Preserve the same WYSIWYS vocabulary as live approval detail so history feels like the receipt of
  the exact prompt, not a lossy activity log.

## Decision detail

Selecting a row opens a decision detail pane with the exact approved plaintext using the same
WYSIWYS render family as the live detail view. The pane also shows verdict signature status, actor
origin status, chain position, request hash, and record hash.

Behavior notes:

- Verified entries use calm confirmation language: the verdict signature, request hash, and chain
  link all agree.
- Unverifiable entries use fail-closed language and never look merely informational. A broken or
  unverifiable entry is unapprovable history evidence, not an action to continue.
- Detail copy distinguishes verdict decisions from UI states: `expired` and `aborted` are terminal
  decisions, while `unverifiable` is evidence status.

## Chain integrity cue

The header includes a subtle but legible chain cue: "Audit chain verified through <timestamp>" for
the healthy case, and a stronger broken-chain banner for the failure case. The broken state names
the chain position where continuity failed.

Behavior notes:

- The verified cue should be persistent enough to support compliance screenshots without dominating
  daily use.
- A broken chain should change both color and wording, not only iconography.
- The timestamp represents the last locally verified record, not a server attestation.

## Export affordance

The export control creates an audit slice for the current filters. The prototype treats export as a
design-only v1 affordance: it previews scope, record count, and included evidence fields before the
user confirms.

Behavior notes:

- Exports include request plaintext, verdict JWS, record hash, previous hash, actor, approver,
  policy decision, and filter metadata.
- The export affordance must not imply the relay can read plaintext history; the device builds the
  slice from local verified records.
- Broken-chain exports remain possible for incident response, but they are clearly marked as
  containing unverifiable records.
