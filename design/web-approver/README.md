# Web approver — design source

Design package for the web approver happy path (#93), delivered by the design agent and imported
2026-06-12. This is the **visual source of truth** for the inbox, request detail (WYSIWYS), and
number-match confirm flows; implementation slices in `packages/web-approver` should match it. The
onboarding (#94) and audit history (#95) designs extend the same token system for adjacent flows.

## Contents (`inbox/`)

- `tokens.css` — design tokens: warm "calm-fintech" neutrals + electric-blue trust accent, light
  (`.theme-light`) and dark (`.theme-dark`) themes, radii/spacing/easing scales. **Use these tokens
  verbatim in the implementation.**
- `screens-inbox.jsx` — pairing code entry, inbox empty state, inbox list, request card.
- `screens-detail.jsx` — request detail (the WYSIWYS moment) and number-match confirm.
- `app.jsx` / `app.css` / `design-canvas.jsx` / `tweaks-panel.jsx` — the interactive design canvas
  shell (open `Allw Approver Inbox.html` in a browser to explore all screens/flows).
- `hero-variants.jsx` / `hero.css` / `Hero Directions.html` — hero/landing explorations.
- `screens/` — exported PNGs of every flow state (inbox, confirm, expired ×3, dark-mode check,
  canvas overview).

## Status

Covers the **happy-path** surfaces. The `PairingScreen` here covers the pairing-code entry moment;
#94 covers the full first-run journey around it.

These JSX files are design artifacts (React-flavored mockups), not production components — they are
not part of the pnpm workspace and are excluded from lint/typecheck.

## Adjacent flows

- `onboarding/` — first-run account creation, pairing ceremony, returning-device unlock, and paired
  empty state.
- `audit-history/` — read-only decision timeline, WYSIWYS decision detail, chain-integrity cue,
  verified/unverifiable states, and export-slice affordance.
