# Web Approver Onboarding Flow Notes

Issue #94 covers the setup journey around the already-delivered inbox/detail/number-match design.
This prototype keeps the same `design/web-approver/inbox/tokens.css` visual language and treats
setup as a trust ceremony.

## First-run account creation

The first screen frames allw around user-owned keys, not a password account. The primary action
is "Generate account root"; the secondary path is recovery import. The screen names the Recovery
kit before any pairing happens so the user understands that account recovery is tied to user-owned
keys.

Behavior notes:

- Generate the account root locally before relay enrollment.
- Explain that the relay stores routing metadata and public keys, not private key material.
- Keep password and SaaS signup language out of this route.

## Device pairing ceremony

The pairing screen starts from the CLI quickstart's pairing code and makes explicit what the browser
is being trusted to do: decrypt pending requests and sign verdicts. The visual code entry mirrors the
existing happy-path pairing moment, but adds the surrounding security explanation.

Behavior notes:

- Treat wrong or expired pairing codes as recoverable, not scary.
- Show that E2EE remains true after pairing because approval context decrypts only on the device.
- QR scan is an equivalent input path, not a separate trust model.

## Returning device login

The returning flow recognizes an already paired browser by local device key. It asks for a lightweight
human re-auth before the inbox unlocks, while avoiding a password reset mental model.

Behavior notes:

- If the keyfile/local browser key is missing, route back to pairing.
- If account-state verification fails, keep the device visible but mark origin trust as unverified.
- Re-auth should protect signing and decryption, not recreate the account.

## Paired empty state

The empty state lands in the inbox and gives the developer the next concrete action: copy hook config
and point the agent at this approver. It should feel ready, not abandoned.

Behavior notes:

- Include copy-pastable Codex hook config, with Claude Code config available in implementation as a
  sibling tab or command switcher.
- Preserve the "no pending approvals" calm state from the happy-path inbox design.
- Keep the security status visible: paired, online, end-to-end encrypted, waiting for the first
  approval request.
