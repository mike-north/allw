# Relay test support

- `accounts.ts` — deterministic self-certifying test accounts and root-signed `pairing/start` bodies.
- `relay-state.ts` — direct Durable Object setup: `pinRelayClock` (injected clock for the submit
  limits and the expiry alarm/sweep) and `bindAccountRoot` (submits need a bound root, #248).
