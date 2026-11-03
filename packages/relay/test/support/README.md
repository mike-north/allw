# Relay test support

- `accounts.ts` — deterministic self-certifying test accounts and root-signed `pairing/start` bodies.
- `relay-state.ts` — direct Durable Object setup: `pinRelayClock` (injected clock for the submit
  limits and the expiry alarm/sweep) and `bindAccountRoot` (submits need a bound root, #248).

## Rate limits are live in the workers pool

The real Workers rate-limiting bindings from `wrangler.jsonc` are active under
`@cloudflare/vitest-pool-workers`. Test requests carry no `CF-Connecting-IP`, so every request to
one account shares the key `<account>|unknown`:

- more than **60** `POST /{acct}/requests` per account within a minute through `SELF` get **429**
  (`RATE_LIMIT_REQUESTS`);
- more than **10** `pairing/start` + `pairing/complete` per account within a minute get **429**
  (`RATE_LIMIT_PAIRING`).

Use a fresh account per test, seed bulk rows through `runInDurableObject` instead of submitting
them, or call `worker.fetch(request, { ...env, RATE_LIMIT_…: fake })` with an injected limiter.
Only the per-client binding (`RATE_LIMIT_CLIENT`, keyed by IP alone) is raised in
`vitest.config.ts`, because all test traffic would otherwise share its single `unknown` bucket.
