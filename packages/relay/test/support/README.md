# Relay test support

- `accounts.ts` — deterministic self-certifying test accounts and root-signed `pairing/start` bodies.
- `relay-state.ts` — direct Durable Object setup: `pinRelayClock` (injected clock for the submit
  limits and the expiry alarm/sweep) and `bindAccountRoot` (submits need a bound root, #248).

## Reaching `AccountRelay`'s private state

Use element access on a value typed `AccountRelay`: `relay["sql"]`, `relay["now"] = () => T`. TypeScript
checks bracket access to private members against the class, so a renamed or retyped member fails
`typecheck`. Annotate `runInDurableObject` callbacks as `(relay: AccountRelay) => …`. Never cast through
`unknown` to a hand-written shape of the relay, or build one with `Object.create(AccountRelay.prototype)`:
`test/private-state-access.test.ts` fails on either (#367). To drive one private method without a runtime
instance, construct a real `AccountRelay` over a stub state (see `relayOverStubState` in
`relay-routing.test.ts`).
