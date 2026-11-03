# Relay test support

- `accounts.ts` — deterministic self-certifying test accounts and root-signed `pairing/start` bodies.
- `relay-state.ts` — direct Durable Object setup: `pinRelayClock` (injected clock for the submit
  limits and the expiry alarm/sweep) and `bindAccountRoot` (submits need a bound root, #248).

## Reaching `AccountRelay`'s private state

Use element access on a value typed `AccountRelay`: `relay["sql"]`, `relay["now"] = () => T`. TypeScript
checks bracket access to private members against the class, so a renamed or retyped member fails
`typecheck`. Annotate `runInDurableObject` callbacks as `(relay: AccountRelay) => …`. To drive one private
method without a runtime instance, construct a real `AccountRelay` over a stub state (see
`relayOverStubState` in `relay-routing.test.ts`).

`pnpm lint` enforces this on every test source (#367), with AST rules in the root `eslint.config.js`
(`relayPrivateStateRestrictions`):

- A double cast through `unknown`, `never` or `any` is allowed only to a runtime type tests stub: `WebSocket`,
  `Env`, `DurableObjectState` or `DurableObjectStorage`. Never to a shape, a union or an intersection.
  `core.test.ts` alone may also cast to `Record`, to read the WASM glue's exports by name.
- A lone cast to `unknown` or `never` is forbidden, so a double cast can't be split across a variable.
- Prototype access is forbidden (`.prototype`, `Object.create`, the prototype getters and setters).
- `as any` falls to `no-explicit-any`.

`test/private-state-plants.ts` plants one violation of each. Its disable directives must stay in use, so lint
fails if a rule stops firing.
