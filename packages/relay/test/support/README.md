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

`pnpm lint` backs this up with `no-restricted-syntax` rules on every test source (#367), defined in the root
`eslint/relay-private-state.js`. They're test hygiene, not a sandbox: they make the mistake hard to write by
accident. That module's comment lists exactly what they check. In short:

- **Double casts.** A double cast through `unknown`, `never` or `any` may target only a bare `WebSocket`,
  `Env`, `DurableObjectState` or `DurableObjectStorage`. `core.test.ts` alone may also target `Record`.
- **Lone and shape casts.** A lone cast to `unknown` or `never` is refused. So is a single cast to an
  object-literal type or to `Partial`, `Pick`, `Omit`, `Record`, `Required` or `Readonly`, except on a
  `JSON.parse(…)` result.
- **Allowed names stay real.** Test code can't redeclare those four names or bind another type to them by
  import or export.
- **Reflection.** Prototype access and the reflection that writes to or rewires an object are refused
  (`Object.create`, `assign`, `defineProperty`, `setPrototypeOf`, `Reflect`, `__proto__`), including through
  computed keys, destructuring, aliases and `globalThis`.
- **`as any`** falls to `no-explicit-any`.

Known limits:

- A single cast to a named shape with optional members (`relay as LooseShape`, or an alias such as
  `type P = Partial<AccountRelay>`) gets through.
- So does a single cast to an intersection (`relay as AccountRelay & { extra?: 1 }`).
- So does laundering through a generic helper (`launder<Shape>(relay)`).
- So does reflection the rules can't see by name: `({}).constructor`, `Function("return this")()`, `new Proxy`,
  `structuredClone`, or a subclass of `AccountRelay`.

Review has to catch these. `eslint/relay-private-state.js` lists them in full.

`test/private-state-plants.ts` plants each violation. Its disable directives must stay in use, so lint fails if
a rule stops firing. `test/lint-coverage.test.ts` fails if any other file disables `no-restricted-syntax`,
if any file uses a blanket disable, or if `test/` gains a source in a language the typed lint block skips.
