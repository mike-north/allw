/**
 * Planted violations that prove the private-state lint rules on relay tests still fire (#367).
 *
 * Each plant below breaks a rule in `eslint/relay-private-state.js` and carries an
 * `eslint-disable-next-line` for exactly the rules it breaks. Relay test lint runs with
 * `reportUnusedDisableDirectives: "error"`, so if a rule stops matching its plant, the directive
 * goes unused and `pnpm lint` fails. This is the only file allowed a used `no-restricted-syntax`
 * disable (`test/lint-coverage.test.ts` checks that). Nothing here runs: the file is not a
 * `*.test.ts`, and its functions are never called. It typechecks, which is the point: TypeScript
 * accepts every plant, so only lint catches it.
 */

import { AccountRelay, type Env } from "../src/index.js";
// An allowed target's name bound to another type, which would make `as unknown as DurableObjectState`
// a cast to that type.
// eslint-disable-next-line no-restricted-syntax -- planted
import type { WebPushTransport as DurableObjectState } from "../src/web-push.js";
// eslint-disable-next-line no-restricted-syntax -- planted
import type * as DurableObjectStorage from "../src/web-push.js";

/** A shape naming the coalescer's old name (#366), which `AccountRelay` no longer has. */
interface StaleShape {
  webPushCoalescer: number;
}

// An allowed target's name exported for another type, for a test to import as if it were the real one.
// eslint-disable-next-line no-restricted-syntax -- planted
export type { StaleShape as Env };

/** Uses the namespace import planted above. */
export type PlantedNamespace = DurableObjectStorage.VapidConfig;

export function plantedPrivateStateViolations(relay: AccountRelay): void {
  // A double cast to a shape, with the target wrapped onto the next line as Prettier can leave it.
  // prettier-ignore
  // eslint-disable-next-line no-restricted-syntax -- planted
  (relay as unknown as
    StaleShape).webPushCoalescer = 1;

  // A double cast to `Record`, which is allowed only in core.test.ts.
  // eslint-disable-next-line no-restricted-syntax, @typescript-eslint/dot-notation -- planted
  (relay as unknown as Record<string, unknown>)["webPushCoalescer"] = 1;

  // A union or intersection target that includes an allowed type.
  // eslint-disable-next-line no-restricted-syntax -- planted
  void (relay as unknown as Env | StaleShape);
  // eslint-disable-next-line no-restricted-syntax -- planted
  (relay as unknown as Env & StaleShape).webPushCoalescer = 1;

  // A double cast through `never` instead of `unknown`.
  // eslint-disable-next-line no-restricted-syntax -- planted
  (relay as never as StaleShape).webPushCoalescer = 1;

  // A cast through `any`.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access -- planted
  (relay as any).webPushCoalescer = 1;

  // The two halves of a double cast split across a variable.
  // eslint-disable-next-line no-restricted-syntax -- planted
  const hidden = relay as unknown;
  (hidden as StaleShape).webPushCoalescer = 1;

  // An angle-bracket double cast.
  // eslint-disable-next-line no-restricted-syntax, @typescript-eslint/consistent-type-assertions -- planted
  (<StaleShape>(<unknown>relay)).webPushCoalescer = 1;

  // A prototype-built instance, through an alias for Object.create and an alias for the class.
  // eslint-disable-next-line no-restricted-syntax -- planted
  const make = Object.create;
  // eslint-disable-next-line no-restricted-syntax -- planted
  const proto = (relay.constructor as typeof AccountRelay).prototype;
  void make(proto);
  // eslint-disable-next-line no-restricted-syntax -- planted
  Reflect.setPrototypeOf({}, proto);

  // A cast through a re-bound allowed name (the import above is the violation).
  void (relay as unknown as DurableObjectState);

  // A single cast to an object-literal type with optional members, and to a utility type.
  // eslint-disable-next-line no-restricted-syntax -- planted
  (relay as { webPushCoalescer?: number }).webPushCoalescer = 1;
  // eslint-disable-next-line no-restricted-syntax -- planted
  (relay as Partial<StaleShape>).webPushCoalescer = 1;
}

/** Allowed target names redeclared as a shape. */
export function plantedTargetRedeclarations(relay: AccountRelay): void {
  // eslint-disable-next-line no-restricted-syntax -- planted
  interface DurableObjectStorage {
    webPushCoalescer: number;
  }
  // eslint-disable-next-line no-restricted-syntax -- planted
  type WebSocket = StaleShape;
  (relay as unknown as DurableObjectStorage).webPushCoalescer = 1;
  (relay as unknown as WebSocket).webPushCoalescer = 1;
  // eslint-disable-next-line no-restricted-syntax, @typescript-eslint/no-unnecessary-type-parameters -- planted
  const launderAs = <Env>(value: unknown): Env => value as Env;
  void launderAs<StaleShape>(relay);
}

/** Reflection that writes to or rewires an instance, by every route the rules name. */
export function plantedReflection(relay: AccountRelay, key: string): void {
  // eslint-disable-next-line no-restricted-syntax -- planted
  Object.assign(relay, { webPushCoalescer: 1 });
  // eslint-disable-next-line no-restricted-syntax -- planted
  Object.defineProperty(relay, "webPushCoalescer", { value: 1 });
  // eslint-disable-next-line no-restricted-syntax -- planted
  Object.defineProperties(relay, { webPushCoalescer: { value: 1 } });
  // eslint-disable-next-line no-restricted-syntax -- planted
  Object.setPrototypeOf(relay, null);
  // eslint-disable-next-line no-restricted-syntax -- planted
  Reflect.set(relay, "webPushCoalescer", 1);
  // eslint-disable-next-line no-restricted-syntax -- planted
  Reflect.defineProperty(relay, "webPushCoalescer", { value: 1 });
  // eslint-disable-next-line no-restricted-syntax -- planted
  Reflect.setPrototypeOf(relay, null);
  // eslint-disable-next-line no-restricted-syntax -- planted
  void { __proto__: relay };
  // eslint-disable-next-line no-restricted-syntax -- planted
  void (relay as unknown as WebSocket & { __proto__: unknown }).__proto__;
  // eslint-disable-next-line no-restricted-syntax, @typescript-eslint/dot-notation -- planted
  void AccountRelay["prototype"];
  // eslint-disable-next-line no-restricted-syntax, @typescript-eslint/dot-notation -- planted
  void Object["create"];
  // eslint-disable-next-line no-restricted-syntax -- planted
  void Object[key as keyof ObjectConstructor];
  // eslint-disable-next-line no-restricted-syntax -- planted
  const { prototype } = AccountRelay;
  // eslint-disable-next-line no-restricted-syntax -- planted
  const { create } = Object;
  // eslint-disable-next-line no-restricted-syntax -- planted
  const objectAlias = Object;
  // eslint-disable-next-line no-restricted-syntax -- planted
  void globalThis.Object.create(prototype);
  // eslint-disable-next-line no-restricted-syntax -- planted
  void globalThis.Reflect;
  // eslint-disable-next-line no-restricted-syntax -- planted
  const withDefault = (value: unknown = Object): unknown => value;
  void create;
  void objectAlias;
  void withDefault;
}
