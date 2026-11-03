/**
 * Planted violations that prove the private-state lint rules on relay tests still fire (#367).
 *
 * Each line below breaks one rule in `eslint.config.js` (`relayPrivateStateRestrictions`) and
 * carries an `eslint-disable-next-line` for exactly the rules it breaks. Relay test lint runs with
 * `reportUnusedDisableDirectives: "error"`, so if a rule stops matching its plant, the directive
 * goes unused and `pnpm lint` fails. Nothing here runs: this file is not a `*.test.ts`, and the
 * function is never called. It typechecks, which is the point: every plant is a cast TypeScript
 * accepts, so only lint catches it.
 */

import type { AccountRelay, Env } from "../src/index.js";

/** A shape naming the coalescer's old name (#366), which `AccountRelay` no longer has. */
interface StaleShape {
  webPushCoalescer: number;
}

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
}
