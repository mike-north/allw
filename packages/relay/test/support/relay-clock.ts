/**
 * Injected clock for `AccountRelay` tests.
 *
 * The relay's submit limits (expiry, horizon, pending cap) and its expiry alarm/sweep read
 * `AccountRelay#now`, which defaults to the real time. Tests replace it on the live instance so
 * boundaries are exact and fixtures stay fixed dates (never `Date.now()` in test data).
 *
 * The override lives on the in-memory instance; it holds for the duration of a test because the
 * workers pool keeps each Durable Object instance alive while it is in use.
 */

import { env, runInDurableObject } from "cloudflare:test";
import type { AccountRelay } from "../../src/index.js";

/** Pin `accountId`'s Durable Object clock to the fixed instant `now` (ms since the epoch). */
export async function pinRelayClock(accountId: string, now: number): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    (instance as unknown as { now: () => number }).now = () => now;
  });
}
