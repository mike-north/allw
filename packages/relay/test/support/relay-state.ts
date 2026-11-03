/**
 * Direct `AccountRelay` state setup for tests: an injected clock and a bound account root.
 *
 * The relay's submit limits (expiry, horizon, pending cap) and its expiry alarm/sweep read
 * `AccountRelay#now`, which defaults to the real time. Tests replace it on the live instance so
 * boundaries are exact and fixtures stay fixed dates (never `Date.now()` in test data). The override
 * lives on the in-memory instance; it holds for a test because the workers pool keeps each Durable
 * Object instance alive while it is in use.
 *
 * `POST /{acct}/requests` refuses accounts with no bound root (404 "unknown account", #248). Tests
 * that submit without pairing a device bind the account's test root directly — the same row a
 * verified root-signed `pairing/start` writes — instead of spending a pairing per account.
 *
 * @see ./README.md
 */

import { env, runInDurableObject } from "cloudflare:test";
import type { SqlStorage } from "@cloudflare/workers-types";
import type { AccountRelay } from "../../src/index.js";
import { rootFor } from "./accounts.js";

/** Fixed `bound_at` for directly-bound roots (2023-11-14Z). */
const BOUND_AT = 1_700_000_000_000;

/** Pin `accountId`'s Durable Object clock to the fixed instant `now` (ms since the epoch). */
export async function pinRelayClock(accountId: string, now: number): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    (instance as unknown as { now: () => number }).now = () => now;
  });
}

/**
 * Bind `accountId`'s test root (from `testAccount`) unless a root is already bound. Idempotent, and
 * compatible with a later real `pairing/start` for the same root.
 */
export async function bindAccountRoot(accountId: string): Promise<void> {
  const rootPubkey = rootFor(accountId).rootPubkey;
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    relay.sql.exec(
      `INSERT OR IGNORE INTO account_meta (id, root_pubkey, bound_at) VALUES (1, ?, ?)`,
      rootPubkey,
      BOUND_AT,
    );
  });
}
