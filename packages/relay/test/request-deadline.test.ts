/**
 * Tests for the request deadline (`src/request-deadline.ts`, #292) and the relay's single clock.
 *
 * - `deadlineOf` is the earlier of `expires_at` and `created_at + maxRequestTtlMs`.
 * - `DEADLINE_SQL`, its SQL twin, computes the same value in the Durable Object's SQLite.
 * - The relay's Durable Object code reads the time only through its injected clock.
 *
 * The lifecycle paths that read the deadline are covered in `relay-routing.test.ts` ("one deadline
 * for every lifecycle path").
 *
 * @see ../../../docs/relay-api.md §3 Integrator endpoints (the request horizon)
 * @see ../../../docs/contract.md §Lifecycle (fail-closed expiry)
 */

import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { AccountRelay } from "../src/index.js";
import { DEADLINE_SQL, deadlineOf } from "../src/request-deadline.js";
import { testAccount } from "./support/accounts.js";

/** A fixed relay receipt time (2023-11-14Z). */
const RECEIVED_AT = 1_700_000_000_000;
const TTL_MS = 15 * 60_000;

/** Each case: the row, and its deadline by the definition (the earlier of the two bounds). */
const CASES = [
  {
    name: "expires_at first",
    row: { created_at: RECEIVED_AT, expires_at: RECEIVED_AT + 60_000 },
    deadline: RECEIVED_AT + 60_000,
  },
  {
    name: "horizon first",
    row: { created_at: RECEIVED_AT, expires_at: RECEIVED_AT + 10 * TTL_MS },
    deadline: RECEIVED_AT + TTL_MS,
  },
  {
    name: "both equal",
    row: { created_at: RECEIVED_AT, expires_at: RECEIVED_AT + TTL_MS },
    deadline: RECEIVED_AT + TTL_MS,
  },
  {
    name: "already past",
    row: { created_at: RECEIVED_AT, expires_at: RECEIVED_AT - 1 },
    deadline: RECEIVED_AT - 1,
  },
] as const;

describe("deadlineOf", () => {
  for (const { name, row, deadline } of CASES) {
    it(`is the earlier bound: ${name}`, () => {
      expect(deadlineOf(row, TTL_MS)).toBe(deadline);
    });
  }
});

describe("DEADLINE_SQL", () => {
  it("computes deadlineOf's value in SQLite for every case", async () => {
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(testAccount("deadline-sql")));
    const fromSql = await runInDurableObject(stub, (instance: AccountRelay) => {
      const sql = instance["sql"];
      return CASES.map(
        ({ row }) =>
          [
            ...sql.exec<{ deadline: number }>(
              `SELECT ${DEADLINE_SQL} AS deadline
               FROM (SELECT ? AS created_at, ? AS expires_at)`,
              TTL_MS,
              row.created_at,
              row.expires_at,
            ),
          ][0]?.deadline,
      );
    });
    expect(fromSql).toEqual(CASES.map(({ deadline }) => deadline));
  });
});

describe("the relay's one clock", () => {
  /** Every relay source file's text, by path (`../src/<file>.ts`). New files are covered too. */
  const SOURCES = import.meta.glob("../src/*.ts", {
    query: "?raw",
    import: "default",
    eager: true,
  });

  /** Lines that read the real time (`Date.now`, called or not, or `new Date()`) outside comments. */
  function clockReads(source: string): string[] {
    return source
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => !line.startsWith("*") && !line.startsWith("//") && !line.startsWith("/*"))
      .filter((line) => line.includes("Date.now") || line.includes("new Date()"));
  }

  it("reads the real time only as the default of an injectable clock", () => {
    expect(Object.keys(SOURCES)).toContain("../src/index.ts");
    const reads = Object.fromEntries(
      Object.entries(SOURCES)
        .map(([path, source]) => [path, clockReads(source)] as const)
        .filter(([, lines]) => lines.length > 0),
    );
    // AccountRelay's clock is the one production reads. It hands itself to the other two: the
    // alarm multiplexer and the Web Push transport (via `buildPushTransports`).
    expect(reads).toEqual({
      "../src/index.ts": ["private now: () => number = () => Date.now();"],
      "../src/alarms.ts": [
        "constructor(storage: DurableObjectStorage, now: () => number = () => Date.now()) {",
      ],
      "../src/web-push.ts": ["this.now = options.now ?? Date.now;"],
    });
  });
});
