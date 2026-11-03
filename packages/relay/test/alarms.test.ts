/**
 * Tests for the Durable Object alarm multiplexer (`src/alarms.ts`).
 *
 * A Durable Object has one alarm; several relay purposes (request expiry, the trailing Web Push
 * wakeup) share it. These tests run the multiplexer on real Durable Object storage, so the
 * `alarm_due` table and `getAlarm()` are the runtime's own. Each test uses its own account's
 * storage, and purpose names the relay does not use.
 *
 * @see https://developers.cloudflare.com/durable-objects/api/alarms/
 */

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import type { DurableObjectStorage } from "@cloudflare/workers-types";
import { ALARM_RETRY_MS, AlarmMultiplexer } from "../src/alarms.js";
import type { AccountRelay } from "../src/index.js";
import { testAccount } from "./support/accounts.js";

type Purpose = "first" | "second";

/**
 * Run `body` against a fresh multiplexer on one account Durable Object's storage, on the real
 * clock unless `now` is given.
 */
async function withMultiplexer<T>(
  name: string,
  body: (mux: AlarmMultiplexer<Purpose>, storage: DurableObjectStorage) => Promise<T>,
  now?: () => number,
): Promise<T> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(testAccount(name)));
  return runInDurableObject(stub, async (_instance: AccountRelay, state) => {
    const storage = state.storage;
    return body(new AlarmMultiplexer<Purpose>(storage, now), storage);
  });
}

/** A due time comfortably in the future, so the runtime never fires the real alarm mid-test. */
function future(offsetMs: number): number {
  return Date.now() + 3_600_000 + offsetMs;
}

describe("AlarmMultiplexer — scheduling", () => {
  it("sets the alarm to the earliest purpose and keeps each purpose's own due time", async () => {
    await withMultiplexer("alarms-earliest", async (mux, storage) => {
      const early = future(0);
      const late = future(60_000);
      await mux.schedule("second", late);
      await mux.schedule("first", early);

      expect(await storage.getAlarm()).toBe(early);
      expect(mux.dueAt("first")).toBe(early);
      expect(mux.dueAt("second")).toBe(late);
    });
  });

  it("moves the alarm when a purpose is rescheduled or cleared, and clears it when none remain", async () => {
    await withMultiplexer("alarms-clear", async (mux, storage) => {
      const early = future(0);
      const late = future(60_000);
      await mux.schedule("first", early);
      await mux.schedule("second", late);

      // Clearing the earlier purpose never drops the other one.
      await mux.schedule("first", null);
      expect(mux.dueAt("first")).toBeNull();
      expect(await storage.getAlarm()).toBe(late);

      // Rescheduling replaces the purpose's time, earlier or later.
      const latest = late + 60_000;
      await mux.schedule("second", latest);
      expect(await storage.getAlarm()).toBe(latest);

      await mux.schedule("second", null);
      expect(await storage.getAlarm()).toBeNull();
    });
  });
});

describe("AlarmMultiplexer — running", () => {
  it("runs only the purposes that are due, and drops a due purpose that did not reschedule", async () => {
    await withMultiplexer("alarms-run-due", async (mux, storage) => {
      const now = future(0);
      const later = now + 60_000;
      await mux.schedule("first", now - 1);
      await mux.schedule("second", later);
      const first = vi.fn();
      const second = vi.fn();

      await mux.run(now, { first, second });

      expect(first).toHaveBeenCalledWith(now);
      expect(second).not.toHaveBeenCalled();
      expect(mux.dueAt("first")).toBeNull();
      expect(mux.dueAt("second")).toBe(later);
      expect(await storage.getAlarm()).toBe(later);
    });
  });

  it("treats a purpose due exactly now as due", async () => {
    await withMultiplexer("alarms-run-boundary", async (mux) => {
      const now = future(0);
      await mux.schedule("first", now);
      const first = vi.fn();
      await mux.run(now, { first, second: vi.fn() });
      expect(first).toHaveBeenCalledTimes(1);
    });
  });

  it("keeps the new time of a purpose whose handler rescheduled it", async () => {
    await withMultiplexer("alarms-run-resched", async (mux, storage) => {
      const now = future(0);
      const next = now + 30_000;
      await mux.schedule("first", now);

      await mux.run(now, {
        first: async () => {
          await mux.schedule("first", next);
        },
        second: vi.fn(),
      });

      expect(mux.dueAt("first")).toBe(next);
      expect(await storage.getAlarm()).toBe(next);
    });
  });

  it("runs handlers in the order given, whatever their due times", async () => {
    await withMultiplexer("alarms-run-order", async (mux) => {
      const now = future(0);
      await mux.schedule("second", now - 10);
      await mux.schedule("first", now - 1);
      const order: string[] = [];

      await mux.run(now, {
        first: () => {
          order.push("first");
        },
        second: () => {
          order.push("second");
        },
      });

      expect(order).toEqual(["first", "second"]);
    });
  });

  it("retries a failing purpose later without losing it, and still runs the others", async () => {
    // The due time it fired for is in the past, so it is replaced rather than kept: keeping it
    // would refire the alarm at once, in a loop.
    await withMultiplexer("alarms-run-throw", async (mux, storage) => {
      const now = future(0);
      await mux.schedule("first", now);
      await mux.schedule("second", now);
      const second = vi.fn();
      const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);

      await mux.run(now, {
        first: () => {
          throw new Error("boom");
        },
        second,
      });

      expect(second).toHaveBeenCalledTimes(1);
      expect(mux.dueAt("first")).toBe(now + ALARM_RETRY_MS);
      expect(mux.dueAt("second")).toBeNull();
      expect(await storage.getAlarm()).toBe(now + ALARM_RETRY_MS);
      expect(warn).toHaveBeenCalled();
      warn.mockRestore();
    });
  });

  it("never pushes back a failing purpose that was already due sooner (review S2)", async () => {
    // Expiry is every-firing: it can fail on a firing caused by another purpose while its own
    // deadline is a few seconds away. The retry must not move that deadline later.
    await withMultiplexer("alarms-run-throw-sooner", async (mux, storage) => {
      const now = future(0);
      const sooner = now + ALARM_RETRY_MS - 7_000;
      await mux.schedule("first", sooner);
      await mux.schedule("second", now);
      const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);

      await mux.run(
        now,
        {
          first: () => {
            throw new Error("boom");
          },
          second: vi.fn(),
        },
        { everyFiring: ["first"] },
      );

      expect(mux.dueAt("first")).toBe(sooner);
      expect(await storage.getAlarm()).toBe(sooner);
      warn.mockRestore();
    });
  });

  it("keeps a sooner time the failing handler set for itself before throwing", async () => {
    await withMultiplexer("alarms-run-resched-then-throw", async (mux) => {
      const now = future(0);
      const next = now + 2_000;
      await mux.schedule("first", now);
      const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);

      await mux.run(now, {
        first: async () => {
          await mux.schedule("first", next);
          throw new Error("boom after rescheduling");
        },
        second: vi.fn(),
      });

      expect(mux.dueAt("first")).toBe(next);
      warn.mockRestore();
    });
  });

  it("keeps a purpose whose handler rescheduled it for the very time it fired for (review N1)", async () => {
    await withMultiplexer("alarms-run-resched-same", async (mux) => {
      const now = future(0);
      await mux.schedule("first", now);

      await mux.run(now, {
        first: async () => {
          await mux.schedule("first", now);
        },
        second: vi.fn(),
      });

      expect(mux.dueAt("first")).toBe(now);
    });
  });

  it("runs an every-firing purpose even when it is not scheduled", async () => {
    await withMultiplexer("alarms-run-every", async (mux, storage) => {
      const now = future(0);
      await mux.schedule("second", now);
      const first = vi.fn();

      await mux.run(now, { first, second: vi.fn() }, { everyFiring: ["first"] });

      expect(first).toHaveBeenCalledTimes(1);
      // Running it did not invent a schedule for it.
      expect(mux.dueAt("first")).toBeNull();
      expect(await storage.getAlarm()).toBeNull();
    });
  });

  it("does not run an every-firing purpose's later schedule early, or drop it", async () => {
    await withMultiplexer("alarms-run-every-later", async (mux) => {
      const now = future(0);
      await mux.schedule("first", now + 60_000);
      await mux.run(now, { first: vi.fn(), second: vi.fn() }, { everyFiring: ["first"] });
      // The handler ran, but its future schedule is kept for the time it names.
      expect(mux.dueAt("first")).toBe(now + 60_000);
    });
  });

  it("removes a due row for a purpose that no longer has a handler", async () => {
    await withMultiplexer("alarms-run-retired", async (mux, storage) => {
      const now = future(0);
      storage.sql.exec(`INSERT INTO alarm_due (purpose, due_at) VALUES ('retired', ?)`, now - 1);

      await mux.run(now, { first: vi.fn(), second: vi.fn() });

      const left = [...storage.sql.exec<{ purpose: string }>(`SELECT purpose FROM alarm_due`)];
      expect(left).toEqual([]);
      expect(await storage.getAlarm()).toBeNull();
    });
  });

  it("never sets the alarm in the past", async () => {
    await withMultiplexer("alarms-past", async (mux, storage) => {
      const before = Date.now();
      await mux.schedule("first", 1);
      expect(await storage.getAlarm()).toBeGreaterThanOrEqual(before);
    });
  });

  it("clamps a past due time to the injected clock's now, not the real time (#292)", async () => {
    const pinned = future(0);
    await withMultiplexer(
      "alarms-past-injected",
      async (mux, storage) => {
        await mux.schedule("first", pinned - 5_000);
        expect(await storage.getAlarm()).toBe(pinned);
        // A due time after the clock's now is kept as is.
        await mux.schedule("first", pinned + 5_000);
        expect(await storage.getAlarm()).toBe(pinned + 5_000);
      },
      () => pinned,
    );
  });
});
