/**
 * One Durable Object alarm, shared by several independent purposes.
 *
 * A Durable Object has a single alarm. Several relay jobs need a wake-up at a future time: request
 * expiry, the trailing Web Push wakeup, and later the storage sweep. If each job called `setAlarm`
 * directly, the last writer would silently cancel the others. This module is the only code that
 * touches the alarm:
 *
 * - Each **purpose** records its own next due time in the `alarm_due` table.
 * - The real alarm is always set to the earliest of those times, and cleared when none remain.
 * - When the alarm fires, every purpose that is due runs its handler.
 * - A purpose may also be marked to run on **every** firing, whatever woke the alarm. This suits a
 *   handler that is idempotent and recomputes its work from stored data. Request expiry is one: an
 *   alarm left by an older deploy, or rows written outside the normal path, are still handled.
 *
 * Purposes are independent: rescheduling or clearing one never moves another's due time.
 *
 * The due times live in SQLite, not in memory, so they survive hibernation and eviction. A fresh
 * instance woken by the alarm finds its schedule intact.
 */

import type { DurableObjectStorage } from "@cloudflare/workers-types";

/**
 * How long a purpose whose handler threw waits before it runs again. A failing handler is
 * rescheduled, never dropped, so one broken purpose can neither lose its own work nor stall the
 * others.
 */
export const ALARM_RETRY_MS = 10_000;

/** Runs the work for one purpose. It reschedules itself (via {@link AlarmMultiplexer.schedule}) if more is due later. */
export type AlarmHandler = (nowMs: number) => Promise<void> | void;

/** A row of `alarm_due`. */
interface AlarmDueRow extends Record<string, string | number | null | ArrayBuffer> {
  purpose: string;
  due_at: number;
}

/**
 * Multiplexes the Durable Object alarm across named purposes; see the module comment.
 *
 * `Purpose` is the closed set of purpose names a Durable Object uses, so a typo is a type error and
 * every handler map is complete.
 */
export class AlarmMultiplexer<Purpose extends string> {
  private readonly storage: DurableObjectStorage;
  /**
   * While {@link run} is executing: the purposes scheduled (or cleared) by a handler during this
   * firing. A due purpose missing from it did not reschedule itself, so its row is removed.
   */
  private scheduledDuringRun: Set<string> | undefined;

  constructor(storage: DurableObjectStorage) {
    this.storage = storage;
    storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS alarm_due (
        purpose TEXT    PRIMARY KEY,
        due_at  INTEGER NOT NULL
      )
    `);
  }

  /**
   * Set `purpose` to run at `dueAt` (epoch ms), replacing any earlier schedule for it. Pass `null`
   * to clear it. The alarm is then re-armed to the earliest due time across all purposes.
   */
  async schedule(purpose: Purpose, dueAt: number | null): Promise<void> {
    this.scheduledDuringRun?.add(purpose);
    if (dueAt === null) {
      this.storage.sql.exec(`DELETE FROM alarm_due WHERE purpose = ?`, purpose);
    } else {
      this.storage.sql.exec(
        `INSERT INTO alarm_due (purpose, due_at) VALUES (?, ?)
         ON CONFLICT (purpose) DO UPDATE SET due_at = excluded.due_at`,
        purpose,
        dueAt,
      );
    }
    await this.rearm();
  }

  /** The due time currently scheduled for `purpose`, or `null` if none. */
  dueAt(purpose: Purpose): number | null {
    const row = [
      ...this.storage.sql.exec<AlarmDueRow>(
        `SELECT purpose, due_at FROM alarm_due WHERE purpose = ?`,
        purpose,
      ),
    ][0];
    return row?.due_at ?? null;
  }

  /**
   * The alarm fired: run every purpose due at `nowMs`, plus every purpose in `options.everyFiring`,
   * in the order of `handlers`. Then re-arm.
   *
   * - A due purpose stays scheduled only if its handler called {@link schedule} for it, even with
   *   the very time it fired for. Otherwise its row is removed once the handler returns.
   * - A handler that throws is logged and retried within {@link ALARM_RETRY_MS}. A retry never
   *   pushes a purpose back: if it is already due sooner but still in the future (including a time
   *   the handler set before throwing), that time is kept. The remaining purposes still run.
   * - A due row for a purpose not in `handlers` (a purpose since retired) is removed.
   */
  async run(
    nowMs: number,
    handlers: Readonly<Record<Purpose, AlarmHandler>>,
    options: { readonly everyFiring?: readonly Purpose[] } = {},
  ): Promise<void> {
    const everyFiring = new Set<string>(options.everyFiring ?? []);
    const due = [
      ...this.storage.sql.exec<AlarmDueRow>(
        `SELECT purpose, due_at FROM alarm_due WHERE due_at <= ?`,
        nowMs,
      ),
    ];
    const dueAtByPurpose = new Map(due.map((row) => [row.purpose, row.due_at]));
    const known = new Set<string>(Object.keys(handlers));
    for (const purpose of dueAtByPurpose.keys()) {
      if (!known.has(purpose)) {
        this.storage.sql.exec(`DELETE FROM alarm_due WHERE purpose = ?`, purpose);
      }
    }
    const scheduled = new Set<string>();
    this.scheduledDuringRun = scheduled;
    try {
      for (const [purpose, handler] of Object.entries(handlers) as [Purpose, AlarmHandler][]) {
        const dueAt = dueAtByPurpose.get(purpose);
        if (dueAt === undefined && !everyFiring.has(purpose)) continue;
        try {
          await handler(nowMs);
          // Remove a due row only if the handler did not reschedule the purpose.
          if (dueAt !== undefined && !scheduled.has(purpose)) {
            this.storage.sql.exec(`DELETE FROM alarm_due WHERE purpose = ?`, purpose);
          }
        } catch (error) {
          console.warn(`alarm purpose '${purpose}' failed; retrying`, error);
          // Retry at now + ALARM_RETRY_MS, unless the purpose is already due sooner and still in
          // the future: a retry never pushes a purpose back. A due time at or before now (the
          // one this firing ran for) is replaced, or the alarm would refire at once and spin.
          this.storage.sql.exec(
            `INSERT INTO alarm_due (purpose, due_at) VALUES (?, ?)
             ON CONFLICT (purpose) DO UPDATE SET due_at =
               CASE WHEN due_at > ? AND due_at < excluded.due_at THEN due_at ELSE excluded.due_at END`,
            purpose,
            nowMs + ALARM_RETRY_MS,
            nowMs,
          );
        }
      }
    } finally {
      this.scheduledDuringRun = undefined;
    }
    await this.rearm();
  }

  /** Set the alarm to the earliest due time (never in the past), or clear it when none remain. */
  private async rearm(): Promise<void> {
    const next = [
      ...this.storage.sql.exec<{ next: number | null }>(
        `SELECT MIN(due_at) AS next FROM alarm_due`,
      ),
    ][0]?.next;
    if (next === null || next === undefined) {
      await this.storage.deleteAlarm();
      return;
    }
    await this.storage.setAlarm(Math.max(next, Date.now()));
  }
}
