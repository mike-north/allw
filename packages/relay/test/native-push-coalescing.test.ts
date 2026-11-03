/**
 * The per-window bound on APNs/FCM wakeups (#248): native push tokens go through the same
 * per-token coalescer as Web Push (one wakeup per `PUSH_COALESCE_MS`, claims persisted in
 * `device_push_token.last_wakeup_at`), and a native token skipped inside a window is owed exactly
 * one trailing wakeup when the window ends. Unlike a payload-less Web Push wakeup, that trailing
 * wakeup carries a request id: the latest submit the window skipped.
 *
 * Every test drives the relay on its injected clock (`AccountRelay#now`, via `pinRelayClock`), so
 * window boundaries are exact fixed instants and the alarm runs at a chosen time. Push tokens are
 * seeded straight into `device_push_token`; the transports are recording fakes installed into the
 * account's Durable Object, so nothing leaves the test runtime.
 *
 * @see ../../../docs/relay-api.md §5 Push wakeups (coalescing, trailing wakeups)
 * @see ../../../docs/threat-model.md "Relay denial of service", Push residual
 */

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import type { SqlStorage } from "@cloudflare/workers-types";
import type { AccountRelay } from "../src/index.js";
import {
  MAX_PUSH_TOKENS_PER_ACCOUNT,
  PUSH_COALESCE_MS,
  type PushTransport,
  type PushTransportKind,
  type PushTransportRegistry,
  type PushWakeup,
} from "../src/push.js";
import { WebPushTransport, type VapidConfig } from "../src/web-push.js";
import { testAccount, testRequestId as rid } from "./support/accounts.js";
import { bindAccountRoot, pinRelayClock } from "./support/relay-state.js";

/** The first submit's instant (2099-12-31T00:00Z). Every other time is an offset from it. */
const T0 = 4_102_358_400_000;
/** The end of the first wakeup's window: the first instant its token can be claimed again. */
const WINDOW_END = T0 + PUSH_COALESCE_MS + 1;
/** One device's APNs token (64 hex digits) and FCM registration token. */
const APNS_TOKEN = "a".repeat(64);
const FCM_TOKEN = "fcm-registration-token-1";
const WEBPUSH_ENDPOINT = "https://fcm.googleapis.com/fcm/send/c3Vic2NyaXB0aW9uLWE";

type RelayInternals = {
  sql: SqlStorage;
  pushTransports: PushTransportRegistry;
  pushFanOut: Promise<void>;
  initSchema(): void;
  alarm(): Promise<void>;
};

type TrailingRow = {
  device_id: string;
  transport: string;
  token: string;
  due_at: number;
  last_skipped_request_id: string | null;
};

function stub(accountId: string): DurableObjectStub {
  return env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
}

function inRelay<T>(accountId: string, fn: (relay: RelayInternals) => T | Promise<T>): Promise<T> {
  return runInDurableObject(stub(accountId), (instance: AccountRelay) =>
    fn(instance as unknown as RelayInternals),
  );
}

/** A recording transport: every wakeup it is handed, in order, for the given kind. */
function recorder(kind: PushTransportKind): PushTransport & { sent: PushWakeup[] } {
  const sent: PushWakeup[] = [];
  return {
    kind,
    sent,
    sendWakeup(wakeup) {
      sent.push(wakeup);
      return Promise.resolve();
    },
  };
}

/** A fresh account: root bound, clock at {@link T0}, `transports` installed, `tokens` registered. */
async function account(
  name: string,
  transports: PushTransportRegistry,
  tokens: ReadonlyArray<{ device_id: string; transport: PushTransportKind; token: string }>,
): Promise<string> {
  const acct = testAccount(`native-coalesce-${name}`);
  await bindAccountRoot(acct);
  await pinRelayClock(acct, T0);
  await inRelay(acct, (relay) => {
    relay.pushTransports = transports;
    tokens.forEach((t, i) => {
      relay.sql.exec(
        `INSERT INTO device_push_token (device_id, transport, token, created_at) VALUES (?, ?, ?, ?)`,
        t.device_id,
        t.transport,
        t.token,
        T0 - 60_000 + i,
      );
    });
  });
  return acct;
}

/**
 * Submit request `name` at relay time `at`, expiring `ttlMs` later; returns the `push_wakeups` the
 * submit scheduled.
 */
async function submitAt(
  acct: string,
  at: number,
  name: string,
  ttlMs = 10 * 60_000,
): Promise<number> {
  await pinRelayClock(acct, at);
  const resp = await SELF.fetch(`https://relay.allw.test/${acct}/requests`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      v: 1,
      id: rid(name),
      created_at: at - 1_000,
      expires_at: at + ttlMs,
      approver: "acct-approver-routing-id",
      context_ciphertext: "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE",
    }),
  });
  expect(resp.status).toBe(202);
  const { push_wakeups } = (await resp.json()) as { push_wakeups: number };
  await fanOutSettled(acct);
  return push_wakeups;
}

function fanOutSettled(acct: string): Promise<void> {
  return inRelay(acct, (relay) => relay.pushFanOut);
}

/** Fire the relay's alarm at relay time `at` and wait for any fan-out it starts. */
async function alarmAt(acct: string, at: number): Promise<void> {
  await pinRelayClock(acct, at);
  await inRelay(acct, async (relay) => {
    await relay.alarm();
    await relay.pushFanOut;
  });
}

function trailingRows(acct: string): Promise<TrailingRow[]> {
  return inRelay(acct, (relay) => [
    ...relay.sql.exec<TrailingRow>(
      `SELECT device_id, transport, token, due_at, last_skipped_request_id
       FROM webpush_trailing_wakeup ORDER BY device_id ASC, token ASC`,
    ),
  ]);
}

describe("APNs/FCM wakeups are bounded per window, with one trailing wakeup (#248)", () => {
  for (const transport of ["apns", "fcm"] as const) {
    const token = transport === "apns" ? APNS_TOKEN : FCM_TOKEN;

    it(`${transport}: submits skipped within the window get exactly one trailing wakeup, carrying the latest skipped request id`, async () => {
      const native = recorder(transport);
      const acct = await account(`trailing-${transport}`, { [transport]: native }, [
        { device_id: "dev-1", transport, token },
      ]);

      // The lead request outlives the skipped ones, so "the latest skipped request" and "the
      // longest-lived pending request" are different ids.
      expect(await submitAt(acct, T0, `${transport}-lead`, 14 * 60_000)).toBe(1);
      expect(await submitAt(acct, T0 + 5_000, `${transport}-skip-1`)).toBe(0);
      expect(await submitAt(acct, T0 + 20_000, `${transport}-skip-2`)).toBe(0);
      expect(native.sent.map((w) => w.requestId)).toEqual([rid(`${transport}-lead`)]);
      expect(await trailingRows(acct)).toEqual([
        {
          device_id: "dev-1",
          transport,
          token,
          due_at: WINDOW_END,
          last_skipped_request_id: rid(`${transport}-skip-2`),
        },
      ]);

      // One millisecond before the window ends nothing is due yet.
      await alarmAt(acct, WINDOW_END - 1);
      expect(native.sent).toHaveLength(1);

      await alarmAt(acct, WINDOW_END);
      expect(native.sent.map((w) => w.requestId)).toEqual([
        rid(`${transport}-lead`),
        rid(`${transport}-skip-2`),
      ]);
      expect(await trailingRows(acct)).toEqual([]);

      // Owed exactly once: a later alarm sends nothing more.
      await alarmAt(acct, WINDOW_END + PUSH_COALESCE_MS * 2);
      expect(native.sent).toHaveLength(2);
    });
  }

  it("bounds an account to 32 tokens × 1 wakeup per window, however many submits arrive", async () => {
    const apns = recorder("apns");
    const fcm = recorder("fcm");
    const half = MAX_PUSH_TOKENS_PER_ACCOUNT / 2;
    const tokens = [
      ...Array.from({ length: half }, (_, i) => ({
        device_id: `dev-${String(i).padStart(2, "0")}`,
        transport: "apns" as const,
        token: i.toString(16).padStart(64, "0"),
      })),
      ...Array.from({ length: half }, (_, i) => ({
        device_id: `dev-${String(half + i).padStart(2, "0")}`,
        transport: "fcm" as const,
        token: `fcm-token-${String(i)}`,
      })),
    ];
    expect(tokens).toHaveLength(32);
    const acct = await account("account-bound", { apns, fcm }, tokens);

    const scheduled: number[] = [];
    for (let n = 0; n < 10; n++) {
      scheduled.push(await submitAt(acct, T0 + n * 1_000, `bound-${String(n)}`));
    }
    expect(scheduled).toEqual([32, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect(apns.sent.length + fcm.sent.length).toBe(32);
    expect(await trailingRows(acct)).toHaveLength(32);

    await alarmAt(acct, WINDOW_END);
    // Two windows: one leading and one trailing wakeup per token, never more.
    const perToken = new Map<string, number>();
    for (const w of [...apns.sent, ...fcm.sent]) {
      perToken.set(w.deviceId, (perToken.get(w.deviceId) ?? 0) + 1);
    }
    expect(perToken.size).toBe(32);
    expect([...perToken.values()].every((count) => count === 2)).toBe(true);
    // Every trailing wakeup carries the window's latest skipped submit.
    const trailing = [...apns.sent.slice(half), ...fcm.sent.slice(half)];
    expect(new Set(trailing.map((w) => w.requestId))).toEqual(new Set([rid("bound-9")]));
  });

  it("loses nothing when a submit lands while the window's wakeup is still in flight", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const sent: string[] = [];
    const apns: PushTransport = {
      kind: "apns",
      async sendWakeup(wakeup) {
        sent.push(wakeup.requestId);
        if (sent.length === 1) await gate;
      },
    };
    const acct = await account("in-flight", { apns }, [
      { device_id: "dev-1", transport: "apns", token: APNS_TOKEN },
    ]);

    // The leading wakeup is held in flight; a submit arrives mid-window, before it is accepted.
    await pinRelayClock(acct, T0);
    const lead = SELF.fetch(`https://relay.allw.test/${acct}/requests`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        v: 1,
        id: rid("in-flight-lead"),
        created_at: T0 - 1_000,
        expires_at: T0 + 10 * 60_000,
        approver: "acct-approver-routing-id",
        context_ciphertext: "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE",
      }),
    });
    expect((await lead).status).toBe(202);
    await vi.waitFor(() => {
      expect(sent).toEqual([rid("in-flight-lead")]);
    });
    await pinRelayClock(acct, T0 + 10_000);
    const midWindow = await SELF.fetch(`https://relay.allw.test/${acct}/requests`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        v: 1,
        id: rid("in-flight-mid"),
        created_at: T0 + 9_000,
        expires_at: T0 + 10 * 60_000,
        approver: "acct-approver-routing-id",
        context_ciphertext: "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE",
      }),
    });
    expect(((await midWindow.json()) as { push_wakeups: number }).push_wakeups).toBe(0);

    // The leading wakeup is accepted only now. It predates the mid-window submit, so it does not
    // cover it: the owed trailing wakeup survives.
    release();
    await fanOutSettled(acct);
    expect((await trailingRows(acct)).map((r) => r.last_skipped_request_id)).toEqual([
      rid("in-flight-mid"),
    ]);

    await alarmAt(acct, WINDOW_END);
    expect(sent).toEqual([rid("in-flight-lead"), rid("in-flight-mid")]);
    expect(await trailingRows(acct)).toEqual([]);
  });

  it("drops an owed wakeup whose transport is no longer configured, or whose token is gone", async () => {
    const apns = recorder("apns");
    const fcm = recorder("fcm");
    const acct = await account("dropped", { apns, fcm }, [
      { device_id: "dev-1", transport: "apns", token: APNS_TOKEN },
      { device_id: "dev-2", transport: "fcm", token: FCM_TOKEN },
    ]);
    expect(await submitAt(acct, T0, "dropped-lead")).toBe(2);
    expect(await submitAt(acct, T0 + 5_000, "dropped-skip")).toBe(0);
    expect(await trailingRows(acct)).toHaveLength(2);

    // APNs credentials are removed from the relay; the FCM token is unregistered.
    await inRelay(acct, (relay) => {
      relay.pushTransports = { fcm };
      relay.sql.exec(`DELETE FROM device_push_token WHERE transport = 'fcm'`);
    });
    await alarmAt(acct, WINDOW_END);

    expect(apns.sent).toHaveLength(1);
    expect(fcm.sent).toHaveLength(1);
    expect(await trailingRows(acct)).toEqual([]);
  });
});

describe("trailing-wakeup schema migration (#248)", () => {
  function b64url(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function makeVapid(): Promise<VapidConfig> {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    return { publicKey: b64url(raw), privateKey: jwk.d ?? "", subject: "mailto:ops@allw.example" };
  }

  it("a web-push wakeup owed before the migration survives it and still fires", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => new Response(null, { status: 201 }));
    const webpush = new WebPushTransport({ vapid: await makeVapid(), fetcher, now: () => T0 });
    const acct = await account("migration", { webpush }, [
      { device_id: "dev-1", transport: "webpush", token: WEBPUSH_ENDPOINT },
    ]);
    // A pending request for the wakeup to cover, stored before the owed row was written.
    expect(await submitAt(acct, T0, "migration-pending")).toBe(1);

    // Rebuild the table in its pre-migration shape (no transport, no skipped request id, no
    // last_skipped_at) holding one owed web-push wakeup, as an older relay left it.
    await inRelay(acct, (relay) => {
      relay.sql.exec(`DROP TABLE webpush_trailing_wakeup`);
      relay.sql.exec(`CREATE TABLE webpush_trailing_wakeup (
        account_id TEXT NOT NULL,
        device_id  TEXT NOT NULL,
        token      TEXT NOT NULL,
        due_at     INTEGER NOT NULL,
        PRIMARY KEY (device_id, token)
      )`);
      relay.sql.exec(
        `INSERT INTO webpush_trailing_wakeup (account_id, device_id, token, due_at) VALUES (?, ?, ?, ?)`,
        acct,
        "dev-1",
        WEBPUSH_ENDPOINT,
        WINDOW_END,
      );
      relay.sql.exec(
        `INSERT OR REPLACE INTO alarm_due (purpose, due_at) VALUES ('webpush-trailing-wakeup', ?)`,
        WINDOW_END,
      );
      relay.initSchema();
    });

    expect(await trailingRows(acct)).toEqual([
      {
        device_id: "dev-1",
        transport: "webpush",
        token: WEBPUSH_ENDPOINT,
        due_at: WINDOW_END,
        last_skipped_request_id: null,
      },
    ]);

    await alarmAt(acct, WINDOW_END);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(String(fetcher.mock.calls[1]?.[0])).toBe(WEBPUSH_ENDPOINT);
    expect(await trailingRows(acct)).toEqual([]);
  });
});
