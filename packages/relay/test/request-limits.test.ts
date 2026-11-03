/**
 * Abuse limits on the relay's unauthenticated routes (#248, relay slice).
 *
 * Every limit is probed at its boundary (accepted) and one unit past it (refused), with the relay's
 * clock injected (`pinRelayClock`) so boundaries are exact and fixtures are fixed dates.
 *
 * - Body size: checked before JSON parsing → 413.
 * - `context_ciphertext` size → 413.
 * - Horizon: `expires_at - now > MAX_REQUEST_TTL_MS` → 400 (Worker-var configurable).
 * - Pending cap per account → 429; expired / resolved / retracted / over-horizon rows don't count.
 * - Over-horizon pending rows are expired by the alarm and then swept after retention.
 * - Every terminal transition blanks the stored envelope, so retained rows hold no ciphertext.
 * - Submits to an account with no bound root → 404 "unknown account".
 * - `pairing/start` and `pairing/complete` bodies are size-capped before parsing → 413.
 * - Rate limiting on `pairing/start`, `pairing/complete`, `requests` → 429 (503 fail-closed when
 *   the limiter binding is missing or throws), keyed by account id + client IP, plus a per-client
 *   limit keyed by IP alone; IPv6 clients are keyed by their /64.
 *
 * @see ../../../docs/relay-api.md §3 Integrator endpoints (limits) and §1 Conventions
 * @see ../../../docs/relay-deploy.md (rate-limit bindings, MAX_REQUEST_TTL_MS)
 * @see ../../../docs/threat-model.md Residual risks — "Relay denial of service"
 * @see ../../../docs/contract.md §Invariants (fail-closed)
 */

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import type { SqlStorage } from "@cloudflare/workers-types";
import worker, { AccountRelay, type Env } from "../src/index.js";
import {
  DEFAULT_MAX_REQUEST_TTL_MS,
  MAX_CONTEXT_CIPHERTEXT_BYTES,
  MAX_PAIRING_BODY_BYTES,
  MAX_PENDING_REQUESTS_PER_ACCOUNT,
  MAX_REQUEST_BODY_BYTES,
  REQUEST_RETENTION_MS,
} from "../src/constants.js";
import {
  clientIpKey,
  clientRateLimitKey,
  enforceRateLimit,
  parseMaxRequestTtlMs,
  rateLimitKey,
  rateLimitedRoute,
  readBodyCapped,
  type RateLimiter,
} from "../src/limits.js";
import { pairingStartBody, testAccount } from "./support/accounts.js";
import { bindAccountRoot, pinRelayClock } from "./support/relay-state.js";

// ---------------------------------------------------------------------------
// Fixtures (fixed dates; never `Date.now()` in data)
// ---------------------------------------------------------------------------

/**
 * The injected relay clock (2096-10-02Z). Far enough in the future that alarms the relay schedules
 * from it (`setAlarm(max(deadline, real now))`) are the fixture values, not the real time.
 */
const NOW = 4_000_000_000_000;
/** A fixed `created_at` for envelopes (contract field; the relay does not interpret it). */
const CREATED_AT = 1_700_000_000_000;
/** The hooks' `MAX_TIMEOUT_MS` (`packages/hook/src/lib/config.ts`): the horizon must cover it. */
const HOOK_MAX_TIMEOUT_MS = 420_000;
const SHORT_CIPHERTEXT = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE";

function envelope(
  id: string,
  overrides: Partial<{ expires_at: number; context_ciphertext: string }> = {},
): Record<string, unknown> {
  return {
    v: 1,
    id,
    created_at: CREATED_AT,
    expires_at: overrides.expires_at ?? NOW + 60_000,
    approver: "acct-approver-limits",
    context_ciphertext: overrides.context_ciphertext ?? SHORT_CIPHERTEXT,
  };
}

function relayUrl(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

async function submitRaw(accountId: string, body: BodyInit): Promise<Response> {
  return SELF.fetch(relayUrl(accountId, "/requests"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
}

async function submit(
  accountId: string,
  body: unknown,
): Promise<{ status: number; error: string | undefined }> {
  const resp = await submitRaw(accountId, JSON.stringify(body));
  const data = (await resp.json()) as { error?: string };
  return { status: resp.status, error: data.error };
}

/** A fresh account with its root bound and its relay clock pinned to {@link NOW}. */
async function freshAccount(name: string): Promise<string> {
  const acct = testAccount(`limits-${name}`);
  await bindAccountRoot(acct);
  await pinRelayClock(acct, NOW);
  return acct;
}

function stubFor(accountId: string): DurableObjectStub {
  return env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
}

interface SeedRow {
  id: string;
  status: "pending" | "expired" | "resolved" | "retracted";
  created_at: number;
  expires_at: number;
  terminal_at: number | null;
}

async function seedRequests(accountId: string, rows: readonly SeedRow[]): Promise<void> {
  await runInDurableObject(stubFor(accountId), (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    for (const row of rows) {
      relay.sql.exec(
        `INSERT INTO request
         (request_id, envelope, created_at, expires_at, status, terminal_at, auth_token_hash)
         VALUES (?, ?, ?, ?, ?, ?, 'seeded-hash')`,
        row.id,
        JSON.stringify(envelope(row.id, { expires_at: row.expires_at })),
        row.created_at,
        row.expires_at,
        row.status,
        row.terminal_at,
      );
    }
  });
}

function livePending(prefix: string, count: number): SeedRow[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `${prefix}-${String(i)}`,
    status: "pending" as const,
    created_at: NOW - 1000,
    expires_at: NOW + 60_000,
    terminal_at: null,
  }));
}

async function requestStatuses(accountId: string): Promise<Record<string, string>> {
  return runInDurableObject(stubFor(accountId), (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    const out: Record<string, string> = {};
    for (const row of relay.sql.exec<{ request_id: string; status: string }>(
      `SELECT request_id, status FROM request`,
    )) {
      out[row.request_id] = row.status;
    }
    return out;
  });
}

async function storedEnvelopes(accountId: string): Promise<Record<string, string>> {
  return runInDurableObject(stubFor(accountId), (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    const out: Record<string, string> = {};
    for (const row of relay.sql.exec<{ request_id: string; envelope: string }>(
      `SELECT request_id, envelope FROM request`,
    )) {
      out[row.request_id] = row.envelope;
    }
    return out;
  });
}

async function runAlarmAt(accountId: string, now: number): Promise<number | null> {
  await pinRelayClock(accountId, now);
  return runInDurableObject(stubFor(accountId), async (instance: AccountRelay) => {
    await instance.alarm();
    const relay = instance as unknown as { ctx: DurableObjectState };
    return relay.ctx.storage.getAlarm();
  });
}

// ---------------------------------------------------------------------------
// Body size (before parsing)
// ---------------------------------------------------------------------------

describe("POST /requests body size", () => {
  /** A valid envelope JSON padded with insignificant whitespace to exactly `bytes` bytes. */
  function paddedBody(id: string, bytes: number): string {
    const base = JSON.stringify(envelope(id));
    return base + " ".repeat(bytes - new TextEncoder().encode(base).byteLength);
  }

  it("accepts a body of exactly MAX_REQUEST_BODY_BYTES", async () => {
    const acct = await freshAccount("body-at");
    const body = paddedBody("req-body-at", MAX_REQUEST_BODY_BYTES);
    expect(new TextEncoder().encode(body).byteLength).toBe(MAX_REQUEST_BODY_BYTES);
    const resp = await submitRaw(acct, body);
    expect(resp.status).toBe(202);
  });

  it("413 for a body one byte over MAX_REQUEST_BODY_BYTES, and stores nothing", async () => {
    const acct = await freshAccount("body-over");
    const resp = await submitRaw(acct, paddedBody("req-body-over", MAX_REQUEST_BODY_BYTES + 1));
    expect(resp.status).toBe(413);
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("413 through the Worker for a streamed body with no Content-Length over the cap", async () => {
    const acct = await freshAccount("body-stream");
    // A finite stream of MAX + 1 bytes in 16 KiB chunks: the chunk that crosses the cap is the last.
    const total = MAX_REQUEST_BODY_BYTES + 1;
    const chunkSize = 16 * 1024;
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          const n = Math.min(chunkSize, total - sent);
          controller.enqueue(new TextEncoder().encode(" ".repeat(n)));
          sent += n;
          if (sent >= total) controller.close();
        },
      },
      { highWaterMark: 0 },
    );
    const resp = await submitRaw(acct, stream);
    expect(resp.status).toBe(413);
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("readBodyCapped stops reading a stream with no Content-Length once past the cap", async () => {
    const chunk = new TextEncoder().encode(" ".repeat(16 * 1024));
    let pulled = 0;
    // An endless stream: the reader must stop at the cap, not at end of stream.
    const stream = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          pulled += 1;
          controller.enqueue(chunk);
        },
      },
      { highWaterMark: 0 },
    );
    const request = new Request("https://relay.allw.test/a/requests", {
      method: "POST",
      body: stream,
    });
    expect(request.headers.get("Content-Length")).toBeNull();
    expect(await readBodyCapped(request, MAX_REQUEST_BODY_BYTES)).toEqual({ kind: "too_large" });
    // 128 KiB / 16 KiB = 8 chunks fill the cap exactly; the 9th crosses it and reading stops.
    expect(pulled).toBeLessThanOrEqual(MAX_REQUEST_BODY_BYTES / chunk.byteLength + 2);
  });

  it("readBodyCapped refuses a declared Content-Length over the cap without reading", async () => {
    const pull = vi.fn();
    const request = new Request("https://relay.allw.test/a/requests", {
      method: "POST",
      headers: { "Content-Length": String(MAX_REQUEST_BODY_BYTES + 1) },
      body: new ReadableStream({ pull }, { highWaterMark: 0 }),
    });
    expect(await readBodyCapped(request, MAX_REQUEST_BODY_BYTES)).toEqual({ kind: "too_large" });
    expect(pull).not.toHaveBeenCalled();
  });

  it("readBodyCapped: exactly the cap is ok, one byte more is too_large", async () => {
    const at = new Request("https://relay.allw.test/a/requests", { method: "POST", body: "abcd" });
    expect(await readBodyCapped(at, 4)).toEqual({ kind: "ok", text: "abcd" });
    const over = new Request("https://relay.allw.test/a/requests", {
      method: "POST",
      body: "abcde",
    });
    expect(await readBodyCapped(over, 4)).toEqual({ kind: "too_large" });
  });

  it("readBodyCapped: malformed Content-Length and invalid UTF-8 are unreadable", async () => {
    const malformed = new Request("https://relay.allw.test/a/requests", {
      method: "POST",
      headers: { "Content-Length": "12abc" },
      body: new ReadableStream(),
    });
    expect(await readBodyCapped(malformed, 1024)).toEqual({ kind: "unreadable" });
    const badUtf8 = new Request("https://relay.allw.test/a/requests", {
      method: "POST",
      body: new Uint8Array([0x7b, 0xff, 0x7d]),
    });
    expect(await readBodyCapped(badUtf8, 1024)).toEqual({ kind: "unreadable" });
  });

  it("400 (not a crash) for invalid UTF-8 and for a non-object JSON body", async () => {
    const acct = await freshAccount("body-bad");
    expect((await submitRaw(acct, new Uint8Array([0x7b, 0xff, 0x7d]))).status).toBe(400);
    expect((await submitRaw(acct, "[1,2,3]")).status).toBe(400);
    expect((await submitRaw(acct, "not json")).status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// context_ciphertext size
// ---------------------------------------------------------------------------

describe("POST /requests context_ciphertext size", () => {
  it("accepts a ciphertext of exactly MAX_CONTEXT_CIPHERTEXT_BYTES", async () => {
    const acct = await freshAccount("ct-at");
    const result = await submit(
      acct,
      envelope("req-ct-at", { context_ciphertext: "A".repeat(MAX_CONTEXT_CIPHERTEXT_BYTES) }),
    );
    expect(result.status).toBe(202);
  });

  it("413 for a ciphertext one byte over the cap", async () => {
    const acct = await freshAccount("ct-over");
    const result = await submit(
      acct,
      envelope("req-ct-over", { context_ciphertext: "A".repeat(MAX_CONTEXT_CIPHERTEXT_BYTES + 1) }),
    );
    expect(result.status).toBe(413);
    expect(result.error).toMatch(/context_ciphertext/);
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("measures UTF-8 bytes, not UTF-16 code units", async () => {
    const acct = await freshAccount("ct-utf8");
    // MAX - 1 ASCII chars + one 2-byte char: MAX characters, MAX + 1 bytes.
    const ciphertext = "A".repeat(MAX_CONTEXT_CIPHERTEXT_BYTES - 1) + "é";
    expect(ciphertext.length).toBe(MAX_CONTEXT_CIPHERTEXT_BYTES);
    const result = await submit(acct, envelope("req-ct-utf8", { context_ciphertext: ciphertext }));
    expect(result.status).toBe(413);
  });
});

// ---------------------------------------------------------------------------
// Horizon
// ---------------------------------------------------------------------------

describe("POST /requests expires_at horizon", () => {
  it("defaults to 15 minutes, which covers the hooks' 420 s timeout", () => {
    expect(DEFAULT_MAX_REQUEST_TTL_MS).toBe(15 * 60 * 1000);
    expect(DEFAULT_MAX_REQUEST_TTL_MS).toBeGreaterThan(HOOK_MAX_TIMEOUT_MS);
  });

  it("accepts expires_at exactly MAX_REQUEST_TTL_MS ahead of the relay clock", async () => {
    const acct = await freshAccount("ttl-at");
    const result = await submit(
      acct,
      envelope("req-ttl-at", { expires_at: NOW + DEFAULT_MAX_REQUEST_TTL_MS }),
    );
    expect(result.status).toBe(202);
  });

  it("400 for expires_at one millisecond past the horizon, and stores nothing", async () => {
    const acct = await freshAccount("ttl-over");
    const result = await submit(
      acct,
      envelope("req-ttl-over", { expires_at: NOW + DEFAULT_MAX_REQUEST_TTL_MS + 1 }),
    );
    expect(result.status).toBe(400);
    expect(result.error).toMatch(/expires_at/);
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("accepts a hook-length request (420 s)", async () => {
    const acct = await freshAccount("ttl-hook");
    const result = await submit(
      acct,
      envelope("req-ttl-hook", { expires_at: NOW + HOOK_MAX_TIMEOUT_MS }),
    );
    expect(result.status).toBe(202);
  });

  it("still refuses expires_at equal to now (already expired) and accepts now + 1", async () => {
    const acct = await freshAccount("ttl-now");
    expect((await submit(acct, envelope("req-ttl-now", { expires_at: NOW }))).status).toBe(400);
    expect((await submit(acct, envelope("req-ttl-now1", { expires_at: NOW + 1 }))).status).toBe(
      202,
    );
  });

  it("honors a configured horizon at its boundary and one past it", async () => {
    const acct = await freshAccount("ttl-config");
    const configured = parseMaxRequestTtlMs("600000");
    await runInDurableObject(stubFor(acct), (instance: AccountRelay) => {
      (instance as unknown as { maxRequestTtlMs: number }).maxRequestTtlMs = configured;
    });
    expect(
      (await submit(acct, envelope("req-cfg-at", { expires_at: NOW + configured }))).status,
    ).toBe(202);
    expect(
      (await submit(acct, envelope("req-cfg-over", { expires_at: NOW + configured + 1 }))).status,
    ).toBe(400);
  });

  it("the Durable Object reads MAX_REQUEST_TTL_MS from its env", () => {
    // Construct directly with a stub state so the env → horizon wiring is checked end to end.
    const ctx = {
      storage: {
        sql: { exec: () => [] },
        deleteAlarm: () => Promise.resolve(),
        setAlarm: () => Promise.resolve(),
      },
      waitUntil: () => undefined,
    } as unknown as DurableObjectState;
    const relay = new AccountRelay(ctx, { ...env, MAX_REQUEST_TTL_MS: "123456" } as Env);
    expect((relay as unknown as { maxRequestTtlMs: number }).maxRequestTtlMs).toBe(123_456);
    const fallback = new AccountRelay(ctx, { ...env, MAX_REQUEST_TTL_MS: undefined } as Env);
    expect((fallback as unknown as { maxRequestTtlMs: number }).maxRequestTtlMs).toBe(
      DEFAULT_MAX_REQUEST_TTL_MS,
    );
  });

  it("parseMaxRequestTtlMs: unset uses the default; invalid values fall back to it", () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(parseMaxRequestTtlMs(undefined)).toBe(DEFAULT_MAX_REQUEST_TTL_MS);
    expect(parseMaxRequestTtlMs("")).toBe(DEFAULT_MAX_REQUEST_TTL_MS);
    expect(parseMaxRequestTtlMs("1800000")).toBe(1_800_000);
    expect(parseMaxRequestTtlMs(" 60000 ")).toBe(60_000);
    expect(errors).not.toHaveBeenCalled();
    for (const bad of ["abc", "0", "-5", "1.5", "1e6", "Infinity", "99999999999999999999"]) {
      expect(parseMaxRequestTtlMs(bad)).toBe(DEFAULT_MAX_REQUEST_TTL_MS);
    }
    expect(errors).toHaveBeenCalledTimes(7);
    errors.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// Pending cap
// ---------------------------------------------------------------------------

describe("POST /requests per-account pending cap", () => {
  it("accepts the submit that reaches the cap, and 429s the one after it", async () => {
    const acct = await freshAccount("cap");
    await seedRequests(acct, livePending("seed", MAX_PENDING_REQUESTS_PER_ACCOUNT - 1));

    expect((await submit(acct, envelope("req-cap-last"))).status).toBe(202);
    const over = await submit(acct, envelope("req-cap-over"));
    expect(over.status).toBe(429);
    expect(over.error).toMatch(/pending/);
    expect((await requestStatuses(acct))["req-cap-over"]).toBeUndefined();
  });

  it("does not count expired, resolved, retracted, past-deadline or over-horizon rows", async () => {
    const acct = await freshAccount("cap-excluded");
    const cap = MAX_PENDING_REQUESTS_PER_ACCOUNT;
    const terminal = (status: SeedRow["status"]) =>
      Array.from({ length: cap }, (_, i) => ({
        id: `${status}-${String(i)}`,
        status,
        created_at: NOW - 10_000,
        expires_at: NOW - 5_000,
        terminal_at: NOW - 5_000,
      }));
    await seedRequests(acct, [
      ...terminal("expired"),
      ...terminal("resolved"),
      ...terminal("retracted"),
      // Still 'pending' in storage but at/past expires_at (the alarm has not run yet).
      ...Array.from({ length: cap }, (_, i) => ({
        id: `overdue-${String(i)}`,
        status: "pending" as const,
        created_at: NOW - 10_000,
        expires_at: NOW,
        terminal_at: null,
      })),
      // Pre-horizon rows with a far-future expiry, received exactly MAX_REQUEST_TTL_MS ago.
      ...Array.from({ length: cap }, (_, i) => ({
        id: `legacy-${String(i)}`,
        status: "pending" as const,
        created_at: NOW - DEFAULT_MAX_REQUEST_TTL_MS,
        expires_at: NOW + 365 * 24 * 60 * 60 * 1000,
        terminal_at: null,
      })),
      ...livePending("live", cap - 1),
    ]);

    expect((await submit(acct, envelope("req-cap-excluded-ok"))).status).toBe(202);
    expect((await submit(acct, envelope("req-cap-excluded-over"))).status).toBe(429);
  });

  it("a pre-horizon row one millisecond younger than the horizon still counts", async () => {
    const acct = await freshAccount("cap-legacy-young");
    await seedRequests(acct, [
      ...livePending("live", MAX_PENDING_REQUESTS_PER_ACCOUNT - 1),
      {
        id: "legacy-young",
        status: "pending",
        created_at: NOW - DEFAULT_MAX_REQUEST_TTL_MS + 1,
        expires_at: NOW + 365 * 24 * 60 * 60 * 1000,
        terminal_at: null,
      },
    ]);
    expect((await submit(acct, envelope("req-cap-legacy-young"))).status).toBe(429);
  });
});

// ---------------------------------------------------------------------------
// Expiry + sweep of over-horizon pending rows
// ---------------------------------------------------------------------------

describe("alarm expires over-horizon pending rows so the sweep removes them", () => {
  const FAR_FUTURE = NOW + 365 * 24 * 60 * 60 * 1000;

  it("expires a row received MAX_REQUEST_TTL_MS ago; keeps one received 1 ms later", async () => {
    const acct = await freshAccount("horizon-expire");
    await seedRequests(acct, [
      {
        id: "legacy-at",
        status: "pending",
        created_at: NOW - DEFAULT_MAX_REQUEST_TTL_MS,
        expires_at: FAR_FUTURE,
        terminal_at: null,
      },
      {
        id: "legacy-young",
        status: "pending",
        created_at: NOW - DEFAULT_MAX_REQUEST_TTL_MS + 1,
        expires_at: FAR_FUTURE,
        terminal_at: null,
      },
    ]);

    const nextAlarm = await runAlarmAt(acct, NOW);
    expect(await requestStatuses(acct)).toEqual({
      "legacy-at": "expired",
      "legacy-young": "pending",
    });
    // The next alarm is the young row's horizon deadline, not its far-future expires_at.
    expect(nextAlarm).toBe(NOW + 1);
  });

  it("sweeps the expired row after the retention window (boundary kept, one past deleted)", async () => {
    const acct = await freshAccount("horizon-sweep");
    await seedRequests(acct, [
      {
        id: "legacy",
        status: "pending",
        created_at: NOW - DEFAULT_MAX_REQUEST_TTL_MS,
        expires_at: FAR_FUTURE,
        terminal_at: null,
      },
    ]);
    expect(await runAlarmAt(acct, NOW)).toBeNull();
    expect(await requestStatuses(acct)).toEqual({ legacy: "expired" });

    await runAlarmAt(acct, NOW + REQUEST_RETENTION_MS);
    expect(await requestStatuses(acct)).toEqual({ legacy: "expired" });

    await runAlarmAt(acct, NOW + REQUEST_RETENTION_MS + 1);
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("schedules a fresh submit's alarm at its expires_at", async () => {
    const acct = await freshAccount("horizon-arm");
    expect((await submit(acct, envelope("req-arm", { expires_at: NOW + 60_000 }))).status).toBe(
      202,
    );
    const alarm = await runInDurableObject(stubFor(acct), (instance: AccountRelay) =>
      (instance as unknown as { ctx: DurableObjectState }).ctx.storage.getAlarm(),
    );
    expect(alarm).toBe(NOW + 60_000);
  });
});

// ---------------------------------------------------------------------------
// Rate limiting (Worker entrypoint)
// ---------------------------------------------------------------------------

/** A fake limiter allowing `limit` calls per key, recording the keys it saw. */
function countingLimiter(limit: number): RateLimiter & { keys: string[] } {
  const counts = new Map<string, number>();
  const keys: string[] = [];
  return {
    keys,
    limit({ key }) {
      keys.push(key);
      const n = (counts.get(key) ?? 0) + 1;
      counts.set(key, n);
      return Promise.resolve({ success: n <= limit });
    },
  };
}

function workerFetch(
  accountId: string,
  subPath: string,
  overrides: Partial<Env>,
  init: RequestInit = { method: "POST", body: "{}" },
  ip = "198.51.100.7",
): Promise<Response> {
  const request = new Request(relayUrl(accountId, subPath), {
    ...init,
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip },
  });
  return worker.fetch(request, { ...env, ...overrides } as Env);
}

describe("rate limiting on unauthenticated routes", () => {
  const routes = [
    { subPath: "/pairing/start", binding: "RATE_LIMIT_PAIRING" as const },
    { subPath: "/pairing/complete", binding: "RATE_LIMIT_PAIRING" as const },
    { subPath: "/requests", binding: "RATE_LIMIT_REQUESTS" as const },
  ];

  it("wrangler.jsonc configures all three bindings", () => {
    expect(typeof env.RATE_LIMIT_PAIRING?.limit).toBe("function");
    expect(typeof env.RATE_LIMIT_REQUESTS?.limit).toBe("function");
    expect(typeof env.RATE_LIMIT_CLIENT?.limit).toBe("function");
  });

  it("per-client limit: fresh account ids from one IP share one bucket (limit-th passes, next 429)", async () => {
    const client = countingLimiter(3);
    const perAccount = countingLimiter(1_000);
    const overrides = { RATE_LIMIT_CLIENT: client, RATE_LIMIT_REQUESTS: perAccount };
    for (const name of ["a", "b", "c"]) {
      const acct = testAccount(`limits-rl-client-${name}`);
      expect((await workerFetch(acct, "/requests", overrides)).status).not.toBe(429);
    }
    const minted = testAccount("limits-rl-client-d");
    const resp = await workerFetch(minted, "/requests", overrides);
    expect(resp.status).toBe(429);
    expect(client.keys).toEqual(Array<string>(4).fill("ip|198.51.100.7"));
    // The refused request never reached the per-account limiter.
    expect(perAccount.keys).toHaveLength(3);
    // Another client IP has its own bucket.
    expect(
      (await workerFetch(minted, "/requests", overrides, undefined, "198.51.100.8")).status,
    ).not.toBe(429);
  });

  it("per-client limit covers the pairing routes too", async () => {
    const client = countingLimiter(0);
    const acct = testAccount("limits-rl-client-pairing");
    for (const subPath of ["/pairing/start", "/pairing/complete"]) {
      expect((await workerFetch(acct, subPath, { RATE_LIMIT_CLIENT: client })).status).toBe(429);
    }
  });

  it("503 (fail-closed) when the per-client binding is missing", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const acct = testAccount("limits-rl-client-missing");
    const resp = await workerFetch(acct, "/requests", {
      RATE_LIMIT_CLIENT: undefined,
    } as Partial<Env>);
    expect(resp.status).toBe(503);
    errors.mockRestore();
  });

  for (const { subPath, binding } of routes) {
    it(`POST ${subPath}: the limit-th call passes through, the next is 429`, async () => {
      const acct = testAccount(`limits-rl-${subPath}`);
      const limiter = countingLimiter(2);
      const overrides = { [binding]: limiter } as Partial<Env>;
      // Within the limit the request reaches the Durable Object (which rejects the empty body).
      expect((await workerFetch(acct, subPath, overrides)).status).not.toBe(429);
      expect((await workerFetch(acct, subPath, overrides)).status).not.toBe(429);
      const limited = await workerFetch(acct, subPath, overrides);
      expect(limited.status).toBe(429);
      expect(limited.headers.get("Retry-After")).toBe("60");
      expect(((await limited.json()) as { error: string }).error).toMatch(/rate limit/);
      expect(limiter.keys).toEqual([
        `${acct}|198.51.100.7`,
        `${acct}|198.51.100.7`,
        `${acct}|198.51.100.7`,
      ]);
    });

    it(`POST ${subPath}: 503 (fail-closed) when the binding is missing`, async () => {
      const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
      const acct = testAccount(`limits-rl-missing-${subPath}`);
      const resp = await workerFetch(acct, subPath, { [binding]: undefined } as Partial<Env>);
      expect(resp.status).toBe(503);
      errors.mockRestore();
    });

    it(`POST ${subPath}: 503 (fail-closed) when the limiter throws`, async () => {
      const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
      const acct = testAccount(`limits-rl-throws-${subPath}`);
      const throwing: RateLimiter = { limit: () => Promise.reject(new Error("limiter down")) };
      const resp = await workerFetch(acct, subPath, { [binding]: throwing } as Partial<Env>);
      expect(resp.status).toBe(503);
      errors.mockRestore();
    });
  }

  it("a rate-limited submit never reaches the Durable Object", async () => {
    const acct = await freshAccount("rl-no-store");
    const deny: RateLimiter = { limit: () => Promise.resolve({ success: false }) };
    const resp = await workerFetch(
      acct,
      "/requests",
      { RATE_LIMIT_REQUESTS: deny },
      { method: "POST", body: JSON.stringify(envelope("req-rl")) },
    );
    expect(resp.status).toBe(429);
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("keys separate clients and separate accounts independently", async () => {
    const limiter = countingLimiter(1);
    const a = testAccount("limits-rl-key-a");
    const b = testAccount("limits-rl-key-b");
    const overrides = { RATE_LIMIT_REQUESTS: limiter };
    expect((await workerFetch(a, "/requests", overrides, undefined, "192.0.2.1")).status).not.toBe(
      429,
    );
    expect((await workerFetch(a, "/requests", overrides, undefined, "192.0.2.1")).status).toBe(429);
    // A different client IP on the same account, and the same IP on another account, are unaffected.
    expect((await workerFetch(a, "/requests", overrides, undefined, "192.0.2.2")).status).not.toBe(
      429,
    );
    expect((await workerFetch(b, "/requests", overrides, undefined, "192.0.2.1")).status).not.toBe(
      429,
    );
  });

  it("does not consult the limiter for authenticated or read routes", async () => {
    const limiter = countingLimiter(0);
    const acct = testAccount("limits-rl-uncovered");
    const overrides = { RATE_LIMIT_PAIRING: limiter, RATE_LIMIT_REQUESTS: limiter };
    expect((await workerFetch(acct, "/devices", overrides, { method: "GET" })).status).toBe(200);
    expect((await workerFetch(acct, "/requests/x", overrides, { method: "GET" })).status).toBe(404);
    expect(limiter.keys).toEqual([]);
  });

  it("rateLimitedRoute matches only the exact unauthenticated POST routes", () => {
    expect(rateLimitedRoute("POST", "/acct/pairing/start")).toBe("pairing");
    expect(rateLimitedRoute("post", "/acct/pairing/complete")).toBe("pairing");
    expect(rateLimitedRoute("POST", "/acct/requests")).toBe("requests");
    expect(rateLimitedRoute("POST", "/acct/requests/")).toBe("requests");
    expect(rateLimitedRoute("GET", "/acct/requests")).toBeNull();
    expect(rateLimitedRoute("POST", "/acct/requests/r1/retract")).toBeNull();
    expect(rateLimitedRoute("POST", "/acct/pairing/other")).toBeNull();
    expect(rateLimitedRoute("POST", "/acct/actors")).toBeNull();
  });

  function withIp(ip: string): Request {
    return new Request("https://relay.allw.test/a/requests", {
      headers: { "CF-Connecting-IP": ip },
    });
  }

  it("clientIpKey keeps IPv4 as-is", () => {
    expect(clientIpKey(withIp("203.0.113.9"))).toBe("203.0.113.9");
    expect(clientRateLimitKey(withIp("203.0.113.9"))).toBe("ip|203.0.113.9");
  });

  it("clientIpKey reduces IPv6 to its /64", () => {
    expect(clientIpKey(withIp("2001:db8:1:2:3:4:5:6"))).toBe("2001:db8:1:2::/64");
    expect(clientIpKey(withIp("2001:0DB8:0001:0002:aaaa:bbbb:cccc:dddd"))).toBe(
      "2001:db8:1:2::/64",
    );
    expect(clientIpKey(withIp("2001:db8::1"))).toBe("2001:db8:0:0::/64");
    expect(clientIpKey(withIp("::1"))).toBe("0:0:0:0::/64");
    expect(clientIpKey(withIp("fe80::1%eth0"))).toBe("fe80:0:0:0::/64");
    expect(clientIpKey(withIp("64:ff9b::192.0.2.1"))).toBe("64:ff9b:0:0::/64");
  });

  it("two IPv6 addresses in the same /64 share a bucket; a different /64 does not", async () => {
    const a = clientIpKey(withIp("2001:db8:aa:bb::1"));
    const b = clientIpKey(withIp("2001:db8:aa:bb:ffff:ffff:ffff:ffff"));
    const other = clientIpKey(withIp("2001:db8:aa:bc::1"));
    expect(a).toBe(b);
    expect(other).not.toBe(a);

    const limiter = countingLimiter(1);
    const acct = testAccount("limits-rl-v6");
    const overrides = { RATE_LIMIT_REQUESTS: limiter };
    expect(
      (await workerFetch(acct, "/requests", overrides, undefined, "2001:db8:aa:bb::1")).status,
    ).not.toBe(429);
    expect(
      (await workerFetch(acct, "/requests", overrides, undefined, "2001:db8:aa:bb::2")).status,
    ).toBe(429);
    expect(
      (await workerFetch(acct, "/requests", overrides, undefined, "2001:db8:aa:bc::1")).status,
    ).not.toBe(429);
  });

  it("clientIpKey maps IPv4-mapped IPv6 to the IPv4, and garbage to 'unknown'", () => {
    expect(clientIpKey(withIp("::ffff:203.0.113.9"))).toBe("203.0.113.9");
    expect(clientIpKey(withIp("::FFFF:cb00:7109"))).toBe("203.0.113.9");
    for (const bad of [
      "not-an-ip",
      "1.2.3",
      "1.2.3.256",
      "01.2.3.4",
      "1::2::3",
      "1:2:3:4:5:6:7:8:9",
      "12345::1",
      "",
    ]) {
      expect(clientIpKey(withIp(bad))).toBe("unknown");
    }
  });

  it("rateLimitKey uses CF-Connecting-IP, or a shared 'unknown' bucket without it", () => {
    const withIp = new Request("https://relay.allw.test/a/requests", {
      headers: { "CF-Connecting-IP": "203.0.113.9" },
    });
    expect(rateLimitKey("acct-1", withIp)).toBe("acct-1|203.0.113.9");
    expect(rateLimitKey("acct-1", new Request("https://relay.allw.test/a/requests"))).toBe(
      "acct-1|unknown",
    );
  });

  it("enforceRateLimit returns null on success", async () => {
    const allow: RateLimiter = { limit: () => Promise.resolve({ success: true }) };
    expect(await enforceRateLimit(allow, "k")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Terminal rows keep no ciphertext (storage bound)
// ---------------------------------------------------------------------------

describe("terminal transitions blank the stored envelope", () => {
  const BIG = "A".repeat(MAX_CONTEXT_CIPHERTEXT_BYTES);

  it("after the alarm expires a request, its row holds an empty envelope", async () => {
    const acct = await freshAccount("blank-expire");
    expect(
      (
        await submit(
          acct,
          envelope("req-blank-exp", { expires_at: NOW + 1, context_ciphertext: BIG }),
        )
      ).status,
    ).toBe(202);
    expect(JSON.parse((await storedEnvelopes(acct))["req-blank-exp"] ?? "{}")).toMatchObject({
      context_ciphertext: BIG,
    });

    await runAlarmAt(acct, NOW + 1);
    expect(await requestStatuses(acct)).toEqual({ "req-blank-exp": "expired" });
    expect(await storedEnvelopes(acct)).toEqual({ "req-blank-exp": "" });
  });

  it("after a retract, its row holds an empty envelope and status reads still work", async () => {
    const acct = await freshAccount("blank-retract");
    const resp = await submitRaw(
      acct,
      JSON.stringify(envelope("req-blank-ret", { context_ciphertext: BIG })),
    );
    expect(resp.status).toBe(202);
    const { request_auth_token: token } = (await resp.json()) as { request_auth_token: string };
    const auth = { Authorization: `Bearer ${token}` };

    const retract = await SELF.fetch(relayUrl(acct, "/requests/req-blank-ret/retract"), {
      method: "POST",
      headers: auth,
    });
    expect(retract.status).toBe(200);
    expect(await storedEnvelopes(acct)).toEqual({ "req-blank-ret": "" });

    const poll = await SELF.fetch(relayUrl(acct, "/requests/req-blank-ret"), { headers: auth });
    expect(poll.status).toBe(200);
    expect(((await poll.json()) as { status: string }).status).toBe("retracted");
  });

  it("the sweep blanks terminal rows stored before envelopes were blanked", async () => {
    const acct = await freshAccount("blank-legacy");
    await seedRequests(acct, [
      {
        id: "old-resolved",
        status: "resolved",
        created_at: NOW - 2000,
        expires_at: NOW + 60_000,
        terminal_at: NOW - 1000,
      },
      {
        id: "live",
        status: "pending",
        created_at: NOW - 1000,
        expires_at: NOW + 60_000,
        terminal_at: null,
      },
    ]);
    await runAlarmAt(acct, NOW);
    const stored = await storedEnvelopes(acct);
    expect(stored["old-resolved"]).toBe("");
    expect(stored.live).not.toBe("");
  });
});

// ---------------------------------------------------------------------------
// Unbound accounts
// ---------------------------------------------------------------------------

describe("POST /requests on an account with no bound root", () => {
  it("404 unknown account, and stores nothing", async () => {
    const acct = testAccount("limits-unbound");
    await pinRelayClock(acct, NOW);
    const result = await submit(acct, envelope("req-unbound"));
    expect(result.status).toBe(404);
    expect(result.error).toBe("unknown account");
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("accepts the same submit once the root is bound", async () => {
    const acct = testAccount("limits-unbound-then-bound");
    await pinRelayClock(acct, NOW);
    expect((await submit(acct, envelope("req-unbound-1"))).status).toBe(404);
    await bindAccountRoot(acct);
    expect((await submit(acct, envelope("req-unbound-2"))).status).toBe(202);
  });
});

// ---------------------------------------------------------------------------
// Pairing body caps
// ---------------------------------------------------------------------------

describe("pairing body size caps", () => {
  function padTo(json: string, bytes: number): string {
    return json + " ".repeat(bytes - new TextEncoder().encode(json).byteLength);
  }

  async function postRaw(acct: string, subPath: string, body: string, headers = {}) {
    return SELF.fetch(relayUrl(acct, subPath), {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body,
    });
  }

  it("pairing/start: exactly MAX_PAIRING_BODY_BYTES is processed (201)", async () => {
    const acct = testAccount("limits-pair-start-at");
    const body = padTo(JSON.stringify(pairingStartBody(acct)), MAX_PAIRING_BODY_BYTES);
    expect((await postRaw(acct, "/pairing/start", body)).status).toBe(201);
  });

  it("pairing/start: one byte over is 413 and binds nothing", async () => {
    const acct = testAccount("limits-pair-start-over");
    const body = padTo(JSON.stringify(pairingStartBody(acct)), MAX_PAIRING_BODY_BYTES + 1);
    expect((await postRaw(acct, "/pairing/start", body)).status).toBe(413);
    const bound = await runInDurableObject(
      stubFor(acct),
      (instance: AccountRelay) =>
        [...(instance as unknown as { sql: SqlStorage }).sql.exec(`SELECT 1 FROM account_meta`)]
          .length,
    );
    expect(bound).toBe(0);
  });

  async function startedPairing(acct: string): Promise<{ code: string; token: string }> {
    const resp = await postRaw(acct, "/pairing/start", JSON.stringify(pairingStartBody(acct)));
    expect(resp.status).toBe(201);
    const data = (await resp.json()) as { code: string; pairing_auth_token: string };
    return { code: data.code, token: data.pairing_auth_token };
  }

  const DEVICE_PUBKEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

  it("pairing/complete: exactly MAX_PAIRING_BODY_BYTES is processed (201)", async () => {
    const acct = testAccount("limits-pair-complete-at");
    const { code, token } = await startedPairing(acct);
    const body = padTo(JSON.stringify({ code, pubkey: DEVICE_PUBKEY }), MAX_PAIRING_BODY_BYTES);
    const resp = await postRaw(acct, "/pairing/complete", body, {
      Authorization: `Bearer ${token}`,
    });
    expect(resp.status).toBe(201);
  });

  it("pairing/complete: one byte over is 413 and the code stays unused", async () => {
    const acct = testAccount("limits-pair-complete-over");
    const { code, token } = await startedPairing(acct);
    const auth = { Authorization: `Bearer ${token}` };
    const over = padTo(JSON.stringify({ code, pubkey: DEVICE_PUBKEY }), MAX_PAIRING_BODY_BYTES + 1);
    expect((await postRaw(acct, "/pairing/complete", over, auth)).status).toBe(413);
    // The refused body consumed nothing: the same code still completes.
    const ok = await postRaw(
      acct,
      "/pairing/complete",
      JSON.stringify({ code, pubkey: DEVICE_PUBKEY }),
      auth,
    );
    expect(ok.status).toBe(201);
  });
});
