/**
 * Abuse limits on the relay's unauthenticated routes (#248, relay slice).
 *
 * Every limit is probed at its boundary (accepted) and one unit past it (refused), with the relay's
 * clock injected (`pinRelayClock`) so boundaries are exact and fixtures are fixed dates.
 *
 * - Body size: checked before JSON parsing → 413.
 * - `context_ciphertext` size → 413.
 * - Horizon: `expires_at - now > MAX_REQUEST_TTL_MS` → 400 (Worker-var configurable).
 * - `created_at` sanity: an integer, `<= expires_at`, `>= now - MAX_REQUEST_TTL_MS` and
 *   `<= now + MAX_CREATED_AT_SKEW_MS`, else 400.
 * - Over-horizon pending rows are expired by the alarm and then swept after retention.
 * - Every terminal transition blanks the stored envelope, so retained rows hold no ciphertext.
 * - Submits to an account with no bound root → 404 "unknown account".
 * - `pairing/start` and `pairing/complete` bodies are size-capped before parsing → 413.
 *
 * @see ../../../docs/relay-api.md §3 Integrator endpoints (limits) and §1 Conventions
 * @see ../../../docs/relay-deploy.md (MAX_REQUEST_TTL_MS)
 * @see ../../../docs/threat-model.md Residual risks — "Relay denial of service"
 * @see ../../../docs/contract.md §Invariants (fail-closed)
 */

import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, it, expect, vi } from "vitest";
import { AccountRelay } from "../src/index.js";
import {
  DEFAULT_MAX_REQUEST_TTL_MS,
  MAX_CONTEXT_CIPHERTEXT_BYTES,
  MAX_CREATED_AT_SKEW_MS,
  MAX_PAIRING_BODY_BYTES,
  MAX_REQUEST_BODY_BYTES,
  REQUEST_RETENTION_MS,
} from "../src/constants.js";
import { parseMaxRequestTtlMs, readBodyCapped } from "../src/limits.js";
import { pairingStartBody, testAccount, testRequestId as rid } from "./support/accounts.js";
import { bindAccountRoot, pinRelayClock } from "./support/relay-state.js";

// ---------------------------------------------------------------------------
// Fixtures (fixed dates; never `Date.now()` in data)
// ---------------------------------------------------------------------------

/**
 * The injected relay clock (2096-10-02Z). Far enough in the future that the alarms the relay
 * schedules from it (`setAlarm(max(deadline, now))`, on this same clock) are the fixture values and
 * never fire on their own during a test.
 */
const NOW = 4_000_000_000_000;
/** A fixed envelope `created_at`: one second before {@link NOW}, inside every created_at bound. */
const CREATED_AT = NOW - 1000;
/** The hooks' `MAX_TIMEOUT_MS` (`packages/hook/src/lib/config.ts`): the horizon must cover it. */
const HOOK_MAX_TIMEOUT_MS = 420_000;
const SHORT_CIPHERTEXT = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE";

function envelope(
  id: string,
  overrides: Partial<{ created_at: number; expires_at: number; context_ciphertext: string }> = {},
): Record<string, unknown> {
  return {
    v: 1,
    id,
    created_at: overrides.created_at ?? CREATED_AT,
    expires_at: overrides.expires_at ?? NOW + 60_000,
    approver: "acct-approver-limits",
    context_ciphertext: overrides.context_ciphertext ?? SHORT_CIPHERTEXT,
  };
}

function relayUrl(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

async function submitRaw(accountId: string, body: BodyInit): Promise<Response> {
  return exports.default.fetch(relayUrl(accountId, "/requests"), {
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
  const data = await resp.json<{ error?: string }>();
  return { status: resp.status, error: data.error };
}

/** A fresh account with its root bound and its relay clock pinned to {@link NOW}. */
async function freshAccount(name: string): Promise<string> {
  const acct = testAccount(`limits-${name}`);
  await bindAccountRoot(acct);
  await pinRelayClock(acct, NOW);
  return acct;
}

function stubFor(accountId: string): DurableObjectStub<AccountRelay> {
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
  await runInDurableObject(stubFor(accountId), (relay: AccountRelay) => {
    for (const row of rows) {
      relay["sql"].exec(
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

async function requestStatuses(accountId: string): Promise<Record<string, string>> {
  return runInDurableObject(stubFor(accountId), (relay: AccountRelay) => {
    const out: Record<string, string> = {};
    for (const row of relay["sql"].exec<{ request_id: string; status: string }>(
      `SELECT request_id, status FROM request`,
    )) {
      out[row.request_id] = row.status;
    }
    return out;
  });
}

async function storedEnvelopes(accountId: string): Promise<Record<string, string>> {
  return runInDurableObject(stubFor(accountId), (relay: AccountRelay) => {
    const out: Record<string, string> = {};
    for (const row of relay["sql"].exec<{ request_id: string; envelope: string }>(
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
    return instance["ctx"].storage.getAlarm();
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
    const body = paddedBody(rid("req-body-at"), MAX_REQUEST_BODY_BYTES);
    expect(new TextEncoder().encode(body).byteLength).toBe(MAX_REQUEST_BODY_BYTES);
    const resp = await submitRaw(acct, body);
    expect(resp.status).toBe(202);
  });

  it("413 for a body one byte over MAX_REQUEST_BODY_BYTES, and stores nothing", async () => {
    const acct = await freshAccount("body-over");
    const resp = await submitRaw(
      acct,
      paddedBody(rid("req-body-over"), MAX_REQUEST_BODY_BYTES + 1),
    );
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

  it("readBodyCapped: a digit-only Content-Length past the safe-integer range is too_large", async () => {
    for (const declared of [
      String(Number.MAX_SAFE_INTEGER), // the largest safe integer: a real size, over the cap
      String(Number.MAX_SAFE_INTEGER + 1), // one past it
      "99999999999999999999",
    ]) {
      const pull = vi.fn();
      const request = new Request("https://relay.allw.test/a/requests", {
        method: "POST",
        headers: { "Content-Length": declared },
        body: new ReadableStream({ pull }, { highWaterMark: 0 }),
      });
      expect(await readBodyCapped(request, MAX_REQUEST_BODY_BYTES), declared).toEqual({
        kind: "too_large",
      });
      expect(pull).not.toHaveBeenCalled();
    }
  });

  it("413 through the Worker for a Content-Length past the safe-integer range", async () => {
    const acct = await freshAccount("body-length-overflow");
    const resp = await exports.default.fetch(relayUrl(acct, "/requests"), {
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": "99999999999999999999" },
      body: "{}",
    });
    expect(resp.status).toBe(413);
    expect(await requestStatuses(acct)).toEqual({});
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
    const cancel = vi.fn();
    const malformed = new Request("https://relay.allw.test/a/requests", {
      method: "POST",
      headers: { "Content-Length": "12abc" },
      body: new ReadableStream({ cancel }),
    });
    expect(await readBodyCapped(malformed, 1024)).toEqual({ kind: "unreadable" });
    // The unread body is released, as for an over-cap length.
    expect(cancel).toHaveBeenCalled();
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
      envelope(rid("req-ct-at"), { context_ciphertext: "A".repeat(MAX_CONTEXT_CIPHERTEXT_BYTES) }),
    );
    expect(result.status).toBe(202);
  });

  it("413 for a ciphertext one byte over the cap", async () => {
    const acct = await freshAccount("ct-over");
    const result = await submit(
      acct,
      envelope(rid("req-ct-over"), {
        context_ciphertext: "A".repeat(MAX_CONTEXT_CIPHERTEXT_BYTES + 1),
      }),
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
    const result = await submit(
      acct,
      envelope(rid("req-ct-utf8"), { context_ciphertext: ciphertext }),
    );
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
      envelope(rid("req-ttl-at"), { expires_at: NOW + DEFAULT_MAX_REQUEST_TTL_MS }),
    );
    expect(result.status).toBe(202);
  });

  it("400 for expires_at one millisecond past the horizon, and stores nothing", async () => {
    const acct = await freshAccount("ttl-over");
    const result = await submit(
      acct,
      envelope(rid("req-ttl-over"), { expires_at: NOW + DEFAULT_MAX_REQUEST_TTL_MS + 1 }),
    );
    expect(result.status).toBe(400);
    expect(result.error).toMatch(/expires_at/);
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("accepts a hook-length request (420 s)", async () => {
    const acct = await freshAccount("ttl-hook");
    const result = await submit(
      acct,
      envelope(rid("req-ttl-hook"), { expires_at: NOW + HOOK_MAX_TIMEOUT_MS }),
    );
    expect(result.status).toBe(202);
  });

  it("accepts an integer expires_at; 400 for a fractional one, and stores nothing", async () => {
    const acct = await freshAccount("ttl-int");
    expect(
      (await submit(acct, envelope(rid("req-ttl-int"), { expires_at: NOW + 60_000 }))).status,
    ).toBe(202);
    const fractional = await submit(
      acct,
      envelope(rid("req-ttl-frac"), { expires_at: NOW + 60_000.5 }),
    );
    expect(fractional.status).toBe(400);
    expect(fractional.error).toBe("'expires_at' must be an integer (i64 ms)");
    expect((await requestStatuses(acct))[rid("req-ttl-frac")]).toBeUndefined();
  });

  it("still refuses expires_at equal to now (already expired) and accepts now + 1", async () => {
    const acct = await freshAccount("ttl-now");
    expect((await submit(acct, envelope(rid("req-ttl-now"), { expires_at: NOW }))).status).toBe(
      400,
    );
    expect(
      (await submit(acct, envelope(rid("req-ttl-now1"), { expires_at: NOW + 1 }))).status,
    ).toBe(202);
  });

  it("honors a configured horizon at its boundary and one past it", async () => {
    const acct = await freshAccount("ttl-config");
    const configured = parseMaxRequestTtlMs("600000");
    await runInDurableObject(stubFor(acct), (instance: AccountRelay) => {
      instance["maxRequestTtlMs"] = configured;
    });
    expect(
      (await submit(acct, envelope(rid("req-cfg-at"), { expires_at: NOW + configured }))).status,
    ).toBe(202);
    expect(
      (await submit(acct, envelope(rid("req-cfg-over"), { expires_at: NOW + configured + 1 })))
        .status,
    ).toBe(400);
  });

  it("the Durable Object reads MAX_REQUEST_TTL_MS from its env", async () => {
    // Construct directly over the runtime's own state (the base class needs a real one) so the
    // env → horizon wiring is checked end to end.
    await runInDurableObject(
      stubFor("acct-ttl-env"),
      (_instance: AccountRelay, state: DurableObjectState) => {
        const relay = new AccountRelay(state, { ...env, MAX_REQUEST_TTL_MS: "123456" });
        expect(relay["maxRequestTtlMs"]).toBe(123_456);
        // The var unset (omitted, not `undefined`: `exactOptionalPropertyTypes`) falls back to the default.
        const { MAX_REQUEST_TTL_MS: _unset, ...envWithoutTtl } = { ...env };
        const fallback = new AccountRelay(state, envWithoutTtl);
        expect(fallback["maxRequestTtlMs"]).toBe(DEFAULT_MAX_REQUEST_TTL_MS);
      },
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
// created_at sanity bound (relay-api §3)
// ---------------------------------------------------------------------------

describe("POST /requests created_at bound", () => {
  /** Submit with `created_at` (and optionally `expires_at`) on a fresh account. */
  async function submitCreatedAt(
    name: string,
    createdAt: number,
    expiresAt = NOW + 60_000,
  ): Promise<{ status: number; error: string | undefined; stored: Record<string, string> }> {
    const acct = await freshAccount(`created-${name}`);
    const result = await submit(
      acct,
      envelope(rid(`req-created-${name}`), { created_at: createdAt, expires_at: expiresAt }),
    );
    return { ...result, stored: await requestStatuses(acct) };
  }

  it("allows 60 s of clock skew ahead of the relay", () => {
    expect(MAX_CREATED_AT_SKEW_MS).toBe(60_000);
  });

  it("accepts an integer created_at; 400 for a fractional one, and stores nothing", async () => {
    expect((await submitCreatedAt("int", NOW - 1000)).status).toBe(202);
    const fractional = await submitCreatedAt("frac", NOW - 999.5);
    expect(fractional.status).toBe(400);
    expect(fractional.error).toBe("'created_at' must be an integer (i64 ms)");
    expect(fractional.stored).toEqual({});
  });

  it("accepts created_at equal to expires_at; 400 one millisecond after it", async () => {
    const expiresAt = NOW + 30_000;
    expect((await submitCreatedAt("eq-exp", expiresAt, expiresAt)).status).toBe(202);
    const after = await submitCreatedAt("after-exp", expiresAt + 1, expiresAt);
    expect(after.status).toBe(400);
    expect(after.error).toBe("'created_at' is after 'expires_at'");
    expect(after.stored).toEqual({});
  });

  it("accepts created_at exactly the horizon in the past; 400 one millisecond earlier", async () => {
    expect((await submitCreatedAt("past-at", NOW - DEFAULT_MAX_REQUEST_TTL_MS)).status).toBe(202);
    const older = await submitCreatedAt("past-over", NOW - DEFAULT_MAX_REQUEST_TTL_MS - 1);
    expect(older.status).toBe(400);
    expect(older.error).toBe(
      `'created_at' is more than ${String(DEFAULT_MAX_REQUEST_TTL_MS)} ms in the past`,
    );
    expect(older.stored).toEqual({});
  });

  it("accepts created_at exactly the skew ahead of the relay; 400 one millisecond further", async () => {
    const expiresAt = NOW + MAX_CREATED_AT_SKEW_MS + 1000;
    expect((await submitCreatedAt("skew-at", NOW + MAX_CREATED_AT_SKEW_MS, expiresAt)).status).toBe(
      202,
    );
    const ahead = await submitCreatedAt("skew-over", NOW + MAX_CREATED_AT_SKEW_MS + 1, expiresAt);
    expect(ahead.status).toBe(400);
    expect(ahead.error).toBe(
      `'created_at' is more than ${String(MAX_CREATED_AT_SKEW_MS)} ms in the future`,
    );
    expect(ahead.stored).toEqual({});
  });

  it("the past bound follows a configured horizon: at it accepted, one past it 400", async () => {
    const acct = await freshAccount("created-config");
    const configured = parseMaxRequestTtlMs("600000");
    await runInDurableObject(stubFor(acct), (instance: AccountRelay) => {
      instance["maxRequestTtlMs"] = configured;
    });
    const at = envelope(rid("req-created-cfg-at"), { created_at: NOW - configured });
    expect((await submit(acct, at)).status).toBe(202);
    const over = envelope(rid("req-created-cfg-over"), { created_at: NOW - configured - 1 });
    expect((await submit(acct, over)).status).toBe(400);
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
    expect(
      (await submit(acct, envelope(rid("req-arm"), { expires_at: NOW + 60_000 }))).status,
    ).toBe(202);
    const alarm = await runInDurableObject(stubFor(acct), (instance: AccountRelay) =>
      instance["ctx"].storage.getAlarm(),
    );
    expect(alarm).toBe(NOW + 60_000);
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
          envelope(rid("req-blank-exp"), { expires_at: NOW + 1, context_ciphertext: BIG }),
        )
      ).status,
    ).toBe(202);
    expect(JSON.parse((await storedEnvelopes(acct))[rid("req-blank-exp")] ?? "{}")).toMatchObject({
      context_ciphertext: BIG,
    });

    await runAlarmAt(acct, NOW + 1);
    expect(await requestStatuses(acct)).toEqual({ [rid("req-blank-exp")]: "expired" });
    expect(await storedEnvelopes(acct)).toEqual({ [rid("req-blank-exp")]: "" });
  });

  it("after a retract, its row holds an empty envelope and status reads still work", async () => {
    const acct = await freshAccount("blank-retract");
    const resp = await submitRaw(
      acct,
      JSON.stringify(envelope(rid("req-blank-ret"), { context_ciphertext: BIG })),
    );
    expect(resp.status).toBe(202);
    const { request_auth_token: token } = await resp.json<{ request_auth_token: string }>();
    const auth = { Authorization: `Bearer ${token}` };

    const retract = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-blank-ret")}/retract`),
      {
        method: "POST",
        headers: auth,
      },
    );
    expect(retract.status).toBe(200);
    expect(await storedEnvelopes(acct)).toEqual({ [rid("req-blank-ret")]: "" });

    const poll = await exports.default.fetch(relayUrl(acct, `/requests/${rid("req-blank-ret")}`), {
      headers: auth,
    });
    expect(poll.status).toBe(200);
    expect((await poll.json<{ status: string }>()).status).toBe("retracted");
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
    const result = await submit(acct, envelope(rid("req-unbound")));
    expect(result.status).toBe(404);
    expect(result.error).toBe("unknown account");
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("accepts the same submit once the root is bound", async () => {
    const acct = testAccount("limits-unbound-then-bound");
    await pinRelayClock(acct, NOW);
    expect((await submit(acct, envelope(rid("req-unbound-1")))).status).toBe(404);
    await bindAccountRoot(acct);
    expect((await submit(acct, envelope(rid("req-unbound-2")))).status).toBe(202);
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
    return exports.default.fetch(relayUrl(acct, subPath), {
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
      (instance: AccountRelay) => [...instance["sql"].exec(`SELECT 1 FROM account_meta`)].length,
    );
    expect(bound).toBe(0);
  });

  async function startedPairing(acct: string): Promise<{ code: string; token: string }> {
    const resp = await postRaw(acct, "/pairing/start", JSON.stringify(pairingStartBody(acct)));
    expect(resp.status).toBe(201);
    const data = await resp.json<{ code: string; pairing_auth_token: string }>();
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

// ---------------------------------------------------------------------------
// Request id syntax
// ---------------------------------------------------------------------------

describe("POST /requests id must be a canonical UUID", () => {
  it("accepts a lowercase canonical UUID", async () => {
    const acct = await freshAccount("id-valid");
    expect((await submit(acct, envelope("3f2b8c1e-9a4d-4e7b-8c2f-1a2b3c4d5e6f"))).status).toBe(202);
  });

  it("400 for an uppercase or mixed-case UUID, never normalized, and stores nothing", async () => {
    // One UUID gets one identity: the device binds to the id exactly as sent.
    const acct = await freshAccount("id-upper");
    for (const bad of [
      "3F2B8C1E-9A4D-4E7B-8C2F-1A2B3C4D5E70",
      "3f2b8c1e-9a4d-4e7b-8c2f-1a2b3c4d5e7F",
    ]) {
      const result = await submit(acct, envelope(bad));
      expect(result.status, bad).toBe(400);
      expect(result.error).toBe("'id' must be a lowercase canonical UUID (8-4-4-4-12 hex)");
    }
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("400 for an over-long id, and stores nothing", async () => {
    const acct = await freshAccount("id-long");
    const result = await submit(
      acct,
      envelope(`3f2b8c1e-9a4d-4e7b-8c2f-1a2b3c4d5e6f${"0".repeat(4096)}`),
    );
    expect(result.status).toBe(400);
    expect(result.error).toMatch(/UUID/);
    expect(await requestStatuses(acct)).toEqual({});
  });

  it("400 for ids that are not canonical UUID syntax", async () => {
    const acct = await freshAccount("id-bad");
    for (const bad of [
      "req-not-a-uuid",
      "3f2b8c1e9a4d4e7b8c2f1a2b3c4d5e6f", // no hyphens
      "{3f2b8c1e-9a4d-4e7b-8c2f-1a2b3c4d5e6f}", // braces
      "urn:uuid:3f2b8c1e-9a4d-4e7b-8c2f-1a2b3c4d5e6f",
      "3f2b8c1e-9a4d-4e7b-8c2f-1a2b3c4d5e6", // one hex digit short
      "3f2b8c1e-9a4d-4e7b-8c2f-1a2b3c4d5e6g", // non-hex
      " 3f2b8c1e-9a4d-4e7b-8c2f-1a2b3c4d5e6f",
    ]) {
      expect((await submit(acct, envelope(bad))).status, bad).toBe(400);
    }
    expect(await requestStatuses(acct)).toEqual({});
  });
});
