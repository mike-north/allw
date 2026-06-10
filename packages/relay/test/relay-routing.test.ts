/**
 * Tests for `AccountRelay` ciphertext routing + verdict relay (issue #11).
 *
 * Exercised inside a real `workerd` runtime via `@cloudflare/vitest-pool-workers`, so the
 * WebSocket hibernation API, SQLite storage, and full HTTP surface are the real implementations.
 *
 * # What this covers (acceptance criteria, issue #11)
 * - End-to-end: integrator submit → device receives ciphertext → device returns verdict →
 *   integrator receives it (both by poll and by live WebSocket push).
 * - Device-online (pushed via fan-out) AND device-offline (queued, delivered on reconnect).
 * - Cross-device retraction + first-verdict-wins dedupe.
 * - Zero-knowledge: the relay stores ONLY the opaque ciphertext envelope + the signed verdict;
 *   never plaintext `ApprovalContext` fields.
 *
 * # Contract references
 * @see ../../../docs/contract.md  (§Messages, §Lifecycle, §Transport)
 * @see ../../../docs/architecture.md  (§Cross-device notification coordination)
 *
 * # Test isolation
 * Each test uses a distinct account id so `idFromName(accountId)` yields a fresh DO instance.
 */

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { AccountRelay } from "../src/index.js";

// ---------------------------------------------------------------------------
// Fixtures (deterministic; never `Date.now()` in data — see fixed-dates rule)
// ---------------------------------------------------------------------------

/** A 32-byte base64url-unpadded device key (32 × 0x00). Matches the registry's pubkey shape. */
const DEVICE_PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/** Far-future expiry (2100-01-01Z, ms) — deterministic AND always > the relay's real `Date.now()`. */
const FUTURE_EXPIRES_AT = 4102444800000;
/** A past expiry (1970-01-01T00:00:01Z, ms) — always < the relay's real `Date.now()` (fail-closed tests). */
const PAST_EXPIRES_AT = 1000;
/** A fixed creation timestamp (2023-11-14Z, ms). */
const CREATED_AT = 1700000000000;

/**
 * Build an ApprovalRequest envelope. By the contract this is the ONLY relay-visible structure:
 * routing/lifecycle fields wrapping an opaque `context_ciphertext` (a JWE). No plaintext context.
 */
function makeEnvelope(
  id: string,
  overrides: Partial<{
    context_ciphertext: string;
    expires_at: number;
  }> = {},
): Record<string, unknown> {
  return {
    v: 1,
    id,
    created_at: CREATED_AT,
    expires_at: overrides.expires_at ?? FUTURE_EXPIRES_AT,
    approver: "acct-approver-routing-id",
    // Opaque to the relay — a stand-in for a compact JWE string. The relay never parses it.
    context_ciphertext: overrides.context_ciphertext ?? "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.FAKE.JWE",
  };
}

/** A stand-in signed Verdict — opaque to the relay; `sig` is a stand-in compact JWS string. */
function makeVerdict(requestId: string, decision = "approved"): Record<string, unknown> {
  return {
    v: 1,
    request_id: requestId,
    request_hash: "ZmFrZS1yZXF1ZXN0LWhhc2gtMzItYnl0ZXMtYjY0dXJsLXBhZA",
    decision,
    decided_at: CREATED_AT,
    approver: { account_id: "acct", device_id: "dev-1" },
    sig: "eyJhbGciOiJFZERTQSJ9..FAKE_JWS_SIGNATURE",
  };
}

function relayUrl(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

async function post<T>(
  accountId: string,
  subPath: string,
  body: unknown,
): Promise<{ status: number; data: T }> {
  const resp = await SELF.fetch(relayUrl(accountId, subPath), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = (await resp.json()) as T;
  return { status: resp.status, data };
}

async function get<T>(accountId: string, subPath: string): Promise<{ status: number; data: T }> {
  const resp = await SELF.fetch(relayUrl(accountId, subPath), { method: "GET" });
  const data = (await resp.json()) as T;
  return { status: resp.status, data };
}

/** Enroll a device via the pairing flow and return its device_id. */
async function enrollDevice(accountId: string, pubkey = DEVICE_PUBKEY): Promise<string> {
  const start = await post<{ code: string }>(accountId, "/pairing/start", {});
  const complete = await post<{ device_id: string }>(accountId, "/pairing/complete", {
    code: start.data.code,
    pubkey,
  });
  return complete.data.device_id;
}

// ---------------------------------------------------------------------------
// WebSocket test client
// ---------------------------------------------------------------------------

interface WsMessage {
  type: string;
  request_id?: string;
  envelope?: Record<string, unknown>;
  verdict?: Record<string, unknown>;
  status?: string;
  error?: string;
}

interface WsClient {
  /** Resolve the next inbound JSON message (or reject after `timeoutMs`). */
  next(timeoutMs?: number): Promise<WsMessage>;
  send(obj: unknown): void;
  raw: WebSocket;
}

/**
 * Open a WebSocket to the relay. The message listener is attached BEFORE `accept()` so that
 * server pushes emitted during the upgrade (offline-queue flush, immediate verdict) are not missed.
 * Returns the 101 client wrapped in a queue-backed reader, or throws on a non-101 response.
 */
async function connectWs(accountId: string, subPath: string): Promise<WsClient> {
  const resp = await SELF.fetch(relayUrl(accountId, subPath), {
    headers: { Upgrade: "websocket" },
  });
  if (resp.status !== 101 || !resp.webSocket) {
    throw new Error(`expected 101 WebSocket upgrade, got ${resp.status}`);
  }
  const ws = resp.webSocket;

  const queue: WsMessage[] = [];
  const waiters: Array<(m: WsMessage) => void> = [];
  ws.addEventListener("message", (event: MessageEvent) => {
    const raw =
      typeof event.data === "string"
        ? event.data
        : new TextDecoder().decode(event.data as ArrayBuffer);
    const msg = JSON.parse(raw) as WsMessage;
    const waiter = waiters.shift();
    if (waiter) waiter(msg);
    else queue.push(msg);
  });

  ws.accept();

  return {
    next(timeoutMs = 2000): Promise<WsMessage> {
      const queued = queue.shift();
      if (queued) return Promise.resolve(queued);
      return new Promise<WsMessage>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("WebSocket message timeout")), timeoutMs);
        waiters.push((m) => {
          clearTimeout(timer);
          resolve(m);
        });
      });
    },
    send(obj: unknown): void {
      ws.send(JSON.stringify(obj));
    },
    raw: ws,
  };
}

// ---------------------------------------------------------------------------
// End-to-end: online device
// ---------------------------------------------------------------------------

describe("AccountRelay — routing (device online)", () => {
  it("E2E: submit → device receives ciphertext → verdict → integrator polls resolved", async () => {
    const acct = "acct-e2e-online";
    await enrollDevice(acct);

    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);

    // Integrator submits the ciphertext envelope.
    const envelope = makeEnvelope("req-online-1");
    const submit = await post<{ request_id: string; status: string; delivered_to: number }>(
      acct,
      "/requests",
      envelope,
    );
    expect(submit.status).toBe(202);
    expect(submit.data.status).toBe("pending");
    expect(submit.data.delivered_to).toBe(1); // fanned out to the one online device

    // Device receives the ciphertext push.
    const pushed = await device.next();
    expect(pushed.type).toBe("request");
    expect(pushed.request_id).toBe("req-online-1");
    expect(pushed.envelope?.context_ciphertext).toBe(envelope.context_ciphertext);

    // Device returns a signed verdict over the same socket.
    const verdict = makeVerdict("req-online-1");
    device.send({ type: "verdict", request_id: "req-online-1", verdict });
    const ack = await device.next();
    expect(ack.type).toBe("ack");
    expect(ack.status).toBe("resolved");

    // Integrator polls and receives the verdict.
    const polled = await get<{ status: string; verdict: Record<string, unknown> }>(
      acct,
      "/requests/req-online-1",
    );
    expect(polled.status).toBe(200);
    expect(polled.data.status).toBe("resolved");
    expect(polled.data.verdict).toEqual(verdict);
  });

  it("pushes the verdict to a live integrator waiting on …/wait", async () => {
    const acct = "acct-e2e-wait";
    await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);

    await post(acct, "/requests", makeEnvelope("req-wait-1"));
    await device.next(); // drain the request push

    // Integrator opens a wait socket BEFORE the device decides.
    const integrator = await connectWs(acct, "/requests/req-wait-1/wait");

    const verdict = makeVerdict("req-wait-1", "denied");
    device.send({ type: "verdict", request_id: "req-wait-1", verdict });

    const pushed = await integrator.next();
    expect(pushed.type).toBe("verdict");
    expect(pushed.request_id).toBe("req-wait-1");
    expect(pushed.verdict).toEqual(verdict);
  });

  it("delivers immediately when …/wait opens after the verdict already landed", async () => {
    const acct = "acct-wait-late";
    await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);

    await post(acct, "/requests", makeEnvelope("req-late-1"));
    await device.next();
    const verdict = makeVerdict("req-late-1");
    device.send({ type: "verdict", request_id: "req-late-1", verdict });
    await device.next(); // ack

    // Now connect the waiter — it should receive the persisted verdict at once.
    const integrator = await connectWs(acct, "/requests/req-late-1/wait");
    const pushed = await integrator.next();
    expect(pushed.type).toBe("verdict");
    expect(pushed.verdict).toEqual(verdict);
  });
});

// ---------------------------------------------------------------------------
// Offline queue
// ---------------------------------------------------------------------------

describe("AccountRelay — routing (device offline)", () => {
  it("queues a request submitted while offline and flushes it on reconnect", async () => {
    const acct = "acct-offline-queue";
    await enrollDevice(acct);

    // Submit with NO device connected → delivered_to 0, request stays pending.
    const submit = await post<{ delivered_to: number; status: string }>(
      acct,
      "/requests",
      makeEnvelope("req-offline-1"),
    );
    expect(submit.data.delivered_to).toBe(0);
    expect(submit.data.status).toBe("pending");

    // Device comes online → receives the queued request on connect.
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);
    const flushed = await device.next();
    expect(flushed.type).toBe("request");
    expect(flushed.request_id).toBe("req-offline-1");
  });

  it("flushes only still-pending requests (already-resolved ones are not re-delivered)", async () => {
    const acct = "acct-offline-mixed";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);

    // Two requests submitted while offline.
    await post(acct, "/requests", makeEnvelope("req-mixed-1"));
    await post(acct, "/requests", makeEnvelope("req-mixed-2"));

    // First device resolves req-mixed-1.
    const d1 = await connectWs(acct, `/devices/${deviceId}/connect`);
    const first = await d1.next();
    const second = await d1.next();
    const ids = [first.request_id, second.request_id].sort();
    expect(ids).toEqual(["req-mixed-1", "req-mixed-2"]);
    d1.send({ type: "verdict", request_id: "req-mixed-1", verdict: makeVerdict("req-mixed-1") });
    await d1.next(); // ack

    // A second device connecting later should receive ONLY the still-pending req-mixed-2.
    const d2 = await connectWs(acct, `/devices/${deviceId}/connect`);
    const flushed = await d2.next();
    expect(flushed.request_id).toBe("req-mixed-2");
    // No further pending request should arrive.
    await expect(d2.next(500)).rejects.toThrow(/timeout/);
  });
});

// ---------------------------------------------------------------------------
// Cross-device retraction + dedupe
// ---------------------------------------------------------------------------

describe("AccountRelay — cross-device coordination", () => {
  it("retracts the request from other devices once one resolves it", async () => {
    const acct = "acct-retract";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);

    // Two presence sockets for the account (e.g. macOS + iPhone).
    const dA = await connectWs(acct, `/devices/${deviceId}/connect`);
    const dB = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope("req-retract-1"));
    // Both receive the request push.
    expect((await dA.next()).type).toBe("request");
    expect((await dB.next()).type).toBe("request");

    // Device A resolves.
    dA.send({
      type: "verdict",
      request_id: "req-retract-1",
      verdict: makeVerdict("req-retract-1"),
    });

    // Device B must receive a retract for that request.
    const retract = await dB.next();
    expect(retract.type).toBe("retract");
    expect(retract.request_id).toBe("req-retract-1");
  });

  it("first verdict wins: a second verdict is ignored (dedupe)", async () => {
    const acct = "acct-dedupe";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope("req-dedupe-1"));
    await device.next();

    const winning = makeVerdict("req-dedupe-1", "approved");
    device.send({ type: "verdict", request_id: "req-dedupe-1", verdict: winning });
    const ack1 = await device.next();
    expect(ack1.status).toBe("resolved");

    // A second, conflicting verdict for the same request is acknowledged but does not overwrite.
    device.send({
      type: "verdict",
      request_id: "req-dedupe-1",
      verdict: makeVerdict("req-dedupe-1", "denied"),
    });
    const ack2 = await device.next();
    expect(ack2.type).toBe("ack");
    expect(ack2.status).toBe("already_resolved");

    const polled = await get<{ verdict: Record<string, unknown> }>(acct, "/requests/req-dedupe-1");
    expect(polled.data.verdict).toEqual(winning); // the first decision stands
  });
});

// ---------------------------------------------------------------------------
// Zero-knowledge invariant
// ---------------------------------------------------------------------------

describe("AccountRelay — zero-knowledge (routing)", () => {
  it("stores ONLY the opaque ciphertext envelope and the signed verdict — no plaintext", async () => {
    const acct = "acct-zk-routing";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    const envelope = makeEnvelope("req-zk-1");
    await post(acct, "/requests", envelope);
    await device.next();
    const verdict = makeVerdict("req-zk-1");
    device.send({ type: "verdict", request_id: "req-zk-1", verdict });
    await device.next();

    // Inspect the DO's SQLite directly.
    const id = env.ACCOUNT.idFromName(acct);
    const stub = env.ACCOUNT.get(id);
    const stored = await runInDurableObject(stub, (instance: AccountRelay) => {
      const relay = instance as unknown as { sql: SqlStorage };
      const reqRows = [
        ...relay.sql.exec<{ envelope: string; status: string }>(
          `SELECT envelope, status FROM request WHERE request_id = 'req-zk-1'`,
        ),
      ];
      const verdictRows = [
        ...relay.sql.exec<{ verdict: string }>(
          `SELECT verdict FROM verdict WHERE request_id = 'req-zk-1'`,
        ),
      ];
      return { reqRows, verdictRows };
    });

    // The stored envelope is exactly what was submitted — routing/lifecycle + opaque ciphertext.
    const storedEnvelope = JSON.parse(stored.reqRows[0]?.envelope ?? "{}") as Record<
      string,
      unknown
    >;
    expect(storedEnvelope).toEqual(envelope);
    // It carries the ciphertext but NONE of the plaintext ApprovalContext fields.
    expect(storedEnvelope.context_ciphertext).toBe(envelope.context_ciphertext);
    for (const plaintextField of [
      "action",
      "summary",
      "actor",
      "risk",
      "reversible",
      "constraints",
    ]) {
      expect(storedEnvelope[plaintextField]).toBeUndefined();
    }
    // The verdict round-trips byte-for-byte (relay holds no key that could forge it).
    const storedVerdict = JSON.parse(stored.verdictRows[0]?.verdict ?? "{}") as Record<
      string,
      unknown
    >;
    expect(storedVerdict).toEqual(verdict);
  });
});

// ---------------------------------------------------------------------------
// Authenticity: only device sockets may resolve a request
// ---------------------------------------------------------------------------

describe("AccountRelay — verdict authenticity", () => {
  it("rejects a verdict sent from a non-device (integrator …/wait) socket", async () => {
    const acct = "acct-sec-verdict";
    await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);

    await post(acct, "/requests", makeEnvelope("req-sec-1"));
    await device.next(); // drain the request push to the legitimate device

    // A non-device client opens the integrator wait socket and tries to forge a verdict.
    const integrator = await connectWs(acct, "/requests/req-sec-1/wait");
    integrator.send({
      type: "verdict",
      request_id: "req-sec-1",
      verdict: makeVerdict("req-sec-1"),
    });

    const resp = await integrator.next();
    expect(resp.type).toBe("error");

    // The request must remain pending — the forged verdict did NOT resolve it.
    const polled = await get<{ status: string }>(acct, "/requests/req-sec-1");
    expect(polled.data.status).toBe("pending");
  });
});

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

describe("AccountRelay — routing negative paths", () => {
  it("rejects a submit missing context_ciphertext (400)", async () => {
    const acct = "acct-neg-noct";
    const body = makeEnvelope("req-noct");
    delete body.context_ciphertext;
    const { status } = await post(acct, "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects an envelope carrying an unexpected key (zero-knowledge guard) (400)", async () => {
    // A stray plaintext-looking field must be refused so it can never be persisted by the relay.
    const body = { ...makeEnvelope("req-extra"), summary: "rm -rf / — please approve" };
    const { status } = await post("acct-neg-extra", "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit missing approver (400)", async () => {
    const body = makeEnvelope("req-noappr");
    delete body.approver;
    const { status } = await post("acct-neg-noappr", "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit missing v (400)", async () => {
    const body = makeEnvelope("req-nov");
    delete body.v;
    const { status } = await post("acct-neg-nov", "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit missing id (400)", async () => {
    const body = makeEnvelope("ignored");
    delete body.id;
    const { status } = await post("acct-neg-noid", "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit missing expires_at (400)", async () => {
    const body = makeEnvelope("req-noexp");
    delete body.expires_at;
    const { status } = await post("acct-neg-noexp", "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit whose expires_at is already in the past (400)", async () => {
    const { status } = await post(
      "acct-neg-expired",
      "/requests",
      makeEnvelope("req-expired", { expires_at: 1 }),
    );
    expect(status).toBe(400);
  });

  it("rejects a duplicate request id (409)", async () => {
    const acct = "acct-neg-dup";
    const first = await post(acct, "/requests", makeEnvelope("req-dup"));
    expect(first.status).toBe(202);
    const second = await post(acct, "/requests", makeEnvelope("req-dup"));
    expect(second.status).toBe(409);
  });

  it("returns 404 polling an unknown request", async () => {
    const { status } = await get("acct-neg-poll", "/requests/does-not-exist");
    expect(status).toBe(404);
  });

  it("returns 404 connecting a WebSocket for an unenrolled device", async () => {
    const resp = await SELF.fetch(relayUrl("acct-neg-wsdev", "/devices/ghost/connect"), {
      headers: { Upgrade: "websocket" },
    });
    expect(resp.status).toBe(404);
  });

  it("returns 426 hitting a WebSocket route without an upgrade header", async () => {
    const acct = "acct-neg-noupgrade";
    const deviceId = await enrollDevice(acct);
    const connectResp = await SELF.fetch(relayUrl(acct, `/devices/${deviceId}/connect`), {
      method: "GET",
    });
    expect(connectResp.status).toBe(426);

    const waitResp = await SELF.fetch(relayUrl(acct, "/requests/whatever/wait"), { method: "GET" });
    expect(waitResp.status).toBe(426);
  });

  it("sends an error over the socket for a verdict on an unknown request", async () => {
    const acct = "acct-neg-badverdict";
    const deviceId = await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    device.send({ type: "verdict", request_id: "no-such-request", verdict: makeVerdict("x") });
    const err = await device.next();
    expect(err.type).toBe("error");
    expect(typeof err.error).toBe("string");
  });

  it("returns 404 opening …/wait for an unknown request", async () => {
    const resp = await SELF.fetch(relayUrl("acct-neg-waitunknown", "/requests/nope/wait"), {
      headers: { Upgrade: "websocket" },
    });
    expect(resp.status).toBe(404);
  });

  it("rejects a degenerate (non-object) verdict value", async () => {
    const acct = "acct-neg-scalarverdict";
    const deviceId = await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    await post(acct, "/requests", makeEnvelope("req-scalar"));
    await device.next();
    // A scalar the integrator could never JWS-verify must be refused before storage.
    device.send({ type: "verdict", request_id: "req-scalar", verdict: 42 });
    const err = await device.next();
    expect(err.type).toBe("error");
    const polled = await get<{ status: string }>(acct, "/requests/req-scalar");
    expect(polled.data.status).toBe("pending");
  });
});

// ---------------------------------------------------------------------------
// Fail-closed expiry (contract §Invariants #6)
// ---------------------------------------------------------------------------

describe("AccountRelay — fail-closed expiry", () => {
  it("refuses a verdict for an expired request and does not resolve it", async () => {
    const acct = "acct-exp-verdict";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    await seedExpiredRequest(acct, "req-exp-v");

    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    device.send({ type: "verdict", request_id: "req-exp-v", verdict: makeVerdict("req-exp-v") });

    const ack = await device.next();
    expect(ack.type).toBe("ack");
    expect(ack.status).toBe("expired");

    // The request is terminal `expired`, NOT `resolved` — a timed-out request is never approvable.
    const polled = await get<{ status: string; verdict?: unknown }>(acct, "/requests/req-exp-v");
    expect(polled.data.status).toBe("expired");
    expect(polled.data.verdict).toBeUndefined();
  });

  it("does not re-flush a request that expired while queued", async () => {
    const acct = "acct-exp-flush";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    await seedExpiredRequest(acct, "req-exp-q");

    // Connecting must NOT deliver the expired queued request.
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    await expect(device.next(500)).rejects.toThrow(/timeout/);
  });

  it("lazy-expires on poll: a past-deadline pending request reports terminal 'expired'", async () => {
    const acct = "acct-exp-poll";
    await seedExpiredRequest(acct, "req-exp-p");

    const polled = await get<{ status: string }>(acct, "/requests/req-exp-p");
    expect(polled.status).toBe(200);
    expect(polled.data.status).toBe("expired");
  });

  it("lazy-expires on …/wait: pushes terminal 'expired' and closes", async () => {
    const acct = "acct-exp-wait";
    await seedExpiredRequest(acct, "req-exp-w");

    const integrator = await connectWs(acct, "/requests/req-exp-w/wait");
    const msg = await integrator.next();
    expect(msg.type).toBe("expired");
    expect(msg.request_id).toBe("req-exp-w");
  });

  it("refuses a verdict from a device whose enrollment was removed", async () => {
    const acct = "acct-exp-revoked";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope("req-rev-1"));
    await device.next(); // request push

    // Simulate a revoke whose hibernation socket outlived the best-effort close.
    await deleteDeviceRow(acct, deviceId);
    device.send({ type: "verdict", request_id: "req-rev-1", verdict: makeVerdict("req-rev-1") });

    const err = await device.next();
    expect(err.type).toBe("error");

    // A de-enrolled device must not drive resolution — the request stays pending.
    const polled = await get<{ status: string }>(acct, "/requests/req-rev-1");
    expect(polled.data.status).toBe("pending");
  });
});

// ---------------------------------------------------------------------------
// Helpers that need a live DO query
// ---------------------------------------------------------------------------

/** Read back the single enrolled device's id via the registry (used to build the connect URL). */
async function firstDeviceId(accountId: string): Promise<string> {
  const { data } = await get<{ devices: Array<{ device_id: string }> }>(accountId, "/devices");
  const first = data.devices[0];
  if (!first) throw new Error(`no enrolled device for ${accountId}`);
  return first.device_id;
}

/**
 * Seed a `pending` request whose `expires_at` is already in the past — `POST /requests` rejects an
 * expired submit, so we insert directly via `runInDurableObject` to exercise the fail-closed paths.
 * Returns the stored envelope.
 */
async function seedExpiredRequest(
  accountId: string,
  requestId: string,
): Promise<Record<string, unknown>> {
  const envelope = makeEnvelope(requestId, { expires_at: PAST_EXPIRES_AT });
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    relay.sql.exec(
      `INSERT OR REPLACE INTO request (request_id, envelope, created_at, expires_at, status)
       VALUES (?, ?, ?, ?, 'pending')`,
      requestId,
      JSON.stringify(envelope),
      CREATED_AT,
      PAST_EXPIRES_AT,
    );
  });
  return envelope;
}

/** Delete a device row directly — simulates a revoke whose hibernation socket outlived the close. */
async function deleteDeviceRow(accountId: string, deviceId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    relay.sql.exec(`DELETE FROM device WHERE device_id = ?`, deviceId);
  });
}
