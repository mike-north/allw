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

import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, it, expect, vi } from "vitest";
import { AccountRelay } from "../src/index.js";
import type {
  PushTransport,
  PushTransportKind,
  PushTransportRegistry,
  PushWakeup,
} from "../src/push.js";
import {
  pairingStartBody,
  rootFor,
  signAccountState,
  signTestVerdict,
  TEST_DECIDED_AT,
  testAccount,
  testRequestId as rid,
  testRoot,
} from "./support/accounts.js";
import { DEVICE_X25519_PUBKEY } from "./support/keys.js";
import { bindAccountRoot, pinRelayClock } from "./support/relay-state.js";

// ---------------------------------------------------------------------------
// Fixtures (deterministic; never `Date.now()` in data — see fixed-dates rule)
// ---------------------------------------------------------------------------

/** A full-order X25519 device key (pairing rejects small-order keys, #248). */
const DEVICE_PUBKEY = DEVICE_X25519_PUBKEY;

/** Far-future expiry (2100-01-01Z, ms) — deterministic AND always > the relay's real `Date.now()`. */
const FUTURE_EXPIRES_AT = 4102444800000;
/** A past expiry (1970-01-01T00:00:01Z, ms) — always < the relay's real `Date.now()` (fail-closed tests). */
const PAST_EXPIRES_AT = 1000;
/**
 * The relay's injected clock for accounts that submit requests: five minutes before
 * {@link FUTURE_EXPIRES_AT}, so that fixed expiry is inside the request horizon (#248).
 */
const RELAY_NOW = FUTURE_EXPIRES_AT - 5 * 60 * 1000;
/**
 * A fixed creation timestamp: one minute before {@link RELAY_NOW}, so a submitted `created_at` is
 * within the relay's bounds (#248). Test verdicts are decided at `TEST_DECIDED_AT`, inside
 * `[CREATED_AT, FUTURE_EXPIRES_AT]`.
 */
const CREATED_AT = RELAY_NOW - 60_000;
/** Retention cutoff fixture: far enough in the past to be swept deterministically. */
const OLD_TERMINAL_AT = 2000;

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
/**
 * A genuinely signed verdict from the account's first enrolled device (#245: the relay records only
 * verdicts whose provenance verifies, so the routing tests send real ones).
 */
async function makeVerdict(
  accountId: string,
  requestId: string,
  decision: "approved" | "denied" = "approved",
): Promise<Record<string, unknown>> {
  return signTestVerdict(accountId, await firstDeviceId(accountId), requestId, { decision });
}

function relayUrl(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

/** Accounts whose root is bound and whose relay clock is pinned to {@link RELAY_NOW}. */
const clockPinned = new Set<string>();

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- T types the parsed body for the caller, as Response.json<T>() does.
async function post<T>(
  accountId: string,
  subPath: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; data: T }> {
  if (subPath === "/requests" && !clockPinned.has(accountId)) {
    // Submits need a bound account root (#248); tests that never pair bind the test root directly.
    await bindAccountRoot(accountId);
    await pinRelayClock(accountId, RELAY_NOW);
    clockPinned.add(accountId);
  }
  const finalHeaders = { ...headers };
  const revokeMatch = /^\/devices\/([^/]+)\/revoke$/.exec(subPath);
  if (revokeMatch && finalHeaders.Authorization === undefined) {
    const token = deviceAuthTokens.get(
      tokenKey(accountId, decodeURIComponent(revokeMatch[1] ?? "")),
    );
    if (token !== undefined) finalHeaders.Authorization = `Bearer ${token}`;
  }
  const retractMatch = /^\/requests\/([^/]+)\/retract$/.exec(subPath);
  if (retractMatch && finalHeaders.Authorization === undefined) {
    const token = requestAuthTokens.get(
      tokenKey(accountId, decodeURIComponent(retractMatch[1] ?? "")),
    );
    if (token !== undefined) finalHeaders.Authorization = `Bearer ${token}`;
  }
  const resp = await exports.default.fetch(relayUrl(accountId, subPath), {
    method: "POST",
    headers: { "Content-Type": "application/json", ...finalHeaders },
    body: JSON.stringify(body),
  });
  const data = (await resp.json()) as T;
  if (subPath === "/requests" && resp.status === 202) {
    rememberRequest(accountId, data as SubmitResult);
  }
  return { status: resp.status, data };
}

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- T types the parsed body for the caller, as Response.json<T>() does.
async function get<T>(
  accountId: string,
  subPath: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; data: T }> {
  const finalHeaders = { ...headers };
  const requestMatch = /^\/requests\/([^/]+)$/.exec(subPath);
  if (requestMatch && finalHeaders.Authorization === undefined) {
    const token = requestAuthTokens.get(
      tokenKey(accountId, decodeURIComponent(requestMatch[1] ?? "")),
    );
    if (token !== undefined) finalHeaders.Authorization = `Bearer ${token}`;
  }
  const resp = await exports.default.fetch(relayUrl(accountId, subPath), {
    method: "GET",
    headers: finalHeaders,
  });
  const data = (await resp.json()) as T;
  return { status: resp.status, data };
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

function appendAuthQuery(subPath: string, token: string): string {
  const separator = subPath.includes("?") ? "&" : "?";
  return `${subPath}${separator}auth=${encodeURIComponent(token)}`;
}

interface PairingStartResult {
  code: string;
  pairing_auth_token: string;
}

interface DeviceEnrollment {
  device_id: string;
  device_auth_token: string;
}

interface SubmitResult {
  request_id: string;
  status: string;
  delivered_to: number;
  push_wakeups?: number;
  request_auth_token: string;
}

const deviceAuthTokens = new Map<string, string>();
const requestAuthTokens = new Map<string, string>();

async function testAuthTokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function tokenKey(accountId: string, id: string): string {
  return `${accountId}\0${id}`;
}

function rememberDevice(accountId: string, device: DeviceEnrollment): void {
  deviceAuthTokens.set(tokenKey(accountId, device.device_id), device.device_auth_token);
}

function rememberRequest(accountId: string, submit: SubmitResult): void {
  requestAuthTokens.set(tokenKey(accountId, submit.request_id), submit.request_auth_token);
}

/** Enroll a device via the pairing flow and retain its token for helper-built auth headers. */
async function pairDevice(accountId: string, pubkey = DEVICE_PUBKEY): Promise<DeviceEnrollment> {
  const start = await post<PairingStartResult>(
    accountId,
    "/pairing/start",
    pairingStartBody(accountId),
  );
  const complete = await post<DeviceEnrollment>(
    accountId,
    "/pairing/complete",
    { code: start.data.code, pubkey },
    bearer(start.data.pairing_auth_token),
  );
  rememberDevice(accountId, complete.data);
  return complete.data;
}

async function enrollDevice(accountId: string, pubkey = DEVICE_PUBKEY): Promise<string> {
  return (await pairDevice(accountId, pubkey)).device_id;
}

async function pairDeviceWithPushToken(
  accountId: string,
  token = "a".repeat(64),
): Promise<DeviceEnrollment> {
  const start = await post<PairingStartResult>(
    accountId,
    "/pairing/start",
    pairingStartBody(accountId),
  );
  const complete = await post<DeviceEnrollment>(
    accountId,
    "/pairing/complete",
    {
      code: start.data.code,
      pubkey: DEVICE_PUBKEY,
      push_tokens: [{ transport: "apns", token }],
    },
    bearer(start.data.pairing_auth_token),
  );
  rememberDevice(accountId, complete.data);
  return complete.data;
}

async function enrollDeviceWithPushToken(
  accountId: string,
  token = "a".repeat(64),
): Promise<string> {
  return (await pairDeviceWithPushToken(accountId, token)).device_id;
}

/** A transport that records each wakeup it is asked to send and always succeeds. */
function recordingTransport(kind: PushTransportKind, sent: PushWakeup[]): PushTransport {
  return {
    kind,
    sendWakeup(wakeup) {
      sent.push(wakeup);
      return Promise.resolve();
    },
  };
}

async function installPushTransports(
  accountId: string,
  pushTransports: PushTransportRegistry,
): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    instance["pushTransports"] = pushTransports;
  });
}

/**
 * Run `body` on a real `AccountRelay` whose Durable Object state is partly replaced, for driving one
 * private method without a runtime fan-out. `AccountRelay` extends the runtime's `DurableObject`,
 * so it can only be built over a real state: this takes the instance the runtime already holds for
 * a fresh account, and swaps in the pieces the test needs. `state` supplies the WebSocket methods
 * (spied on the real state for the call), and `exec` answers every SQL statement the body runs.
 * The schema setup has already run for real.
 */
async function withRelayOverStubState<T>(
  state: Partial<Pick<DurableObjectState, "acceptWebSocket" | "getWebSockets" | "getTags">>,
  exec: (query: string) => unknown[],
  body: (relay: AccountRelay) => T | Promise<T>,
): Promise<T> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(testAccount("acct-stub-state")));
  return runInDurableObject(stub, async (relay: AccountRelay, realState) => {
    const stubSql = {
      storage: { sql: { exec: (query: string) => exec(query) } },
    } as unknown as DurableObjectState;
    const spies = [
      state.acceptWebSocket &&
        vi.spyOn(realState, "acceptWebSocket").mockImplementation(state.acceptWebSocket),
      state.getWebSockets &&
        vi.spyOn(realState, "getWebSockets").mockImplementation(state.getWebSockets),
      state.getTags && vi.spyOn(realState, "getTags").mockImplementation(state.getTags),
    ];
    const realSql = relay["sql"];
    const realNow = relay["now"];
    relay["sql"] = stubSql.storage.sql;
    try {
      return await body(relay);
    } finally {
      relay["sql"] = realSql;
      relay["now"] = realNow;
      for (const spy of spies) spy?.mockRestore();
    }
  });
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
  /**
   * Assert that no message is waiting on this socket, without waiting out a timeout. Sends a frame
   * the relay always answers (a non-JSON message gets an `error`) and requires that answer to be the
   * next message. A Durable Object handles one event at a time, and the sends these tests check (a
   * connect's queue flush, a submit's fan-out) complete inside an earlier event, so any such message
   * is already ahead of the answer on the socket.
   *
   * The guarantee is narrower than a long wait's: it covers only messages sent synchronously by
   * events that have already completed. A send the relay defers to a timer, or makes after an
   * `await` that lets the barrier's event run first, can land after the answer and go unseen. So
   * this relies on the relay's message and connect handlers sending synchronously, as they do now.
   */
  expectNothingPending(): Promise<void>;
  send(obj: unknown): void;
  raw: WebSocket;
}

/**
 * Open a WebSocket to the relay. The message listener is attached BEFORE `accept()` so that
 * server pushes emitted during the upgrade (offline-queue flush, immediate verdict) are not missed.
 * Returns the 101 client wrapped in a queue-backed reader, or throws on a non-101 response.
 */
async function connectWs(accountId: string, subPath: string): Promise<WsClient> {
  const parsed = new URL(relayUrl(accountId, subPath));
  const deviceMatch = /^\/devices\/([^/]+)\/connect$/.exec(
    parsed.pathname.slice(accountId.length + 1),
  );
  const waitMatch = /^\/requests\/([^/]+)\/wait$/.exec(parsed.pathname.slice(accountId.length + 1));
  const token = deviceMatch
    ? deviceAuthTokens.get(tokenKey(accountId, decodeURIComponent(deviceMatch[1] ?? "")))
    : waitMatch
      ? requestAuthTokens.get(tokenKey(accountId, decodeURIComponent(waitMatch[1] ?? "")))
      : undefined;
  const resp = await exports.default.fetch(parsed.toString(), {
    headers: {
      Upgrade: "websocket",
      ...(token === undefined ? {} : { "Sec-WebSocket-Protocol": `allw.v1, allw.auth.${token}` }),
    },
  });
  expect(resp.headers.get("Sec-WebSocket-Protocol")).toBe("allw.v1");
  if (resp.status !== 101 || !resp.webSocket) {
    throw new Error(`expected 101 WebSocket upgrade, got ${String(resp.status)}`);
  }
  const ws = resp.webSocket;

  const queue: WsMessage[] = [];
  const waiters: ((m: WsMessage) => void)[] = [];
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

  function next(timeoutMs = 2000): Promise<WsMessage> {
    const queued = queue.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise<WsMessage>((resolve, reject) => {
      const waiter = (m: WsMessage): void => {
        clearTimeout(timer);
        resolve(m);
      };
      const timer = setTimeout(() => {
        // Withdraw the waiter, so a message that arrives after the timeout is queued for the next
        // read instead of going to this already-rejected promise.
        const index = waiters.indexOf(waiter);
        if (index !== -1) waiters.splice(index, 1);
        reject(new Error("WebSocket message timeout"));
      }, timeoutMs);
      waiters.push(waiter);
    });
  }

  return {
    next,
    send(obj: unknown): void {
      ws.send(JSON.stringify(obj));
    },
    async expectNothingPending(): Promise<void> {
      // Created before the await, so a missing answer's stack names the calling test line rather
      // than next()'s timer.
      const callSite = new Error(
        "expectNothingPending: the relay never answered the barrier frame",
      );
      ws.send("barrier: not a JSON message");
      let answer: WsMessage;
      try {
        answer = await next();
      } catch {
        throw callSite;
      }
      expect(answer, "a message was already pending ahead of the barrier's answer").toEqual({
        type: "error",
        error: "invalid JSON message",
      });
    },
    raw: ws,
  };
}

// ---------------------------------------------------------------------------
// End-to-end: online device
// ---------------------------------------------------------------------------

describe("WsClient (test helper)", () => {
  // Regression: a timed-out next() left its waiter queued, so the next message went to the
  // rejected promise and was lost to every later read.
  it("a message arriving after a timed-out next() is still read by the next next()", async () => {
    const acct = testAccount("acct-wsclient-timeout");
    await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);

    await expect(device.next(50)).rejects.toThrow(/timeout/);
    // The relay answers a non-JSON frame with an error frame; it must reach the next read.
    device.raw.send("not a JSON message");
    expect(await device.next()).toEqual({ type: "error", error: "invalid JSON message" });
  });
});

describe("AccountRelay — routing (device online)", () => {
  it("E2E: submit → device receives ciphertext → verdict → integrator polls resolved", async () => {
    const acct = testAccount("acct-e2e-online");
    await enrollDevice(acct);

    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);

    // Integrator submits the ciphertext envelope.
    const envelope = makeEnvelope(rid("req-online-1"));
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
    expect(pushed.request_id).toBe(rid("req-online-1"));
    expect(pushed.envelope?.context_ciphertext).toBe(envelope.context_ciphertext);

    // Device returns a signed verdict over the same socket.
    const verdict = await makeVerdict(acct, rid("req-online-1"));
    device.send({ type: "verdict", request_id: rid("req-online-1"), verdict });
    const ack = await device.next();
    expect(ack.type).toBe("ack");
    expect(ack.status).toBe("resolved");

    // Integrator polls and receives the verdict.
    const polled = await get<{ status: string; verdict: Record<string, unknown> }>(
      acct,
      `/requests/${rid("req-online-1")}`,
    );
    expect(polled.status).toBe(200);
    expect(polled.data.status).toBe("resolved");
    expect(polled.data.verdict).toEqual(verdict);
  });

  it("pushes the verdict to a live integrator waiting on …/wait", async () => {
    const acct = testAccount("acct-e2e-wait");
    await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-wait-1")));
    await device.next(); // drain the request push

    // Integrator opens a wait socket BEFORE the device decides.
    const integrator = await connectWs(acct, `/requests/${rid("req-wait-1")}/wait`);

    const verdict = await makeVerdict(acct, rid("req-wait-1"), "denied");
    device.send({ type: "verdict", request_id: rid("req-wait-1"), verdict });

    const pushed = await integrator.next();
    expect(pushed.type).toBe("verdict");
    expect(pushed.request_id).toBe(rid("req-wait-1"));
    expect(pushed.verdict).toEqual(verdict);
  });

  it("delivers immediately when …/wait opens after the verdict already landed", async () => {
    const acct = testAccount("acct-wait-late");
    await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-late-1")));
    await device.next();
    const verdict = await makeVerdict(acct, rid("req-late-1"));
    device.send({ type: "verdict", request_id: rid("req-late-1"), verdict });
    await device.next(); // ack

    // Now connect the waiter — it should receive the persisted verdict at once.
    const integrator = await connectWs(acct, `/requests/${rid("req-late-1")}/wait`);
    const pushed = await integrator.next();
    expect(pushed.type).toBe("verdict");
    expect(pushed.verdict).toEqual(verdict);
  });
});

// ---------------------------------------------------------------------------
// Offline queue
// ---------------------------------------------------------------------------

describe("AccountRelay — routing (device offline)", () => {
  it("submitting a request schedules request-id-only push wakeups for registered tokens", async () => {
    const acct = testAccount("acct-push-wakeup");
    const start = await post<PairingStartResult>(acct, "/pairing/start", pairingStartBody(acct));
    await post(
      acct,
      "/pairing/complete",
      {
        code: start.data.code,
        pubkey: DEVICE_PUBKEY,
        push_tokens: [{ transport: "apns", token: "a".repeat(64) }],
      },
      bearer(start.data.pairing_auth_token),
    );
    const wakeups: PushWakeup[] = [];
    await installPushTransports(acct, { apns: recordingTransport("apns", wakeups) });

    const submit = await post<{
      delivered_to: number;
      push_wakeups: number;
      status: string;
    }>(acct, "/requests", makeEnvelope(rid("req-push-wakeup")));

    expect(submit.status).toBe(202);
    expect(submit.data.status).toBe("pending");
    expect(submit.data.delivered_to).toBe(0);
    expect(submit.data.push_wakeups).toBe(1);
    await vi.waitFor(() => {
      expect(wakeups.map((w) => w.requestId)).toEqual([rid("req-push-wakeup")]);
    });
  });

  it("schedules no wakeup for a token whose transport is not configured", async () => {
    const acct = testAccount("acct-push-unconfigured");
    // The test Worker has no APNs credentials, so no APNs transport is registered.
    await enrollDeviceWithPushToken(acct);

    const submit = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      makeEnvelope(rid("req-push-unconfigured")),
    );

    expect(submit.status).toBe(202);
    expect(submit.data.push_wakeups).toBe(0);
  });

  it("still delivers over WebSocket when a push transport throws", async () => {
    const acct = testAccount("acct-push-throw-still-ws");
    const deviceId = await enrollDeviceWithPushToken(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    await installPushTransports(acct, {
      apns: {
        kind: "apns",
        sendWakeup() {
          return Promise.reject(new Error("provider unavailable"));
        },
      },
    });

    const submit = await post<{
      delivered_to: number;
      push_wakeups: number;
      status: string;
    }>(acct, "/requests", makeEnvelope(rid("req-push-throw")));

    expect(submit.status).toBe(202);
    expect(submit.data.status).toBe("pending");
    expect(submit.data.delivered_to).toBe(1);
    // `push_wakeups` counts wakeups scheduled; the throwing transport runs off the response path.
    expect(submit.data.push_wakeups).toBe(1);
    const pushed = await device.next();
    expect(pushed.type).toBe("request");
    expect(pushed.request_id).toBe(rid("req-push-throw"));
  });

  it("stops scheduling push wakeups after the target device is revoked", async () => {
    const acct = testAccount("acct-push-revoke-clears-wakeups");
    const deviceId = await enrollDeviceWithPushToken(acct);
    await installPushTransports(acct, { apns: recordingTransport("apns", []) });

    const beforeRevoke = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      makeEnvelope(rid("req-push-before-revoke")),
    );
    expect(beforeRevoke.status).toBe(202);
    expect(beforeRevoke.data.push_wakeups).toBe(1);

    const revoke = await post<{ revoked: boolean }>(acct, `/devices/${deviceId}/revoke`, {});
    expect(revoke.status).toBe(200);

    const afterRevoke = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      makeEnvelope(rid("req-push-after-revoke")),
    );
    expect(afterRevoke.status).toBe(202);
    expect(afterRevoke.data.push_wakeups).toBe(0);
  });

  it("queues a request submitted while offline and flushes it on reconnect", async () => {
    const acct = testAccount("acct-offline-queue");
    await enrollDevice(acct);

    // Submit with NO device connected → delivered_to 0, request stays pending.
    const submit = await post<{ delivered_to: number; status: string }>(
      acct,
      "/requests",
      makeEnvelope(rid("req-offline-1")),
    );
    expect(submit.data.delivered_to).toBe(0);
    expect(submit.data.status).toBe("pending");

    // Device comes online → receives the queued request on connect.
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);
    const flushed = await device.next();
    expect(flushed.type).toBe("request");
    expect(flushed.request_id).toBe(rid("req-offline-1"));
  });

  it("flushes only still-pending requests (already-resolved ones are not re-delivered)", async () => {
    const acct = testAccount("acct-offline-mixed");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);

    // Two requests submitted while offline.
    await post(acct, "/requests", makeEnvelope(rid("req-mixed-1")));
    await post(acct, "/requests", makeEnvelope(rid("req-mixed-2")));

    // First device resolves req-mixed-1.
    const d1 = await connectWs(acct, `/devices/${deviceId}/connect`);
    const first = await d1.next();
    const second = await d1.next();
    const ids = [first.request_id, second.request_id].sort();
    expect(ids).toEqual([rid("req-mixed-1"), rid("req-mixed-2")].sort());
    d1.send({
      type: "verdict",
      request_id: rid("req-mixed-1"),
      verdict: await makeVerdict(acct, rid("req-mixed-1")),
    });
    await d1.next(); // ack

    // A second device connecting later should receive ONLY the still-pending req-mixed-2.
    const d2 = await connectWs(acct, `/devices/${deviceId}/connect`);
    const flushed = await d2.next();
    expect(flushed.request_id).toBe(rid("req-mixed-2"));
    // No further pending request arrives.
    await d2.expectNothingPending();
  });
});

// ---------------------------------------------------------------------------
// Cross-device retraction + dedupe
// ---------------------------------------------------------------------------

describe("AccountRelay — cross-device coordination", () => {
  it("retracts the request from other devices once one resolves it", async () => {
    const acct = testAccount("acct-retract");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);

    // Two presence sockets for the account (e.g. macOS + iPhone).
    const dA = await connectWs(acct, `/devices/${deviceId}/connect`);
    const dB = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-retract-1")));
    // Both receive the request push.
    expect((await dA.next()).type).toBe("request");
    expect((await dB.next()).type).toBe("request");

    // Device A resolves.
    dA.send({
      type: "verdict",
      request_id: rid("req-retract-1"),
      verdict: await makeVerdict(acct, rid("req-retract-1")),
    });

    // Device B must receive a retract for that request.
    const retract = await dB.next();
    expect(retract.type).toBe("retract");
    expect(retract.request_id).toBe(rid("req-retract-1"));
  });

  it("first verdict wins: a second verdict is ignored (dedupe)", async () => {
    const acct = testAccount("acct-dedupe");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-dedupe-1")));
    await device.next();

    const winning = await makeVerdict(acct, rid("req-dedupe-1"), "approved");
    device.send({ type: "verdict", request_id: rid("req-dedupe-1"), verdict: winning });
    const ack1 = await device.next();
    expect(ack1.status).toBe("resolved");

    // A second, conflicting verdict for the same request is acknowledged but does not overwrite.
    device.send({
      type: "verdict",
      request_id: rid("req-dedupe-1"),
      verdict: await makeVerdict(acct, rid("req-dedupe-1"), "denied"),
    });
    const ack2 = await device.next();
    expect(ack2.type).toBe("ack");
    expect(ack2.status).toBe("already_resolved");

    const polled = await get<{ verdict: Record<string, unknown> }>(
      acct,
      `/requests/${rid("req-dedupe-1")}`,
    );
    expect(polled.data.verdict).toEqual(winning); // the first decision stands
  });

  it("fans out to only one connection per visible surface", async () => {
    const acct = testAccount("acct-surface-dedupe");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);

    // These two sockets represent distinct enrolled devices/transports that would notify the same
    // physical screen, e.g. native macOS plus iPhone notification mirroring on that Mac.
    const nativeMac = await connectWs(acct, `/devices/${deviceId}/connect?surface_id=mac-screen`);
    const mirroredPhone = await connectWs(
      acct,
      `/devices/${deviceId}/connect?surface_id=mac-screen`,
    );
    const phone = await connectWs(acct, `/devices/${deviceId}/connect?surface_id=phone-screen`);

    const submit = await post<{ delivered_to: number }>(
      acct,
      "/requests",
      makeEnvelope(rid("req-surface-1")),
    );
    expect(submit.data.delivered_to).toBe(2);

    expect((await nativeMac.next()).request_id).toBe(rid("req-surface-1"));
    expect((await phone.next()).request_id).toBe(rid("req-surface-1"));
    await mirroredPhone.expectNothingPending();
  });

  it("continues same-surface fan-out when the first tagged socket cannot be sent to", async () => {
    const staleMac = { send: () => void 0 } as unknown as WebSocket;
    const liveMacMessages: string[] = [];
    const liveMac = {
      send: (message: string) => liveMacMessages.push(message),
    } as unknown as WebSocket;
    const phoneMessages: string[] = [];
    const phone = {
      send: (message: string) => phoneMessages.push(message),
    } as unknown as WebSocket;

    const tags = new Map<WebSocket, string[]>([
      [staleMac, ["device", "surface:mac-screen"]],
      [liveMac, ["device", "surface:mac-screen"]],
      [phone, ["device", "surface:phone-screen"]],
    ]);

    // A closing hibernation socket can still be returned by the tag index but reject `send()`. It
    // must not claim the visible surface unless the relay actually sends the request to it.
    vi.spyOn(staleMac, "send").mockImplementation(() => {
      throw new Error("socket already closing");
    });

    const delivered = await withRelayOverStubState(
      {
        getTags: (ws: WebSocket) => tags.get(ws) ?? [],
        getWebSockets: (tag: string) => (tag === "device" ? [staleMac, liveMac, phone] : []),
      },
      () => [],
      (relay) =>
        relay["sendRequestToOneSocketPerSurface"](
          rid("req-surface-stale-1"),
          makeEnvelope(rid("req-surface-stale-1")),
        ),
    );

    expect(delivered).toBe(2);
    expect(JSON.parse(liveMacMessages[0] ?? "{}")).toMatchObject({
      type: "request",
      request_id: rid("req-surface-stale-1"),
    });
    expect(JSON.parse(phoneMessages[0] ?? "{}")).toMatchObject({
      type: "request",
      request_id: rid("req-surface-stale-1"),
    });
  });

  it("flushes queued requests to only one reconnecting connection per visible surface", async () => {
    const acct = testAccount("acct-surface-flush");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);

    await post(acct, "/requests", makeEnvelope(rid("req-surface-queued")));

    const nativeMac = await connectWs(acct, `/devices/${deviceId}/connect?surface_id=mac-screen`);
    const mirroredPhone = await connectWs(
      acct,
      `/devices/${deviceId}/connect?surface_id=mac-screen`,
    );
    const phone = await connectWs(acct, `/devices/${deviceId}/connect?surface_id=phone-screen`);

    expect((await nativeMac.next()).request_id).toBe(rid("req-surface-queued"));
    expect((await phone.next()).request_id).toBe(rid("req-surface-queued"));
    await mirroredPhone.expectNothingPending();
  });

  it("flushes queued requests when only stale sockets exist for the reconnecting surface", async () => {
    const staleMac = {
      readyState: WebSocket.CLOSING,
      send: () => {
        throw new Error("socket already closing");
      },
    } as unknown as WebSocket;
    const envelope = makeEnvelope(rid("req-surface-stale-queued"));
    const authTokenHash = await testAuthTokenHash("stale-device-token");

    // The stub `exec` ignores the deadline filter: it returns the queued row for any request query.
    await withRelayOverStubState(
      {
        acceptWebSocket: (ws: WebSocket) => {
          ws.accept();
        },
        getWebSockets: (tag: string) => (tag === "surface:mac-screen" ? [staleMac] : []),
      },
      (query) => {
        if (query.includes("FROM device WHERE")) {
          return [{ device_id: "dev-stale-flush", auth_token_hash: authTokenHash }];
        }
        if (query.includes("FROM request")) {
          return [
            { request_id: rid("req-surface-stale-queued"), envelope: JSON.stringify(envelope) },
          ];
        }
        return [];
      },
      async (relay) => {
        relay["now"] = () => RELAY_NOW;

        const response = await relay["handleDeviceConnect"](
          "dev-stale-flush",
          new Request(
            "https://relay.allw.test/acct/devices/dev-stale-flush/connect?surface_id=mac-screen",
            // A real client offers the application marker and a private credential protocol.
            {
              headers: {
                Upgrade: "websocket",
                "Sec-WebSocket-Protocol": "allw.v1, allw.auth.stale-device-token",
              },
            },
          ),
        );
        expect(response.status).toBe(101);
        expect(response.webSocket).toBeDefined();

        const client = response.webSocket;
        if (!client) throw new Error("expected a WebSocket on the 101 response");
        const queued = new Promise<WsMessage>((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error("WebSocket message timeout"));
          }, 500);
          client.addEventListener("message", (event: MessageEvent) => {
            clearTimeout(timeout);
            resolve(JSON.parse(event.data as string) as WsMessage);
          });
        });
        client.accept();

        await expect(queued).resolves.toMatchObject({
          type: "request",
          request_id: rid("req-surface-stale-queued"),
        });
      },
    );
  });
});

// ---------------------------------------------------------------------------
// Zero-knowledge invariant
// ---------------------------------------------------------------------------

describe("AccountRelay — zero-knowledge (routing)", () => {
  it("stores ONLY the opaque ciphertext envelope and the signed verdict — no plaintext", async () => {
    const acct = testAccount("acct-zk-routing");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    const envelope = makeEnvelope(rid("req-zk-1"));
    await post(acct, "/requests", envelope);
    await device.next();

    const id = env.ACCOUNT.idFromName(acct);
    const stub = env.ACCOUNT.get(id);
    const readStored = () =>
      runInDurableObject(stub, (relay: AccountRelay) => {
        const reqRows = [
          ...relay["sql"].exec<{ envelope: string; status: string }>(
            `SELECT envelope, status FROM request WHERE request_id = ?`,
            rid("req-zk-1"),
          ),
        ];
        const verdictRows = [
          ...relay["sql"].exec<{ verdict: string }>(
            `SELECT verdict FROM verdict WHERE request_id = ?`,
            rid("req-zk-1"),
          ),
        ];
        return { reqRows, verdictRows };
      });

    // While pending, the stored envelope is exactly what was submitted — routing/lifecycle +
    // opaque ciphertext.
    const pending = await readStored();
    const storedEnvelope = JSON.parse(pending.reqRows[0]?.envelope ?? "{}") as Record<
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

    const verdict = await makeVerdict(acct, rid("req-zk-1"));
    device.send({ type: "verdict", request_id: rid("req-zk-1"), verdict });
    await device.next();

    // Once resolved, the envelope (and its ciphertext) is blanked — only the verdict remains (#248).
    const stored = await readStored();
    expect(stored.reqRows[0]).toEqual({ envelope: "", status: "resolved" });
    const polled = await get<{ status: string; verdict: unknown }>(
      acct,
      `/requests/${rid("req-zk-1")}`,
    );
    expect(polled.data.status).toBe("resolved");
    expect(polled.data.verdict).toEqual(verdict);
    // The verdict round-trips byte-for-byte (relay holds no key that could forge it).
    const storedVerdict = JSON.parse(stored.verdictRows[0]?.verdict ?? "{}") as Record<
      string,
      unknown
    >;
    expect(storedVerdict).toEqual(verdict);
  });
});

// ---------------------------------------------------------------------------
// Late verdicts on terminal rows whose envelope was blanked (#248, #352)
// ---------------------------------------------------------------------------

describe("AccountRelay — a late verdict on a blanked terminal row", () => {
  /**
   * Terminal rows keep no envelope (#248), and the provenance check (#352) reads the window from
   * the envelope. A late verdict on a retracted or expired row must therefore get that status from
   * the early returns, which run before the provenance check: never a provenance or parse error.
   */
  async function setUp(name: string, expiresAt = FUTURE_EXPIRES_AT) {
    const acct = testAccount(`acct-late-blank-${name}`);
    await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);
    const requestId = rid(`req-late-blank-${name}`);
    await post(acct, "/requests", { ...makeEnvelope(requestId), expires_at: expiresAt });
    expect((await device.next()).request_id).toBe(requestId);
    return { acct, device, requestId };
  }

  async function storedRow(acct: string, requestId: string) {
    return runInDurableObject(
      env.ACCOUNT.get(env.ACCOUNT.idFromName(acct)),
      (relay: AccountRelay) => {
        return [
          ...relay["sql"].exec<{ envelope: string; status: string }>(
            `SELECT envelope, status FROM request WHERE request_id = ?`,
            requestId,
          ),
        ][0];
      },
    );
  }

  /** Send a genuine verdict and return the first ack, skipping the retract push before it. */
  async function sendLateVerdict(ctx: {
    acct: string;
    device: WsClient;
    requestId: string;
  }): Promise<WsMessage> {
    const verdict = await makeVerdict(ctx.acct, ctx.requestId);
    ctx.device.send({ type: "verdict", request_id: ctx.requestId, verdict });
    for (;;) {
      const msg = await ctx.device.next();
      if (msg.type !== "retract") return msg;
    }
  }

  it("a retracted row answers its status", async () => {
    const ctx = await setUp("retracted");
    const retract = await post(ctx.acct, `/requests/${ctx.requestId}/retract`, {});
    expect(retract.status).toBe(200);
    expect(await storedRow(ctx.acct, ctx.requestId)).toEqual({ envelope: "", status: "retracted" });

    expect(await sendLateVerdict(ctx)).toEqual({
      type: "ack",
      request_id: ctx.requestId,
      status: "retracted",
    });
    expect(await storedRow(ctx.acct, ctx.requestId)).toEqual({ envelope: "", status: "retracted" });
  });

  it("an expired row answers its status", async () => {
    const expiresAt = RELAY_NOW + 60_000;
    const ctx = await setUp("expired", expiresAt);
    await runInDurableObject(
      env.ACCOUNT.get(env.ACCOUNT.idFromName(ctx.acct)),
      async (relay: AccountRelay) => {
        relay["now"] = () => expiresAt + 1;
        await relay.alarm();
      },
    );
    expect(await storedRow(ctx.acct, ctx.requestId)).toEqual({ envelope: "", status: "expired" });

    expect(await sendLateVerdict(ctx)).toEqual({
      type: "ack",
      request_id: ctx.requestId,
      status: "expired",
    });
    expect(await storedRow(ctx.acct, ctx.requestId)).toEqual({ envelope: "", status: "expired" });
  });
});

// ---------------------------------------------------------------------------
// Authenticity: only device sockets may resolve a request
// ---------------------------------------------------------------------------

describe("AccountRelay — verdict authenticity", () => {
  it("rejects a verdict sent from a non-device (integrator …/wait) socket", async () => {
    const acct = testAccount("acct-sec-verdict");
    await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${await firstDeviceId(acct)}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-sec-1")));
    await device.next(); // drain the request push to the legitimate device

    // A non-device client opens the integrator wait socket and tries to forge a verdict.
    const integrator = await connectWs(acct, `/requests/${rid("req-sec-1")}/wait`);
    integrator.send({
      type: "verdict",
      request_id: rid("req-sec-1"),
      verdict: await makeVerdict(acct, rid("req-sec-1")),
    });

    const resp = await integrator.next();
    expect(resp.type).toBe("error");

    // The request must remain pending — the forged verdict did NOT resolve it.
    const polled = await get<{ status: string }>(acct, `/requests/${rid("req-sec-1")}`);
    expect(polled.data.status).toBe("pending");
  });
});

// ---------------------------------------------------------------------------
// Verdict finality (issue #245): only provenance-valid verdicts are recorded
// ---------------------------------------------------------------------------

describe("AccountRelay — verdict finality (#245)", () => {
  /** A second device's encryption pubkey (any valid 32-byte base64url value). */
  const SECOND_DEVICE_PUBKEY = "E".repeat(43);

  /**
   * An account with two enrolled devices, both connected; a pending request delivered to both, and
   * a live integrator waiter on it.
   */
  async function setUp(name: string, requestId: string) {
    const acct = testAccount(name);
    const first = await enrollDevice(acct);
    const second = await enrollDevice(acct, SECOND_DEVICE_PUBKEY);
    const d1 = await connectWs(acct, `/devices/${first}/connect`);
    const d2 = await connectWs(acct, `/devices/${second}/connect`);
    await post(acct, "/requests", makeEnvelope(requestId));
    expect((await d1.next()).type).toBe("request");
    expect((await d2.next()).type).toBe("request");
    const integrator = await connectWs(acct, `/requests/${requestId}/wait`);
    return { acct, first, second, d1, d2, integrator };
  }

  /**
   * After a refused verdict: the request is still pending with nothing recorded, the other device
   * got no retract, and the legitimate device's genuine verdict still resolves it. The integrator
   * receives that genuine verdict only.
   */
  async function expectStillAnswerable(
    ctx: Awaited<ReturnType<typeof setUp>>,
    requestId: string,
  ): Promise<void> {
    const polled = await get<{ status: string; verdict?: unknown }>(
      ctx.acct,
      `/requests/${requestId}`,
    );
    expect(polled.data.status).toBe("pending");
    expect(polled.data.verdict).toBeUndefined();

    const genuine = signTestVerdict(ctx.acct, ctx.first, requestId);
    ctx.d1.send({ type: "verdict", request_id: requestId, verdict: genuine });
    expect(await ctx.d1.next()).toEqual({ type: "ack", request_id: requestId, status: "resolved" });
    // The first message the other device sees is the retract for the genuine verdict.
    expect(await ctx.d2.next()).toEqual({ type: "retract", request_id: requestId });
    const pushed = await ctx.integrator.next();
    expect(pushed.type).toBe("verdict");
    expect(pushed.verdict).toEqual(genuine);
  }

  /** Send `verdict` from device 1 for `requestId`; expect the provenance error frame. */
  async function expectRefused(
    ctx: Awaited<ReturnType<typeof setUp>>,
    requestId: string,
    verdict: unknown,
    error = "verdict failed provenance verification",
    socket: WsClient = ctx.d1,
  ): Promise<void> {
    socket.send({ type: "verdict", request_id: requestId, verdict });
    expect(await socket.next()).toEqual({ type: "error", request_id: requestId, error });
  }

  it("refuses a junk verdict (a JSON object that is not a signed verdict)", async () => {
    const ctx = await setUp("acct-final-junk", rid("req-final-junk"));
    for (const junk of [
      { decision: "denied" },
      {
        v: 1,
        request_id: rid("req-final-junk"),
        request_hash: "ZmFrZS1yZXF1ZXN0LWhhc2gtMzItYnl0ZXMtYjY0dXI",
        decision: "denied",
        decided_at: CREATED_AT,
        approver: { account_id: ctx.acct, device_id: ctx.first },
        sig: "eyJhbGciOiJFZERTQSJ9..FAKE_JWS_SIGNATURE",
      },
    ]) {
      await expectRefused(ctx, rid("req-final-junk"), junk);
    }
    await expectStillAnswerable(ctx, rid("req-final-junk"));
  });

  it("refuses a verdict signed by a key no certificate vouches for", async () => {
    const ctx = await setUp("acct-final-uncertified", rid("req-final-uncertified"));
    await expectRefused(
      ctx,
      rid("req-final-uncertified"),
      signTestVerdict(ctx.acct, ctx.first, rid("req-final-uncertified"), {
        decision: "denied",
        uncertifiedKey: true,
      }),
    );
    await expectStillAnswerable(ctx, rid("req-final-uncertified"));
  });

  it("refuses a device certificate issued by another account's root", async () => {
    const ctx = await setUp("acct-final-foreign-root", rid("req-final-foreign-root"));
    await expectRefused(
      ctx,
      rid("req-final-foreign-root"),
      signTestVerdict(ctx.acct, ctx.first, rid("req-final-foreign-root"), {
        decision: "denied",
        certifiedBy: testRoot("acct-final-foreign-root-attacker"),
      }),
    );
    await expectStillAnswerable(ctx, rid("req-final-foreign-root"));
  });

  it("refuses a genuine verdict replayed for a different request id", async () => {
    const ctx = await setUp("acct-final-replay", rid("req-final-replay"));
    const forOther = signTestVerdict(ctx.acct, ctx.first, rid("req-final-other"), {
      decision: "denied",
    });
    await expectRefused(ctx, rid("req-final-replay"), forOther);
    // Rewriting only the outer request_id does not help: it no longer matches the signed one.
    await expectRefused(ctx, rid("req-final-replay"), {
      ...forOther,
      request_id: rid("req-final-replay"),
    });
    await expectStillAnswerable(ctx, rid("req-final-replay"));
  });

  it("refuses a genuine verdict whose kid is another device than the socket's", async () => {
    const ctx = await setUp("acct-final-kid", rid("req-final-kid"));
    await expectRefused(
      ctx,
      rid("req-final-kid"),
      signTestVerdict(ctx.acct, ctx.second, rid("req-final-kid"), { decision: "denied" }),
      "verdict is signed by another device",
    );
    await expectStillAnswerable(ctx, rid("req-final-kid"));
  });

  it("refuses a verdict from a device revoked in the relay's verified account state", async () => {
    const ctx = await setUp("acct-final-revoked", rid("req-final-revoked"));
    const published = await post(ctx.acct, "/account-states", {
      account_states: [
        signAccountState(rootFor(ctx.acct), { sequence: 1, revokedDevices: [ctx.second] }),
      ],
    });
    expect(published.status).toBe(200);
    await expectRefused(
      ctx,
      rid("req-final-revoked"),
      signTestVerdict(ctx.acct, ctx.second, rid("req-final-revoked"), { decision: "denied" }),
      "verdict failed provenance verification",
      ctx.d2,
    );
    // The revoked device's socket got its error; the legitimate device still resolves.
    const polled = await get<{ status: string }>(ctx.acct, `/requests/${rid("req-final-revoked")}`);
    expect(polled.data.status).toBe("pending");
    const genuine = signTestVerdict(ctx.acct, ctx.first, rid("req-final-revoked"));
    ctx.d1.send({ type: "verdict", request_id: rid("req-final-revoked"), verdict: genuine });
    expect((await ctx.d1.next()).status).toBe("resolved");
    expect((await ctx.integrator.next()).verdict).toEqual(genuine);
  });

  it("refuses a verdict whose certificate had expired at its decided_at", async () => {
    const ctx = await setUp("acct-final-cert-expired", rid("req-final-cert-expired"));
    await expectRefused(
      ctx,
      rid("req-final-cert-expired"),
      signTestVerdict(ctx.acct, ctx.first, rid("req-final-cert-expired"), {
        decision: "denied",
        // Expired one millisecond before the signed decision time.
        certExpiresAt: TEST_DECIDED_AT - 1,
      }),
    );
    await expectStillAnswerable(ctx, rid("req-final-cert-expired"));
  });

  // Reviewer probe on #352: a device whose certificate expired in November 2023 signs a decision
  // backdated to before the request existed, when its certificate was still valid. Judging the
  // certificate at the device-chosen `decided_at` alone would accept it and let the device
  // pre-empt every request; the request window bounds `decided_at` first.
  it("refuses an expired-cert device backdating its decision to before the request", async () => {
    const ctx = await setUp("acct-final-backdated", rid("req-final-backdated"));
    const backdated = signTestVerdict(ctx.acct, ctx.first, rid("req-final-backdated"), {
      decision: "denied",
      certExpiresAt: 1_699_999_500_000,
      decidedAt: 1_699_999_000_000, // before the envelope's created_at (CREATED_AT)
    });
    expect(backdated.decided_at).toBeLessThan(CREATED_AT);
    await expectRefused(ctx, rid("req-final-backdated"), backdated);
    // No retract reached the other device, nothing was recorded, and the request still resolves.
    await expectStillAnswerable(ctx, rid("req-final-backdated"));
  });

  it("refuses a verdict decided after the request's expires_at", async () => {
    const ctx = await setUp("acct-final-late", rid("req-final-late"));
    await expectRefused(
      ctx,
      rid("req-final-late"),
      signTestVerdict(ctx.acct, ctx.first, rid("req-final-late"), {
        decision: "denied",
        decidedAt: FUTURE_EXPIRES_AT + 1,
      }),
    );
    await expectStillAnswerable(ctx, rid("req-final-late"));
  });

  it("accepts a decision on the window's edges (envelope created_at and expires_at)", async () => {
    // The window is the envelope's, as the integrator's verify_verdict checks it: CREATED_AT is a
    // minute before the relay received the request, so this also shows the relay's receive time is
    // not the bound.
    for (const [name, decidedAt] of [
      ["created", CREATED_AT],
      ["expires", FUTURE_EXPIRES_AT],
    ] as const) {
      const requestId = rid(`req-final-edge-${name}`);
      const ctx = await setUp(`acct-final-edge-${name}`, requestId);
      const verdict = signTestVerdict(ctx.acct, ctx.first, requestId, { decidedAt });
      ctx.d1.send({ type: "verdict", request_id: requestId, verdict });
      expect(await ctx.d1.next()).toEqual({
        type: "ack",
        request_id: requestId,
        status: "resolved",
      });
      expect((await ctx.integrator.next()).verdict).toEqual(verdict);
    }
  });

  it("refuses another device's approver before any signature check", async () => {
    const ctx = await setUp("acct-final-approver", rid("req-final-approver"));
    // A junk signature would fail provenance; naming another device is refused first, without
    // verifying anything.
    await expectRefused(
      ctx,
      rid("req-final-approver"),
      {
        v: 1,
        request_id: rid("req-final-approver"),
        request_hash: "ZmFrZS1yZXF1ZXN0LWhhc2gtMzItYnl0ZXMtYjY0dXI",
        decision: "denied",
        decided_at: TEST_DECIDED_AT,
        approver: { account_id: ctx.acct, device_id: ctx.second },
        sig: "not-a-jws",
      },
      "verdict is signed by another device",
    );
    await expectStillAnswerable(ctx, rid("req-final-approver"));
  });

  it("gives a malformed approver the provenance error, not 'another device'", async () => {
    const ctx = await setUp("acct-final-approver-shape", rid("req-final-approver-shape"));
    const genuine = signTestVerdict(ctx.acct, ctx.first, rid("req-final-approver-shape"), {
      decision: "denied",
    });
    await expectRefused(ctx, rid("req-final-approver-shape"), {
      ...genuine,
      approver: { account_id: ctx.acct, device_id: 42 },
    });
    await expectStillAnswerable(ctx, rid("req-final-approver-shape"));
  });

  it("refuses every verdict when the account has no bound root (fail-closed)", async () => {
    const ctx = await setUp("acct-final-unbound", rid("req-final-unbound"));
    // A pre-binding leftover: the device rows exist but no root is bound to check against.
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(ctx.acct));
    await runInDurableObject(stub, (instance: AccountRelay) => {
      instance["sql"].exec(`DELETE FROM account_meta`);
    });
    await expectRefused(
      ctx,
      rid("req-final-unbound"),
      signTestVerdict(ctx.acct, ctx.first, rid("req-final-unbound")),
    );
    const polled = await get<{ status: string }>(ctx.acct, `/requests/${rid("req-final-unbound")}`);
    expect(polled.data.status).toBe("pending");
  });

  it("records a genuine denial: provenance is not a decision, the integrator judges it", async () => {
    const ctx = await setUp("acct-final-denial", rid("req-final-denial"));
    const denial = signTestVerdict(ctx.acct, ctx.first, rid("req-final-denial"), {
      decision: "denied",
    });
    ctx.d1.send({ type: "verdict", request_id: rid("req-final-denial"), verdict: denial });
    expect((await ctx.d1.next()).status).toBe("resolved");
    expect(await ctx.d2.next()).toEqual({ type: "retract", request_id: rid("req-final-denial") });
    expect((await ctx.integrator.next()).verdict).toEqual(denial);
  });
});

// ---------------------------------------------------------------------------
// Endpoint authentication (issue #89)
// ---------------------------------------------------------------------------

describe("AccountRelay — endpoint authentication", () => {
  it("requires the enrolled device token for device presence sockets", async () => {
    const acct = testAccount("acct-auth-device-connect");
    const device = await pairDevice(acct);

    const noAuth = await exports.default.fetch(
      relayUrl(acct, `/devices/${device.device_id}/connect`),
      {
        headers: { Upgrade: "websocket" },
      },
    );
    expect(noAuth.status).toBe(401);

    const wrongAuth = await exports.default.fetch(
      relayUrl(acct, `/devices/${device.device_id}/connect`),
      {
        headers: {
          Upgrade: "websocket",
          "Sec-WebSocket-Protocol": `allw.v1, allw.auth.wrong-token`,
        },
      },
    );
    expect(wrongAuth.status).toBe(403);

    const ok = await exports.default.fetch(relayUrl(acct, `/devices/${device.device_id}/connect`), {
      headers: {
        Upgrade: "websocket",
        "Sec-WebSocket-Protocol": `allw.v1, allw.auth.${device.device_auth_token}`,
      },
    });
    expect(ok.status).toBe(101);
    ok.webSocket?.accept();
    ok.webSocket?.close();
  });

  it("rejects another enrolled device's real token for a target device presence socket", async () => {
    const acct = testAccount("acct-auth-device-connect-scoped");
    const deviceA = await pairDevice(acct);
    const deviceB = await pairDevice(acct, "__________________________________________8");

    const crossDevice = await exports.default.fetch(
      relayUrl(acct, `/devices/${deviceA.device_id}/connect`),
      {
        headers: {
          Upgrade: "websocket",
          "Sec-WebSocket-Protocol": `allw.v1, allw.auth.${deviceB.device_auth_token}`,
        },
      },
    );
    expect(crossDevice.status).toBe(403);
  });

  it("fails closed when legacy device or request rows have no stored auth-token hash", async () => {
    const acct = testAccount("acct-auth-null-hash");
    const device = await pairDevice(acct);
    const submit = await post<SubmitResult>(
      acct,
      "/requests",
      makeEnvelope(rid("req-auth-null-hash")),
    );
    expect(submit.status).toBe(202);

    await runInDurableObject(
      env.ACCOUNT.get(env.ACCOUNT.idFromName(acct)),
      (relay: AccountRelay) => {
        relay["sql"].exec(
          `UPDATE device SET auth_token_hash = NULL WHERE device_id = ?`,
          device.device_id,
        );
        relay["sql"].exec(
          `UPDATE request SET auth_token_hash = NULL WHERE request_id = ?`,
          submit.data.request_id,
        );
      },
    );

    const connect = await exports.default.fetch(
      relayUrl(acct, `/devices/${device.device_id}/connect`),
      {
        headers: { Upgrade: "websocket" },
      },
    );
    expect(connect.status).toBe(401);

    const poll = await exports.default.fetch(relayUrl(acct, `/requests/${submit.data.request_id}`));
    expect(poll.status).toBe(401);

    const wait = await exports.default.fetch(
      relayUrl(acct, `/requests/${submit.data.request_id}/wait`),
      {
        headers: { Upgrade: "websocket" },
      },
    );
    expect(wait.status).toBe(401);
  });

  it("requires the per-request token for polling and wait sockets", async () => {
    const acct = testAccount("acct-auth-request-token");
    const submit = await post<SubmitResult>(acct, "/requests", makeEnvelope(rid("req-auth-token")));
    expect(submit.status).toBe(202);

    const noAuthPoll = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-auth-token")}`),
    );
    expect(noAuthPoll.status).toBe(401);

    const wrongAuthPoll = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-auth-token")}`),
      {
        headers: bearer("wrong-request-token"),
      },
    );
    expect(wrongAuthPoll.status).toBe(403);

    const okPoll = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-auth-token")}`),
      {
        headers: bearer(submit.data.request_auth_token),
      },
    );
    expect(okPoll.status).toBe(200);

    const noAuthWait = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-auth-token")}/wait`),
      {
        headers: { Upgrade: "websocket" },
      },
    );
    expect(noAuthWait.status).toBe(401);

    const wrongAuthWait = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-auth-token")}/wait`),
      {
        headers: {
          Upgrade: "websocket",
          "Sec-WebSocket-Protocol": `allw.v1, allw.auth.wrong-request-token`,
        },
      },
    );
    expect(wrongAuthWait.status).toBe(403);

    const okWait = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-auth-token")}/wait`),
      {
        headers: {
          Upgrade: "websocket",
          "Sec-WebSocket-Protocol": `allw.v1, allw.auth.${submit.data.request_auth_token}`,
        },
      },
    );
    expect(okWait.status).toBe(101);
    okWait.webSocket?.accept();
    okWait.webSocket?.close();
  });
});

// ---------------------------------------------------------------------------
// Where a bearer token may be presented (#303)
// ---------------------------------------------------------------------------

/**
 * One authenticated HTTP route, set up on a fresh account: the request to make and the token that
 * authorizes it. `ok` is the status the route returns when that token is sent as a header, so each
 * negative case also proves the 401 comes from where the token was presented, not from the request.
 */
interface QueryAuthCase {
  route: string;
  ok: number;
  setUp(accountId: string): Promise<{
    method: string;
    subPath: string;
    token: string;
    body?: Record<string, unknown>;
  }>;
}

const HTTP_QUERY_AUTH_CASES: readonly QueryAuthCase[] = [
  {
    route: "POST /pairing/complete",
    ok: 201,
    async setUp(acct) {
      const start = await post<PairingStartResult>(acct, "/pairing/start", pairingStartBody(acct));
      return {
        method: "POST",
        subPath: "/pairing/complete",
        token: start.data.pairing_auth_token,
        body: { code: start.data.code, pubkey: DEVICE_PUBKEY },
      };
    },
  },
  {
    route: "POST /actors",
    ok: 201,
    async setUp(acct) {
      const device = await pairDevice(acct);
      return {
        method: "POST",
        subPath: "/actors",
        token: device.device_auth_token,
        body: { actor_id: "actor-query-auth", pubkey: DEVICE_PUBKEY },
      };
    },
  },
  {
    route: "POST /devices/{id}/revoke",
    ok: 200,
    async setUp(acct) {
      const device = await pairDevice(acct);
      return {
        method: "POST",
        subPath: `/devices/${device.device_id}/revoke`,
        token: device.device_auth_token,
        body: {},
      };
    },
  },
  {
    route: "PUT /devices/{id}/push-tokens",
    ok: 200,
    async setUp(acct) {
      const device = await pairDevice(acct);
      return {
        method: "PUT",
        subPath: `/devices/${device.device_id}/push-tokens`,
        token: device.device_auth_token,
        body: { push_tokens: [] },
      };
    },
  },
  {
    route: "GET /devices/{id}/inbox",
    ok: 200,
    async setUp(acct) {
      const device = await pairDevice(acct);
      return {
        method: "GET",
        subPath: `/devices/${device.device_id}/inbox`,
        token: device.device_auth_token,
      };
    },
  },
  {
    route: "GET /requests/{id}",
    ok: 200,
    async setUp(acct) {
      const submit = await post<SubmitResult>(
        acct,
        "/requests",
        makeEnvelope(rid("req-query-get")),
      );
      return {
        method: "GET",
        subPath: `/requests/${submit.data.request_id}`,
        token: submit.data.request_auth_token,
      };
    },
  },
  {
    route: "POST /requests/{id}/retract",
    ok: 200,
    async setUp(acct) {
      const submit = await post<SubmitResult>(
        acct,
        "/requests",
        makeEnvelope(rid("req-query-retract")),
      );
      return {
        method: "POST",
        subPath: `/requests/${submit.data.request_id}/retract`,
        token: submit.data.request_auth_token,
        body: {},
      };
    },
  },
];

/** Send one route's request with the given extra headers, bypassing the auto-auth helpers. */
function rawFetch(
  accountId: string,
  call: { method: string; subPath: string; body?: Record<string, unknown> },
  headers: Record<string, string>,
): Promise<Response> {
  return exports.default.fetch(relayUrl(accountId, call.subPath), {
    method: call.method,
    headers: call.body === undefined ? headers : { "Content-Type": "application/json", ...headers },
    ...(call.body === undefined ? {} : { body: JSON.stringify(call.body) }),
  });
}

describe("AccountRelay — query credentials never authenticate (#251)", () => {
  // A token in a URL lands in access, proxy and CDN logs, browser history and Referer. Browsers
  // use credential protocol offers for WebSockets instead of accepting any query form.
  for (const c of HTTP_QUERY_AUTH_CASES) {
    it(`rejects a query-only token on ${c.route} with 401, and accepts the same token as a header`, async () => {
      const acct = testAccount(`acct-query-auth-${c.route.replace(/[^a-z]+/gi, "-")}`);
      const call = await c.setUp(acct);
      const withQuery = { ...call, subPath: appendAuthQuery(call.subPath, call.token) };

      const queryOnly = await rawFetch(acct, withQuery, {});
      expect(queryOnly.status).toBe(401);

      // Even a request claiming to be an upgrade does not unlock the query form on an HTTP route.
      // (Only GET routes can carry one: the runtime sends every upgrade request as a GET.)
      if (call.method === "GET") {
        const queryWithUpgrade = await rawFetch(acct, withQuery, { Upgrade: "websocket" });
        expect(queryWithUpgrade.status).toBe(401);
      }

      const header = await rawFetch(acct, call, bearer(call.token));
      expect(header.status).toBe(c.ok);
    });
  }

  it("refuses query-only credentials on both upgrade routes", async () => {
    const acct = testAccount("acct-query-auth-clean-break");
    const device = await pairDevice(acct);
    const submit = await post<SubmitResult>(
      acct,
      "/requests",
      makeEnvelope(rid("query-clean-break")),
    );
    for (const [path, token] of [
      [`/devices/${device.device_id}/connect`, device.device_auth_token],
      [`/requests/${submit.data.request_id}/wait`, submit.data.request_auth_token],
    ] as const) {
      const url = relayUrl(acct, appendAuthQuery(path, token));
      const response = await exports.default.fetch(url, { headers: { Upgrade: "websocket" } });
      expect(response.status).toBe(401);
    }
  });
});

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

describe("AccountRelay — routing negative paths", () => {
  it("rejects a submit missing context_ciphertext (400)", async () => {
    const acct = testAccount("acct-neg-noct");
    const body = makeEnvelope(rid("req-noct"));
    delete body.context_ciphertext;
    const { status } = await post(acct, "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects an envelope carrying an unexpected key (zero-knowledge guard) (400)", async () => {
    // A stray plaintext-looking field must be refused so it can never be persisted by the relay.
    const body = { ...makeEnvelope(rid("req-extra")), summary: "rm -rf / — please approve" };
    const { status } = await post(testAccount("acct-neg-extra"), "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit missing approver (400)", async () => {
    const body = makeEnvelope(rid("req-noappr"));
    delete body.approver;
    const { status } = await post(testAccount("acct-neg-noappr"), "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit missing v (400)", async () => {
    const body = makeEnvelope(rid("req-nov"));
    delete body.v;
    const { status } = await post(testAccount("acct-neg-nov"), "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit missing id (400)", async () => {
    const body = makeEnvelope("ignored");
    delete body.id;
    const { status } = await post(testAccount("acct-neg-noid"), "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit missing expires_at (400)", async () => {
    const body = makeEnvelope(rid("req-noexp"));
    delete body.expires_at;
    const { status } = await post(testAccount("acct-neg-noexp"), "/requests", body);
    expect(status).toBe(400);
  });

  it("rejects a submit whose expires_at is already in the past (400)", async () => {
    const { status } = await post(
      testAccount("acct-neg-expired"),
      "/requests",
      makeEnvelope(rid("req-expired"), { expires_at: 1 }),
    );
    expect(status).toBe(400);
  });

  it("rejects a duplicate request id (409)", async () => {
    const acct = testAccount("acct-neg-dup");
    const first = await post(acct, "/requests", makeEnvelope(rid("req-dup")));
    expect(first.status).toBe(202);
    const second = await post(acct, "/requests", makeEnvelope(rid("req-dup")));
    expect(second.status).toBe(409);
  });

  it("answers polling an unknown request as unauthorized, never 'not found' (#357)", async () => {
    const { status } = await get(testAccount("acct-neg-poll"), "/requests/does-not-exist");
    expect(status).toBe(401);
  });

  it("returns 404 connecting a WebSocket for an unenrolled device", async () => {
    const resp = await exports.default.fetch(
      relayUrl(testAccount("acct-neg-wsdev"), "/devices/ghost/connect"),
      {
        headers: { Upgrade: "websocket" },
      },
    );
    expect(resp.status).toBe(404);
  });

  it("returns 426 hitting a WebSocket route without an upgrade header", async () => {
    const acct = testAccount("acct-neg-noupgrade");
    const deviceId = await enrollDevice(acct);
    const connectResp = await exports.default.fetch(
      relayUrl(acct, `/devices/${deviceId}/connect`),
      {
        method: "GET",
      },
    );
    expect(connectResp.status).toBe(426);

    const waitResp = await exports.default.fetch(relayUrl(acct, "/requests/whatever/wait"), {
      method: "GET",
    });
    expect(waitResp.status).toBe(426);
  });

  it("sends an error over the socket for a verdict on an unknown request", async () => {
    const acct = testAccount("acct-neg-badverdict");
    const deviceId = await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    device.send({
      type: "verdict",
      request_id: "no-such-request",
      verdict: await makeVerdict(acct, "x"),
    });
    const err = await device.next();
    expect(err.type).toBe("error");
    expect(typeof err.error).toBe("string");
  });

  it("answers opening …/wait for an unknown request as unauthorized (#357)", async () => {
    const resp = await exports.default.fetch(
      relayUrl(testAccount("acct-neg-waitunknown"), "/requests/nope/wait"),
      {
        headers: { Upgrade: "websocket" },
      },
    );
    expect(resp.status).toBe(401);
  });

  it("rejects a degenerate (non-object) verdict value", async () => {
    const acct = testAccount("acct-neg-scalarverdict");
    const deviceId = await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    await post(acct, "/requests", makeEnvelope(rid("req-scalar")));
    await device.next();
    // A scalar the integrator could never JWS-verify must be refused before storage.
    device.send({ type: "verdict", request_id: rid("req-scalar"), verdict: 42 });
    const err = await device.next();
    expect(err.type).toBe("error");
    const polled = await get<{ status: string }>(acct, `/requests/${rid("req-scalar")}`);
    expect(polled.data.status).toBe("pending");
  });
});

// ---------------------------------------------------------------------------
// Fail-closed expiry (contract §Invariants #6)
// ---------------------------------------------------------------------------

describe("AccountRelay — fail-closed expiry", () => {
  it("refuses a verdict for an expired request and does not resolve it", async () => {
    const acct = testAccount("acct-exp-verdict");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    await seedExpiredRequest(acct, rid("req-exp-v"));

    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    device.send({
      type: "verdict",
      request_id: rid("req-exp-v"),
      verdict: await makeVerdict(acct, rid("req-exp-v")),
    });

    const ack = await device.next();
    expect(ack.type).toBe("ack");
    expect(ack.status).toBe("expired");

    // The request is terminal `expired`, NOT `resolved` — a timed-out request is never approvable.
    const polled = await get<{ status: string; verdict?: unknown }>(
      acct,
      `/requests/${rid("req-exp-v")}`,
    );
    expect(polled.data.status).toBe("expired");
    expect(polled.data.verdict).toBeUndefined();
  });

  it("does not re-flush a request that expired while queued", async () => {
    const acct = testAccount("acct-exp-flush");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    await seedExpiredRequest(acct, rid("req-exp-q"));

    // Connecting must NOT deliver the expired queued request.
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    await device.expectNothingPending();
  });

  it("lazy-expires on poll: a past-deadline pending request reports terminal 'expired'", async () => {
    const acct = testAccount("acct-exp-poll");
    await seedExpiredRequest(acct, rid("req-exp-p"));

    const polled = await get<{ status: string }>(acct, `/requests/${rid("req-exp-p")}`);
    expect(polled.status).toBe(200);
    expect(polled.data.status).toBe("expired");
  });

  it("lazy-expires on poll: retracts devices and wakes existing waiters", async () => {
    const acct = testAccount("acct-exp-poll-notify");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-exp-poll-notify")));
    expect((await device.next()).request_id).toBe(rid("req-exp-poll-notify"));

    const integrator = await connectWs(acct, `/requests/${rid("req-exp-poll-notify")}/wait`);
    await forceExpireRequest(acct, rid("req-exp-poll-notify"));

    const polled = await get<{ status: string }>(acct, `/requests/${rid("req-exp-poll-notify")}`);
    expect(polled.status).toBe(200);
    expect(polled.data.status).toBe("expired");

    const retract = await device.next();
    expect(retract.type).toBe("retract");
    expect(retract.request_id).toBe(rid("req-exp-poll-notify"));

    const expired = await integrator.next();
    expect(expired.type).toBe("expired");
    expect(expired.request_id).toBe(rid("req-exp-poll-notify"));
  });

  it("lazy-expires on …/wait: pushes terminal 'expired' and closes", async () => {
    const acct = testAccount("acct-exp-wait");
    await seedExpiredRequest(acct, rid("req-exp-w"));

    const integrator = await connectWs(acct, `/requests/${rid("req-exp-w")}/wait`);
    const msg = await integrator.next();
    expect(msg.type).toBe("expired");
    expect(msg.request_id).toBe(rid("req-exp-w"));
  });

  it("alarm proactively expires overdue pending requests, retracts devices, and wakes waiters", async () => {
    const acct = testAccount("acct-exp-alarm");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    const submit = await post(acct, "/requests", makeEnvelope(rid("req-exp-alarm")));
    expect(submit.status).toBe(202);
    expect((await device.next()).request_id).toBe(rid("req-exp-alarm"));

    const integrator = await connectWs(acct, `/requests/${rid("req-exp-alarm")}/wait`);

    await forceExpireAndRunAlarm(acct, rid("req-exp-alarm"));

    const retract = await device.next();
    expect(retract.type).toBe("retract");
    expect(retract.request_id).toBe(rid("req-exp-alarm"));

    const expired = await integrator.next();
    expect(expired.type).toBe("expired");
    expect(expired.request_id).toBe(rid("req-exp-alarm"));

    const status = await readRequestStatus(acct, rid("req-exp-alarm"));
    expect(status).toBe("expired");
  });

  it("alarm tracks the nearest pending expiry and clears itself when no pending work remains", async () => {
    const acct = testAccount("acct-exp-rearm");
    const firstExpiry = 4102444800000;
    const secondExpiry = firstExpiry + 60_000;
    await post(acct, "/requests", makeEnvelope(rid("req-exp-a"), { expires_at: firstExpiry }));
    await post(acct, "/requests", makeEnvelope(rid("req-exp-b"), { expires_at: secondExpiry }));

    expect(await readScheduledAlarm(acct)).toBe(firstExpiry);

    await forceExpireAndRunAlarm(acct, rid("req-exp-a"));
    expect(await readRequestStatus(acct, rid("req-exp-a"))).toBe("expired");
    expect(await readScheduledAlarm(acct)).toBe(secondExpiry);

    await forceExpireAndRunAlarm(acct, rid("req-exp-b"));
    expect(await readRequestStatus(acct, rid("req-exp-b"))).toBe("expired");
    expect(await readScheduledAlarm(acct)).toBeNull();
  });

  it("alarm retention sweep deletes old terminal rows and their verdicts", async () => {
    const acct = testAccount("acct-exp-retention");
    await seedOldTerminalRows(acct);

    await runAlarm(acct);

    const rows = await listRequestAndVerdictIds(acct);
    expect(rows.requests).toEqual([rid("req-fresh-expired"), rid("req-fresh-resolved")].sort());
    expect(rows.verdicts).toEqual([rid("req-fresh-resolved")]);
  });

  it("refuses a verdict from a device whose enrollment was removed", async () => {
    const acct = testAccount("acct-exp-revoked");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-rev-1")));
    await device.next(); // request push

    // A genuine verdict, signed while the device was still enrolled.
    const verdict = await makeVerdict(acct, rid("req-rev-1"));
    // Simulate a revoke whose hibernation socket outlived the best-effort close.
    await deleteDeviceRow(acct, deviceId);
    device.send({ type: "verdict", request_id: rid("req-rev-1"), verdict });

    const err = await device.next();
    expect(err.type).toBe("error");

    // A de-enrolled device must not drive resolution — the request stays pending.
    const polled = await get<{ status: string }>(acct, `/requests/${rid("req-rev-1")}`);
    expect(polled.data.status).toBe("pending");
  });
});

// ---------------------------------------------------------------------------
// One deadline for every lifecycle path (#292)
// ---------------------------------------------------------------------------

/**
 * The horizon these tests lower the relay to after a submit: two minutes, under the five minutes
 * between {@link RELAY_NOW} and {@link FUTURE_EXPIRES_AT}. This is an operator lowering
 * `MAX_REQUEST_TTL_MS` while requests are pending. A request received at `RELAY_NOW` then has a
 * horizon deadline ({@link HORIZON_DEADLINE}) three minutes before its `expires_at`.
 */
const LOWERED_HORIZON_MS = 2 * 60_000;
/** `created_at + LOWERED_HORIZON_MS` for a request the relay received at {@link RELAY_NOW}. */
const HORIZON_DEADLINE = RELAY_NOW + LOWERED_HORIZON_MS;

describe("AccountRelay — one deadline for every lifecycle path (#292)", () => {
  /**
   * Each test holds a request past its horizon deadline but before its `expires_at`, on a pinned
   * clock, and checks that one path neither delivers nor resolves it. Before #292 the inbox, the
   * reconnect flush, lazy expiry (poll, wait, retract), verdict acceptance and the wakeup deadline
   * all read `expires_at` alone, so such a row stayed live on them while the alarm expired it.
   */
  function stubFor(accountId: string): DurableObjectStub<AccountRelay> {
    return env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  }

  /** Lower the account's request horizon, as a redeploy with a smaller `MAX_REQUEST_TTL_MS` would. */
  async function lowerHorizon(accountId: string): Promise<void> {
    await runInDurableObject(stubFor(accountId), (instance: AccountRelay) => {
      instance["maxRequestTtlMs"] = LOWERED_HORIZON_MS;
    });
  }

  /**
   * Submit `requestId` at {@link RELAY_NOW} (expiring at {@link FUTURE_EXPIRES_AT}), then lower the
   * horizon. The relay's clock stays at `RELAY_NOW`; each test moves it.
   */
  async function submitThenLowerHorizon(accountId: string, requestId: string): Promise<void> {
    const submit = await post<SubmitResult>(accountId, "/requests", makeEnvelope(requestId));
    expect(submit.status).toBe(202);
    await lowerHorizon(accountId);
  }

  async function storedVerdictCount(accountId: string, requestId: string): Promise<number> {
    return runInDurableObject(stubFor(accountId), (relay: AccountRelay) => {
      return [...relay["sql"].exec(`SELECT 1 FROM verdict WHERE request_id = ?`, requestId)].length;
    });
  }

  it("submit: a wakeup's deadline ignores a pending request past its horizon deadline", async () => {
    const acct = testAccount("acct-deadline-submit");
    await pairDeviceWithPushToken(acct);
    const wakeups: PushWakeup[] = [];
    await installPushTransports(acct, { apns: recordingTransport("apns", wakeups) });
    await submitThenLowerHorizon(acct, rid("req-deadline-submit-old"));
    await vi.waitFor(() => {
      expect(wakeups).toHaveLength(1);
    });

    // Past the coalescing window, and at the old request's horizon deadline.
    await pinRelayClock(acct, HORIZON_DEADLINE);
    const freshExpiresAt = HORIZON_DEADLINE + 60_000;
    const submit = await post<SubmitResult>(acct, "/requests", {
      ...makeEnvelope(rid("req-deadline-submit-new")),
      // Inside the lowered horizon's `created_at` bound.
      created_at: HORIZON_DEADLINE,
      expires_at: freshExpiresAt,
    });
    expect(submit.status).toBe(202);
    expect(submit.data.push_wakeups).toBe(1);
    await vi.waitFor(() => {
      expect(wakeups).toHaveLength(2);
    });
    // The old request's `expires_at` (FUTURE_EXPIRES_AT) is later, but it is no longer live.
    expect(wakeups[1]).toMatchObject({
      requestId: rid("req-deadline-submit-new"),
      expiresAt: freshExpiresAt,
    });
  });

  it("submit: refuses a request whose deadline is now", async () => {
    const acct = testAccount("acct-deadline-submit-now");
    await submitThenLowerHorizon(acct, rid("req-deadline-submit-now-a"));
    await pinRelayClock(acct, RELAY_NOW);
    const refused = await post<{ error: string }>(acct, "/requests", {
      ...makeEnvelope(rid("req-deadline-submit-now-b")),
      expires_at: RELAY_NOW,
    });
    expect(refused.status).toBe(400);
    expect(refused.data.error).toBe("request already expired");
  });

  it("alarm: arms at the horizon deadline, not at expires_at", async () => {
    const acct = testAccount("acct-deadline-alarm");
    await submitThenLowerHorizon(acct, rid("req-deadline-alarm"));
    expect(await readScheduledAlarm(acct)).toBe(FUTURE_EXPIRES_AT);

    // Any firing re-arms request expiry from the stored rows, now under the lowered horizon.
    await runAlarm(acct);
    expect(await readScheduledAlarm(acct)).toBe(HORIZON_DEADLINE);
  });

  it("sweep: expires the request at its horizon deadline, and not 1 ms before", async () => {
    const acct = testAccount("acct-deadline-sweep");
    const deviceId = await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    await submitThenLowerHorizon(acct, rid("req-deadline-sweep"));
    expect((await device.next()).request_id).toBe(rid("req-deadline-sweep"));
    const integrator = await connectWs(acct, `/requests/${rid("req-deadline-sweep")}/wait`);

    await pinRelayClock(acct, HORIZON_DEADLINE - 1);
    await runAlarm(acct);
    expect(await readRequestStatus(acct, rid("req-deadline-sweep"))).toBe("pending");
    await device.expectNothingPending();

    await pinRelayClock(acct, HORIZON_DEADLINE);
    await runAlarm(acct);
    expect(await readRequestStatus(acct, rid("req-deadline-sweep"))).toBe("expired");
    expect(await device.next()).toEqual({ type: "retract", request_id: rid("req-deadline-sweep") });
    expect(await integrator.next()).toEqual({
      type: "expired",
      request_id: rid("req-deadline-sweep"),
    });
  });

  it("inbox: omits the request at its horizon deadline, lists it 1 ms before", async () => {
    const acct = testAccount("acct-deadline-inbox");
    const deviceId = await enrollDevice(acct);
    await submitThenLowerHorizon(acct, rid("req-deadline-inbox"));
    const inboxIds = async (): Promise<unknown[]> => {
      const resp = await get<{ envelopes: Record<string, unknown>[] }>(
        acct,
        `/devices/${deviceId}/inbox`,
        bearer(deviceAuthTokens.get(tokenKey(acct, deviceId)) ?? ""),
      );
      expect(resp.status).toBe(200);
      return resp.data.envelopes.map((e) => e.id);
    };

    await pinRelayClock(acct, HORIZON_DEADLINE - 1);
    expect(await inboxIds()).toEqual([rid("req-deadline-inbox")]);
    await pinRelayClock(acct, HORIZON_DEADLINE);
    expect(await inboxIds()).toEqual([]);
  });

  it("flush: a reconnect at the horizon deadline does not deliver the request", async () => {
    const acct = testAccount("acct-deadline-flush");
    const deviceId = await enrollDevice(acct);
    await submitThenLowerHorizon(acct, rid("req-deadline-flush"));

    await pinRelayClock(acct, HORIZON_DEADLINE - 1);
    const before = await connectWs(acct, `/devices/${deviceId}/connect`);
    expect((await before.next()).request_id).toBe(rid("req-deadline-flush"));

    await pinRelayClock(acct, HORIZON_DEADLINE);
    const after = await connectWs(acct, `/devices/${deviceId}/connect`);
    await after.expectNothingPending();
  });

  it("poll: lazy-expires the request at its horizon deadline", async () => {
    const acct = testAccount("acct-deadline-poll");
    await submitThenLowerHorizon(acct, rid("req-deadline-poll"));

    await pinRelayClock(acct, HORIZON_DEADLINE - 1);
    expect(
      (await get<{ status: string }>(acct, `/requests/${rid("req-deadline-poll")}`)).data,
    ).toMatchObject({ status: "pending" });
    await pinRelayClock(acct, HORIZON_DEADLINE);
    expect(
      (await get<{ status: string }>(acct, `/requests/${rid("req-deadline-poll")}`)).data,
    ).toMatchObject({ status: "expired" });
    expect(await readRequestStatus(acct, rid("req-deadline-poll"))).toBe("expired");
  });

  it("wait: a waiter that connects at the horizon deadline is told 'expired'", async () => {
    const acct = testAccount("acct-deadline-wait");
    await submitThenLowerHorizon(acct, rid("req-deadline-wait"));

    await pinRelayClock(acct, HORIZON_DEADLINE);
    const waiter = await connectWs(acct, `/requests/${rid("req-deadline-wait")}/wait`);
    expect(await waiter.next()).toEqual({ type: "expired", request_id: rid("req-deadline-wait") });
    expect(await readRequestStatus(acct, rid("req-deadline-wait"))).toBe("expired");
  });

  it("retract: 409 'already expired' at the horizon deadline", async () => {
    const acct = testAccount("acct-deadline-retract");
    await submitThenLowerHorizon(acct, rid("req-deadline-retract"));

    await pinRelayClock(acct, HORIZON_DEADLINE);
    const retract = await post<{ error: string }>(
      acct,
      `/requests/${rid("req-deadline-retract")}/retract`,
      {},
    );
    expect(retract.status).toBe(409);
    expect(retract.data.error).toBe("request already expired");
    expect(await readRequestStatus(acct, rid("req-deadline-retract"))).toBe("expired");
  });

  it("verdict: a genuine verdict at the horizon deadline is acked 'expired' and not recorded", async () => {
    const acct = testAccount("acct-deadline-verdict");
    const deviceId = await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    await submitThenLowerHorizon(acct, rid("req-deadline-verdict"));
    expect((await device.next()).request_id).toBe(rid("req-deadline-verdict"));

    await pinRelayClock(acct, HORIZON_DEADLINE);
    device.send({
      type: "verdict",
      request_id: rid("req-deadline-verdict"),
      verdict: await makeVerdict(acct, rid("req-deadline-verdict")),
    });
    expect(await device.next()).toEqual({
      type: "ack",
      request_id: rid("req-deadline-verdict"),
      status: "expired",
    });
    expect(await readRequestStatus(acct, rid("req-deadline-verdict"))).toBe("expired");
    expect(await storedVerdictCount(acct, rid("req-deadline-verdict"))).toBe(0);
  });

  it("at exactly expires_at: poll reports 'expired' and a verdict is refused", async () => {
    // The boundary every path shares: live strictly before the deadline, expired at it. Poll and
    // verdict acceptance used to keep a request live at exactly `expires_at`.
    const acct = testAccount("acct-deadline-expires-at");
    const deviceId = await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    const pollId = rid("req-deadline-at-poll");
    const verdictId = rid("req-deadline-at-verdict");
    const expiresAt = RELAY_NOW + 60_000;
    for (const id of [pollId, verdictId]) {
      expect(
        (await post(acct, "/requests", { ...makeEnvelope(id), expires_at: expiresAt })).status,
      ).toBe(202);
      expect((await device.next()).request_id).toBe(id);
    }

    await pinRelayClock(acct, expiresAt);
    expect((await get<{ status: string }>(acct, `/requests/${pollId}`)).data).toMatchObject({
      status: "expired",
    });
    expect(await device.next()).toEqual({ type: "retract", request_id: pollId });
    device.send({
      type: "verdict",
      request_id: verdictId,
      verdict: await makeVerdict(acct, verdictId),
    });
    expect(await device.next()).toEqual({ type: "ack", request_id: verdictId, status: "expired" });
    expect(await storedVerdictCount(acct, verdictId)).toBe(0);
  });

  it("verdict: accepted 1 ms before the horizon deadline", async () => {
    const acct = testAccount("acct-deadline-verdict-before");
    const deviceId = await enrollDevice(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    await submitThenLowerHorizon(acct, rid("req-deadline-verdict-before"));
    expect((await device.next()).request_id).toBe(rid("req-deadline-verdict-before"));

    await pinRelayClock(acct, HORIZON_DEADLINE - 1);
    device.send({
      type: "verdict",
      request_id: rid("req-deadline-verdict-before"),
      verdict: await makeVerdict(acct, rid("req-deadline-verdict-before")),
    });
    expect(await device.next()).toMatchObject({ type: "ack", status: "resolved" });
    expect(await storedVerdictCount(acct, rid("req-deadline-verdict-before"))).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Integrator-initiated retract (issue #195) — NOT a verdict, distinct from `expired`
// ---------------------------------------------------------------------------

describe("AccountRelay — retract (issue #195)", () => {
  it("retracts a pending request: terminal 'retracted', no verdict, distinct from expired", async () => {
    const acct = testAccount("acct-retract-basic");
    const submit = await post<SubmitResult>(
      acct,
      "/requests",
      makeEnvelope(rid("req-retract-basic")),
    );
    expect(submit.status).toBe(202);

    const retract = await post<{ request_id: string; status: string }>(
      acct,
      `/requests/${rid("req-retract-basic")}/retract`,
      {},
    );
    expect(retract.status).toBe(200);
    expect(retract.data.status).toBe("retracted");

    const polled = await get<{ status: string; verdict?: unknown }>(
      acct,
      `/requests/${rid("req-retract-basic")}`,
    );
    expect(polled.data.status).toBe("retracted");
    expect(polled.data.status).not.toBe("expired");
    expect(polled.data.verdict).toBeUndefined();
  });

  it("clears the pending prompt from connected devices (reuses the {type:'retract'} fan-out)", async () => {
    const acct = testAccount("acct-retract-devices");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-retract-devices")));
    expect((await device.next()).type).toBe("request");

    await post(acct, `/requests/${rid("req-retract-devices")}/retract`, {});

    const retract = await device.next();
    expect(retract.type).toBe("retract");
    expect(retract.request_id).toBe(rid("req-retract-devices"));
  });

  it("pushes {type:'retracted'} to a live integrator wait socket and closes it", async () => {
    const acct = testAccount("acct-retract-wait-live");
    await post(acct, "/requests", makeEnvelope(rid("req-retract-wait-live")));
    const integrator = await connectWs(acct, `/requests/${rid("req-retract-wait-live")}/wait`);

    await post(acct, `/requests/${rid("req-retract-wait-live")}/retract`, {});

    const msg = await integrator.next();
    expect(msg.type).toBe("retracted");
    expect(msg.request_id).toBe(rid("req-retract-wait-live"));
  });

  it("…/wait opened AFTER a retract immediately reports 'retracted' and closes (symmetric with expired)", async () => {
    const acct = testAccount("acct-retract-wait-late");
    await post(acct, "/requests", makeEnvelope(rid("req-retract-wait-late")));
    await post(acct, `/requests/${rid("req-retract-wait-late")}/retract`, {});

    const integrator = await connectWs(acct, `/requests/${rid("req-retract-wait-late")}/wait`);
    const msg = await integrator.next();
    expect(msg.type).toBe("retracted");
    expect(msg.request_id).toBe(rid("req-retract-wait-late"));
  });

  it("is idempotent: retracting an already-retracted request succeeds (200)", async () => {
    const acct = testAccount("acct-retract-idempotent");
    await post(acct, "/requests", makeEnvelope(rid("req-retract-idempotent")));
    const first = await post<{ status: string }>(
      acct,
      `/requests/${rid("req-retract-idempotent")}/retract`,
      {},
    );
    expect(first.status).toBe(200);

    const second = await post<{ status: string }>(
      acct,
      `/requests/${rid("req-retract-idempotent")}/retract`,
      {},
    );
    expect(second.status).toBe(200);
    expect(second.data.status).toBe("retracted");
  });

  it("refuses a device verdict for an already-retracted request (retract is not overridable)", async () => {
    const acct = testAccount("acct-retract-then-verdict");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-retract-then-verdict")));
    await device.next(); // request push
    await post(acct, `/requests/${rid("req-retract-then-verdict")}/retract`, {});
    await device.next(); // the cross-device retract fan-out

    device.send({
      type: "verdict",
      request_id: rid("req-retract-then-verdict"),
      verdict: await makeVerdict(acct, rid("req-retract-then-verdict")),
    });
    const ack = await device.next();
    expect(ack.type).toBe("ack");
    expect(ack.status).toBe("retracted");

    // A late verdict must never resurrect a retracted request as resolved.
    const polled = await get<{ status: string; verdict?: unknown }>(
      acct,
      `/requests/${rid("req-retract-then-verdict")}`,
    );
    expect(polled.data.status).toBe("retracted");
    expect(polled.data.verdict).toBeUndefined();
  });

  it("SECURITY: refuses to retract a request that already resolved — the recorded verdict stands (409)", async () => {
    const acct = testAccount("acct-retract-vs-resolved");
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope(rid("req-retract-vs-resolved")));
    await device.next();
    const winning = await makeVerdict(acct, rid("req-retract-vs-resolved"), "approved");
    device.send({ type: "verdict", request_id: rid("req-retract-vs-resolved"), verdict: winning });
    expect((await device.next()).status).toBe("resolved");

    const retract = await post<{ error: string }>(
      acct,
      `/requests/${rid("req-retract-vs-resolved")}/retract`,
      {},
    );
    expect(retract.status).toBe(409);

    // A retract that lost the race must never discard the already-recorded human decision.
    const polled = await get<{ status: string; verdict: Record<string, unknown> }>(
      acct,
      `/requests/${rid("req-retract-vs-resolved")}`,
    );
    expect(polled.data.status).toBe("resolved");
    expect(polled.data.verdict).toEqual(winning);
  });

  it("SECURITY: refuses to retract an already-expired request (409)", async () => {
    const acct = testAccount("acct-retract-vs-expired");
    await seedExpiredRequest(acct, rid("req-retract-vs-expired"));

    const retract = await post<{ error: string }>(
      acct,
      `/requests/${rid("req-retract-vs-expired")}/retract`,
      {},
    );
    expect(retract.status).toBe(409);

    const polled = await get<{ status: string }>(
      acct,
      `/requests/${rid("req-retract-vs-expired")}`,
    );
    expect(polled.data.status).toBe("expired");
  });

  it("SECURITY: refuses retracting an unknown request as unauthorized (#357)", async () => {
    const { status } = await post(
      testAccount("acct-retract-unknown"),
      "/requests/does-not-exist/retract",
      {},
    );
    expect(status).toBe(401);
  });

  it("SECURITY: requires the per-request token, scoped to exactly that request (no cross-request retract)", async () => {
    const acct = testAccount("acct-retract-auth-scoped");
    const submitA = await post<SubmitResult>(
      acct,
      "/requests",
      makeEnvelope(rid("req-retract-auth-a")),
    );
    const submitB = await post<SubmitResult>(
      acct,
      "/requests",
      makeEnvelope(rid("req-retract-auth-b")),
    );
    expect(submitA.status).toBe(202);
    expect(submitB.status).toBe(202);

    const noAuth = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-retract-auth-a")}/retract`),
      {
        method: "POST",
      },
    );
    expect(noAuth.status).toBe(401);

    const wrongAuth = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-retract-auth-a")}/retract`),
      {
        method: "POST",
        headers: bearer("wrong-request-token"),
      },
    );
    expect(wrongAuth.status).toBe(403);

    // An integrator holding a REAL, currently-valid token for a DIFFERENT request must not be able
    // to retract this one — the token is scoped to exactly the request it was issued for (#195).
    const crossRequest = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-retract-auth-a")}/retract`),
      {
        method: "POST",
        headers: bearer(submitB.data.request_auth_token),
      },
    );
    expect(crossRequest.status).toBe(403);

    const ok = await post<{ status: string }>(
      acct,
      `/requests/${rid("req-retract-auth-a")}/retract`,
      {},
    );
    expect(ok.status).toBe(200);

    // The OTHER request is unaffected by the cross-scoped attempt above.
    const stillPendingB = await get<{ status: string }>(
      acct,
      `/requests/${rid("req-retract-auth-b")}`,
    );
    expect(stillPendingB.data.status).toBe("pending");
  });

  it("returns 405 retracting via the wrong method", async () => {
    const acct = testAccount("acct-retract-method");
    await post(acct, "/requests", makeEnvelope(rid("req-retract-method")));
    const resp = await exports.default.fetch(
      relayUrl(acct, `/requests/${rid("req-retract-method")}/retract`),
      {
        method: "GET",
        headers: bearer(requestAuthTokens.get(tokenKey(acct, rid("req-retract-method"))) ?? ""),
      },
    );
    expect(resp.status).toBe(405);
  });
});

// ---------------------------------------------------------------------------
// Device inbox (HTTP polling — issue #147)
// ---------------------------------------------------------------------------

describe("AccountRelay — device inbox (HTTP poll)", () => {
  it("returns pending envelopes for the authenticated device", async () => {
    const acct = testAccount("acct-inbox-basic");
    const device = await pairDevice(acct);
    const token = device.device_auth_token;
    const envA = makeEnvelope(rid("req-inbox-a"));
    const envB = makeEnvelope(rid("req-inbox-b"));
    await post(acct, "/requests", envA);
    await post(acct, "/requests", envB);

    const resp = await get<{ envelopes: Record<string, unknown>[] }>(
      acct,
      `/devices/${device.device_id}/inbox`,
      bearer(token),
    );
    expect(resp.status).toBe(200);
    const ids = resp.data.envelopes.map((e) => e.id);
    expect(ids).toContain(rid("req-inbox-a"));
    expect(ids).toContain(rid("req-inbox-b"));
    // Zero-knowledge: only relay-visible envelope fields, never plaintext context
    for (const env of resp.data.envelopes) {
      const keys = Object.keys(env);
      expect(keys).not.toContain("action");
      expect(keys).not.toContain("summary");
      expect(keys).not.toContain("actor");
      expect(keys).toContain("context_ciphertext");
    }
  });

  it("excludes resolved and expired requests from the inbox", async () => {
    const acct = testAccount("acct-inbox-exclude");
    const device = await pairDevice(acct);
    const token = device.device_auth_token;

    // Submit two requests; resolve one via the WebSocket.
    await post(acct, "/requests", makeEnvelope(rid("req-exclude-pending")));
    await post(acct, "/requests", makeEnvelope(rid("req-exclude-resolved")));
    const wsDevice = await connectWs(acct, `/devices/${device.device_id}/connect`);
    // drain both offline-queue messages
    await wsDevice.next();
    await wsDevice.next();
    wsDevice.send({
      type: "verdict",
      request_id: rid("req-exclude-resolved"),
      verdict: await makeVerdict(acct, rid("req-exclude-resolved")),
    });
    await wsDevice.next(); // ack

    const resp = await get<{ envelopes: Record<string, unknown>[] }>(
      acct,
      `/devices/${device.device_id}/inbox`,
      bearer(token),
    );
    expect(resp.status).toBe(200);
    const ids = resp.data.envelopes.map((e) => e.id);
    expect(ids).toContain(rid("req-exclude-pending"));
    expect(ids).not.toContain(rid("req-exclude-resolved"));
  });

  it("excludes already-expired requests from the inbox (fail-closed)", async () => {
    const acct = testAccount("acct-inbox-expired");
    const device = await pairDevice(acct);
    const token = device.device_auth_token;

    // Seed an expired request directly (POST /requests rejects already-expired).
    await seedExpiredRequest(acct, rid("req-inbox-already-expired"));
    // Submit a live request.
    await post(acct, "/requests", makeEnvelope(rid("req-inbox-live")));

    const resp = await get<{ envelopes: Record<string, unknown>[] }>(
      acct,
      `/devices/${device.device_id}/inbox`,
      bearer(token),
    );
    expect(resp.status).toBe(200);
    const ids = resp.data.envelopes.map((e) => e.id);
    expect(ids).not.toContain(rid("req-inbox-already-expired"));
    expect(ids).toContain(rid("req-inbox-live"));
  });

  it("returns 401 without a bearer token", async () => {
    const acct = testAccount("acct-inbox-noauth");
    const device = await pairDevice(acct);

    const resp = await exports.default.fetch(relayUrl(acct, `/devices/${device.device_id}/inbox`), {
      method: "GET",
    });
    expect(resp.status).toBe(401);
  });

  it("returns 403 with a wrong bearer token", async () => {
    const acct = testAccount("acct-inbox-wrongauth");
    const device = await pairDevice(acct);

    const resp = await exports.default.fetch(relayUrl(acct, `/devices/${device.device_id}/inbox`), {
      method: "GET",
      headers: { Authorization: "Bearer wrong-token" },
    });
    expect(resp.status).toBe(403);
  });

  it("returns 404 for an unenrolled device id", async () => {
    const acct = testAccount("acct-inbox-notfound");
    await pairDevice(acct);

    const resp = await exports.default.fetch(relayUrl(acct, `/devices/not-a-real-device/inbox`), {
      method: "GET",
      headers: { Authorization: "Bearer any-token" },
    });
    expect(resp.status).toBe(404);
  });

  it("405 on POST to the inbox route", async () => {
    const acct = testAccount("acct-inbox-405");
    const device = await pairDevice(acct);
    const token = device.device_auth_token;

    const resp = await exports.default.fetch(relayUrl(acct, `/devices/${device.device_id}/inbox`), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: "{}",
    });
    expect(resp.status).toBe(405);
  });

  it("returns an empty array when no pending requests exist", async () => {
    const acct = testAccount("acct-inbox-empty");
    const device = await pairDevice(acct);
    const token = device.device_auth_token;

    const resp = await get<{ envelopes: unknown[] }>(
      acct,
      `/devices/${device.device_id}/inbox`,
      bearer(token),
    );
    expect(resp.status).toBe(200);
    expect(resp.data.envelopes).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Helpers that need a live DO query
// ---------------------------------------------------------------------------

/** Read back the single enrolled device's id via the registry (used to build the connect URL). */
async function firstDeviceId(accountId: string): Promise<string> {
  const { data } = await get<{ devices: { device_id: string }[] }>(accountId, "/devices");
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
  const requestAuthToken = `expired-request-token-${requestId}`;
  const requestAuthTokenHash = await testAuthTokenHash(requestAuthToken);
  requestAuthTokens.set(tokenKey(accountId, requestId), requestAuthToken);
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (relay: AccountRelay) => {
    relay["sql"].exec(
      `INSERT OR REPLACE INTO request
       (request_id, envelope, created_at, expires_at, status, terminal_at, auth_token_hash)
       VALUES (?, ?, ?, ?, 'pending', NULL, ?)`,
      requestId,
      JSON.stringify(envelope),
      CREATED_AT,
      PAST_EXPIRES_AT,
      requestAuthTokenHash,
    );
  });
  return envelope;
}

async function runAlarm(accountId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, async (instance: AccountRelay) => {
    await instance.alarm();
  });
}

async function forceExpireAndRunAlarm(accountId: string, requestId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, async (relay: AccountRelay) => {
    relay["sql"].exec(
      `UPDATE request SET expires_at = ? WHERE request_id = ?`,
      PAST_EXPIRES_AT,
      requestId,
    );
    await relay.alarm();
  });
}

async function forceExpireRequest(accountId: string, requestId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (relay: AccountRelay) => {
    relay["sql"].exec(
      `UPDATE request SET expires_at = ? WHERE request_id = ?`,
      PAST_EXPIRES_AT,
      requestId,
    );
  });
}

async function readScheduledAlarm(accountId: string): Promise<number | null> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, async (relay: AccountRelay) => {
    return relay["ctx"].storage.getAlarm();
  });
}

async function readRequestStatus(accountId: string, requestId: string): Promise<string | null> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, (relay: AccountRelay) => {
    const rows = [
      ...relay["sql"].exec<{ status: string }>(
        `SELECT status FROM request WHERE request_id = ?`,
        requestId,
      ),
    ];
    return rows[0]?.status ?? null;
  });
}

async function seedOldTerminalRows(accountId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (relay: AccountRelay) => {
    const rows = [
      {
        request_id: rid("req-old-expired"),
        envelope: makeEnvelope(rid("req-old-expired"), { expires_at: OLD_TERMINAL_AT }),
        created_at: OLD_TERMINAL_AT - 1000,
        expires_at: OLD_TERMINAL_AT,
        status: "expired",
        terminal_at: OLD_TERMINAL_AT,
      },
      {
        request_id: rid("req-fresh-expired"),
        envelope: makeEnvelope(rid("req-fresh-expired")),
        created_at: CREATED_AT,
        expires_at: FUTURE_EXPIRES_AT,
        status: "expired",
        terminal_at: FUTURE_EXPIRES_AT,
      },
      {
        request_id: rid("req-old-resolved"),
        envelope: makeEnvelope(rid("req-old-resolved"), { expires_at: OLD_TERMINAL_AT }),
        created_at: OLD_TERMINAL_AT - 1000,
        expires_at: OLD_TERMINAL_AT,
        status: "resolved",
        terminal_at: OLD_TERMINAL_AT,
      },
      {
        request_id: rid("req-fresh-resolved"),
        envelope: makeEnvelope(rid("req-fresh-resolved")),
        created_at: CREATED_AT,
        expires_at: FUTURE_EXPIRES_AT,
        status: "resolved",
        terminal_at: FUTURE_EXPIRES_AT,
      },
    ];
    for (const row of rows) {
      relay["sql"].exec(
        `INSERT OR REPLACE INTO request
         (request_id, envelope, created_at, expires_at, status, terminal_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        row.request_id,
        JSON.stringify(row.envelope),
        row.created_at,
        row.expires_at,
        row.status,
        row.terminal_at,
      );
    }
    relay["sql"].exec(
      `INSERT OR REPLACE INTO verdict (request_id, verdict, device_id, received_at)
       VALUES (?, ?, ?, ?)`,
      rid("req-old-resolved"),
      JSON.stringify({ request_id: rid("req-old-resolved"), sig: "stored-verdict" }),
      "dev-old",
      OLD_TERMINAL_AT,
    );
    relay["sql"].exec(
      `INSERT OR REPLACE INTO verdict (request_id, verdict, device_id, received_at)
       VALUES (?, ?, ?, ?)`,
      rid("req-fresh-resolved"),
      JSON.stringify({ request_id: rid("req-fresh-resolved"), sig: "stored-verdict" }),
      "dev-fresh",
      FUTURE_EXPIRES_AT,
    );
  });
}

async function listRequestAndVerdictIds(
  accountId: string,
): Promise<{ requests: string[]; verdicts: string[] }> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, (relay: AccountRelay) => {
    const requests = [
      ...relay["sql"].exec<{ request_id: string }>(
        `SELECT request_id FROM request ORDER BY request_id ASC`,
      ),
    ].map((row) => row.request_id);
    const verdicts = [
      ...relay["sql"].exec<{ request_id: string }>(
        `SELECT request_id FROM verdict ORDER BY request_id ASC`,
      ),
    ].map((row) => row.request_id);
    return { requests, verdicts };
  });
}

/** Delete a device row directly — simulates a revoke whose hibernation socket outlived the close. */
async function deleteDeviceRow(accountId: string, deviceId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (relay: AccountRelay) => {
    relay["sql"].exec(`DELETE FROM device WHERE device_id = ?`, deviceId);
  });
}
