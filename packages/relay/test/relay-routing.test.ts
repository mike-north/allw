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
import { describe, it, expect, vi } from "vitest";
import { AccountRelay } from "../src/index.js";
import type { PushTransportRegistry } from "../src/push.js";
import type { SqlStorage } from "@cloudflare/workers-types";

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
  headers: Record<string, string> = {},
): Promise<{ status: number; data: T }> {
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
  const resp = await SELF.fetch(relayUrl(accountId, subPath), {
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
  const resp = await SELF.fetch(relayUrl(accountId, subPath), {
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
  const start = await post<PairingStartResult>(accountId, "/pairing/start", {});
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
  const start = await post<PairingStartResult>(accountId, "/pairing/start", {});
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

async function installPushTransports(
  accountId: string,
  pushTransports: PushTransportRegistry,
): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    (instance as unknown as { pushTransports: PushTransportRegistry }).pushTransports =
      pushTransports;
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
  send(obj: unknown): void;
  raw: WebSocket;
}

/**
 * Open a WebSocket to the relay. The message listener is attached BEFORE `accept()` so that
 * server pushes emitted during the upgrade (offline-queue flush, immediate verdict) are not missed.
 * Returns the 101 client wrapped in a queue-backed reader, or throws on a non-101 response.
 */
async function connectWs(accountId: string, subPath: string): Promise<WsClient> {
  let authedSubPath = subPath;
  const deviceMatch = /^\/devices\/([^/?]+)\/connect(?:\?(.+))?$/.exec(subPath);
  const waitMatch = /^\/requests\/([^/?]+)\/wait(?:\?(.+))?$/.exec(subPath);
  if (deviceMatch && !new URLSearchParams(deviceMatch[2] ?? "").has("auth")) {
    const token = deviceAuthTokens.get(
      tokenKey(accountId, decodeURIComponent(deviceMatch[1] ?? "")),
    );
    if (token !== undefined) authedSubPath = appendAuthQuery(subPath, token);
  } else if (waitMatch && !new URLSearchParams(waitMatch[2] ?? "").has("auth")) {
    const token = requestAuthTokens.get(
      tokenKey(accountId, decodeURIComponent(waitMatch[1] ?? "")),
    );
    if (token !== undefined) authedSubPath = appendAuthQuery(subPath, token);
  }
  const resp = await SELF.fetch(relayUrl(accountId, authedSubPath), {
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
  it("submitting a request schedules request-id-only push wakeups for registered tokens", async () => {
    const acct = "acct-push-wakeup";
    const start = await post<PairingStartResult>(acct, "/pairing/start", {});
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

    const submit = await post<{
      delivered_to: number;
      push_wakeups: number;
      status: string;
    }>(acct, "/requests", makeEnvelope("req-push-wakeup"));

    expect(submit.status).toBe(202);
    expect(submit.data.status).toBe("pending");
    expect(submit.data.delivered_to).toBe(0);
    expect(submit.data.push_wakeups).toBe(1);
  });

  it("still delivers over WebSocket when a push transport throws", async () => {
    const acct = "acct-push-throw-still-ws";
    const deviceId = await enrollDeviceWithPushToken(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);
    await installPushTransports(acct, {
      apns: {
        kind: "apns",
        async sendWakeup() {
          throw new Error("provider unavailable");
        },
      },
    });

    const submit = await post<{
      delivered_to: number;
      push_wakeups: number;
      status: string;
    }>(acct, "/requests", makeEnvelope("req-push-throw"));

    expect(submit.status).toBe(202);
    expect(submit.data.status).toBe("pending");
    expect(submit.data.delivered_to).toBe(1);
    expect(submit.data.push_wakeups).toBe(0);
    const pushed = await device.next();
    expect(pushed.type).toBe("request");
    expect(pushed.request_id).toBe("req-push-throw");
  });

  it("stops scheduling push wakeups after the target device is revoked", async () => {
    const acct = "acct-push-revoke-clears-wakeups";
    const deviceId = await enrollDeviceWithPushToken(acct);

    const beforeRevoke = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      makeEnvelope("req-push-before-revoke"),
    );
    expect(beforeRevoke.status).toBe(202);
    expect(beforeRevoke.data.push_wakeups).toBe(1);

    const revoke = await post<{ revoked: boolean }>(acct, `/devices/${deviceId}/revoke`, {});
    expect(revoke.status).toBe(200);

    const afterRevoke = await post<{ push_wakeups: number }>(
      acct,
      "/requests",
      makeEnvelope("req-push-after-revoke"),
    );
    expect(afterRevoke.status).toBe(202);
    expect(afterRevoke.data.push_wakeups).toBe(0);
  });

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

  it("fans out to only one connection per visible surface", async () => {
    const acct = "acct-surface-dedupe";
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
      makeEnvelope("req-surface-1"),
    );
    expect(submit.data.delivered_to).toBe(2);

    expect((await nativeMac.next()).request_id).toBe("req-surface-1");
    expect((await phone.next()).request_id).toBe("req-surface-1");
    await expect(mirroredPhone.next(500)).rejects.toThrow(/timeout/);
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

    const relay = Object.create(AccountRelay.prototype) as {
      ctx: Pick<DurableObjectState, "getTags" | "getWebSockets">;
      sendRequestToOneSocketPerSurface(requestId: string, envelope: unknown): number;
    };
    relay.ctx = {
      getTags: (ws: WebSocket) => tags.get(ws) ?? [],
      getWebSockets: (tag: string) => (tag === "device" ? [staleMac, liveMac, phone] : []),
    } as Pick<DurableObjectState, "getTags" | "getWebSockets">;

    // A closing hibernation socket can still be returned by the tag index but reject `send()`. It
    // must not claim the visible surface unless the relay actually sends the request to it.
    vi.spyOn(staleMac, "send").mockImplementation(() => {
      throw new Error("socket already closing");
    });

    const delivered = relay.sendRequestToOneSocketPerSurface(
      "req-surface-stale-1",
      makeEnvelope("req-surface-stale-1"),
    );

    expect(delivered).toBe(2);
    expect(JSON.parse(liveMacMessages[0] ?? "{}")).toMatchObject({
      type: "request",
      request_id: "req-surface-stale-1",
    });
    expect(JSON.parse(phoneMessages[0] ?? "{}")).toMatchObject({
      type: "request",
      request_id: "req-surface-stale-1",
    });
  });

  it("flushes queued requests to only one reconnecting connection per visible surface", async () => {
    const acct = "acct-surface-flush";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);

    await post(acct, "/requests", makeEnvelope("req-surface-queued"));

    const nativeMac = await connectWs(acct, `/devices/${deviceId}/connect?surface_id=mac-screen`);
    const mirroredPhone = await connectWs(
      acct,
      `/devices/${deviceId}/connect?surface_id=mac-screen`,
    );
    const phone = await connectWs(acct, `/devices/${deviceId}/connect?surface_id=phone-screen`);

    expect((await nativeMac.next()).request_id).toBe("req-surface-queued");
    expect((await phone.next()).request_id).toBe("req-surface-queued");
    await expect(mirroredPhone.next(500)).rejects.toThrow(/timeout/);
  });

  it("flushes queued requests when only stale sockets exist for the reconnecting surface", async () => {
    const staleMac = {
      readyState: WebSocket.CLOSING,
      send: () => {
        throw new Error("socket already closing");
      },
    } as unknown as WebSocket;
    const envelope = makeEnvelope("req-surface-stale-queued");
    const authTokenHash = await testAuthTokenHash("stale-device-token");

    const relay = Object.create(AccountRelay.prototype) as {
      ctx: Pick<DurableObjectState, "acceptWebSocket" | "getWebSockets">;
      sql: Pick<SqlStorage, "exec">;
      handleDeviceConnect(deviceId: string, request: Request): Response;
    };
    relay.ctx = {
      acceptWebSocket: (ws: WebSocket) => ws.accept(),
      getWebSockets: (tag: string) => (tag === "surface:mac-screen" ? [staleMac] : []),
    } as Pick<DurableObjectState, "acceptWebSocket" | "getWebSockets">;
    relay.sql = {
      exec: (query: string) => {
        if (query.includes("FROM device")) {
          return [{ device_id: "dev-stale-flush", auth_token_hash: authTokenHash }];
        }
        if (query.includes("FROM request")) {
          return [{ request_id: "req-surface-stale-queued", envelope: JSON.stringify(envelope) }];
        }
        return [];
      },
    } as unknown as Pick<SqlStorage, "exec">;

    const response = await relay.handleDeviceConnect(
      "dev-stale-flush",
      new Request(
        "https://relay.allw.test/acct/devices/dev-stale-flush/connect?surface_id=mac-screen&auth=stale-device-token",
      ),
    );
    expect(response.status).toBe(101);
    expect(response.webSocket).toBeDefined();

    const client = response.webSocket as WebSocket;
    const queued = new Promise<WsMessage>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("WebSocket message timeout")), 500);
      client.addEventListener("message", (event: MessageEvent) => {
        clearTimeout(timeout);
        resolve(JSON.parse(event.data as string) as WsMessage);
      });
    });
    client.accept();

    await expect(queued).resolves.toMatchObject({
      type: "request",
      request_id: "req-surface-stale-queued",
    });
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
// Endpoint authentication (issue #89)
// ---------------------------------------------------------------------------

describe("AccountRelay — endpoint authentication", () => {
  it("requires the enrolled device token for device presence sockets", async () => {
    const acct = "acct-auth-device-connect";
    const device = await pairDevice(acct);

    const noAuth = await SELF.fetch(relayUrl(acct, `/devices/${device.device_id}/connect`), {
      headers: { Upgrade: "websocket" },
    });
    expect(noAuth.status).toBe(401);

    const wrongAuth = await SELF.fetch(
      relayUrl(acct, appendAuthQuery(`/devices/${device.device_id}/connect`, "wrong-token")),
      { headers: { Upgrade: "websocket" } },
    );
    expect(wrongAuth.status).toBe(403);

    const ok = await SELF.fetch(
      relayUrl(
        acct,
        appendAuthQuery(`/devices/${device.device_id}/connect`, device.device_auth_token),
      ),
      { headers: { Upgrade: "websocket" } },
    );
    expect(ok.status).toBe(101);
    ok.webSocket?.accept();
    ok.webSocket?.close();
  });

  it("rejects another enrolled device's real token for a target device presence socket", async () => {
    const acct = "acct-auth-device-connect-scoped";
    const deviceA = await pairDevice(acct);
    const deviceB = await pairDevice(acct, "__________________________________________8");

    const crossDevice = await SELF.fetch(
      relayUrl(
        acct,
        appendAuthQuery(`/devices/${deviceA.device_id}/connect`, deviceB.device_auth_token),
      ),
      { headers: { Upgrade: "websocket" } },
    );
    expect(crossDevice.status).toBe(403);
  });

  it("fails closed when legacy device or request rows have no stored auth-token hash", async () => {
    const acct = "acct-auth-null-hash";
    const device = await pairDevice(acct);
    const submit = await post<SubmitResult>(acct, "/requests", makeEnvelope("req-auth-null-hash"));
    expect(submit.status).toBe(202);

    await runInDurableObject(env.ACCOUNT.get(env.ACCOUNT.idFromName(acct)), (instance) => {
      const relay = instance as unknown as { sql: SqlStorage };
      relay.sql.exec(
        `UPDATE device SET auth_token_hash = NULL WHERE device_id = ?`,
        device.device_id,
      );
      relay.sql.exec(
        `UPDATE request SET auth_token_hash = NULL WHERE request_id = ?`,
        submit.data.request_id,
      );
    });

    const connect = await SELF.fetch(relayUrl(acct, `/devices/${device.device_id}/connect`), {
      headers: { Upgrade: "websocket" },
    });
    expect(connect.status).toBe(401);

    const poll = await SELF.fetch(relayUrl(acct, `/requests/${submit.data.request_id}`));
    expect(poll.status).toBe(401);

    const wait = await SELF.fetch(relayUrl(acct, `/requests/${submit.data.request_id}/wait`), {
      headers: { Upgrade: "websocket" },
    });
    expect(wait.status).toBe(401);
  });

  it("requires the per-request token for polling and wait sockets", async () => {
    const acct = "acct-auth-request-token";
    const submit = await post<SubmitResult>(acct, "/requests", makeEnvelope("req-auth-token"));
    expect(submit.status).toBe(202);

    const noAuthPoll = await SELF.fetch(relayUrl(acct, "/requests/req-auth-token"));
    expect(noAuthPoll.status).toBe(401);

    const wrongAuthPoll = await SELF.fetch(relayUrl(acct, "/requests/req-auth-token"), {
      headers: bearer("wrong-request-token"),
    });
    expect(wrongAuthPoll.status).toBe(403);

    const okPoll = await SELF.fetch(relayUrl(acct, "/requests/req-auth-token"), {
      headers: bearer(submit.data.request_auth_token),
    });
    expect(okPoll.status).toBe(200);

    const noAuthWait = await SELF.fetch(relayUrl(acct, "/requests/req-auth-token/wait"), {
      headers: { Upgrade: "websocket" },
    });
    expect(noAuthWait.status).toBe(401);

    const wrongAuthWait = await SELF.fetch(
      relayUrl(acct, appendAuthQuery("/requests/req-auth-token/wait", "wrong-request-token")),
      { headers: { Upgrade: "websocket" } },
    );
    expect(wrongAuthWait.status).toBe(403);

    const okWait = await SELF.fetch(
      relayUrl(
        acct,
        appendAuthQuery("/requests/req-auth-token/wait", submit.data.request_auth_token),
      ),
      { headers: { Upgrade: "websocket" } },
    );
    expect(okWait.status).toBe(101);
    okWait.webSocket?.accept();
    okWait.webSocket?.close();
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

  it("lazy-expires on poll: retracts devices and wakes existing waiters", async () => {
    const acct = "acct-exp-poll-notify";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope("req-exp-poll-notify"));
    expect((await device.next()).request_id).toBe("req-exp-poll-notify");

    const integrator = await connectWs(acct, "/requests/req-exp-poll-notify/wait");
    await forceExpireRequest(acct, "req-exp-poll-notify");

    const polled = await get<{ status: string }>(acct, "/requests/req-exp-poll-notify");
    expect(polled.status).toBe(200);
    expect(polled.data.status).toBe("expired");

    const retract = await device.next();
    expect(retract.type).toBe("retract");
    expect(retract.request_id).toBe("req-exp-poll-notify");

    const expired = await integrator.next();
    expect(expired.type).toBe("expired");
    expect(expired.request_id).toBe("req-exp-poll-notify");
  });

  it("lazy-expires on …/wait: pushes terminal 'expired' and closes", async () => {
    const acct = "acct-exp-wait";
    await seedExpiredRequest(acct, "req-exp-w");

    const integrator = await connectWs(acct, "/requests/req-exp-w/wait");
    const msg = await integrator.next();
    expect(msg.type).toBe("expired");
    expect(msg.request_id).toBe("req-exp-w");
  });

  it("alarm proactively expires overdue pending requests, retracts devices, and wakes waiters", async () => {
    const acct = "acct-exp-alarm";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    const submit = await post(acct, "/requests", makeEnvelope("req-exp-alarm"));
    expect(submit.status).toBe(202);
    expect((await device.next()).request_id).toBe("req-exp-alarm");

    const integrator = await connectWs(acct, "/requests/req-exp-alarm/wait");

    await forceExpireAndRunAlarm(acct, "req-exp-alarm");

    const retract = await device.next();
    expect(retract.type).toBe("retract");
    expect(retract.request_id).toBe("req-exp-alarm");

    const expired = await integrator.next();
    expect(expired.type).toBe("expired");
    expect(expired.request_id).toBe("req-exp-alarm");

    const status = await readRequestStatus(acct, "req-exp-alarm");
    expect(status).toBe("expired");
  });

  it("alarm tracks the nearest pending expiry and clears itself when no pending work remains", async () => {
    const acct = "acct-exp-rearm";
    const firstExpiry = 4102444800000;
    const secondExpiry = firstExpiry + 60_000;
    await post(acct, "/requests", makeEnvelope("req-exp-a", { expires_at: firstExpiry }));
    await post(acct, "/requests", makeEnvelope("req-exp-b", { expires_at: secondExpiry }));

    expect(await readScheduledAlarm(acct)).toBe(firstExpiry);

    await forceExpireAndRunAlarm(acct, "req-exp-a");
    expect(await readRequestStatus(acct, "req-exp-a")).toBe("expired");
    expect(await readScheduledAlarm(acct)).toBe(secondExpiry);

    await forceExpireAndRunAlarm(acct, "req-exp-b");
    expect(await readRequestStatus(acct, "req-exp-b")).toBe("expired");
    expect(await readScheduledAlarm(acct)).toBeNull();
  });

  it("alarm retention sweep deletes old terminal rows and their verdicts", async () => {
    const acct = "acct-exp-retention";
    await seedOldTerminalRows(acct);

    await runAlarm(acct);

    const rows = await listRequestAndVerdictIds(acct);
    expect(rows.requests).toEqual(["req-fresh-expired", "req-fresh-resolved"]);
    expect(rows.verdicts).toEqual(["req-fresh-resolved"]);
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
// Integrator-initiated retract (issue #195) — NOT a verdict, distinct from `expired`
// ---------------------------------------------------------------------------

describe("AccountRelay — retract (issue #195)", () => {
  it("retracts a pending request: terminal 'retracted', no verdict, distinct from expired", async () => {
    const acct = "acct-retract-basic";
    const submit = await post<SubmitResult>(acct, "/requests", makeEnvelope("req-retract-basic"));
    expect(submit.status).toBe(202);

    const retract = await post<{ request_id: string; status: string }>(
      acct,
      "/requests/req-retract-basic/retract",
      {},
    );
    expect(retract.status).toBe(200);
    expect(retract.data.status).toBe("retracted");

    const polled = await get<{ status: string; verdict?: unknown }>(
      acct,
      "/requests/req-retract-basic",
    );
    expect(polled.data.status).toBe("retracted");
    expect(polled.data.status).not.toBe("expired");
    expect(polled.data.verdict).toBeUndefined();
  });

  it("clears the pending prompt from connected devices (reuses the {type:'retract'} fan-out)", async () => {
    const acct = "acct-retract-devices";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope("req-retract-devices"));
    expect((await device.next()).type).toBe("request");

    await post(acct, "/requests/req-retract-devices/retract", {});

    const retract = await device.next();
    expect(retract.type).toBe("retract");
    expect(retract.request_id).toBe("req-retract-devices");
  });

  it("pushes {type:'retracted'} to a live integrator wait socket and closes it", async () => {
    const acct = "acct-retract-wait-live";
    await post(acct, "/requests", makeEnvelope("req-retract-wait-live"));
    const integrator = await connectWs(acct, "/requests/req-retract-wait-live/wait");

    await post(acct, "/requests/req-retract-wait-live/retract", {});

    const msg = await integrator.next();
    expect(msg.type).toBe("retracted");
    expect(msg.request_id).toBe("req-retract-wait-live");
  });

  it("…/wait opened AFTER a retract immediately reports 'retracted' and closes (symmetric with expired)", async () => {
    const acct = "acct-retract-wait-late";
    await post(acct, "/requests", makeEnvelope("req-retract-wait-late"));
    await post(acct, "/requests/req-retract-wait-late/retract", {});

    const integrator = await connectWs(acct, "/requests/req-retract-wait-late/wait");
    const msg = await integrator.next();
    expect(msg.type).toBe("retracted");
    expect(msg.request_id).toBe("req-retract-wait-late");
  });

  it("is idempotent: retracting an already-retracted request succeeds (200)", async () => {
    const acct = "acct-retract-idempotent";
    await post(acct, "/requests", makeEnvelope("req-retract-idempotent"));
    const first = await post<{ status: string }>(
      acct,
      "/requests/req-retract-idempotent/retract",
      {},
    );
    expect(first.status).toBe(200);

    const second = await post<{ status: string }>(
      acct,
      "/requests/req-retract-idempotent/retract",
      {},
    );
    expect(second.status).toBe(200);
    expect(second.data.status).toBe("retracted");
  });

  it("refuses a device verdict for an already-retracted request (retract is not overridable)", async () => {
    const acct = "acct-retract-then-verdict";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope("req-retract-then-verdict"));
    await device.next(); // request push
    await post(acct, "/requests/req-retract-then-verdict/retract", {});
    await device.next(); // the cross-device retract fan-out

    device.send({
      type: "verdict",
      request_id: "req-retract-then-verdict",
      verdict: makeVerdict("req-retract-then-verdict"),
    });
    const ack = await device.next();
    expect(ack.type).toBe("ack");
    expect(ack.status).toBe("retracted");

    // A late verdict must never resurrect a retracted request as resolved.
    const polled = await get<{ status: string; verdict?: unknown }>(
      acct,
      "/requests/req-retract-then-verdict",
    );
    expect(polled.data.status).toBe("retracted");
    expect(polled.data.verdict).toBeUndefined();
  });

  it("SECURITY: refuses to retract a request that already resolved — the recorded verdict stands (409)", async () => {
    const acct = "acct-retract-vs-resolved";
    await enrollDevice(acct);
    const deviceId = await firstDeviceId(acct);
    const device = await connectWs(acct, `/devices/${deviceId}/connect`);

    await post(acct, "/requests", makeEnvelope("req-retract-vs-resolved"));
    await device.next();
    const winning = makeVerdict("req-retract-vs-resolved", "approved");
    device.send({ type: "verdict", request_id: "req-retract-vs-resolved", verdict: winning });
    expect((await device.next()).status).toBe("resolved");

    const retract = await post<{ error: string }>(
      acct,
      "/requests/req-retract-vs-resolved/retract",
      {},
    );
    expect(retract.status).toBe(409);

    // A retract that lost the race must never discard the already-recorded human decision.
    const polled = await get<{ status: string; verdict: Record<string, unknown> }>(
      acct,
      "/requests/req-retract-vs-resolved",
    );
    expect(polled.data.status).toBe("resolved");
    expect(polled.data.verdict).toEqual(winning);
  });

  it("SECURITY: refuses to retract an already-expired request (409)", async () => {
    const acct = "acct-retract-vs-expired";
    await seedExpiredRequest(acct, "req-retract-vs-expired");

    const retract = await post<{ error: string }>(
      acct,
      "/requests/req-retract-vs-expired/retract",
      {},
    );
    expect(retract.status).toBe(409);

    const polled = await get<{ status: string }>(acct, "/requests/req-retract-vs-expired");
    expect(polled.data.status).toBe("expired");
  });

  it("SECURITY: returns 404 retracting an unknown request", async () => {
    const { status } = await post("acct-retract-unknown", "/requests/does-not-exist/retract", {});
    expect(status).toBe(404);
  });

  it("SECURITY: requires the per-request token, scoped to exactly that request (no cross-request retract)", async () => {
    const acct = "acct-retract-auth-scoped";
    const submitA = await post<SubmitResult>(acct, "/requests", makeEnvelope("req-retract-auth-a"));
    const submitB = await post<SubmitResult>(acct, "/requests", makeEnvelope("req-retract-auth-b"));
    expect(submitA.status).toBe(202);
    expect(submitB.status).toBe(202);

    const noAuth = await SELF.fetch(relayUrl(acct, "/requests/req-retract-auth-a/retract"), {
      method: "POST",
    });
    expect(noAuth.status).toBe(401);

    const wrongAuth = await SELF.fetch(relayUrl(acct, "/requests/req-retract-auth-a/retract"), {
      method: "POST",
      headers: bearer("wrong-request-token"),
    });
    expect(wrongAuth.status).toBe(403);

    // An integrator holding a REAL, currently-valid token for a DIFFERENT request must not be able
    // to retract this one — the token is scoped to exactly the request it was issued for (#195).
    const crossRequest = await SELF.fetch(relayUrl(acct, "/requests/req-retract-auth-a/retract"), {
      method: "POST",
      headers: bearer(submitB.data.request_auth_token),
    });
    expect(crossRequest.status).toBe(403);

    const ok = await post<{ status: string }>(acct, "/requests/req-retract-auth-a/retract", {});
    expect(ok.status).toBe(200);

    // The OTHER request is unaffected by the cross-scoped attempt above.
    const stillPendingB = await get<{ status: string }>(acct, "/requests/req-retract-auth-b");
    expect(stillPendingB.data.status).toBe("pending");
  });

  it("returns 405 retracting via the wrong method", async () => {
    const acct = "acct-retract-method";
    await post(acct, "/requests", makeEnvelope("req-retract-method"));
    const resp = await SELF.fetch(relayUrl(acct, "/requests/req-retract-method/retract"), {
      method: "GET",
      headers: bearer(requestAuthTokens.get(tokenKey(acct, "req-retract-method")) ?? ""),
    });
    expect(resp.status).toBe(405);
  });
});

// ---------------------------------------------------------------------------
// Device inbox (HTTP polling — issue #147)
// ---------------------------------------------------------------------------

describe("AccountRelay — device inbox (HTTP poll)", () => {
  it("returns pending envelopes for the authenticated device", async () => {
    const acct = "acct-inbox-basic";
    const device = await pairDevice(acct);
    const token = device.device_auth_token;
    const envA = makeEnvelope("req-inbox-a");
    const envB = makeEnvelope("req-inbox-b");
    await post(acct, "/requests", envA);
    await post(acct, "/requests", envB);

    const resp = await get<{ envelopes: unknown[] }>(
      acct,
      `/devices/${device.device_id}/inbox`,
      bearer(token),
    );
    expect(resp.status).toBe(200);
    const ids = resp.data.envelopes.map((e) => (e as Record<string, unknown>).id);
    expect(ids).toContain("req-inbox-a");
    expect(ids).toContain("req-inbox-b");
    // Zero-knowledge: only relay-visible envelope fields, never plaintext context
    for (const env of resp.data.envelopes) {
      const keys = Object.keys(env as Record<string, unknown>);
      expect(keys).not.toContain("action");
      expect(keys).not.toContain("summary");
      expect(keys).not.toContain("actor");
      expect(keys).toContain("context_ciphertext");
    }
  });

  it("excludes resolved and expired requests from the inbox", async () => {
    const acct = "acct-inbox-exclude";
    const device = await pairDevice(acct);
    const token = device.device_auth_token;

    // Submit two requests; resolve one via the WebSocket.
    await post(acct, "/requests", makeEnvelope("req-exclude-pending"));
    await post(acct, "/requests", makeEnvelope("req-exclude-resolved"));
    const wsDevice = await connectWs(acct, `/devices/${device.device_id}/connect`);
    // drain both offline-queue messages
    await wsDevice.next();
    await wsDevice.next();
    wsDevice.send({
      type: "verdict",
      request_id: "req-exclude-resolved",
      verdict: makeVerdict("req-exclude-resolved"),
    });
    await wsDevice.next(); // ack

    const resp = await get<{ envelopes: unknown[] }>(
      acct,
      `/devices/${device.device_id}/inbox`,
      bearer(token),
    );
    expect(resp.status).toBe(200);
    const ids = resp.data.envelopes.map((e) => (e as Record<string, unknown>).id);
    expect(ids).toContain("req-exclude-pending");
    expect(ids).not.toContain("req-exclude-resolved");
  });

  it("excludes already-expired requests from the inbox (fail-closed)", async () => {
    const acct = "acct-inbox-expired";
    const device = await pairDevice(acct);
    const token = device.device_auth_token;

    // Seed an expired request directly (POST /requests rejects already-expired).
    await seedExpiredRequest(acct, "req-inbox-already-expired");
    // Submit a live request.
    await post(acct, "/requests", makeEnvelope("req-inbox-live"));

    const resp = await get<{ envelopes: unknown[] }>(
      acct,
      `/devices/${device.device_id}/inbox`,
      bearer(token),
    );
    expect(resp.status).toBe(200);
    const ids = resp.data.envelopes.map((e) => (e as Record<string, unknown>).id);
    expect(ids).not.toContain("req-inbox-already-expired");
    expect(ids).toContain("req-inbox-live");
  });

  it("returns 401 without a bearer token", async () => {
    const acct = "acct-inbox-noauth";
    const device = await pairDevice(acct);

    const resp = await SELF.fetch(relayUrl(acct, `/devices/${device.device_id}/inbox`), {
      method: "GET",
    });
    expect(resp.status).toBe(401);
  });

  it("returns 403 with a wrong bearer token", async () => {
    const acct = "acct-inbox-wrongauth";
    const device = await pairDevice(acct);

    const resp = await SELF.fetch(relayUrl(acct, `/devices/${device.device_id}/inbox`), {
      method: "GET",
      headers: { Authorization: "Bearer wrong-token" },
    });
    expect(resp.status).toBe(403);
  });

  it("returns 404 for an unenrolled device id", async () => {
    const acct = "acct-inbox-notfound";
    await pairDevice(acct);

    const resp = await SELF.fetch(relayUrl(acct, `/devices/not-a-real-device/inbox`), {
      method: "GET",
      headers: { Authorization: "Bearer any-token" },
    });
    expect(resp.status).toBe(404);
  });

  it("405 on POST to the inbox route", async () => {
    const acct = "acct-inbox-405";
    const device = await pairDevice(acct);
    const token = device.device_auth_token;

    const resp = await SELF.fetch(relayUrl(acct, `/devices/${device.device_id}/inbox`), {
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
    const acct = "acct-inbox-empty";
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
  const requestAuthToken = `expired-request-token-${requestId}`;
  const requestAuthTokenHash = await testAuthTokenHash(requestAuthToken);
  requestAuthTokens.set(tokenKey(accountId, requestId), requestAuthToken);
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    relay.sql.exec(
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
  await runInDurableObject(stub, async (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage; alarm(): Promise<void> };
    relay.sql.exec(
      `UPDATE request SET expires_at = ? WHERE request_id = ?`,
      PAST_EXPIRES_AT,
      requestId,
    );
    await relay.alarm();
  });
}

async function forceExpireRequest(accountId: string, requestId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    relay.sql.exec(
      `UPDATE request SET expires_at = ? WHERE request_id = ?`,
      PAST_EXPIRES_AT,
      requestId,
    );
  });
}

async function readScheduledAlarm(accountId: string): Promise<number | null> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, async (instance: AccountRelay) => {
    const relay = instance as unknown as { ctx: DurableObjectState };
    return relay.ctx.storage.getAlarm();
  });
}

async function readRequestStatus(accountId: string, requestId: string): Promise<string | null> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    const rows = [
      ...relay.sql.exec<{ status: string }>(
        `SELECT status FROM request WHERE request_id = ?`,
        requestId,
      ),
    ];
    return rows[0]?.status ?? null;
  });
}

async function seedOldTerminalRows(accountId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    const rows = [
      {
        request_id: "req-old-expired",
        envelope: makeEnvelope("req-old-expired", { expires_at: OLD_TERMINAL_AT }),
        created_at: OLD_TERMINAL_AT - 1000,
        expires_at: OLD_TERMINAL_AT,
        status: "expired",
        terminal_at: OLD_TERMINAL_AT,
      },
      {
        request_id: "req-fresh-expired",
        envelope: makeEnvelope("req-fresh-expired"),
        created_at: CREATED_AT,
        expires_at: FUTURE_EXPIRES_AT,
        status: "expired",
        terminal_at: FUTURE_EXPIRES_AT,
      },
      {
        request_id: "req-old-resolved",
        envelope: makeEnvelope("req-old-resolved", { expires_at: OLD_TERMINAL_AT }),
        created_at: OLD_TERMINAL_AT - 1000,
        expires_at: OLD_TERMINAL_AT,
        status: "resolved",
        terminal_at: OLD_TERMINAL_AT,
      },
      {
        request_id: "req-fresh-resolved",
        envelope: makeEnvelope("req-fresh-resolved"),
        created_at: CREATED_AT,
        expires_at: FUTURE_EXPIRES_AT,
        status: "resolved",
        terminal_at: FUTURE_EXPIRES_AT,
      },
    ];
    for (const row of rows) {
      relay.sql.exec(
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
    relay.sql.exec(
      `INSERT OR REPLACE INTO verdict (request_id, verdict, device_id, received_at)
       VALUES (?, ?, ?, ?)`,
      "req-old-resolved",
      JSON.stringify(makeVerdict("req-old-resolved")),
      "dev-old",
      OLD_TERMINAL_AT,
    );
    relay.sql.exec(
      `INSERT OR REPLACE INTO verdict (request_id, verdict, device_id, received_at)
       VALUES (?, ?, ?, ?)`,
      "req-fresh-resolved",
      JSON.stringify(makeVerdict("req-fresh-resolved")),
      "dev-fresh",
      FUTURE_EXPIRES_AT,
    );
  });
}

async function listRequestAndVerdictIds(
  accountId: string,
): Promise<{ requests: string[]; verdicts: string[] }> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    const requests = [
      ...relay.sql.exec<{ request_id: string }>(
        `SELECT request_id FROM request ORDER BY request_id ASC`,
      ),
    ].map((row) => row.request_id);
    const verdicts = [
      ...relay.sql.exec<{ request_id: string }>(
        `SELECT request_id FROM verdict ORDER BY request_id ASC`,
      ),
    ].map((row) => row.request_id);
    return { requests, verdicts };
  });
}

/** Delete a device row directly — simulates a revoke whose hibernation socket outlived the close. */
async function deleteDeviceRow(accountId: string, deviceId: string): Promise<void> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  await runInDurableObject(stub, (instance: AccountRelay) => {
    const relay = instance as unknown as { sql: SqlStorage };
    relay.sql.exec(`DELETE FROM device WHERE device_id = ?`, deviceId);
  });
}
