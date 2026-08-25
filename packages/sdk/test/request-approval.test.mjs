/**
 * End-to-end tests for `@allw/sdk` `requestApproval` (issue #12).
 *
 * These exercise the real compiled SDK (`dist/index.js`) and the real WASM core against a
 * **test double** of the relay's HTTP/WS surface. The double mirrors the contract's Relay routing
 * API (`docs/contract.md` §Transport): `GET /:acct/devices`, `POST /:acct/requests`,
 * `GET /:acct/requests/:id` (poll), and the `…/wait` WebSocket. A valid signed verdict is minted
 * in-process through the WASM signing surface (`sign_verdict` / `issue_device_cert` / key
 * derivation), so the happy path verifies for real — no stubbed crypto.
 *
 * The matrix (issue #12 acceptance):
 *  (a) happy WS round-trip → resolves `approved`, `verify()` re-passes;
 *  (a') happy poll round-trip (no WebSocket) → resolves `approved`;
 *  (b) timeout (no verdict) → resolves `expired`, never approved, `verify()` false;
 *  (b') relay `expired` terminal → resolves `expired`;
 *  (c) tampered / forged verdict → never approved (synthesized `denied`), `verify()` false;
 *  (c-sig) verdict from an uncertified key → never approved;
 *  (c') authenticated human "denied" → resolves `denied` (the verified decision), `verify()` false;
 *  (d) negative: no devices, relay submit error;
 *  (i) integrator-initiated cancellation (`ApprovalRequest.signal`, issue #195) → rejects with
 *      `RequestRetractedError`, discovered via WS push, via poll fallback, or short-circuited
 *      pre-submission; a failed retract call is best-effort and leaves the deadline in force;
 *  plus a zero-leak envelope-shape assertion.
 *
 * Run order (the wasm must be built and the SDK compiled first):
 *   pnpm run build:wasm                # from repo root
 *   pnpm --filter @allw/sdk build      # tsc → dist
 *   pnpm --filter @allw/sdk test
 *
 * @see ../../../docs/contract.md (§Lifecycle, §Messages, §Verification checklist, §Transport)
 * @see ../../relay/src/index.ts (the routing surface this double mirrors)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

import { createClient, RequestRetractedError } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

/** Load the `--target web` wasm synchronously (mirrors test/wasm.test.mjs). */
async function loadWasm() {
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  const bytes = readFileSync(join(vendorDir, "allw_wasm_bg.wasm"));
  glue.initSync({ module: new WebAssembly.Module(bytes) });
  return glue;
}

// ── Deterministic fixtures (never Date.now() in data — fixed-dates rule) ──────────────

/** A fixed "now" so expires_at = NOW + timeout is deterministic and inside the verify window. */
const NOW_MS = 1700001000000; // 2023-11-14T22:30:00Z
const TIMEOUT_MS = 60_000;
const ACCOUNT_ID = "acct_sdk_test_01";
const RELAY_URL = "https://relay.allw.test";

/** A representative ApprovalRequest in the SDK's ergonomic camelCase shape. */
function sampleRequest(overrides = {}) {
  return {
    action: {
      recordSchemaVersion: 1,
      surface: "command",
      syntactic: { bin: "git", raw: "git push --force" },
      risk: "high",
    },
    summary: "Force-push to main",
    actor: { id: "machine:macbook-pro", kind: "claude-code" },
    risk: "high",
    reversible: false,
    timeoutMs: TIMEOUT_MS,
    ...overrides,
  };
}

/**
 * The snake_case wire context the SDK builds internally (mirrors `toWireContext`). The test signs
 * a verdict bound to the request_hash computed from THIS object — identical bytes to the SDK's.
 */
function wireContext(req) {
  const constraints = req.constraints ?? {
    allowedDecisions: ["approved", "denied"],
    challengeRequired: false,
  };
  const ctx = {
    action: {
      record_schema_version: req.action.recordSchemaVersion,
      surface: req.action.surface,
      syntactic: req.action.syntactic,
      risk: req.action.risk,
    },
    summary: req.summary,
    actor: { id: req.actor.id, kind: req.actor.kind },
    risk: req.risk,
    reversible: req.reversible,
    constraints: {
      allowed_decisions: constraints.allowedDecisions,
      challenge_required: constraints.challengeRequired,
    },
  };
  if (req.chain !== undefined) ctx.chain = req.chain;
  return ctx;
}

/**
 * Build an approver: account-root key, a device key it certifies, and the device's X25519
 * encryption pubkey (a JWE recipient). All derived through the WASM surface.
 */
function makeApprover(wasm) {
  const accountSeed = Buffer.alloc(32, 7).toString("base64url");
  const deviceSeed = Buffer.alloc(32, 9).toString("base64url");
  const deviceX25519Seed = Buffer.alloc(32, 11).toString("base64url");
  const accountRootPub = wasm.ed25519_public_key(accountSeed);
  const devicePub = wasm.ed25519_public_key(deviceSeed);
  const deviceX25519Pub = wasm.x25519_public_key(deviceX25519Seed);
  const deviceId = "dev_sdk_test_01";
  const cert = wasm.issue_device_cert(accountSeed, ACCOUNT_ID, deviceId, devicePub, NOW_MS - 1000);
  return {
    accountSeed,
    deviceSeed,
    deviceX25519Seed,
    deviceX25519Pub,
    accountRootPub,
    devicePub,
    deviceId,
    cert,
  };
}

/** One enrolled device record as the relay's `GET /:acct/devices` returns it. */
function deviceRecord(approver) {
  return {
    device_id: approver.deviceId,
    pubkey: approver.deviceX25519Pub,
    label: null,
    created_at: 0,
  };
}

/**
 * Build a SECOND device enrolled under the same account root as `primary` (e.g. a since-revoked
 * device) — same account-state/relay shape as {@link makeApprover}, but distinguishable by
 * `deviceId`/keys so recipient-filtering tests can tell the two devices' ciphertext access apart.
 */
function makeSecondDevice(wasm, primary, { seedByte, deviceId }) {
  const deviceSeed = Buffer.alloc(32, seedByte).toString("base64url");
  const deviceX25519Seed = Buffer.alloc(32, seedByte + 1).toString("base64url");
  const devicePub = wasm.ed25519_public_key(deviceSeed);
  const deviceX25519Pub = wasm.x25519_public_key(deviceX25519Seed);
  const cert = wasm.issue_device_cert(
    primary.accountSeed,
    ACCOUNT_ID,
    deviceId,
    devicePub,
    NOW_MS - 1000,
  );
  return {
    accountSeed: primary.accountSeed,
    deviceSeed,
    deviceX25519Seed,
    deviceX25519Pub,
    accountRootPub: primary.accountRootPub,
    devicePub,
    deviceId,
    cert,
  };
}

/**
 * Mint a signed verdict for a captured envelope, bound to the SDK's context. `decision` controls
 * approved/denied/etc. Uses the device key the cert certifies (a genuine, verifiable verdict).
 */
function signVerdict(wasm, approver, req, capturedEnvelope, { decision = "approved" } = {}) {
  const requestHash = wasm.compute_request_hash(
    JSON.stringify(wireContext(req)),
    capturedEnvelope.expires_at,
  );
  const unsigned = {
    v: 1,
    request_id: capturedEnvelope.id,
    request_hash: requestHash,
    decision,
    decided_at: NOW_MS, // inside [created_at, expires_at]
    approver: { account_id: ACCOUNT_ID, device_id: approver.deviceId },
  };
  const nonce = Buffer.alloc(16, 3).toString("base64url");
  const verdictJson = wasm.sign_verdict(
    JSON.stringify(unsigned),
    approver.deviceSeed,
    nonce,
    approver.cert,
  );
  return JSON.parse(verdictJson);
}

/** Root-sign a minimal account-state document for account-state-aware SDK verification tests. */
function signAccountState(wasm, approver, { sequence, revokedDeviceIds = [] }) {
  return wasm.sign_account_state(
    JSON.stringify({
      v: 1,
      account_id: ACCOUNT_ID,
      sequence,
      current_root: approver.accountRootPub,
      previous_roots: [],
      devices: [],
      actors: [],
      revocations: revokedDeviceIds.map((id) => ({
        kind: "device",
        id,
        revoked_at: NOW_MS,
        reason: "test revocation",
      })),
    }),
    approver.accountSeed,
  );
}

// ── Relay test double ─────────────────────────────────────────────────────────────────

/**
 * A configurable fake of the relay routing surface. `behavior.poll(envelope)` returns either a
 * verdict object (resolved), `"expired"`, or `null` (stay pending). The double captures the
 * submitted envelope so a test can mint a matching verdict afterwards.
 */
function makeRelayDouble({ devices, behavior }) {
  const state = {
    captured: null,
    submitted: false,
    requestAuthToken: null,
    retracted: false,
    retractCalls: 0,
  };

  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const path = u.pathname;
    const method = (init.method ?? "GET").toUpperCase();

    if (method === "GET" && path.endsWith("/devices")) {
      return jsonResponse({ devices });
    }
    if (method === "POST" && path.endsWith("/requests")) {
      const envelope = JSON.parse(init.body);
      state.captured = envelope;
      state.submitted = true;
      state.requestAuthToken = `token-${envelope.id}`;
      if (behavior.submitStatus && behavior.submitStatus !== 202) {
        return jsonResponse({ error: "rejected" }, behavior.submitStatus);
      }
      return jsonResponse(
        {
          request_id: envelope.id,
          status: "pending",
          delivered_to: 1,
          request_auth_token: state.requestAuthToken,
        },
        202,
      );
    }
    if (method === "POST" && path.endsWith("/retract")) {
      state.retractCalls += 1;
      if (init.headers?.Authorization !== `Bearer ${state.requestAuthToken}`) {
        return jsonResponse({ error: "authorization denied" }, 403);
      }
      if (behavior.retractStatus && behavior.retractStatus !== 200) {
        return jsonResponse({ error: "conflict" }, behavior.retractStatus);
      }
      state.retracted = true;
      behavior.onRetract?.();
      return jsonResponse({ request_id: state.captured?.id ?? "x", status: "retracted" });
    }
    if (method === "GET" && path.includes("/requests/")) {
      if (init.headers?.Authorization !== `Bearer ${state.requestAuthToken}`) {
        return jsonResponse({ error: "authorization denied" }, 403);
      }
      if (state.retracted) return jsonResponse({ request_id: "x", status: "retracted" });
      const outcome = behavior.poll(state.captured);
      if (outcome === null) return jsonResponse({ request_id: "x", status: "pending" });
      if (outcome === "expired") return jsonResponse({ request_id: "x", status: "expired" });
      return jsonResponse({ request_id: "x", status: "resolved", verdict: outcome });
    }
    return jsonResponse({ error: "not found" }, 404);
  };

  return { fetchImpl, state };
}

function jsonResponse(data, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: () => Promise.resolve(data) };
}

/**
 * A fake WebSocket that, on construction, asynchronously emits the configured terminal frame (or
 * nothing). Mirrors the `…/wait` push protocol. `frameFor()` is called lazily so the frame can be
 * built from the already-captured envelope.
 */
function makeWebSocketFactory(frameFor) {
  const urls = [];
  const factory = (url) => {
    urls.push(url);
    return new FakeWebSocket(url, frameFor);
  };
  factory.urls = urls;
  return factory;
}

class FakeWebSocket {
  constructor(url, frameFor) {
    this.url = url;
    this.listeners = { message: [], open: [], error: [], close: [] };
    this.closed = false;
    // Emit after listeners are attached (the SDK attaches synchronously post-construction).
    queueMicrotask(() => {
      if (this.closed) return;
      const frame = frameFor();
      if (frame === undefined) return;
      for (const l of this.listeners.message) l({ data: JSON.stringify(frame) });
    });
  }
  addEventListener(type, listener) {
    this.listeners[type].push(listener);
  }
  close() {
    this.closed = true;
  }
}

/**
 * A controllable fake `…/wait` socket that emits nothing on its own — a test drives it explicitly
 * via `emit()`, modeling the relay pushing a message (e.g. `{type:"retracted"}`) on the SAME
 * integrator wait socket sometime AFTER connection, in response to a separate action (like the
 * client's own `POST …/retract` call landing).
 */
function makeControllableWebSocketFactory() {
  let instance = null;
  const factory = (url) => {
    instance = new ControllableFakeWebSocket(url);
    return instance;
  };
  factory.emit = (frame) => instance?.emit(frame);
  return factory;
}

class ControllableFakeWebSocket {
  constructor(url) {
    this.url = url;
    this.listeners = { message: [], open: [], error: [], close: [] };
    this.closed = false;
  }
  emit(frame) {
    if (this.closed) return;
    for (const l of this.listeners.message) l({ data: JSON.stringify(frame) });
  }
  addEventListener(type, listener) {
    this.listeners[type].push(listener);
  }
  close() {
    this.closed = true;
  }
}

/**
 * A clock for the fail-closed **timeout** test. Each scheduled callback advances the virtual clock
 * by its delay and fires on a microtask (no real waiting). The deadline timer's delay is the full
 * `TIMEOUT_MS`, so the first `schedule` advances `now` to the deadline; the poll loop then
 * self-terminates to `timeout` on its next iteration (`now() >= deadline`). Deterministic, with no
 * real timers and no dangling event-loop starvation.
 */
function makeTimeoutClock() {
  let current = NOW_MS;
  return {
    now: () => current,
    schedule: (fn, ms) => {
      current += ms;
      queueMicrotask(fn);
    },
  };
}

/** Shared client config for the poll-only (real-timer, fixed-now) tests. */
function pollClient(approver, relay) {
  return createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined, // poll-only path
    pollIntervalMs: 5,
  });
}

/** Run a test body with deterministic request ids so replay behavior is not masked by id binding. */
async function withFixedRequestId(id, fn) {
  const hadOwn = Object.prototype.hasOwnProperty.call(globalThis.crypto, "randomUUID");
  const original = globalThis.crypto.randomUUID;
  Object.defineProperty(globalThis.crypto, "randomUUID", {
    configurable: true,
    value: () => id,
  });
  try {
    return await fn();
  } finally {
    if (hadOwn) {
      Object.defineProperty(globalThis.crypto, "randomUUID", {
        configurable: true,
        value: original,
      });
    } else {
      delete globalThis.crypto.randomUUID;
    }
  }
}

/**
 * Poll `predicate` (real timers; the fake-clock helpers above don't advance until something
 * `await`s) until it is true, so a test can deterministically wait for an async side effect (e.g.
 * "the envelope was submitted") before driving the next step, instead of guessing a microtask
 * count.
 */
async function waitFor(predicate, { timeoutMs = 2000, stepMs = 1 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("waitFor: condition never became true");
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────────────

test("(a) happy WS round-trip → approved, verify() re-passes", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: { poll: () => null },
  });

  // The WS frame is built lazily AFTER the envelope is captured, so the verdict binds to the real id.
  const wsFactory = makeWebSocketFactory(() => ({
    type: "verdict",
    request_id: relay.state.captured.id,
    verdict: signVerdict(wasm, approver, req, relay.state.captured, { decision: "approved" }),
  }));

  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: wsFactory,
  });

  const verdict = await client.requestApproval(req);
  assert.match(
    wsFactory.urls[0],
    new RegExp(
      `/requests/${relay.state.captured.id}/wait\\?auth=token-${relay.state.captured.id}$`,
    ),
    "the wait WebSocket URL carries the request auth token returned by submit",
  );
  assert.equal(
    verdict.decision,
    "approved",
    "a delivered, verified, approved verdict resolves approved",
  );
  assert.equal(typeof verdict.requestId, "string");
  assert.equal(
    await verdict.verify(approver.accountRootPub),
    true,
    "verify() re-passes against the root key",
  );
  const wrongRoot = wasm.ed25519_public_key(Buffer.alloc(32, 0x5a).toString("base64url"));
  assert.equal(await verdict.verify(wrongRoot), false, "verify() fails under a different root key");
});

test("(a') happy poll round-trip (no WebSocket) → approved", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: (env) => (env ? signVerdict(wasm, approver, req, env, { decision: "approved" }) : null),
    },
  });

  const verdict = await pollClient(approver, relay).requestApproval(req);
  assert.equal(verdict.decision, "approved", "poll fallback verifies an approved verdict");
});

test("(a-revoked) accountStates reject an otherwise valid verdict from a revoked device", async () => {
  const wasm = await loadWasm();
  // Two enrolled devices so the sender-side filter (issue #204 fix 1) does not itself short-circuit
  // the request (that all-revoked path is covered by (fix1-c)) — this test targets the INDEPENDENT
  // defense-in-depth layer: verdict verification must reject a revoked device's signature even if a
  // verdict from it is somehow delivered (e.g. a compromised relay replaying/fabricating a poll
  // response), regardless of whether it was ever a JWE recipient for this particular request.
  const kept = makeApprover(wasm);
  const revokedDevice = makeSecondDevice(wasm, kept, { seedByte: 40, deviceId: "dev_revoked_03" });
  const req = sampleRequest();
  const revokedState = signAccountState(wasm, kept, {
    sequence: 1,
    revokedDeviceIds: [revokedDevice.deviceId],
  });

  const relay = makeRelayDouble({
    devices: [deviceRecord(kept), deviceRecord(revokedDevice)],
    behavior: {
      poll: (env) =>
        env ? signVerdict(wasm, revokedDevice, req, env, { decision: "approved" }) : null,
    },
  });
  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: kept.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined,
    pollIntervalMs: 5,
    accountStates: [revokedState],
  });

  const verdict = await client.requestApproval(req);
  assert.equal(
    verdict.decision,
    "denied",
    "a revoked device's otherwise valid approval fails closed to denied",
  );
  assert.equal(
    await verdict.verify(kept.accountRootPub),
    false,
    "verify() uses the client account-state set by default",
  );
});

// ── Sender-side recipient filtering (issue #204 fix 1) ──────────────────────────────────
//
// The relay-listed device set is untrusted; these assert on the actual JWE recipient set the
// SDK builds by attempting to decrypt the SUBMITTED ciphertext as each device. A revoked
// device's absence from that recipient set is the real, end-to-end analogue of "assert on the
// set passed to encrypt_context" (there is no seam to intercept the WASM call directly from a
// compiled-`dist` test, so the ciphertext itself — the only thing a hostile relay ever sees —
// is the artifact under test).

test("(fix1-a) a device revoked in account state receives NO JWE recipient entry", async () => {
  const wasm = await loadWasm();
  const kept = makeApprover(wasm);
  const revokedDevice = makeSecondDevice(wasm, kept, { seedByte: 20, deviceId: "dev_revoked_01" });
  const req = sampleRequest();
  const revokedState = signAccountState(wasm, kept, {
    sequence: 1,
    revokedDeviceIds: [revokedDevice.deviceId],
  });

  const relay = makeRelayDouble({
    devices: [deviceRecord(kept), deviceRecord(revokedDevice)],
    behavior: {
      poll: (env) => (env ? signVerdict(wasm, kept, req, env, { decision: "approved" }) : null),
    },
  });
  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: kept.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined,
    pollIntervalMs: 5,
    accountStates: [revokedState],
  });

  const verdict = await client.requestApproval(req);
  assert.equal(verdict.decision, "approved", "the non-revoked device's verdict still verifies");

  const jwe = relay.state.captured.context_ciphertext;
  const decrypted = JSON.parse(wasm.decrypt_context(jwe, kept.deviceId, kept.deviceX25519Seed));
  assert.deepEqual(
    decrypted,
    wireContext(req),
    "the kept (non-revoked) device can still decrypt the submitted context",
  );
  assert.throws(
    () => wasm.decrypt_context(jwe, revokedDevice.deviceId, revokedDevice.deviceX25519Seed),
    /no recipient header kid matches the requested device id/,
    "the revoked device has NO recipient entry in the JWE — it cannot even attempt decryption",
  );
});

test("(fix1-b) a lower-sequence account state does not resurrect a revoked device's recipient entry", async () => {
  const wasm = await loadWasm();
  const kept = makeApprover(wasm);
  const revokedDevice = makeSecondDevice(wasm, kept, { seedByte: 30, deviceId: "dev_revoked_02" });
  const req = sampleRequest();
  // Highest sequence (5) revokes the device; a STALE lower-sequence (4) document that omits the
  // revocation must not roll it back (mirrors the core's
  // `stale_account_state_does_not_override_newer_device_revocation`).
  const newerRevocation = signAccountState(wasm, kept, {
    sequence: 5,
    revokedDeviceIds: [revokedDevice.deviceId],
  });
  const staleWithoutRevocation = signAccountState(wasm, kept, {
    sequence: 4,
    revokedDeviceIds: [],
  });

  const relay = makeRelayDouble({
    devices: [deviceRecord(kept), deviceRecord(revokedDevice)],
    behavior: {
      poll: (env) => (env ? signVerdict(wasm, kept, req, env, { decision: "approved" }) : null),
    },
  });
  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: kept.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined,
    pollIntervalMs: 5,
    accountStates: [staleWithoutRevocation, newerRevocation],
  });

  await client.requestApproval(req);
  const jwe = relay.state.captured.context_ciphertext;
  assert.throws(
    () => wasm.decrypt_context(jwe, revokedDevice.deviceId, revokedDevice.deviceX25519Seed),
    /no recipient header kid matches the requested device id/,
    "a stale lower-sequence document must not resurrect the highest-sequence revocation",
  );
});

test("(fix1-c) all enrolled devices revoked → requestApproval rejects without submitting", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const revokedState = signAccountState(wasm, approver, {
    sequence: 1,
    revokedDeviceIds: [approver.deviceId],
  });

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: { poll: () => null },
  });
  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined,
    pollIntervalMs: 5,
    accountStates: [revokedState],
  });

  await assert.rejects(
    () => client.requestApproval(sampleRequest()),
    /no non-revoked devices/,
    "an account with every enrolled device revoked must fail loudly (deny), never submit to nobody",
  );
  assert.equal(
    relay.state.submitted,
    false,
    "no envelope may be submitted when every recipient was filtered out as revoked",
  );
});

test("(b) timeout (no verdict ever) → expired, never approved, verify() false", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: { poll: () => null },
  });
  const clock = makeTimeoutClock();

  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: clock.now,
    webSocketFactory: undefined,
    pollIntervalMs: 5,
    scheduleImpl: clock.schedule,
  });

  const verdict = await client.requestApproval(req);
  assert.notEqual(verdict.decision, "approved", "a timed-out request is NEVER approved");
  assert.equal(verdict.decision, "expired", "fail-closed timeout resolves to expired");
  assert.equal(
    await verdict.verify(approver.accountRootPub),
    false,
    "no artifact → verify() is false",
  );
});

test("(b') relay reports terminal 'expired' → resolves expired", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: { poll: () => "expired" },
  });

  const verdict = await pollClient(approver, relay).requestApproval(sampleRequest());
  assert.equal(
    verdict.decision,
    "expired",
    "a relay 'expired' terminal resolves expired, never approved",
  );
});

test("(c) tampered verdict (outer decision flipped) → never approved, synthesized denied", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: (env) => {
        if (!env) return null;
        const verdict = signVerdict(wasm, approver, req, env, { decision: "approved" });
        verdict.decision = "denied"; // forge: outer diverges from the signed claim (ClaimsMismatch)
        return verdict;
      },
    },
  });

  const verdict = await pollClient(approver, relay).requestApproval(req);
  assert.notEqual(verdict.decision, "approved", "a forged verdict must NEVER resolve approved");
  assert.equal(verdict.decision, "denied", "an unverifiable verdict fails closed to denied");
  assert.equal(
    await verdict.verify(approver.accountRootPub),
    false,
    "verify() rejects the forgery",
  );
});

test("(c-sig) verdict signed by an uncertified key → never approved", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: (env) => {
        if (!env) return null;
        const requestHash = wasm.compute_request_hash(
          JSON.stringify(wireContext(req)),
          env.expires_at,
        );
        const unsigned = {
          v: 1,
          request_id: env.id,
          request_hash: requestHash,
          decision: "approved",
          decided_at: NOW_MS,
          approver: { account_id: ACCOUNT_ID, device_id: approver.deviceId },
        };
        const wrongSeed = Buffer.alloc(32, 0x42).toString("base64url"); // not the certified key
        const nonce = Buffer.alloc(16, 4).toString("base64url");
        return JSON.parse(
          wasm.sign_verdict(JSON.stringify(unsigned), wrongSeed, nonce, approver.cert),
        );
      },
    },
  });

  const verdict = await pollClient(approver, relay).requestApproval(req);
  assert.equal(
    verdict.decision,
    "denied",
    "a verdict from an uncertified key fails closed to denied",
  );
  assert.equal(await verdict.verify(approver.accountRootPub), false);
});

test("(c') authenticated human 'denied' → resolves denied (the verified decision), verify() false", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: (env) => (env ? signVerdict(wasm, approver, req, env, { decision: "denied" }) : null),
    },
  });

  const verdict = await pollClient(approver, relay).requestApproval(req);
  assert.equal(
    verdict.decision,
    "denied",
    "a verified human denial surfaces the real 'denied' decision",
  );
  assert.equal(
    await verdict.verify(approver.accountRootPub),
    false,
    "verify() is true only for approved",
  );
});

test("(d) no enrolled devices → requestApproval rejects (cannot encrypt)", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({ devices: [], behavior: { poll: () => null } });

  await assert.rejects(
    () => pollClient(approver, relay).requestApproval(sampleRequest()),
    /no enrolled devices/,
    "a request to an account with no devices must reject (no recipient to encrypt to)",
  );
});

test("(d') relay submit error (409 duplicate id) → requestApproval rejects", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: { poll: () => null, submitStatus: 409 },
  });

  await assert.rejects(
    () => pollClient(approver, relay).requestApproval(sampleRequest()),
    /relay submit failed/,
    "a relay submit failure surfaces as a rejected promise",
  );
});

test("submitted envelope carries EXACTLY the contract's key set (no plaintext leak)", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();
  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: { poll: (env) => (env ? signVerdict(wasm, approver, req, env, {}) : null) },
  });

  await pollClient(approver, relay).requestApproval(req);
  const env = relay.state.captured;
  assert.deepEqual(
    Object.keys(env).sort(),
    ["approver", "context_ciphertext", "created_at", "expires_at", "id", "v"],
    "the envelope must be exactly the relay-visible routing/lifecycle key set + ciphertext",
  );
  for (const leak of ["action", "summary", "actor", "risk", "reversible", "constraints"]) {
    assert.equal(env[leak], undefined, `plaintext field '${leak}' must NOT be on the envelope`);
  }
  assert.equal(env.expires_at, NOW_MS + TIMEOUT_MS, "expires_at = now + timeoutMs");
});

test("(g) a verdict signed for a DIFFERENT envelope id resolves denied (no-swap binding)", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();

  // The device returns a genuine, fully-signed verdict — but bound to a different request id than
  // the SDK generated. Verification uses the SDK's LOCAL id, so the id mismatch must reject (a
  // content-identical request shares a request_hash; only the id distinguishes them — contract
  // §Verification checklist #2). Pins that approval can't be replayed onto another envelope.
  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: (env) =>
        env
          ? signVerdict(
              wasm,
              approver,
              req,
              { ...env, id: "00000000-0000-4000-8000-000000000000" },
              { decision: "approved" },
            )
          : null,
    },
  });

  const verdict = await pollClient(approver, relay).requestApproval(req);
  assert.equal(
    verdict.decision,
    "denied",
    "a verdict bound to a different id must not be approved",
  );
  assert.equal(await verdict.verify(approver.accountRootPub), false);
});

test("(g') a replayed approved verdict nonce is rejected on the same client (#48)", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();
  let replayedVerdict = null;

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: (env) => {
        if (!env) return null;
        replayedVerdict ??= signVerdict(wasm, approver, req, env, { decision: "approved" });
        return replayedVerdict;
      },
    },
  });
  const client = pollClient(approver, relay);

  await withFixedRequestId("00000000-0000-4000-8000-000000000048", async () => {
    const first = await client.requestApproval(req);
    assert.equal(first.decision, "approved", "the first presentation of the nonce is accepted");
    assert.equal(
      await first.verify(approver.accountRootPub),
      true,
      "re-verifying the same Verdict object is idempotent",
    );
    assert.equal(
      await first.verify(approver.accountRootPub),
      true,
      "a second verify() call on the same object still does not self-trip replay protection",
    );

    const second = await client.requestApproval(req);
    assert.equal(
      second.decision,
      "denied",
      "the same signed verdict replayed to a later identical request fails closed",
    );
    assert.equal(
      await second.verify(approver.accountRootPub),
      false,
      "replayed nonce is not fresh",
    );
  });
});

test("(g'') a custom async NonceStore is honored atomically (#48 review)", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();
  const seen = new Set();
  const acceptedNonces = [];
  const nonceStore = {
    async checkAndInsert(nonceB64) {
      acceptedNonces.push(nonceB64);
      await Promise.resolve();
      if (seen.has(nonceB64)) return false;
      seen.add(nonceB64);
      return true;
    },
  };

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: (env) => (env ? signVerdict(wasm, approver, req, env, { decision: "approved" }) : null),
    },
  });

  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined,
    pollIntervalMs: 5,
    nonceStore,
  });

  const verdict = await client.requestApproval(req);
  assert.equal(verdict.decision, "approved");
  assert.equal(await verdict.verify(approver.accountRootPub), true);
  assert.equal(
    acceptedNonces.length,
    1,
    "requestApproval accepts the verified nonce once; verify() on the same Verdict is idempotent",
  );
});

test("(g''') default nonce stores are per-client, not global (#48 review)", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();
  let replayedVerdict = null;

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: (env) => {
        if (!env) return null;
        replayedVerdict ??= signVerdict(wasm, approver, req, env, { decision: "approved" });
        return replayedVerdict;
      },
    },
  });

  await withFixedRequestId("00000000-0000-4000-8000-000000000049", async () => {
    const first = await pollClient(approver, relay).requestApproval(req);
    assert.equal(first.decision, "approved");

    const second = await pollClient(approver, relay).requestApproval(req);
    assert.equal(
      second.decision,
      "approved",
      "a fresh default client has an independent in-memory nonce store",
    );
  });
});

test("(h) WS closes without a verdict → poll fallback delivers the approval", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: (env) => (env ? signVerdict(wasm, approver, req, env, { decision: "approved" }) : null),
    },
  });

  // A WebSocket that immediately closes with no terminal frame must degrade to polling, not fail.
  const closingWebSocketFactory = (url) => {
    const listeners = { message: [], open: [], error: [], close: [] };
    queueMicrotask(() => {
      for (const l of listeners.close) l();
    });
    return {
      url,
      addEventListener: (type, l) => listeners[type].push(l),
      close: () => {},
    };
  };

  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: closingWebSocketFactory,
    pollIntervalMs: 5,
  });

  const verdict = await client.requestApproval(req);
  assert.equal(
    verdict.decision,
    "approved",
    "WS close falls back to polling, which delivers approval",
  );
});

// ── Integrator-initiated cancellation (issue #195) ─────────────────────────────────────

test("(i) an already-aborted signal rejects immediately without ever submitting", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: { poll: () => null },
  });
  const controller = new AbortController();
  controller.abort();

  await assert.rejects(
    () =>
      pollClient(approver, relay).requestApproval({
        ...sampleRequest(),
        signal: controller.signal,
      }),
    RequestRetractedError,
    "an already-aborted signal must reject with RequestRetractedError",
  );
  assert.equal(relay.state.submitted, false, "no envelope is ever submitted to the relay");
});

test("(i') cancellation discovered over the wait WebSocket rejects with RequestRetractedError", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();
  const controller = new AbortController();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: {
      poll: () => null,
      // Simulate the relay pushing `{type:"retracted"}` back on the SAME wait socket once the
      // client's own retract call lands (mirrors `notifyRetractedRequest` in the real relay).
      onRetract: () => wsFactory.emit({ type: "retracted", request_id: relay.state.captured.id }),
    },
  });
  const wsFactory = makeControllableWebSocketFactory();

  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: wsFactory,
  });

  const pending = client.requestApproval({ ...req, signal: controller.signal });
  // Cancel once the submit has had a chance to land (a real caller cancels asynchronously, e.g. on
  // learning the approval was resolved elsewhere).
  await waitFor(() => relay.state.submitted);
  controller.abort();

  await assert.rejects(
    () => pending,
    RequestRetractedError,
    "a WS-pushed 'retracted' terminal state rejects the pending requestApproval call",
  );
  assert.equal(
    relay.state.retractCalls,
    1,
    "aborting calls the relay retract endpoint exactly once",
  );
});

test("(i'') cancellation discovered via poll fallback rejects with RequestRetractedError", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();
  const controller = new AbortController();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    behavior: { poll: () => null },
  });

  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined, // poll-only path
    pollIntervalMs: 5,
  });

  const pending = client.requestApproval({ ...req, signal: controller.signal });
  await waitFor(() => relay.state.submitted);
  controller.abort();

  await assert.rejects(
    () => pending,
    RequestRetractedError,
    "the poll fallback discovers the relay's 'retracted' status and rejects",
  );
});

test("(i''') a failed retract call is best-effort: the original deadline still governs", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const req = sampleRequest();
  const controller = new AbortController();

  const relay = makeRelayDouble({
    devices: [deviceRecord(approver)],
    // The relay refuses the retract (e.g. the request was already terminal server-side); no
    // verdict is ever produced either, so only the fail-closed deadline can resolve the call.
    behavior: { poll: () => null, retractStatus: 409 },
  });
  const clock = makeTimeoutClock();

  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    fetchImpl: relay.fetchImpl,
    nowImpl: clock.now,
    webSocketFactory: undefined,
    pollIntervalMs: 5,
    scheduleImpl: clock.schedule,
  });

  const pending = client.requestApproval({ ...req, signal: controller.signal });
  await waitFor(() => relay.state.submitted);
  controller.abort();

  const verdict = await pending;
  assert.equal(
    verdict.decision,
    "expired",
    "a best-effort retract failure never blocks or corrupts the fail-closed timeout",
  );
  assert.equal(relay.state.retractCalls, 1, "the retract attempt was still made");
  assert.equal(relay.state.retracted, false, "the relay-side status was never actually flipped");
});
