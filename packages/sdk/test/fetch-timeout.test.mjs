/**
 * Regression tests for issue #52: the pre-deadline relay calls (the account-state fetch, `submit`) and the
 * `poll()` loop must be bounded by a per-request fetch timeout, so a relay that accepts the TCP
 * connection but never responds (black-holed host, hung load balancer, captive portal) cannot wedge
 * `requestApproval` indefinitely. Before this fix those `fetch`es passed no `AbortSignal` and ran
 * *before* the await-verdict deadline timer was armed, so a hung connection left `requestApproval`
 * neither resolving to a verdict nor throwing — **no decision was ever emitted** (the fail-closed
 * gap blocking the v0 walking-skeleton "fail-closed" claim).
 *
 * The fix makes every relay fetch race against a {@link schedule}-driven timeout; a hung/aborted
 * pre-deadline fetch resolves `requestApproval` **fail-closed** to a non-approved `Verdict`
 * (`expired`) — the same terminal a wait-stage timeout produces — and a bare network error likewise
 * fails closed. These tests assert that resolution happens within bounded (virtual) time, never
 * hangs, and never returns `approved`.
 *
 * The account-state fetch (`relayAccountStateSource`, #243) runs before anything is sealed, so a
 * hung or failed one rejects with a deny-class `RecipientSelectionError` (stage `"load"`) instead
 * of resolving `expired`: no request exists yet to expire.
 *
 * Driven entirely by an injected fake clock (the `scheduleImpl`/`nowImpl` seam the SDK already
 * exposes) — no wall-clock, no real timers.
 *
 * Run order (the wasm must be built and the SDK compiled first):
 *   pnpm run build:wasm                # from repo root
 *   pnpm --filter @allw/sdk build      # tsc → dist
 *   pnpm --filter @allw/sdk test
 *
 * @see https://github.com/mike-north/allw/issues/52
 * @see ../../../docs/contract.md (§Invariants #6 — fail-closed)
 * @see ../src/relay.ts (RelayClient.timedFetch — the bounded fetch)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

import { createClient, RecipientSelectionError, relayAccountStateSource } from "../dist/index.js";
import { oneDeviceAccountStates } from "./fixtures/account-state.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

/** Load the `--target web` wasm synchronously (mirrors request-approval.test.mjs). */
async function loadWasm() {
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  const bytes = readFileSync(join(vendorDir, "allw_wasm_bg.wasm"));
  glue.initSync({ module: new WebAssembly.Module(bytes) });
  return glue;
}

const NOW_MS = 1700001000000; // 2023-11-14T22:30:00Z (fixed — fixed-dates rule)
const TIMEOUT_MS = 300_000; // overall SDK deadline (5 min) — well above the per-fetch timeout
const ACCOUNT_ID = "acct_sdk_test_52";
const RELAY_URL = "https://relay.allw.test";

/** A representative ApprovalRequest in the SDK's ergonomic camelCase shape. */
function sampleRequest(overrides = {}) {
  return {
    action: {
      recordSchemaVersion: 2,
      surface: "command",
      syntactic: { bin: "git", raw: "git push --force" },
    },
    summary: "Force-push to main",
    actor: { id: "machine:macbook-pro", kind: "claude-code" },

    reversible: false,
    timeoutMs: TIMEOUT_MS,
    ...overrides,
  };
}

/** Build an approver whose root-signed account state vouches for one device. */
function makeApprover(wasm) {
  const accountSeed = Buffer.alloc(32, 7).toString("base64url");
  const deviceX25519Seed = Buffer.alloc(32, 11).toString("base64url");
  const accountRootPub = wasm.ed25519_public_key(accountSeed);
  const deviceX25519Pub = wasm.x25519_public_key(deviceX25519Seed);
  const deviceId = "dev_sdk_test_52";
  const accountStates = oneDeviceAccountStates(wasm, {
    accountId: ACCOUNT_ID,
    accountSeed,
    deviceId,
    encryptionPub: deviceX25519Pub,
  });
  return { accountRootPub, deviceX25519Pub, deviceId, accountStates };
}

/** A floor store that records nothing (these tests are about the fetch, not the floor). */
const NO_FLOOR = { read: async () => undefined, raise: async () => {} };

function jsonResponse(data, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: () => Promise.resolve(data) };
}

/**
 * A virtual clock that fires each scheduled callback on a microtask, advancing `now` by the delay.
 * The first `schedule` call from a hung `timedFetch` advances the clock by the per-fetch timeout and
 * fires the timeout callback — deterministically, with no real waiting. Mirrors `makeTimeoutClock`
 * in request-approval.test.mjs.
 */
function makeFakeClock() {
  let current = NOW_MS;
  return {
    now: () => current,
    schedule: (fn, ms) => {
      current += ms;
      queueMicrotask(fn);
    },
  };
}

/** A promise that never settles — the "accepts the connection but never responds" relay. */
function neverResolves() {
  return new Promise(() => {});
}

/**
 * A configurable relay double. `hang` names which call hangs forever (`account-states` | `submit` |
 * `poll`); `reject` names which call rejects with a network-style `TypeError`. Other calls behave
 * normally (account state served, submit accepted, poll pending).
 */
function makeRelayDouble({ accountStates, hang, reject }) {
  const state = { submitted: false };
  const fetchImpl = (url, init = {}) => {
    const u = new URL(url);
    const path = u.pathname;
    const method = (init.method ?? "GET").toUpperCase();

    if (method === "GET" && path.endsWith("/account-states")) {
      if (hang === "account-states") return neverResolves();
      if (reject === "account-states") return Promise.reject(new TypeError("fetch failed"));
      return Promise.resolve(
        jsonResponse({ account_states: accountStates, max_sequence: accountStates.length }),
      );
    }
    if (method === "POST" && path.endsWith("/requests")) {
      state.submitted = true;
      if (hang === "submit") return neverResolves();
      if (reject === "submit") return Promise.reject(new TypeError("fetch failed"));
      return Promise.resolve(
        jsonResponse(
          { request_id: "x", status: "pending", delivered_to: 1, request_auth_token: "token-x" },
          202,
        ),
      );
    }
    if (method === "GET" && path.includes("/requests/")) {
      if (hang === "poll") return neverResolves();
      if (reject === "poll") return Promise.reject(new TypeError("fetch failed"));
      return Promise.resolve(jsonResponse({ request_id: "x", status: "pending" }));
    }
    return Promise.resolve(jsonResponse({ error: "not found" }, 404));
  };
  return { fetchImpl, state };
}

/** Build a poll-only client driven by the fake clock and a short per-fetch timeout. */
function client(approver, relay, clock, overrides = {}) {
  return createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: approver.accountRootPub,
    accountStates: approver.accountStates,
    fetchImpl: relay.fetchImpl,
    nowImpl: clock.now,
    webSocketFactory: undefined, // poll-only path (no real WS dials)
    pollIntervalMs: 5,
    fetchTimeoutMs: 30_000, // well under TIMEOUT_MS; fired by the fake clock
    scheduleImpl: clock.schedule,
    ...overrides,
  });
}

// ── #52: a hung pre-deadline fetch must fail closed (not hang, not approve) ───────────────────────

/** A client whose account state comes from the relay, through the same fake-clock-bounded fetch. */
function relaySourcedClient(approver, relay, clock) {
  return client(approver, relay, clock, {
    accountStates: relayAccountStateSource({
      relayUrl: RELAY_URL,
      accountId: ACCOUNT_ID,
      floorStore: NO_FLOOR,
      fetchImpl: relay.fetchImpl,
      fetchTimeoutMs: 30_000,
      scheduleImpl: clock.schedule,
    }),
  });
}

test("(#52) hung account-state fetch (never responds) → deny-class rejection, never hangs, nothing sent", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({ accountStates: approver.accountStates, hang: "account-states" });
  const clock = makeFakeClock();

  await assert.rejects(
    () => relaySourcedClient(approver, relay, clock).requestApproval(sampleRequest()),
    (err) => {
      assert.ok(err instanceof RecipientSelectionError, String(err));
      assert.equal(err.stage, "load");
      assert.equal(err.cause?.name, "RelayTimeoutError", "bounded by the per-fetch timeout");
      return true;
    },
  );
  assert.equal(relay.state.submitted, false, "nothing is sealed or sent");
});

test("(#52) a relay-sourced account state that loads normally still reaches submit", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({ accountStates: approver.accountStates, hang: "poll" });
  const clock = makeFakeClock();

  const verdict = await relaySourcedClient(approver, relay, clock).requestApproval(sampleRequest());
  assert.equal(relay.state.submitted, true);
  assert.equal(verdict.decision, "expired", "the hung poll still fails closed to expired");
});

test("(#52) hung submit (never responds) → fail-closed expired, never approved", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({ accountStates: approver.accountStates, hang: "submit" });
  const clock = makeFakeClock();

  const verdict = await client(approver, relay, clock).requestApproval(sampleRequest());

  assert.notEqual(verdict.decision, "approved", "a hung submit must NEVER resolve approved");
  assert.equal(verdict.decision, "expired", "a hung submit fails closed to expired");
});

// ── #52: a network error on a pre-deadline fetch likewise fails closed ────────────────────────────

test("(#52) account-state fetch rejects (network TypeError) → deny-class rejection, nothing sent", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({
    accountStates: approver.accountStates,
    reject: "account-states",
  });
  const clock = makeFakeClock();

  await assert.rejects(
    () => relaySourcedClient(approver, relay, clock).requestApproval(sampleRequest()),
    (err) => err instanceof RecipientSelectionError && err.stage === "load",
  );
  assert.equal(relay.state.submitted, false);
});

test("(#52) submit rejects (network TypeError) → fail-closed expired, never approved", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({ accountStates: approver.accountStates, reject: "submit" });
  const clock = makeFakeClock();

  const verdict = await client(approver, relay, clock).requestApproval(sampleRequest());

  assert.notEqual(verdict.decision, "approved", "a network-failed submit is NEVER approved");
  assert.equal(verdict.decision, "expired", "a network error before the deadline fails closed");
});

// ── #52: a hung poll inside the wait loop is bounded too (no single poll wedges the loop) ─────────

test("(#52) hung poll loop → fail-closed expired (the per-fetch timeout unwedges the poll)", async () => {
  const wasm = await loadWasm();
  const approver = makeApprover(wasm);
  const relay = makeRelayDouble({ accountStates: approver.accountStates, hang: "poll" });
  const clock = makeFakeClock();

  const verdict = await client(approver, relay, clock).requestApproval(sampleRequest());

  assert.notEqual(verdict.decision, "approved", "a hung poll must NEVER resolve approved");
  assert.equal(verdict.decision, "expired", "a hung poll fails closed to expired");
});
