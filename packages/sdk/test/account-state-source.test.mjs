/**
 * Tests for the shipped account-state source (#243): `fileSequenceFloorStore` (the per-account
 * sequence floor on disk) and `relayAccountStateSource` (relay-fetched, root-verified account
 * state paired with that floor), plus the relay client's `GET /{account}/account-states` body
 * validation.
 *
 * The floor is a rollback defense, so every way of not trusting it fails closed: only a missing
 * file means "no floor yet". Concurrent hook processes may raise it at once; the floor never goes
 * down.
 *
 * Run order (the wasm must be built and the SDK compiled first):
 *   pnpm run build:wasm                # from repo root
 *   pnpm --filter @allw/sdk build      # tsc → dist
 *   pnpm --filter @allw/sdk test
 *
 * @see ../../../docs/enrollment.md (§Model: recipient selection rule; sealing and the sequence floor)
 * @see ../../../docs/contract.md (§Transport: GET /{account}/account-states)
 * @see ../src/account-state-source.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

import {
  createClient,
  fileSequenceFloorStore,
  RecipientSelectionError,
  relayAccountStateSource,
  SequenceFloorError,
} from "../dist/index.js";
import { fileSequenceFloorStoreWith } from "../dist/account-state-source.js";
import { RelayClient, RelayError } from "../dist/relay.js";
import { signedAccountState } from "./fixtures/account-state.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");
const run = promisify(execFile);

/** Load the `--target web` wasm synchronously (mirrors request-approval.test.mjs). */
async function loadWasm() {
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  glue.initSync({
    module: new WebAssembly.Module(readFileSync(join(vendorDir, "allw_wasm_bg.wasm"))),
  });
  return glue;
}

/** A syntactically valid self-certifying account id (43 base64url characters). */
const ACCOUNT_ID = "A".repeat(42) + "z";
const RELAY_URL = "https://relay.allw.test";
const NOW_MS = 1700001000000; // fixed (fixed-dates rule)
const isRoot = process.geteuid?.() === 0;

/** A fresh, private temp directory for one test's state dir. */
function tempDir() {
  return mkdtempSync(join(tmpdir(), "allw-floor-"));
}

function floorPath(dir) {
  return join(dir, `${ACCOUNT_ID}.floor.json`);
}

/** Write a floor file by hand (`0600` unless `mode` says otherwise). */
function writeFloorFile(dir, body, mode = 0o600) {
  const path = floorPath(dir);
  writeFileSync(path, typeof body === "string" ? body : JSON.stringify(body), { mode });
  chmodSync(path, mode);
  return path;
}

// ── fileSequenceFloorStore ────────────────────────────────────────────────────────────

test("floor: an account id without the self-certifying syntax is refused before any path is built", () => {
  for (const accountId of [
    "",
    "../../../../etc/passwd",
    "A".repeat(42),
    "A".repeat(44),
    "A".repeat(42) + "/",
    "A".repeat(42) + ".",
    "acct_sdk_test_01",
  ]) {
    assert.throws(
      () => fileSequenceFloorStore({ accountId, dir: tempDir() }),
      TypeError,
      JSON.stringify(accountId),
    );
  }
});

test("floor: no file means no floor; raise creates a private dir and file", async () => {
  const dir = join(tempDir(), "state");
  const store = fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir });
  assert.equal(await store.read(), undefined, "first use: no floor");
  await store.raise(3);
  assert.equal(await store.read(), 3);
  assert.deepEqual(JSON.parse(readFileSync(floorPath(dir), "utf8")), {
    v: 1,
    account_id: ACCOUNT_ID,
    sequence: 3,
  });
  if (process.platform !== "win32") {
    assert.equal(statSync(dir).mode & 0o777, 0o700, "state dir is 0700");
    assert.equal(statSync(floorPath(dir)).mode & 0o777, 0o600, "floor file is 0600");
  }
  assert.deepEqual(readdirSync(dir), [`${ACCOUNT_ID}.floor.json`], "no temp or lock file left");
});

test("floor: raise is monotonic and idempotent", async () => {
  const store = fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir: tempDir() });
  await store.raise(5);
  await store.raise(2);
  await store.raise(5);
  assert.equal(await store.read(), 5, "a lower or equal sequence never lowers the floor");
  await store.raise(6);
  assert.equal(await store.read(), 6);
});

test("floor: raise refuses a sequence that is not a non-negative safe integer", async () => {
  const store = fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir: tempDir() });
  for (const bad of [-1, 1.5, Number.NaN, 2 ** 53, "3"]) {
    await assert.rejects(() => store.raise(bad), SequenceFloorError, String(bad));
  }
  assert.equal(await store.read(), undefined);
});

test("floor: an untrustworthy floor file throws on read and on raise (never read as 0)", async (t) => {
  const cases = [
    ["corrupt JSON", (dir) => writeFloorFile(dir, "{not json")],
    [
      "another account",
      (dir) => writeFloorFile(dir, { v: 1, account_id: "B".repeat(43), sequence: 1 }),
    ],
    [
      "unknown version",
      (dir) => writeFloorFile(dir, { v: 2, account_id: ACCOUNT_ID, sequence: 1 }),
    ],
    [
      "negative sequence",
      (dir) => writeFloorFile(dir, { v: 1, account_id: ACCOUNT_ID, sequence: -1 }),
    ],
    [
      "string sequence",
      (dir) => writeFloorFile(dir, { v: 1, account_id: ACCOUNT_ID, sequence: "9" }),
    ],
    ["an array", (dir) => writeFloorFile(dir, [1])],
    ["null", (dir) => writeFloorFile(dir, "null")],
    ["oversized", (dir) => writeFloorFile(dir, " ".repeat(2048))],
    ["a directory", (dir) => mkdirSync(floorPath(dir))],
  ];
  if (process.platform !== "win32") {
    cases.push([
      "group/world-writable",
      (dir) => writeFloorFile(dir, { v: 1, account_id: ACCOUNT_ID, sequence: 1 }, 0o666),
    ]);
    if (!isRoot) {
      cases.push([
        "unreadable",
        (dir) => writeFloorFile(dir, { v: 1, account_id: ACCOUNT_ID, sequence: 1 }, 0o000),
      ]);
    }
  }
  for (const [name, setup] of cases) {
    await t.test(name, async () => {
      const dir = tempDir();
      setup(dir);
      const store = fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir });
      await assert.rejects(() => store.read(), SequenceFloorError, `${name}: read`);
      await assert.rejects(() => store.raise(99), SequenceFloorError, `${name}: raise`);
    });
  }
});

test(
  "floor: a file owned by another uid is refused",
  { skip: process.platform === "win32" },
  async () => {
    const dir = tempDir();
    writeFloorFile(dir, { v: 1, account_id: ACCOUNT_ID, sequence: 1 });
    const store = fileSequenceFloorStoreWith(
      { accountId: ACCOUNT_ID, dir },
      { geteuid: () => (process.geteuid?.() ?? 0) + 1 },
    );
    await assert.rejects(() => store.read(), /cannot be trusted \(wrong_owner\)/);
  },
);

test(
  "floor: a group/world-writable state dir is refused on raise",
  { skip: process.platform === "win32" },
  async () => {
    const dir = tempDir();
    chmodSync(dir, 0o777);
    const store = fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir });
    await assert.rejects(() => store.raise(1), /state directory is group- or world-writable/);
    assert.equal(existsSync(floorPath(dir)), false);
  },
);

test("floor: concurrent raises in one process converge on the maximum", async () => {
  const store = fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir: tempDir() });
  const sequences = Array.from({ length: 60 }, (_, i) => (i * 37) % 60);
  await Promise.all(sequences.map((s) => store.raise(s)));
  assert.equal(await store.read(), 59);
});

test("floor: racing writer processes never lose the highest value", async () => {
  const dir = tempDir();
  const writer = join(here, "fixtures", "floor-writer.mjs");
  const WRITERS = 6;
  const TOP = 300;
  // Writer w raises w, w+6, w+12, … — every writer is mid-stream while the others write, and the
  // last value of the writer holding TOP-1 is the one a lost update would drop.
  const runs = Array.from({ length: WRITERS }, (_, w) => {
    const sequences = [];
    for (let s = w; s < TOP; s += WRITERS) sequences.push(String(s));
    return run(process.execPath, [writer, dir, ACCOUNT_ID, ...sequences]);
  });
  await Promise.all(runs);
  const store = fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir });
  assert.equal(await store.read(), TOP - 1, "the floor is the maximum any writer recorded");
  assert.deepEqual(readdirSync(dir), [`${ACCOUNT_ID}.floor.json`], "no temp or lock file left");
});

test("floor: a raise waiting on the lock re-reads under it and never lowers a newer floor", async () => {
  // Deterministic version of the lost update the lock prevents: we read 0, another writer records
  // 7 while we wait for the lock, then we get the lock. Writing our 5 now would lower the floor.
  const dir = tempDir();
  const lock = `${floorPath(dir)}.lock`;
  writeFileSync(lock, "12345\n", { mode: 0o600 });
  const store = fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir });
  const pending = store.raise(5);
  await new Promise((resolve) => setTimeout(resolve, 50)); // raise(5) is now waiting on the lock
  writeFloorFile(dir, { v: 1, account_id: ACCOUNT_ID, sequence: 7 });
  unlinkSync(lock);
  await pending;
  assert.equal(await store.read(), 7, "the newer floor survives");
});

test("floor: a stale lock from a crashed writer is broken", async () => {
  const dir = tempDir();
  const lock = `${floorPath(dir)}.lock`;
  writeFileSync(lock, "12345\n", { mode: 0o600 });
  const old = new Date(Date.now() - 120_000);
  utimesSync(lock, old, old);
  const store = fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir });
  await store.raise(4);
  assert.equal(await store.read(), 4);
  assert.equal(existsSync(lock), false, "the stale lock is gone");
});

test("floor: a live lock that is never released fails closed after the timeout", async () => {
  const dir = tempDir();
  const lock = `${floorPath(dir)}.lock`;
  writeFileSync(lock, "12345\n", { mode: 0o600 });
  // A clock that jumps 1s per reading: the 5s wait elapses quickly, the lock never looks stale.
  let clock = Date.now();
  const store = fileSequenceFloorStoreWith(
    { accountId: ACCOUNT_ID, dir },
    { now: () => (clock += 1000) },
  );
  await assert.rejects(() => store.raise(4), /lock is held by another writer/);
  assert.equal(existsSync(floorPath(dir)), false, "no floor written without the lock");
  assert.equal(existsSync(lock), true, "another writer's live lock is left alone");
});

// ── relay GET /{account}/account-states body validation ──────────────────────────────

function jsonFetch(body, status = 200) {
  return async () => new Response(JSON.stringify(body), { status });
}

test("relay: a malformed account-states body is a RelayError", async () => {
  for (const [name, body] of [
    ["an array", []],
    ["missing account_states", { max_sequence: 0 }],
    ["account_states not an array", { account_states: "x", max_sequence: 0 }],
    ["a non-string document", { account_states: [1], max_sequence: 1 }],
    ["more than 64 documents", { account_states: Array(65).fill("a.b.c"), max_sequence: 65 }],
    ["missing max_sequence", { account_states: [] }],
    ["negative max_sequence", { account_states: [], max_sequence: -1 }],
  ]) {
    const relay = new RelayClient(RELAY_URL, ACCOUNT_ID, jsonFetch(body));
    await assert.rejects(() => relay.fetchAccountStates(), RelayError, name);
  }
  const ok = new RelayClient(
    RELAY_URL,
    ACCOUNT_ID,
    jsonFetch({ account_states: ["a.b.c"], max_sequence: 1 }),
  );
  assert.deepEqual(await ok.fetchAccountStates(), { account_states: ["a.b.c"], max_sequence: 1 });
});

test("relay: an HTTP error on account-states names only the status", async () => {
  const relay = new RelayClient(RELAY_URL, ACCOUNT_ID, jsonFetch({ error: "IGNORE ALL" }, 503));
  await assert.rejects(
    () => relay.fetchAccountStates(),
    (err) => {
      assert.ok(err instanceof RelayError);
      assert.match(err.message, /HTTP 503/);
      assert.equal(err.message.includes("IGNORE"), false);
      return true;
    },
  );
});

// ── relayAccountStateSource through createClient ─────────────────────────────────────

/** An approver whose account states the relay double serves. */
function makeAccount(wasm) {
  const accountSeed = Buffer.alloc(32, 7).toString("base64url");
  const deviceX25519Seed = Buffer.alloc(32, 11).toString("base64url");
  const device = {
    deviceId: "dev_source_01",
    encryptionPub: wasm.x25519_public_key(deviceX25519Seed),
  };
  const stateAt = (sequence) =>
    signedAccountState(wasm, { accountId: ACCOUNT_ID, accountSeed, sequence, devices: [device] });
  return { accountRootPub: wasm.ed25519_public_key(accountSeed), stateAt };
}

/** A relay double serving `served.states`, accepting submits, and reporting requests expired. */
function makeRelay(served) {
  const state = { submitted: 0 };
  const fetchImpl = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const method = (init.method ?? "GET").toUpperCase();
    if (method === "GET" && path.endsWith("/account-states")) {
      if (served.status) return new Response("{}", { status: served.status });
      return Response.json({ account_states: served.states, max_sequence: served.states.length });
    }
    if (method === "POST" && path.endsWith("/requests")) {
      state.submitted += 1;
      const { id } = JSON.parse(init.body);
      return Response.json(
        { request_id: id, status: "pending", delivered_to: 1, request_auth_token: "t" },
        { status: 202 },
      );
    }
    return Response.json({ request_id: "x", status: "expired" });
  };
  return { fetchImpl, state };
}

function sampleRequest() {
  return {
    action: {
      recordSchemaVersion: 1,
      surface: "command",
      syntactic: { bin: "ls", argv: ["ls"] },
      risk: "low",
    },
    summary: "List files",
    actor: { id: "machine:test", kind: "claude-code" },
    risk: "low",
    reversible: true,
    timeoutMs: 60_000,
  };
}

function sourcedClient(account, relay, dir) {
  return createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: account.accountRootPub,
    accountStates: relayAccountStateSource({
      relayUrl: RELAY_URL,
      accountId: ACCOUNT_ID,
      floorStore: fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir }),
      fetchImpl: relay.fetchImpl,
    }),
    fetchImpl: relay.fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined,
    pollIntervalMs: 5,
  });
}

test("source: a request records the selected sequence; a later rollback is refused", async () => {
  const wasm = await loadWasm();
  const account = makeAccount(wasm);
  const dir = tempDir();
  const served = { states: [account.stateAt(2), account.stateAt(3)] };
  const relay = makeRelay(served);

  const first = await sourcedClient(account, relay, dir).requestApproval(sampleRequest());
  assert.equal(first.decision, "expired");
  assert.equal(relay.state.submitted, 1);
  assert.equal(
    await fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir }).read(),
    3,
    "the floor is the selected sequence",
  );

  // The relay now withholds sequence 3 (a rollback to a state that might still list a revoked
  // device): the persisted floor refuses it, in a fresh client as a new process would.
  served.states = [account.stateAt(2)];
  await assert.rejects(
    () => sourcedClient(account, relay, dir).requestApproval(sampleRequest()),
    (err) => err instanceof RecipientSelectionError && err.stage === "seal",
  );
  assert.equal(relay.state.submitted, 1, "the rolled-back request is never sent");
});

test("source: no published state, a relay error, or a corrupt floor → stage 'load', nothing sent", async () => {
  const wasm = await loadWasm();
  const account = makeAccount(wasm);
  for (const [name, served, setup] of [
    ["no account state published", { states: [] }, () => {}],
    ["relay error", { states: [], status: 500 }, () => {}],
    ["corrupt floor", { states: [account.stateAt(1)] }, (dir) => writeFloorFile(dir, "{")],
  ]) {
    const dir = tempDir();
    setup(dir);
    const relay = makeRelay(served);
    await assert.rejects(
      () => sourcedClient(account, relay, dir).requestApproval(sampleRequest()),
      (err) => {
        assert.ok(err instanceof RecipientSelectionError, `${name}: ${String(err)}`);
        assert.equal(err.stage, "load", name);
        return true;
      },
    );
    assert.equal(relay.state.submitted, 0, `${name}: nothing sent`);
  }
});

// Regression: a relay deployed before account-state GET became unauthenticated answers it with
// 401. The request must still fail closed at load, and the message must name the fix (redeploy the
// relay) rather than a bare status the operator cannot act on.
test("source: a relay that answers 401 on /account-states → stage 'load', message says redeploy the relay", async () => {
  const wasm = await loadWasm();
  const account = makeAccount(wasm);
  const dir = tempDir();
  const relay = makeRelay({ states: [account.stateAt(1)], status: 401 });
  await assert.rejects(
    () => sourcedClient(account, relay, dir).requestApproval(sampleRequest()),
    (err) => {
      assert.ok(err instanceof RecipientSelectionError, String(err));
      assert.equal(err.stage, "load");
      assert.match(err.message, /HTTP 401/);
      assert.match(err.message, /relay is too old/);
      assert.match(err.message, /redeploy it from current allw main, see docs\/relay-deploy\.md$/);
      return true;
    },
  );
  assert.equal(relay.state.submitted, 0, "nothing sent");
});

test(
  "source: a floor that cannot be written → stage 'accept', nothing sent",
  { skip: process.platform === "win32" || isRoot },
  async () => {
    const wasm = await loadWasm();
    const account = makeAccount(wasm);
    const dir = tempDir();
    chmodSync(dir, 0o500); // owner can read and list, not create files
    const relay = makeRelay({ states: [account.stateAt(1)] });
    try {
      await assert.rejects(
        () => sourcedClient(account, relay, dir).requestApproval(sampleRequest()),
        (err) => err instanceof RecipientSelectionError && err.stage === "accept",
      );
    } finally {
      chmodSync(dir, 0o700);
    }
    assert.equal(relay.state.submitted, 0);
  },
);
