/**
 * Relay-client (pairing) tests for the v0 stand-in approver (issue #41).
 *
 * The real relay runs under `workerd` (Cloudflare Workers), so a Node CLI cannot reach it
 * in-process. These tests exercise the approver's HTTP pairing client and `pair` orchestration
 * against a lightweight in-Node HTTP server that mimics the relay's device-facing pairing surface
 * (`docs/contract.md` §Transport → Relay routing API; relay package `POST /:acct/pairing/start`,
 * `POST /:acct/pairing/complete`). It asserts the approver:
 *   - derives the self-certifying account id from its account root and authorizes
 *     `/pairing/start` with a root-signed `allw-pairing-start+jws` — the fake relay verifies it with
 *     the real core exactly as the relay does (derivation, signature, freshness, one-time `jti`),
 *   - sends only the **X25519 (encryption) public key** to `/pairing/complete` (never a seed),
 *   - mints + stores a device_cert and the relay/account/device metadata,
 *   - builds the correct `ws(s)://…/devices/:id/connect` presence URL,
 *   - publishes and fetches account state with **no device token** — the fake relay verifies each
 *     published document against the bound root with the real core, as the relay does.
 *
 * @see ../../relay/src/index.ts (the endpoints mimicked here)
 * @see ../../../docs/contract.md §Identity & keys, §Transport
 * @see ../../../docs/relay-api.md §3 Pairing (root-signed pairing/start)
 * @see ../../../docs/enrollment.md §Self-Certifying Account Id
 * @see ../../../docs/relay-api.md §3 Account state (root-verified publish, unauthenticated fetch)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadWasm } from "../dist/index.js";
import { readKeyfile } from "../dist/lib/keyfile.js";
import {
  deviceConnectWsUrl,
  fetchAccountStates,
  fetchAccountStatesWithMetadata,
  pairingStart,
  publishAccountStates,
  pairingComplete,
  PAIRING_TIMEOUT_MS,
} from "../dist/lib/relay-client.js";
import { runPair } from "../dist/commands/pair.js";

const PAIRING_CODE = "ABC23456";
const ASSIGNED_DEVICE_ID = "dev-from-relay-xyz";
const PAIRING_AUTH_TOKEN = "pairing-token-from-relay";
const DEVICE_AUTH_TOKEN = "device-token-from-relay";
/** The fixed clock both `runPair` (`now`) and the fake relay's verifier use. */
const FIXED_NOW = 1700000000000;
/** What the fake relay serves for an account nothing was published to (opaque to the client). */
/** What the real relay serves for an account that has never published account state. */
const NO_ACCOUNT_STATES = { account_states: [], max_sequence: 0 };

const DEFAULT_ACCOUNT_STATES = {
  account_states: ["account-state-jws-1", "account-state-jws-2"],
  max_sequence: 7,
};

/**
 * Start a fake relay mimicking the pairing endpoints. Captures every request body so tests can
 * assert exactly what the approver sent. `pairing/start` is verified like the real relay: the path's
 * account id must derive from `root_pubkey` (400), `authorization` is required (401), and the core
 * must accept it at `now` with an unused `jti` (403); the first success binds the root.
 * `account-states` mirrors the relay too: `POST` needs a bound root (409), every document must pass
 * the core's `verify_account_state` (403), and the highest sequence must rise (409); `GET` needs no
 * token. Unpublished accounts serve `unpublished` (default `DEFAULT_ACCOUNT_STATES`; pairing tests
 * use the real relay's empty set). `/pairing/complete` assigns `deviceIds` in order (the last one
 * repeats). `accountStatesGetStatus` makes `GET account-states` answer that status instead, as a relay
 * deployed before the endpoint was unauthenticated does (401). Returns { url, requests, boundRoots,
 * publishedStates, close }.
 */
async function startFakeRelay({
  now = FIXED_NOW,
  unpublished = DEFAULT_ACCOUNT_STATES,
  deviceIds = [ASSIGNED_DEVICE_ID],
  accountStatesGetStatus,
} = {}) {
  let completes = 0;
  const wasm = await loadWasm();
  const requests = [];
  /** account id → bound root pubkey. */
  const boundRoots = new Map();
  const seenJtis = new Set();
  /** account id → { account_states, max_sequence } of verified published documents. */
  const publishedStates = new Map();
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const parsed = body ? JSON.parse(body) : {};
      requests.push({
        method: req.method,
        url: req.url,
        body: parsed,
        authorization: req.headers.authorization,
      });

      // POST /:acct/pairing/start → { code, expires_at }
      if (req.method === "POST" && req.url.endsWith("/pairing/start")) {
        const accountId = decodeURIComponent(req.url.split("/")[1] ?? "");
        const reject = (status) => {
          res.writeHead(status, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `rejected ${String(status)}` }));
        };
        if (typeof parsed.root_pubkey !== "string") return reject(400);
        let derived;
        try {
          derived = wasm.account_id_for_root(parsed.root_pubkey);
        } catch {
          return reject(400);
        }
        if (derived !== accountId) return reject(400);
        if (typeof parsed.authorization !== "string") return reject(401);
        let claims;
        try {
          claims = JSON.parse(
            wasm.verify_pairing_start_authorization(
              parsed.authorization,
              accountId,
              parsed.root_pubkey,
              now,
            ),
          );
        } catch {
          return reject(403);
        }
        if (seenJtis.has(claims.jti)) return reject(403);
        seenJtis.add(claims.jti);
        if (!boundRoots.has(accountId)) boundRoots.set(accountId, parsed.root_pubkey);
        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            code: PAIRING_CODE,
            expires_at: 1700003600000,
            pairing_auth_token: PAIRING_AUTH_TOKEN,
          }),
        );
        return;
      }
      // POST /:acct/pairing/complete → { device_id, device_auth_token }
      if (req.method === "POST" && req.url.endsWith("/pairing/complete")) {
        if (req.headers.authorization !== `Bearer ${PAIRING_AUTH_TOKEN}`) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "authorization denied" }));
          return;
        }
        const deviceId = deviceIds[Math.min(completes, deviceIds.length - 1)];
        completes += 1;
        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            device_id: deviceId,
            device_auth_token: DEVICE_AUTH_TOKEN,
          }),
        );
        return;
      }
      // POST /:acct/account-states → { account_states, max_sequence } (root-verified, no token)
      if (req.method === "POST" && req.url.endsWith("/account-states")) {
        const accountId = decodeURIComponent(req.url.split("/")[1] ?? "");
        const reply = (status, payload) => {
          res.writeHead(status, { "Content-Type": "application/json" });
          res.end(JSON.stringify(payload));
        };
        const docs = parsed.account_states;
        if (
          !Array.isArray(docs) ||
          docs.length === 0 ||
          docs.length > 16 ||
          !docs.every((doc) => typeof doc === "string")
        ) {
          return reply(400, { error: "'account_states' must be an array of 1 to 16 strings" });
        }
        const root = boundRoots.get(accountId);
        if (root === undefined) return reply(409, { error: "account root not bound" });
        let highest = -1;
        for (const jws of docs) {
          let sequence;
          try {
            sequence = JSON.parse(wasm.verify_account_state(jws, accountId, root)).sequence;
          } catch {
            return reply(403, { error: "did not verify" });
          }
          highest = Math.max(highest, sequence);
        }
        const stored = publishedStates.get(accountId)?.max_sequence ?? -1;
        if (highest <= stored) return reply(409, { error: "sequence not above current" });
        const current = { account_states: parsed.account_states, max_sequence: highest };
        publishedStates.set(accountId, current);
        return reply(200, current);
      }
      // GET /:acct/account-states → { account_states, max_sequence } (unauthenticated)
      if (req.method === "GET" && req.url.endsWith("/account-states")) {
        if (accountStatesGetStatus !== undefined) {
          res.writeHead(accountStatesGetStatus, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "authorization required" }));
          return;
        }
        const accountId = decodeURIComponent(req.url.split("/")[1] ?? "");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(publishedStates.get(accountId) ?? unpublished));
        return;
      }
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}`,
        requests,
        boundRoots,
        publishedStates,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

/**
 * Start a relay that ACCEPTS the connection but NEVER responds (it holds the socket open and writes
 * nothing). This is the "hung relay" failure mode the `AbortSignal.timeout` guard exists for — a
 * dead-but-listening relay, distinct from connection-refused. Returns { url, close }.
 */
function startHungRelay() {
  const sockets = new Set();
  const server = createServer((req, _res) => {
    // Consume the request but deliberately never call res.end()/write() — the client must abort.
    req.resume();
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise((r) => {
            for (const s of sockets) s.destroy();
            server.close(r);
          }),
      });
    });
  });
}

async function withTempKeyfile(fn) {
  const dir = mkdtempSync(join(tmpdir(), "allw-approver-pair-"));
  try {
    // Awaited, so the directory outlives an async `fn`.
    return await fn(join(dir, "keyfile.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A deterministic account root for client-level tests. */
function testRoot(wasm, fill) {
  const seed = Buffer.alloc(32, fill).toString("base64url");
  const pubkey = wasm.ed25519_public_key(seed);
  return { seed, pubkey, accountId: wasm.account_id_for_root(pubkey) };
}

test("pairingStart sends the root pubkey + root-signed authorization and returns the code", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay();
  try {
    const root = testRoot(wasm, 0x41);
    const authorization = wasm.sign_pairing_start_authorization(
      root.seed,
      FIXED_NOW,
      FIXED_NOW + 60_000,
      "jti-client-test-0001",
    );
    const result = await pairingStart(
      relay.url,
      root.accountId,
      { rootPubkey: root.pubkey, authorization },
      "desk",
    );
    assert.equal(result.code, PAIRING_CODE);
    assert.equal(result.pairing_auth_token, PAIRING_AUTH_TOKEN);
    assert.equal(relay.requests[0].url, `/${root.accountId}/pairing/start`);
    assert.deepEqual(relay.requests[0].body, {
      root_pubkey: root.pubkey,
      authorization,
      label: "desk",
    });
  } finally {
    await relay.close();
  }
});

test("pairingStart surfaces a relay rejection (account id not derived from the root) as an error", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay();
  try {
    const root = testRoot(wasm, 0x42);
    const authorization = wasm.sign_pairing_start_authorization(
      root.seed,
      FIXED_NOW,
      FIXED_NOW + 60_000,
      "jti-client-test-0002",
    );
    await assert.rejects(
      () => pairingStart(relay.url, "acct-free-form", { rootPubkey: root.pubkey, authorization }),
      /HTTP 400/,
    );
  } finally {
    await relay.close();
  }
});

test("pairingComplete sends ONLY the X25519 pubkey and returns the relay device_id", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay();
  try {
    const x25519Pub = wasm.x25519_public_key(Buffer.alloc(32, 11).toString("base64url"));
    const paired = await pairingComplete(
      relay.url,
      "acct-2",
      PAIRING_CODE,
      PAIRING_AUTH_TOKEN,
      x25519Pub,
      "laptop",
    );
    assert.equal(paired.device_id, ASSIGNED_DEVICE_ID);
    assert.equal(paired.device_auth_token, DEVICE_AUTH_TOKEN);

    const completeReq = relay.requests.find((r) => r.url.endsWith("/pairing/complete"));
    assert.equal(completeReq.authorization, `Bearer ${PAIRING_AUTH_TOKEN}`);
    assert.equal(completeReq.body.pubkey, x25519Pub, "the registered pubkey is the X25519 key");
    assert.equal(completeReq.body.code, PAIRING_CODE);
    // SECURITY: no seed/secret may ever be sent to the relay (zero-knowledge).
    const bodyKeys = Object.keys(completeReq.body);
    assert.ok(
      !bodyKeys.some((k) => k.includes("seed") || k.includes("secret") || k.includes("private")),
      "no secret material is sent to the relay",
    );
  } finally {
    await relay.close();
  }
});

test("fetchAccountStates sends no device token and returns compact state docs", async () => {
  const relay = await startFakeRelay();
  try {
    const states = await fetchAccountStates(relay.url, "acct-2");

    assert.deepEqual(states, DEFAULT_ACCOUNT_STATES.account_states);
    const fetchReq = relay.requests.find((r) => r.url.endsWith("/account-states"));
    assert.equal(fetchReq.method, "GET");
    // GET account-states is unauthenticated (#242): the device token never leaves the keyfile.
    assert.equal(fetchReq.authorization, undefined);
  } finally {
    await relay.close();
  }
});

test("fetchAccountStatesWithMetadata returns relay max_sequence metadata", async () => {
  const relay = await startFakeRelay();
  try {
    const result = await fetchAccountStatesWithMetadata(relay.url, "acct-2");

    assert.deepEqual(result.accountStates, DEFAULT_ACCOUNT_STATES.account_states);
    assert.equal(result.maxSequence, 7);
  } finally {
    await relay.close();
  }
});

test("fetchAccountStatesWithMetadata rejects a response without max_sequence (fail-closed, no default)", async () => {
  // Regression: a missing max_sequence used to be coerced to 0, silently disabling the approver's
  // relay-metadata rollback check instead of failing closed.
  const originalFetch = globalThis.fetch;
  try {
    for (const body of [
      { account_states: [] },
      { account_states: [], max_sequence: null },
      { account_states: [], max_sequence: -1 },
      { account_states: [], max_sequence: 2 ** 53 },
    ]) {
      globalThis.fetch = async () =>
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      await assert.rejects(
        fetchAccountStatesWithMetadata("https://relay.allw.test", "acct-2"),
        /unexpected shape/,
        JSON.stringify(body),
      );
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

/** A root-signed account-state document for `root`'s own account at `sequence`. */
function signedAccountState(wasm, root, sequence) {
  return wasm.sign_account_state(
    JSON.stringify({
      v: 1,
      account_id: root.accountId,
      sequence,
      current_root: root.pubkey,
      previous_roots: [],
      devices: [],
      actors: [],
      revocations: [{ kind: "device", id: "dev-lost", revoked_at: FIXED_NOW }],
    }),
    root.seed,
  );
}

test("publishAccountStates publishes root-signed state with no device token", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay();
  try {
    const root = testRoot(wasm, 0x51);
    relay.boundRoots.set(root.accountId, root.pubkey);
    const doc = signedAccountState(wasm, root, 3);

    const result = await publishAccountStates(relay.url, root.accountId, [doc]);

    assert.deepEqual(result, { accountStates: [doc], maxSequence: 3 });
    const publishReq = relay.requests.find(
      (r) => r.method === "POST" && r.url.endsWith("/account-states"),
    );
    assert.equal(publishReq.authorization, undefined);
    // The relay derives max_sequence from the verified documents; the client never asserts one.
    assert.deepEqual(publishReq.body, { account_states: [doc] });
    assert.deepEqual(
      (await fetchAccountStatesWithMetadata(relay.url, root.accountId)).accountStates,
      [doc],
    );
  } finally {
    await relay.close();
  }
});

test("publishAccountStates fails closed on a relay rejection", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay();
  try {
    const root = testRoot(wasm, 0x52);
    const other = testRoot(wasm, 0x53);
    const doc = signedAccountState(wasm, root, 3);

    // No root bound yet → 409.
    await assert.rejects(publishAccountStates(relay.url, root.accountId, [doc]), /HTTP 409/);

    relay.boundRoots.set(root.accountId, root.pubkey);
    // Signed by another root → 403.
    const forged = signedAccountState(wasm, { ...other, accountId: root.accountId }, 4);
    await assert.rejects(publishAccountStates(relay.url, root.accountId, [forged]), /HTTP 403/);

    // An empty document set is malformed → 400 (the fake relay enforces the real 1–16 bound).
    await assert.rejects(publishAccountStates(relay.url, root.accountId, []), /HTTP 400/);

    // Republishing the current document (not a higher sequence) → 409.
    await publishAccountStates(relay.url, root.accountId, [doc]);
    await assert.rejects(publishAccountStates(relay.url, root.accountId, [doc]), /HTTP 409/);
  } finally {
    await relay.close();
  }
});

test("runPair self-drives start+complete, mints a device_cert, and persists pairing state", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay({ unpublished: NO_ACCOUNT_STATES });
  const logLines = [];
  try {
    await withTempKeyfile(async (keyfilePath) => {
      const updated = await runPair(
        wasm,
        {
          relayUrl: relay.url,
          keyfilePath,
          label: "cabin",
          now: FIXED_NOW,
        },
        (line) => logLines.push(line),
      );

      // The account id is derived from the keyfile's root (never chosen), the relay verified the
      // root-signed start for that id, and bound that root.
      const derivedId = wasm.account_id_for_root(updated.account_root_pubkey);
      assert.match(derivedId, /^[A-Za-z0-9_-]{43}$/);
      assert.equal(updated.account_id, derivedId);
      assert.equal(relay.requests[0].url, `/${derivedId}/pairing/start`);
      assert.equal(relay.requests[1].url, `/${derivedId}/pairing/complete`);
      assert.equal(relay.boundRoots.get(derivedId), updated.account_root_pubkey);
      // Integrator-facing output shows the derived id next to the trust anchor.
      assert.ok(logLines.some((l) => l.includes(`account id:          ${derivedId}`)));
      assert.ok(
        logLines.some((l) => l.includes(`account-root pubkey: ${updated.account_root_pubkey}`)),
      );
      // The start request carried no secret material.
      assert.deepEqual(Object.keys(relay.requests[0].body).sort(), [
        "authorization",
        "label",
        "root_pubkey",
      ]);

      // The persisted keyfile carries the relay-issued device id + a minted cert.
      assert.equal(updated.device_id, ASSIGNED_DEVICE_ID);
      assert.equal(updated.device_auth_token, DEVICE_AUTH_TOKEN);
      assert.equal(updated.relay_url, relay.url);
      assert.ok(
        updated.device_cert && updated.device_cert.split(".").length === 3,
        "a compact-JWS device_cert is stored",
      );

      // It round-trips from disk identically (the cert + seeds persisted).
      const fromDisk = readKeyfile(keyfilePath);
      assert.deepEqual(fromDisk, updated, "the paired keyfile persisted to disk");

      // The relay only ever saw the X25519 pubkey on /pairing/complete.
      const completeReq = relay.requests.find((r) => r.url.endsWith("/pairing/complete"));
      assert.equal(completeReq.body.pubkey, updated.device_encryption_pubkey);

      // The minted cert chains the device SIGNING key to the account root — verify it certifies the
      // signing pubkey by signing a verdict with the device signing seed and verifying it.
      const requestId = "req-pair-roundtrip";
      const context = {
        action: {
          record_schema_version: 2,
          surface: "command",
          syntactic: { raw: "echo hi" },
        },
        summary: "echo hi",
        actor: { id: "machine:x", kind: "claude-code" },

        reversible: true,
        constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
      };
      const contextJson = JSON.stringify(context);
      const expiresAt = 1700003600000;
      const requestHash = wasm.compute_request_hash(contextJson, expiresAt);
      const unsigned = {
        v: 1,
        request_id: requestId,
        request_hash: requestHash,
        decision: "approved",
        decided_at: 1700001000000,
        approver: { account_id: updated.account_id, device_id: ASSIGNED_DEVICE_ID },
      };
      const nonce = Buffer.alloc(16, 5).toString("base64url");
      const verdict = wasm.sign_verdict(
        JSON.stringify(unsigned),
        updated.device_signing_seed,
        nonce,
        updated.device_cert,
      );
      const requestJson = JSON.stringify({
        v: 1,
        id: requestId,
        created_at: 1700000000000,
        expires_at: expiresAt,
        approver: updated.account_id,
      });
      const result = JSON.parse(
        wasm.verify_verdict(
          verdict,
          requestJson,
          contextJson,
          updated.account_root_pubkey,
          1700001500000,
        ),
      );
      assert.equal(
        result.approved,
        true,
        "the minted device_cert chains the signing key to the account root",
      );
    });
  } finally {
    await relay.close();
  }
});

test("pairingStart ABORTS against a hung relay (fail-closed AbortSignal.timeout — #51 nit)", async () => {
  await loadWasm();
  const relay = await startHungRelay();
  // Inject a short timeout so the abort is provable without waiting the production 15s. The
  // assertions below are pinned to THIS value (not the 15s default), so they actually prove the
  // INJECTED timeout fired — any sub-15s failure would otherwise pass vacuously.
  const INJECTED_TIMEOUT_MS = 150;
  // The default must be the real production window — guards against the injected value silently
  // becoming the default (which would make the timing assertion meaningless).
  assert.ok(
    PAIRING_TIMEOUT_MS > INJECTED_TIMEOUT_MS,
    "the production default must exceed the injected test timeout",
  );
  try {
    // The relay accepts the socket but never responds. Without the abort, this would hang forever;
    // with it, the request must reject (aborted via AbortSignal.timeout) rather than block.
    const started = Date.now();
    await assert.rejects(
      () =>
        pairingStart(
          relay.url,
          "acct-hung",
          { rootPubkey: "unused", authorization: "unused" },
          undefined,
          INJECTED_TIMEOUT_MS,
        ),
      // Node surfaces an AbortSignal.timeout as a TimeoutError (name), not a generic Error message —
      // assert specifically so this can't pass on some unrelated transport rejection.
      (err) => err instanceof Error && err.name === "TimeoutError",
      "a hung relay must abort the pairing request with a timeout, not block indefinitely",
    );
    // Pinned to the INJECTED timeout: the request must reject within a small multiple of 150ms,
    // proving the injected timeout (not luck or some 14s-later failure) drove the abort. The slack
    // (a few × the timeout) absorbs CI scheduling jitter while staying far below the 15s default.
    const elapsed = Date.now() - started;
    assert.ok(
      elapsed < INJECTED_TIMEOUT_MS * 5,
      `the request aborted within ~5× the injected ${String(INJECTED_TIMEOUT_MS)}ms timeout (was ${String(elapsed)}ms), proving the injected timeout fired`,
    );
  } finally {
    await relay.close();
  }
});

test("deviceConnectWsUrl upgrades http(s)→ws(s) and builds the presence path", async () => {
  await loadWasm();
  assert.equal(
    deviceConnectWsUrl("https://relay.example.com", "acct-9", "dev-9", "device-token"),
    "wss://relay.example.com/acct-9/devices/dev-9/connect?auth=device-token",
  );
  assert.equal(
    deviceConnectWsUrl("http://127.0.0.1:8787/", "acct-9", "dev 9", "token value"),
    "ws://127.0.0.1:8787/acct-9/devices/dev%209/connect?auth=token%20value",
  );
});

test("runPair refuses to overwrite a CORRUPT keyfile with a fresh identity (review item #4)", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay();
  try {
    await withTempKeyfile(async (keyfilePath) => {
      // A pre-existing but corrupt keyfile (invalid JSON) must NOT be silently discarded and
      // replaced with a new identity — that could orphan a relay-registered device.
      writeFileSync(keyfilePath, "{ corrupt keyfile");
      await assert.rejects(
        () => runPair(wasm, { relayUrl: relay.url, keyfilePath }, () => {}),
        /not valid JSON/,
        "pair must fail loudly on a corrupt keyfile, not mint a new identity over it",
      );
      // The relay must never have been contacted (we bailed before any registration).
      assert.equal(
        relay.requests.length,
        0,
        "no relay registration happens when the existing keyfile is corrupt",
      );
    });
  } finally {
    await relay.close();
  }
});

test("runPair rejects an explicit --account that does not match the derived id, before any relay call", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay();
  try {
    await withTempKeyfile(async (keyfilePath) => {
      await assert.rejects(
        () =>
          runPair(
            wasm,
            { relayUrl: relay.url, accountId: "my-account", keyfilePath, now: FIXED_NOW },
            () => {},
          ),
        /does not match the account id derived/,
      );
      assert.equal(relay.requests.length, 0, "a mismatched id never reaches the relay");
    });
  } finally {
    await relay.close();
  }
});

test("runPair accepts an explicit --account equal to the derived id", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay({ unpublished: NO_ACCOUNT_STATES });
  try {
    await withTempKeyfile(async (keyfilePath) => {
      // Generate the identity first so the test knows the derived id up front.
      const { runKeygen } = await import("../dist/commands/keygen.js");
      const keyfile = runKeygen(wasm, { keyfilePath }, () => {});
      const derivedId = wasm.account_id_for_root(keyfile.account_root_pubkey);
      const updated = await runPair(
        wasm,
        { relayUrl: relay.url, accountId: derivedId, keyfilePath, now: FIXED_NOW },
        () => {},
      );
      assert.equal(updated.account_id, derivedId);
      assert.equal(relay.boundRoots.get(derivedId), keyfile.account_root_pubkey);
    });
  } finally {
    await relay.close();
  }
});

test("runPair fails closed when the relay rejects the authorization (e.g. stale clock)", async () => {
  const wasm = await loadWasm();
  // The relay's clock is 10 minutes ahead: the 2-minute authorization pair signs is expired there.
  const relay = await startFakeRelay({ now: FIXED_NOW + 10 * 60 * 1000 });
  try {
    await withTempKeyfile(async (keyfilePath) => {
      await assert.rejects(
        () => runPair(wasm, { relayUrl: relay.url, keyfilePath, now: FIXED_NOW }, () => {}),
        /HTTP 403/,
      );
      assert.equal(
        relay.requests.filter((r) => r.url.endsWith("/pairing/complete")).length,
        0,
        "no device is registered after a rejected start",
      );
    });
  } finally {
    await relay.close();
  }
});

// ── pair publishes the account state that vouches for the device (#243) ─────────────────────────

/** Verify the relay's published documents for `keyfile`'s account; returns the AccountState JSONs. */
function publishedStatesFor(wasm, relay, keyfile) {
  const published = relay.publishedStates.get(keyfile.account_id);
  assert.ok(published, "pair published account state");
  return published.account_states.map((jws) =>
    JSON.parse(wasm.verify_account_state(jws, keyfile.account_id, keyfile.account_root_pubkey)),
  );
}

test("runPair publishes a root-signed account state vouching for exactly this device (#243)", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay({ unpublished: NO_ACCOUNT_STATES });
  try {
    await withTempKeyfile(async (keyfilePath) => {
      const updated = await runPair(
        wasm,
        { relayUrl: relay.url, keyfilePath, now: FIXED_NOW },
        () => {},
      );
      const [state] = publishedStatesFor(wasm, relay, updated);
      assert.equal(state.sequence, 1, "the first state of a fresh account");
      assert.equal(state.current_root, updated.account_root_pubkey);
      assert.deepEqual(state.devices, [
        {
          device_id: ASSIGNED_DEVICE_ID,
          encryption_pubkey: updated.device_encryption_pubkey,
          signing_pubkey: updated.device_signing_pubkey,
          status: "active",
        },
      ]);
      assert.equal(updated.account_state_highest_sequence, 1, "the device's own floor follows");
      // The publish came after pairing/complete and carried no device token.
      const urls = relay.requests.map((r) => `${r.method} ${r.url.split("/").slice(2).join("/")}`);
      assert.deepEqual(urls.slice(-2), ["GET account-states", "POST account-states"]);
      assert.equal(relay.requests.at(-1).authorization, undefined);
    });
  } finally {
    await relay.close();
  }
});

test("runPair for a second device carries the first device forward at the next sequence (#243)", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay({
    unpublished: NO_ACCOUNT_STATES,
    deviceIds: ["dev-first", "dev-second"],
  });
  try {
    await withTempKeyfile(async (firstPath) => {
      const first = await runPair(
        wasm,
        { relayUrl: relay.url, keyfilePath: firstPath, now: FIXED_NOW },
        () => {},
      );
      await withTempKeyfile(async (secondPath) => {
        // A second device under the same account root: same root seed, its own device keys.
        const { generateKeyfile, writeKeyfile } = await import("../dist/lib/keyfile.js");
        const fresh = generateKeyfile(wasm);
        writeKeyfile(secondPath, {
          ...fresh,
          account_root_seed: first.account_root_seed,
          account_root_pubkey: first.account_root_pubkey,
        });
        const second = await runPair(
          wasm,
          { relayUrl: relay.url, keyfilePath: secondPath, now: FIXED_NOW },
          () => {},
        );
        const [state] = publishedStatesFor(wasm, relay, second);
        assert.equal(state.sequence, 2);
        assert.deepEqual(
          state.devices.map((d) => [d.device_id, d.encryption_pubkey]),
          [
            ["dev-first", first.device_encryption_pubkey],
            ["dev-second", second.device_encryption_pubkey],
          ],
        );
      });
    });
  } finally {
    await relay.close();
  }
});

// The documented upgrade (docs/quickstart.md §Upgrading an existing pairing): an account paired before
// pair published account state has none on the relay. Re-running pair with the same keyfile keeps the
// seeds and account, gets a new device id, and publishes a state naming only that new id.
test("re-running runPair on an already-paired keyfile with no published state publishes one for the new device id (#243 upgrade)", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay({
    unpublished: NO_ACCOUNT_STATES,
    deviceIds: ["dev-old", "dev-new"],
  });
  try {
    await withTempKeyfile(async (keyfilePath) => {
      const before = await runPair(
        wasm,
        { relayUrl: relay.url, keyfilePath, now: FIXED_NOW },
        () => {},
      );
      // Simulate the pre-#243 world: the old pairing left nothing published on the relay, and the
      // keyfile has no recorded account-state floor.
      relay.publishedStates.delete(before.account_id);
      const { account_state_highest_sequence: _floor, ...legacy } = readKeyfile(keyfilePath);
      const { writeKeyfile } = await import("../dist/lib/keyfile.js");
      writeKeyfile(keyfilePath, legacy);

      const after = await runPair(
        wasm,
        { relayUrl: relay.url, keyfilePath, now: FIXED_NOW },
        () => {},
      );
      assert.equal(after.account_id, before.account_id, "same account");
      assert.equal(after.account_root_pubkey, before.account_root_pubkey);
      assert.equal(after.device_encryption_seed, before.device_encryption_seed, "seeds kept");
      assert.equal(after.device_signing_seed, before.device_signing_seed);
      assert.equal(after.device_id, "dev-new", "a new device id");
      assert.notEqual(after.device_cert, before.device_cert, "a new cert for the new id");
      const [state] = publishedStatesFor(wasm, relay, after);
      assert.equal(state.sequence, 1);
      assert.deepEqual(
        state.devices.map((d) => [d.device_id, d.encryption_pubkey]),
        [["dev-new", before.device_encryption_pubkey]],
        "the state names only the new device id, so a client on the old id must re-paste",
      );
    });
  } finally {
    await relay.close();
  }
});

// #378: re-running pair registers a new relay id for the same keyfile keys. The core composition
// replaces the entry for those keys, so ids never pile up; another device's entry is untouched.
test("two consecutive re-pairs leave exactly one entry for the keyfile's keys, under the newest id (#378)", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay({
    unpublished: NO_ACCOUNT_STATES,
    deviceIds: ["dev-cli-1", "dev-other", "dev-cli-2", "dev-cli-3"],
  });
  try {
    await withTempKeyfile(async (cliPath) => {
      const first = await runPair(
        wasm,
        { relayUrl: relay.url, keyfilePath: cliPath, now: FIXED_NOW },
        () => {},
      );
      let other;
      await withTempKeyfile(async (otherPath) => {
        // Another device under the same root, with its own keys.
        const { generateKeyfile, writeKeyfile } = await import("../dist/lib/keyfile.js");
        writeKeyfile(otherPath, {
          ...generateKeyfile(wasm),
          account_root_seed: first.account_root_seed,
          account_root_pubkey: first.account_root_pubkey,
        });
        other = await runPair(
          wasm,
          { relayUrl: relay.url, keyfilePath: otherPath, now: FIXED_NOW },
          () => {},
        );
      });
      // The other device's pair advanced the published state to 2; the CLI keyfile's floor is 1.
      for (const [expectedId, expectedSequence] of [
        ["dev-cli-2", 3],
        ["dev-cli-3", 4],
      ]) {
        const repaired = await runPair(
          wasm,
          { relayUrl: relay.url, keyfilePath: cliPath, now: FIXED_NOW },
          () => {},
        );
        assert.equal(repaired.device_id, expectedId);
        const [state] = publishedStatesFor(wasm, relay, repaired);
        assert.equal(state.sequence, expectedSequence);
        assert.deepEqual(
          state.devices.map((d) => [d.device_id, d.encryption_pubkey]),
          [
            ["dev-other", other.device_encryption_pubkey],
            [expectedId, first.device_encryption_pubkey],
          ],
          "the previous id for these keys is gone; the other device stays",
        );
        assert.equal(repaired.account_state_highest_sequence, expectedSequence);
      }
    });
  } finally {
    await relay.close();
  }
});

// #378: pair names every id its published state retires, so the human knows which web approver
// must re-paste the keyfile values. The core validates only the id being added, so an id already in
// a root-signed state (one written before that check, from a relay-issued id) is untrusted text:
// the line is escaped.
test("a re-pair prints an escaped 'retired' line for the id it replaces, and a first pair prints none (#378)", async () => {
  const wasm = await loadWasm();
  const hostileId = "dev-cli-0\u001b[2J\u0007";
  const relay = await startFakeRelay({
    unpublished: NO_ACCOUNT_STATES,
    deviceIds: ["dev-cli-1", "dev-cli-2"],
  });
  try {
    await withTempKeyfile(async (cliPath) => {
      const firstLines = [];
      const first = await runPair(
        wasm,
        { relayUrl: relay.url, keyfilePath: cliPath, now: FIXED_NOW },
        (line) => firstLines.push(line),
      );
      assert.ok(!firstLines.some((l) => l.includes("retired:")), "a first pair retires nothing");

      // A later root-signed state lists this keyfile's keys under the hostile id.
      const jws = wasm.sign_account_state(
        JSON.stringify({
          v: 1,
          account_id: first.account_id,
          sequence: 2,
          current_root: first.account_root_pubkey,
          previous_roots: [],
          devices: [
            {
              device_id: hostileId,
              encryption_pubkey: first.device_encryption_pubkey,
              signing_pubkey: first.device_signing_pubkey,
              status: "active",
            },
          ],
          actors: [],
          revocations: [],
        }),
        first.account_root_seed,
      );
      relay.publishedStates.set(first.account_id, { account_states: [jws], max_sequence: 2 });

      const lines = [];
      const repaired = await runPair(
        wasm,
        { relayUrl: relay.url, keyfilePath: cliPath, now: FIXED_NOW },
        (line) => lines.push(line),
      );
      assert.equal(repaired.device_id, "dev-cli-2");
      const retired = lines.filter((l) => l.includes("retired:"));
      assert.deepEqual(retired, [
        `  retired: ${wasm.escape_for_display(hostileId)} (same keys; a web approver still using it must re-paste the keyfile values)`,
      ]);
      assert.notEqual(wasm.escape_for_display(hostileId), hostileId, "the id needed escaping");
      assert.ok(
        !/[\u0000-\u001f\u007f]/.test(retired[0]),
        "no raw control character reaches the terminal",
      );
      const published = lines.findIndex((l) => l === "Published account state — sequence 3");
      assert.equal(lines.indexOf(retired[0]), published + 1, "listed under the published state");
    });
  } finally {
    await relay.close();
  }
});

// Regression: a relay deployed before account-state GET became unauthenticated answers it with 401.
// pair must still fail closed (nothing published, keyfile unpaired) and say to redeploy the relay.
test("runPair against a relay too old for account-state GET (401) fails closed and says redeploy the relay", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay({
    unpublished: NO_ACCOUNT_STATES,
    accountStatesGetStatus: 401,
  });
  try {
    await withTempKeyfile(async (keyfilePath) => {
      await assert.rejects(
        () => runPair(wasm, { relayUrl: relay.url, keyfilePath, now: FIXED_NOW }, () => {}),
        /HTTP 401.*relay is too old to publish account state; redeploy it from current allw main/,
      );
      assert.equal(readKeyfile(keyfilePath).device_id, undefined, "not paired on disk");
      assert.equal(
        relay.requests.some((r) => r.method === "POST" && r.url.endsWith("/account-states")),
        false,
        "nothing published",
      );
    });
  } finally {
    await relay.close();
  }
});

test("runPair fails closed, leaving the keyfile unpaired, when the relay's account state cannot be trusted (#243)", async () => {
  const wasm = await loadWasm();
  for (const [name, unpublished] of [
    ["a document that does not verify", DEFAULT_ACCOUNT_STATES],
    ["a max_sequence no document backs", { account_states: [], max_sequence: 4 }],
  ]) {
    const relay = await startFakeRelay({ unpublished });
    try {
      await withTempKeyfile(async (keyfilePath) => {
        await assert.rejects(
          () => runPair(wasm, { relayUrl: relay.url, keyfilePath, now: FIXED_NOW }, () => {}),
          undefined,
          name,
        );
        assert.equal(readKeyfile(keyfilePath).device_id, undefined, `${name}: not paired on disk`);
        assert.equal(
          relay.requests.some((r) => r.method === "POST" && r.url.endsWith("/account-states")),
          false,
          `${name}: nothing published`,
        );
      });
    } finally {
      await relay.close();
    }
  }
});
