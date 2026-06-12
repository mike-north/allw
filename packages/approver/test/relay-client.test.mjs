/**
 * Relay-client (pairing) tests for the v0 stand-in approver (issue #41).
 *
 * The real relay runs under `workerd` (Cloudflare Workers), so a Node CLI cannot reach it
 * in-process. These tests exercise the approver's HTTP pairing client and `pair` orchestration
 * against a lightweight in-Node HTTP server that mimics the relay's device-facing pairing surface
 * (`docs/contract.md` §Transport → Relay routing API; relay package `POST /:acct/pairing/start`,
 * `POST /:acct/pairing/complete`). It asserts the approver:
 *   - sends only the **X25519 (encryption) public key** to `/pairing/complete` (never a seed),
 *   - mints + stores a device_cert and the relay/account/device metadata,
 *   - builds the correct `ws(s)://…/devices/:id/connect` presence URL.
 *
 * @see ../../relay/src/index.ts (the endpoints mimicked here)
 * @see ../../../docs/contract.md §Identity & keys, §Transport
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
  pairingComplete,
  PAIRING_TIMEOUT_MS,
} from "../dist/lib/relay-client.js";
import { runPair } from "../dist/commands/pair.js";

const PAIRING_CODE = "ABC23456";
const ASSIGNED_DEVICE_ID = "dev-from-relay-xyz";
const PAIRING_AUTH_TOKEN = "pairing-token-from-relay";
const DEVICE_AUTH_TOKEN = "device-token-from-relay";

/**
 * Start a fake relay mimicking the pairing endpoints. Captures every request body so tests can
 * assert exactly what the approver sent. Returns { url, requests, close }.
 */
function startFakeRelay() {
  const requests = [];
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
        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            device_id: ASSIGNED_DEVICE_ID,
            device_auth_token: DEVICE_AUTH_TOKEN,
          }),
        );
        return;
      }
      // GET /:acct/account-states → { account_states }
      if (req.method === "GET" && req.url.endsWith("/account-states")) {
        if (req.headers.authorization !== `Bearer ${DEVICE_AUTH_TOKEN}`) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "authorization denied" }));
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            account_states: ["account-state-jws-1", "account-state-jws-2"],
            max_sequence: 7,
          }),
        );
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

function withTempKeyfile(fn) {
  const dir = mkdtempSync(join(tmpdir(), "allw-approver-pair-"));
  try {
    return fn(join(dir, "keyfile.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("pairingStart returns the relay's code", async () => {
  await loadWasm();
  const relay = await startFakeRelay();
  try {
    const result = await pairingStart(relay.url, "acct-1");
    assert.equal(result.code, PAIRING_CODE);
    assert.equal(result.pairing_auth_token, PAIRING_AUTH_TOKEN);
    assert.equal(relay.requests[0].url, "/acct-1/pairing/start");
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

test("fetchAccountStates uses the paired device bearer token and returns compact state docs", async () => {
  const relay = await startFakeRelay();
  try {
    const states = await fetchAccountStates(relay.url, "acct-2", DEVICE_AUTH_TOKEN);

    assert.deepEqual(states, ["account-state-jws-1", "account-state-jws-2"]);
    const fetchReq = relay.requests.find((r) => r.url.endsWith("/account-states"));
    assert.equal(fetchReq.method, "GET");
    assert.equal(fetchReq.authorization, `Bearer ${DEVICE_AUTH_TOKEN}`);
  } finally {
    await relay.close();
  }
});

test("fetchAccountStatesWithMetadata returns relay max_sequence metadata", async () => {
  const relay = await startFakeRelay();
  try {
    const result = await fetchAccountStatesWithMetadata(relay.url, "acct-2", DEVICE_AUTH_TOKEN);

    assert.deepEqual(result.accountStates, ["account-state-jws-1", "account-state-jws-2"]);
    assert.equal(result.maxSequence, 7);
  } finally {
    await relay.close();
  }
});

test("runPair self-drives start+complete, mints a device_cert, and persists pairing state", async () => {
  const wasm = await loadWasm();
  const relay = await startFakeRelay();
  try {
    await withTempKeyfile(async (keyfilePath) => {
      const updated = await runPair(
        wasm,
        {
          relayUrl: relay.url,
          accountId: "acct-3",
          keyfilePath,
          label: "cabin",
          now: 1700000000000,
        },
        () => {}, // silence logging in the test
      );

      // The persisted keyfile carries the relay-issued device id + a minted cert.
      assert.equal(updated.device_id, ASSIGNED_DEVICE_ID);
      assert.equal(updated.device_auth_token, DEVICE_AUTH_TOKEN);
      assert.equal(updated.account_id, "acct-3");
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
          record_schema_version: 1,
          surface: "command",
          syntactic: { raw: "echo hi" },
          risk: "low",
        },
        summary: "echo hi",
        actor: { id: "machine:x", kind: "claude-code" },
        risk: "low",
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
        approver: { account_id: "acct-3", device_id: ASSIGNED_DEVICE_ID },
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
        approver: "acct-3",
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
      () => pairingStart(relay.url, "acct-hung", undefined, INJECTED_TIMEOUT_MS),
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
        () => runPair(wasm, { relayUrl: relay.url, accountId: "acct-x", keyfilePath }, () => {}),
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
