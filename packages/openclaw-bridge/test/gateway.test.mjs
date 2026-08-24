/**
 * Gateway-client integration tests, driven against a **real WebSocket server** speaking OpenClaw's
 * real `RequestFrame` / `ResponseFrame` / `EventFrame` envelopes and the documented
 * `connect.challenge` → `connect` → `hello-ok` handshake.
 *
 * These assert the properties that a hand-built transport double could not: what the bridge
 * actually puts on the wire (scopes, capabilities, pinned protocol, device proof), that the paired
 * device token is persisted and reused, and that the listener is installed before the backfill runs.
 *
 * @see ../../../docs/openclaw-integration.md §4.1 scopes, §4.2 pairing, §4.3 protocol/subscription
 * @see https://docs.openclaw.ai/gateway/clients
 */

import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";

import { createGatewayConnection, openCredentialStore, silentLogger } from "../dist/index.js";
import { recordingLogger } from "./support/fake-gateway.mjs";
import {
  CHALLENGE_NONCE,
  CHALLENGE_TS,
  helloOk,
  startFakeGateway,
  waitFor,
} from "./support/fake-gateway-server.mjs";
import { CONFIG, GATEWAY_ID } from "./support/fixtures.mjs";

const NOOP_LIFECYCLE = { onConnected: () => undefined, onDisconnected: () => undefined };

function freshStateDir() {
  return mkdtempSync(join(tmpdir(), "allw-openclaw-bridge-test-"));
}

/** Open a connection against `server`, run `body`, and always stop the client. */
async function withConnection(
  { server, stateDir, logger = silentLogger, lifecycle = NOOP_LIFECYCLE },
  body,
) {
  const store = openCredentialStore(stateDir, GATEWAY_ID);
  const connection = createGatewayConnection(
    { ...CONFIG, gatewayUrl: server.url, stateDir },
    store,
    logger,
    lifecycle,
  );
  connection.start();
  try {
    return await body(connection, store);
  } finally {
    await connection.stop();
  }
}

// ── §4.1 scopes ─────────────────────────────────────────────────────────────────

test("the bridge connects with exactly operator.approvals (§4.1)", async () => {
  const server = await startFakeGateway();
  try {
    await withConnection({ server, stateDir: freshStateDir() }, async () => {
      await waitFor(() => server.connects.length > 0, "connect params");
      const params = server.connects[0];

      assert.equal(params.role, "operator");
      assert.deepEqual(params.scopes, ["operator.approvals"]);
      assert.ok(
        !params.scopes.includes("operator.admin"),
        "admin would let the bridge rewrite policy",
      );
      assert.ok(!params.scopes.includes("operator.read"), "read would deliver session content");
    });
  } finally {
    await server.close();
  }
});

// ── §4.3 protocol pin + capabilities ────────────────────────────────────────────

test("the wire version is pinned to exactly 4 (§4.3)", async () => {
  const server = await startFakeGateway();
  try {
    await withConnection({ server, stateDir: freshStateDir() }, async () => {
      await waitFor(() => server.connects.length > 0, "connect params");
      assert.equal(server.connects[0].minProtocol, 4);
      assert.equal(server.connects[0].maxProtocol, 4);
    });
  } finally {
    await server.close();
  }
});

test("only implemented capabilities are advertised — never tool-events (§4.3)", async () => {
  const server = await startFakeGateway();
  try {
    await withConnection({ server, stateDir: freshStateDir() }, async () => {
      await waitFor(() => server.connects.length > 0, "connect params");
      const caps = server.connects[0].caps;
      assert.deepEqual([...caps].sort(), ["approvals", "exec-approvals", "plugin-approvals"]);
      assert.ok(
        !caps.includes("tool-events"),
        "tool-events would opt the connection into live tool-execution streaming",
      );
    });
  } finally {
    await server.close();
  }
});

// ── §4.2 device identity + pairing ──────────────────────────────────────────────

test("the connect frame carries a device proof signed over the challenge (§4.2)", async () => {
  const server = await startFakeGateway();
  const stateDir = freshStateDir();
  try {
    await withConnection({ server, stateDir }, async (_connection, store) => {
      await waitFor(() => server.connects.length > 0, "connect params");
      const { device } = server.connects[0];

      assert.ok(device, "an operator client must present a device identity");
      assert.equal(device.nonce, CHALLENGE_NONCE);
      assert.equal(
        device.signedAt,
        CHALLENGE_TS,
        "the challenge's own ts is the signedAt — never local time",
      );

      // The signature must verify against the persisted device public key.
      const identity = store.loadOrCreateDeviceIdentity();
      const payload = [
        "v3",
        device.id,
        server.connects[0].client.id,
        server.connects[0].client.mode,
        "operator",
        "operator.approvals",
        String(CHALLENGE_TS),
        "",
        CHALLENGE_NONCE,
        server.connects[0].client.platform,
        "",
      ].join("|");
      assert.equal(
        cryptoVerify(
          null,
          Buffer.from(payload, "utf8"),
          createPublicKey(identity.publicKeyPem),
          Buffer.from(device.signature, "base64url"),
        ),
        true,
        "the device proof must be a real Ed25519 signature over the challenge payload",
      );
    });
  } finally {
    await server.close();
  }
});

test("the device private key and paired token are stored 0600, never in the environment (§4.2)", async () => {
  const server = await startFakeGateway({
    onConnect: () => ({
      ok: true,
      payload: helloOk({
        auth: { deviceToken: "device-token-abc", role: "operator", scopes: ["operator.approvals"] },
      }),
    }),
  });
  const stateDir = freshStateDir();
  try {
    await withConnection({ server, stateDir }, async (_connection, store) => {
      await waitFor(() => store.loadDeviceToken("operator") !== null, "persisted device token");
      assert.deepEqual(store.loadDeviceToken("operator"), {
        token: "device-token-abc",
        scopes: ["operator.approvals"],
      });

      const path = join(stateDir, `openclaw-bridge-${GATEWAY_ID}.json`);
      assert.equal(statSync(path).mode & 0o777, 0o600, "credentials must be owner-only");
      assert.ok(
        !Object.values(process.env).includes("device-token-abc"),
        "the device token must never reach the process environment",
      );
    });
  } finally {
    await server.close();
  }
});

test("a persisted device token is reused on the next connection (§4.2)", async () => {
  const server = await startFakeGateway({
    onConnect: () => ({
      ok: true,
      payload: helloOk({
        auth: { deviceToken: "device-token-abc", role: "operator", scopes: ["operator.approvals"] },
      }),
    }),
  });
  const stateDir = freshStateDir();
  try {
    await withConnection({ server, stateDir }, async (_connection, store) => {
      await waitFor(() => store.loadDeviceToken("operator") !== null, "persisted device token");
    });
    await withConnection({ server, stateDir }, async () => {
      await waitFor(() => server.connects.length > 1, "second connect");
      assert.equal(server.connects[1].auth?.deviceToken, "device-token-abc");
    });
  } finally {
    await server.close();
  }
});

test("the device identity is stable across restarts (§4.2)", async () => {
  const server = await startFakeGateway();
  const stateDir = freshStateDir();
  try {
    await withConnection({ server, stateDir }, async () => {
      await waitFor(() => server.connects.length > 0, "first connect");
    });
    await withConnection({ server, stateDir }, async () => {
      await waitFor(() => server.connects.length > 1, "second connect");
      assert.equal(server.connects[0].device.id, server.connects[1].device.id);
      assert.equal(server.connects[0].device.publicKey, server.connects[1].device.publicKey);
    });
  } finally {
    await server.close();
  }
});

// ── negatives: handshake failures never produce a "connected" bridge ────────────

test("a challenge without a ts is rejected rather than falling back to local time (§4.2)", async () => {
  const server = await startFakeGateway({ challenge: { nonce: CHALLENGE_NONCE } });
  const { logger, records } = recordingLogger();
  try {
    await withConnection({ server, stateDir: freshStateDir(), logger }, async (connection) => {
      await waitFor(
        () => records.some((r) => r.event === "gateway.connect-error"),
        "connect error",
      );
      assert.equal(connection.connected, false);
      assert.equal(server.connects.length, 0, "no connect frame may be sent without a valid ts");
    });
  } finally {
    await server.close();
  }
});

test("a protocol mismatch surfaces as a connect error and never a hello (§4.3)", async () => {
  const server = await startFakeGateway({
    onConnect: () => ({
      ok: false,
      error: {
        code: "PROTOCOL_MISMATCH",
        message: "protocol mismatch",
        details: { code: "PROTOCOL_MISMATCH", expectedProtocol: 5 },
      },
    }),
  });
  const { logger, records } = recordingLogger();
  try {
    await withConnection({ server, stateDir: freshStateDir(), logger }, async (connection) => {
      await waitFor(
        () => records.some((r) => r.event === "gateway.connect-error"),
        "connect error",
      );
      assert.equal(connection.connected, false);
      assert.ok(!records.some((r) => r.event === "gateway.connected"));
    });
  } finally {
    await server.close();
  }
});

test("PAIRING_REQUIRED surfaces the request id the operator must approve (§4.2)", async () => {
  const server = await startFakeGateway({
    onConnect: () => ({
      ok: false,
      error: {
        code: "UNAUTHORIZED",
        message: "pairing required",
        details: { code: "PAIRING_REQUIRED", reason: "not-paired", requestId: "pair_123" },
      },
    }),
  });
  const { logger, records } = recordingLogger();
  try {
    await withConnection({ server, stateDir: freshStateDir(), logger }, async (connection) => {
      await waitFor(
        () => records.some((r) => r.event === "gateway.pairing-required"),
        "pairing-required log",
      );
      const record = records.find((r) => r.event === "gateway.pairing-required");
      assert.equal(record.fields.requestId, "pair_123");
      assert.match(record.fields.hint, /openclaw devices approve/);
      assert.equal(connection.connected, false);
    });
  } finally {
    await server.close();
  }
});

// ── §4.3 listener before backfill, reconcile by id ──────────────────────────────

test("the event listener is live before the backfill runs (§4.3)", async () => {
  const order = [];
  const server = await startFakeGateway({
    methods: {
      "exec.approval.list": () => {
        order.push("exec.approval.list");
        return { approvals: [] };
      },
    },
  });
  const seen = [];
  try {
    await withConnection(
      {
        server,
        stateDir: freshStateDir(),
        lifecycle: {
          onConnected: async () => {
            // Emit a broadcast *before* the backfill call returns: it must still be delivered,
            // which is only true if the handler was installed ahead of the projection.
            server.emit("exec.approval.requested", { id: "apr_race" });
            await new Promise((resolve) => setTimeout(resolve, 20));
            order.push("projection");
          },
          onDisconnected: () => undefined,
        },
      },
      async (connection) => {
        connection.addEventListener((event) => {
          if (event.event === "exec.approval.requested") {
            order.push("event");
            seen.push(event.payload.id);
          }
        });
        await waitFor(() => order.includes("projection"), "projection");
      },
    );
  } finally {
    await server.close();
  }

  assert.deepEqual(seen, ["apr_race"], "an event racing the backfill must not be lost");
  assert.ok(order.indexOf("event") < order.indexOf("projection"));
});

test("RPCs issued by the bridge reach the gateway with the exact method names (§7.4)", async () => {
  const server = await startFakeGateway({
    methods: {
      "approval.get": () => ({ id: "apr_1", status: "pending" }),
      "approval.resolve": () => ({ applied: true }),
    },
  });
  try {
    await withConnection({ server, stateDir: freshStateDir() }, async (connection) => {
      await waitFor(() => connection.connected, "hello-ok");
      await connection.request("approval.get", { id: "apr_1" });
      await connection.request("approval.resolve", { id: "apr_1", kind: "exec", decision: "deny" });

      assert.deepEqual(server.calls, [
        { method: "approval.get", params: { id: "apr_1" } },
        { method: "approval.resolve", params: { id: "apr_1", kind: "exec", decision: "deny" } },
      ]);
    });
  } finally {
    await server.close();
  }
});

test("a dropped connection reports a disconnect and stops reporting as connected (§9)", async () => {
  const server = await startFakeGateway();
  const disconnects = [];
  try {
    await withConnection(
      {
        server,
        stateDir: freshStateDir(),
        lifecycle: {
          onConnected: () => undefined,
          onDisconnected: (code, reason) => disconnects.push({ code, reason }),
        },
      },
      async (connection) => {
        await waitFor(() => connection.connected, "hello-ok");
        server.dropConnections();
        await waitFor(() => disconnects.length > 0, "disconnect");
        assert.equal(connection.connected, false);
      },
    );
  } finally {
    await server.close();
  }
});
