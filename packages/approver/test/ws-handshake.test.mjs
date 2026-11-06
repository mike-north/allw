/**
 * Real CLI / Node WebSocket negotiation against a loopback test peer. The peer selects only the
 * application marker; a missing or credential-selected protocol is rejected by the native client.
 * Workers-pool tests separately prove the relay issues this exact selection after real auth.
 * @see ../../../docs/relay-api.md §1, §4
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadWasm } from "../dist/index.js";
import { generateKeyfile, writeKeyfile } from "../dist/lib/keyfile.js";

const TOKEN = "handshake-private-device-token";

test(
  "CLI default Node connector forwards offers; application-only selection opens and logs no capability",
  { timeout: 15_000 },
  async (t) => {
    const connections = new Set();
    const server = createServer((_req, response) => response.writeHead(404).end());
    let requestUrl;
    let offered;
    server.on("upgrade", (request, socket) => {
      connections.add(socket);
      // A deliberately broken client may reset the peer while rejecting negotiation.
      socket.on("error", () => {});
      socket.on("close", () => connections.delete(socket));
      requestUrl = request.url;
      offered = request.headers["sec-websocket-protocol"];
      const accept = createHash("sha1")
        .update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
        .digest("base64");
      socket.write(
        `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: allw.v1\r\n\r\n`,
      );
      socket.write(Buffer.from([0x88, 0]));
      socket.on("data", () => socket.end());
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const dir = mkdtempSync(join(tmpdir(), "allw-ws-handshake-"));
    let child;
    try {
      const wasm = await loadWasm();
      const keys = generateKeyfile(wasm);
      const keyfilePath = join(dir, "keyfile.json");
      writeKeyfile(keyfilePath, {
        ...keys,
        relay_url: `http://127.0.0.1:${server.address().port}`,
        account_id: wasm.account_id_for_root(keys.account_root_pubkey),
        device_id: "dev-handshake",
        device_auth_token: TOKEN,
        device_cert: "test-cert-not-used-without-requests",
      });
      const cli = new URL("../dist/cli.js", import.meta.url);
      child = spawn(process.execPath, [cli.pathname, "watch", "--keyfile", keyfilePath], {
        env: { PATH: process.env.PATH, HOME: dir },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let output = "";
      child.stdout.on("data", (data) => {
        output += data;
      });
      child.stderr.on("data", (data) => {
        output += data;
      });
      t.signal.addEventListener(
        "abort",
        () => {
          child.kill("SIGKILL");
          for (const socket of connections) socket.destroy();
        },
        { once: true },
      );
      const code = await new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("close", resolve);
      });
      assert.equal(code, 0, output);
      assert.equal(
        requestUrl,
        `/${wasm.account_id_for_root(keys.account_root_pubkey)}/devices/dev-handshake/connect`,
      );
      assert.equal(typeof offered, "string", "the constructor must forward protocol offers");
      assert.deepEqual(
        offered.split(",").map((p) => p.trim()),
        ["allw.v1", `allw.auth.${TOKEN}`],
      );
      assert.match(output, /Connected\. Waiting/);
      assert.equal(output.includes(TOKEN), false);
      assert.equal(output.includes("allw.auth."), false);
    } finally {
      if (child && child.exitCode === null) child.kill("SIGKILL");
      for (const socket of connections) socket.destroy();
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
