/**
 * UAT: the `allw-approver` binary refuses a plaintext or malformed relay URL (#267), as a user
 * sees it. Every relay entry point is covered: `pair --relay`, `watch --relay` and the keyfile's
 * stored `relay_url`. In each case the process exits non-zero and stderr names the source and the
 * fix.
 *
 * To show that no request is built, a loopback HTTP server counts every connection, and the
 * commands are also given URLs that would reach it if the check were missing. Each URL is still
 * rejected by the rule: one carries a query (`http://127.0.0.1:<port>?probe`), the other is the
 * IPv6 loopback (`http://[::1]:<port>`, which the server also listens on when the host has IPv6).
 * Userinfo is not used as a probe: Node's `fetch` itself refuses a URL with credentials, so it would
 * not show that the CLI's own check ran.
 * The expected verdicts come from the rule in `docs/threat-model.md` §Relay and Transport and the
 * shared vectors, not from captured output.
 *
 * @see https://github.com/mike-north/allw/issues/267
 * @see ../../../docs/threat-model.md (§Relay and Transport)
 * @see ../../sdk/test/fixtures/relay-url-vectors.json
 */

import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "../dist/index.js";
import { generateKeyfile, writeKeyfile } from "../dist/lib/keyfile.js";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

const wasm = await loadWasm();

/** Run the compiled approver bin with an isolated HOME; resolves { code, stdout, stderr }. */
function runCli(args, home) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { PATH: process.env.PATH, HOME: home },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`allw-approver ${args[0]} did not exit within 15000ms`));
    }, 15000);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

/** Run `fn(dir)` with a fresh temp directory, removed afterwards. */
async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "allw-relay-url-cli-"));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A paired keyfile at `<dir>/keyfile.json` whose stored relay is `relayUrl`. */
function writePairedKeyfile(dir, relayUrl) {
  const fresh = generateKeyfile(wasm);
  const path = join(dir, "keyfile.json");
  writeKeyfile(path, {
    ...fresh,
    relay_url: relayUrl,
    account_id: wasm.account_id_for_root(fresh.account_root_pubkey),
    device_id: "dev-relay-url-cli-267",
    device_auth_token: "device-token-267",
    device_cert: "cert.placeholder.267",
  });
  return path;
}

/** A loopback server that counts every connection (HTTP request or WebSocket upgrade attempt). */
let probe;
let connections = 0;
let port;

before(async () => {
  probe = createServer((_req, res) => {
    res.writeHead(500).end();
  });
  probe.on("connection", () => {
    connections += 1;
  });
  // "::" with dual-stack also accepts IPv4, so 127.0.0.1 and [::1] both land here; fall back to
  // IPv4 only on a host without IPv6.
  await new Promise((resolve, reject) => {
    probe.once("error", reject);
    probe.listen(0, "::", resolve);
  }).catch(
    () =>
      new Promise((resolve, reject) => {
        // If IPv4 loopback can't be bound either, fail before() at once instead of hanging.
        probe.once("error", reject);
        probe.listen(0, "127.0.0.1", resolve);
      }),
  );
  port = probe.address().port;
});

after(() => {
  probe.close();
});

/**
 * Rejected URLs that point at the probe server (built lazily: the port is known only after
 * `before`). If the check were missing, a request or socket would land on the probe.
 */
const PROBE_URLS = [
  ["http://127.0.0.1:<port>?probe", () => `http://127.0.0.1:${String(port)}?probe`],
  ["http://[::1]:<port>", () => `http://[::1]:${String(port)}`],
];

/** Assert the run was refused: non-zero exit, a single actionable error line, nothing on stdout. */
function assertRefused({ code, stdout, stderr }, messagePattern) {
  assert.equal(code, 1, `exit code (stderr: ${stderr})`);
  assert.match(stderr, messagePattern);
  assert.doesNotMatch(stdout, /Paired|Connecting/, "nothing proceeds past the check");
}

describe("pair --relay (#267 UAT)", () => {
  test("pair --relay http://relay.example.com exits 1 with an actionable error and writes no keyfile", async () => {
    await withTempDir(async (dir) => {
      const keyfile = join(dir, "keyfile.json");
      const result = await runCli(
        ["pair", "--relay", "http://relay.example.com", "--keyfile", keyfile],
        dir,
      );
      assertRefused(
        result,
        /^allw-approver: --relay 'http:\/\/relay\.example\.com' must use https:\/\/ \(plain http:\/\/ is allowed only for a local relay on localhost or 127\.0\.0\.1; use 127\.0\.0\.1 rather than \[::1\]\); pass e\.g\. --relay https:\/\/relay\.example\.com$/m,
      );
      assert.equal(existsSync(keyfile), false, "a refused pair leaves no keyfile behind");
    });
  });

  for (const [shape, relay] of PROBE_URLS) {
    test(`pair --relay ${shape} sends nothing to the relay`, async () => {
      await withTempDir(async (dir) => {
        const before = connections;
        const result = await runCli(
          ["pair", "--relay", relay(), "--keyfile", join(dir, "keyfile.json")],
          dir,
        );
        assert.equal(connections, before, "no connection reached the relay");
        assertRefused(result, /^allw-approver: --relay '/m);
      });
    });
  }
});

describe("watch --relay (#267 UAT)", () => {
  test("watch --relay http://relay.example.com exits 1 with an actionable error", async () => {
    await withTempDir(async (dir) => {
      const keyfile = writePairedKeyfile(dir, "https://relay.example.com");
      const result = await runCli(
        ["watch", "--relay", "http://relay.example.com", "--keyfile", keyfile],
        dir,
      );
      assertRefused(
        result,
        /^allw-approver: --relay 'http:\/\/relay\.example\.com' must use https:\/\//m,
      );
    });
  });

  for (const [shape, relay] of PROBE_URLS) {
    test(`watch --relay ${shape} opens no socket and fetches nothing`, async () => {
      await withTempDir(async (dir) => {
        const keyfile = writePairedKeyfile(dir, "https://relay.example.com");
        const before = connections;
        const result = await runCli(["watch", "--relay", relay(), "--keyfile", keyfile], dir);
        assert.equal(connections, before, "no connection reached the relay");
        assertRefused(result, /^allw-approver: --relay '/m);
      });
    });
  }
});

describe("keyfile relay_url, used by watch (#267 UAT)", () => {
  test("a stored http://relay.example.com exits 1 and says to re-pair or override", async () => {
    await withTempDir(async (dir) => {
      const keyfile = writePairedKeyfile(dir, "http://relay.example.com");
      const result = await runCli(["watch", "--keyfile", keyfile], dir);
      assertRefused(
        result,
        /^allw-approver: keyfile relay_url 'http:\/\/relay\.example\.com' must use https:\/\/.*re-pair with an https relay \(allw-approver pair --relay https:\/\/relay\.example\.com\), or pass --relay to override it$/m,
      );
    });
  });

  test("a stored URL with a query, pointing at a live relay, opens no socket", async () => {
    await withTempDir(async (dir) => {
      const keyfile = writePairedKeyfile(dir, `http://127.0.0.1:${String(port)}?probe`);
      const before = connections;
      const result = await runCli(["watch", "--keyfile", keyfile], dir);
      assert.equal(connections, before, "no connection reached the relay");
      assertRefused(result, /^allw-approver: keyfile relay_url '/m);
    });
  });
});
