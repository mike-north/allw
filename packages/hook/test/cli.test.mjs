/**
 * UAT-layer test: drive the real `allw-hook` executable as a `node` subprocess, exactly as Claude
 * Code invokes it — JSON on stdin, a permission-decision JSON on stdout, exit 0. This proves the
 * acceptance criterion that the hook "runs entirely under node (no binary to allowlist)" and that
 * the process boundary is fail-closed.
 *
 * These cases use the no-config / non-gated / malformed paths so the subprocess never needs a live
 * relay; the full crypto round-trip is covered deterministically in integration.test.mjs.
 *
 * @see https://code.claude.com/docs/en/hooks (the stdin/stdout/exit-code contract)
 * @see ../../../docs/architecture.md (WASM-local: node entrypoint, never a native binary)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

/** A gated tool call the subprocess tests can feed exactly as Claude Code would. */
function bashStdin(command = "rm -rf build") {
  return JSON.stringify({
    hook_event_name: "PreToolUse",
    cwd: process.cwd(),
    tool_name: "Bash",
    tool_input: { command },
  });
}

/**
 * Run the compiled hook bin under `node`, feeding `stdin`.
 *
 * The wall-clock guard is part of the UAT: if the process wedges instead of emitting an explicit
 * decision, the test fails quickly and kills the child so CI does not inherit the hang.
 */
function runCli(stdin, env = {}, options = {}) {
  const timeoutMs = options.timeoutMs ?? 5000;
  return new Promise((resolve, reject) => {
    const startedAt = performance.now();
    const child = spawn(process.execPath, [CLI], {
      // A clean, minimal env so an ambient ALLW_* on the dev machine can't leak into the test.
      env: { PATH: process.env.PATH, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`allw-hook subprocess did not exit within ${String(timeoutMs)}ms`));
    }, timeoutMs);
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
      resolve({ code, stdout, stderr, elapsedMs: performance.now() - startedAt });
    });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

/** Parse the single-line decision JSON the hook prints. */
function decisionOf(stdout) {
  return JSON.parse(stdout).hookSpecificOutput.permissionDecision;
}

/** Read the human/actionable reason from the hook's stdout decision JSON. */
function reasonOf(stdout) {
  return JSON.parse(stdout).hookSpecificOutput.permissionDecisionReason;
}

/** Minimal config that gets a gated call to the real SDK transport path. */
function hookEnv(relayUrl, extra = {}) {
  return {
    ALLW_RELAY_URL: relayUrl,
    ALLW_ACCOUNT_ID: "acct-uat",
    ALLW_APPROVER_ROOT_KEY: "k".repeat(43),
    ALLW_TIMEOUT_MS: "1000",
    // UATs need to prove bounded failure without burning the SDK's production 30s default.
    ALLW_FETCH_TIMEOUT_MS: "100",
    ...extra,
  };
}

/** Allocate a localhost port, close it, and return the URL for a connection-refused relay case. */
async function refusedRelayUrl() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address !== null && typeof address === "object");
  const url = `http://127.0.0.1:${String(address.port)}`;
  await new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
  return url;
}

/** A relay double that accepts TCP connections and intentionally never writes an HTTP response. */
async function hungRelay() {
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address !== null && typeof address === "object");

  return {
    url: `http://127.0.0.1:${String(address.port)}`,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}

test("subprocess: a non-gated tool (Read) emits allow and exits 0 (no config needed)", async () => {
  const stdin = JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Read",
    tool_input: { file_path: "/etc/hosts" },
  });
  const { code, stdout } = await runCli(stdin);
  assert.equal(code, 0, "the hook always exits 0 (it speaks in decisions, not error codes)");
  assert.equal(decisionOf(stdout), "allow");
});

test("subprocess: a gated Bash command with no config fails closed → deny, exit 0", async () => {
  const stdin = JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "rm -rf /" },
  });
  const { code, stdout } = await runCli(stdin);
  assert.equal(code, 0);
  assert.equal(decisionOf(stdout), "deny", "missing config blocks the gated command");
  assert.ok(
    /ALLW_RELAY_URL is not set/.test(
      JSON.parse(stdout).hookSpecificOutput.permissionDecisionReason,
    ),
  );
});

test("subprocess: malformed stdin fails closed → deny, exit 0", async () => {
  const { code, stdout } = await runCli("this is not json");
  assert.equal(code, 0);
  assert.equal(decisionOf(stdout), "deny");
});

test("subprocess: empty stdin fails closed → deny, exit 0", async () => {
  const { code, stdout } = await runCli("");
  assert.equal(code, 0);
  assert.equal(decisionOf(stdout), "deny");
});

test("(#54) subprocess: ALLW_TIMEOUT_MS at the cap denies at startup before relay dial", async () => {
  const relay = await hungRelay();
  try {
    const { code, stdout, elapsedMs } = await runCli(
      bashStdin(),
      hookEnv(relay.url, { ALLW_TIMEOUT_MS: "420000" }),
      { timeoutMs: 2000 },
    );

    assert.equal(code, 0);
    assert.equal(decisionOf(stdout), "deny");
    assert.match(reasonOf(stdout), /ALLW_TIMEOUT_MS=420000ms is too large/);
    assert.ok(
      elapsedMs < 1000,
      `oversized config must deny before waiting on relay I/O, elapsed=${String(elapsedMs)}ms`,
    );
  } finally {
    await relay.close();
  }
});

test("(#54) subprocess: connection-refused relay fails closed to deny within a bounded time", async () => {
  const { code, stdout, elapsedMs } = await runCli(bashStdin(), hookEnv(await refusedRelayUrl()), {
    timeoutMs: 2500,
  });

  assert.equal(code, 0);
  assert.equal(decisionOf(stdout), "deny");
  assert.match(reasonOf(stdout), /not approved \(verdict: expired\)/);
  assert.ok(
    elapsedMs < 2000,
    `connection refusal should not approach Claude Code's 480s hook timeout, elapsed=${String(
      elapsedMs,
    )}ms`,
  );
});

test("(#54) subprocess: hung relay fetch fails closed to deny within a bounded time", async () => {
  const relay = await hungRelay();
  try {
    const { code, stdout, elapsedMs } = await runCli(bashStdin(), hookEnv(relay.url), {
      timeoutMs: 2500,
    });

    assert.equal(code, 0);
    assert.equal(decisionOf(stdout), "deny");
    assert.match(reasonOf(stdout), /not approved \(verdict: expired\)/);
    assert.ok(
      elapsedMs < 2000,
      `hung relay must be bounded by the SDK fetch timeout, elapsed=${String(elapsedMs)}ms`,
    );
  } finally {
    await relay.close();
  }
});
