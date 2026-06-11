/**
 * Process-level **fail-closed UAT** (issue #54): spawn the real `allw-hook` bin as a `node`
 * subprocess — exactly as Claude Code's `PreToolUse` command hook invokes it (JSON on stdin, a
 * permission-decision JSON on stdout, exit 0) — and prove the fail-closed guarantee survives the
 * real process boundary against an unreachable relay.
 *
 * This complements the SDK-layer test (`packages/sdk/test/fetch-timeout.test.mjs`), which proves the
 * *mechanism* deterministically under a fake clock. Here we prove it *end-to-end through the spawned
 * process*: subprocess spawn, the stdin/stdout wire protocol, the real (wall-clock) SDK fetch
 * timeout firing, and the exit code. The whole point of the contract (`docs/contract.md`
 * §Invariants #6) is that the hook **emits an explicit `deny` (exit 0)** before any external
 * timeout — never hanging into Claude Code's hook timeout, where a non-emitting hook fails *open*.
 *
 * Two unreachable-relay shapes are exercised:
 *   - **hung relay**: a TCP server that accepts the connection but never writes a byte (black-holed
 *     host, hung load balancer, captive portal) — the await would hang forever without the SDK's
 *     per-fetch timeout;
 *   - **connection refused**: a port with nothing listening — the fetch rejects with a network error.
 *
 * Both must produce a `deny`, exit 0, **within a bounded time** comfortably under the pinned Claude
 * Code hook timeout. To keep CI fast (the SDK default fetch timeout is 30s, the deadline 5 min) the
 * hook honors `ALLW_FETCH_TIMEOUT_MS` (issue #54): we set it to 200ms so the hung-relay deny lands in
 * well under a second — driving a *short real* timeout without weakening production defaults.
 *
 * A third case pins the config-cap path end-to-end: `ALLW_TIMEOUT_MS` at/above the cap → the hook
 * denies *at startup* (before any relay dial) with the actionable reason.
 *
 * @see ../../sdk/test/fetch-timeout.test.mjs (the SDK-layer, fake-clock proof of the same mechanism)
 * @see ../../../docs/contract.md §Invariants #6 (fail-closed)
 * @see ../src/lib/config.ts (ALLW_FETCH_TIMEOUT_MS / ALLW_TIMEOUT_MS validation + caps)
 * @see https://code.claude.com/docs/en/hooks (the stdin/stdout/exit-code contract)
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");

// A short per-relay-fetch timeout so a hung/refused relay fails closed in well under a second. This
// is the CI-fast knob under test: production keeps the SDK's 30s default; the UAT drives 200ms.
const FETCH_TIMEOUT_MS = 200;
// The upper bound we assert the subprocess decides within. Generous over the 200ms fetch timeout to
// absorb subprocess spawn + WASM load on a loaded CI box, yet far below Claude Code's hook timeout.
const DECIDE_UPPER_BOUND_MS = 2_000;

/**
 * Run the compiled hook bin under `node`, feeding `stdin`; resolves
 * `{ code, stdout, stderr, elapsedMs }`. A clean, minimal env keeps any ambient `ALLW_*` on the dev
 * machine from leaking in.
 */
function runCli(stdin, env = {}) {
  return new Promise((resolve, reject) => {
    const start = process.hrtime.bigint();
    const child = spawn(process.execPath, [CLI], {
      env: { PATH: process.env.PATH, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => {
      const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
      resolve({ code, stdout, stderr, elapsedMs });
    });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

/** Parse the single-line decision JSON the hook prints. */
function parseDecision(stdout) {
  const parsed = JSON.parse(stdout);
  return parsed.hookSpecificOutput;
}

/** A realistic PreToolUse stdin payload for a gated Bash command. */
function bashStdin(command) {
  return JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command },
    cwd: "/workspace/project",
  });
}

/**
 * The env that points the hook at `relayUrl`. The account id / root key need only be *present* and
 * well-formed enough for config to parse — the relay is never reached, so their values don't matter
 * for a fail-closed test. `ALLW_FETCH_TIMEOUT_MS` is the CI-fast knob.
 */
function unreachableRelayEnv(relayUrl) {
  return {
    ALLW_RELAY_URL: relayUrl,
    ALLW_ACCOUNT_ID: "acct-uat",
    ALLW_APPROVER_ROOT_KEY: "k".repeat(43),
    ALLW_FETCH_TIMEOUT_MS: String(FETCH_TIMEOUT_MS),
  };
}

/**
 * Start a TCP server that accepts connections but never writes a response byte (it holds the socket
 * open indefinitely). Resolves to `{ url, close }`. Sockets are tracked so `close` tears them down.
 */
function startHungRelay() {
  return new Promise((resolve) => {
    /** @type {Set<import("node:net").Socket>} */
    const sockets = new Set();
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      // Deliberately never write / never end — the connection hangs (black-holed relay).
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${String(port)}`,
        close: () =>
          new Promise((res) => {
            for (const s of sockets) s.destroy();
            server.close(() => res());
          }),
      });
    });
  });
}

/**
 * Reserve a port, then close it so nothing is listening — connecting there is **refused** (a network
 * error, distinct from a hang). Resolves to a URL pointing at the now-free port.
 */
function refusedRelayUrl() {
  return new Promise((resolve) => {
    const probe = createServer();
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(`http://127.0.0.1:${String(port)}`));
    });
  });
}

// ── hung relay: accepts the TCP connection, never responds ────────────────────────────────────────

test("(#54) subprocess against a HUNG relay → deny, exit 0, within a bounded time", async (t) => {
  const relay = await startHungRelay();
  after(() => relay.close());

  const { code, stdout, stderr, elapsedMs } = await runCli(
    bashStdin("rm -rf build"),
    unreachableRelayEnv(relay.url),
  );

  assert.equal(code, 0, `the hook must exit 0 with a decision (stderr: ${stderr})`);
  const decision = parseDecision(stdout);
  assert.equal(decision.hookEventName, "PreToolUse");
  assert.equal(
    decision.permissionDecision,
    "deny",
    "a relay that accepts but never responds fails closed to deny — it never hangs",
  );
  assert.ok(
    elapsedMs < DECIDE_UPPER_BOUND_MS,
    `the hook must decide well under the CC hook timeout — took ${elapsedMs.toFixed(0)}ms ` +
      `(bound ${String(DECIDE_UPPER_BOUND_MS)}ms with a ${String(FETCH_TIMEOUT_MS)}ms fetch timeout)`,
  );
  t.diagnostic(`hung-relay deny in ${elapsedMs.toFixed(0)}ms`);
});

// ── connection refused: nothing listening on the port ────────────────────────────────────────────

test("(#54) subprocess against a REFUSED relay (no listener) → deny, exit 0, within a bounded time", async (t) => {
  const url = await refusedRelayUrl();

  const { code, stdout, stderr, elapsedMs } = await runCli(
    bashStdin("rm -rf build"),
    unreachableRelayEnv(url),
  );

  assert.equal(code, 0, `the hook must exit 0 with a decision (stderr: ${stderr})`);
  const decision = parseDecision(stdout);
  assert.equal(
    decision.permissionDecision,
    "deny",
    "a refused connection (network error) fails closed to deny",
  );
  assert.ok(
    elapsedMs < DECIDE_UPPER_BOUND_MS,
    `the hook must decide promptly — took ${elapsedMs.toFixed(0)}ms (bound ${String(
      DECIDE_UPPER_BOUND_MS,
    )}ms)`,
  );
  t.diagnostic(`refused-relay deny in ${elapsedMs.toFixed(0)}ms`);
});

// ── config cap: an oversized ALLW_TIMEOUT_MS denies at startup, before any relay dial ────────────

test("(#54) subprocess with ALLW_TIMEOUT_MS at the cap (420000) → deny at startup with the actionable reason", async () => {
  // 420000 = MAX_TIMEOUT_MS (config.ts); a value >= the cap is refused before the relay is contacted,
  // because it would let Claude Code's pinned hook timeout fire before the hook emits its deny.
  const { code, stdout } = await runCli(bashStdin("rm -rf build"), {
    ALLW_RELAY_URL: "https://relay.allw.test",
    ALLW_ACCOUNT_ID: "acct-uat",
    ALLW_APPROVER_ROOT_KEY: "k".repeat(43),
    ALLW_TIMEOUT_MS: "420000",
  });

  assert.equal(code, 0);
  const decision = parseDecision(stdout);
  assert.equal(
    decision.permissionDecision,
    "deny",
    "an oversized deadline is refused (fail-closed)",
  );
  assert.ok(
    /too large/.test(decision.permissionDecisionReason),
    `the deny reason must explain the cap, got: ${decision.permissionDecisionReason}`,
  );
  assert.ok(
    /420000/.test(decision.permissionDecisionReason),
    "the reason must name the cap so it is actionable",
  );
});

test("(#54) subprocess with an oversized ALLW_TIMEOUT_MS (900000 = 15 min) → deny at startup", async () => {
  const { code, stdout } = await runCli(bashStdin("rm -rf build"), {
    ALLW_RELAY_URL: "https://relay.allw.test",
    ALLW_ACCOUNT_ID: "acct-uat",
    ALLW_APPROVER_ROOT_KEY: "k".repeat(43),
    ALLW_TIMEOUT_MS: "900000",
  });

  assert.equal(code, 0);
  const decision = parseDecision(stdout);
  assert.equal(decision.permissionDecision, "deny");
  assert.ok(/too large/.test(decision.permissionDecisionReason));
});
