#!/usr/bin/env node
/**
 * `allw-openclaw-bridge` — the OpenClaw gateway operator client.
 *
 * Runs as `node dist/cli.js` over the shared WASM core: **no `napi`, no packaged native
 * executable** (`docs/architecture.md` §Local execution, `docs/openclaw-integration.md` §10). A
 * misconfiguration is a startup failure, never a degraded mode — a bridge that cannot gate must not
 * appear to be gating.
 */

import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { createClient, fileSequenceFloorStore, relayAccountStateSource } from "@allw/sdk";
import { loadWasm } from "@allw/hook";

import { OpenClawBridge } from "./lib/bridge.js";
import { ConfigError, loadConfig } from "./lib/config.js";
import { openCredentialStore } from "./lib/credential-store.js";
import { createGatewayConnection } from "./lib/gateway.js";
import { createLogger, stderrSink } from "./lib/logging.js";
import { getVersion } from "./version.js";

/** Start the bridge and run until the process is stopped. */
export async function runBridge(argv: readonly string[]): Promise<number> {
  if (argv.includes("--version") || argv.includes("-v")) {
    process.stdout.write(`${getVersion()}\n`);
    return 0;
  }

  const logger = createLogger(stderrSink);

  let config;
  try {
    config = loadConfig(process.env, homedir());
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`${err.message}\n`);
      return 2;
    }
    throw err;
  }

  const wasm = await loadWasm();
  const store = openCredentialStore(config.stateDir, config.gatewayId);
  // Recipients come from the root-signed account state the relay serves, never from its device
  // list; the per-account sequence floor refuses a rollback across restarts. It lives in the
  // bridge's state directory (`<ALLW_OPENCLAW_STATE_DIR>/state`, by default `~/.allw/state`, the
  // same place the hooks keep theirs), like the bridge's other state.
  // A load, verification or floor failure throws inside `requestApproval`, which the bridge denies.
  const client = createClient({
    relayUrl: config.relayUrl,
    accountId: config.accountId,
    approverRootKey: config.approverRootKey,
    expectedAccountId: config.accountId,
    accountStates: relayAccountStateSource({
      relayUrl: config.relayUrl,
      accountId: config.accountId,
      floorStore: fileSequenceFloorStore({
        accountId: config.accountId,
        dir: join(config.stateDir, "state"),
      }),
      fetchTimeoutMs: config.fetchTimeoutMs,
    }),
    fetchTimeoutMs: config.fetchTimeoutMs,
  });

  // A holder, because the connection's lifecycle closure and the bridge reference each other. The
  // bridge is assigned immediately below and is only ever read once a `hello-ok` has fired.
  const held: { bridge?: OpenClawBridge } = {};
  const connection = createGatewayConnection(config, store, logger, {
    onConnected: async () => {
      // The event listener is installed below, before `start()` — so by the time this runs the
      // handlers are already live and the backfill can only ever *reconcile* against them (§4.3).
      await held.bridge?.project();
    },
    onDisconnected: (code, reason) => {
      logger.warn("gateway.disconnected", { code, reason });
    },
  });

  const bridge = new OpenClawBridge({
    gateway: connection,
    wasm,
    requestApproval: (req) => client.requestApproval(req),
    config,
    logger,
    now: () => Date.now(),
  });

  held.bridge = bridge;
  bridge.listen();
  logger.info("bridge.starting", {
    gatewayId: config.gatewayId,
    actor: `openclaw:${config.gatewayId}`,
    scopes: "operator.approvals",
  });
  connection.start();

  await new Promise<void>((resolve) => {
    const shutdown = (): void => {
      void connection.stop().finally(resolve);
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });
  return 0;
}

/**
 * Whether this module is the process entrypoint (run the bridge) rather than imported by a test.
 * An installed bin is a **symlink** in `node_modules/.bin`, so `argv[1]` is the symlink path while
 * `import.meta.url` is the real `dist/cli.js`; comparing them raw made `allw-openclaw-bridge` exit
 * silently without doing anything. Resolve the symlink first, as `@allw/hook` does.
 * Regression-tested by the packaged-install smoke test (`scripts/smoke-packaged-install.mjs`).
 */
function isMainEntrypoint(): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(argv1)).href;
  } catch {
    return import.meta.url === pathToFileURL(argv1).href;
  }
}

if (isMainEntrypoint()) {
  runBridge(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      process.stderr.write(
        `allw-openclaw-bridge: fatal: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exitCode = 1;
    });
}
