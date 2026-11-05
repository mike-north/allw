/**
 * Subprocess fixture for `../poll-keepalive.test.mjs`: a minimal caller that awaits
 * `requestApproval` at the top level on the **poll** path (no WebSocket) against a relay double
 * that never decides. Correct behavior: the wait keeps the process alive until the fail-closed
 * deadline, then prints `decision: expired` and exits 0.
 *
 * Modes (`argv[2]`):
 * - `never` (default): the relay never answers; expect `expired` at the 400 ms deadline.
 * - `early`: the relay reports a terminal outcome on the first poll while a 60 s deadline is still
 *   pending; expect the process to exit at once (the deadline timer must not hold it open).
 * - `long-interval`: as `never`, but the poll interval (5 s) exceeds the 400 ms deadline; expect
 *   `expired` and a prompt exit (the poll sleep is clamped to the deadline, not slept in full).
 *
 * Regression for #254: the bug where every SDK wait timer was `unref`'d, so on the poll path nothing held
 * the event loop between polls and Node exited mid-wait (code 13 under top-level await; code 0 with
 * no output under `void main()`, as the hook CLIs run).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createClient } from "../../dist/index.js";
import { oneDeviceAccountStates } from "./account-state.mjs";

const vendorDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "vendor", "allw-wasm");
const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
glue.initSync({
  module: new WebAssembly.Module(readFileSync(join(vendorDir, "allw_wasm_bg.wasm"))),
});

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const ACCOUNT_ID = "acct_poll_keepalive";
const ACCOUNT_SEED = Buffer.alloc(32, 7).toString("base64url");
const accountStates = oneDeviceAccountStates(glue, {
  accountId: ACCOUNT_ID,
  accountSeed: ACCOUNT_SEED,
  deviceId: "dev_poll_keepalive",
  encryptionPub: glue.x25519_public_key(Buffer.alloc(32, 11).toString("base64url")),
});

const mode = process.argv[2] ?? "never";

/** A relay double that accepts the request, then reports it pending (or terminal, in `early`). */
const fetchImpl = async (url, init = {}) => {
  const path = new URL(url).pathname;
  const method = (init.method ?? "GET").toUpperCase();
  if (method === "POST" && path.endsWith("/requests")) {
    const { id } = JSON.parse(init.body);
    return json(
      { request_id: id, status: "pending", delivered_to: 1, request_auth_token: "t" },
      202,
    );
  }
  return json({ request_id: "x", status: mode === "early" ? "expired" : "pending" });
};

const client = createClient({
  relayUrl: "https://relay.allw.test",
  accountId: ACCOUNT_ID,
  approverRootKey: glue.ed25519_public_key(ACCOUNT_SEED),
  accountStates,
  fetchImpl,
  webSocketFactory: undefined,
  pollIntervalMs: mode === "long-interval" ? 5_000 : 100,
});

const verdict = await client.requestApproval({
  action: {
    recordSchemaVersion: 1,
    surface: "command",
    syntactic: { bin: "ls", argv: ["ls"] },
    risk: "low",
  },
  summary: "poll keep-alive",
  actor: { id: "machine:test", kind: "script" },
  risk: "low",
  reversible: true,
  timeoutMs: mode === "early" ? 60_000 : 400,
});
console.log(`decision: ${verdict.decision}`);
