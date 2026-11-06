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
 * - `pending-verification` / `pending-verification-void`: a valid approval reaches a nonce store
 *   that never settles and owns no I/O. Either caller style must print expiry before exiting.
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

const ACCOUNT_SEED = Buffer.alloc(32, 7).toString("base64url");
/** Canonical identity keeps the valid approval on the nonce-store path. */
const ACCOUNT_ID = glue.account_id_for_root(glue.ed25519_public_key(ACCOUNT_SEED));
const accountStates = oneDeviceAccountStates(glue, {
  accountId: ACCOUNT_ID,
  accountSeed: ACCOUNT_SEED,
  deviceId: "dev_poll_keepalive",
  encryptionPub: glue.x25519_public_key(Buffer.alloc(32, 11).toString("base64url")),
});

const mode = process.argv[2] ?? "never";
const pendingVerification = mode.startsWith("pending-verification");
/** Fixed lifecycle values keep signed test data independent of the wall clock. */
const NOW_MS = 1_700_000_000_000;
let envelope;

/** A relay double that accepts the request, then reports it pending (or terminal, in `early`). */
const fetchImpl = async (url, init = {}) => {
  const path = new URL(url).pathname;
  const method = (init.method ?? "GET").toUpperCase();
  if (method === "POST" && path.endsWith("/requests")) {
    envelope = JSON.parse(init.body);
    const { id } = envelope;
    return json(
      { request_id: id, status: "pending", delivered_to: 1, request_auth_token: "t" },
      202,
    );
  }
  if (pendingVerification) {
    const deviceId = "dev_poll_keepalive";
    const signingSeed = Buffer.alloc(32, 9).toString("base64url");
    const context = glue.decrypt_context(
      envelope.context_ciphertext,
      deviceId,
      Buffer.alloc(32, 11).toString("base64url"),
    );
    const cert = glue.issue_device_cert(
      ACCOUNT_SEED,
      ACCOUNT_ID,
      deviceId,
      glue.ed25519_public_key(signingSeed),
      NOW_MS - 1000,
    );
    const verdict = JSON.parse(
      glue.sign_verdict(
        JSON.stringify({
          v: 1,
          request_id: envelope.id,
          request_hash: glue.compute_request_hash(context, envelope.expires_at),
          decision: "approved",
          decided_at: NOW_MS,
          approver: { account_id: ACCOUNT_ID, device_id: deviceId },
        }),
        signingSeed,
        Buffer.alloc(16, 3).toString("base64url"),
        cert,
      ),
    );
    return json({ request_id: envelope.id, status: "resolved", verdict });
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
  nowImpl: () => NOW_MS,
  ...(pendingVerification
    ? {
        nonceStore: {
          checkAndInsert: () => {
            console.log("nonce: pending");
            return new Promise(() => {});
          },
        },
      }
    : {}),
  pollIntervalMs: mode === "long-interval" ? 5_000 : 100,
});

/** Both hook-style fire-and-forget and script-style await must survive pending verification. */
async function main() {
  const verdict = await client.requestApproval({
    action: {
      recordSchemaVersion: 2,
      surface: "command",
      syntactic: { bin: "ls", argv: ["ls"] },
    },
    summary: "poll keep-alive",
    actor: { id: "machine:test", kind: "script" },

    reversible: true,
    timeoutMs: mode === "early" ? 60_000 : 400,
  });
  console.log(`decision: ${verdict.decision}`);
}
if (mode.endsWith("-void")) void main();
else await main();
