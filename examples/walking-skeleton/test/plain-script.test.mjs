/**
 * User-acceptance test for issue #231: a ~10-line plain script gates a command on a human
 * approval through `@allw/sdk`'s `commandRequest`, and runs **verbatim**.
 *
 * The script under test is `../scripts/gate-refund.mjs`, the same file `packages/sdk/README.md`
 * shows (asserted below so the docs cannot drift). It runs as a real `node` subprocess, exactly as
 * a script author would run it, so this test drives the SDK only through its public surface.
 *
 * Harness: the same pieces as `./e2e.test.mjs` — the in-process relay double (which mirrors the
 * relay's routing contract and its zero-knowledge envelope guard) plus the real `@allw/approver`
 * core paired on a fresh identity. Because the script is a separate process, the relay double is
 * served over a loopback HTTP server; the SDK's WebSocket upgrade is refused, so it uses its
 * documented poll fallback.
 *
 * Clock: the subprocess uses the real clock (a script cannot take an injected one), so the relay
 * double and approver use the real clock too — otherwise the approver's `decided_at` would fall
 * outside the request's `[created_at, expires_at]` window. Test *data* contains no clock reads; the
 * pairing timestamp is the only one taken, and only as "a moment before the request".
 *
 * Proves (issue #231 acceptance):
 * - approve → the script sees `decision === "approved"` and exits 0;
 * - deny → a non-approved decision, exit 1 (fail-closed);
 * - timeout → `expired`, exit 1 (fail-closed);
 * - the human-shown action is exactly the core's `action_from_argv` record for the script's argv
 *   (WYSIWYS), with the documented `commandRequest` defaults (`actor`, `reversible`, `risk`);
 * - a malformed argv (missing argument) rejects before anything is submitted.
 *
 * @see ../../../docs/contract.md §Invariants (fail-closed; never returns "allow"; WYSIWYS)
 * @see ../../../docs/policy-seam.md §ActionRecord (`surface: "command"`)
 * @see ./e2e.test.mjs (the harness pattern this reuses)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { hostname } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "@allw/approver";

import { InProcessRelay } from "../dist/lib/in-process-relay.js";
import { attachAutoApprover } from "../dist/lib/approver-harness.js";
import { buildPairedApprover } from "../dist/lib/identity.js";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const SCRIPT = join(packageRoot, "scripts", "gate-refund.mjs");
const SDK_README = join(packageRoot, "..", "..", "packages", "sdk", "README.md");

const ACCOUNT_ID = "acct-plain-script";
const DEVICE_ID = "dev-plain-script";
const CHARGE_ID = "ch_3PqR9sT";
/** The argv the script builds for {@link CHARGE_ID} (see `scripts/gate-refund.mjs`). */
const SCRIPT_ARGV = ["stripe", "refunds", "create", "--charge", CHARGE_ID];

/** The real clock — see the module comment for why this suite cannot use a fixed one. */
const now = () => Date.now();

/** Serve the relay double's fetch surface on a loopback port. */
async function serveRelay(relay) {
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === "string") headers.set(key, value);
    }
    const response = await relay.fetchImpl(`http://${req.headers.host}${req.url}`, {
      method: req.method,
      headers,
      ...(chunks.length > 0 ? { body: Buffer.concat(chunks).toString("utf8") } : {}),
    });
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(await response.text());
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}`, close: () => server.close() };
}

/** Stand up the relay double + a paired approver deciding per `mode`. */
async function harness(t, mode) {
  const wasm = await loadWasm();
  const pairedAt = now();
  const identity = buildPairedApprover(wasm, {
    accountId: ACCOUNT_ID,
    deviceId: DEVICE_ID,
    relayUrl: "http://127.0.0.1",
    issuedAt: pairedAt - 1000,
    label: "plain-script device",
  });
  const relay = new InProcessRelay({ now });
  relay.enrollDevice({
    device_id: DEVICE_ID,
    pubkey: identity.keyfile.device_encryption_pubkey,
    label: identity.keyfile.label ?? null,
    created_at: pairedAt - 10_000,
  });
  const { log } = attachAutoApprover(identity, relay.connectDevice(), mode, now);
  const served = await serveRelay(relay);
  t.after(served.close);
  return { wasm, identity, relay, log, relayUrl: served.url };
}

/** Run the script verbatim as a subprocess; resolves `{ code, stdout, stderr }`. */
function runScript(args, env) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [SCRIPT, ...args],
      { cwd: packageRoot, env: { ...process.env, ...env } },
      (error, stdout, stderr) => {
        resolve({ code: error ? error.code : 0, stdout, stderr });
      },
    );
  });
}

/** The script's environment: where the relay is, which account, and the approver's root key. */
function scriptEnv(h, extra = {}) {
  return {
    ALLW_RELAY_URL: h.relayUrl,
    ALLW_ACCOUNT_ID: ACCOUNT_ID,
    ALLW_APPROVER_ROOT_KEY: h.identity.keyfile.account_root_pubkey,
    ...extra,
  };
}

test("the SDK README shows the script under test verbatim", () => {
  const readme = readFileSync(SDK_README, "utf8");
  const script = readFileSync(SCRIPT, "utf8");
  assert.ok(readme.includes(script.trimEnd()), "packages/sdk/README.md embeds gate-refund.mjs");
});

test("approve: the script's command is shown exactly and the script proceeds", async (t) => {
  const h = await harness(t, "approved");
  const result = await runScript([CHARGE_ID], scriptEnv(h));

  assert.equal(result.code, 0, `script exited 0 (stderr: ${result.stderr})`);
  assert.match(result.stdout, /^decision: approved$/m);

  assert.equal(h.log.length, 1, "the approver handled exactly one request");
  assert.equal(h.log[0].decision, "approved");
  const context = h.log[0].context;
  // WYSIWYS: the decrypted, human-shown action is exactly the core's record for the script's argv.
  assert.deepEqual(
    context.action,
    JSON.parse(h.wasm.action_from_argv(JSON.stringify(SCRIPT_ARGV), null, null)),
  );
  assert.equal(context.action.surface, "command", "no new surface: a script action is a command");
  assert.equal(context.summary, `Refund charge ${CHARGE_ID}`);
  // commandRequest defaults (#231): script actor on this machine, irreversible, core-derived risk.
  assert.deepEqual(context.actor, { id: `machine:${hostname()}`, kind: "script" });
  assert.equal(context.reversible, false);
  assert.equal(context.risk, context.action.risk);
});

test("deny (fail-closed): a human 'no' stops the script", async (t) => {
  const h = await harness(t, "denied");
  const result = await runScript([CHARGE_ID], scriptEnv(h));

  assert.equal(result.code, 1, "the script exits non-zero");
  assert.match(result.stdout, /^decision: denied$/m);
  assert.equal(h.log[0].decision, "denied");
});

test("timeout (fail-closed): no answer by the deadline resolves expired", async (t) => {
  const h = await harness(t, "timeout");
  const result = await runScript([CHARGE_ID], scriptEnv(h, { ALLW_TIMEOUT_MS: "500" }));

  assert.equal(result.code, 1, "the script exits non-zero");
  assert.match(result.stdout, /^decision: expired$/m);
  assert.equal(h.log.length, 1, "the request reached the approver");
  assert.equal(h.log[0].decision, null, "the approver never answered");
});

test("malformed argv (missing charge id) rejects before anything is submitted", async (t) => {
  const h = await harness(t, "approved");
  const result = await runScript([], scriptEnv(h));

  assert.notEqual(result.code, 0, "the script fails");
  assert.match(result.stderr, /CommandActionError/);
  assert.match(result.stderr, /argv\[4\] must be a string \(got undefined\)/);
  assert.doesNotMatch(result.stdout, /decision:/, "no verdict was ever awaited");
  assert.deepEqual(h.relay.requestIds(), [], "nothing reached the relay");
  assert.equal(h.log.length, 0, "the approver saw nothing");
});
