/**
 * Child-process driver for the #246 watch UAT (`../display-safety.test.mjs`).
 *
 * Runs the real `runWatch` loop with the real readline prompter (`createReadlinePrompter`, which
 * writes to `process.stdout`) and the default console logger, against a stub relay socket that
 * delivers one request: by default the ESC/CR line-erase spoof, or the `ApprovalContext` in
 * `<context-file>` when one is given (the tool-surface headline UAT, #321). The parent pipes a
 * decision on stdin and inspects this process's raw stdout/stderr bytes.
 *
 * Usage: node watch-spoof-driver.mjs <scratch-dir> [<context-file>]
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { createReadlinePrompter, loadWasm, runWatch } from "../../dist/index.js";
import { generateKeyfile, writeKeyfile } from "../../dist/lib/keyfile.js";

const ACCOUNT_ID = "acct-display-uat";
const DEVICE_ID = "dev-display-uat";
const REQUEST_ID = "req-display-uat";
const ISSUED_AT = 1700000000000;
const EXPIRES_AT = 1700003600000;
const NOW_MS = 1700001500000;

const dir = process.argv[2];
if (dir === undefined)
  throw new Error("usage: watch-spoof-driver.mjs <scratch-dir> [<context-file>]");
const contextFile = process.argv[3];

const wasm = await loadWasm();
const fresh = generateKeyfile(wasm);
const keyfile = {
  ...fresh,
  relay_url: "https://relay.allw.test",
  account_id: ACCOUNT_ID,
  device_id: DEVICE_ID,
  device_auth_token: "device-token",
  device_cert: wasm.issue_device_cert(
    fresh.account_root_seed,
    ACCOUNT_ID,
    DEVICE_ID,
    fresh.device_signing_pubkey,
    ISSUED_AT,
  ),
};
const keyfilePath = join(dir, "keyfile.json");
writeKeyfile(keyfilePath, keyfile);

const spoofContext = {
  action: {
    record_schema_version: 3,
    surface: "command",
    // The spoof, then 100 more lines, so the block is far taller than a terminal.
    facts: {
      raw: [
        "rm -rf ~/x; : \u001b[2K\rgit status",
        ...Array.from({ length: 100 }, (_, i) => `echo line ${String(i)}`),
      ].join("\n"),
    },
  },
  summary: "check git status",
  actor: { id: "machine:ci", kind: "claude-code" },

  reversible: false,
  constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
};
const context =
  contextFile === undefined ? spoofContext : JSON.parse(readFileSync(contextFile, "utf8"));
const envelope = {
  v: 1,
  id: REQUEST_ID,
  created_at: ISSUED_AT,
  expires_at: EXPIRES_AT,
  approver: ACCOUNT_ID,
  context_ciphertext: wasm.encrypt_context(
    JSON.stringify(context),
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: fresh.device_encryption_pubkey }]),
  ),
};

// No relay account state: the origin renders ⚠ UNVERIFIED (no network access needed).
globalThis.fetch = async () =>
  new Response(JSON.stringify({ account_states: [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });

const listeners = { open: [], message: [], error: [], close: [] };
const emit = (type, ev = {}) => {
  for (const listener of listeners[type]) listener(ev);
};
queueMicrotask(() => {
  emit("open");
  emit("message", { data: JSON.stringify({ type: "request", request_id: REQUEST_ID, envelope }) });
});

await runWatch(
  wasm,
  { keyfilePath },
  {
    connect: () => ({
      addEventListener: (type, listener) => listeners[type].push(listener),
      // The verdict is the last thing this run needs; close once it is sent.
      send: () => emit("close"),
      close: () => emit("close"),
    }),
    prompter: createReadlinePrompter(),
    now: () => NOW_MS,
  },
);
