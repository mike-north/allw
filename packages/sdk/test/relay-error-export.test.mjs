/**
 * `RelayError` is part of `@allw/sdk`'s public surface (#365), so an integrator can narrow a failed
 * `requestApproval` with `instanceof` instead of matching `err.name`.
 *
 * Consumer-layer: the import is the bare specifier `@allw/sdk`, which Node resolves through the
 * package's own `exports` map (package self-reference), exactly as an installed consumer's import
 * would, never a deep `dist/` path. The relay is a fetch double that refuses the submit with 413,
 * the over-size `context_ciphertext` answer integrators can hit with honest input. Recipients come
 * from root-signed account state (#243), so each client is given a state vouching for one device.
 *
 * @see https://github.com/mike-north/allw/issues/365
 * @see ../../../docs/relay-api.md §3 (Integrator endpoints: request limits)
 * @see https://nodejs.org/api/packages.html#self-referencing-a-package-using-its-name
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  RecipientSelectionError,
  RelayError,
  createClient,
  relayAccountStateSource,
  fileSequenceFloorStore,
} from "@allw/sdk";

import { signedAccountState } from "./fixtures/account-state.mjs";

const vendorDir = join(dirname(fileURLToPath(import.meta.url)), "..", "vendor", "allw-wasm");

/** Load the vendored `--target web` WASM, to sign the fixture account state. */
async function loadWasm() {
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  glue.initSync({
    module: new WebAssembly.Module(readFileSync(join(vendorDir, "allw_wasm_bg.wasm"))),
  });
  return glue;
}

/** A fixed X25519 public key (base64url), derived from a fixed private key so runs are repeatable. */
function fixedX25519PublicKey() {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"),
    Buffer.alloc(32, 21),
  ]);
  const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return createPublicKey(key).export({ format: "jwk" }).x;
}

/** The fixed account-root seed (base64url); the account id derives from its public key. */
const ACCOUNT_SEED = Buffer.alloc(32, 7).toString("base64url");

/** The test account: a self-certifying id and its root key (`docs/enrollment.md` §Model). */
async function account() {
  const wasm = await loadWasm();
  const rootPub = wasm.ed25519_public_key(ACCOUNT_SEED);
  const accountId = wasm.account_id_for_root(rootPub);
  /** Root-signed state vouching for `devices` (`{ deviceId, encryptionPub }`). */
  const statesFor = (devices) => [
    signedAccountState(wasm, { accountId, accountSeed: ACCOUNT_SEED, devices }),
  ];
  return { accountId, rootPub, statesFor };
}

/** The one device the account state vouches for. */
const DEVICE = { deviceId: "dev_365", encryptionPub: fixedX25519PublicKey() };

/** A JSON response as the SDK's fetch reads it. */
function jsonResponse(data, status) {
  return { ok: status >= 200 && status < 300, status, json: () => Promise.resolve(data) };
}

/** A client whose account state vouches for `devices` and whose relay answers the submit with `submitStatus`. */
async function clientWith({ devices, submitStatus }) {
  const { accountId, rootPub, statesFor } = await account();
  return createClient({
    relayUrl: "https://relay.allw.test",
    accountId,
    approverRootKey: rootPub,
    accountStates: statesFor(devices),
    webSocketFactory: undefined,
    fetchImpl: () =>
      Promise.resolve(jsonResponse({ error: "context_ciphertext too large" }, submitStatus)),
  });
}

/**
 * A client whose relay accepts the submit and then answers every poll with `pollStatus`, counting
 * the polls in `seen.polls`.
 */
async function clientWithPollFailure(pollStatus, seen) {
  const { accountId, rootPub, statesFor } = await account();
  return createClient({
    relayUrl: "https://relay.allw.test",
    accountId,
    approverRootKey: rootPub,
    accountStates: statesFor([DEVICE]),
    webSocketFactory: undefined,
    pollIntervalMs: 1,
    fetchImpl: (url, init = {}) => {
      const method = (init.method ?? "GET").toUpperCase();
      const path = new URL(url).pathname;
      if (method === "POST" && path.endsWith("/requests")) {
        const { id } = JSON.parse(init.body);
        return Promise.resolve(
          jsonResponse(
            { request_id: id, status: "pending", delivered_to: 1, request_auth_token: "tok_365" },
            202,
          ),
        );
      }
      seen.polls += 1;
      return Promise.resolve(jsonResponse({ error: "authorization denied" }, pollStatus));
    },
  });
}

/** A request to submit; its content is irrelevant to the relay's refusal. */
const REQUEST = {
  action: {
    recordSchemaVersion: 3,
    surface: "command",
    syntactic: { raw: "git push" },
  },
  summary: "Push to main",
  actor: { id: "machine:ci", kind: "claude-code" },

  reversible: false,
  timeoutMs: 60_000,
};

test("RelayError is exported from the package entry point as an Error subclass", () => {
  assert.equal(typeof RelayError, "function");
  const err = new RelayError("relay submit failed (HTTP 413)", 413);
  assert.ok(err instanceof Error);
  assert.equal(err.name, "RelayError");
  assert.equal(err.status, 413);
});

test("a 413 from the relay narrows with instanceof RelayError and carries the status", async () => {
  const client = await clientWith({ devices: [DEVICE], submitStatus: 413 });
  let caught;
  try {
    await client.requestApproval(REQUEST);
    assert.fail("an over-size request must reject (fail-closed), never resolve");
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof RelayError, `a RelayError, got ${String(caught)}`);
  // After the narrowing, `status` is the relay's HTTP status.
  assert.equal(caught.status, 413);
  assert.equal(caught.name, "RelayError");
  assert.ok(
    !caught.message.includes("context_ciphertext too large"),
    "the relay's body is never quoted",
  );
});

test("a failure with no relay reply behind it is not a RelayError", async () => {
  // Account state that vouches for no device: the SDK refuses at seal, before any submit.
  const client = await clientWith({ devices: [], submitStatus: 202 });
  await assert.rejects(client.requestApproval(REQUEST), (err) => {
    assert.ok(err instanceof RecipientSelectionError, String(err));
    assert.ok(!(err instanceof RelayError), `not a RelayError: ${String(err)}`);
    assert.equal(err.stage, "seal", "it is the no-recipient refusal");
    return true;
  });
});

test("a failed account-state fetch rejects with RecipientSelectionError whose cause is the RelayError", async () => {
  // The account-state fetch fails before anything is sealed or sent, so the rejection is a
  // load-stage RecipientSelectionError; the relay's status stays reachable through `cause`.
  const { accountId, rootPub } = await account();
  const dir = mkdtempSync(join(tmpdir(), "allw-365-"));
  const fetchImpl = () => Promise.resolve(jsonResponse({ error: "boom" }, 500));
  const client = createClient({
    relayUrl: "https://relay.allw.test",
    accountId,
    approverRootKey: rootPub,
    accountStates: relayAccountStateSource({
      relayUrl: "https://relay.allw.test",
      accountId,
      floorStore: fileSequenceFloorStore({ accountId, dir }),
      fetchImpl,
    }),
    webSocketFactory: undefined,
    fetchImpl,
  });
  await assert.rejects(client.requestApproval(REQUEST), (err) => {
    assert.ok(err instanceof RecipientSelectionError, String(err));
    assert.equal(err.stage, "load");
    assert.ok(err.cause instanceof RelayError, `cause is a RelayError: ${String(err.cause)}`);
    assert.equal(err.cause.status, 500);
    return true;
  });
});

test("a non-2xx poll after the submit resolves to an expired verdict, not a RelayError rejection", async () => {
  // Only the submit rejects with RelayError. Once the request is submitted, a
  // relay error while waiting is a fail-closed "expired" verdict (docs/relay-api.md §3).
  for (const pollStatus of [401, 403, 500]) {
    const seen = { polls: 0 };
    const verdict = await (await clientWithPollFailure(pollStatus, seen)).requestApproval(REQUEST);
    assert.equal(verdict.decision, "expired", `HTTP ${String(pollStatus)} while waiting`);
    assert.ok(seen.polls >= 1, "the client did poll and got the error");
  }
});
