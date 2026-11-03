/**
 * `RelayError` is part of `@allw/sdk`'s public surface (#365), so an integrator can narrow a failed
 * `requestApproval` with `instanceof` instead of matching `err.name`.
 *
 * Consumer-layer: the import is the bare specifier `@allw/sdk`, which Node resolves through the
 * package's own `exports` map (package self-reference), exactly as an installed consumer's import
 * would, never a deep `dist/` path. The relay is a fetch double that refuses the submit with 413,
 * the over-size `context_ciphertext` answer integrators can hit with honest input.
 *
 * @see https://github.com/mike-north/allw/issues/365
 * @see ../../../docs/relay-api.md §3 (Integrator endpoints: request limits)
 * @see https://nodejs.org/api/packages.html#self-referencing-a-package-using-its-name
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";

import { RelayError, createClient } from "@allw/sdk";

/** A fixed X25519 public key (base64url), derived from a fixed private key so runs are repeatable. */
function fixedX25519PublicKey() {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"),
    Buffer.alloc(32, 21),
  ]);
  const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return createPublicKey(key).export({ format: "jwk" }).x;
}

/** A fixed Ed25519 public key (base64url) to stand in for the account-root key. */
function fixedEd25519PublicKey() {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, 7),
  ]);
  const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return createPublicKey(key).export({ format: "jwk" }).x;
}

/** One enrolled device, as `GET /:acct/devices` returns it. */
const DEVICE = { device_id: "dev_365", pubkey: fixedX25519PublicKey(), label: null, created_at: 0 };

/** A JSON response as the SDK's fetch reads it. */
function jsonResponse(data, status) {
  return { ok: status >= 200 && status < 300, status, json: () => Promise.resolve(data) };
}

/** A client whose relay lists `devices` and answers the submit with `submitStatus`. */
function clientWith({ devices, submitStatus }) {
  return createClient({
    relayUrl: "https://relay.allw.test",
    accountId: "acct_365",
    approverRootKey: fixedEd25519PublicKey(),
    webSocketFactory: undefined,
    fetchImpl: (url, init = {}) => {
      const method = (init.method ?? "GET").toUpperCase();
      if (method === "GET" && new URL(url).pathname.endsWith("/devices")) {
        return Promise.resolve(jsonResponse({ devices }, 200));
      }
      return Promise.resolve(jsonResponse({ error: "context_ciphertext too large" }, submitStatus));
    },
  });
}

/** A request to submit; its content is irrelevant to the relay's refusal. */
const REQUEST = {
  action: {
    recordSchemaVersion: 1,
    surface: "command",
    syntactic: { bin: "git", raw: "git push" },
    risk: "high",
  },
  summary: "Push to main",
  actor: { id: "machine:ci", kind: "claude-code" },
  risk: "high",
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
  const client = clientWith({ devices: [DEVICE], submitStatus: 413 });
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
  // No enrolled devices: the SDK refuses before any submit, with a plain Error.
  const client = clientWith({ devices: [], submitStatus: 202 });
  await assert.rejects(client.requestApproval(REQUEST), (err) => {
    assert.ok(err instanceof Error);
    assert.ok(!(err instanceof RelayError), `not a RelayError: ${String(err)}`);
    assert.match(err.message, /device/i, "it is the no-enrolled-devices refusal");
    return true;
  });
});
