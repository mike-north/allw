/**
 * Credential-custody tests.
 *
 * The device private key and the paired device token are secrets at rest: owner-only permissions,
 * never an environment variable, never a config file the operator edits by hand.
 *
 * @see ../../../docs/openclaw-integration.md §4.2 Pairing and credential handling
 */

import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { openCredentialStore } from "../dist/index.js";

const GATEWAY_ID = "home-mini";

function freshStore() {
  const dir = mkdtempSync(join(tmpdir(), "allw-openclaw-cred-"));
  return {
    dir,
    store: openCredentialStore(dir, GATEWAY_ID),
    path: join(dir, `openclaw-bridge-${GATEWAY_ID}.json`),
  };
}

test("a fresh store mints an Ed25519 identity and persists it 0600", () => {
  const { store, path } = freshStore();
  const identity = store.loadOrCreateDeviceIdentity();

  assert.match(identity.privateKeyPem, /^-----BEGIN PRIVATE KEY-----/);
  assert.match(identity.publicKeyPem, /^-----BEGIN PUBLIC KEY-----/);
  assert.ok(identity.deviceId.startsWith("allw-openclaw-bridge-"));
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test("the identity is stable across reopens", () => {
  const { dir, store } = freshStore();
  const first = store.loadOrCreateDeviceIdentity();
  const second = openCredentialStore(dir, GATEWAY_ID).loadOrCreateDeviceIdentity();
  assert.deepEqual(second, first);
});

test("device tokens round-trip per role and can be cleared", () => {
  const { store } = freshStore();
  store.loadOrCreateDeviceIdentity();

  assert.equal(store.loadDeviceToken("operator"), null);
  store.storeDeviceToken("operator", { token: "tok-1", scopes: ["operator.approvals"] });
  assert.deepEqual(store.loadDeviceToken("operator"), {
    token: "tok-1",
    scopes: ["operator.approvals"],
  });
  assert.equal(
    store.loadDeviceToken("node"),
    null,
    "tokens are scoped to the role they were issued for",
  );

  store.clearDeviceToken("operator");
  assert.equal(store.loadDeviceToken("operator"), null);
});

test("storing a token preserves owner-only permissions on rewrite", () => {
  const { store, path } = freshStore();
  store.loadOrCreateDeviceIdentity();
  store.storeDeviceToken("operator", { token: "tok-1", scopes: [] });
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test("an empty token is treated as absent rather than surfaced as a credential", () => {
  const { store } = freshStore();
  store.loadOrCreateDeviceIdentity();
  store.storeDeviceToken("operator", { token: "", scopes: [] });
  assert.equal(store.loadDeviceToken("operator"), null);
});

test("a corrupt credential file is treated as absent, not half-parsed", () => {
  const { dir, store, path } = freshStore();
  store.loadOrCreateDeviceIdentity();
  writeFileSync(path, "{ not json", { mode: 0o600 });

  const identity = openCredentialStore(dir, GATEWAY_ID).loadOrCreateDeviceIdentity();
  assert.match(identity.privateKeyPem, /^-----BEGIN PRIVATE KEY-----/);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test("a credential file from a future schema version is not reused", () => {
  const { dir, store, path } = freshStore();
  const original = store.loadOrCreateDeviceIdentity();
  const file = JSON.parse(readFileSync(path, "utf8"));
  writeFileSync(path, JSON.stringify({ ...file, version: 99 }), { mode: 0o600 });

  const identity = openCredentialStore(dir, GATEWAY_ID).loadOrCreateDeviceIdentity();
  assert.notEqual(identity.deviceId, original.deviceId);
});

test("each gateway label gets its own credential file", () => {
  const { dir, store } = freshStore();
  const a = store.loadOrCreateDeviceIdentity();
  const b = openCredentialStore(dir, "devbox-1").loadOrCreateDeviceIdentity();
  assert.notEqual(a.deviceId, b.deviceId);
});
