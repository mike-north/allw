/**
 * Keyfile custody tests for the v0 stand-in approver (issue #41).
 *
 * Covers generation (three software-held seeds → derived pubkeys via the WASM core), round-trip
 * persistence with restrictive permissions, and fail-closed validation of corrupt/partial keyfiles
 * (a missing seed must abort, never be silently repaired — it could otherwise sign with a wrong key).
 *
 * @see ../../../docs/contract.md §Identity & keys (production custody is hardware-backed; this is v0)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, statSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadWasm } from "../dist/index.js";
import {
  KEYFILE_VERSION,
  generateKeyfile,
  readKeyfile,
  validateKeyfile,
  writeKeyfile,
} from "../dist/lib/keyfile.js";

/** A fresh temp dir per test, cleaned up after. */
function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "allw-approver-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("generateKeyfile produces three distinct 43-char base64url pubkeys from the core", async () => {
  const wasm = await loadWasm();
  const kf = generateKeyfile(wasm);

  assert.equal(kf.version, KEYFILE_VERSION, "version is the current schema version");
  for (const seed of [kf.account_root_seed, kf.device_signing_seed, kf.device_encryption_seed]) {
    // 32 bytes → 43 base64url-unpadded chars.
    assert.equal(Buffer.from(seed, "base64url").length, 32, "each seed decodes to 32 bytes");
  }
  for (const pub of [
    kf.account_root_pubkey,
    kf.device_signing_pubkey,
    kf.device_encryption_pubkey,
  ]) {
    assert.equal(pub.length, 43, "each derived pubkey is 43 base64url chars");
  }

  // Independent seeds → independent keys (the device signing and encryption keys must differ).
  assert.notEqual(kf.device_signing_pubkey, kf.device_encryption_pubkey);
  assert.notEqual(kf.account_root_pubkey, kf.device_signing_pubkey);

  // Derivation is deterministic: re-deriving from the stored seed reproduces the pubkey.
  assert.equal(
    wasm.ed25519_public_key(kf.account_root_seed),
    kf.account_root_pubkey,
    "account-root pubkey re-derives deterministically from its seed",
  );
});

test("write/read round-trips a keyfile and writes it 0600 (owner-only)", async () => {
  const wasm = await loadWasm();
  withTempDir((dir) => {
    const path = join(dir, "nested", "keyfile.json");
    const kf = { ...generateKeyfile(wasm), account_id: "acct", device_id: "dev" };
    writeKeyfile(path, kf);

    const back = readKeyfile(path);
    assert.deepEqual(back, kf, "the keyfile round-trips byte-for-byte through write/read");

    // Owner-only permission bits (best-effort; skip the assertion on platforms without POSIX modes).
    const mode = statSync(path).mode & 0o777;
    if (process.platform !== "win32") {
      assert.equal(mode, 0o600, "the keyfile is written owner-read/write only (0600)");
    }
  });
});

test("readKeyfile throws a helpful error when no keyfile exists", async () => {
  await loadWasm();
  withTempDir((dir) => {
    assert.throws(
      () => readKeyfile(join(dir, "absent.json")),
      /no keyfile at .* run 'allw-approver pair'/,
      "a missing keyfile must point the user at 'pair'",
    );
  });
});

test("validateKeyfile rejects a keyfile missing a seed (fail-closed)", async () => {
  await loadWasm();
  const wasm = await loadWasm();
  const kf = generateKeyfile(wasm);
  const broken = { ...kf };
  delete broken.device_signing_seed;
  assert.throws(
    () => validateKeyfile(broken),
    /missing required field 'device_signing_seed'/,
    "a keyfile missing a signing seed must abort, not be silently repaired",
  );
});

test("validateKeyfile rejects an unsupported version", async () => {
  await loadWasm();
  assert.throws(
    () => validateKeyfile({ version: 999 }),
    /unsupported keyfile version 999/,
    "a future/unknown keyfile version must be rejected fail-closed",
  );
});

test("readKeyfile throws on non-JSON content", async () => {
  await loadWasm();
  withTempDir((dir) => {
    const path = join(dir, "garbage.json");
    writeFileSync(path, "this is not json");
    assert.throws(() => readKeyfile(path), /not valid JSON/, "corrupt keyfile content must throw");
  });
});
