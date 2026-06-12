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
import { chmodSync, mkdtempSync, statSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadWasm } from "../dist/index.js";
import {
  KEYFILE_VERSION,
  generateKeyfile,
  loadKeyfile,
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

// ── Key-format validation (review item #3) ───────────────────────────────────────────────────

test("validateKeyfile rejects a seed that is not 32 bytes of base64url", async () => {
  const wasm = await loadWasm();
  const kf = generateKeyfile(wasm);

  // A 43-char-looking but wrong-length / wrong-charset seed must fail at validation, not later at
  // first crypto use deep in the WASM core.
  for (const bad of [
    "too-short",
    "not!base64url!chars!!!!!!!!!!!!!!!!!!!!!!!!!", // 43 chars but illegal characters
    Buffer.alloc(16, 7).toString("base64url"), // valid base64url, but only 16 bytes
    Buffer.alloc(64, 7).toString("base64url"), // valid base64url, but 64 bytes
  ]) {
    assert.throws(
      () => validateKeyfile({ ...kf, account_root_seed: bad }),
      /not a valid base64url-unpadded 32-byte key/,
      `a malformed seed (${bad.slice(0, 12)}…) must be rejected at validation`,
    );
  }
});

test("validateKeyfile rejects a malformed derived pubkey", async () => {
  const wasm = await loadWasm();
  const kf = generateKeyfile(wasm);
  assert.throws(
    () =>
      validateKeyfile({
        ...kf,
        device_encryption_pubkey: Buffer.alloc(31, 1).toString("base64url"),
      }),
    /'device_encryption_pubkey' is not a valid base64url-unpadded 32-byte key/,
    "a 31-byte pubkey must fail validation",
  );
});

test("validateKeyfile rejects a non-string optional pairing field (review item #6)", async () => {
  const wasm = await loadWasm();
  const kf = generateKeyfile(wasm);
  // A corrupt keyfile with a numeric device_id is NOT "unpaired" — it is corrupt, and must throw so
  // a garbled id can never flow into routing/signing.
  assert.throws(
    () => validateKeyfile({ ...kf, device_id: 12345 }),
    /'device_id' must be a string when present/,
    "a non-string device_id must be rejected, not treated as unpaired",
  );
  // A present string optional field is accepted.
  assert.doesNotThrow(() =>
    validateKeyfile({ ...kf, device_id: "dev-ok", relay_url: "https://r" }),
  );
});

test("validateKeyfile accepts only a non-negative safe account-state sequence floor", async () => {
  const wasm = await loadWasm();
  const kf = generateKeyfile(wasm);

  assert.equal(
    validateKeyfile({ ...kf, account_state_highest_sequence: 3 }).account_state_highest_sequence,
    3,
    "a valid persisted account-state sequence floor round-trips through validation",
  );
  for (const bad of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, "3"]) {
    assert.throws(
      () => validateKeyfile({ ...kf, account_state_highest_sequence: bad }),
      /'account_state_highest_sequence' must be a non-negative safe integer/,
      `invalid sequence floor ${String(bad)} must be rejected`,
    );
  }
});

// ── loadKeyfile distinguishes absent / corrupt / unreadable (review items #2 + #4) ────────────

test("loadKeyfile returns { kind: 'absent' } only for a genuinely missing file (ENOENT)", async () => {
  await loadWasm();
  withTempDir((dir) => {
    const result = loadKeyfile(join(dir, "absent.json"));
    assert.equal(result.kind, "absent", "a missing keyfile is reported as absent, not an error");
  });
});

test("loadKeyfile returns { kind: 'ok', keyfile } for a valid keyfile", async () => {
  const wasm = await loadWasm();
  withTempDir((dir) => {
    const path = join(dir, "kf.json");
    const kf = { ...generateKeyfile(wasm), account_id: "acct", device_id: "dev" };
    writeKeyfile(path, kf);
    const result = loadKeyfile(path);
    assert.equal(result.kind, "ok");
    if (result.kind === "ok") assert.deepEqual(result.keyfile, kf);
  });
});

test("loadKeyfile THROWS (not absent) on invalid JSON — must not be mistaken for missing", async () => {
  await loadWasm();
  withTempDir((dir) => {
    const path = join(dir, "corrupt.json");
    writeFileSync(path, "{ not json");
    assert.throws(
      () => loadKeyfile(path),
      /not valid JSON/,
      "corrupt content is an error, not absent",
    );
  });
});

test("loadKeyfile THROWS (not absent) on a permission error (EACCES), not 'no keyfile'", async (t) => {
  // chmod 000 has no effect when running as root (CI sometimes does) — skip there.
  if (typeof process.getuid === "function" && process.getuid() === 0) {
    t.skip("running as root: file-mode permission checks do not apply");
    return;
  }
  if (process.platform === "win32") {
    t.skip("POSIX permission modes do not apply on Windows");
    return;
  }
  const wasm = await loadWasm();
  withTempDir((dir) => {
    const path = join(dir, "noperm.json");
    writeKeyfile(path, { ...generateKeyfile(wasm) });
    chmodSync(path, 0o000); // unreadable
    try {
      assert.throws(
        () => loadKeyfile(path),
        /failed to read keyfile/,
        "an EACCES read error must surface as a read failure, NOT be misreported as 'absent'",
      );
      // And it must NOT be reported as the friendly "no keyfile … run pair" message.
      assert.throws(
        () => readKeyfile(path),
        (err) => !/no keyfile at/.test(err.message),
      );
    } finally {
      chmodSync(path, 0o600); // restore so withTempDir can clean up
    }
  });
});
