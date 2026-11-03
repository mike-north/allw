/**
 * Small-order X25519 recipient keys through the compiled WASM (#248).
 *
 * The shared vector `crates/allw-core/tests/fixtures/x25519_small_order.json` (libsodium's
 * `has_small_order` list, copied by hand) is asserted on the Rust side by
 * `crates/allw-core/tests/x25519_small_order_vector.rs`. Here the same vector goes through the
 * `.wasm`:
 *
 * - `x25519_small_order_points()` returns exactly the fixture list, so a WASM consumer (the relay,
 *   at pairing time) can reject exactly what the core refuses to encrypt to;
 * - `is_small_order_x25519_public_key` and `encrypt_context` agree on every listed point, its
 *   bit-255-set variant, and the non-small-order controls;
 * - `encrypt_context` to a small-order key **throws** an error that names the device, instead of
 *   panicking. A wasm panic aborts the instance and poisons every later call, so the same instance
 *   must still encrypt to a valid recipient afterwards — and that ciphertext must decrypt.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7748#section-6.1 (all-zero shared-secret check)
 * @see https://cr.yp.to/ecdh.html#validate (the small-order points of Curve25519)
 * @see ../../../crates/allw-core/src/jwe.rs (`X25519_SMALL_ORDER_POINTS`, `EncryptError`)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

/** Load the `--target web` wasm synchronously (mirrors test/wasm.test.mjs). */
async function loadWasm() {
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  const bytes = readFileSync(join(vendorDir, "allw_wasm_bg.wasm"));
  glue.initSync({ module: new WebAssembly.Module(bytes) });
  return glue;
}

function loadVector() {
  const raw = readFileSync(
    join(
      here,
      "..",
      "..",
      "..",
      "crates",
      "allw-core",
      "tests",
      "fixtures",
      "x25519_small_order.json",
    ),
    "utf8",
  );
  return JSON.parse(raw);
}

/** The same point with bit 255 set (X25519 masks it, RFC 7748 §5). */
function withHighBit(b64url) {
  const bytes = Buffer.from(b64url, "base64url");
  bytes[31] |= 0x80;
  return bytes.toString("base64url");
}

const CONTEXT = {
  action: {
    record_schema_version: 1,
    surface: "command",
    syntactic: { argv: ["git", "status"], raw: "git status" },
    risk: "low",
  },
  summary: "check git status",
  actor: { id: "machine:ci", kind: "claude-code" },
  risk: "low",
  reversible: true,
  constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
};

function encryptTo(wasm, recipients) {
  return wasm.encrypt_context(JSON.stringify(CONTEXT), JSON.stringify(recipients));
}

test("x25519_small_order_points() is exactly the shared vector's list", async () => {
  const wasm = await loadWasm();
  const vector = loadVector();
  assert.deepEqual(
    JSON.parse(wasm.x25519_small_order_points()),
    vector.small_order.map((p) => p.b64url),
  );
});

test("the denylist and encrypt_context agree on every vector point and control", async () => {
  const wasm = await loadWasm();
  const vector = loadVector();
  for (const point of vector.small_order) {
    for (const key of [point.b64url, withHighBit(point.b64url)]) {
      assert.equal(wasm.is_small_order_x25519_public_key(key), true, `${point.name} is denylisted`);
      assert.throws(
        () => encryptTo(wasm, [{ device_id: "dev-small-order", public_key_b64: key }]),
        /recipient device 'dev-small-order' has a small-order X25519 public key/,
        `${point.name} is refused by encrypt_context`,
      );
    }
  }
  for (const point of vector.not_small_order) {
    assert.equal(wasm.is_small_order_x25519_public_key(point.b64url), false, point.name);
    assert.equal(
      typeof encryptTo(wasm, [{ device_id: "dev-ok", public_key_b64: point.b64url }]),
      "string",
      `${point.name} encrypts`,
    );
  }
});

test("is_small_order_x25519_public_key rejects a key that is not 32 bytes of base64url", async () => {
  const wasm = await loadWasm();
  assert.throws(() => wasm.is_small_order_x25519_public_key("AAAA"));
  assert.throws(() => wasm.is_small_order_x25519_public_key("not base64url!"));
});

test("after a small-order refusal, the same WASM instance still encrypts to a valid recipient", async () => {
  const wasm = await loadWasm();
  const [zero] = loadVector().small_order;
  const seed = Buffer.alloc(32, 0x5a).toString("base64url");
  const valid = { device_id: "dev-valid", public_key_b64: wasm.x25519_public_key(seed) };

  // A small-order key anywhere in the recipient list refuses the whole encryption, naming it.
  assert.throws(
    () => encryptTo(wasm, [valid, { device_id: "dev-evil", public_key_b64: zero.b64url }]),
    /recipient device 'dev-evil' has a small-order X25519 public key/,
  );

  // The instance is not poisoned: the next call succeeds and round-trips.
  const jwe = encryptTo(wasm, [valid]);
  assert.deepEqual(JSON.parse(wasm.decrypt_context(jwe, "dev-valid", seed)), CONTEXT);
});
