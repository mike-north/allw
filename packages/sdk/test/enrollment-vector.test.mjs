/**
 * Shared Rust/WASM vector for root-holder enrollment authoring (#379, #381), through the compiled
 * `.wasm`.
 *
 * `crates/allw-core/tests/fixtures/enrollment_vector.json` is asserted on the Rust side by
 * `crates/allw-core/tests/enrollment_vector.rs`. Here the same cases go through the WASM exports
 * that `allw-approver pair` / `vouch` and the web approver call: `check_device_enrollment`,
 * `device_key_fingerprint` and `next_account_state`. Every refusal must **throw** with a message
 * naming the reason (fail-closed at the JS boundary); every success must compose exactly the
 * expected next state.
 *
 * @see ../../../docs/enrollment.md §Interim vouching
 * @see ../../../crates/allw-core/src/enrollment.rs
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

async function loadWasm() {
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  glue.initSync({
    module: new WebAssembly.Module(readFileSync(join(vendorDir, "allw_wasm_bg.wasm"))),
  });
  return glue;
}

const vector = JSON.parse(
  readFileSync(
    join(
      here,
      "..",
      "..",
      "..",
      "crates",
      "allw-core",
      "tests",
      "fixtures",
      "enrollment_vector.json",
    ),
    "utf8",
  ),
);

const ROOT_SEED = Buffer.alloc(32, 0x11).toString("base64url");
const OTHER_ROOT_SEED = Buffer.alloc(32, 0x33).toString("base64url");

test("device material: the WASM accepts and refuses exactly the vector's cases", async () => {
  const wasm = await loadWasm();
  for (const c of vector.material) {
    const run = () =>
      wasm.check_device_enrollment(c.device_id, c.encryption_pubkey, c.signing_pubkey);
    if (c.error === null) {
      assert.doesNotThrow(run, c.name);
    } else {
      assert.throws(run, (err) => err.message.includes(c.message_contains), c.name);
    }
  }
});

test("fingerprints: the WASM reproduces the independently computed values", async () => {
  const wasm = await loadWasm();
  for (const c of vector.fingerprints) {
    assert.equal(wasm.device_key_fingerprint(c.kind, c.key), c.fingerprint);
  }
  assert.throws(
    () => wasm.device_key_fingerprint("other", vector.fingerprints[0].key),
    /kind must be/,
  );
});

test("next_account_state: the WASM composes or refuses exactly the vector's cases", async () => {
  const wasm = await loadWasm();
  const rootPubkey = wasm.ed25519_public_key(ROOT_SEED);
  const accountId = wasm.account_id_for_root(rootPubkey);
  const keyOf = (name) => vector.keys[name];
  for (const c of vector.next_state) {
    const docs = c.states.map((s) =>
      wasm.sign_account_state(
        JSON.stringify({
          v: 1,
          account_id: accountId,
          sequence: s.sequence,
          current_root: rootPubkey,
          previous_roots: [],
          devices: s.devices.map((d) => ({
            device_id: d.id,
            encryption_pubkey: keyOf(d.key).encryption_pubkey,
            signing_pubkey: keyOf(d.key).signing_pubkey,
            status: d.status,
          })),
          actors: [],
          revocations: s.revocations.map((id) => ({
            kind: "device",
            id,
            revoked_at: 1700000000000,
          })),
        }),
        s.signed_by === "other" ? OTHER_ROOT_SEED : ROOT_SEED,
      ),
    );
    const run = () =>
      JSON.parse(
        wasm.next_account_state(
          JSON.stringify(docs),
          c.relay_max_sequence,
          c.floor,
          accountId,
          rootPubkey,
          JSON.stringify({
            kind: "add_device",
            device_id: c.add.id,
            encryption_pubkey: keyOf(c.add.key).encryption_pubkey,
            signing_pubkey: keyOf(c.add.key).signing_pubkey,
          }),
        ),
      );
    if (c.error === null) {
      const next = run();
      assert.equal(next.sequence, c.expect.sequence, c.name);
      assert.equal(next.account_id, accountId, c.name);
      assert.deepEqual(
        next.devices.map((d) => [d.device_id, d.encryption_pubkey, d.signing_pubkey, d.status]),
        c.expect.devices.map(([id, key, status]) => [
          id,
          keyOf(key).encryption_pubkey,
          keyOf(key).signing_pubkey,
          status,
        ]),
        c.name,
      );
    } else {
      assert.throws(run, (err) => err.message.includes(c.message_contains), c.name);
    }
  }
});

test("next_account_state refuses malformed JS input before composing", async () => {
  const wasm = await loadWasm();
  const rootPubkey = wasm.ed25519_public_key(ROOT_SEED);
  const accountId = wasm.account_id_for_root(rootPubkey);
  const a = vector.keys.a;
  const change = JSON.stringify({ kind: "add_device", device_id: "dev-a", ...a });
  for (const [args, message] of [
    [
      ["[]", -1, 0, accountId, rootPubkey, change],
      /relay_max_sequence must be a non-negative safe integer/,
    ],
    [["[]", 0, 1.5, accountId, rootPubkey, change], /floor must be a non-negative safe integer/],
    [
      ["[]", 0, 0, accountId, rootPubkey, JSON.stringify({ kind: "rotate_device" })],
      /invalid account-state change/,
    ],
    [
      [
        "[]",
        0,
        0,
        accountId,
        rootPubkey,
        JSON.stringify({ kind: "add_device", device_id: "dev-a", ...a, extra: 1 }),
      ],
      /invalid account-state change/,
    ],
    [
      [
        "[]",
        0,
        0,
        accountId,
        rootPubkey,
        JSON.stringify({ kind: "add_device", device_id: "dev a", ...a }),
      ],
      /invalid device material/,
    ],
  ]) {
    assert.throws(() => wasm.next_account_state(...args), message);
  }
});
