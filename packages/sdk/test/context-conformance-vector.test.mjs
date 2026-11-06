/**
 * Rust/WASM parity for removed fields following the existing ignore-unknown contract.
 * @see ../../../docs/contract.md §Unknown fields and optional assertions
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

/** Loads the `--target web` wasm module synchronously from on-disk bytes (node-friendly). */
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
      "context_conformance_vector.json",
    ),
    "utf8",
  );
  return JSON.parse(raw);
}

/** A copy of `base` with each `dotted.path → value` of `set` written in. */
function patched(base, set) {
  const context = structuredClone(base);
  for (const [path, value] of Object.entries(set)) {
    const keys = path.split(".");
    const last = keys.pop();
    let target = context;
    for (const key of keys) target = target[key];
    target[last] = value;
  }
  return context;
}

test("decrypt_context accepts or refuses every case in the shared vector", async () => {
  const wasm = await loadWasm();
  const vector = loadVector();
  assert.ok(vector.cases.length >= 10);
  const recipients = JSON.stringify([
    {
      device_id: vector.device_id,
      public_key_b64: wasm.x25519_public_key(vector.device_x25519_seed_b64),
    },
  ]);

  for (const c of vector.cases) {
    assert.equal(c.expected, "accepted", c.class);
    const context = patched(vector.base_context, c.set);
    const jwe = wasm.encrypt_context(JSON.stringify(context), recipients);
    const open = () =>
      JSON.parse(wasm.decrypt_context(jwe, vector.device_id, vector.device_x25519_seed_b64));

    const opened = open();
    assert.equal(opened.risk, undefined, c.class);
    assert.equal(opened.action.risk, undefined, c.class);
    assert.equal(opened.action.capabilities, undefined, c.class);
    assert.equal(opened.action.scope, undefined, c.class);
  }
});
