/**
 * WASM half of the shared v1 device-side context-check vector (#296).
 *
 * `crates/allw-core/tests/fixtures/context_conformance_vector.json` is asserted by the Rust core
 * (`crates/allw-core/tests/context_conformance_vector.rs`) and, here, through the compiled `.wasm`.
 * Each case is sealed with `encrypt_context` and opened with `decrypt_context`, the call both
 * approvers make. That shows a context with non-null reserved fields, or a hidden risk downgrade,
 * can't be opened on a device. Expected values are hand-written from `docs/contract.md`
 * §Device-side context checks.
 *
 * @see ../../../docs/contract.md
 * @see ../../../crates/allw-core/tests/fixtures/context_conformance_vector.json
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
    const context = patched(vector.base_context, c.set);
    const jwe = wasm.encrypt_context(JSON.stringify(context), recipients);
    const open = () =>
      JSON.parse(wasm.decrypt_context(jwe, vector.device_id, vector.device_x25519_seed_b64));

    if (c.expected === "accepted") {
      const opened = open();
      assert.equal(opened.risk, context.risk, c.class);
      assert.equal(opened.action.risk, context.action.risk, c.class);
      assert.equal(opened.action.capabilities, undefined, c.class);
      assert.equal(opened.action.scope, undefined, c.class);
    } else {
      assert.equal(c.expected, "refused", c.class);
      assert.equal(typeof c.expected_error, "string", c.class);
      assert.throws(
        open,
        (err) => {
          assert.ok(err instanceof Error, c.class);
          assert.ok(
            err.message.includes(c.expected_error),
            `${c.class}: ${JSON.stringify(err.message)} should name ${JSON.stringify(c.expected_error)}`,
          );
          return true;
        },
        c.class,
      );
    }
  }
});
