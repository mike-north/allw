/**
 * Tests for `initWasm`'s memoization (`src/wasm.ts`).
 *
 * The generated `--target web` glue guards only against an init that has already finished
 * (`if (wasm !== undefined) return wasm;`), so overlapping `default()` calls would each instantiate
 * the module and the second would replace the exports that handles from the first still use. The
 * boot path can start a core load for the ignored-relay notice (#307) while the inbox starts its
 * own, so `initWasm` must share one init between overlapping callers.
 *
 * These use a fake glue that has the FFI subset `assertGlueShape` checks and counts its
 * `default()` calls; the real artifact's browser path is covered by `site-build.test.mjs`.
 *
 * @see https://rustwasm.github.io/docs/wasm-bindgen/reference/deployment.html#without-a-bundler
 */
import assert from "node:assert/strict";
import { beforeEach, describe, test } from "node:test";

import { initWasm, initWasmSync, resetWasmForTests } from "../dist/index.js";

/** The FFI functions `assertGlueShape` requires, as no-ops. */
const FFI = Object.fromEntries(
  [
    "decrypt_context",
    "compute_request_hash",
    "derive_number_match_challenge",
    "verify_actor_attestation",
    "verify_account_state",
    "sign_verdict",
    "ed25519_public_key",
    "x25519_public_key",
  ].map((name) => [name, () => undefined]),
);

/** A fake glue whose `default()` waits for `finish()` and records each call. */
function deferredGlue() {
  const calls = [];
  let finishers = [];
  const glue = {
    ...FFI,
    initSync() {},
    default(source) {
      calls.push(source);
      return new Promise((resolve, reject) => {
        finishers.push({ resolve, reject });
      });
    },
  };
  return {
    glue,
    calls,
    finish() {
      for (const f of finishers) f.resolve({});
      finishers = [];
    },
    fail(error) {
      for (const f of finishers) f.reject(error);
      finishers = [];
    },
  };
}

describe("initWasm — one init for overlapping callers", () => {
  beforeEach(() => {
    resetWasmForTests();
  });

  test("a call made while the first is still instantiating shares it", async () => {
    const fake = deferredGlue();
    const first = initWasm(fake.glue, "core.wasm");
    const second = initWasm(fake.glue, "core.wasm");
    await Promise.resolve();
    fake.finish();
    const [a, b] = await Promise.all([first, second]);
    assert.equal(fake.calls.length, 1, "the module is instantiated once");
    assert.equal(a, fake.glue);
    assert.equal(b, fake.glue);
  });

  test("a call after the init finished reuses it", async () => {
    const fake = deferredGlue();
    const first = initWasm(fake.glue, "core.wasm");
    await Promise.resolve();
    fake.finish();
    await first;
    assert.equal(await initWasm(fake.glue, "core.wasm"), fake.glue);
    assert.equal(fake.calls.length, 1);
  });

  test("a failed init rejects every waiting caller and is retried by the next call", async () => {
    const fake = deferredGlue();
    const first = initWasm(fake.glue, "core.wasm");
    const second = initWasm(fake.glue, "core.wasm");
    await Promise.resolve();
    fake.fail(new Error("fetch failed"));
    await assert.rejects(first, /fetch failed/);
    await assert.rejects(second, /fetch failed/);

    const retry = initWasm(fake.glue, "core.wasm");
    await Promise.resolve();
    fake.finish();
    assert.equal(await retry, fake.glue);
    assert.equal(fake.calls.length, 2, "the failure was not memoized");
  });

  test("initWasmSync refuses to instantiate while an initWasm is in flight", async () => {
    const fake = deferredGlue();
    let syncInits = 0;
    const syncGlue = {
      ...FFI,
      default: async () => ({}),
      initSync() {
        syncInits += 1;
      },
    };
    const pending = initWasm(fake.glue, "core.wasm");
    assert.throws(() => initWasmSync(syncGlue, {}), /an async initWasm is in flight/);
    assert.equal(syncInits, 0, "nothing was instantiated a second time");

    await Promise.resolve();
    fake.finish();
    await pending;
    assert.equal(
      initWasmSync(syncGlue, {}),
      fake.glue,
      "once it finishes, the sync call reuses it",
    );
    assert.equal(syncInits, 0);
  });

  test("a glue missing the FFI subset is rejected, and not memoized", async () => {
    const { decrypt_context: _omitted, ...incomplete } = FFI;
    await assert.rejects(
      initWasm({ ...incomplete, default: async () => ({}), initSync() {} }, "core.wasm"),
      /missing 'decrypt_context'/,
    );
    const fake = deferredGlue();
    const later = initWasm(fake.glue, "core.wasm");
    await Promise.resolve();
    fake.finish();
    assert.equal(await later, fake.glue);
  });
});
