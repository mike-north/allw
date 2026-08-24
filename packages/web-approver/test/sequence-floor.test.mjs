/**
 * Unit tests for {@link createLocalAccountStateFloorStore} / {@link createInMemoryAccountStateFloorStore}
 * — the device-side account-state rollback floor persistence (#171, the web analogue of #115's
 * approver-keyfile floor). These exercise the STORE in isolation; `test/account-state-sequence-floor.test.mjs`
 * exercises the full gate through `createWasmRuntime.prepare` against the real WASM core.
 *
 * Covers the security-relevant negative paths called out in #171:
 *   - the floor persists across separate store instances backed by the same underlying storage
 *     (simulating a page reload);
 *   - the floor is monotonic — `save()` with a lower-or-equal sequence is always a no-op, in any order;
 *   - storage absence (never written) and storage tampering (a corrupt raw value) both fail closed to
 *     `0` rather than throwing or crashing — never a stale/negative floor.
 *
 * @see ../src/sequence-floor.ts (the unit under test)
 * @see ../../../docs/enrollment.md §Account State
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ACCOUNT_STATE_FLOOR_STORAGE_KEY,
  createInMemoryAccountStateFloorStore,
  createLocalAccountStateFloorStore,
} from "../dist/sequence-floor.js";

/**
 * A fake in-memory `Storage` implementation, mirroring `pairing.test.mjs`'s `memoryStorage()`.
 * Avoids depending on `localStorage` (not available in the Node test runner).
 */
function memoryStorage() {
  const map = new Map();
  return {
    getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    setItem(key, value) {
      map.set(key, value);
    },
    removeItem(key) {
      map.delete(key);
    },
    get size() {
      return map.size;
    },
  };
}

// ── Absence: no floor recorded yet ────────────────────────────────────────────────────────────

test("absent storage: load() returns 0 (no floor recorded yet, not a crash)", () => {
  const store = createLocalAccountStateFloorStore(memoryStorage());
  assert.equal(store.load(), 0);
});

// ── Persists a new higher sequence ────────────────────────────────────────────────────────────

test("save() persists a positive sequence; load() reflects it", () => {
  const store = createLocalAccountStateFloorStore(memoryStorage());
  store.save(3);
  assert.equal(store.load(), 3);
});

test("save() ignores non-positive or non-integer sequences", () => {
  const store = createLocalAccountStateFloorStore(memoryStorage());
  store.save(0);
  assert.equal(store.load(), 0, "0 must never be persisted as a floor");
  store.save(-5);
  assert.equal(store.load(), 0, "a negative sequence must never be persisted");
  store.save(1.5);
  assert.equal(store.load(), 0, "a non-integer sequence must never be persisted");
});

// ── Floor persisted across reloads (separate store instances, same backing storage) ──────────

test("floor persisted across reloads: a fresh store instance over the same storage sees the prior floor", () => {
  const storage = memoryStorage();

  // "First session": pair, observe sequence 4, persist it.
  const sessionOne = createLocalAccountStateFloorStore(storage);
  sessionOne.save(4);

  // "Page reload": a brand-new store instance is constructed, but the underlying storage survived.
  const sessionTwo = createLocalAccountStateFloorStore(storage);
  assert.equal(sessionTwo.load(), 4, "the floor must survive across store instances (a reload)");
});

// ── Monotonic: never lowered, regardless of call order ────────────────────────────────────────

test("monotonic: save() with a lower sequence after a higher one is a no-op", () => {
  const store = createLocalAccountStateFloorStore(memoryStorage());
  store.save(5);
  store.save(3);
  assert.equal(store.load(), 5, "the floor must never move down");
});

test("monotonic: save() with an equal sequence is a no-op (still just 'not raised')", () => {
  const store = createLocalAccountStateFloorStore(memoryStorage());
  store.save(5);
  store.save(5);
  assert.equal(store.load(), 5);
});

test("monotonic: out-of-order saves settle on the highest value seen", () => {
  const store = createLocalAccountStateFloorStore(memoryStorage());
  for (const sequence of [2, 7, 1, 4, 7, 3]) {
    store.save(sequence);
  }
  assert.equal(store.load(), 7, "the floor settles on the maximum ever observed, in any order");
});

test("in-memory store is independently monotonic (no persistence dependency)", () => {
  const store = createInMemoryAccountStateFloorStore();
  store.save(10);
  store.save(2);
  assert.equal(store.load(), 10);
  store.clear();
  assert.equal(store.load(), 0, "clear() is a test/reset-only escape hatch");
});

// ── Storage tampering: a corrupt raw value fails closed to 0, never throws ───────────────────

test("tampered storage: a non-numeric raw value fails closed to 0 rather than throwing", () => {
  const storage = memoryStorage();
  storage.setItem(ACCOUNT_STATE_FLOOR_STORAGE_KEY, "not-a-number");
  const store = createLocalAccountStateFloorStore(storage);
  assert.doesNotThrow(() => store.load());
  assert.equal(store.load(), 0, "corrupt storage must never crash or resurrect a stale floor");
});

test("tampered storage: a negative raw value fails closed to 0", () => {
  const storage = memoryStorage();
  storage.setItem(ACCOUNT_STATE_FLOOR_STORAGE_KEY, "-7");
  const store = createLocalAccountStateFloorStore(storage);
  assert.equal(store.load(), 0);
});

test("tampered storage: a non-integer raw value fails closed to 0", () => {
  const storage = memoryStorage();
  storage.setItem(ACCOUNT_STATE_FLOOR_STORAGE_KEY, "3.7");
  const store = createLocalAccountStateFloorStore(storage);
  assert.equal(store.load(), 0);
});

test("storage read errors (e.g. security errors in private browsing) fail closed to 0, never throw", () => {
  const throwingStorage = {
    getItem() {
      throw new Error("SecurityError: storage access blocked");
    },
    setItem() {
      throw new Error("SecurityError: storage access blocked");
    },
    removeItem() {},
  };
  const store = createLocalAccountStateFloorStore(throwingStorage);
  assert.doesNotThrow(() => store.load());
  assert.equal(store.load(), 0);
  assert.doesNotThrow(() => store.save(5), "a blocked write must not crash approval rendering");
});

// ── clear() removes the persisted value ───────────────────────────────────────────────────────

test("clear() removes the persisted floor", () => {
  const storage = memoryStorage();
  const store = createLocalAccountStateFloorStore(storage);
  store.save(6);
  assert.equal(store.load(), 6);
  store.clear();
  assert.equal(store.load(), 0);
});
