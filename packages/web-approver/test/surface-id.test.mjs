/**
 * Tests for {@link resolveSurfaceId} / {@link createLocalSurfaceIdStore} — the persisted
 * per-install `surface_id` (issue #150; `docs/relay-api.md` §3, §7.4).
 *
 * @see ../src/surface-id.ts
 * @see ../../../docs/relay-api.md §3 (`connect?surface_id=…` shape contract), §7.4 (client FAQ)
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  SURFACE_ID_STORAGE_KEY,
  createLocalSurfaceIdStore,
  resolveSurfaceId,
} from "../dist/surface-id.js";

/** A minimal in-memory `Storage`-shaped fake (mirrors the pattern in sequence-floor tests). */
function fakeStorage(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => {
      map.set(key, String(value));
    },
    removeItem: (key) => {
      map.delete(key);
    },
    _map: map,
  };
}

test("resolveSurfaceId mints and persists a fresh id when none is stored", () => {
  const storage = fakeStorage();
  const store = createLocalSurfaceIdStore(storage);

  const id = resolveSurfaceId(store, () => "generated-uuid-1");

  assert.equal(id, "generated-uuid-1");
  assert.equal(storage.getItem(SURFACE_ID_STORAGE_KEY), "generated-uuid-1");
});

test("resolveSurfaceId returns the persisted id on a later call — stable across reloads", () => {
  const storage = fakeStorage();
  const store = createLocalSurfaceIdStore(storage);

  const first = resolveSurfaceId(store, () => "generated-uuid-1");
  // A fresh store instance over the SAME storage (simulates a page reload).
  const secondStore = createLocalSurfaceIdStore(storage);
  const second = resolveSurfaceId(secondStore, () => "generated-uuid-2-should-not-be-used");

  assert.equal(second, first, "the surface id must not rotate across reloads (defeats dedupe)");
});

test("a corrupt/foreign stored value is discarded and replaced (never sent to the relay as-is)", () => {
  // The relay's surface_id shape contract (docs/relay-api.md §3) is 1-128 [A-Za-z0-9._:-] chars;
  // a space is outside that alphabet and would be rejected by the relay's WS upgrade with 400.
  const storage = fakeStorage({ [SURFACE_ID_STORAGE_KEY]: "not a valid surface id!" });
  const store = createLocalSurfaceIdStore(storage);

  const id = resolveSurfaceId(store, () => "replacement-uuid");

  assert.equal(id, "replacement-uuid");
  assert.equal(storage.getItem(SURFACE_ID_STORAGE_KEY), "replacement-uuid");
});

test("an empty stored value is treated as absent and replaced", () => {
  const storage = fakeStorage({ [SURFACE_ID_STORAGE_KEY]: "" });
  const store = createLocalSurfaceIdStore(storage);

  const id = resolveSurfaceId(store, () => "replacement-uuid");

  assert.equal(id, "replacement-uuid");
});

test("createLocalSurfaceIdStore.load() returns null when the storage read throws", () => {
  const store = createLocalSurfaceIdStore({
    getItem: () => {
      throw new Error("SecurityError: storage disabled in this context");
    },
    setItem: () => {},
  });

  assert.equal(store.load(), null);
});

test("createLocalSurfaceIdStore.save() swallows a storage write failure without throwing", () => {
  const store = createLocalSurfaceIdStore({
    getItem: () => null,
    setItem: () => {
      throw new Error("QuotaExceededError");
    },
  });

  assert.doesNotThrow(() => {
    store.save("some-id");
  });
});

test("resolveSurfaceId defaults to crypto.randomUUID() when no generator is injected", () => {
  const storage = fakeStorage();
  const store = createLocalSurfaceIdStore(storage);

  const id = resolveSurfaceId(store);

  // A real UUIDv4 — just assert the shape, not a specific value (non-deterministic by design).
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
});
