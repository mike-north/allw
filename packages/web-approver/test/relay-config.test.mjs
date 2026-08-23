/**
 * Tests for runtime relay-URL configuration (issue #180).
 *
 * Covers the acceptance criterion that the relay URL is resolved at runtime — never baked into
 * the bundle at build time — from, in priority order: a `?relay=` query parameter, a persisted
 * storage value, or (when neither is present) the small config-UI fallback
 * ({@link mountRelayConfigGate}).
 *
 * @see ../src/relay-config.ts
 * @see ../src/app.ts (the production bootstrap that calls these before mounting the pairing gate)
 */

import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { JSDOM } from "jsdom";

import {
  RELAY_URL_QUERY_PARAM,
  RELAY_URL_STORAGE_KEY,
  mountRelayConfigGate,
  resolveRelayUrl,
} from "../dist/index.js";

/** A fake in-memory `Storage` — avoids depending on `localStorage` in the Node test runner. */
function memoryStorage() {
  const map = new Map();
  return {
    getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    setItem(key, value) {
      map.set(key, String(value));
    },
    removeItem(key) {
      map.delete(key);
    },
    clear() {
      map.clear();
    },
    get length() {
      return map.size;
    },
    key(index) {
      return Array.from(map.keys())[index] ?? null;
    },
  };
}

// ── resolveRelayUrl ──────────────────────────────────────────────────────────────────────────────

describe("resolveRelayUrl", () => {
  test("returns null when neither a query param nor a stored value is present", () => {
    const storage = memoryStorage();
    assert.equal(resolveRelayUrl({ search: "", storage }), null);
  });

  test("resolves and persists a valid ?relay= query value", () => {
    const storage = memoryStorage();
    const search = `?${RELAY_URL_QUERY_PARAM}=${encodeURIComponent("https://relay.example.com")}`;
    assert.equal(resolveRelayUrl({ search, storage }), "https://relay.example.com");
    assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), "https://relay.example.com");
  });

  test("strips a trailing slash from the query value before persisting/returning", () => {
    const storage = memoryStorage();
    const search = `?${RELAY_URL_QUERY_PARAM}=${encodeURIComponent("https://relay.example.com/")}`;
    assert.equal(resolveRelayUrl({ search, storage }), "https://relay.example.com");
  });

  test("falls back to a previously-stored value when the query param is absent", () => {
    const storage = memoryStorage();
    storage.setItem(RELAY_URL_STORAGE_KEY, "https://relay.stored.example.com");
    assert.equal(resolveRelayUrl({ search: "", storage }), "https://relay.stored.example.com");
  });

  test("a malformed query value (not an absolute URL) falls through to the stored value, never returned as-is", () => {
    const storage = memoryStorage();
    storage.setItem(RELAY_URL_STORAGE_KEY, "https://relay.stored.example.com");
    const search = `?${RELAY_URL_QUERY_PARAM}=not-a-url`;
    assert.equal(resolveRelayUrl({ search, storage }), "https://relay.stored.example.com");
    // The malformed value must not have overwritten the previously-stored good value.
    assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), "https://relay.stored.example.com");
  });

  test("a non-http(s) scheme (e.g. javascript:) is rejected — fail-closed, never resolved", () => {
    const storage = memoryStorage();
    const search = `?${RELAY_URL_QUERY_PARAM}=${encodeURIComponent("javascript:alert(1)")}`;
    assert.equal(resolveRelayUrl({ search, storage }), null);
    assert.equal(
      storage.getItem(RELAY_URL_STORAGE_KEY),
      null,
      "must not persist a rejected scheme",
    );
  });

  test("an empty stored value is treated as absent (returns null), not passed through", () => {
    const storage = memoryStorage();
    storage.setItem(RELAY_URL_STORAGE_KEY, "   ");
    assert.equal(resolveRelayUrl({ search: "", storage }), null);
  });
});

// ── mountRelayConfigGate ─────────────────────────────────────────────────────────────────────────

/**
 * Install a fresh jsdom and the globals `relay-config.ts` reads (`document`). Returns the root
 * element and a `restore()` to revert the globals.
 */
function installDom() {
  const dom = new JSDOM('<div id="app"></div>', { url: "https://approver.local/" });
  const root = dom.window.document.getElementById("app");
  const saved = { document: globalThis.document };
  globalThis.document = dom.window.document;
  return {
    root,
    restore() {
      globalThis.document = saved.document;
    },
  };
}

describe("mountRelayConfigGate", () => {
  test("renders a form and does not call onConfigured before submission", () => {
    const { root, restore } = installDom();
    try {
      let called = false;
      mountRelayConfigGate({ root, storage: memoryStorage(), onConfigured: () => (called = true) });
      assert.ok(root.querySelector("form.relay-config-form"), "config form must be rendered");
      assert.equal(called, false);
    } finally {
      restore();
    }
  });

  test("submitting a valid relay URL persists it and calls onConfigured", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const configured = [];
      mountRelayConfigGate({ root, storage, onConfigured: (url) => configured.push(url) });

      const input = root.querySelector('input[name="relayUrl"]');
      input.value = "https://relay.example.com";
      const form = root.querySelector("form.relay-config-form");
      form.dispatchEvent(
        new globalThis.document.defaultView.Event("submit", { bubbles: true, cancelable: true }),
      );

      assert.deepEqual(configured, ["https://relay.example.com"]);
      assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), "https://relay.example.com");
    } finally {
      restore();
    }
  });

  test("submitting an invalid relay URL shows an inline error and does NOT call onConfigured (fail-closed)", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const configured = [];
      mountRelayConfigGate({ root, storage, onConfigured: (url) => configured.push(url) });

      const input = root.querySelector('input[name="relayUrl"]');
      input.value = "not a url";
      const form = root.querySelector("form.relay-config-form");
      form.dispatchEvent(
        new globalThis.document.defaultView.Event("submit", { bubbles: true, cancelable: true }),
      );

      assert.equal(configured.length, 0, "onConfigured must not fire for invalid input");
      assert.ok(root.querySelector(".relay-config-error-banner"), "an inline error must be shown");
      assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), null, "must not persist invalid input");
    } finally {
      restore();
    }
  });
});
