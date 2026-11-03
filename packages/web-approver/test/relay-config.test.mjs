/**
 * Tests for runtime relay-URL configuration (issues #180, #249).
 *
 * Covers the acceptance criterion that the relay URL is resolved at runtime — never baked into
 * the bundle at build time — from, in priority order: a `?relay=` query parameter, a persisted
 * storage value, or (when neither is present) the small config-UI fallback
 * ({@link mountRelayConfigGate}); and #249's transport rule (https, or http only on loopback —
 * one negative test per rejection branch) plus the ignored-override notice for a paired device.
 *
 * @see https://github.com/mike-north/allw/issues/249
 * @see ../../../docs/web-approver-deploy.md (§Runtime relay configuration, §Relay pinning)
 * @see ../src/relay-config.ts
 * @see ../src/app.ts (the production bootstrap that calls these before mounting the pairing gate)
 */

import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { JSDOM } from "jsdom";

import {
  INSECURE_RELAY_URL_REASON,
  RELAY_URL_QUERY_PARAM,
  RELAY_URL_STORAGE_KEY,
  checkRelayUrl,
  describeIgnoredRelayOverride,
  mountIgnoredRelayNotice,
  mountRelayConfigGate,
  resolveRelayUrl,
} from "../dist/index.js";

/** A `location.search` string carrying `?relay=<value>`. */
function relayQuery(value) {
  return `?${RELAY_URL_QUERY_PARAM}=${encodeURIComponent(value)}`;
}

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

// ── checkRelayUrl (#249 transport rule) ─────────────────────────────────────────────────────────

describe("checkRelayUrl", () => {
  test("accepts an https:// relay and strips trailing slashes", () => {
    assert.deepEqual(checkRelayUrl(" https://relay.example.com/ "), {
      ok: true,
      relayUrl: "https://relay.example.com",
    });
  });

  for (const loopback of ["http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"]) {
    test(`accepts plaintext http:// on loopback (${loopback})`, () => {
      assert.deepEqual(checkRelayUrl(loopback), { ok: true, relayUrl: loopback });
    });
  }

  test("rejects plaintext http:// to a remote host (http://relay.example.com) with an actionable reason", () => {
    const checked = checkRelayUrl("http://relay.example.com");
    assert.equal(checked.ok, false);
    assert.equal(checked.reason, INSECURE_RELAY_URL_REASON);
    assert.match(checked.reason, /https:\/\//);
    assert.match(checked.reason, /localhost, 127\.0\.0\.1, or \[::1\]/);
  });

  test("rejects http:// to a host that merely starts with 'localhost'", () => {
    const checked = checkRelayUrl("http://localhost.evil.example");
    assert.equal(checked.ok, false);
    assert.equal(checked.reason, INSECURE_RELAY_URL_REASON);
  });

  test("rejects a non-http(s) scheme (javascript:)", () => {
    const checked = checkRelayUrl("javascript:alert(1)");
    assert.equal(checked.ok, false);
    assert.equal(checked.reason, INSECURE_RELAY_URL_REASON);
  });

  test("rejects a value that is not an absolute URL", () => {
    const checked = checkRelayUrl("relay.example.com");
    assert.equal(checked.ok, false);
    assert.match(checked.reason, /valid relay URL/);
  });

  test("rejects an empty value", () => {
    const checked = checkRelayUrl("   ");
    assert.equal(checked.ok, false);
    assert.match(checked.reason, /Enter a relay URL/);
  });
});

// ── resolveRelayUrl (pre-pairing candidate) ─────────────────────────────────────────────────────

describe("resolveRelayUrl", () => {
  test("returns no relay when neither a query param nor a stored value is present", () => {
    const storage = memoryStorage();
    assert.deepEqual(resolveRelayUrl({ search: "", storage }), {
      relayUrl: null,
      rejectedQueryReason: null,
    });
  });

  test("resolves and persists a valid ?relay= query value", () => {
    const storage = memoryStorage();
    const search = relayQuery("https://relay.example.com");
    assert.deepEqual(resolveRelayUrl({ search, storage }), {
      relayUrl: "https://relay.example.com",
      rejectedQueryReason: null,
    });
    assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), "https://relay.example.com");
  });

  test("strips a trailing slash from the query value before persisting/returning", () => {
    const storage = memoryStorage();
    const search = relayQuery("https://relay.example.com/");
    assert.equal(resolveRelayUrl({ search, storage }).relayUrl, "https://relay.example.com");
  });

  test("falls back to a previously-stored value when the query param is absent", () => {
    const storage = memoryStorage();
    storage.setItem(RELAY_URL_STORAGE_KEY, "https://relay.stored.example.com");
    assert.equal(
      resolveRelayUrl({ search: "", storage }).relayUrl,
      "https://relay.stored.example.com",
    );
  });

  test("a malformed query value falls through to the stored value and reports why it was rejected", () => {
    const storage = memoryStorage();
    storage.setItem(RELAY_URL_STORAGE_KEY, "https://relay.stored.example.com");
    const resolution = resolveRelayUrl({ search: `?${RELAY_URL_QUERY_PARAM}=not-a-url`, storage });
    assert.equal(resolution.relayUrl, "https://relay.stored.example.com");
    assert.match(resolution.rejectedQueryReason, /valid relay URL/);
    // The malformed value must not have overwritten the previously-stored good value.
    assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), "https://relay.stored.example.com");
  });

  test("a non-http(s) scheme (e.g. javascript:) is rejected — fail-closed, never resolved", () => {
    const storage = memoryStorage();
    const resolution = resolveRelayUrl({ search: relayQuery("javascript:alert(1)"), storage });
    assert.equal(resolution.relayUrl, null);
    assert.equal(resolution.rejectedQueryReason, INSECURE_RELAY_URL_REASON);
    assert.equal(
      storage.getItem(RELAY_URL_STORAGE_KEY),
      null,
      "must not persist a rejected scheme",
    );
  });

  test("a plaintext http:// ?relay= to a remote host is rejected, not persisted, with the reason (#249)", () => {
    const storage = memoryStorage();
    const resolution = resolveRelayUrl({ search: relayQuery("http://relay.example.com"), storage });
    assert.equal(resolution.relayUrl, null);
    assert.equal(resolution.rejectedQueryReason, INSECURE_RELAY_URL_REASON);
    assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), null);
  });

  test("a stored plaintext http:// remote relay (written before #249) is rejected on read", () => {
    const storage = memoryStorage();
    storage.setItem(RELAY_URL_STORAGE_KEY, "http://relay.example.com");
    assert.equal(resolveRelayUrl({ search: "", storage }).relayUrl, null);
  });

  test("an empty stored value is treated as absent, not passed through", () => {
    const storage = memoryStorage();
    storage.setItem(RELAY_URL_STORAGE_KEY, "   ");
    assert.equal(resolveRelayUrl({ search: "", storage }).relayUrl, null);
  });
});

// ── describeIgnoredRelayOverride (paired device) ────────────────────────────────────────────────

describe("describeIgnoredRelayOverride", () => {
  const PINNED = "https://relay.example.com";

  test("no ?relay= → nothing ignored", () => {
    assert.equal(describeIgnoredRelayOverride("", PINNED), null);
  });

  test("a ?relay= equal to the pinned relay (modulo trailing slash) → nothing ignored", () => {
    assert.equal(describeIgnoredRelayOverride(relayQuery(`${PINNED}/`), PINNED), null);
  });

  test("a ?relay= to another origin names that origin", () => {
    assert.equal(
      describeIgnoredRelayOverride(relayQuery("https://evil.example/steal?x=1"), PINNED),
      "https://evil.example",
    );
  });

  test("an insecure ?relay= is still reported as ignored, by origin", () => {
    assert.equal(
      describeIgnoredRelayOverride(relayQuery("http://evil.example"), PINNED),
      "http://evil.example",
    );
  });

  test("an unparseable ?relay= is echoed back (truncated), never resolved", () => {
    const ignored = describeIgnoredRelayOverride(relayQuery("x".repeat(500)), PINNED);
    assert.equal(ignored, `${"x".repeat(120)}…`);
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

  test("submitting http://relay.example.com is rejected with the https-only reason (#249)", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const configured = [];
      mountRelayConfigGate({ root, storage, onConfigured: (url) => configured.push(url) });

      root.querySelector('input[name="relayUrl"]').value = "http://relay.example.com";
      root
        .querySelector("form.relay-config-form")
        .dispatchEvent(
          new globalThis.document.defaultView.Event("submit", { bubbles: true, cancelable: true }),
        );

      assert.equal(configured.length, 0, "onConfigured must not fire for an insecure relay");
      assert.equal(
        root.querySelector(".relay-config-error-banner").textContent,
        INSECURE_RELAY_URL_REASON,
      );
      assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), null);
    } finally {
      restore();
    }
  });

  test("initialError (a rejected ?relay= link) is shown on first render", () => {
    const { root, restore } = installDom();
    try {
      mountRelayConfigGate({
        root,
        storage: memoryStorage(),
        onConfigured: () => undefined,
        initialError: INSECURE_RELAY_URL_REASON,
      });
      assert.equal(
        root.querySelector(".relay-config-error-banner").textContent,
        INSECURE_RELAY_URL_REASON,
      );
    } finally {
      restore();
    }
  });
});

// ── mountIgnoredRelayNotice ──────────────────────────────────────────────────────────────────────

describe("mountIgnoredRelayNotice", () => {
  test("names the ignored origin and the pinned relay, as text (never parsed as markup)", () => {
    const { root, restore } = installDom();
    try {
      mountIgnoredRelayNotice({
        host: root,
        ignored: "<img src=x onerror=alert(1)>",
        pinnedRelayUrl: "https://relay.example.com/base",
      });
      const notice = root.querySelector(".relay-pin-notice");
      assert.ok(notice, "notice must render");
      assert.equal(notice.getAttribute("role"), "status");
      assert.match(notice.textContent, /paired with https:\/\/relay\.example\.com /);
      assert.equal(
        notice.querySelector(".relay-pin-notice-origin").textContent,
        "<img src=x onerror=alert(1)>",
      );
      assert.equal(root.querySelector("img"), null, "ignored text must not become markup");
    } finally {
      restore();
    }
  });
});
