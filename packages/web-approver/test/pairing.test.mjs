/**
 * Tests for the login / pairing-ceremony gate (issue #148).
 *
 * Covers the three pre-inbox routes and the fail-closed invariant:
 *
 *   - **Returning device**: a valid stored identity → returning screen → `onPaired` fires on
 *     "Unlock inbox", passing the stored identity; the inbox is NOT rendered before unlock.
 *   - **New device / pairing ceremony**: no stored identity → pairing form → valid credentials
 *     submitted → `onPaired` fires, identity persisted; invalid credentials → error banner, no
 *     `onPaired` call (inbox never reached).
 *   - **Reset / other device**: "Use another device" on the returning screen clears the store
 *     and routes to the pairing form.
 *   - **Corrupt stored identity**: a stored value that cannot be parsed routes to pairing, not
 *     the returning screen — fail-closed on corrupted local state.
 *   - **`mountWebApprover` with `pairingStore`**: the full mount path; the inbox shell is absent
 *     until `onPaired` fires; once fired the inbox is rendered.
 *
 * All fixtures use fixed clock constants — never `Date.now()` in test data.
 *
 * @see ../src/pairing.ts
 * @see ../src/browser.ts (mountWebApprover pairingStore path)
 * @see design/web-approver/onboarding/flow-notes.md
 * @see docs/contract.md §Invariants #6 (fail-closed)
 * @see docs/enrollment.md §Pairing Flow
 */

import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { JSDOM } from "jsdom";

import {
  INSECURE_RELAY_URL_REASON,
  createLocalPairingStore,
  mountPairingGate,
} from "../dist/index.js";
// Internal to the package (a stopgap until the core display model lands, #246/#259).
import { visiblyEscape } from "../dist/pairing.js";
import { mountWebApprover } from "../dist/browser.js";

// ── Fixed clock (never Date.now() in test data) ───────────────────────────

const NOW = Date.parse("2026-06-12T16:00:00.000Z");
const SOON = NOW + 60_000;

// ── Fixture helpers ───────────────────────────────────────────────────────

/** `PairingStore.load()` results with no payload. */
const ABSENT = { status: "absent" };
const CORRUPT = { status: "corrupt" };

/** A minimal valid `ApproverIdentity` (fixed seeds, not real cryptographic material). */
const VALID_IDENTITY = {
  accountId: "acct-pairing-test",
  deviceId: "dev-pairing-test",
  deviceEncryptionSeed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  deviceSigningSeed: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
  deviceCert: "eyJhbGciOiJFZERTQSJ9.test.sig",
  accountRootPubkey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
  deviceAuthToken: "relay-bearer-test-token",
};

/**
 * A fake in-memory Storage implementation for PairingStore injection.
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

/**
 * A minimal runtime mock for mountWebApprover tests: prepare always resolves, signDecision
 * records calls. Not used for any real crypto.
 */
function fakeRuntime() {
  const signCalls = [];
  return {
    signCalls,
    async prepare(envelope) {
      return {
        expiresAt: envelope.expires_at,
        requestHash: `hash-${envelope.id}`,
        context: {
          kind: "command",
          command: { cwd: "/", argv: ["echo", "hi"], raw: "echo hi" },
          actor: { id: "test-actor", display: "Test Actor", attestation: "unverified" },
          risk: { level: "low", reversible: true, summary: "test" },
          allowed_decisions: ["approved", "denied"],
        },
      };
    },
    async signDecision(input) {
      signCalls.push(input);
      return {
        requestId: input.envelope.id,
        decision: input.decision,
        signedVerdictJson: JSON.stringify({
          request_id: input.envelope.id,
          decision: input.decision,
        }),
      };
    },
  };
}

/**
 * Install a fresh jsdom and the globals `browser.ts` / `pairing.ts` read (`document`, `window`,
 * `HTMLButtonElement`, `FormData`). Returns the root element and a `restore()` to revert globals.
 */
function installDom() {
  const dom = new JSDOM('<div id="app"></div>', { url: "https://approver.local/" });
  const root = dom.window.document.getElementById("app");
  const saved = {
    document: globalThis.document,
    window: globalThis.window,
    HTMLButtonElement: globalThis.HTMLButtonElement,
    FormData: globalThis.FormData,
  };
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  globalThis.HTMLButtonElement = dom.window.HTMLButtonElement;
  globalThis.FormData = dom.window.FormData;
  return {
    dom,
    root,
    restore() {
      globalThis.document = saved.document;
      globalThis.window = saved.window;
      globalThis.HTMLButtonElement = saved.HTMLButtonElement;
      globalThis.FormData = saved.FormData;
    },
  };
}

/**
 * Flush pending microtasks so async promise chains settle before assertions.
 */
async function flushMicrotasks(n = 30) {
  for (let i = 0; i < n; i++) {
    await Promise.resolve();
  }
}

/** Fill and submit the pairing form with the given field values. */
function submitPairingForm(root, fields) {
  for (const [name, value] of Object.entries(fields)) {
    const input = root.querySelector(`input[name="${name}"]`);
    if (input) {
      input.value = value;
      // Dispatch an 'input' event so any listeners are notified
      input.dispatchEvent(new globalThis.document.defaultView.Event("input"));
    }
  }
  const form = root.querySelector("form.pairing-form");
  assert.ok(form, "pairing form must be present");
  form.dispatchEvent(
    new globalThis.document.defaultView.Event("submit", { bubbles: true, cancelable: true }),
  );
}

// ── mountPairingGate: returning device path ───────────────────────────────

describe("mountPairingGate — returning device", () => {
  test("stored valid identity shows the returning screen and fires onPaired on unlock", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      storage.setItem("allw:pairing:v1", JSON.stringify(VALID_IDENTITY));
      const store = createLocalPairingStore(storage);

      const pairings = [];
      mountPairingGate({
        root,
        pairingStore: store,
        onPaired: (identity) => {
          pairings.push(identity);
        },
      });

      // Returning screen must be shown — not the pairing form.
      assert.ok(root.querySelector(".pairing-shell"), "pairing shell rendered");
      assert.ok(
        !root.querySelector("form.pairing-form"),
        "pairing form must NOT be shown for a returning device",
      );
      assert.equal(pairings.length, 0, "onPaired must not fire before the user clicks Unlock");

      // "Unlock inbox" button must be present.
      const unlockBtn = [...root.querySelectorAll("button")].find(
        (b) => b.textContent === "Unlock inbox",
      );
      assert.ok(unlockBtn, "Unlock inbox button must be rendered on the returning screen");

      unlockBtn.click();

      assert.equal(pairings.length, 1, "onPaired fires exactly once when Unlock is clicked");
      assert.deepEqual(
        pairings[0],
        VALID_IDENTITY,
        "onPaired receives the stored identity verbatim",
      );
    } finally {
      restore();
    }
  });

  test("stored identity is shown with device id and account id in the device ticket", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      storage.setItem("allw:pairing:v1", JSON.stringify(VALID_IDENTITY));
      const store = createLocalPairingStore(storage);

      mountPairingGate({ root, pairingStore: store, onPaired: () => undefined });

      const ticketText = root.querySelector(".pairing-device-ticket")?.textContent ?? "";
      assert.ok(
        ticketText.includes(VALID_IDENTITY.deviceId),
        "device ticket must show the device id",
      );
      assert.ok(
        ticketText.includes(VALID_IDENTITY.accountId),
        "device ticket must show the account id",
      );
    } finally {
      restore();
    }
  });

  test("'Use another device' clears the store and shows the pairing form", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      storage.setItem("allw:pairing:v1", JSON.stringify(VALID_IDENTITY));
      const store = createLocalPairingStore(storage);

      const pairings = [];
      mountPairingGate({
        root,
        pairingStore: store,
        onPaired: (id) => {
          pairings.push(id);
        },
      });

      const resetBtn = [...root.querySelectorAll("button")].find(
        (b) => b.textContent === "Use another device",
      );
      assert.ok(resetBtn, '"Use another device" button must be rendered on the returning screen');

      resetBtn.click();

      // After reset, the stored identity is cleared and the pairing form is shown.
      assert.deepEqual(store.load(), ABSENT, "store must be cleared after reset");
      assert.ok(root.querySelector("form.pairing-form"), "pairing form must be shown after reset");
      assert.equal(pairings.length, 0, "onPaired must NOT fire on reset");
    } finally {
      restore();
    }
  });

  test("corrupt stored identity routes to pairing (fail-closed on invalid local state)", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      // Deliberately corrupt: missing required fields
      storage.setItem("allw:pairing:v1", JSON.stringify({ accountId: "only-one-field" }));
      const store = createLocalPairingStore(storage);

      mountPairingGate({ root, pairingStore: store, onPaired: () => undefined });

      // Must show the pairing form, not the returning screen.
      assert.ok(
        root.querySelector("form.pairing-form"),
        "corrupt stored identity must route to pairing form (fail-closed)",
      );
      assert.ok(
        !root.querySelector(".pairing-device-ticket"),
        "returning screen must NOT be shown for corrupt stored identity",
      );
    } finally {
      restore();
    }
  });

  test("missing stored identity routes to pairing form", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const store = createLocalPairingStore(storage);

      mountPairingGate({ root, pairingStore: store, onPaired: () => undefined });

      assert.ok(
        root.querySelector("form.pairing-form"),
        "no stored identity must show the pairing form",
      );
    } finally {
      restore();
    }
  });
});

// ── mountPairingGate: pairing ceremony path ───────────────────────────────

describe("mountPairingGate — pairing ceremony", () => {
  test("valid credentials fire onPaired and persist the identity", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const store = createLocalPairingStore(storage);

      const pairings = [];
      mountPairingGate({
        root,
        pairingStore: store,
        onPaired: (id) => {
          pairings.push(id);
        },
      });

      assert.ok(root.querySelector("form.pairing-form"), "pairing form is shown initially");
      assert.equal(pairings.length, 0, "onPaired must not fire before form submission");

      submitPairingForm(root, VALID_IDENTITY);

      assert.equal(pairings.length, 1, "onPaired fires exactly once after valid submission");
      assert.deepEqual(pairings[0], VALID_IDENTITY, "onPaired receives the submitted identity");

      // The identity must be persisted so returning visits show the returning screen.
      const { status, identity: loaded } = store.load();
      assert.equal(status, "paired", "identity must be persisted after pairing");
      assert.equal(loaded.accountId, VALID_IDENTITY.accountId);
      assert.equal(loaded.deviceId, VALID_IDENTITY.deviceId);
    } finally {
      restore();
    }
  });

  test("missing required field shows an error banner and does NOT fire onPaired (fail-closed)", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const store = createLocalPairingStore(storage);

      const pairings = [];
      mountPairingGate({
        root,
        pairingStore: store,
        onPaired: (id) => {
          pairings.push(id);
        },
      });

      // Submit with all fields EXCEPT deviceId (a required field).
      const incompleteFields = { ...VALID_IDENTITY };
      delete incompleteFields.deviceId;
      submitPairingForm(root, incompleteFields);

      assert.equal(pairings.length, 0, "onPaired must NOT fire when required fields are missing");
      assert.ok(
        root.querySelector(".pairing-error-banner"),
        "an error banner must be shown for incomplete submission",
      );
      // The inbox must not be rendered — still on the pairing screen.
      assert.ok(
        root.querySelector("form.pairing-form"),
        "pairing form must remain visible after failed submission",
      );
      assert.ok(
        !root.querySelector(".approver-shell"),
        "inbox approver-shell must NOT be rendered when pairing fails",
      );
    } finally {
      restore();
    }
  });

  test("all fields empty shows an error banner and does NOT fire onPaired", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const store = createLocalPairingStore(storage);

      const pairings = [];
      mountPairingGate({
        root,
        pairingStore: store,
        onPaired: (id) => {
          pairings.push(id);
        },
      });

      // Submit with no field values at all.
      submitPairingForm(root, {});

      assert.equal(pairings.length, 0, "onPaired must NOT fire for an empty submission");
      assert.ok(
        root.querySelector(".pairing-error-banner"),
        "error banner must be shown for empty submission",
      );
    } finally {
      restore();
    }
  });

  test("error banner is shown with an accessible role='alert'", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const store = createLocalPairingStore(storage);

      mountPairingGate({ root, pairingStore: store, onPaired: () => undefined });
      submitPairingForm(root, {});

      const banner = root.querySelector(".pairing-error-banner");
      assert.ok(banner, "error banner must be present after failed submission");
      assert.equal(banner.getAttribute("role"), "alert", "error banner must have role='alert'");
    } finally {
      restore();
    }
  });
});

// ── mountWebApprover with pairingStore: inbox gating ─────────────────────

describe("mountWebApprover — pairingStore inbox gating", () => {
  test("inbox is NOT rendered before pairing is confirmed", async () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const store = createLocalPairingStore(storage);

      // Start the mount — no stored identity, so the pairing form shows.
      const mountPromise = mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: fakeRuntime(),
        fetchInbox: async () => [],
        pairingStore: store,
      });

      await flushMicrotasks();

      // The pairing form must be shown.
      assert.ok(
        root.querySelector("form.pairing-form"),
        "pairing form must be shown before credentials are submitted",
      );
      // The approve-capable inbox must NOT be shown.
      assert.ok(
        !root.querySelector(".approver-shell"),
        "inbox must NOT be rendered before pairing is confirmed (fail-closed)",
      );

      // Submit valid credentials to complete pairing.
      submitPairingForm(root, VALID_IDENTITY);
      await flushMicrotasks();

      // Now the inbox shell must be rendered.
      const mount = await mountPromise;
      assert.ok(mount.controller, "mountWebApprover resolves with a controller after pairing");
      assert.ok(
        root.querySelector(".approver-shell"),
        "inbox approver-shell is rendered after successful pairing",
      );
      mount.stop();
    } finally {
      restore();
    }
  });

  test("returning device: inbox shown after 'Unlock inbox' click (not before)", async () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      storage.setItem("allw:pairing:v1", JSON.stringify(VALID_IDENTITY));
      const store = createLocalPairingStore(storage);

      const mountPromise = mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: fakeRuntime(),
        fetchInbox: async () => [],
        pairingStore: store,
      });

      await flushMicrotasks();

      // Returning screen must be shown — inbox must not.
      assert.ok(
        root.querySelector(".pairing-shell"),
        "returning screen must be shown for a stored identity",
      );
      assert.ok(
        !root.querySelector(".approver-shell"),
        "inbox must NOT be rendered before 'Unlock inbox' is clicked",
      );

      const unlockBtn = [...root.querySelectorAll("button")].find(
        (b) => b.textContent === "Unlock inbox",
      );
      assert.ok(unlockBtn, "Unlock inbox button must be present");
      unlockBtn.click();

      await flushMicrotasks();

      const mount = await mountPromise;
      assert.ok(
        root.querySelector(".approver-shell"),
        "inbox is rendered after 'Unlock inbox' click",
      );
      mount.stop();
    } finally {
      restore();
    }
  });

  test("without pairingStore, mountWebApprover renders the inbox directly (no gate)", async () => {
    const { root, restore } = installDom();
    try {
      // No pairingStore provided — existing behavior preserved.
      const mount = await mountWebApprover({
        root,
        nowMs: () => NOW,
        runtime: fakeRuntime(),
        fetchInbox: async () => [],
        // pairingStore intentionally omitted
      });

      assert.ok(
        root.querySelector(".approver-shell"),
        "inbox is rendered immediately without a pairingStore",
      );
      assert.ok(
        !root.querySelector("form.pairing-form"),
        "pairing form must NOT appear without a pairingStore",
      );
      mount.stop();
    } finally {
      restore();
    }
  });
});

// ── createLocalPairingStore ───────────────────────────────────────────────

describe("createLocalPairingStore", () => {
  test("load reports absent when nothing is stored", () => {
    const store = createLocalPairingStore(memoryStorage());
    assert.deepEqual(store.load(), ABSENT);
  });

  test("save + load round-trips a valid identity", () => {
    const store = createLocalPairingStore(memoryStorage());
    store.save(VALID_IDENTITY);
    assert.deepEqual(store.load(), { status: "paired", identity: VALID_IDENTITY });
  });

  test("clear removes the stored identity", () => {
    const store = createLocalPairingStore(memoryStorage());
    store.save(VALID_IDENTITY);
    store.clear();
    assert.deepEqual(store.load(), ABSENT, "cleared store must report absent");
  });

  test("load reports corrupt for unparseable stored JSON", () => {
    const storage = memoryStorage();
    storage.setItem("allw:pairing:v1", "NOT-VALID-JSON{{{{");
    const store = createLocalPairingStore(storage);
    assert.deepEqual(store.load(), CORRUPT, "corrupt JSON must not load (fail-closed)");
  });

  test("load reports corrupt when the stored object is missing required fields", () => {
    const storage = memoryStorage();
    storage.setItem("allw:pairing:v1", JSON.stringify({ accountId: "only-one" }));
    const store = createLocalPairingStore(storage);
    assert.deepEqual(store.load(), CORRUPT, "partial identity must not load (fail-closed)");
  });

  test("load reports corrupt for a stored array (not an object)", () => {
    const storage = memoryStorage();
    storage.setItem("allw:pairing:v1", JSON.stringify([]));
    const store = createLocalPairingStore(storage);
    assert.deepEqual(store.load(), CORRUPT, "array value must not load (fail-closed)");
  });

  test("load reports corrupt for an identity with an empty-string field", () => {
    const storage = memoryStorage();
    const withEmptyField = { ...VALID_IDENTITY, deviceId: "" };
    storage.setItem("allw:pairing:v1", JSON.stringify(withEmptyField));
    const store = createLocalPairingStore(storage);
    assert.deepEqual(store.load(), CORRUPT, "identity with empty string field must not load");
  });
});

// ── Relay pinning in the stored identity (#249) ──────────────────────────

describe("createLocalPairingStore — pinned relay (#249)", () => {
  test("round-trips an identity pinned to an https relay", () => {
    const storage = memoryStorage();
    const store = createLocalPairingStore(storage);
    store.save({ ...VALID_IDENTITY, relayUrl: "https://relay.example.com" });
    assert.equal(store.load().identity.relayUrl, "https://relay.example.com");
  });

  test("a stored pin to a plaintext http:// remote relay is rejected, never loaded (fail-closed)", () => {
    const storage = memoryStorage();
    storage.setItem(
      "allw:pairing:v1",
      JSON.stringify({ ...VALID_IDENTITY, relayUrl: "http://relay.example.com" }),
    );
    const stored = storage.getItem("allw:pairing:v1");
    assert.deepEqual(createLocalPairingStore(storage).load(), {
      status: "relay-pin-rejected",
      pinnedRelayUrl: "http://relay.example.com",
      reason: INSECURE_RELAY_URL_REASON,
      snapshot: stored,
    });
  });

  test("a stored pin to http://[::1] (accepted by older builds) is rejected, never loaded (#286)", () => {
    const storage = memoryStorage();
    storage.setItem(
      "allw:pairing:v1",
      JSON.stringify({ ...VALID_IDENTITY, relayUrl: "http://[::1]:8787" }),
    );
    const loaded = createLocalPairingStore(storage).load();
    assert.equal(loaded.status, "relay-pin-rejected");
    assert.equal(loaded.pinnedRelayUrl, "http://[::1]:8787");
    assert.equal(loaded.identity, undefined, "a rejected pin never exposes the identity");
  });

  test("a stored pin that is not canonical (trailing slash) is rejected and names the canonical form", () => {
    const storage = memoryStorage();
    storage.setItem(
      "allw:pairing:v1",
      JSON.stringify({ ...VALID_IDENTITY, relayUrl: "https://relay.example.com/" }),
    );
    const loaded = createLocalPairingStore(storage).load();
    assert.equal(loaded.status, "relay-pin-rejected");
    assert.match(loaded.reason, /canonical form \(https:\/\/relay\.example\.com\)/);
  });

  for (const [label, pin] of [
    ["an empty pin", ""],
    ["an unparseable pin", "not a url"],
  ]) {
    test(`${label} is rejected with a reason that doesn't prompt for input (N1)`, () => {
      const storage = memoryStorage();
      storage.setItem("allw:pairing:v1", JSON.stringify({ ...VALID_IDENTITY, relayUrl: pin }));
      const loaded = createLocalPairingStore(storage).load();
      assert.equal(loaded.status, "relay-pin-rejected");
      assert.equal(loaded.reason, "The stored relay is not a valid URL.");
    });
  }

  test("clearIfUnchanged clears only the exact value that was loaded", () => {
    const storage = memoryStorage();
    const store = createLocalPairingStore(storage);
    storage.setItem(
      "allw:pairing:v1",
      JSON.stringify({ ...VALID_IDENTITY, relayUrl: "http://[::1]:8787" }),
    );
    const { snapshot } = store.load();

    store.save({ ...VALID_IDENTITY, deviceId: "dev-newer", relayUrl: "http://127.0.0.1:8787" });
    assert.equal(store.clearIfUnchanged(snapshot), false, "a newer value is never cleared");
    assert.equal(store.load().identity.deviceId, "dev-newer");

    storage.setItem(
      "allw:pairing:v1",
      JSON.stringify({ ...VALID_IDENTITY, relayUrl: "http://[::1]:8787" }),
    );
    assert.equal(store.clearIfUnchanged(store.load().snapshot), true);
    assert.deepEqual(store.load(), ABSENT);
  });

  test("a stored pin that is not a string is corrupt (not a re-pair state)", () => {
    const storage = memoryStorage();
    storage.setItem("allw:pairing:v1", JSON.stringify({ ...VALID_IDENTITY, relayUrl: 42 }));
    assert.deepEqual(createLocalPairingStore(storage).load(), CORRUPT);
  });

  test("a rejected pin with a missing identity field is corrupt, not a re-pair state", () => {
    const storage = memoryStorage();
    const { deviceAuthToken: _omitted, ...partial } = VALID_IDENTITY;
    storage.setItem(
      "allw:pairing:v1",
      JSON.stringify({ ...partial, relayUrl: "http://[::1]:8787" }),
    );
    assert.deepEqual(createLocalPairingStore(storage).load(), CORRUPT);
  });
});

describe("mountPairingGate — relay shown and pinned at pairing (#249)", () => {
  test("shows the relay before submit and pins it into the stored identity", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      const store = createLocalPairingStore(storage);
      const pairings = [];
      mountPairingGate({
        root,
        pairingStore: store,
        relayUrl: "https://relay.example.com",
        onPaired: (identity) => pairings.push(identity),
      });

      assert.equal(
        root.querySelector(".pairing-relay-url").textContent,
        "https://relay.example.com",
        "the relay must be shown before the human commits",
      );
      assert.equal(pairings.length, 0);

      submitPairingForm(root, VALID_IDENTITY);

      assert.equal(pairings.length, 1);
      assert.equal(pairings[0].relayUrl, "https://relay.example.com");
      assert.equal(store.load().identity.relayUrl, "https://relay.example.com");
    } finally {
      restore();
    }
  });

  test("a returning device keeps its pinned relay even if the gate is given another", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      storage.setItem(
        "allw:pairing:v1",
        JSON.stringify({ ...VALID_IDENTITY, relayUrl: "https://relay.example.com" }),
      );
      const pairings = [];
      mountPairingGate({
        root,
        pairingStore: createLocalPairingStore(storage),
        relayUrl: "https://evil.example",
        onPaired: (identity) => pairings.push(identity),
      });
      const unlock = [...root.querySelectorAll("button")].find(
        (b) => b.textContent === "Unlock inbox",
      );
      unlock.click();
      assert.equal(pairings[0].relayUrl, "https://relay.example.com");
    } finally {
      restore();
    }
  });
});

// ── Re-pair required: a stored pin this build rejects (#286) ─────────────

describe("visiblyEscape (#286)", () => {
  test("keeps printable ASCII unchanged", () => {
    assert.equal(visiblyEscape("http://[::1]:8787/a?b#c"), "http://[::1]:8787/a?b#c");
  });

  test("escapes a bidi override so it cannot reorder the shown text", () => {
    assert.equal(visiblyEscape("https://a‮live.example"), "https://a⟨U+202E⟩live.example");
  });

  test("escapes control characters, zero-width characters and non-ASCII look-alikes", () => {
    assert.equal(visiblyEscape("a\u001Bb​cа"), "a⟨U+001B⟩b⟨U+200B⟩c⟨U+0430⟩");
  });

  test("escapes astral code points as one escape, and escapes the escape brackets themselves", () => {
    assert.equal(visiblyEscape("\u{1F600}"), "⟨U+1F600⟩");
    assert.equal(visiblyEscape("⟨U+0041⟩"), "⟨U+27E8⟩U+0041⟨U+27E9⟩");
  });
});

describe("mountPairingGate — stored pin this build rejects (#286)", () => {
  const PAIRING_KEY = "allw:pairing:v1";

  function mountWithStored(storedIdentity) {
    const { dom, root, restore } = installDom();
    const storage = memoryStorage();
    const storedRaw = JSON.stringify(storedIdentity);
    storage.setItem(PAIRING_KEY, storedRaw);
    const pairings = [];
    mountPairingGate({
      root,
      pairingStore: createLocalPairingStore(storage),
      relayUrl: "http://127.0.0.1:8787",
      onPaired: (identity) => pairings.push(identity),
    });
    return { dom, root, restore, storage, storedRaw, pairings };
  }

  test("shows the re-pair state naming the pinned relay and why, and keeps the identity", () => {
    const { root, restore, storage, storedRaw, pairings } = mountWithStored({
      ...VALID_IDENTITY,
      relayUrl: "http://[::1]:8787",
    });
    try {
      assert.equal(root.querySelector(".pairing-kicker").textContent, "Re-pair required");
      assert.equal(root.querySelector(".pairing-relay-url").textContent, "http://[::1]:8787");
      assert.match(root.querySelector(".pairing-relay-note").textContent, /127\.0\.0\.1/);
      assert.equal(root.querySelector("form.pairing-form"), null, "no pairing form yet");
      assert.equal(storage.getItem(PAIRING_KEY), storedRaw, "nothing is cleared before confirm");
      assert.equal(pairings.length, 0, "a rejected pin never reaches the inbox");
    } finally {
      restore();
    }
  });

  test("clears the identity only when the human confirms, then shows the pairing form", () => {
    const { root, restore, storage, pairings } = mountWithStored({
      ...VALID_IDENTITY,
      relayUrl: "http://[::1]:8787",
    });
    try {
      const confirm = [...root.querySelectorAll("button")].find(
        (b) => b.textContent === "Forget this pairing and pair again",
      );
      assert.ok(confirm, "the confirm action is shown");
      confirm.click();

      assert.equal(storage.getItem(PAIRING_KEY), null, "cleared on confirm");
      assert.ok(root.querySelector("form.pairing-form"), "the pairing form follows");
      assert.equal(root.querySelector(".pairing-relay-url").textContent, "http://127.0.0.1:8787");
      assert.equal(pairings.length, 0);
    } finally {
      restore();
    }
  });

  test("shows a hostile pin visibly escaped (bidi override never reaches the DOM)", () => {
    const { root, restore } = mountWithStored({
      ...VALID_IDENTITY,
      relayUrl: "http://evil‮example.com",
    });
    try {
      const shown = root.querySelector(".pairing-relay-url").textContent;
      assert.equal(shown, "http://evil⟨U+202E⟩example.com");
      assert.ok(!root.textContent.includes("‮"), "no raw bidi override anywhere on screen");
    } finally {
      restore();
    }
  });

  test("an empty pin is shown as (empty), with a reason that doesn't prompt for input (N1)", () => {
    const { root, restore } = mountWithStored({ ...VALID_IDENTITY, relayUrl: "" });
    try {
      assert.equal(root.querySelector(".pairing-relay-url").textContent, "(empty)");
      assert.equal(
        root.querySelector(".pairing-relay-note").textContent,
        "The stored relay is not a valid URL.",
      );
    } finally {
      restore();
    }
  });

  test("a stale tab's confirm never clears a newer identity another tab saved (B1 regression)", () => {
    const { root: rootA, restore } = installDom();
    try {
      const storage = memoryStorage();
      storage.setItem(
        PAIRING_KEY,
        JSON.stringify({ ...VALID_IDENTITY, relayUrl: "http://[::1]:8787" }),
      );
      const rootB = rootA.ownerDocument.createElement("div");
      rootA.ownerDocument.body.append(rootB);
      const confirmIn = (root) =>
        [...root.querySelectorAll("button")]
          .find((b) => b.textContent === "Forget this pairing and pair again")
          .click();
      const pairingsA = [];
      const pairingsB = [];
      // Two tabs load the same rejected identity and both show the re-pair screen.
      for (const [root, pairings] of [
        [rootA, pairingsA],
        [rootB, pairingsB],
      ]) {
        mountPairingGate({
          root,
          pairingStore: createLocalPairingStore(storage),
          relayUrl: "http://127.0.0.1:8787",
          onPaired: (identity) => pairings.push(identity),
        });
      }

      // Tab B confirms and re-pairs: a new identity is saved.
      confirmIn(rootB);
      const newer = { ...VALID_IDENTITY, deviceId: "dev-newer" };
      submitPairingForm(rootB, newer);
      assert.equal(pairingsB.length, 1);
      const savedByB = storage.getItem(PAIRING_KEY);
      assert.equal(JSON.parse(savedByB).deviceId, "dev-newer");

      // Later, the stale tab A confirms forgetting the [::1] pairing it still shows.
      confirmIn(rootA);

      assert.equal(storage.getItem(PAIRING_KEY), savedByB, "the newer identity survives");
      assert.equal(
        rootA.querySelector(".pairing-kicker").textContent,
        "Already paired",
        "tab A routes to the identity that is stored now",
      );
      assert.equal(pairingsA.length, 0);
    } finally {
      restore();
    }
  });

  test("a corrupt identity keeps today's behaviour: cleared and routed to pairing", () => {
    const { deviceAuthToken: _omitted, ...partial } = VALID_IDENTITY;
    const { root, restore, storage } = mountWithStored({ ...partial, relayUrl: "http://[::1]" });
    try {
      assert.ok(root.querySelector("form.pairing-form"), "straight to the pairing form");
      assert.equal(storage.getItem(PAIRING_KEY), null);
    } finally {
      restore();
    }
  });
});
