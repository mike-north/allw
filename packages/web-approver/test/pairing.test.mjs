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

import { mountPairingGate, createLocalPairingStore } from "../dist/index.js";
import { mountWebApprover } from "../dist/browser.js";

// ── Fixed clock (never Date.now() in test data) ───────────────────────────

const NOW = Date.parse("2026-06-12T16:00:00.000Z");
const SOON = NOW + 60_000;

// ── Fixture helpers ───────────────────────────────────────────────────────

/** A minimal valid `ApproverIdentity` (fixed seeds, not real cryptographic material). */
const VALID_IDENTITY = {
  accountId: "acct-pairing-test",
  deviceId: "dev-pairing-test",
  deviceEncryptionSeed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  deviceSigningSeed: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
  deviceCert: "eyJhbGciOiJFZERTQSJ9.test.sig",
  accountRootPubkey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
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
      assert.equal(store.load(), null, "store must be cleared after reset");
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
      const loaded = store.load();
      assert.ok(loaded !== null, "identity must be persisted after pairing");
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
  test("load returns null when nothing is stored", () => {
    const store = createLocalPairingStore(memoryStorage());
    assert.equal(store.load(), null);
  });

  test("save + load round-trips a valid identity", () => {
    const store = createLocalPairingStore(memoryStorage());
    store.save(VALID_IDENTITY);
    const loaded = store.load();
    assert.ok(loaded !== null, "saved identity must be loadable");
    assert.deepEqual(loaded, VALID_IDENTITY);
  });

  test("clear removes the stored identity", () => {
    const store = createLocalPairingStore(memoryStorage());
    store.save(VALID_IDENTITY);
    store.clear();
    assert.equal(store.load(), null, "cleared store must return null");
  });

  test("load returns null for corrupt stored JSON", () => {
    const storage = memoryStorage();
    storage.setItem("allw:pairing:v1", "NOT-VALID-JSON{{{{");
    const store = createLocalPairingStore(storage);
    assert.equal(store.load(), null, "corrupt JSON must return null (fail-closed)");
  });

  test("load returns null when stored object is missing required fields", () => {
    const storage = memoryStorage();
    storage.setItem("allw:pairing:v1", JSON.stringify({ accountId: "only-one" }));
    const store = createLocalPairingStore(storage);
    assert.equal(store.load(), null, "partial identity must return null (fail-closed)");
  });

  test("load returns null for a stored array (not an object)", () => {
    const storage = memoryStorage();
    storage.setItem("allw:pairing:v1", JSON.stringify([]));
    const store = createLocalPairingStore(storage);
    assert.equal(store.load(), null, "array value must return null (fail-closed)");
  });

  test("load returns null for an identity with an empty-string field", () => {
    const storage = memoryStorage();
    const withEmptyField = { ...VALID_IDENTITY, deviceId: "" };
    storage.setItem("allw:pairing:v1", JSON.stringify(withEmptyField));
    const store = createLocalPairingStore(storage);
    assert.equal(store.load(), null, "identity with empty string field must return null");
  });
});
