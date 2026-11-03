/**
 * Boot-sequence tests for relay pinning (issue #249).
 *
 * These drive the production `boot()` (`src/app.ts`) end to end through the real relay-config,
 * onboarding, and pairing modules in jsdom, with only the WASM/inbox step (`startInbox`) injected —
 * so they observe exactly which relay the paired identity is handed to, what is persisted, and
 * whether anything touched the network before the human committed. A global `fetch` and
 * `WebSocket` spy fails loudly if any request is attempted during boot.
 *
 * Scenarios (the issue's acceptance tests, plus the legacy-identity and https-only branches):
 *   - paired + `?relay=` to another origin → nothing reaches that origin, the stored identity is
 *     byte-for-byte unchanged, the inbox gets the pinned relay, and a notice names the ignored
 *     origin;
 *   - unpaired + `?relay=` → the relay is shown on the pairing screen before any request is made;
 *     pairing pins it into the stored identity;
 *   - an identity stored before pinning existed is bound to the already-persisted relay, never to
 *     a `?relay=` link;
 *   - unpaired + `?relay=http://relay.example.com` → rejected with the https-only reason;
 *   - an identity pinned to a relay the current rule rejects (`http://[::1]`) → a re-pair-required
 *     screen first; the identity is cleared only on confirmation (#286). A corrupt identity is
 *     still discarded by the pairing gate.
 *
 * @see https://github.com/mike-north/allw/issues/249
 * @see ../src/app.ts
 * @see ../../../docs/web-approver-deploy.md (§Relay pinning)
 * @see ../../../docs/threat-model.md (§Trust Boundaries)
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test, { afterEach, beforeEach, describe } from "node:test";

import { JSDOM } from "jsdom";

import { boot, bootInbox } from "../dist/app.js";
import {
  INSECURE_RELAY_URL_REASON,
  RELAY_URL_STORAGE_KEY,
  WITHHELD_PIN_TEXT,
} from "../dist/index.js";

import { loadTestWasm } from "./wasm-helper.mjs";

const PAIRING_KEY = "allw:pairing:v1";
const ONBOARDING_KEY = "allw:onboarding:v1";
const PINNED_RELAY = "https://relay.example.com";
const EVIL_RELAY = "https://evil.example";

/** A paired identity (fixed, non-cryptographic fixture values) pinned to {@link PINNED_RELAY}. */
const PINNED_IDENTITY = {
  accountId: "acct-boot-test",
  deviceId: "dev-boot-test",
  deviceEncryptionSeed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  deviceSigningSeed: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  deviceCert: "eyJhbGciOiJFZERTQSJ9.test.sig",
  accountRootPubkey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
  deviceAuthToken: "relay-bearer-boot-test",
  relayUrl: PINNED_RELAY,
};

/** The same identity as stored by a build that predates relay pinning (no `relayUrl`). */
const { relayUrl: _omitted, ...LEGACY_IDENTITY } = PINNED_IDENTITY;

/** A fake in-memory `Storage`. */
function memoryStorage() {
  const map = new Map();
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => void map.set(key, String(value)),
    removeItem: (key) => void map.delete(key),
    clear: () => map.clear(),
    get length() {
      return map.size;
    },
    key: (index) => Array.from(map.keys())[index] ?? null,
  };
}

let dom;
let saved;
/** Every URL a fetch or WebSocket was attempted against during the test. */
let networkAttempts;

beforeEach(() => {
  dom = new JSDOM('<div id="notices"></div><div id="app"></div>', {
    url: "https://approver.local/",
  });
  saved = {
    document: globalThis.document,
    FormData: globalThis.FormData,
    fetch: globalThis.fetch,
    WebSocket: globalThis.WebSocket,
  };
  networkAttempts = [];
  globalThis.document = dom.window.document;
  globalThis.FormData = dom.window.FormData;
  globalThis.fetch = (url) => {
    networkAttempts.push(String(url));
    return Promise.reject(new Error("boot must not touch the network"));
  };
  globalThis.WebSocket = function SpyWebSocket(url) {
    networkAttempts.push(String(url));
    throw new Error("boot must not open a WebSocket");
  };
});

afterEach(() => {
  globalThis.document = saved.document;
  globalThis.FormData = saved.FormData;
  globalThis.fetch = saved.fetch;
  globalThis.WebSocket = saved.WebSocket;
});

/** Load the real core's `escape_for_display` (#246) from the vendored WASM, as production does. */
async function loadCoreDisplayEscape() {
  const wasm = await loadTestWasm();
  return (text) => wasm.escape_for_display(text);
}

/**
 * Boot with `search` + `storage`, recording every identity handed to the inbox or to the
 * notification controls, and counting requests to forget notifications (`onForget` sees each). The
 * re-pair screen's display escape comes from the real core unless `loadDisplayEscape` overrides it.
 */
async function bootWith({
  search,
  storage,
  loadDisplayEscape = loadCoreDisplayEscape,
  onForget = () => undefined,
}) {
  const document = dom.window.document;
  const root = document.getElementById("app");
  const noticeHost = document.getElementById("notices");
  const inboxStarts = [];
  const notificationStarts = [];
  /**
   * How many times boot asked to forget notifications (clear the credential mirror), and the
   * forgotten relay credentials each request carried.
   */
  const forgets = { count: 0, forgotten: [] };
  await boot({
    root,
    noticeHost,
    storage,
    search,
    startInbox: async (_root, identity) => {
      inboxStarts.push(identity);
    },
    startNotifications: (identity) => {
      notificationStarts.push(identity);
    },
    forgetNotifications: async (forgotten) => {
      forgets.count += 1;
      forgets.forgotten.push(forgotten);
      onForget(forgets.count);
    },
    loadDisplayEscape,
  });
  return { root, noticeHost, inboxStarts, notificationStarts, forgets };
}

function click(root, label) {
  const button = [...root.querySelectorAll("button")].find((b) => b.textContent === label);
  assert.ok(button, `button '${label}' must be present`);
  button.click();
}

function submitPairingForm(root, fields) {
  for (const [name, value] of Object.entries(fields)) {
    const input = root.querySelector(`input[name="${name}"]`);
    if (input) input.value = value;
  }
  root
    .querySelector("form.pairing-form")
    .dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
}

const relayQuery = (value) => `?relay=${encodeURIComponent(value)}`;

/**
 * Resolve once `probe()` is truthy, flushing microtasks between checks, rather than relying on the
 * exact number of awaits inside `boot`. Fails after a bounded number of ticks.
 */
async function waitFor(probe, ticks = 100) {
  for (let i = 0; i < ticks; i++) {
    if (probe()) return;
    await Promise.resolve();
  }
  assert.fail("condition not met within the tick budget");
}

describe("boot — notification controls (#237)", () => {
  test("mount only once the human unlocks, with the pinned identity, after the inbox starts", async () => {
    const storage = memoryStorage();
    storage.setItem(PAIRING_KEY, JSON.stringify(PINNED_IDENTITY));

    const { root, inboxStarts, notificationStarts } = await bootWith({ search: "", storage });
    assert.equal(notificationStarts.length, 0, "nothing before the returning-device unlock");

    click(root, "Unlock inbox");
    assert.equal(inboxStarts.length, 1);
    assert.equal(notificationStarts.length, 1);
    assert.equal(notificationStarts[0].relayUrl, PINNED_RELAY);
    assert.equal(notificationStarts[0].deviceId, PINNED_IDENTITY.deviceId);
    assert.deepEqual(networkAttempts, []);
  });

  test("an unpaired browser gets no notification controls until it pairs", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    const { root, notificationStarts } = await bootWith({
      search: relayQuery("https://relay.selfhost.example"),
      storage,
    });
    assert.equal(notificationStarts.length, 0);
    submitPairingForm(root, LEGACY_IDENTITY);
    assert.equal(notificationStarts.length, 1);
    assert.equal(notificationStarts[0].relayUrl, "https://relay.selfhost.example");
  });

  test("a paired browser keeps its notification credentials", async () => {
    const storage = memoryStorage();
    storage.setItem(PAIRING_KEY, JSON.stringify(PINNED_IDENTITY));
    const { root, forgets } = await bootWith({ search: "", storage });
    click(root, "Unlock inbox");
    assert.equal(forgets.count, 0);
  });

  test("a browser with no usable identity forgets any mirrored credentials at boot", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    storage.setItem(PAIRING_KEY, "{not json");
    storage.setItem(RELAY_URL_STORAGE_KEY, PINNED_RELAY);
    const { forgets } = await bootWith({ search: "", storage });
    assert.ok(forgets.count >= 1, "a corrupt identity's notification credentials are forgotten");
  });

  test("a browser with no stored identity forgets at boot, before onboarding or any action", async () => {
    // No identity and onboarding not done: the walkthrough comes first, so boot's own forget is
    // the only one that runs before the human does anything (review of #315, finding 4). A relay
    // is already persisted, so boot runs through to the walkthrough without prompting.
    const storage = memoryStorage();
    storage.setItem(RELAY_URL_STORAGE_KEY, PINNED_RELAY);
    const { root, forgets } = await bootWith({ search: "", storage });
    assert.equal(root.querySelector("form.pairing-form"), null, "the walkthrough is showing");
    assert.equal(forgets.count, 1);
    assert.deepEqual(forgets.forgotten, [null], "there is no identity to take a token from");
  });

  test("'Use another device' forgets the notification credentials with the pairing", async () => {
    const storage = memoryStorage();
    storage.setItem(PAIRING_KEY, JSON.stringify(PINNED_IDENTITY));
    const { root, forgets } = await bootWith({ search: "", storage });
    assert.equal(forgets.count, 0);
    click(root, "Use another device");
    assert.equal(storage.getItem(PAIRING_KEY), null);
    // The confirm forgets; the pairing gate's own clear before its form may forget again, which is
    // harmless (forgetting is idempotent).
    assert.ok(forgets.count >= 1, "the confirmed re-pair forgets the notification credentials");
    // The forgotten identity's four relay fields travel with the forget, so its registration can be
    // withdrawn even when the mirror is already empty (review of #315, round 2). Never the seeds.
    assert.deepEqual(forgets.forgotten[0], {
      relayUrl: PINNED_RELAY,
      accountId: PINNED_IDENTITY.accountId,
      deviceId: PINNED_IDENTITY.deviceId,
      deviceAuthToken: PINNED_IDENTITY.deviceAuthToken,
    });
  });

  test("confirming a re-pair forgets the notification credentials; showing the screen does not", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    storage.setItem(
      PAIRING_KEY,
      JSON.stringify({ ...PINNED_IDENTITY, relayUrl: "http://[::1]:8787" }),
    );
    storage.setItem(RELAY_URL_STORAGE_KEY, "http://127.0.0.1:8787");
    const forgetsSeen = [];
    const bootPromise = bootWith({ search: "", storage, onForget: (n) => forgetsSeen.push(n) });
    const root = dom.window.document.getElementById("app");
    await waitFor(() => root.querySelector(".pairing-kicker"));
    assert.deepEqual(forgetsSeen, [], "nothing is forgotten before the human confirms");

    click(root, "Forget this pairing and pair again");
    const { forgets } = await bootPromise;
    assert.equal(storage.getItem(PAIRING_KEY), null);
    // The confirm forgets; the pairing gate's own clear before its form may forget again, which is
    // harmless (forgetting is idempotent).
    assert.ok(forgets.count >= 1, "the confirmed re-pair forgets the notification credentials");
  });

  test("a stale tab's re-pair confirm that keeps a newer identity forgets nothing (B1)", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    storage.setItem(
      PAIRING_KEY,
      JSON.stringify({ ...PINNED_IDENTITY, relayUrl: "http://[::1]:8787" }),
    );
    storage.setItem(RELAY_URL_STORAGE_KEY, "http://127.0.0.1:8787");
    const bootPromise = bootWith({ search: "", storage });
    const root = dom.window.document.getElementById("app");
    await waitFor(() => root.querySelector(".pairing-kicker"));

    // Another tab re-pairs (and may have enabled notifications for the new identity) meanwhile.
    storage.setItem(
      PAIRING_KEY,
      JSON.stringify({
        ...PINNED_IDENTITY,
        deviceId: "dev-newer",
        relayUrl: "http://127.0.0.1:8787",
      }),
    );
    click(root, "Forget this pairing and pair again");
    const { forgets } = await bootPromise;
    assert.equal(JSON.parse(storage.getItem(PAIRING_KEY)).deviceId, "dev-newer");
    assert.equal(forgets.count, 0, "the newer identity's notification credentials are kept");
  });
});

describe("boot — paired device with a ?relay= link to another origin (#249)", () => {
  test("nothing reaches the other origin, the stored identity is unchanged, and a notice names it", async () => {
    const storage = memoryStorage();
    const storedRaw = JSON.stringify(PINNED_IDENTITY);
    storage.setItem(PAIRING_KEY, storedRaw);
    storage.setItem(RELAY_URL_STORAGE_KEY, PINNED_RELAY);

    const { root, noticeHost, inboxStarts } = await bootWith({
      search: relayQuery(`${EVIL_RELAY}/collect`),
      storage,
    });

    // The notice names the ignored origin, and lives outside #app so it survives screen changes.
    const notice = noticeHost.querySelector(".relay-pin-notice");
    assert.ok(notice, "a visible notice must name the ignored relay");
    assert.equal(notice.querySelector(".relay-pin-notice-origin").textContent, EVIL_RELAY);

    click(root, "Unlock inbox");

    assert.equal(inboxStarts.length, 1, "the returning device reaches the inbox");
    assert.equal(inboxStarts[0].relayUrl, PINNED_RELAY, "every relay call uses the pinned relay");
    assert.equal(inboxStarts[0].deviceAuthToken, PINNED_IDENTITY.deviceAuthToken);
    assert.deepEqual(
      networkAttempts,
      [],
      "no request may be made during boot, least of all to the link's relay",
    );
    assert.equal(storage.getItem(PAIRING_KEY), storedRaw, "stored identity must be unchanged");
    assert.equal(
      storage.getItem(RELAY_URL_STORAGE_KEY),
      PINNED_RELAY,
      "the ignored link must not be persisted",
    );
    assert.ok(noticeHost.querySelector(".relay-pin-notice"), "notice still visible after unlock");
  });

  test("a ?relay= equal to the pinned relay shows no notice", async () => {
    const storage = memoryStorage();
    storage.setItem(PAIRING_KEY, JSON.stringify(PINNED_IDENTITY));
    const { noticeHost } = await bootWith({ search: relayQuery(`${PINNED_RELAY}/`), storage });
    assert.equal(noticeHost.childElementCount, 0);
  });

  test("'Use another device' re-pairs against the pinned relay, not the link's", async () => {
    const storage = memoryStorage();
    storage.setItem(PAIRING_KEY, JSON.stringify(PINNED_IDENTITY));
    const { root, inboxStarts } = await bootWith({ search: relayQuery(EVIL_RELAY), storage });

    click(root, "Use another device");
    assert.equal(root.querySelector(".pairing-relay-url").textContent, PINNED_RELAY);
    submitPairingForm(root, LEGACY_IDENTITY);

    assert.equal(inboxStarts.length, 1);
    assert.equal(inboxStarts[0].relayUrl, PINNED_RELAY);
    assert.equal(JSON.parse(storage.getItem(PAIRING_KEY)).relayUrl, PINNED_RELAY);
    assert.deepEqual(networkAttempts, []);
  });
});

describe("boot — identity stored before relay pinning existed", () => {
  test("is bound to the already-persisted relay, never to a ?relay= link", async () => {
    const storage = memoryStorage();
    storage.setItem(PAIRING_KEY, JSON.stringify(LEGACY_IDENTITY));
    storage.setItem(RELAY_URL_STORAGE_KEY, PINNED_RELAY);

    const { root, noticeHost, inboxStarts } = await bootWith({
      search: relayQuery(EVIL_RELAY),
      storage,
    });

    assert.equal(JSON.parse(storage.getItem(PAIRING_KEY)).relayUrl, PINNED_RELAY);
    assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), PINNED_RELAY);
    assert.ok(noticeHost.querySelector(".relay-pin-notice"), "the link is reported as ignored");

    click(root, "Unlock inbox");
    assert.equal(inboxStarts[0].relayUrl, PINNED_RELAY);
    assert.deepEqual(networkAttempts, []);
  });

  test("with no persisted relay, asks the human (the link is still not used)", async () => {
    const storage = memoryStorage();
    storage.setItem(PAIRING_KEY, JSON.stringify(LEGACY_IDENTITY));

    const bootPromise = bootWith({ search: relayQuery(EVIL_RELAY), storage });
    const root = dom.window.document.getElementById("app");
    assert.ok(root.querySelector("form.relay-config-form"), "the relay prompt is shown");

    root.querySelector('input[name="relayUrl"]').value = PINNED_RELAY;
    root
      .querySelector("form.relay-config-form")
      .dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
    const { inboxStarts } = await bootPromise;

    assert.equal(JSON.parse(storage.getItem(PAIRING_KEY)).relayUrl, PINNED_RELAY);
    click(root, "Unlock inbox");
    assert.equal(inboxStarts[0].relayUrl, PINNED_RELAY);
    assert.deepEqual(networkAttempts, []);
  });
});

/**
 * A stored identity pinned to a relay this build rejects (#286). For example, builds before
 * `[::1]` was dropped from the loopback set could pin `http://[::1]:…`. The identity is a distinct
 * re-pair-required state: boot shows it before resolving or asking for any relay, nothing is
 * cleared until the human confirms, and no relay is contacted. One test per path: a valid pin loads
 * normally, a rejected pin shows the re-pair state, and a corrupt identity keeps today's behaviour.
 *
 * @see https://github.com/mike-north/allw/issues/286
 */
describe("boot — stored identity pinned to a relay this build rejects (#286)", () => {
  const V6_PINNED_IDENTITY = { ...PINNED_IDENTITY, relayUrl: "http://[::1]:8787" };
  const LOOPBACK_CANDIDATE = "http://127.0.0.1:8787";
  const confirmLabel = "Forget this pairing and pair again";

  test("a valid pin loads normally: returning-device screen, inbox on the pinned relay", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    storage.setItem(PAIRING_KEY, JSON.stringify(PINNED_IDENTITY));
    storage.setItem(RELAY_URL_STORAGE_KEY, LOOPBACK_CANDIDATE);

    const { root, inboxStarts } = await bootWith({ search: "", storage });

    assert.equal(root.querySelector(".pairing-kicker").textContent, "Already paired");
    click(root, "Unlock inbox");
    assert.equal(inboxStarts[0].relayUrl, PINNED_RELAY);
    assert.deepEqual(networkAttempts, []);
  });

  test("a rejected pin shows the re-pair state first and keeps the identity until confirmed", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    const storedRaw = JSON.stringify(V6_PINNED_IDENTITY);
    storage.setItem(PAIRING_KEY, storedRaw);
    storage.setItem(RELAY_URL_STORAGE_KEY, LOOPBACK_CANDIDATE);

    const bootPromise = bootWith({ search: relayQuery(EVIL_RELAY), storage });
    const root = dom.window.document.getElementById("app");
    await waitFor(() => root.querySelector(".pairing-kicker"));

    assert.equal(root.querySelector(".pairing-kicker").textContent, "Re-pair required");
    assert.equal(root.querySelector(".pairing-relay-url").textContent, "http://[::1]:8787");
    assert.equal(root.querySelector("form.pairing-form"), null);
    assert.equal(root.querySelector("form.relay-config-form"), null);
    assert.equal(storage.getItem(PAIRING_KEY), storedRaw, "the identity is still stored");
    assert.deepEqual(networkAttempts, []);

    click(root, confirmLabel);
    const { noticeHost, inboxStarts } = await bootPromise;

    assert.equal(storage.getItem(PAIRING_KEY), null, "cleared only after confirmation");
    assert.ok(root.querySelector("form.pairing-form"), "then the browser pairs again");
    // A re-pair visit is a previously paired browser (decision D1): the ?relay= link is ignored,
    // reported, and never persisted; the already-persisted candidate is the relay shown.
    assert.equal(root.querySelector(".pairing-relay-url").textContent, LOOPBACK_CANDIDATE);
    assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), LOOPBACK_CANDIDATE);
    const notice = noticeHost.querySelector(".relay-pin-notice");
    assert.ok(notice, "the ignored link is reported");
    assert.match(notice.textContent, /is re-pairing with http:\/\/127\.0\.0\.1:8787/);
    assert.doesNotMatch(notice.textContent, /is paired with/, "not paired yet on this visit");
    assert.equal(inboxStarts.length, 0, "the rejected identity never reaches the inbox");
    assert.deepEqual(networkAttempts, []);
  });

  test("confirming in a stale tab keeps a newer identity saved since, and routes to it (B1)", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    storage.setItem(PAIRING_KEY, JSON.stringify(V6_PINNED_IDENTITY));
    storage.setItem(RELAY_URL_STORAGE_KEY, LOOPBACK_CANDIDATE);

    const bootPromise = bootWith({ search: "", storage });
    const root = dom.window.document.getElementById("app");
    await waitFor(() => root.querySelector(".pairing-kicker"));
    assert.equal(root.querySelector(".pairing-kicker").textContent, "Re-pair required");

    // Another tab re-pairs meanwhile and saves a new, valid identity.
    const newer = { ...PINNED_IDENTITY, deviceId: "dev-newer", relayUrl: LOOPBACK_CANDIDATE };
    const newerRaw = JSON.stringify(newer);
    storage.setItem(PAIRING_KEY, newerRaw);

    click(root, confirmLabel);
    const { inboxStarts } = await bootPromise;

    assert.equal(storage.getItem(PAIRING_KEY), newerRaw, "the newer identity is never cleared");
    assert.equal(root.querySelector(".pairing-kicker").textContent, "Already paired");
    click(root, "Unlock inbox");
    assert.equal(inboxStarts[0].deviceId, "dev-newer");
    assert.equal(inboxStarts[0].relayUrl, LOOPBACK_CANDIDATE);
    assert.deepEqual(networkAttempts, []);
  });

  test("a rejected pin with no candidate relay still explains first, then asks for a relay", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    const storedRaw = JSON.stringify(V6_PINNED_IDENTITY);
    storage.setItem(PAIRING_KEY, storedRaw);

    void bootWith({ search: "", storage });
    const root = dom.window.document.getElementById("app");
    await waitFor(() => root.querySelector(".pairing-kicker"));

    assert.equal(root.querySelector(".pairing-kicker").textContent, "Re-pair required");
    assert.equal(root.querySelector("form.relay-config-form"), null, "no relay prompt yet");
    assert.equal(storage.getItem(PAIRING_KEY), storedRaw);

    click(root, confirmLabel);
    await waitFor(() => root.querySelector("form.relay-config-form"));

    assert.equal(storage.getItem(PAIRING_KEY), null);
    assert.ok(root.querySelector("form.relay-config-form"), "now the relay prompt is shown");
    assert.deepEqual(networkAttempts, []);
  });

  test("a hostile pin is rendered through the core escape, never raw", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    storage.setItem(
      PAIRING_KEY,
      JSON.stringify({ ...PINNED_IDENTITY, relayUrl: "http://evil\u202Eexample.com\u001B" }),
    );

    void bootWith({ search: "", storage });
    const root = dom.window.document.getElementById("app");
    await waitFor(() => root.querySelector(".pairing-relay-url"));

    // crates/allw-core/src/display.rs: bidi controls → ⟨U+XXXX⟩, C0 controls → backslash escapes.
    assert.equal(
      root.querySelector(".pairing-relay-url").textContent,
      "http://evil⟨U+202E⟩example.com\\x1b",
    );
    assert.ok(!root.textContent.includes("\u202E"), "no raw bidi override on screen");
    assert.ok(!root.textContent.includes("\u001B"), "no raw ESC on screen");
    assert.deepEqual(networkAttempts, []);
  });

  test("if the core fails to load, the pin is withheld and the confirm still re-pairs", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    storage.setItem(
      PAIRING_KEY,
      JSON.stringify({ ...PINNED_IDENTITY, relayUrl: "http://evil\u202Eexample.com" }),
    );
    storage.setItem(RELAY_URL_STORAGE_KEY, LOOPBACK_CANDIDATE);

    const bootPromise = bootWith({
      search: "",
      storage,
      loadDisplayEscape: () => Promise.reject(new Error("the WASM core did not load")),
    });
    const root = dom.window.document.getElementById("app");
    await waitFor(() => root.querySelector(".pairing-kicker"));

    assert.equal(root.querySelector(".pairing-kicker").textContent, "Re-pair required");
    assert.equal(root.querySelector(".pairing-relay-url").textContent, WITHHELD_PIN_TEXT);
    assert.ok(!root.textContent.includes("evil"), "no part of the pin is printed");

    click(root, confirmLabel);
    const { inboxStarts } = await bootPromise;

    assert.equal(storage.getItem(PAIRING_KEY), null, "cleared on confirmation");
    assert.ok(root.querySelector("form.pairing-form"), "then the browser pairs again");
    assert.equal(root.querySelector(".pairing-relay-url").textContent, LOOPBACK_CANDIDATE);
    assert.equal(inboxStarts.length, 0);
    assert.deepEqual(networkAttempts, []);
  });

  test("a corrupt identity keeps today's behaviour: boots unpaired and is cleared by the gate", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");
    const { deviceAuthToken: _omitted, ...partial } = V6_PINNED_IDENTITY;
    storage.setItem(PAIRING_KEY, JSON.stringify(partial));
    storage.setItem(RELAY_URL_STORAGE_KEY, LOOPBACK_CANDIDATE);

    const { root, inboxStarts } = await bootWith({ search: "", storage });

    assert.ok(root.querySelector("form.pairing-form"), "straight to the pairing form");
    assert.equal(storage.getItem(PAIRING_KEY), null, "the corrupt value is discarded");
    assert.equal(inboxStarts.length, 0);
    assert.deepEqual(networkAttempts, []);
  });
});

describe("boot — unpaired device with a ?relay= link (#249)", () => {
  test("the relay is shown before any request is made, and pairing pins it", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");

    const { root, inboxStarts } = await bootWith({
      search: relayQuery("https://relay.selfhost.example/"),
      storage,
    });

    // Shown before the human commits — and nothing has been requested yet.
    assert.ok(root.querySelector("form.pairing-form"), "the pairing form is shown");
    assert.equal(
      root.querySelector(".pairing-relay-url").textContent,
      "https://relay.selfhost.example",
    );
    assert.deepEqual(networkAttempts, []);
    assert.equal(inboxStarts.length, 0);

    submitPairingForm(root, LEGACY_IDENTITY);

    assert.equal(inboxStarts.length, 1);
    assert.equal(inboxStarts[0].relayUrl, "https://relay.selfhost.example");
    assert.equal(
      JSON.parse(storage.getItem(PAIRING_KEY)).relayUrl,
      "https://relay.selfhost.example",
      "the relay is pinned inside the stored identity",
    );
    assert.deepEqual(networkAttempts, []);
  });

  test("a plaintext http:// ?relay= to a remote host is rejected with the https-only reason", async () => {
    const storage = memoryStorage();
    storage.setItem(ONBOARDING_KEY, "1");

    void bootWith({ search: relayQuery("http://relay.example.com"), storage });
    const root = dom.window.document.getElementById("app");

    assert.ok(root.querySelector("form.relay-config-form"), "the relay prompt is shown instead");
    assert.equal(
      root.querySelector(".relay-config-error-banner").textContent,
      INSECURE_RELAY_URL_REASON,
    );
    assert.equal(root.querySelector("form.pairing-form"), null, "pairing does not proceed");
    assert.equal(storage.getItem(RELAY_URL_STORAGE_KEY), null);
    assert.deepEqual(networkAttempts, []);
  });
});

// ── bootInbox: the production inbox start uses the pinned relay (#249) ──────────────────────────

const vendorDir = new URL("../../sdk/vendor/allw-wasm/", import.meta.url);
const wasmAvailable = existsSync(new URL("allw_wasm_bg.wasm", vendorDir));

describe("bootInbox — every relay call goes to the pinned relay", { skip: !wasmAvailable }, () => {
  test("inbox poll and connect WebSocket target only the identity's relayUrl", async () => {
    // A stale candidate relay in storage must never be consulted once an identity is pinned.
    const storage = memoryStorage();
    storage.setItem(RELAY_URL_STORAGE_KEY, EVIL_RELAY);
    const savedStorage = globalThis.localStorage;
    globalThis.localStorage = storage;
    const fetchedUrls = [];
    // Record the dial and hand back an inert socket (the default spy throws, which would abort
    // the mount); stop() closes it.
    globalThis.WebSocket = function RecordingWebSocket(url) {
      networkAttempts.push(String(url));
      this.close = () => undefined;
      this.addEventListener = () => undefined;
    };
    globalThis.fetch = async (url) => {
      fetchedUrls.push(String(url));
      return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
    };
    try {
      const { resetWasmForTests } = await import("../dist/index.js");
      resetWasmForTests();
      const root = dom.window.document.getElementById("app");
      const mount = await bootInbox(root, PINNED_IDENTITY, {
        loadGlue: () => import(new URL("allw_wasm.js", vendorDir).href),
        moduleSource: new WebAssembly.Module(readFileSync(new URL("allw_wasm_bg.wasm", vendorDir))),
      });
      try {
        assert.ok(root.querySelector(".approver-shell"), "the live inbox is mounted");
        assert.ok(fetchedUrls.length > 0, "the inbox polls the relay");
        for (const url of fetchedUrls) {
          assert.ok(url.startsWith(`${PINNED_RELAY}/`), `fetch went to the pinned relay: ${url}`);
        }
        assert.ok(
          fetchedUrls.includes(
            `${PINNED_RELAY}/${PINNED_IDENTITY.accountId}/devices/${PINNED_IDENTITY.deviceId}/inbox`,
          ),
        );
        const sockets = networkAttempts.filter((url) => url.startsWith("ws"));
        assert.ok(sockets.length > 0, "the retract listener dials the relay");
        for (const url of sockets) {
          assert.ok(
            url.startsWith("wss://relay.example.com/"),
            `WebSocket to pinned relay: ${url}`,
          );
        }
        assert.ok(
          [...fetchedUrls, ...networkAttempts].every((url) => !url.includes("evil.example")),
          "nothing reaches the stale candidate relay",
        );
      } finally {
        mount.stop();
      }
    } finally {
      globalThis.localStorage = savedStorage;
    }
  });
});
