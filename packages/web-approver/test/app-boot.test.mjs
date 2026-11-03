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
 *   - unpaired + `?relay=http://relay.example.com` → rejected with the https-only reason.
 *
 * @see https://github.com/mike-north/allw/issues/249
 * @see ../src/app.ts
 * @see ../../../docs/web-approver-deploy.md (§Relay pinning)
 * @see ../../../docs/threat-model.md (§Trust Boundaries)
 */

import assert from "node:assert/strict";
import test, { afterEach, beforeEach, describe } from "node:test";

import { JSDOM } from "jsdom";

import { boot } from "../dist/app.js";
import { INSECURE_RELAY_URL_REASON, RELAY_URL_STORAGE_KEY } from "../dist/index.js";

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

/** Boot with `search` + `storage`, recording every identity handed to the inbox. */
async function bootWith({ search, storage }) {
  const document = dom.window.document;
  const root = document.getElementById("app");
  const noticeHost = document.getElementById("notices");
  const inboxStarts = [];
  await boot({
    root,
    noticeHost,
    storage,
    search,
    startInbox: async (_root, identity) => {
      inboxStarts.push(identity);
    },
  });
  return { root, noticeHost, inboxStarts };
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
