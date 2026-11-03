/**
 * Tests for web approver notifications (issue #237): the service worker's event handlers, the relay
 * calls behind them, the IndexedDB credential mirror's validation, and the page's subscribe
 * controls, including the iOS Home Screen guidance branch.
 *
 * Everything runs with injected `fetch`, `showNotification`, window clients, push manager,
 * permission API and storage, so no browser or relay is needed. Expected values come from the
 * issue's acceptance criteria and the relay contract, not from captured output:
 *   - every push ends in a visible notification, including an empty inbox (relay §5: wakeups are
 *     payload-less and coalesced, so the inbox can be empty by the time the worker reads it);
 *   - notification title and body never depend on envelope contents (#237: "no request plaintext");
 *   - the subscription uses `userVisibleOnly: true` and the relay's VAPID key;
 *   - the endpoint is registered with `PUT /{acct}/devices/{device_id}/push-tokens`, body
 *     `{ push_tokens: [{ transport: "webpush", token }] }`, Bearer device token (#236);
 *   - only relay URL, account id, device id and device token are mirrored, never seeds;
 *   - forgetting the pairing clears the mirror, drops the subscription, and clears the device's
 *     relay push tokens with `{ push_tokens: [] }` (#236: an empty array clears).
 *
 * @see https://github.com/mike-north/allw/issues/237
 * @see https://github.com/mike-north/allw/issues/236
 * @see ../../../docs/relay-api.md (§3 relay-level and device endpoints, §5 Web Push)
 * @see https://www.w3.org/TR/push-api/
 * @see https://www.rfc-editor.org/rfc/rfc8292 (VAPID)
 * @see https://developer.apple.com/documentation/usernotifications/sending-web-push-notifications-in-web-apps-and-browsers
 */

import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, test } from "node:test";

import { JSDOM } from "jsdom";

import {
  parsePushCredentials,
  parsePushRegistration,
  pushCredentialsFrom,
} from "../dist/push-credentials.js";
import {
  clearPushTokens,
  decodeBase64Url,
  fetchPendingCount,
  fetchVapidPublicKey,
  registerPushEndpoint,
} from "../dist/push-relay.js";
import {
  PAIRING_CHANGED_NOTE,
  forgetNotifications,
  isAppleMobile,
  mountNotificationControls,
  pushAvailability,
} from "../dist/push-subscribe.js";
import {
  EMPTY_INBOX_BODY,
  NOTIFICATION_TAG,
  NOTIFICATION_TITLE,
  UNKNOWN_INBOX_BODY,
  handleNotificationClick,
  handlePush,
  handleSubscriptionChange,
  notificationForPendingCount,
} from "../dist/sw-handlers.js";

// ── Fixtures ──────────────────────────────────────────────────────────────────────────────────────

const RELAY = "https://relay.example.com";
const CREDENTIALS = {
  relayUrl: RELAY,
  accountId: "acct_push_237",
  deviceId: "dev_push_237",
  deviceAuthToken: "device-token-237",
};
/** A paired identity: the credentials plus secrets that must never be mirrored. */
const IDENTITY = {
  ...CREDENTIALS,
  deviceEncryptionSeed: "SECRET-ENCRYPTION-SEED",
  deviceSigningSeed: "SECRET-SIGNING-SEED",
  deviceCert: "device.cert.sig",
  accountRootPubkey: "ROOT-PUBKEY",
};
const ENDPOINT = "https://fcm.googleapis.com/fcm/send/subscription-237";
const INBOX_URL = `${RELAY}/acct_push_237/devices/dev_push_237/inbox`;
const PUSH_TOKENS_URL = `${RELAY}/acct_push_237/devices/dev_push_237/push-tokens`;
const VAPID_URL = `${RELAY}/.well-known/allw/vapid-public-key`;

/** A valid uncompressed P-256 point shape: 0x04 then 64 bytes. */
const VAPID_KEY = Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 0x04 : i));
const VAPID_KEY_B64URL = Buffer.from(VAPID_KEY).toString("base64url");

const DESKTOP_CHROME_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const IPHONE_SAFARI_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
const IPADOS_SAFARI_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";

/** A JSON `Response`. */
function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A recording fetch whose answers come from `route(url, init)` (a Response or an Error to throw). */
function fakeFetch(route) {
  const calls = [];
  const impl = async (url, init = {}) => {
    calls.push({ url, init });
    const answer = route(url, init);
    if (answer instanceof Error) throw answer;
    return answer;
  };
  return { impl, calls };
}

/** An in-memory credential store. */
function memoryPushStore({ credentials = null, registration = null } = {}) {
  const state = { credentials, registration };
  const writes = [];
  return {
    state,
    writes,
    async readCredentials() {
      return state.credentials;
    },
    async writeCredentials(value) {
      writes.push(["credentials", value]);
      state.credentials = value;
    },
    async readRegistration() {
      return state.registration;
    },
    async writeRegistration(value) {
      writes.push(["registration", value]);
      state.registration = value;
    },
    async clear() {
      writes.push(["clear"]);
      state.credentials = null;
      state.registration = null;
    },
  };
}

/** A recording `showNotification`. */
function notificationSink() {
  const shown = [];
  return {
    shown,
    showNotification: async (title, options) => {
      shown.push({ title, options });
    },
  };
}

/** Two pending envelopes full of request data that must never reach a notification. */
function sensitiveInbox(prefix) {
  return {
    envelopes: [
      {
        id: `${prefix}-req-1`,
        summary: `${prefix} force-push to main`,
        actor: `${prefix}-agent`,
        cwd: `/home/${prefix}/secret-project`,
        context_ciphertext: `${prefix}-ciphertext`,
      },
      {
        id: `${prefix}-req-2`,
        summary: `${prefix} rm -rf build`,
        actor: `${prefix}-agent`,
        cwd: `/home/${prefix}`,
        context_ciphertext: `${prefix}-ciphertext-2`,
      },
    ],
  };
}

// ── Service worker: push ──────────────────────────────────────────────────────────────────────────

describe("handlePush — every push ends in a visible notification (#237)", () => {
  test("requests waiting: fetches the inbox with the device token and shows the count", async () => {
    const { impl, calls } = fakeFetch(() => json(200, sensitiveInbox("alpha")));
    const sink = notificationSink();
    await handlePush({
      store: memoryPushStore({ credentials: CREDENTIALS }),
      fetchImpl: impl,
      showNotification: sink.showNotification,
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, INBOX_URL);
    assert.equal(calls[0].init.headers.authorization, "Bearer device-token-237");
    assert.deepEqual(sink.shown, [
      {
        title: NOTIFICATION_TITLE,
        options: {
          body: "2 approval requests are waiting.",
          tag: NOTIFICATION_TAG,
          renotify: true,
          icon: "./icons/icon-192.png",
        },
      },
    ]);
  });

  test("the title and body are independent of envelope contents (no request plaintext)", async () => {
    const shownFor = async (inbox) => {
      const sink = notificationSink();
      await handlePush({
        store: memoryPushStore({ credentials: CREDENTIALS }),
        fetchImpl: fakeFetch(() => json(200, inbox)).impl,
        showNotification: sink.showNotification,
      });
      return sink.shown;
    };
    const alpha = await shownFor(sensitiveInbox("alpha"));
    const bravo = await shownFor(sensitiveInbox("bravo"));

    assert.deepEqual(alpha, bravo, "same count, different contents → identical notification");
    const rendered = JSON.stringify(alpha);
    for (const leaked of [
      "alpha",
      "force-push",
      "rm -rf",
      "agent",
      "/home",
      "ciphertext",
      "req-1",
    ]) {
      assert.ok(!rendered.includes(leaked), `notification must not contain '${leaked}'`);
    }
  });

  test("a single pending request reads naturally", () => {
    assert.equal(notificationForPendingCount(1).options.body, "1 approval request is waiting.");
  });

  test("an empty inbox (answered elsewhere, expired, or coalesced) still shows a notification", async () => {
    const sink = notificationSink();
    await handlePush({
      store: memoryPushStore({ credentials: CREDENTIALS }),
      fetchImpl: fakeFetch(() => json(200, { envelopes: [] })).impl,
      showNotification: sink.showNotification,
    });
    assert.equal(sink.shown.length, 1);
    assert.equal(sink.shown[0].title, NOTIFICATION_TITLE);
    assert.equal(sink.shown[0].options.body, EMPTY_INBOX_BODY);
  });

  for (const [label, route] of [
    ["the relay is unreachable", () => new TypeError("Failed to fetch")],
    ["the relay answers 401", () => json(401, { error: "unauthorized" })],
    ["the relay answers 503", () => json(503, { error: "unavailable" })],
    ["the body is not JSON", () => new Response("<html>", { status: 200 })],
    ["the body has no envelopes array", () => json(200, { envelopes: "nope" })],
  ]) {
    test(`still shows the generic notification when ${label}`, async () => {
      const sink = notificationSink();
      await handlePush({
        store: memoryPushStore({ credentials: CREDENTIALS }),
        fetchImpl: fakeFetch(route).impl,
        showNotification: sink.showNotification,
      });
      assert.equal(sink.shown.length, 1);
      assert.equal(sink.shown[0].options.body, UNKNOWN_INBOX_BODY);
    });
  }

  test("with no mirrored credentials, shows the generic notification and makes no request", async () => {
    const { impl, calls } = fakeFetch(() => json(200, sensitiveInbox("x")));
    const sink = notificationSink();
    await handlePush({
      store: memoryPushStore(),
      fetchImpl: impl,
      showNotification: sink.showNotification,
    });
    assert.equal(calls.length, 0);
    assert.equal(sink.shown[0].options.body, UNKNOWN_INBOX_BODY);
  });

  test("a storage failure still ends in a notification", async () => {
    const sink = notificationSink();
    await handlePush({
      store: {
        readCredentials: async () => {
          throw new Error("IndexedDB unavailable");
        },
      },
      fetchImpl: fakeFetch(() => json(200, { envelopes: [] })).impl,
      showNotification: sink.showNotification,
    });
    assert.equal(sink.shown[0].options.body, UNKNOWN_INBOX_BODY);
  });
});

// ── Service worker: notification tap ─────────────────────────────────────────────────────────────

/**
 * A relay that accepts a request and then stalls must not hold a push hostage: browsers end the push
 * event with no notification, and Safari revokes subscriptions whose pushes show nothing. Every relay
 * call has a deadline covering headers and body (review of #315, finding 1).
 */
describe("relay deadline — a stalled relay still ends in a notification (#237)", () => {
  const SHORT = 30;
  const never = () => new Promise(() => {});

  /** A 200 whose body never finishes: a real `Response` over a stream that never closes. */
  function stalledBody() {
    return new Response(new ReadableStream({ start() {} }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }

  test("a fetch that never answers shows the generic notification", async () => {
    const { showNotification: show, shown } = notificationSink();
    await handlePush({
      store: memoryPushStore({ credentials: CREDENTIALS }),
      fetchImpl: never,
      showNotification: show,
      relayTimeoutMs: SHORT,
    });
    assert.equal(shown.length, 1);
    assert.equal(shown[0].options.body, UNKNOWN_INBOX_BODY);
    assert.equal(shown[0].options.tag, NOTIFICATION_TAG);
  });

  test("headers that arrive with a body that stalls show the generic notification", async () => {
    const { showNotification: show, shown } = notificationSink();
    await handlePush({
      store: memoryPushStore({ credentials: CREDENTIALS }),
      fetchImpl: async () => stalledBody(),
      showNotification: show,
      relayTimeoutMs: SHORT,
    });
    assert.equal(shown.length, 1);
    assert.equal(shown[0].options.body, UNKNOWN_INBOX_BODY);
  });

  test("a credential read that never settles still shows the generic notification", async () => {
    const { showNotification: show, shown } = notificationSink();
    await handlePush({
      store: { readCredentials: never },
      fetchImpl: () => assert.fail("no relay call without credentials"),
      showNotification: show,
      relayTimeoutMs: SHORT,
    });
    assert.equal(shown.length, 1);
    assert.equal(shown[0].options.body, UNKNOWN_INBOX_BODY);
  });

  test("the deadline aborts the request, so a real fetch stops reading", async () => {
    let signal;
    const count = await fetchPendingCount(
      CREDENTIALS,
      (_url, init) => {
        signal = init.signal;
        return never();
      },
      SHORT,
    );
    assert.equal(count, null);
    assert.ok(signal instanceof AbortSignal);
    assert.equal(signal.aborted, true);
  });

  test("a resubscribe whose relay calls stall fails instead of hanging", async () => {
    for (const fetchImpl of [never, async () => stalledBody()]) {
      const result = await handleSubscriptionChange({
        store: memoryPushStore({ credentials: CREDENTIALS }),
        fetchImpl,
        newSubscription: null,
        resubscribe: async () => ({ endpoint: ENDPOINT }),
        relayTimeoutMs: SHORT,
      });
      assert.equal(result.status, "failed");
      assert.match(result.reason, /did not answer within/);
    }
  });

  test("a registration whose PUT stalls fails instead of hanging", async () => {
    const result = await registerPushEndpoint(CREDENTIALS, ENDPOINT, never, SHORT);
    assert.equal(result.ok, false);
    assert.equal(result.status, null);
  });
});

describe("handleNotificationClick (#237)", () => {
  const APP_URL = "https://approver.example/";

  function windowClient(url) {
    const client = {
      url,
      focused: 0,
      async focus() {
        client.focused++;
      },
    };
    return client;
  }

  test("focuses an open approver window instead of opening another", async () => {
    let closed = 0;
    const opened = [];
    const other = windowClient("https://elsewhere.example/");
    const approver = windowClient(`${APP_URL}?relay=x`);
    await handleNotificationClick({
      closeNotification: () => {
        closed++;
      },
      matchWindows: async () => [other, approver],
      openWindow: async (url) => {
        opened.push(url);
      },
      appUrl: APP_URL,
    });
    assert.equal(closed, 1);
    assert.equal(approver.focused, 1);
    assert.equal(other.focused, 0);
    assert.deepEqual(opened, []);
  });

  test("opens the app when no approver window is open", async () => {
    const opened = [];
    await handleNotificationClick({
      closeNotification: () => undefined,
      matchWindows: async () => [windowClient("https://elsewhere.example/")],
      openWindow: async (url) => {
        opened.push(url);
      },
      appUrl: APP_URL,
    });
    assert.deepEqual(opened, [APP_URL]);
  });
});

// ── Service worker: subscription change ──────────────────────────────────────────────────────────

describe("handleSubscriptionChange — re-register when the browser replaces the subscription (#237)", () => {
  test("a credential store that rejects is a failed result, never a rejected event", async () => {
    const store = memoryPushStore({ credentials: CREDENTIALS });
    store.readCredentials = async () => {
      throw new Error("IndexedDB blocked");
    };
    const result = await handleSubscriptionChange({
      store,
      fetchImpl: () => assert.fail("no relay call without credentials"),
      newSubscription: { endpoint: ENDPOINT },
      resubscribe: async () => assert.fail("no resubscribe"),
    });
    assert.equal(result.status, "failed");
    assert.match(result.reason, /could not read the notification credentials/);
  });

  test("a registration record that can't be written is a failed result, never a rejected event", async () => {
    const store = memoryPushStore({ credentials: CREDENTIALS });
    store.writeRegistration = async () => {
      throw new Error("QuotaExceededError");
    };
    const result = await handleSubscriptionChange({
      store,
      fetchImpl: fakeFetch(() =>
        json(200, { push_tokens: [{ transport: "webpush", token: ENDPOINT }] }),
      ).impl,
      newSubscription: { endpoint: ENDPOINT },
      resubscribe: async () => assert.fail("no resubscribe"),
    });
    assert.equal(result.status, "failed");
    assert.match(result.reason, /could not record the registration/);
  });

  const NEW_ENDPOINT = "https://fcm.googleapis.com/fcm/send/replacement-237";

  test("registers the browser-provided new subscription and records it", async () => {
    const store = memoryPushStore({ credentials: CREDENTIALS });
    const { impl, calls } = fakeFetch(() =>
      json(200, { push_tokens: [{ transport: "webpush", token: NEW_ENDPOINT }] }),
    );
    const result = await handleSubscriptionChange({
      store,
      fetchImpl: impl,
      newSubscription: { endpoint: NEW_ENDPOINT },
      resubscribe: async () => assert.fail("must not resubscribe when a new subscription is given"),
    });
    assert.deepEqual(result, { status: "registered", endpoint: NEW_ENDPOINT });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, PUSH_TOKENS_URL);
    assert.equal(calls[0].init.method, "PUT");
    assert.deepEqual(store.state.registration, { ...pick(CREDENTIALS), endpoint: NEW_ENDPOINT });
  });

  test("without a new subscription, subscribes again with the relay's VAPID key, then registers", async () => {
    const store = memoryPushStore({ credentials: CREDENTIALS });
    const { impl } = fakeFetch((url) =>
      url === VAPID_URL
        ? json(200, { vapid_public_key: VAPID_KEY_B64URL })
        : json(200, { push_tokens: [{ transport: "webpush", token: NEW_ENDPOINT }] }),
    );
    const keys = [];
    const result = await handleSubscriptionChange({
      store,
      fetchImpl: impl,
      newSubscription: null,
      resubscribe: async (key) => {
        keys.push([...key]);
        return { endpoint: NEW_ENDPOINT };
      },
    });
    assert.equal(result.status, "registered");
    assert.deepEqual(keys, [[...VAPID_KEY]]);
  });

  test("does nothing when notifications were never enabled (no mirrored credentials)", async () => {
    const { impl, calls } = fakeFetch(() => assert.fail("no request expected"));
    const result = await handleSubscriptionChange({
      store: memoryPushStore(),
      fetchImpl: impl,
      newSubscription: { endpoint: NEW_ENDPOINT },
      resubscribe: async () => assert.fail("no resubscribe expected"),
    });
    assert.equal(result.status, "skipped");
    assert.equal(calls.length, 0);
  });

  test("a refused registration is a failure and records nothing", async () => {
    const store = memoryPushStore({ credentials: CREDENTIALS });
    const result = await handleSubscriptionChange({
      store,
      fetchImpl: fakeFetch(() => json(400, { error: "bad push_token" })).impl,
      newSubscription: { endpoint: NEW_ENDPOINT },
      resubscribe: async () => assert.fail("no resubscribe expected"),
    });
    assert.equal(result.status, "failed");
    assert.equal(store.state.registration, null);
  });
});

/** The registration-record fields shared with the credentials. */
function pick({ relayUrl, accountId, deviceId }) {
  return { relayUrl, accountId, deviceId };
}

// ── Relay calls ──────────────────────────────────────────────────────────────────────────────────

describe("relay calls (#237)", () => {
  test("fetchVapidPublicKey decodes the relay's 65-byte uncompressed P-256 key", async () => {
    const { impl, calls } = fakeFetch(() => json(200, { vapid_public_key: VAPID_KEY_B64URL }));
    const result = await fetchVapidPublicKey(RELAY, impl);
    assert.equal(calls[0].url, VAPID_URL);
    assert.equal(result.ok, true);
    assert.deepEqual([...result.key], [...VAPID_KEY]);
  });

  test("fetchVapidPublicKey reports a 404 as notifications disabled on the relay", async () => {
    const result = await fetchVapidPublicKey(RELAY, fakeFetch(() => json(404, {})).impl);
    assert.deepEqual({ ok: result.ok, reason: result.reason }, { ok: false, reason: "disabled" });
  });

  for (const [label, body] of [
    ["a key of the wrong length", { vapid_public_key: Buffer.alloc(33, 4).toString("base64url") }],
    [
      "a compressed point (no 0x04 prefix)",
      { vapid_public_key: Buffer.alloc(65, 2).toString("base64url") },
    ],
    ["a key that is not base64url", { vapid_public_key: "not base64url!" }],
    ["a missing key", {}],
  ]) {
    test(`fetchVapidPublicKey rejects ${label}`, async () => {
      const result = await fetchVapidPublicKey(RELAY, fakeFetch(() => json(200, body)).impl);
      assert.equal(result.ok, false);
      assert.equal(result.reason, "failed");
    });
  }

  test("registerPushEndpoint PUTs the device's complete token set with its bearer token (#236 contract)", async () => {
    const { impl, calls } = fakeFetch(() =>
      json(200, { push_tokens: [{ transport: "webpush", token: ENDPOINT }] }),
    );
    const result = await registerPushEndpoint(CREDENTIALS, ENDPOINT, impl);
    assert.deepEqual(result, { ok: true });
    assert.equal(calls[0].url, PUSH_TOKENS_URL);
    assert.equal(calls[0].init.method, "PUT");
    assert.equal(calls[0].init.headers.authorization, "Bearer device-token-237");
    assert.equal(calls[0].init.headers["content-type"], "application/json");
    assert.deepEqual(JSON.parse(calls[0].init.body), {
      push_tokens: [{ transport: "webpush", token: ENDPOINT }],
    });
  });

  test("registerPushEndpoint accepts the relay's normalized (URL.href) form of the endpoint", async () => {
    // The relay stores webpush tokens as URL.href (docs/relay-api.md §3), e.g. a lowercased host.
    const spelled = "https://FCM.googleapis.com/fcm/send/subscription-237";
    const result = await registerPushEndpoint(
      CREDENTIALS,
      spelled,
      fakeFetch(() => json(200, { push_tokens: [{ transport: "webpush", token: ENDPOINT }] })).impl,
    );
    assert.deepEqual(result, { ok: true });
  });

  test("registerPushEndpoint fails when the relay's stored set lacks the endpoint", async () => {
    const result = await registerPushEndpoint(
      CREDENTIALS,
      ENDPOINT,
      fakeFetch(() => json(200, { push_tokens: [] })).impl,
    );
    assert.equal(result.ok, false);
    assert.match(result.detail, /did not store/);
  });

  for (const status of [400, 401, 404, 409]) {
    test(`registerPushEndpoint reports a ${String(status)} as a failure with the status`, async () => {
      const result = await registerPushEndpoint(
        CREDENTIALS,
        ENDPOINT,
        fakeFetch(() => json(status, { error: "no" })).impl,
      );
      assert.deepEqual({ ok: result.ok, status: result.status }, { ok: false, status });
    });
  }

  test("a 409 says the budget is full and how to free a registration (#236: 409, nothing changes)", async () => {
    const result = await registerPushEndpoint(
      CREDENTIALS,
      ENDPOINT,
      fakeFetch(() => json(409, { error: "account push-token limit reached" })).impl,
    );
    assert.equal(result.ok, false);
    assert.match(result.detail, /as many push registrations as the relay allows \(409\)/);
    // The advice names the one shipped action that frees a registration (forgetting the pairing on
    // another browser clears its tokens); revoking another device isn't available yet (#204).
    assert.match(result.detail, /in a browser you no longer use and choose .Use another device./);
  });

  for (const status of [401, 403]) {
    test(`a ${String(status)} says the relay refused this device's credentials`, async () => {
      const result = await registerPushEndpoint(
        CREDENTIALS,
        ENDPOINT,
        fakeFetch(() => json(status, { error: "unauthorized" })).impl,
      );
      assert.match(result.detail, /refused this device's credentials/);
    });
  }

  test("clearPushTokens PUTs an empty token set with the device's bearer token (#236: [] clears)", async () => {
    const { impl, calls } = fakeFetch(() => json(200, { push_tokens: [] }));
    const result = await clearPushTokens(CREDENTIALS, impl);
    assert.deepEqual(result, { ok: true });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, PUSH_TOKENS_URL);
    assert.equal(calls[0].init.method, "PUT");
    assert.equal(calls[0].init.headers.authorization, `Bearer ${CREDENTIALS.deviceAuthToken}`);
    assert.deepEqual(JSON.parse(calls[0].init.body), { push_tokens: [] });
  });

  test("clearPushTokens fails when the relay still lists tokens", async () => {
    const result = await clearPushTokens(
      CREDENTIALS,
      fakeFetch(() => json(200, { push_tokens: [{ transport: "webpush", token: ENDPOINT }] })).impl,
    );
    assert.equal(result.ok, false);
  });

  test("clearPushTokens reports a non-200 or a network error as a failure, never a throw", async () => {
    const refused = await clearPushTokens(CREDENTIALS, fakeFetch(() => json(401, {})).impl);
    assert.deepEqual({ ok: refused.ok, status: refused.status }, { ok: false, status: 401 });
    const offline = await clearPushTokens(
      CREDENTIALS,
      fakeFetch(() => new TypeError("Failed to fetch")).impl,
    );
    assert.deepEqual({ ok: offline.ok, status: offline.status }, { ok: false, status: null });
  });

  test("registerPushEndpoint reports a network error as a failure, never a throw", async () => {
    const result = await registerPushEndpoint(
      CREDENTIALS,
      ENDPOINT,
      fakeFetch(() => new TypeError("Failed to fetch")).impl,
    );
    assert.deepEqual({ ok: result.ok, status: result.status }, { ok: false, status: null });
  });

  test("fetchPendingCount returns only the number of envelopes", async () => {
    const count = await fetchPendingCount(
      CREDENTIALS,
      fakeFetch(() => json(200, sensitiveInbox("z"))).impl,
    );
    assert.equal(count, 2);
  });

  test("decodeBase64Url rejects characters outside the alphabet", () => {
    assert.equal(decodeBase64Url("ab+c"), null);
    assert.equal(decodeBase64Url("a"), null);
    assert.deepEqual([...decodeBase64Url("AQID")], [1, 2, 3]);
  });
});

// ── Credential mirror ─────────────────────────────────────────────────────────────────────────────

describe("credential mirror — only the four relay fields, never seeds (#237)", () => {
  test("pushCredentialsFrom copies exactly relayUrl, accountId, deviceId and deviceAuthToken", () => {
    const mirrored = pushCredentialsFrom(IDENTITY);
    assert.deepEqual(Object.keys(mirrored).sort(), [
      "accountId",
      "deviceAuthToken",
      "deviceId",
      "relayUrl",
    ]);
    assert.ok(!JSON.stringify(mirrored).includes("SECRET"), "no seed may be mirrored");
  });

  test("parsePushCredentials accepts exactly the four fields", () => {
    assert.deepEqual(parsePushCredentials({ ...CREDENTIALS }), CREDENTIALS);
  });

  for (const [label, value] of [
    ["an extra field (e.g. a seed)", { ...CREDENTIALS, deviceSigningSeed: "SECRET" }],
    ["a missing field", { relayUrl: RELAY, accountId: "a", deviceId: "d" }],
    ["an empty field", { ...CREDENTIALS, deviceAuthToken: "" }],
    ["a plaintext http:// remote relay", { ...CREDENTIALS, relayUrl: "http://relay.example.com" }],
    ["a non-canonical relay", { ...CREDENTIALS, relayUrl: "https://relay.example.com/" }],
    ["an array", [CREDENTIALS]],
    ["null", null],
  ]) {
    test(`parsePushCredentials rejects ${label}`, () => {
      assert.equal(parsePushCredentials(value), null);
    });
  }

  test("parsePushRegistration requires the four registration fields", () => {
    const registration = { ...pick(CREDENTIALS), endpoint: ENDPOINT };
    assert.deepEqual(parsePushRegistration({ ...registration }), registration);
    assert.equal(parsePushRegistration({ ...registration, endpoint: "" }), null);
    assert.equal(parsePushRegistration({ ...registration, extra: "x" }), null);
  });
});

// ── Forgetting a pairing ────────────────────────────────────────────────────────────────────────

/**
 * A pairing that is forgotten ("Use another device", re-pair, a corrupt or absent identity) must
 * not leave its bearer token behind in the service worker's mirror, where the worker would keep
 * using it on every push.
 */
describe("forgetNotifications — the mirror never outlives the pairing (#237)", () => {
  /** A subscription that records when it was dropped, into the shared `events` log. */
  function recordingSubscription(events) {
    return {
      endpoint: ENDPOINT,
      async unsubscribe() {
        events.push("unsubscribe");
        return true;
      },
    };
  }

  test("clears the mirror first, drops the subscription, then clears the relay's tokens", async () => {
    const events = [];
    const store = memoryPushStore({
      credentials: CREDENTIALS,
      registration: { ...pick(CREDENTIALS), endpoint: ENDPOINT },
    });
    const originalClear = store.clear;
    store.clear = async () => {
      events.push("clear");
      await originalClear();
    };
    const { impl, calls } = fakeFetch((url, init) => {
      events.push(`${init.method} ${url}`);
      return json(200, { push_tokens: [] });
    });

    await forgetNotifications({
      store,
      fetchImpl: impl,
      getSubscription: async () => recordingSubscription(events),
    });

    assert.equal(store.state.credentials, null, "the bearer token is gone from the mirror");
    assert.equal(store.state.registration, null);
    // Local steps finish before the network one, so a slow relay can't undo a later subscription.
    assert.deepEqual(events, ["clear", "unsubscribe", `PUT ${PUSH_TOKENS_URL}`]);
    assert.equal(calls[0].init.headers.authorization, `Bearer ${CREDENTIALS.deviceAuthToken}`);
    assert.deepEqual(JSON.parse(calls[0].init.body), { push_tokens: [] });
  });

  test("with nothing mirrored, it still clears and unsubscribes, and makes no relay call", async () => {
    const events = [];
    const store = memoryPushStore();
    const { impl, calls } = fakeFetch(() => json(200, { push_tokens: [] }));
    await forgetNotifications({
      store,
      fetchImpl: impl,
      getSubscription: async () => recordingSubscription(events),
    });
    assert.deepEqual(store.writes, [["clear"]]);
    assert.deepEqual(events, ["unsubscribe"]);
    assert.equal(calls.length, 0);
  });

  test("an unreachable relay or a failing subscription never throws, and the mirror is cleared", async () => {
    const store = memoryPushStore({ credentials: CREDENTIALS });
    await forgetNotifications({
      store,
      fetchImpl: fakeFetch(() => new TypeError("Failed to fetch")).impl,
      getSubscription: async () => {
        throw new Error("push service unavailable");
      },
    });
    assert.equal(store.state.credentials, null);
  });

  test("an unreadable mirror is still cleared", async () => {
    const store = memoryPushStore({ credentials: CREDENTIALS });
    store.readCredentials = async () => {
      throw new Error("IndexedDB read failed");
    };
    const { impl, calls } = fakeFetch(() => json(200, { push_tokens: [] }));
    await forgetNotifications({ store, fetchImpl: impl, getSubscription: null });
    assert.equal(store.state.credentials, null);
    assert.equal(calls.length, 0, "no token was read, so none is sent");
  });
});

// ── Page controls ─────────────────────────────────────────────────────────────────────────────────

describe("pushAvailability — the iOS Home Screen requirement (#237)", () => {
  const base = {
    userAgent: DESKTOP_CHROME_UA,
    maxTouchPoints: 0,
    isStandalone: false,
    registerServiceWorker: async () => assert.fail("not called"),
    notifications: { permission: () => "default", requestPermission: async () => "default" },
    fetchImpl: async () => assert.fail("not called"),
    store: memoryPushStore(),
  };

  test("iPhone Safari in a tab needs installing to the Home Screen", () => {
    assert.equal(pushAvailability({ ...base, userAgent: IPHONE_SAFARI_UA }), "ios-needs-install");
  });

  test("iPadOS (desktop-class Mac user agent on a touch device) needs installing too", () => {
    assert.equal(isAppleMobile(IPADOS_SAFARI_UA, 5), true);
    assert.equal(
      pushAvailability({ ...base, userAgent: IPADOS_SAFARI_UA, maxTouchPoints: 5 }),
      "ios-needs-install",
    );
  });

  test("a real Mac (same user agent, no touch) is not treated as iOS", () => {
    assert.equal(isAppleMobile(IPADOS_SAFARI_UA, 0), false);
    assert.equal(pushAvailability({ ...base, userAgent: IPADOS_SAFARI_UA }), "available");
  });

  test("the installed iOS web app (standalone) can enable notifications", () => {
    assert.equal(
      pushAvailability({ ...base, userAgent: IPHONE_SAFARI_UA, isStandalone: true }),
      "available",
    );
  });

  test("a browser without service workers / Push API is unsupported", () => {
    assert.equal(pushAvailability({ ...base, registerServiceWorker: null }), "unsupported");
    assert.equal(pushAvailability({ ...base, notifications: null }), "unsupported");
  });
});

describe("mountNotificationControls (#237)", () => {
  let dom;
  let host;
  let savedDocument;

  beforeEach(() => {
    dom = new JSDOM('<div id="notifications"></div>', { url: "https://approver.example/" });
    savedDocument = globalThis.document;
    globalThis.document = dom.window.document;
    host = dom.window.document.getElementById("notifications");
  });

  afterEach(() => {
    globalThis.document = savedDocument;
  });

  function subscriptionFor(endpoint) {
    const subscription = {
      endpoint,
      unsubscribed: false,
      async unsubscribe() {
        subscription.unsubscribed = true;
        return true;
      },
    };
    return subscription;
  }

  /** A full injected environment; `relay` answers the VAPID key and push-token PUT. */
  function environment({
    userAgent = DESKTOP_CHROME_UA,
    isStandalone = false,
    permission = "default",
    grant = "granted",
    existing = null,
    store = memoryPushStore(),
    relay = (url) =>
      url === VAPID_URL
        ? json(200, { vapid_public_key: VAPID_KEY_B64URL })
        : json(200, { push_tokens: [{ transport: "webpush", token: ENDPOINT }] }),
    supported = true,
  } = {}) {
    let currentPermission = permission;
    let subscription = existing;
    const subscribeCalls = [];
    let registrations = 0;
    const { impl, calls } = fakeFetch(relay);
    const env = {
      userAgent,
      maxTouchPoints: 0,
      isStandalone,
      registerServiceWorker: supported
        ? async () => {
            registrations++;
            return {
              pushManager: {
                getSubscription: async () => subscription,
                subscribe: async (options) => {
                  subscribeCalls.push(options);
                  subscription = subscriptionFor(ENDPOINT);
                  return subscription;
                },
              },
            };
          }
        : null,
      notifications: supported
        ? {
            permission: () => currentPermission,
            requestPermission: async () => {
              currentPermission = grant;
              return grant;
            },
          }
        : null,
      fetchImpl: impl,
      store,
    };
    return {
      env,
      calls,
      subscribeCalls,
      store,
      registrations: () => registrations,
    };
  }

  const text = () => host.querySelector(".push-controls-text")?.textContent ?? "";
  const button = () => host.querySelector("button.push-controls-btn");

  /**
   * Another tab forgets (or replaces) the pairing while this tab's controls are up (review of #315,
   * finding 2). The controls must not write the forgotten token back into the shared mirror, and
   * must not re-register it with the relay.
   */
  test("a forget during an in-flight enable writes nothing and sends no PUT", async () => {
    const t = environment();
    let releasePermission;
    t.env.notifications.requestPermission = () =>
      new Promise((resolve) => {
        releasePermission = () => resolve("granted");
      });
    let paired = true;
    const controls = mountNotificationControls({
      host,
      identity: IDENTITY,
      env: t.env,
      isStillPaired: () => paired,
    });
    await controls.ready;
    const enabling = controls.enable();
    await waitFor(() => releasePermission !== undefined);

    // Tab B: "Use another device" while the permission prompt is open here.
    paired = false;
    await forgetNotifications({
      store: t.store,
      fetchImpl: t.env.fetchImpl,
      getSubscription: null,
    });
    releasePermission();

    assert.deepEqual(await enabling, { kind: "off", note: PAIRING_CHANGED_NOTE });
    assert.deepEqual(t.store.writes, [["clear"]], "only the forget touched the mirror");
    assert.equal(t.store.state.credentials, null);
    assert.ok(
      t.calls.every((call) => call.init.method !== "PUT"),
      "no push-token PUT reached the relay",
    );
    assert.equal(text(), PAIRING_CHANGED_NOTE);
  });

  test("a forget during the registration PUT withdraws it and writes nothing", async () => {
    let paired = true;
    const t = environment({
      relay: (url, init) => {
        if (url === VAPID_URL) return json(200, { vapid_public_key: VAPID_KEY_B64URL });
        const tokens = JSON.parse(init.body).push_tokens;
        // Tab B forgets the pairing while this registration is in flight.
        if (tokens.length > 0) paired = false;
        return json(200, { push_tokens: tokens });
      },
    });
    const controls = mountNotificationControls({
      host,
      identity: IDENTITY,
      env: t.env,
      isStillPaired: () => paired,
    });
    await controls.ready;
    assert.deepEqual(await controls.enable(), { kind: "off", note: PAIRING_CHANGED_NOTE });

    const puts = t.calls.filter((call) => call.init.method === "PUT");
    assert.deepEqual(
      puts.map((call) => JSON.parse(call.init.body)),
      [{ push_tokens: [{ transport: "webpush", token: ENDPOINT }] }, { push_tokens: [] }],
      "the registration is withdrawn",
    );
    assert.deepEqual(t.store.writes, [], "nothing was mirrored");
  });

  test("on load, a pairing forgotten elsewhere is not re-mirrored", async () => {
    const store = memoryPushStore({ registration: { ...pick(CREDENTIALS), endpoint: ENDPOINT } });
    const t = environment({
      permission: "granted",
      existing: subscriptionFor(ENDPOINT),
      store,
    });
    const controls = mountNotificationControls({
      host,
      identity: IDENTITY,
      env: t.env,
      isStillPaired: () => false,
    });
    assert.deepEqual(await controls.ready, { kind: "off", note: PAIRING_CHANGED_NOTE });
    assert.deepEqual(store.writes, []);
    assert.equal(t.calls.length, 0);
  });

  test("iOS in a browser tab shows Home Screen instructions instead of the enable button", async () => {
    const t = environment({ userAgent: IPHONE_SAFARI_UA });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    assert.deepEqual(await controls.ready, { kind: "ios-needs-install" });
    assert.match(text(), /Add to Home Screen/);
    assert.equal(button(), null);
    assert.equal(t.registrations(), 0, "no service worker registration attempted");
  });

  test("the installed iOS app shows the enable button", async () => {
    const t = environment({ userAgent: IPHONE_SAFARI_UA, isStandalone: true });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    assert.equal((await controls.ready).kind, "off");
    assert.equal(button().textContent, "Enable notifications");
  });

  test("an unsupported browser says so, and keeps approving in the tab possible", async () => {
    const t = environment({ supported: false });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    assert.deepEqual(await controls.ready, { kind: "unsupported" });
    assert.match(text(), /Keep this tab open/);
  });

  test("permission already denied is shown on load, with how to fix it", async () => {
    const t = environment({ permission: "denied" });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    assert.deepEqual(await controls.ready, { kind: "denied" });
    assert.match(text(), /blocked for this site/);
    assert.equal(button(), null);
  });

  test("enable: permission → VAPID key → userVisibleOnly subscribe → mirror → PUT → on", async () => {
    const t = environment();
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    assert.equal((await controls.ready).kind, "off");
    assert.equal(t.calls.length, 0, "nothing is sent before the human acts");

    assert.deepEqual(await controls.enable(), { kind: "on" });

    assert.equal(t.subscribeCalls.length, 1);
    assert.equal(t.subscribeCalls[0].userVisibleOnly, true);
    assert.deepEqual([...t.subscribeCalls[0].applicationServerKey], [...VAPID_KEY]);
    assert.deepEqual(
      t.calls.map((call) => [call.init.method, call.url]),
      [
        ["GET", VAPID_URL],
        ["PUT", PUSH_TOKENS_URL],
      ],
    );
    assert.deepEqual(
      t.store.state.credentials,
      CREDENTIALS,
      "exactly the four fields are mirrored",
    );
    assert.ok(!JSON.stringify(t.store.writes).includes("SECRET"), "no seed is ever written");
    assert.deepEqual(t.store.state.registration, { ...pick(CREDENTIALS), endpoint: ENDPOINT });
    assert.match(text(), /Notifications are on/);
  });

  test("the enable button runs the flow", async () => {
    const t = environment();
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    await controls.ready;
    button().click();
    await waitFor(() => controls.state().kind === "on");
    assert.equal(t.subscribeCalls.length, 1);
  });

  test("denying the permission prompt shows the denied state and subscribes nothing", async () => {
    const t = environment({ grant: "denied" });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    await controls.ready;
    assert.deepEqual(await controls.enable(), { kind: "denied" });
    assert.equal(t.subscribeCalls.length, 0);
    assert.equal(t.calls.length, 0);
  });

  test("dismissing the permission prompt leaves notifications off with a note", async () => {
    const t = environment({ grant: "default" });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    await controls.ready;
    const state = await controls.enable();
    assert.equal(state.kind, "off");
    assert.match(state.note, /weren't turned on/);
    assert.equal(button().textContent, "Enable notifications");
  });

  test("a relay with Web Push disabled (VAPID 404) is a visible state, not an error loop", async () => {
    const t = environment({ relay: () => json(404, {}) });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    await controls.ready;
    assert.deepEqual(await controls.enable(), { kind: "relay-disabled" });
    assert.equal(t.subscribeCalls.length, 0);
    assert.match(text(), /doesn't send notifications/);
  });

  test("a failed registration is shown with a retry, and never throws", async () => {
    const t = environment({
      relay: (url) =>
        url === VAPID_URL ? json(200, { vapid_public_key: VAPID_KEY_B64URL }) : json(503, {}),
    });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    await controls.ready;
    const state = await controls.enable();
    assert.equal(state.kind, "failed");
    assert.match(text(), /Couldn't turn on notifications: the relay answered 503/);
    assert.match(text(), /You can still approve with this tab open/);
    assert.equal(button().textContent, "Try again");
    assert.equal(t.store.state.registration, null, "nothing recorded as registered");
  });

  test("a subscribe() rejection (e.g. no push service) is a visible failure", async () => {
    const t = environment();
    const original = t.env.registerServiceWorker;
    t.env.registerServiceWorker = async () => {
      const registration = await original();
      registration.pushManager.subscribe = async () => {
        throw new Error("Registration failed - push service error");
      };
      return registration;
    };
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    await controls.ready;
    const state = await controls.enable();
    assert.equal(state.kind, "failed");
    assert.match(state.detail, /push service error/);
  });

  test("on load, an already-registered subscription for this device is on, with no request", async () => {
    const store = memoryPushStore({
      registration: { ...pick(CREDENTIALS), endpoint: ENDPOINT },
    });
    const t = environment({ permission: "granted", existing: subscriptionFor(ENDPOINT), store });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    assert.deepEqual(await controls.ready, { kind: "on" });
    assert.equal(t.calls.length, 0);
    assert.deepEqual(store.state.credentials, CREDENTIALS, "the mirror is refreshed");
  });

  test("on load, a changed endpoint is re-registered", async () => {
    const store = memoryPushStore({
      registration: { ...pick(CREDENTIALS), endpoint: "https://fcm.googleapis.com/fcm/send/old" },
    });
    const t = environment({ permission: "granted", existing: subscriptionFor(ENDPOINT), store });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    assert.deepEqual(await controls.ready, { kind: "on" });
    assert.deepEqual(
      t.calls.map((call) => call.init.method),
      ["PUT"],
    );
    assert.equal(store.state.registration.endpoint, ENDPOINT);
  });

  test("on load, a subscription registered for a previous pairing is re-registered for this device", async () => {
    const store = memoryPushStore({
      registration: { ...pick(CREDENTIALS), deviceId: "dev_previous", endpoint: ENDPOINT },
    });
    const t = environment({ permission: "granted", existing: subscriptionFor(ENDPOINT), store });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    assert.deepEqual(await controls.ready, { kind: "on" });
    assert.equal(t.calls[0].url, PUSH_TOKENS_URL);
    assert.equal(store.state.registration.deviceId, CREDENTIALS.deviceId);
  });

  test("on load, a subscription made for another relay is dropped and the human is asked again", async () => {
    const existing = subscriptionFor(ENDPOINT);
    const store = memoryPushStore({
      registration: {
        ...pick(CREDENTIALS),
        relayUrl: "https://old-relay.example",
        endpoint: ENDPOINT,
      },
    });
    const t = environment({ permission: "granted", existing, store });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    const state = await controls.ready;
    assert.equal(state.kind, "off");
    assert.match(state.note, /different relay/);
    assert.equal(existing.unsubscribed, true);
    assert.equal(t.calls.length, 0);
  });

  test("on load, a granted permission with no subscription offers the enable button", async () => {
    const t = environment({ permission: "granted" });
    const controls = mountNotificationControls({ host, identity: IDENTITY, env: t.env });
    assert.deepEqual(await controls.ready, { kind: "off", note: null });
    assert.equal(button().textContent, "Enable notifications");
  });
});

/** Resolve once `probe()` is truthy, flushing microtasks; fail after a bounded number of ticks. */
async function waitFor(probe, ticks = 200) {
  for (let i = 0; i < ticks; i++) {
    if (probe()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.fail("condition not met within the tick budget");
}
