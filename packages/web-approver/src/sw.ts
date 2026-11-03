/**
 * The web approver's service worker (issue #237), bundled by `scripts/build-site.mjs` to
 * `dist-site/sw.js` and registered by the page at the app's root scope (`./push-subscribe.ts`).
 *
 * It does exactly three things, all delegated to `./sw-handlers.ts`:
 *
 * - `push` → count pending requests and **always** show a notification with fixed text.
 * - `notificationclick` → focus an open approver window, or open the app.
 * - `pushsubscriptionchange` → register the replacement subscription with the relay.
 *
 * It caches nothing and intercepts no fetches: the approver works with the tab open exactly as
 * before, whether or not this worker is installed. It never decrypts, signs or verifies.
 *
 * The workspace typechecks against the DOM library, so the service worker globals are described by
 * the minimal structural types below rather than the separate `WebWorker` library.
 *
 * @see ./sw-handlers.ts
 * @see https://www.w3.org/TR/push-api/#extensions-to-the-serviceworkerglobalscope-interface
 */

import { createIndexedDbPushCredentialStore } from "./push-credentials.js";
import {
  handleNotificationClick,
  handlePush,
  handleSubscriptionChange,
  type WindowClientLike,
} from "./sw-handlers.js";

/** `ExtendableEvent`: keeps the worker alive until the handler's promise settles. */
interface ExtendableEventLike {
  waitUntil(promise: Promise<unknown>): void;
}

/** `NotificationEvent`. */
interface NotificationEventLike extends ExtendableEventLike {
  readonly notification: { close(): void };
}

/** `PushSubscriptionChangeEvent`. */
interface PushSubscriptionChangeEventLike extends ExtendableEventLike {
  readonly newSubscription?: PushSubscription | null;
}

/** The parts of `ServiceWorkerGlobalScope` this worker uses. */
interface ServiceWorkerScopeLike {
  readonly registration: ServiceWorkerRegistration;
  readonly clients: {
    matchAll(options: {
      type: "window";
      includeUncontrolled: boolean;
    }): Promise<readonly WindowClientLike[]>;
    openWindow(url: string): Promise<unknown>;
    claim(): Promise<void>;
  };
  readonly indexedDB: IDBFactory;
  fetch(input: string, init?: RequestInit): Promise<Response>;
  skipWaiting(): Promise<void>;
  addEventListener(
    type: "install" | "activate" | "push",
    listener: (event: ExtendableEventLike) => void,
  ): void;
  addEventListener(
    type: "notificationclick",
    listener: (event: NotificationEventLike) => void,
  ): void;
  addEventListener(
    type: "pushsubscriptionchange",
    listener: (event: PushSubscriptionChangeEventLike) => void,
  ): void;
}

/** Wire the handlers to the worker's events. */
function installServiceWorker(scope: ServiceWorkerScopeLike): void {
  const store = createIndexedDbPushCredentialStore(scope.indexedDB);
  const fetchImpl = (input: string, init?: RequestInit) => scope.fetch(input, init);

  // Take over immediately on install/update: the worker holds no cache, so an old and a new
  // version never need to coexist.
  scope.addEventListener("install", (event) => {
    event.waitUntil(scope.skipWaiting());
  });
  scope.addEventListener("activate", (event) => {
    event.waitUntil(scope.clients.claim());
  });

  scope.addEventListener("push", (event) => {
    event.waitUntil(
      handlePush({
        store,
        fetchImpl,
        showNotification: (title, options) => scope.registration.showNotification(title, options),
      }),
    );
  });

  scope.addEventListener("notificationclick", (event) => {
    event.waitUntil(
      handleNotificationClick({
        closeNotification: () => {
          event.notification.close();
        },
        matchWindows: () => scope.clients.matchAll({ type: "window", includeUncontrolled: true }),
        openWindow: (url) => scope.clients.openWindow(url),
        appUrl: scope.registration.scope,
      }),
    );
  });

  scope.addEventListener("pushsubscriptionchange", (event) => {
    event.waitUntil(
      handleSubscriptionChange({
        store,
        fetchImpl,
        newSubscription: event.newSubscription ?? null,
        resubscribe: (applicationServerKey) =>
          scope.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey }),
      }),
    );
  });
}

// Only inside a real service worker: importing this module anywhere else (a test, a bundler
// probe) must not register listeners on the wrong global.
if ("ServiceWorkerGlobalScope" in globalThis) {
  installServiceWorker(globalThis as unknown as ServiceWorkerScopeLike);
}
