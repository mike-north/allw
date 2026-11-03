/**
 * What the web approver's service worker does on each event (issue #237), as plain functions over
 * injected dependencies so they run under `node:test` without a browser. `./sw.ts` is the thin
 * entry that wires them to the real service worker events.
 *
 * # Every push ends in a visible notification
 * Wakeups are payload-less (`docs/relay-api.md` §5): a push says only "look at your inbox". The
 * subscription is created with `userVisibleOnly: true`, and a push that shows no notification gets
 * the subscription throttled or revoked (Safari revokes after a few). By the time the worker fetches
 * the inbox it may already be empty, because another device answered, the request expired, or the
 * relay coalesced several submits into one wakeup. So {@link handlePush} shows a notification on
 * **every** path: requests waiting, inbox empty, inbox unreadable, or no credentials.
 *
 * # No request data in a notification
 * The notification title and body are fixed text plus, at most, the number of pending requests
 * ({@link notificationForPendingCount}). They never contain a summary, command, actor, cwd or any
 * other envelope field. The worker never decrypts: `fetchPendingCount` returns only a count, so
 * there is no request data in scope to leak. Deciding, number-match and signing happen only in the
 * full UI, behind the existing pairing gate.
 *
 * @see ./sw.ts (event wiring)
 * @see ./push-relay.ts (the relay calls)
 * @see ./push-credentials.ts (the credential mirror the worker reads)
 * @see ../../../docs/relay-api.md (§5 Web Push)
 */

import type { PushCredentialStore } from "./push-credentials.js";
import {
  fetchPendingCount,
  fetchVapidPublicKey,
  registerPushEndpoint,
  type PushFetch,
} from "./push-relay.js";

/** The fixed notification title. */
export const NOTIFICATION_TITLE = "allw approvals";

/**
 * The notification `tag`: each new notification replaces the previous one instead of stacking,
 * and `renotify` makes the replacement alert again.
 */
export const NOTIFICATION_TAG = "allw-approvals";

/** The body when the inbox was read and is empty. */
export const EMPTY_INBOX_BODY = "An approval request was handled or expired.";

/** The body when the inbox could not be read (or this browser has no credentials mirrored). */
export const UNKNOWN_INBOX_BODY = "Open allw approvals to check for approval requests.";

/** The subset of `NotificationOptions` the worker sets. */
export interface ApprovalNotificationOptions {
  readonly body: string;
  readonly tag: string;
  readonly renotify: boolean;
  readonly icon: string;
}

/** A notification to show: a title and its options. */
export interface ApprovalNotification {
  readonly title: string;
  readonly options: ApprovalNotificationOptions;
}

/** The notification icon, relative to the worker's scope. */
const NOTIFICATION_ICON = "./icons/icon-192.png";

/**
 * The notification for a wakeup, from the pending count alone: `null` when the inbox could not be
 * read. This is the only input, which is what keeps request data out of notifications.
 */
export function notificationForPendingCount(count: number | null): ApprovalNotification {
  let body: string;
  if (count === null) body = UNKNOWN_INBOX_BODY;
  else if (count === 0) body = EMPTY_INBOX_BODY;
  else if (count === 1) body = "1 approval request is waiting.";
  else body = `${String(count)} approval requests are waiting.`;
  return {
    title: NOTIFICATION_TITLE,
    options: { body, tag: NOTIFICATION_TAG, renotify: true, icon: NOTIFICATION_ICON },
  };
}

/** Dependencies of {@link handlePush}. */
export interface PushHandlerDeps {
  readonly store: Pick<PushCredentialStore, "readCredentials">;
  readonly fetchImpl: PushFetch;
  /** `registration.showNotification`. */
  readonly showNotification: (title: string, options: ApprovalNotificationOptions) => Promise<void>;
}

/**
 * Handle a `push`: read the mirrored credentials, count the pending requests, and show a
 * notification. A notification is shown whatever fails before it; only `showNotification` itself
 * can reject.
 */
export async function handlePush(deps: PushHandlerDeps): Promise<void> {
  let count: number | null = null;
  try {
    const credentials = await deps.store.readCredentials();
    if (credentials !== null) count = await fetchPendingCount(credentials, deps.fetchImpl);
  } catch {
    count = null;
  }
  const notification = notificationForPendingCount(count);
  await deps.showNotification(notification.title, notification.options);
}

/** A window client the worker can focus (the subset of `WindowClient` used here). */
export interface WindowClientLike {
  readonly url: string;
  focus(): Promise<unknown>;
}

/** Dependencies of {@link handleNotificationClick}. */
export interface NotificationClickDeps {
  /** Close the clicked notification. */
  readonly closeNotification: () => void;
  /** `clients.matchAll({ type: "window", includeUncontrolled: true })`. */
  readonly matchWindows: () => Promise<readonly WindowClientLike[]>;
  /** `clients.openWindow(url)`. */
  readonly openWindow: (url: string) => Promise<unknown>;
  /** The app's URL: the worker registration's scope. */
  readonly appUrl: string;
}

/**
 * Handle a notification tap: focus an open approver window if there is one, else open the app.
 * The app opens on its pairing gate as always; nothing here bypasses it.
 */
export async function handleNotificationClick(deps: NotificationClickDeps): Promise<void> {
  deps.closeNotification();
  const windows = await deps.matchWindows();
  const existing = windows.find((client) => client.url.startsWith(deps.appUrl));
  if (existing !== undefined) {
    await existing.focus();
    return;
  }
  await deps.openWindow(deps.appUrl);
}

/** Dependencies of {@link handleSubscriptionChange}. */
export interface SubscriptionChangeDeps {
  readonly store: PushCredentialStore;
  readonly fetchImpl: PushFetch;
  /** The event's `newSubscription`, when the browser provides one. */
  readonly newSubscription: { readonly endpoint: string } | null;
  /** `registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey })`. */
  readonly resubscribe: (
    applicationServerKey: Uint8Array<ArrayBuffer>,
  ) => Promise<{ readonly endpoint: string }>;
}

/** Outcome of {@link handleSubscriptionChange}, for logging and tests. */
export type SubscriptionChangeResult =
  | { readonly status: "registered"; readonly endpoint: string }
  | { readonly status: "skipped"; readonly reason: string }
  | { readonly status: "failed"; readonly reason: string };

/**
 * Handle `pushsubscriptionchange`: the browser replaced or expired the subscription, so register
 * the new endpoint with the relay (subscribing again first if the browser didn't). Without
 * mirrored credentials notifications were never enabled here, and nothing is done.
 */
export async function handleSubscriptionChange(
  deps: SubscriptionChangeDeps,
): Promise<SubscriptionChangeResult> {
  const credentials = await deps.store.readCredentials();
  if (credentials === null) return { status: "skipped", reason: "notifications not enabled" };

  let endpoint = deps.newSubscription?.endpoint;
  if (endpoint === undefined) {
    const key = await fetchVapidPublicKey(credentials.relayUrl, deps.fetchImpl);
    if (!key.ok) return { status: "failed", reason: key.detail };
    try {
      endpoint = (await deps.resubscribe(key.key)).endpoint;
    } catch (error) {
      return { status: "failed", reason: `could not subscribe again (${String(error)})` };
    }
  }

  const registered = await registerPushEndpoint(credentials, endpoint, deps.fetchImpl);
  if (!registered.ok) return { status: "failed", reason: registered.detail };
  await deps.store.writeRegistration({
    relayUrl: credentials.relayUrl,
    accountId: credentials.accountId,
    deviceId: credentials.deviceId,
    endpoint,
  });
  return { status: "registered", endpoint };
}
