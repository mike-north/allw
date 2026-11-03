/**
 * The page-side notification controls (issue #237): after pairing, an explicit "Enable
 * notifications" action subscribes this browser to Web Push and registers the subscription with
 * the relay as the device's `webpush` push token.
 *
 * # The flow
 * 1. **Availability.** iOS and iPadOS deliver Web Push only to a web app installed to the Home
 *    Screen (Safari 16.4+), so an Apple mobile browser that is not running standalone gets
 *    install instructions instead of the button. A browser without service workers, the Push API
 *    or notifications gets a plain "not available" note.
 * 2. **On load** the service worker (`./sw.ts`, served as `./sw.js`) is registered at the app's
 *    root scope. If notifications are already permitted and a subscription exists, the credential
 *    mirror is refreshed and the subscription is re-registered when it differs from the last one
 *    registered for this device (new endpoint, new pairing).
 * 3. **Enable** (a user gesture): request permission → fetch the relay's VAPID public key →
 *    `pushManager.subscribe({ userVisibleOnly: true, applicationServerKey })` → mirror the four
 *    credential fields to IndexedDB → `PUT` the endpoint as the device's push token.
 *
 * # Never in the way of approving
 * Every outcome, including denied, unsupported and failed, is a visible state in this control's
 * own host element, outside the inbox. Nothing here blocks, delays or gates the inbox: with the tab
 * open the approver works exactly as before. Every error is caught and shown, never thrown.
 *
 * @see ./sw-handlers.ts (what the worker does with a push)
 * @see ./push-credentials.ts (the IndexedDB credential mirror)
 * @see ./push-relay.ts (the relay calls)
 * @see https://developer.apple.com/documentation/usernotifications/sending-web-push-notifications-in-web-apps-and-browsers
 * @see ../../../docs/web-approver-deploy.md (§Notifications)
 */

import {
  pushCredentialsFrom,
  type PushCredentialStore,
  type PushCredentials,
  type PushRegistration,
} from "./push-credentials.js";
import {
  clearPushTokens,
  fetchVapidPublicKey,
  registerPushEndpoint,
  type PushFetch,
} from "./push-relay.js";

/** A push subscription (the part of `PushSubscription` used here). */
export interface PushSubscriptionLike {
  readonly endpoint: string;
  unsubscribe(): Promise<boolean>;
}

/** The part of a `ServiceWorkerRegistration` used here. */
export interface PushServiceWorkerRegistration {
  readonly pushManager: {
    getSubscription(): Promise<PushSubscriptionLike | null>;
    subscribe(options: {
      userVisibleOnly: true;
      applicationServerKey: Uint8Array<ArrayBuffer>;
    }): Promise<PushSubscriptionLike>;
  };
}

/** Everything the controls read from the browser, injectable for tests. */
export interface PushEnvironment {
  /** `navigator.userAgent`. */
  readonly userAgent: string;
  /** `navigator.maxTouchPoints` (tells iPadOS, which reports a Mac user agent, from a Mac). */
  readonly maxTouchPoints: number;
  /** Whether the app is running installed (`display-mode: standalone`, or iOS `navigator.standalone`). */
  readonly isStandalone: boolean;
  /**
   * Register the service worker at the app's root scope and resolve once it is active
   * (`pushManager.subscribe` needs an active worker). `null` when service workers or the Push API
   * are unavailable.
   */
  readonly registerServiceWorker: (() => Promise<PushServiceWorkerRegistration>) | null;
  /** The Notifications permission API, or `null` when unavailable. */
  readonly notifications: {
    permission(): NotificationPermission;
    requestPermission(): Promise<NotificationPermission>;
  } | null;
  readonly fetchImpl: PushFetch;
  readonly store: PushCredentialStore;
}

/**
 * Whether this is iOS or iPadOS: an iPhone/iPad/iPod user agent, or iPadOS's desktop-class "Mac"
 * user agent on a touch device. Every iOS browser runs WebKit and has the same Home Screen
 * requirement for Web Push, so this is not limited to Safari.
 */
export function isAppleMobile(userAgent: string, maxTouchPoints: number): boolean {
  return (
    /\b(iPhone|iPad|iPod)\b/.test(userAgent) ||
    (/\bMacintosh\b/.test(userAgent) && maxTouchPoints > 1)
  );
}

/** What the controls can offer in this browser. */
export type PushAvailability = "available" | "ios-needs-install" | "unsupported";

/** Decide what the controls can offer before touching any browser API. */
export function pushAvailability(env: PushEnvironment): PushAvailability {
  if (isAppleMobile(env.userAgent, env.maxTouchPoints) && !env.isStandalone) {
    return "ios-needs-install";
  }
  if (env.registerServiceWorker === null || env.notifications === null) return "unsupported";
  return "available";
}

/** Every state the controls can show. */
export type NotificationControlState =
  | { readonly kind: "checking" }
  | { readonly kind: "ios-needs-install" }
  | { readonly kind: "unsupported" }
  | { readonly kind: "off"; readonly note: string | null }
  | { readonly kind: "working" }
  | { readonly kind: "on" }
  | { readonly kind: "denied" }
  | { readonly kind: "relay-disabled" }
  | { readonly kind: "failed"; readonly detail: string };

/** The paired identity's fields the controls need (pinned relay + bearer token). */
export interface PushIdentity {
  readonly relayUrl: string;
  readonly accountId: string;
  readonly deviceId: string;
  readonly deviceAuthToken: string;
}

/** Options for {@link mountNotificationControls}. */
export interface NotificationControlsOptions {
  /** The element the controls render into, outside the inbox. */
  readonly host: HTMLElement;
  /** The paired identity; only its four relay-credential fields are used. */
  readonly identity: PushIdentity;
  readonly env: PushEnvironment;
  /**
   * Whether `identity` is still this browser's pairing (same device and bearer token). Another tab
   * can forget or replace the pairing while these controls are mounted; the controls check this
   * right before registering with the relay and again before writing the credential mirror, so a
   * forgotten identity is never re-mirrored or re-registered. Defaults to always true.
   */
  readonly isStillPaired?: () => boolean;
}

/** The mounted controls: the current state and the enable action, for tests and callers. */
export interface NotificationControls {
  /** The state currently shown. */
  state(): NotificationControlState;
  /** Run the enable flow, as the button does. Resolves to the resulting state. */
  enable(): Promise<NotificationControlState>;
  /** Resolves once the on-load check has finished. */
  readonly ready: Promise<NotificationControlState>;
}

/** Whether `registration` records `endpoint` for this exact device and relay. */
function isCurrentRegistration(
  registration: PushRegistration | null,
  credentials: PushCredentials,
  endpoint: string,
): boolean {
  return (
    registration !== null &&
    registration.relayUrl === credentials.relayUrl &&
    registration.accountId === credentials.accountId &&
    registration.deviceId === credentials.deviceId &&
    registration.endpoint === endpoint
  );
}

/** Shown when another tab forgot or replaced this browser's pairing while the controls were up. */
export const PAIRING_CHANGED_NOTE =
  "This browser's pairing changed in another tab. Reload the page to set up notifications.";

/**
 * Register `endpoint` with the relay, then mirror the credentials and record the registration.
 * The pairing is re-checked before the relay call and again before anything is written: if it was
 * forgotten meanwhile, nothing is mirrored, and a registration already sent is withdrawn (best
 * effort), so a forgotten identity's token never returns to the mirror or the relay.
 */
async function registerSubscription(
  env: PushEnvironment,
  credentials: PushCredentials,
  endpoint: string,
  isStillPaired: () => boolean,
): Promise<NotificationControlState> {
  if (!isStillPaired()) return { kind: "off", note: PAIRING_CHANGED_NOTE };
  const result = await registerPushEndpoint(credentials, endpoint, env.fetchImpl);
  if (!result.ok) return { kind: "failed", detail: result.detail };
  if (!isStillPaired()) {
    await clearPushTokens(credentials, env.fetchImpl);
    return { kind: "off", note: PAIRING_CHANGED_NOTE };
  }
  await env.store.writeCredentials(credentials);
  await env.store.writeRegistration({
    relayUrl: credentials.relayUrl,
    accountId: credentials.accountId,
    deviceId: credentials.deviceId,
    endpoint,
  });
  return { kind: "on" };
}

/** A message for an unexpected rejection. */
function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Small DOM helper. */
function el<Tag extends keyof HTMLElementTagNameMap>(
  tag: Tag,
  className: string,
  textContent?: string,
): HTMLElementTagNameMap[Tag] {
  const element = document.createElement(tag);
  element.className = className;
  if (textContent !== undefined) element.textContent = textContent;
  return element;
}

/** The text shown for each state. */
function messageFor(state: NotificationControlState): string {
  switch (state.kind) {
    case "ios-needs-install":
      return "To get notifications on iPhone or iPad, add allw approvals to your Home Screen: tap the Share button, choose Add to Home Screen, then open allw approvals from the Home Screen and enable notifications there.";
    case "unsupported":
      return "This browser can't show allw notifications. Keep this tab open to see approval requests.";
    case "off":
      return (
        state.note ??
        "Get a notification when an approval request arrives. It says only that a request is waiting, never what it is."
      );
    case "checking":
      return "Checking notifications…";
    case "working":
      return "Turning on notifications…";
    case "on":
      return "Notifications are on for this browser.";
    case "denied":
      return "Notifications are blocked for this site. To turn them on, allow notifications for this site in your browser settings. You can still approve with this tab open.";
    case "relay-disabled":
      return "Your relay doesn't send notifications. Keep this tab open to see approval requests.";
    case "failed":
      return `Couldn't turn on notifications: ${state.detail}. You can still approve with this tab open.`;
  }
}

/** Render `state` into `host`, wiring the enable button when the state offers one. */
function render(host: HTMLElement, state: NotificationControlState, onEnable: () => void): void {
  const box = el("section", `push-controls push-controls--${state.kind}`);
  box.setAttribute("aria-live", "polite");
  box.append(el("p", "push-controls-text", messageFor(state)));
  if (state.kind === "off" || state.kind === "failed" || state.kind === "working") {
    const button = el(
      "button",
      "push-controls-btn",
      state.kind === "failed" ? "Try again" : "Enable notifications",
    );
    button.type = "button";
    button.disabled = state.kind === "working";
    button.addEventListener("click", onEnable);
    box.append(button);
  }
  host.replaceChildren(box);
}

/**
 * Mount the notification controls for a paired identity. Returns immediately; the on-load check
 * runs in the background and its result is rendered (and available as `ready`).
 */
export function mountNotificationControls(
  options: NotificationControlsOptions,
): NotificationControls {
  const { host, env } = options;
  const isStillPaired = options.isStillPaired ?? (() => true);
  const credentials = pushCredentialsFrom(options.identity);
  let current: NotificationControlState = { kind: "checking" };
  let enabling = false;
  let registrationPromise: Promise<PushServiceWorkerRegistration> | null = null;

  function show(state: NotificationControlState): NotificationControlState {
    current = state;
    render(host, state, () => {
      void enable();
    });
    return state;
  }

  function serviceWorker(): Promise<PushServiceWorkerRegistration> {
    if (env.registerServiceWorker === null) throw new Error("service workers are unavailable");
    registrationPromise ??= env.registerServiceWorker();
    return registrationPromise;
  }

  async function onLoad(): Promise<NotificationControlState> {
    const availability = pushAvailability(env);
    if (availability !== "available" || env.notifications === null) {
      return show({
        kind: availability === "ios-needs-install" ? "ios-needs-install" : "unsupported",
      });
    }
    if (env.notifications.permission() === "denied") return show({ kind: "denied" });
    try {
      const registration = await serviceWorker();
      if (env.notifications.permission() !== "granted") return show({ kind: "off", note: null });
      const subscription = await registration.pushManager.getSubscription();
      if (subscription === null) return show({ kind: "off", note: null });
      const last = await env.store.readRegistration();
      if (last !== null && last.relayUrl !== credentials.relayUrl) {
        // A subscription made for another relay was signed for that relay's VAPID key, so this
        // relay's pushes would never arrive on it. Drop it; the human enables again.
        await subscription.unsubscribe();
        return show({
          kind: "off",
          note: "This browser was paired with a different relay. Enable notifications again to get them from this one.",
        });
      }
      if (isCurrentRegistration(last, credentials, subscription.endpoint)) {
        if (!isStillPaired()) return show({ kind: "off", note: PAIRING_CHANGED_NOTE });
        await env.store.writeCredentials(credentials);
        return show({ kind: "on" });
      }
      return show(
        await registerSubscription(env, credentials, subscription.endpoint, isStillPaired),
      );
    } catch (error) {
      return show({ kind: "failed", detail: describe(error) });
    }
  }

  async function enable(): Promise<NotificationControlState> {
    // A second click while an attempt runs is ignored (the button is disabled meanwhile).
    if (enabling) return current;
    if (env.notifications === null) return show({ kind: "unsupported" });
    enabling = true;
    show({ kind: "working" });
    try {
      const permission = await env.notifications.requestPermission();
      if (permission === "denied") return show({ kind: "denied" });
      if (permission !== "granted") {
        return show({
          kind: "off",
          note: "Notifications weren't turned on. Enable them whenever you like.",
        });
      }
      const key = await fetchVapidPublicKey(credentials.relayUrl, env.fetchImpl);
      if (!key.ok) {
        return show(
          key.reason === "disabled"
            ? { kind: "relay-disabled" }
            : { kind: "failed", detail: key.detail },
        );
      }
      const registration = await serviceWorker();
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: key.key,
      });
      return show(
        await registerSubscription(env, credentials, subscription.endpoint, isStillPaired),
      );
    } catch (error) {
      return show({ kind: "failed", detail: describe(error) });
    } finally {
      enabling = false;
    }
  }

  show({ kind: "checking" });
  const ready = onLoad();
  return { state: () => current, enable, ready };
}

/** What {@link forgetNotifications} needs, injectable for tests. */
export interface ForgetNotificationsDeps {
  readonly store: PushCredentialStore;
  readonly fetchImpl: PushFetch;
  /**
   * This origin's current push subscription, without registering a service worker; `null` when
   * the Push API is unavailable.
   */
  readonly getSubscription: (() => Promise<PushSubscriptionLike | null>) | null;
}

/**
 * Undo notifications for a pairing that is being forgotten ("Use another device", re-pair, a
 * corrupt or absent identity at boot). The mirrored bearer token must not outlive the identity it
 * belongs to, so the mirror is cleared **first**, before anything that can fail. Then, best effort,
 * the browser's subscription is dropped so no further pushes arrive. Both are local and quick, and
 * finish before the network step, so a slow relay can't make this undo a subscription the human
 * creates after re-pairing. Last, the relay is told to drop this device's push tokens, using the
 * token read just before the clear. Never throws.
 */
export async function forgetNotifications(deps: ForgetNotificationsDeps): Promise<void> {
  let credentials: PushCredentials | null = null;
  try {
    credentials = await deps.store.readCredentials();
  } catch {
    // Unreadable: clear below regardless.
  }
  try {
    await deps.store.clear();
  } catch {
    // IndexedDB unavailable: nothing was mirrored, or nothing more can be done here.
  }
  try {
    const subscription = deps.getSubscription === null ? null : await deps.getSubscription();
    await subscription?.unsubscribe();
  } catch {
    // Best effort: the service worker shows only its generic notification without credentials.
  }
  if (credentials !== null) await clearPushTokens(credentials, deps.fetchImpl);
}

/** The production {@link ForgetNotificationsDeps}, read from `window`. */
export function browserForgetNotificationsDeps(
  win: Window & typeof globalThis,
  store: PushCredentialStore,
): ForgetNotificationsDeps {
  const nav = win.navigator;
  const pushSupported = "serviceWorker" in nav && "PushManager" in win;
  return {
    store,
    fetchImpl: (input, init) => win.fetch(input, init),
    getSubscription: pushSupported
      ? async () => {
          const registration = await nav.serviceWorker.getRegistration("./");
          return registration === undefined ? null : registration.pushManager.getSubscription();
        }
      : null,
  };
}

/** The production {@link PushEnvironment}, read from `window`. */
export function browserPushEnvironment(
  win: Window & typeof globalThis,
  store: PushCredentialStore,
): PushEnvironment {
  const nav = win.navigator as Navigator & { readonly standalone?: boolean };
  const pushSupported = "serviceWorker" in nav && "PushManager" in win;
  const notificationApi = "Notification" in win ? win.Notification : null;
  return {
    userAgent: nav.userAgent,
    maxTouchPoints: nav.maxTouchPoints,
    isStandalone: win.matchMedia("(display-mode: standalone)").matches || nav.standalone === true,
    registerServiceWorker: pushSupported
      ? async () => {
          await nav.serviceWorker.register("./sw.js", { scope: "./" });
          return nav.serviceWorker.ready;
        }
      : null,
    notifications:
      notificationApi === null
        ? null
        : {
            permission: () => notificationApi.permission,
            requestPermission: () => notificationApi.requestPermission(),
          },
    fetchImpl: (input, init) => win.fetch(input, init),
    store,
  };
}
