/**
 * The service worker's copy of the device's relay credentials (issue #237).
 *
 * A service worker cannot read `localStorage`, where the pairing store keeps the paired identity
 * (`./pairing.ts`). To fetch the inbox when a push arrives it needs the **minimum** to authenticate
 * one relay call: the pinned relay URL, the account id, the device id, and the device's bearer
 * `deviceAuthToken`. This module mirrors exactly those four values into IndexedDB, which both the
 * page and the service worker can read. It **never** mirrors the device seeds, the device cert or
 * the account root key: the service worker only counts pending requests, it never decrypts, signs
 * or verifies anything (decision and number-match stay in the full UI).
 *
 * The same store also records which push subscription was last registered with the relay for which
 * device (`PushRegistration`), so the page can re-register when the subscription or the pairing
 * changes. The endpoint URL is not a secret, but it is kept in a separate record so the credential
 * record stays exactly the four fields above.
 *
 * Both records are re-validated on read; anything malformed reads as absent (fail-closed: the
 * service worker then shows its generic notification and makes no relay call).
 *
 * # Storage tradeoff
 * The bearer token in IndexedDB has the same exposure as the full identity in `localStorage`: any
 * script running on the approver origin can read it (`docs/threat-model.md`). Mirroring it adds no
 * new reader; it is written only once the human enables notifications. It must also never outlive
 * the pairing: whenever the paired identity is forgotten, the mirror is cleared with it
 * (`forgetNotifications` in `./push-subscribe.ts`), so a forgotten device's token is not left
 * behind for the service worker to keep using.
 *
 * @see ./sw-handlers.ts (the service worker's reader)
 * @see ./push-subscribe.ts (the page-side writer)
 * @see ../../../docs/web-approver-deploy.md (§Notifications)
 */

import { checkRelayUrl } from "./relay-config.js";

/** The relay credentials a service worker needs for one authenticated inbox fetch. */
export interface PushCredentials {
  /** The pinned, canonical relay URL (`checkRelayUrl`'s form). */
  readonly relayUrl: string;
  readonly accountId: string;
  readonly deviceId: string;
  /** The device's own bearer token for its relay endpoints. */
  readonly deviceAuthToken: string;
}

/** Which push subscription endpoint was last registered with the relay, for which device. */
export interface PushRegistration {
  readonly relayUrl: string;
  readonly accountId: string;
  readonly deviceId: string;
  /** The `PushSubscription.endpoint` that the relay accepted as this device's `webpush` token. */
  readonly endpoint: string;
}

/** Persistence for the service worker's credential mirror and the last registration. */
export interface PushCredentialStore {
  /** The mirrored credentials, or `null` when absent or malformed. */
  readCredentials(): Promise<PushCredentials | null>;
  /** Replace the mirrored credentials. */
  writeCredentials(credentials: PushCredentials): Promise<void>;
  /** The last registration, or `null` when absent or malformed. */
  readRegistration(): Promise<PushRegistration | null>;
  /** Replace the last registration. */
  writeRegistration(registration: PushRegistration): Promise<void>;
  /**
   * Delete both records. Called when this browser's pairing is forgotten, so the bearer token
   * leaves the origin together with the identity it belongs to.
   */
  clear(): Promise<void>;
}

/**
 * The four credential fields from a paired identity, and nothing else. A structural copy, so the
 * seeds, cert and root key on the identity object can never ride along into storage.
 */
export function pushCredentialsFrom(identity: {
  readonly relayUrl: string;
  readonly accountId: string;
  readonly deviceId: string;
  readonly deviceAuthToken: string;
}): PushCredentials {
  return {
    relayUrl: identity.relayUrl,
    accountId: identity.accountId,
    deviceId: identity.deviceId,
    deviceAuthToken: identity.deviceAuthToken,
  };
}

/** A plain object with only string-keyed own properties. */
function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0
  );
}

/** Whether `record` has exactly `keys`, each a non-empty string. */
function hasExactStringFields(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(record);
  if (own.length !== keys.length) return false;
  return keys.every((key) => {
    const value = record[key];
    return typeof value === "string" && value.length > 0;
  });
}

/** Whether `relayUrl` is a relay URL this build accepts, already in canonical form. */
function isCanonicalRelayUrl(relayUrl: string): boolean {
  const checked = checkRelayUrl(relayUrl);
  return checked.ok && checked.relayUrl === relayUrl;
}

const CREDENTIAL_KEYS = ["relayUrl", "accountId", "deviceId", "deviceAuthToken"] as const;
const REGISTRATION_KEYS = ["relayUrl", "accountId", "deviceId", "endpoint"] as const;

/**
 * Narrow a stored value to {@link PushCredentials}: exactly the four fields, non-empty strings, and
 * a relay URL this build accepts. Anything else (including extra fields) is `null`.
 */
export function parsePushCredentials(value: unknown): PushCredentials | null {
  if (!isPlainRecord(value) || !hasExactStringFields(value, CREDENTIAL_KEYS)) return null;
  const credentials = value as unknown as PushCredentials;
  return isCanonicalRelayUrl(credentials.relayUrl) ? credentials : null;
}

/** Narrow a stored value to {@link PushRegistration}; anything else is `null`. */
export function parsePushRegistration(value: unknown): PushRegistration | null {
  if (!isPlainRecord(value) || !hasExactStringFields(value, REGISTRATION_KEYS)) return null;
  return value as unknown as PushRegistration;
}

/** The IndexedDB database, object store and keys the mirror uses. */
const DB_NAME = "allw-push";
const DB_VERSION = 1;
const OBJECT_STORE = "kv";
const CREDENTIALS_KEY = "credentials";
const REGISTRATION_KEY = "registration";

/** Promisify one `IDBRequest`. */
function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => {
      resolve(request.result);
    };
    request.onerror = () => {
      reject(request.error ?? new Error("IndexedDB request failed"));
    };
  });
}

/** Open (creating on first use) the mirror database. */
function openDatabase(factory: IDBFactory): Promise<IDBDatabase> {
  const request = factory.open(DB_NAME, DB_VERSION);
  request.onupgradeneeded = () => {
    if (!request.result.objectStoreNames.contains(OBJECT_STORE)) {
      request.result.createObjectStore(OBJECT_STORE);
    }
  };
  return requestResult(request);
}

/**
 * A {@link PushCredentialStore} backed by IndexedDB, readable from both the page and the service
 * worker. Pass the global `indexedDB` (page: `window.indexedDB`; worker: `self.indexedDB`).
 */
export function createIndexedDbPushCredentialStore(factory: IDBFactory): PushCredentialStore {
  async function read(key: string): Promise<unknown> {
    const db = await openDatabase(factory);
    try {
      return await requestResult(
        db.transaction(OBJECT_STORE, "readonly").objectStore(OBJECT_STORE).get(key),
      );
    } finally {
      db.close();
    }
  }

  async function write(key: string, value: unknown): Promise<void> {
    const db = await openDatabase(factory);
    try {
      await requestResult(
        db.transaction(OBJECT_STORE, "readwrite").objectStore(OBJECT_STORE).put(value, key),
      );
    } finally {
      db.close();
    }
  }

  async function clearAll(): Promise<void> {
    const db = await openDatabase(factory);
    try {
      await requestResult(
        db.transaction(OBJECT_STORE, "readwrite").objectStore(OBJECT_STORE).clear(),
      );
    } finally {
      db.close();
    }
  }

  return {
    async readCredentials() {
      return parsePushCredentials(await read(CREDENTIALS_KEY));
    },
    async writeCredentials(credentials) {
      await write(CREDENTIALS_KEY, pushCredentialsFrom(credentials));
    },
    async readRegistration() {
      return parsePushRegistration(await read(REGISTRATION_KEY));
    },
    async writeRegistration(registration) {
      await write(REGISTRATION_KEY, {
        relayUrl: registration.relayUrl,
        accountId: registration.accountId,
        deviceId: registration.deviceId,
        endpoint: registration.endpoint,
      });
    },
    clear: clearAll,
  };
}
