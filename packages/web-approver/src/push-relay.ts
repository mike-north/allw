/**
 * The three relay calls behind web approver notifications (issue #237).
 *
 * - {@link fetchVapidPublicKey}: `GET /.well-known/allw/vapid-public-key` (no auth). The relay's
 *   VAPID public key, which `PushManager.subscribe()` takes as `applicationServerKey`. A 404 means
 *   the relay has Web Push disabled.
 * - {@link registerPushEndpoint}: `PUT /{acct}/devices/{device_id}/push-tokens` with the device's
 *   own bearer token. The body is the device's **complete** token set,
 *   `{ push_tokens: [{ transport: "webpush", token: <endpoint> }] }`; the relay replaces the stored
 *   set and answers `200 { push_tokens: [...] }` with what it stored (issue #236).
 * - {@link fetchPendingCount}: `GET /{acct}/devices/{device_id}/inbox`. Only the **number** of
 *   pending envelopes leaves this module, never their contents, so no caller can put request data
 *   into a notification.
 *
 * Every call takes an injectable `fetch` and reports failure as a value, never a throw, so the
 * page's controls and the service worker's handlers can always reach a visible end state. Every call
 * also has a deadline ({@link RELAY_CALL_TIMEOUT_MS}) covering the response headers **and** body: a
 * relay that accepts a request and then stalls is a failure, not a wait without end. That matters
 * most in the service worker, which must show a notification for every push (browsers revoke
 * subscriptions whose pushes show nothing).
 *
 * @see ../../../docs/relay-api.md (§3 relay-level and device endpoints, §5 Web Push)
 * @see https://www.rfc-editor.org/rfc/rfc8292 (VAPID)
 */

import type { PushCredentials } from "./push-credentials.js";
import { inboxUrl } from "./relay-poll.js";

/** An injectable `fetch`. */
export type PushFetch = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * How long one relay call may take, headers and body together, before it counts as failed. Well
 * inside the time browsers give a push event, so a stalled relay still leaves the service worker
 * time to show its generic notification.
 */
export const RELAY_CALL_TIMEOUT_MS = 8_000;

/** What came back from one relay call, within its deadline. */
type RelayAnswer =
  | { readonly reached: false; readonly detail: string }
  | {
      readonly reached: true;
      readonly status: number;
      /** The parsed JSON body of a 2xx answer; `null` for a non-2xx answer (body not read). */
      readonly json: { readonly ok: true; readonly value: unknown } | { readonly ok: false } | null;
    };

/**
 * Make one relay call and, for a 2xx answer, read its JSON body, all within `timeoutMs`. On the
 * deadline the request is aborted (so a real `fetch` stops reading too) and the call resolves as
 * unreached. Never throws.
 */
async function callRelay(
  fetchImpl: PushFetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<RelayAnswer> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<RelayAnswer>((resolve) => {
    timer = setTimeout(() => {
      resolve({
        reached: false,
        detail: `the relay did not answer within ${String(timeoutMs / 1000)} s`,
      });
      controller.abort(new Error("relay call deadline"));
    }, timeoutMs);
  });
  const call = async (): Promise<RelayAnswer> => {
    let response: Response;
    try {
      response = await fetchImpl(url, { ...init, signal: controller.signal });
    } catch (error) {
      return { reached: false, detail: `could not reach the relay (${String(error)})` };
    }
    if (!response.ok) return { reached: true, status: response.status, json: null };
    try {
      return {
        reached: true,
        status: response.status,
        json: { ok: true, value: (await response.json()) as unknown },
      };
    } catch {
      return { reached: true, status: response.status, json: { ok: false } };
    }
  };
  try {
    return await Promise.race([call(), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/** `field` of a JSON object body, or `undefined`. */
function jsonField(value: unknown, field: string): unknown {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)[field]
    : undefined;
}

/** Strip trailing slashes from a relay base URL. */
function relayBase(relayUrl: string): string {
  return relayUrl.replace(/\/+$/, "");
}

/** `<relay>/.well-known/allw/vapid-public-key`. */
export function vapidPublicKeyUrl(relayUrl: string): string {
  return `${relayBase(relayUrl)}/.well-known/allw/vapid-public-key`;
}

/** `<relay>/<acct>/devices/<device>/push-tokens`. */
export function pushTokensUrl(relayUrl: string, accountId: string, deviceId: string): string {
  return `${relayBase(relayUrl)}/${encodeURIComponent(accountId)}/devices/${encodeURIComponent(deviceId)}/push-tokens`;
}

/** Decode unpadded or padded base64url; `null` on any invalid character. */
export function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value)) return null;
  const base64 = value.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
  if (base64.length % 4 === 1) return null;
  let binary: string;
  try {
    binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  } catch {
    return null;
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Outcome of {@link fetchVapidPublicKey}. */
export type VapidKeyResult =
  | { readonly ok: true; readonly key: Uint8Array<ArrayBuffer> }
  | { readonly ok: false; readonly reason: "disabled" | "failed"; readonly detail: string };

/**
 * Fetch the relay's VAPID public key. The key must decode to an uncompressed P-256 point (65 bytes,
 * leading `0x04`); anything else is a failure rather than a subscription the relay can't sign for.
 */
export async function fetchVapidPublicKey(
  relayUrl: string,
  fetchImpl: PushFetch,
  timeoutMs: number = RELAY_CALL_TIMEOUT_MS,
): Promise<VapidKeyResult> {
  const answer = await callRelay(
    fetchImpl,
    vapidPublicKeyUrl(relayUrl),
    { method: "GET" },
    timeoutMs,
  );
  if (!answer.reached) return { ok: false, reason: "failed", detail: answer.detail };
  if (answer.status === 404) {
    return { ok: false, reason: "disabled", detail: "this relay has notifications turned off" };
  }
  if (answer.json === null) {
    return { ok: false, reason: "failed", detail: `the relay answered ${String(answer.status)}` };
  }
  if (!answer.json.ok) {
    return { ok: false, reason: "failed", detail: "the relay's key response was not JSON" };
  }
  const encoded = jsonField(answer.json.value, "vapid_public_key");
  const decoded = typeof encoded === "string" ? decodeBase64Url(encoded) : null;
  if (decoded?.length !== 65 || decoded[0] !== 0x04) {
    return { ok: false, reason: "failed", detail: "the relay's VAPID key is malformed" };
  }
  const key = new Uint8Array(new ArrayBuffer(65));
  key.set(decoded);
  return { ok: true, key };
}

/** Outcome of {@link registerPushEndpoint} and {@link clearPushTokens}. */
export type RegisterResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly status: number | null; readonly detail: string };

/** `URL.href` of `value`, the form the relay stores a `webpush` token in; `null` if unparseable. */
function normalizedEndpoint(value: string): string | null {
  try {
    return new URL(value).href;
  } catch {
    return null;
  }
}

/**
 * What a non-200 answer from `PUT …/push-tokens` means, for the human. The relay's statuses
 * (`docs/relay-api.md` §3): 401/403 when the device's own bearer token is refused (for example after
 * the device was revoked), 409 when the account's push-token budget is full, 400 for a body the
 * relay rejects. The 409 advice names the one action shipped today that frees a registration:
 * forgetting the pairing on another browser clears that device's push tokens. (Revoking another
 * device, e.g. a lost one, is not available yet: #204.)
 */
function describePushTokensStatus(status: number): string {
  switch (status) {
    case 401:
    case 403:
      return `the relay refused this device's credentials (${String(status)}); it may have been revoked`;
    case 409:
      return "this account already has as many push registrations as the relay allows (409). To free one, open allw approvals in a browser you no longer use and choose \u201cUse another device\u201d, then try again here";
    default:
      return `the relay answered ${String(status)}`;
  }
}

/** Outcome of {@link putPushTokens}: the stored set the relay returned, or why it failed. */
type PutPushTokensResult =
  | { readonly ok: true; readonly stored: readonly unknown[] }
  | { readonly ok: false; readonly status: number | null; readonly detail: string };

/**
 * Replace this device's push tokens with `tokens` (`PUT /{acct}/devices/{device_id}/push-tokens`,
 * authenticated with the device's own bearer token). `[]` clears the set. Resolves to the stored
 * set from a `200` answer; never throws.
 */
async function putPushTokens(
  credentials: PushCredentials,
  tokens: readonly { readonly transport: "webpush"; readonly token: string }[],
  fetchImpl: PushFetch,
  timeoutMs: number,
): Promise<PutPushTokensResult> {
  const answer = await callRelay(
    fetchImpl,
    pushTokensUrl(credentials.relayUrl, credentials.accountId, credentials.deviceId),
    {
      method: "PUT",
      headers: {
        authorization: `Bearer ${credentials.deviceAuthToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ push_tokens: tokens }),
    },
    timeoutMs,
  );
  if (!answer.reached) return { ok: false, status: null, detail: answer.detail };
  if (answer.status !== 200 || answer.json === null) {
    return {
      ok: false,
      status: answer.status,
      detail: describePushTokensStatus(answer.status),
    };
  }
  if (!answer.json.ok) {
    return { ok: false, status: 200, detail: "the relay's response was not JSON" };
  }
  const stored = jsonField(answer.json.value, "push_tokens");
  if (!Array.isArray(stored)) {
    return { ok: false, status: 200, detail: "the relay's response had no push_tokens list" };
  }
  return { ok: true, stored };
}

/**
 * Register `endpoint` as this device's only `webpush` token. Succeeds only on `200` with the
 * endpoint present in the stored set the relay returns, so a relay that silently dropped it is a
 * visible failure, not "notifications on".
 */
export async function registerPushEndpoint(
  credentials: PushCredentials,
  endpoint: string,
  fetchImpl: PushFetch,
  timeoutMs: number = RELAY_CALL_TIMEOUT_MS,
): Promise<RegisterResult> {
  const result = await putPushTokens(
    credentials,
    [{ transport: "webpush", token: endpoint }],
    fetchImpl,
    timeoutMs,
  );
  if (!result.ok) return result;
  const wanted = normalizedEndpoint(endpoint);
  const registered = result.stored.some((entry: unknown) => {
    if (typeof entry !== "object" || entry === null) return false;
    const { transport, token } = entry as Record<string, unknown>;
    return (
      transport === "webpush" &&
      typeof token === "string" &&
      wanted !== null &&
      normalizedEndpoint(token) === wanted
    );
  });
  if (!registered) {
    return { ok: false, status: 200, detail: "the relay did not store this subscription" };
  }
  return { ok: true };
}

/**
 * Clear every push token this device registered, so the relay stops sending it wakeups. Succeeds
 * only on `200` with an empty stored set.
 */
export async function clearPushTokens(
  credentials: PushCredentials,
  fetchImpl: PushFetch,
  timeoutMs: number = RELAY_CALL_TIMEOUT_MS,
): Promise<RegisterResult> {
  const result = await putPushTokens(credentials, [], fetchImpl, timeoutMs);
  if (!result.ok) return result;
  if (result.stored.length !== 0) {
    return { ok: false, status: 200, detail: "the relay still lists push tokens for this device" };
  }
  return { ok: true };
}

/**
 * How many requests are pending for this device, or `null` when the inbox could not be read
 * (network error, no answer within the deadline, non-2xx, malformed body). Only the count is
 * returned: envelope contents never leave this function.
 */
export async function fetchPendingCount(
  credentials: PushCredentials,
  fetchImpl: PushFetch,
  timeoutMs: number = RELAY_CALL_TIMEOUT_MS,
): Promise<number | null> {
  const answer = await callRelay(
    fetchImpl,
    inboxUrl(credentials.relayUrl, credentials.accountId, credentials.deviceId),
    { method: "GET", headers: { authorization: `Bearer ${credentials.deviceAuthToken}` } },
    timeoutMs,
  );
  if (!answer.reached || answer.json?.ok !== true) return null;
  const envelopes = jsonField(answer.json.value, "envelopes");
  return Array.isArray(envelopes) ? envelopes.length : null;
}
