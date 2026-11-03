/**
 * The relay's **relay-level** namespace: routes that belong to the relay as a whole rather than to
 * one account, served under `/.well-known/allw/` (RFC 8615 site metadata).
 *
 * # Why a separate namespace
 * Every other path is `/{account_id}/…`, and account ids are caller-chosen. A relay-level route under
 * an ordinary first segment (e.g. `/push/…`) would shadow, or be shadowed by, the account with that
 * id. A leading `.` is outside the base64url alphabet that real account ids use, so `/.well-known/`
 * does not collide with one. The top-level router claims the whole `/.well-known` segment before
 * account routing, so no such path ever reaches a Durable Object (a would-be account literally named
 * `.well-known` is simply unreachable, never shadowed). **Any relay-level route added later belongs
 * under `/.well-known/allw/`.**
 *
 * @see https://www.rfc-editor.org/rfc/rfc8615 (Well-Known URIs)
 */

import { handleVapidPublicKey, type VapidEnv } from "./web-push.js";

/** First path segment that selects the relay-level namespace. */
export const WELL_KNOWN_SEGMENT = ".well-known";

/** The VAPID public key a browser subscribes with (`docs/relay-api.md` §3). */
export const VAPID_PUBLIC_KEY_PATH = "/.well-known/allw/vapid-public-key";

/** Whether a request path belongs to the relay-level namespace (and never to an account). */
export function isWellKnownPath(pathname: string): boolean {
  return pathname.split("/")[1] === WELL_KNOWN_SEGMENT;
}

/** Route a relay-level request. Unknown relay-level paths are 404 and never fall through to accounts. */
export async function handleWellKnown(request: Request, env: VapidEnv): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (pathname === VAPID_PUBLIC_KEY_PATH) return handleVapidPublicKey(request, env);
  return Response.json({ error: "not found" }, { status: 404 });
}
