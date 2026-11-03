/**
 * Abuse limits for the relay's unauthenticated routes (#248): body-size capping and the request
 * horizon's Worker-var parsing.
 *
 * These are routing/availability controls, not authorization: a request that passes them is still
 * only ever ciphertext routed to the account's devices. Every limit fails closed — an over-budget
 * input or an unreadable body is refused.
 *
 * @see ../../../docs/relay-api.md §3 Integrator endpoints (limits and status codes)
 * @see ../../../docs/relay-deploy.md (the request-horizon var)
 */

import { DEFAULT_MAX_REQUEST_TTL_MS } from "./constants.js";

/** Outcome of reading a body under a byte cap. */
export type CappedBody =
  | { readonly kind: "ok"; readonly text: string }
  | { readonly kind: "too_large" }
  | { readonly kind: "unreadable" };

/**
 * Read `request`'s body as UTF-8 text, refusing it once it exceeds `maxBytes`.
 *
 * A declared `Content-Length` above the cap is refused before any byte is read. Because the header
 * can be absent (chunked) or wrong, the stream is also counted as it is read and abandoned as soon
 * as the running total passes the cap — the body is never buffered beyond `maxBytes` + one chunk.
 */
export async function readBodyCapped(request: Request, maxBytes: number): Promise<CappedBody> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null) {
    const digits = declared.trim();
    if (!/^\d+$/.test(digits)) {
      // Release the unread body rather than leaving the sender's stream dangling.
      await request.body?.cancel().catch(() => undefined);
      return { kind: "unreadable" };
    }
    // A digit-only length beyond the safe-integer range is still a declared size, and over any cap.
    const length = Number(digits);
    if (!Number.isSafeInteger(length) || length > maxBytes) {
      await request.body?.cancel().catch(() => undefined);
      return { kind: "too_large" };
    }
  }
  if (request.body === null) return { kind: "ok", text: "" };

  const stream = request.body as ReadableStream<Uint8Array>;
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const result: ReadableStreamReadResult<Uint8Array> = await reader.read();
      if (result.done) break;
      const value = result.value;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return { kind: "too_large" };
      }
      chunks.push(value);
    }
  } catch {
    return { kind: "unreadable" };
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return {
      kind: "ok",
      text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes),
    };
  } catch {
    return { kind: "unreadable" };
  }
}

/** Outcome of reading and parsing a JSON-object body under a byte cap. */
export type CappedJsonBody =
  | { readonly kind: "ok"; readonly body: Record<string, unknown> }
  | { readonly kind: "too_large" }
  | { readonly kind: "invalid" };

/**
 * {@link readBodyCapped}, then parse the text as a JSON object. Unreadable bytes, invalid JSON, and
 * non-object JSON (arrays, scalars, null) are all `invalid`.
 */
export async function readJsonObjectCapped(
  request: Request,
  maxBytes: number,
): Promise<CappedJsonBody> {
  const raw = await readBodyCapped(request, maxBytes);
  if (raw.kind === "too_large") return raw;
  if (raw.kind === "unreadable") return { kind: "invalid" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.text);
  } catch {
    return { kind: "invalid" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { kind: "invalid" };
  }
  return { kind: "ok", body: parsed as Record<string, unknown> };
}

/** UTF-8 byte length of a string (what the ciphertext cap measures). */
export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

/**
 * Resolve the request horizon from the optional `MAX_REQUEST_TTL_MS` Worker var.
 *
 * Unset → {@link DEFAULT_MAX_REQUEST_TTL_MS}. A set value must be a positive safe integer of
 * milliseconds; anything else is a misconfiguration, logged, and replaced by the default — the
 * horizon is never disabled or widened by a typo. A value below the hooks' 420 s timeout is honored
 * (the operator's choice) and makes such submits fail closed with 400.
 */
export function parseMaxRequestTtlMs(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return DEFAULT_MAX_REQUEST_TTL_MS;
  const trimmed = raw.trim();
  const value = Number(trimmed);
  if (!/^\d+$/.test(trimmed) || !Number.isSafeInteger(value) || value <= 0) {
    console.error(
      `allw relay: ignoring invalid MAX_REQUEST_TTL_MS ${JSON.stringify(raw)}; using the default`,
    );
    return DEFAULT_MAX_REQUEST_TTL_MS;
  }
  return value;
}
