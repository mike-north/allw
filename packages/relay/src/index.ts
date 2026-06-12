/**
 * `@allw/relay` — zero-knowledge approval relay.
 *
 * Routes ciphertext + signed verdicts between integrators and a user's devices; never
 * decrypts. One Durable Object per account coordinates device presence, push fan-out, and
 * cross-device retraction/dedupe. See `../../docs/architecture.md`.
 *
 * # Zero-knowledge invariant
 * This module ONLY stores public keys and routing metadata. Private keys and plaintext secrets
 * MUST NEVER appear here. `AccountRelay` is a registry of public key material, nothing more.
 *
 * # Auth note (deferred — issue #10 scope)
 * The endpoints below implement registry mechanics only. Endpoint authn/authz — who is allowed
 * to start a pairing, enroll an actor key, or revoke a device — is out of scope for #10 and
 * must follow `docs/enrollment.md`.
 */

import { PAIRING_TTL_MS } from "./constants.js";
import {
  ApnsPushTransport,
  FcmPushTransport,
  NoopPushTransport,
  WebPushStubTransport,
  dispatchPushWakeups,
  isPushTransportKind,
  type PushTransportRegistry,
  type PushTransportKind,
} from "./push.js";

export interface Env {
  readonly ACCOUNT: DurableObjectNamespace;
  readonly APNS_ENDPOINT?: string;
  readonly APNS_TOPIC?: string;
  readonly APNS_BEARER_TOKEN?: string;
  readonly FCM_ENDPOINT?: string;
  readonly FCM_BEARER_TOKEN?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    // Route by account id → its Durable Object.
    const accountId = url.pathname.split("/")[1] ?? "";
    if (!accountId) return new Response("missing account", { status: 400 });
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
    return stub.fetch(request);
  },
} satisfies ExportedHandler<Env>;

// ---------------------------------------------------------------------------
// Types used by AccountRelay
// ---------------------------------------------------------------------------

// SqlStorage.exec<T> requires T extends Record<string, SqlStorageValue>.
// Adding the index signature satisfies the constraint while keeping the named fields.

interface DeviceRow extends Record<string, string | number | null | ArrayBuffer> {
  device_id: string;
  pubkey: string;
  label: string | null;
  created_at: number;
}

interface DevicePushTokenRow extends Record<string, string | number | null | ArrayBuffer> {
  device_id: string;
  transport: PushTransportKind;
  token: string;
  created_at: number;
}

interface IncomingPushToken {
  transport: PushTransportKind;
  token: string;
}

interface ActorRow extends Record<string, string | number | null | ArrayBuffer> {
  actor_id: string;
  pubkey: string;
  label: string | null;
  created_at: number;
}

interface PairingRow extends Record<string, string | number | null | ArrayBuffer> {
  code: string;
  label: string | null;
  created_at: number;
  expires_at: number;
  used: number;
}

interface RequestRow extends Record<string, string | number | null | ArrayBuffer> {
  request_id: string;
  envelope: string;
  created_at: number;
  expires_at: number;
  status: string;
  terminal_at: number | null;
}

interface VerdictRow extends Record<string, string | number | null | ArrayBuffer> {
  request_id: string;
  verdict: string;
  device_id: string | null;
  received_at: number;
}

// Public shape returned to callers — only public key material + metadata.
interface DeviceRecord {
  device_id: string;
  pubkey: string;
  label: string | null;
  created_at: number;
}

interface ActorRecord {
  actor_id: string;
  pubkey: string;
  label: string | null;
  created_at: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Alphabet for human-enterable pairing codes: Crockford base32 (32 characters).
 * Omits I, L, O, U to avoid transcription errors (I↔1, L↔1, O↔0, U↔V).
 * Exactly 32 chars — one char per 5-bit value (2^5 = 32).
 */
const PAIRING_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" as const;
// Verify at construction time: the alphabet must be exactly 32 chars for the bitmask to work.
// (2^5 = 32)
if (PAIRING_ALPHABET.length !== 32) {
  throw new Error("PAIRING_ALPHABET must be exactly 32 characters");
}

const PAIRING_CODE_LENGTH = 8;
const REQUEST_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically random pairing code from the unambiguous base32 alphabet.
 * Uses a bitmask+rejection-sample approach to avoid modulo bias.
 */
function generatePairingCode(): string {
  const mask = 31; // 0b11111 — selects 5 bits → 0..31
  const bytes = new Uint8Array(PAIRING_CODE_LENGTH * 2); // over-allocate; rejection loop
  let result = "";

  while (result.length < PAIRING_CODE_LENGTH) {
    crypto.getRandomValues(bytes);
    for (let i = 0; i < bytes.length && result.length < PAIRING_CODE_LENGTH; i++) {
      const val = (bytes[i] ?? 0) & mask;
      // All 32 values are valid — no rejection needed with a 32-char alphabet and 5-bit mask.
      result += PAIRING_ALPHABET[val] ?? "";
    }
  }

  return result;
}

/**
 * Validate that `pubkey` is a valid base64url-unpadded string that decodes to exactly 32 bytes.
 * This covers both Ed25519 verifying keys and X25519 public keys, which are both 32-byte.
 * Returns the decoded bytes on success, or `null` on failure.
 */
function validatePubkey(pubkey: string): Uint8Array | null {
  // 32 bytes encode to exactly 43 base64url-unpadded chars (ceil(32*4/3)). Reject by length
  // FIRST — cheap, and bounds the work for oversized inputs before any decode.
  if (pubkey.length !== 43) return null;
  // base64url: A-Z a-z 0-9 - _ ; no = padding
  if (!/^[A-Za-z0-9\-_]+$/.test(pubkey)) return null;

  // Re-pad for standard base64 decoding.
  // base64url encodes n bytes as ceil(n*4/3) chars (no padding). Re-adding padding:
  // pad = (4 - (len % 4)) % 4  gives 0, 1, or 2 '=' chars.
  const padCount = (4 - (pubkey.length % 4)) % 4;
  const padded = pubkey + "=".repeat(padCount);
  let binary: string;
  try {
    binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return null;
  }
  if (binary.length !== 32) return null;

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Parse a JSON body; returns null if the body is invalid JSON or not an object. */
async function parseJsonBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await request.json();
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return null;
    }
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
  const v = body[key];
  return typeof v === "string" ? v : undefined;
}

function requiredString(body: Record<string, unknown>, key: string): string | null {
  const v = body[key];
  return typeof v === "string" ? v : null;
}

function requiredNumber(body: Record<string, unknown>, key: string): number | null {
  const v = body[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function optionalPushTokens(body: Record<string, unknown>): IncomingPushToken[] | null {
  const raw = body.push_tokens;
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) return null;
  const tokens: IncomingPushToken[] = [];
  const seenTokens = new Set<string>();
  for (const item of raw) {
    if (!isPlainObject(item)) return null;
    const transport = item.transport;
    const token = item.token;
    if (typeof transport !== "string" || !isPushTransportKind(transport)) return null;
    if (typeof token !== "string" || token.length < 1 || token.length > 4096) return null;
    // Duplicate registrations are idempotent for one device; collapse them before DB mutation so
    // a repeated token cannot half-complete pairing by tripping the push-token primary key.
    const tokenKey = `${transport}\0${token}`;
    if (seenTokens.has(tokenKey)) continue;
    seenTokens.add(tokenKey);
    tokens.push({ transport, token });
  }
  return tokens;
}

/** True when the request is a WebSocket upgrade (`Upgrade: websocket`, case-insensitive). */
function isWebSocketUpgrade(request: Request): boolean {
  return (request.headers.get("Upgrade") ?? "").toLowerCase() === "websocket";
}

/**
 * Serialize `obj` to JSON and send it over `ws`. Returns false if the socket rejected the send
 * (e.g. it is already closing) so fan-out can count live deliveries without throwing.
 */
function trySendJson(ws: WebSocket, obj: unknown): boolean {
  try {
    ws.send(JSON.stringify(obj));
    return true;
  } catch {
    return false;
  }
}

/** Narrow an unknown parsed value to a plain string-keyed object (rejects arrays/null). */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// WebSocket tags (hibernation `acceptWebSocket` tags; queried via `ctx.getWebSockets(tag)`).
// A device socket carries both DEVICE_TAG (for account-wide fan-out) and `device:<id>` (identity).
// An integrator waiter carries `integrator:<request_id>` (targeted verdict push).
const DEVICE_TAG = "device";
const deviceTag = (deviceId: string): string => `device:${deviceId}`;
const surfaceTag = (surfaceId: string): string => `surface:${surfaceId}`;
const integratorTag = (requestId: string): string => `integrator:${requestId}`;

// The exact, exhaustive set of ApprovalRequest envelope keys the relay accepts (contract.md
// §Messages). Anything else is rejected at submit time to keep plaintext out of the relay.
const ENVELOPE_KEYS = ["v", "id", "created_at", "expires_at", "approver", "context_ciphertext"];

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Validate a caller-declared visible surface id for cross-transport notification dedupe. */
function parseSurfaceId(request: Request): string | null | undefined {
  const value = new URL(request.url).searchParams.get("surface_id");
  if (value === null) return undefined;
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(value)) return null;
  return value;
}

// ---------------------------------------------------------------------------
// AccountRelay Durable Object
// ---------------------------------------------------------------------------

/**
 * Per-account relay: device pairing + public-key registry, actor-key enrollment.
 *
 * # Zero-knowledge invariant
 * ONLY public keys and routing metadata are stored here. Private keys and plaintext secrets
 * must NEVER be written to any SQLite table in this class.
 *
 * # Auth note (deferred — issue #10 scope)
 * Endpoint authn/authz (who may start pairing, enroll actors, revoke devices) is deliberately
 * out of scope for this PR. The production rules are specified in `docs/enrollment.md`.
 */
export class AccountRelay implements DurableObject {
  private readonly sql: SqlStorage;
  private readonly ctx: DurableObjectState;
  private readonly pushTransports: PushTransportRegistry;

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    this.pushTransports = buildPushTransports(env);
    this.initSchema();
    // On reactivation, restore the alarm from persisted pending rows in case the previous
    // isolate exited after a write but before the scheduled alarm was durably restored.
    this.ctx.waitUntil(this.armExpiryAlarm());
  }

  // ---------------------------------------------------------------------------
  // Schema initialisation (idempotent)
  // ---------------------------------------------------------------------------

  private initSchema(): void {
    // SECURITY: These tables store ONLY public keys + routing/lifecycle metadata.
    // Private keys and plaintext context MUST NEVER appear here (zero-knowledge invariant).
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS device (
        device_id  TEXT    PRIMARY KEY,
        pubkey     TEXT    NOT NULL,
        label      TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS device_push_token (
        device_id  TEXT    NOT NULL,
        transport  TEXT    NOT NULL,
        token      TEXT    NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, transport, token)
      );

      CREATE TABLE IF NOT EXISTS actor (
        actor_id   TEXT    PRIMARY KEY,
        pubkey     TEXT    NOT NULL,
        label      TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS pairing (
        code       TEXT    PRIMARY KEY,
        label      TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used       INTEGER NOT NULL DEFAULT 0
      );

      -- Pending approval requests awaiting a device verdict.
      -- SECURITY: 'envelope' holds the relay-visible ApprovalRequest ONLY — routing/lifecycle
      -- (v, id, created_at, expires_at, approver) wrapping the opaque 'context_ciphertext' (a JWE).
      -- The relay never parses the ciphertext and never sees the plaintext ApprovalContext.
      CREATE TABLE IF NOT EXISTS request (
        request_id TEXT    PRIMARY KEY,
        envelope   TEXT    NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        status     TEXT    NOT NULL DEFAULT 'pending',
        terminal_at INTEGER
      );

      -- Signed device verdicts, stored solely to relay back to the integrator.
      -- SECURITY: a Verdict is a JWS-signed decision (request_id, request_hash, decision, …) — it
      -- reveals only the decision, never the encrypted action context, and the relay holds no key
      -- that could forge it. Stored as opaque JSON so an offline/disconnected integrator can fetch it.
      CREATE TABLE IF NOT EXISTS verdict (
        request_id  TEXT    PRIMARY KEY,
        verdict     TEXT    NOT NULL,
        device_id   TEXT,
        received_at INTEGER NOT NULL
      );
    `);
    try {
      this.sql.exec(`ALTER TABLE request ADD COLUMN terminal_at INTEGER`);
    } catch {
      // Existing fresh schemas already have the column; older local DO state is migrated above.
    }
    this.sql.exec(`
      UPDATE request
      SET terminal_at = expires_at
      WHERE status = 'expired' AND terminal_at IS NULL;

      UPDATE request
      SET terminal_at = COALESCE(
        (SELECT received_at FROM verdict WHERE verdict.request_id = request.request_id),
        expires_at
      )
      WHERE status = 'resolved' AND terminal_at IS NULL;
    `);
  }

  // ---------------------------------------------------------------------------
  // Durable Object fetch handler
  // ---------------------------------------------------------------------------

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    // Strip the leading "/<accountId>" segment forwarded by the Worker.
    const segments = url.pathname.split("/").filter(Boolean);
    // segments[0] is the accountId (stripped); the sub-path starts at [1].
    const subSegments = segments.slice(1);
    const method = request.method.toUpperCase();
    const path0 = subSegments[0] ?? "";
    const path1 = subSegments[1] ?? "";
    const path2 = subSegments[2] ?? "";

    // POST /pairing/start
    if (method === "POST" && path0 === "pairing" && path1 === "start") {
      return this.handlePairingStart(request);
    }

    // POST /pairing/complete
    if (method === "POST" && path0 === "pairing" && path1 === "complete") {
      return this.handlePairingComplete(request);
    }

    // POST /actors
    if (method === "POST" && path0 === "actors" && !path1) {
      return this.handleActorEnroll(request);
    }

    // GET /actors
    if (method === "GET" && path0 === "actors" && !path1) {
      return this.handleActorList();
    }

    // GET /devices
    if (method === "GET" && path0 === "devices" && !path1) {
      return this.handleDeviceList();
    }

    // POST /devices/{device_id}/revoke
    if (method === "POST" && path0 === "devices" && path1 !== "" && path2 === "revoke") {
      return this.handleDeviceRevoke(path1);
    }

    // GET /devices/{device_id}/connect (WebSocket) — device presence + offline-queue flush.
    if (method === "GET" && path0 === "devices" && path1 !== "" && path2 === "connect") {
      if (!isWebSocketUpgrade(request)) {
        return json({ error: "WebSocket upgrade required" }, 426);
      }
      return this.handleDeviceConnect(path1, request);
    }

    // POST /requests — integrator submits an ApprovalRequest envelope (ciphertext + routing).
    if (method === "POST" && path0 === "requests" && !path1) {
      return this.handleSubmit(request, segments[0] ?? "");
    }

    // GET /requests/{request_id}/wait (WebSocket) — integrator awaits the verdict (pushed).
    if (method === "GET" && path0 === "requests" && path1 !== "" && path2 === "wait") {
      if (!isWebSocketUpgrade(request)) {
        return json({ error: "WebSocket upgrade required" }, 426);
      }
      return this.handleIntegratorWait(path1);
    }

    // GET /requests/{request_id} — integrator polls request status / fetches the verdict.
    if (method === "GET" && path0 === "requests" && path1 !== "" && path2 === "") {
      return this.handleGetRequest(path1);
    }

    // 405 only for a KNOWN route path reached with an unsupported method; any other (unknown)
    // sub-path is a 404 — e.g. `GET /devices/<id>` or `GET /pairing/unknown` are not routes.
    const isKnownRoutePath =
      (path0 === "pairing" && (path1 === "start" || path1 === "complete") && path2 === "") ||
      (path0 === "actors" && path1 === "") ||
      (path0 === "devices" && path1 === "") ||
      (path0 === "devices" &&
        path1 !== "" &&
        path2 === "revoke" &&
        (subSegments[3] ?? "") === "") ||
      (path0 === "devices" &&
        path1 !== "" &&
        path2 === "connect" &&
        (subSegments[3] ?? "") === "") ||
      (path0 === "requests" && path1 === "") ||
      (path0 === "requests" && path1 !== "" && path2 === "" && (subSegments[2] ?? "") === "") ||
      (path0 === "requests" && path1 !== "" && path2 === "wait" && (subSegments[3] ?? "") === "");
    if (isKnownRoutePath) {
      return json({ error: "method not allowed" }, 405);
    }

    return json({ error: "not found" }, 404);
  }

  // ---------------------------------------------------------------------------
  // Route handlers
  // ---------------------------------------------------------------------------

  /**
   * POST /pairing/start
   * Body: { label?: string }
   * Response: { code: string, expires_at: number }
   *
   * Generates a short human-enterable pairing code and stores it with a TTL.
   * The code is shown to the account owner (e.g. as a QR or typed string) to enroll a new device.
   */
  private async handlePairingStart(request: Request): Promise<Response> {
    const body = await parseJsonBody(request);
    const label = body ? optionalString(body, "label") : undefined;

    const code = generatePairingCode();
    const now = Date.now();
    const expiresAt = now + PAIRING_TTL_MS;

    this.sql.exec(
      `INSERT INTO pairing (code, label, created_at, expires_at, used)
       VALUES (?, ?, ?, ?, 0)`,
      code,
      label ?? null,
      now,
      expiresAt,
    );

    return json({ code, expires_at: expiresAt }, 201);
  }

  /**
   * POST /pairing/complete
   * Body: { code: string, pubkey: string (b64url 32 bytes), label?: string,
   *         push_tokens?: Array<{ transport: "apns" | "fcm" | "webpush", token: string }> }
   * Response: { device_id: string }
   *
   * Validates the pairing code and enrolls the device's public key.
   * - 404: code not found
   * - 409: code already used
   * - 410: code expired
   * - 400: invalid pubkey (not base64url or not 32 bytes)
   */
  private async handlePairingComplete(request: Request): Promise<Response> {
    const body = await parseJsonBody(request);
    if (!body) return json({ error: "invalid JSON body" }, 400);

    const code = requiredString(body, "code");
    if (!code) return json({ error: "'code' is required (string)" }, 400);

    const pubkey = requiredString(body, "pubkey");
    if (!pubkey) return json({ error: "'pubkey' is required (string)" }, 400);

    if (!validatePubkey(pubkey)) {
      return json({ error: "'pubkey' must be a base64url-unpadded 32-byte public key" }, 400);
    }

    const label = optionalString(body, "label");
    const pushTokens = optionalPushTokens(body);
    if (pushTokens === null) {
      return json({ error: "'push_tokens' must contain supported transport/token pairs" }, 400);
    }

    // Look up the pairing row
    const rows = [
      ...this.sql.exec<PairingRow>(
        `SELECT code, label, created_at, expires_at, used FROM pairing WHERE code = ?`,
        code,
      ),
    ];
    const pairing = rows[0];
    if (!pairing) return json({ error: "pairing code not found" }, 404);
    if (pairing.used !== 0) return json({ error: "pairing code already used" }, 409);
    if (Date.now() > pairing.expires_at) {
      return json({ error: "pairing code expired" }, 410);
    }

    const deviceId = crypto.randomUUID();
    const now = Date.now();

    // Mark the code as used and insert the device record atomically.
    // SECURITY: only the public key (pubkey) is stored — no private key ever touches this table.
    this.sql.exec(`UPDATE pairing SET used = 1 WHERE code = ?`, code);
    this.sql.exec(
      `INSERT INTO device (device_id, pubkey, label, created_at) VALUES (?, ?, ?, ?)`,
      deviceId,
      pubkey,
      // Fall back to the label supplied at /pairing/start so that field stays meaningful when
      // /pairing/complete omits its own.
      label ?? pairing.label ?? null,
      now,
    );
    for (const pushToken of pushTokens) {
      this.sql.exec(
        `INSERT INTO device_push_token (device_id, transport, token, created_at)
         VALUES (?, ?, ?, ?)`,
        deviceId,
        pushToken.transport,
        pushToken.token,
        now,
      );
    }

    return json({ device_id: deviceId }, 201);
  }

  /**
   * POST /actors
   * Body: { actor_id: string, pubkey: string (b64url 32 bytes), label?: string }
   * Response: { actor_id: string }
   *
   * Enrolls a machine/agent actor key. Duplicate actor_id is rejected with 409.
   * SECURITY: only the public key is stored (zero-knowledge invariant).
   */
  private async handleActorEnroll(request: Request): Promise<Response> {
    const body = await parseJsonBody(request);
    if (!body) return json({ error: "invalid JSON body" }, 400);

    const actorId = requiredString(body, "actor_id");
    if (!actorId) return json({ error: "'actor_id' is required (string)" }, 400);

    const pubkey = requiredString(body, "pubkey");
    if (!pubkey) return json({ error: "'pubkey' is required (string)" }, 400);

    if (!validatePubkey(pubkey)) {
      return json({ error: "'pubkey' must be a base64url-unpadded 32-byte public key" }, 400);
    }

    const label = optionalString(body, "label");
    const now = Date.now();

    // Reject duplicates: actor_id must be unique (the caller controls the namespace).
    const existing = [
      ...this.sql.exec<ActorRow>(`SELECT actor_id FROM actor WHERE actor_id = ?`, actorId),
    ];
    if (existing.length > 0) {
      return json({ error: "actor already enrolled" }, 409);
    }

    // SECURITY: only pubkey (public key material) is stored — never a private key.
    this.sql.exec(
      `INSERT INTO actor (actor_id, pubkey, label, created_at) VALUES (?, ?, ?, ?)`,
      actorId,
      pubkey,
      label ?? null,
      now,
    );

    return json({ actor_id: actorId }, 201);
  }

  /**
   * GET /devices
   * Response: { devices: DeviceRecord[] }
   *
   * Lists all enrolled devices for this account.
   * Returns only public key material + metadata (zero-knowledge invariant holds).
   */
  private handleDeviceList(): Response {
    const rows = [
      ...this.sql.exec<DeviceRow>(
        `SELECT device_id, pubkey, label, created_at FROM device ORDER BY created_at ASC`,
      ),
    ];

    // SECURITY: the DeviceRecord shape contains ONLY public key material + routing metadata.
    const devices: DeviceRecord[] = rows.map((r) => ({
      device_id: r.device_id,
      pubkey: r.pubkey,
      label: r.label,
      created_at: r.created_at,
    }));

    return json({ devices });
  }

  /**
   * GET /actors
   * Response: { actors: ActorRecord[] }
   *
   * Lists all enrolled actor keys for this account.
   * Returns only public key material + metadata (zero-knowledge invariant holds).
   */
  private handleActorList(): Response {
    const rows = [
      ...this.sql.exec<ActorRow>(
        `SELECT actor_id, pubkey, label, created_at FROM actor ORDER BY created_at ASC`,
      ),
    ];

    // SECURITY: the ActorRecord shape contains ONLY public key material + routing metadata.
    const actors: ActorRecord[] = rows.map((r) => ({
      actor_id: r.actor_id,
      pubkey: r.pubkey,
      label: r.label,
      created_at: r.created_at,
    }));

    return json({ actors });
  }

  /**
   * POST /devices/{device_id}/revoke
   * Response: { revoked: true } | 404
   *
   * Removes the device record. Returns 404 if the device is not enrolled.
   */
  private handleDeviceRevoke(deviceId: string): Response {
    const existing = [
      ...this.sql.exec<DeviceRow>(`SELECT device_id FROM device WHERE device_id = ?`, deviceId),
    ];
    if (existing.length === 0) {
      return json({ error: "device not found" }, 404);
    }

    this.sql.exec(`DELETE FROM device WHERE device_id = ?`, deviceId);
    this.sql.exec(`DELETE FROM device_push_token WHERE device_id = ?`, deviceId);
    // Drop any live presence socket for the revoked device — it must stop receiving ciphertext.
    for (const ws of this.ctx.getWebSockets(deviceTag(deviceId))) {
      try {
        ws.close(1008, "device revoked");
      } catch {
        // already closing — ignore
      }
    }
    return json({ revoked: true });
  }

  // ---------------------------------------------------------------------------
  // Ciphertext routing + verdict relay (issue #11)
  // ---------------------------------------------------------------------------

  /**
   * GET /devices/{device_id}/connect  (WebSocket upgrade)
   *
   * Opens a hibernatable presence socket for an enrolled device and immediately flushes every
   * still-pending request (the offline queue): a device that was offline when a request arrived
   * receives it on reconnect. `surface_id` is an optional visible-screen/topology id used to avoid
   * double-prompting one screen via multiple transports (for example native macOS plus iPhone
   * Mirroring). Returns 404 if the device is not enrolled, 400 for a malformed `surface_id` (a
   * request without a WebSocket upgrade header is rejected earlier, at the router, with 426).
   *
   * Protocol (relay → device): `{ type: "request", request_id, envelope }` (ciphertext to fetch),
   * `{ type: "retract", request_id }` (another surface resolved it).
   * Protocol (device → relay): `{ type: "verdict", request_id, verdict }` (signed decision).
   */
  private handleDeviceConnect(deviceId: string, request: Request): Response {
    const enrolled = [
      ...this.sql.exec<DeviceRow>(`SELECT device_id FROM device WHERE device_id = ?`, deviceId),
    ];
    if (enrolled.length === 0) {
      return json({ error: "device not enrolled" }, 404);
    }
    const surfaceId = parseSurfaceId(request);
    if (surfaceId === null) {
      return json({ error: "surface_id must be 1-128 URL-safe identifier chars" }, 400);
    }
    const shouldFlushOfflineQueue =
      surfaceId === undefined || !this.hasOpenSocketOnSurface(surfaceId);

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    // Hibernation: the DO may be evicted while the socket stays open; handlers below re-attach it.
    const tags = [DEVICE_TAG, deviceTag(deviceId)];
    if (surfaceId !== undefined) tags.push(surfaceTag(surfaceId));
    this.ctx.acceptWebSocket(server, tags);

    if (shouldFlushOfflineQueue) {
      // Flush the offline queue: every still-live pending request, oldest first. Fail-closed: a
      // request that expired while queued is excluded (`expires_at > now`), so a dead request is
      // never re-pushed to a reconnecting device. (Submit fan-out needs no such guard —
      // `handleSubmit` rejects an already-expired `expires_at`, so a freshly stored request is
      // always future-dated.)
      const now = Date.now();
      const pending = [
        ...this.sql.exec<RequestRow>(
          `SELECT request_id, envelope FROM request
           WHERE status = 'pending' AND expires_at > ? ORDER BY created_at ASC`,
          now,
        ),
      ];
      for (const p of pending) {
        trySendJson(server, {
          type: "request",
          request_id: p.request_id,
          envelope: JSON.parse(p.envelope) as unknown,
        });
      }
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  /**
   * POST /requests
   * Body: the ApprovalRequest envelope — `{ v, id, created_at, expires_at, approver,
   *        context_ciphertext }`. The relay stores it opaquely (never parsing the ciphertext).
   * Response: `{ request_id, status: "pending", delivered_to }` (202).
   *
   * Stores the request and fans the ciphertext out to every online device. If no device is
   * connected it stays queued and is delivered on the next `…/connect` (see handleDeviceConnect).
   * - 400: not exactly the contract's envelope fields, or already expired.
   * - 409: a request with this `id` was already submitted.
   */
  private async handleSubmit(request: Request, accountId: string): Promise<Response> {
    const envelope = await parseJsonBody(request);
    if (!envelope) return json({ error: "invalid JSON body" }, 400);

    // SECURITY (zero-knowledge): the ApprovalRequest envelope must be EXACTLY the contract's
    // routing/lifecycle fields wrapping the opaque ciphertext (contract.md §Messages). Rejecting
    // any unexpected key prevents an integrator from persisting plaintext `ApprovalContext` fields
    // (action, summary, actor, …) in the relay — the relay must only ever hold ciphertext + routing.
    const extraneous = Object.keys(envelope).filter((k) => !ENVELOPE_KEYS.includes(k));
    if (extraneous.length > 0) {
      return json({ error: `unexpected envelope field(s): ${extraneous.join(", ")}` }, 400);
    }

    const id = requiredString(envelope, "id");
    if (!id) return json({ error: "'id' is required (string)" }, 400);
    if (requiredNumber(envelope, "v") === null) {
      return json({ error: "'v' is required (number)" }, 400);
    }
    if (requiredNumber(envelope, "created_at") === null) {
      return json({ error: "'created_at' is required (i64 ms)" }, 400);
    }
    if (!requiredString(envelope, "approver")) {
      return json({ error: "'approver' is required (string)" }, 400);
    }
    // The ciphertext is opaque to the relay — present and a string is all we check.
    if (!requiredString(envelope, "context_ciphertext")) {
      return json({ error: "'context_ciphertext' is required (opaque JWE string)" }, 400);
    }
    const expiresAt = requiredNumber(envelope, "expires_at");
    if (expiresAt === null) return json({ error: "'expires_at' is required (i64 ms)" }, 400);

    const now = Date.now();
    if (expiresAt <= now) return json({ error: "request already expired" }, 400);

    // Fast-path duplicate rejection. The INSERT below is ALSO guarded: `handleSubmit` awaits the
    // JSON parse, so two concurrent submits for the same id can interleave past this SELECT and
    // race on the primary key — the catch maps that to the same 409, never a 500.
    const existing = [
      ...this.sql.exec<RequestRow>(`SELECT request_id FROM request WHERE request_id = ?`, id),
    ];
    if (existing.length > 0) return json({ error: "request already submitted" }, 409);

    // SECURITY: the whole envelope is routing/lifecycle + the opaque ciphertext — no plaintext.
    try {
      this.sql.exec(
        `INSERT INTO request (request_id, envelope, created_at, expires_at, status, terminal_at)
         VALUES (?, ?, ?, ?, 'pending', NULL)`,
        id,
        JSON.stringify(envelope),
        now,
        expiresAt,
      );
    } catch {
      // Primary-key conflict: a concurrent submit with this id won the race → consistently a 409.
      return json({ error: "request already submitted" }, 409);
    }
    await this.armExpiryAlarm();

    const delivered = this.sendRequestToOneSocketPerSurface(id, envelope);
    const pushWakeups = await this.sendPushWakeups(accountId, id);

    return json(
      { request_id: id, status: "pending", delivered_to: delivered, push_wakeups: pushWakeups },
      202,
    );
  }

  /** Send request-id-only push wakeups to every registered device push token. */
  private async sendPushWakeups(accountId: string, requestId: string): Promise<number> {
    const tokens = [
      ...this.sql.exec<DevicePushTokenRow>(
        `SELECT device_id, transport, token, created_at FROM device_push_token ORDER BY created_at ASC`,
      ),
    ];
    return dispatchPushWakeups(tokens, {
      accountId,
      requestId,
      transports: this.pushTransports,
    });
  }

  /**
   * GET /requests/{request_id}
   * Response: `{ request_id, status }` where status is `pending`, terminal `expired` (fail-closed,
   *           past `expires_at`), or `resolved` (+ the signed `verdict`). 404 if unknown.
   *
   * The polling counterpart to `…/wait` — lets a disconnected integrator fetch a persisted verdict.
   * Lazy-expires a past-deadline request on read so it never reports a perpetual `pending`.
   */
  private handleGetRequest(requestId: string): Response {
    const rows = [
      ...this.sql.exec<RequestRow>(
        `SELECT request_id, status, expires_at FROM request WHERE request_id = ?`,
        requestId,
      ),
    ];
    const req = rows[0];
    if (!req) return json({ error: "request not found" }, 404);
    const status = this.expireIfDue(requestId, req.status, req.expires_at, Date.now());
    if (status !== "resolved") {
      // pending, or terminal `expired` (fail-closed) — never a verdict.
      return json({ request_id: requestId, status });
    }
    return json({
      request_id: requestId,
      status: "resolved",
      verdict: this.loadVerdict(requestId),
    });
  }

  /**
   * GET /requests/{request_id}/wait  (WebSocket upgrade)
   *
   * A live waiting integrator: the verdict is pushed the instant a device decides (or immediately
   * if it already has), then the socket is closed. A past-deadline request is lazy-expired and the
   * terminal status is pushed at once (fail-closed). Returns 404 for an unknown request (a request
   * without a WebSocket upgrade header is rejected earlier, at the router, with 426).
   *
   * Protocol (relay → integrator): `{ type: "verdict", request_id, verdict }` or
   * `{ type: "expired", request_id }` (terminal, no verdict will come).
   */
  private handleIntegratorWait(requestId: string): Response {
    const rows = [
      ...this.sql.exec<RequestRow>(
        `SELECT request_id, status, expires_at FROM request WHERE request_id = ?`,
        requestId,
      ),
    ];
    const req = rows[0];
    if (!req) return json({ error: "request not found" }, 404);
    const status = this.expireIfDue(requestId, req.status, req.expires_at, Date.now());

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server, ["integrator", integratorTag(requestId)]);

    if (status === "resolved") {
      trySendJson(server, {
        type: "verdict",
        request_id: requestId,
        verdict: this.loadVerdict(requestId),
      });
      try {
        server.close(1000, "resolved");
      } catch {
        // already closing — ignore
      }
    } else if (status === "expired") {
      // Fail-closed terminal state — tell the waiter at once and close; no verdict will arrive.
      trySendJson(server, { type: "expired", request_id: requestId });
      try {
        server.close(1000, "expired");
      } catch {
        // already closing — ignore
      }
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  /**
   * Fail-closed lazy expiry (contract §Invariants #6): if a `pending` request is past its
   * `expires_at`, transition it to the terminal `expired` status. Returns the effective status so
   * read paths report `expired` — never a perpetual `pending` — the first time anyone looks after
   * the deadline. This shared transition also notifies live clients so a poll or late verdict cannot
   * clear the alarm while leaving existing waiters/devices stuck on the stale pending request.
   */
  private expireIfDue(
    requestId: string,
    status: string,
    expiresAt: number,
    now: number,
    options: { skipDeviceSocket?: WebSocket } = {},
  ): string {
    if (status === "pending" && now > expiresAt) {
      this.sql.exec(
        `UPDATE request SET status = 'expired', terminal_at = ?
         WHERE request_id = ? AND status = 'pending'`,
        now,
        requestId,
      );
      this.notifyExpiredRequest(requestId, options.skipDeviceSocket);
      this.ctx.waitUntil(this.armExpiryAlarm());
      return "expired";
    }
    return status;
  }

  /** Load and parse the stored (opaque) verdict for a request, or null if none recorded. */
  private loadVerdict(requestId: string): unknown {
    const rows = [
      ...this.sql.exec<VerdictRow>(`SELECT verdict FROM verdict WHERE request_id = ?`, requestId),
    ];
    const row = rows[0];
    return row ? (JSON.parse(row.verdict) as unknown) : null;
  }

  /** Resolve the `device:<id>` identity tag for a hibernation socket, if it carries one. */
  private deviceIdForSocket(ws: WebSocket): string | null {
    for (const tag of this.ctx.getTags(ws)) {
      if (tag.startsWith("device:")) return tag.slice("device:".length);
    }
    return null;
  }

  /** Resolve the visible surface tag for a hibernation socket. */
  private surfaceIdForSocket(ws: WebSocket): string | null {
    for (const tag of this.ctx.getTags(ws)) {
      if (tag.startsWith("surface:")) return tag.slice("surface:".length);
    }
    return null;
  }

  /** True when a same-surface peer is still open enough to own queued reconnect delivery. */
  private hasOpenSocketOnSurface(surfaceId: string): boolean {
    for (const ws of this.ctx.getWebSockets(surfaceTag(surfaceId))) {
      // Hibernation tag indexes can briefly retain closing sockets; those must not suppress the
      // reconnecting live socket's offline-queue flush.
      if (ws.readyState === WebSocket.OPEN) return true;
    }
    return false;
  }

  /** Send a request to at most one live socket per visible surface. */
  private sendRequestToOneSocketPerSurface(requestId: string, envelope: unknown): number {
    const deliveredSurfaces = new Set<string>();
    let delivered = 0;
    for (const ws of this.ctx.getWebSockets(DEVICE_TAG)) {
      const surfaceId = this.surfaceIdForSocket(ws);
      if (surfaceId !== null && deliveredSurfaces.has(surfaceId)) continue;
      if (trySendJson(ws, { type: "request", request_id: requestId, envelope })) {
        delivered++;
        // Only a successful send claims the visible surface; stale closing sockets must not block
        // a later live socket for the same screen/transport group.
        if (surfaceId !== null) deliveredSurfaces.add(surfaceId);
      }
    }
    return delivered;
  }

  // ---------------------------------------------------------------------------
  // WebSocket hibernation handlers
  // ---------------------------------------------------------------------------

  /**
   * Hibernation message handler. The only inbound message that mutates state is a device verdict:
   * `{ type: "verdict", request_id, verdict }`. On a fresh verdict the relay stores it, marks the
   * request resolved, retracts it from the other devices, and pushes it to any waiting integrator.
   * A verdict for an already-resolved request is ignored (dedupe / cross-device race).
   */
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const text = typeof message === "string" ? message : new TextDecoder().decode(message);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      trySendJson(ws, { type: "error", error: "invalid JSON message" });
      return;
    }
    if (!isPlainObject(parsed)) {
      trySendJson(ws, { type: "error", error: "message must be a JSON object" });
      return;
    }
    if (parsed.type === "verdict") {
      this.onDeviceVerdict(ws, parsed);
      return;
    }
    // Unknown message types are ignored (forward-compatible: e.g. future client-side acks/pings).
    return Promise.resolve();
  }

  /** Hibernation close handler — finish the closing handshake from our side. */
  async webSocketClose(
    ws: WebSocket,
    code: number,
    _reason: string,
    _wasClean: boolean,
  ): Promise<void> {
    try {
      // 1006 (abnormal) is not a valid code to echo; use 1000 in that case.
      ws.close(code === 1006 ? 1000 : code, "closing");
    } catch {
      // already closed — ignore
    }
    return Promise.resolve();
  }

  /**
   * Process a device verdict message. Idempotent: a second verdict for the same request (whether a
   * cross-device race or a retry) is acknowledged but does not overwrite the recorded decision.
   */
  private onDeviceVerdict(ws: WebSocket, msg: Record<string, unknown>): void {
    // SECURITY: only a device presence socket may submit a verdict. An integrator `…/wait` socket
    // (or any other non-device client) carries no `device:<id>` tag — it must NEVER be able to
    // resolve a request by sending a forged verdict payload. Authenticity of the verdict body is
    // additionally guaranteed by its JWS signature, verified downstream by the integrator.
    const deviceId = this.deviceIdForSocket(ws);
    if (deviceId === null) {
      trySendJson(ws, { type: "error", error: "verdicts are only accepted from device sockets" });
      return;
    }

    // SECURITY (fail-closed): re-confirm the device is still enrolled. The socket tag proves which
    // device opened the connection, but a revoke may have removed the enrollment while a hibernation
    // socket survived the best-effort close — a de-enrolled device must not be able to drive a
    // request to `resolved`. (The integrator's JWS verification is the real backstop; this keeps the
    // relay's own state honest.)
    const stillEnrolled = [
      ...this.sql.exec<DeviceRow>(`SELECT device_id FROM device WHERE device_id = ?`, deviceId),
    ];
    if (stillEnrolled.length === 0) {
      trySendJson(ws, { type: "error", error: "device is no longer enrolled" });
      try {
        ws.close(1008, "device revoked");
      } catch {
        // already closing — ignore
      }
      return;
    }

    const requestId = requiredString(msg, "request_id");
    if (!requestId) {
      trySendJson(ws, { type: "error", error: "'request_id' is required (string)" });
      return;
    }
    // Require a JSON-object verdict (the contract Verdict shape). We never parse the JWS inside it,
    // but a degenerate scalar (42, "x") could never be verified downstream — reject it outright.
    if (!isPlainObject(msg.verdict)) {
      trySendJson(ws, { type: "error", error: "'verdict' must be a JSON object" });
      return;
    }

    const reqRows = [
      ...this.sql.exec<RequestRow>(
        `SELECT request_id, status, expires_at FROM request WHERE request_id = ?`,
        requestId,
      ),
    ];
    const req = reqRows[0];
    if (!req) {
      trySendJson(ws, { type: "error", error: "unknown request" });
      return;
    }
    if (req.status === "resolved") {
      // Dedupe: the first verdict wins; ignore later ones (another device may have resolved it).
      trySendJson(ws, { type: "ack", request_id: requestId, status: "already_resolved" });
      return;
    }

    // Fail-closed (contract §Invariants #6): a request past its deadline must NEVER become
    // approvable. Transition pending→expired and refuse to record the verdict.
    const now = Date.now();
    if (req.status === "expired" || (req.status === "pending" && now > req.expires_at)) {
      this.expireIfDue(requestId, req.status, req.expires_at, now, { skipDeviceSocket: ws });
      trySendJson(ws, { type: "ack", request_id: requestId, status: "expired" });
      return;
    }

    // SECURITY: the verdict is a JWS-signed decision, stored opaquely solely to route it back.
    const verdictJson = JSON.stringify(msg.verdict);
    try {
      this.sql.exec(
        `INSERT INTO verdict (request_id, verdict, device_id, received_at) VALUES (?, ?, ?, ?)`,
        requestId,
        verdictJson,
        deviceId,
        now,
      );
    } catch {
      // Primary-key conflict: a verdict for this request already landed (a concurrent resolve).
      // First verdict wins — ack as already_resolved rather than throwing out of the DO event.
      trySendJson(ws, { type: "ack", request_id: requestId, status: "already_resolved" });
      return;
    }
    this.sql.exec(
      `UPDATE request SET status = 'resolved', terminal_at = ? WHERE request_id = ?`,
      now,
      requestId,
    );
    this.ctx.waitUntil(this.armExpiryAlarm());

    const verdictValue = JSON.parse(verdictJson) as unknown;

    // Retract from the other devices so the pending surface clears everywhere.
    for (const sock of this.ctx.getWebSockets(DEVICE_TAG)) {
      if (sock === ws) continue;
      trySendJson(sock, { type: "retract", request_id: requestId });
    }

    // Push to any live integrator waiter(s), then close their sockets.
    for (const sock of this.ctx.getWebSockets(integratorTag(requestId))) {
      trySendJson(sock, { type: "verdict", request_id: requestId, verdict: verdictValue });
      try {
        sock.close(1000, "resolved");
      } catch {
        // already closing — ignore
      }
    }

    trySendJson(ws, { type: "ack", request_id: requestId, status: "resolved" });
  }

  /**
   * Durable Object alarm: proactively fail-closes expired pending requests, retracts them from
   * connected devices, wakes live integrator waiters, and then schedules the next pending expiry.
   */
  async alarm(): Promise<void> {
    const now = Date.now();
    const expired = this.expirePendingDue(now);
    for (const request of expired) {
      this.notifyExpiredRequest(request.request_id);
    }
    this.sweepTerminalRows(now);
    await this.armExpiryAlarm();
  }

  /** Schedule the alarm to the nearest pending expiry, or clear it when no pending request remains. */
  private async armExpiryAlarm(): Promise<void> {
    const next = [
      ...this.sql.exec<{ expires_at: number }>(
        `SELECT expires_at FROM request WHERE status = 'pending' ORDER BY expires_at ASC LIMIT 1`,
      ),
    ][0];
    if (!next) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    await this.ctx.storage.setAlarm(Math.max(next.expires_at, Date.now()));
  }

  /** Mark every overdue pending request expired and return the rows that changed state. */
  private expirePendingDue(now: number): RequestRow[] {
    const overdue = [
      ...this.sql.exec<RequestRow>(
        `SELECT request_id, envelope, created_at, expires_at, status, terminal_at FROM request
         WHERE status = 'pending' AND expires_at <= ? ORDER BY expires_at ASC`,
        now,
      ),
    ];
    for (const request of overdue) {
      this.sql.exec(
        `UPDATE request SET status = 'expired', terminal_at = ?
         WHERE request_id = ? AND status = 'pending'`,
        now,
        request.request_id,
      );
    }
    return overdue;
  }

  /** Fan out terminal expiry to surfaces that might still be showing or waiting on the request. */
  private notifyExpiredRequest(requestId: string, skipDeviceSocket?: WebSocket): void {
    for (const sock of this.ctx.getWebSockets(DEVICE_TAG)) {
      if (sock === skipDeviceSocket) continue;
      trySendJson(sock, { type: "retract", request_id: requestId });
    }
    for (const sock of this.ctx.getWebSockets(integratorTag(requestId))) {
      trySendJson(sock, { type: "expired", request_id: requestId });
      try {
        sock.close(1000, "expired");
      } catch {
        // already closing — ignore
      }
    }
  }

  /** Bound storage growth by removing old terminal request rows and their stored verdicts. */
  private sweepTerminalRows(now: number): void {
    const cutoff = now - REQUEST_RETENTION_MS;
    this.sql.exec(
      `DELETE FROM request
       WHERE status IN ('expired', 'resolved') AND terminal_at IS NOT NULL AND terminal_at < ?`,
      cutoff,
    );
    this.sql.exec(`DELETE FROM verdict WHERE request_id NOT IN (SELECT request_id FROM request)`);
  }
}

function buildPushTransports(env: Env): PushTransportRegistry {
  const transports: PushTransportRegistry = {
    apns: new NoopPushTransport("apns"),
    fcm: new NoopPushTransport("fcm"),
    webpush: new WebPushStubTransport(),
  };
  if (env.APNS_ENDPOINT && env.APNS_TOPIC && env.APNS_BEARER_TOKEN) {
    transports.apns = new ApnsPushTransport({
      endpoint: env.APNS_ENDPOINT,
      topic: env.APNS_TOPIC,
      bearerToken: env.APNS_BEARER_TOKEN,
    });
  }
  if (env.FCM_ENDPOINT && env.FCM_BEARER_TOKEN) {
    transports.fcm = new FcmPushTransport({
      endpoint: env.FCM_ENDPOINT,
      bearerToken: env.FCM_BEARER_TOKEN,
    });
  }
  return transports;
}
