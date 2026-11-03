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
 * # Endpoint auth
 * Registry and request endpoints use relay-scoped bearer capability tokens. Tokens are random,
 * short protocol secrets; the DO stores only SHA-256 hashes so persisted state cannot be replayed
 * as a bearer credential. See issue #89 and `docs/enrollment.md`.
 *
 * # Self-certifying accounts
 * An account id is derived from its account-root public key (`docs/enrollment.md` §Model). Starting
 * a pairing — the only way to add a device — requires a root-signed authorization that the core
 * verifies against a root that derives to the path's account id; the first verified root is then
 * bound to the account's Durable Object. Root verification runs in the audited core (`./core.ts`).
 *
 * The first bind requires an account with no prior device, pairing or actor rows (legacy
 * unverified account state is dropped at schema init):
 * before roots were bound, anyone could create those under any id (including a derived one), so
 * such rows are attacker-seedable and binding over them would launder them under the root. The bind
 * is refused (409) instead of purging, so the condition is visible rather than silently repaired.
 * `pairing/complete` likewise refuses (403) on an unbound account.
 */

import { AlarmMultiplexer } from "./alarms.js";
import { PAIRING_TTL_MS } from "./constants.js";
import { withCors, type CorsEnv } from "./cors.js";
import {
  CoreUnavailableError,
  accountIdForRoot,
  checkAccountIdForRoot,
  ensureCore,
  verifyAccountState,
  verifyPairingStartAuthorization,
  verifyVerdictProvenance,
} from "./core.js";
import {
  ApnsPushTransport,
  FcmPushTransport,
  MAX_PUSH_TOKENS_PER_ACCOUNT,
  MAX_PUSH_TOKENS_PER_REGISTRATION,
  MAX_PUSH_TOKENS_PER_TRANSPORT,
  WEB_PUSH_COALESCE_MS,
  WEB_PUSH_TRAILING_RETRY_MS,
  diffPushTokenSet,
  WakeupCoalescer,
  dispatchPushWakeups,
  parseWebPushCoalesceKey,
  webPushCoalesceKey,
  type WakeupClaimStore,
  isPushTransportKind,
  schedulablePushTokens,
  type PushTransportRegistry,
  type PushTransportKind,
  type StoredPushToken,
} from "./push.js";
import {
  WebPushTransport,
  parseWebPushEndpoint,
  vapidConfigFromEnv,
  type VapidEnv,
} from "./web-push.js";
import { handleWellKnown, isWellKnownPath } from "./well-known.js";

export interface Env extends VapidEnv, CorsEnv {
  readonly ACCOUNT: DurableObjectNamespace;
  readonly APNS_ENDPOINT?: string;
  readonly APNS_TOPIC?: string;
  readonly APNS_BEARER_TOKEN?: string;
  readonly FCM_ENDPOINT?: string;
  readonly FCM_BEARER_TOKEN?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // CORS for browser clients is applied once here, around all routing (see `cors.ts`), so it
    // covers relay-level routes (e.g. the VAPID public key) as well as account routes.
    return withCors(request, env, async (req) => {
      const url = new URL(req.url);
      // Relay-level routes live under `/.well-known/` and are dispatched before account routing.
      if (isWellKnownPath(url.pathname)) return handleWellKnown(req, env);
      // Route by account id → its Durable Object.
      const accountId = url.pathname.split("/")[1] ?? "";
      if (!accountId) return new Response("missing account", { status: 400 });
      const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
      return stub.fetch(req);
    });
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
  auth_token_hash: string | null;
}

interface DevicePushTokenRow extends Record<string, string | number | null | ArrayBuffer> {
  device_id: string;
  transport: PushTransportKind;
  token: string;
  created_at: number;
}

/** A row of `webpush_trailing_wakeup`: a subscription owed one wakeup once its window ends. */
interface TrailingWakeupRow extends Record<string, string | number | null | ArrayBuffer> {
  account_id: string;
  device_id: string;
  token: string;
  due_at: number;
}

/**
 * The jobs that share this Durable Object's single alarm (see `alarms.ts`), in the order they run
 * when due together: expiry first, so a trailing wakeup never counts a request that just expired.
 */
type RelayAlarmPurpose = "request-expiry" | "webpush-trailing-wakeup";

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
  auth_token_hash: string | null;
}

interface AccountMetaRow extends Record<string, string | number | null | ArrayBuffer> {
  root_pubkey: string;
}

interface RequestRow extends Record<string, string | number | null | ArrayBuffer> {
  request_id: string;
  envelope: string;
  created_at: number;
  expires_at: number;
  status: string;
  terminal_at: number | null;
  auth_token_hash: string | null;
}

interface VerdictRow extends Record<string, string | number | null | ArrayBuffer> {
  request_id: string;
  verdict: string;
  device_id: string | null;
  received_at: number;
}

interface VerifiedAccountStateRow extends Record<string, string | number | null | ArrayBuffer> {
  state_jws: string;
  sequence: number;
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
const AUTH_TOKEN_BYTES = 32;
const MAX_ACCOUNT_STATE_DOCS = 16;
const MAX_ACCOUNT_STATE_JWS_BYTES = 32 * 1024;

/**
 * How long a used pairing-start `jti` is kept past its authorization's `expires_at`. Equal to the
 * core's `PAIRING_START_MAX_CLOCK_SKEW_MS` (60 s): a Durable Object re-instantiated on a host whose
 * clock lags the one that swept the row would otherwise accept the authorization as fresh again
 * with no replay record. Must never be smaller than that skew.
 */
const PAIRING_START_JTI_RETENTION_MARGIN_MS = 60 * 1000;

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

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/** Generate a high-entropy bearer token for relay-local endpoint authorization. */
function generateAuthToken(): string {
  const bytes = new Uint8Array(AUTH_TOKEN_BYTES);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/** Store only a stable hash of bearer tokens so SQLite rows are not reusable credentials. */
async function hashAuthToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return base64UrlEncode(new Uint8Array(digest));
}

function timingSafeEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

function bearerToken(request: Request): string | null {
  const auth = request.headers.get("Authorization") ?? "";
  const match = /^Bearer ([A-Za-z0-9_-]+)$/.exec(auth);
  if (match) return match[1] ?? null;
  const queryToken = new URL(request.url).searchParams.get("auth");
  return queryToken && /^[A-Za-z0-9_-]+$/.test(queryToken) ? queryToken : null;
}

function authError(status: 401 | 403): Response {
  return json(
    { error: status === 401 ? "authorization required" : "authorization denied" },
    status,
  );
}

/**
 * The relay's audited core could not be instantiated. Fail closed with a 500 that does not blame
 * the caller's input, and log the cause for the operator.
 */
function coreUnavailable(err: unknown): Response {
  console.error(
    "allw relay: core unavailable",
    err instanceof CoreUnavailableError ? err.cause : err,
  );
  return json({ error: "relay verification core unavailable" }, 500);
}

async function tokenMatches(storedHash: string | null, token: string | null): Promise<boolean> {
  if (storedHash === null) return false;
  if (token === null) return false;
  return timingSafeEqual(storedHash, await hashAuthToken(token));
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
  // Budget (push.ts): every stored token costs an outbound request per submit. Reject, never truncate.
  if (raw.length > MAX_PUSH_TOKENS_PER_REGISTRATION) return null;
  const tokens: IncomingPushToken[] = [];
  const seenTokens = new Set<string>();
  for (const item of raw) {
    if (!isPlainObject(item)) return null;
    const transport = item.transport;
    const rawToken = item.token;
    if (typeof transport !== "string" || !isPushTransportKind(transport)) return null;
    if (typeof rawToken !== "string" || rawToken.length < 1 || rawToken.length > 4096) return null;
    let token = rawToken;
    if (transport === "apns") {
      if (!/^[0-9a-fA-F]{64}$/.test(token)) return null;
      // Hex is case-insensitive: store one canonical spelling, so one device token spelled two ways
      // is one row (and one wakeup), and re-sending it in another case is a no-op (#304).
      token = token.toLowerCase();
    }
    if (transport === "fcm" && !/^[A-Za-z0-9:_-]{1,4096}$/.test(token)) return null;
    if (transport === "webpush") {
      // SECURITY (SSRF): a webpush token is the subscription endpoint the relay will POST to.
      // Store the normalized href, so one subscription spelled two ways is one row.
      const endpoint = parseWebPushEndpoint(token);
      if (!endpoint || endpoint.href.length > 4096) return null;
      token = endpoint.href;
    }
    // Duplicate registrations are idempotent for one device; collapse them before DB mutation so
    // a repeated token cannot half-complete pairing by tripping the push-token primary key.
    const tokenKey = `${transport}\0${token}`;
    if (seenTokens.has(tokenKey)) continue;
    seenTokens.add(tokenKey);
    tokens.push({ transport, token });
  }
  for (const transport of new Set(tokens.map((t) => t.transport))) {
    const count = tokens.filter((t) => t.transport === transport).length;
    if (count > MAX_PUSH_TOKENS_PER_TRANSPORT) return null;
  }
  return tokens;
}

function isCompactJws(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_ACCOUNT_STATE_JWS_BYTES &&
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)
  );
}

function requiredAccountStates(body: Record<string, unknown>): string[] | null {
  const raw = body.account_states;
  if (!Array.isArray(raw) || raw.length > MAX_ACCOUNT_STATE_DOCS) return null;
  const states: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (!isCompactJws(item)) return null;
    // The relay stores opaque root-signed account-state documents. Exact duplicates are harmless,
    // but collapsing them keeps the distribution response deterministic.
    if (seen.has(item)) continue;
    seen.add(item);
    states.push(item);
  }
  return states;
}

/**
 * The optional `max_sequence` a publisher may assert. `undefined` when absent; `null` when present
 * but not a non-negative safe integer. The relay never trusts it: when present it must equal the
 * highest *verified* sequence in the publish.
 */
function optionalAccountStateMaxSequence(body: Record<string, unknown>): number | null | undefined {
  const raw = body.max_sequence;
  if (raw === undefined) return undefined;
  return typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
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

/**
 * The relay's {@link WakeupClaimStore}: each Web Push subscription's last claim is the
 * `last_wakeup_at` column of its own `device_push_token` row. It survives Durable Object eviction,
 * so the one-per-window bound holds across it (#319). Removing the token removes its claim too.
 */
class DevicePushTokenClaimStore implements WakeupClaimStore {
  private readonly sql: SqlStorage;

  constructor(sql: SqlStorage) {
    this.sql = sql;
  }

  lastClaimedAt(key: string): number | undefined {
    const { deviceId, token } = parseWebPushCoalesceKey(key);
    const row = [
      ...this.sql.exec<{ last_wakeup_at: number | null }>(
        `SELECT last_wakeup_at FROM device_push_token
         WHERE device_id = ? AND transport = 'webpush' AND token = ?`,
        deviceId,
        token,
      ),
    ][0];
    return row?.last_wakeup_at ?? undefined;
  }

  recordClaim(key: string, atMs: number): void {
    const { deviceId, token } = parseWebPushCoalesceKey(key);
    this.sql.exec(
      `UPDATE device_push_token SET last_wakeup_at = ?
       WHERE device_id = ? AND transport = 'webpush' AND token = ?`,
      atMs,
      deviceId,
      token,
    );
  }
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
 * # Endpoint auth
 * Pairing completion, device presence, actor enrollment, device revocation, and request poll/wait
 * use relay-scoped bearer capability tokens introduced by #89. Token hashes are stored in SQLite;
 * plaintext bearer values are returned once to the caller. Pairing start is authorized by the
 * account root itself (a root-signed authorization verified by the core), and the first verified
 * root is bound in `account_meta`.
 */
export class AccountRelay implements DurableObject {
  private readonly sql: SqlStorage;
  private readonly ctx: DurableObjectState;
  private readonly pushTransports: PushTransportRegistry;
  /**
   * Spaces Web Push wakeups per subscription (`WEB_PUSH_COALESCE_MS`); see `schedulePushWakeups`.
   * Last claims are kept in SQLite ({@link DevicePushTokenClaimStore}).
   */
  private readonly webPushCoalescer: WakeupCoalescer;
  /**
   * Settles once every push fan-out started so far has finished, pruning included. Never rejects.
   * Only tests read it (to assert on the outcome of background delivery without sleeping).
   */
  private pushFanOut: Promise<void> = Promise.resolve();
  /** The single DO alarm, shared by every {@link RelayAlarmPurpose}. Never call `setAlarm` directly. */
  private readonly alarms: AlarmMultiplexer<RelayAlarmPurpose>;

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    this.pushTransports = buildPushTransports(env);
    this.initSchema();
    this.webPushCoalescer = new WakeupCoalescer(
      WEB_PUSH_COALESCE_MS,
      new DevicePushTokenClaimStore(this.sql),
    );
    this.alarms = new AlarmMultiplexer(ctx.storage);
    // On reactivation, restore every alarm purpose from its persisted rows, in case the previous
    // isolate exited after a write but before the scheduled alarm was durably restored.
    this.ctx.waitUntil(this.armExpiryAlarm().then(() => this.armTrailingWakeupAlarm()));
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
        created_at INTEGER NOT NULL,
        auth_token_hash TEXT
      );

      -- last_wakeup_at: for a webpush token, when its most recent wakeup was claimed (epoch ms),
      -- read by the coalescer so its one-per-window bound survives eviction (#319). NULL if never.
      CREATE TABLE IF NOT EXISTS device_push_token (
        device_id      TEXT    NOT NULL,
        transport      TEXT    NOT NULL,
        token          TEXT    NOT NULL,
        created_at     INTEGER NOT NULL,
        last_wakeup_at INTEGER,
        PRIMARY KEY (device_id, transport, token)
      );

      -- Web Push subscriptions owed one trailing wakeup: a submit was coalesced (skipped) while
      -- the subscription's window was open, so it may have landed after the service worker's
      -- inbox fetch. One row per subscription, sent when its window ends (due_at) via the alarm.
      -- Routing metadata only. account_id is this DO's own account, kept for the wakeup payload.
      -- last_skipped_at is the latest skipped submit: a later wakeup accepted by the push service
      -- clears the row only if it was claimed after that submit (it then covers it).
      CREATE TABLE IF NOT EXISTS webpush_trailing_wakeup (
        account_id      TEXT    NOT NULL,
        device_id       TEXT    NOT NULL,
        token           TEXT    NOT NULL,
        due_at          INTEGER NOT NULL,
        last_skipped_at INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (device_id, token)
      );

      CREATE TABLE IF NOT EXISTS actor (
        actor_id   TEXT    PRIMARY KEY,
        pubkey     TEXT    NOT NULL,
        label      TEXT,
        created_at INTEGER NOT NULL
      );

      -- The account root this Durable Object is bound to: written once, by the first pairing
      -- start whose root-signed authorization verified against a root that derives to this
      -- account's id. Later root-signed calls are verified against this row. Public key only.
      CREATE TABLE IF NOT EXISTS account_meta (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        root_pubkey TEXT    NOT NULL,
        bound_at    INTEGER NOT NULL
      );

      -- One-time ids of accepted pairing-start authorizations, kept until the authorization
      -- expires so a replay inside its validity window is rejected. Expired rows are swept on the
      -- next pairing start; an authorization past expires_at is rejected by the core anyway.
      CREATE TABLE IF NOT EXISTS pairing_start_jti (
        jti        TEXT    PRIMARY KEY,
        expires_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS pairing (
        code       TEXT    PRIMARY KEY,
        label      TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used       INTEGER NOT NULL DEFAULT 0,
        auth_token_hash TEXT
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
        terminal_at INTEGER,
        auth_token_hash TEXT
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

      -- Root-signed account-state documents the relay itself verified (core verify_account_state)
      -- against the account's bound root and id. Only the highest verified sequence is kept: a
      -- publish replaces these rows only with verified documents at a strictly higher sequence.
      -- Normally one row; more than one only if the root signed distinct documents at the same
      -- sequence, which verifiers resolve fail-closed (union of revocations).
      CREATE TABLE IF NOT EXISTS verified_account_state (
        state_jws   TEXT    PRIMARY KEY,
        sequence    INTEGER NOT NULL,
        verified_at INTEGER NOT NULL
      );

      -- The pre-#242 opaque cache stored unverified strings and a caller-asserted max_sequence (one
      -- junk publish at 2^53-1 blocked every later honest publish). Nothing in it can be trusted,
      -- so it is dropped; the root holder republishes verified state.
      DROP TABLE IF EXISTS account_state;
      DROP TABLE IF EXISTS account_state_meta;
    `);
    try {
      this.sql.exec(`ALTER TABLE request ADD COLUMN terminal_at INTEGER`);
    } catch {
      // Existing fresh schemas already have the column; older local DO state is migrated above.
    }
    for (const migration of [
      `ALTER TABLE device ADD COLUMN auth_token_hash TEXT`,
      `ALTER TABLE pairing ADD COLUMN auth_token_hash TEXT`,
      `ALTER TABLE request ADD COLUMN auth_token_hash TEXT`,
      `ALTER TABLE device_push_token ADD COLUMN last_wakeup_at INTEGER`,
      `ALTER TABLE webpush_trailing_wakeup ADD COLUMN last_skipped_at INTEGER NOT NULL DEFAULT 0`,
    ]) {
      try {
        this.sql.exec(migration);
      } catch {
        // Fresh schemas already have the column; older local DO state is migrated above.
      }
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
    // APNs tokens are stored lowercase (#304). Rows stored before that may be in any case: keep one
    // row per device and token ignoring case (two spellings would collide once lowercased), then
    // lowercase what is left. The survivor is the earliest registration (lowest created_at, rowid
    // breaking ties), so the token keeps the created_at of when the device first registered it.
    // Idempotent; on an already-canonical table both statements change nothing.
    this.sql.exec(`
      DELETE FROM device_push_token
      WHERE transport = 'apns'
        AND EXISTS (
          SELECT 1 FROM device_push_token AS earlier
          WHERE earlier.transport = 'apns'
            AND earlier.device_id = device_push_token.device_id
            AND lower(earlier.token) = lower(device_push_token.token)
            AND (
              earlier.created_at < device_push_token.created_at
              OR (
                earlier.created_at = device_push_token.created_at
                AND earlier.rowid < device_push_token.rowid
              )
            )
        );

      UPDATE device_push_token SET token = lower(token)
      WHERE transport = 'apns' AND token <> lower(token);
    `);
    // Pending requests by deadline. Every submit and trailing wakeup reads the latest pending
    // deadline (latestPendingRequest), and the expiry alarm the earliest (armExpiryAlarm). Partial,
    // so terminal rows awaiting the retention sweep cost nothing. Idempotent, like the
    // migrations above; it runs after them, so the columns it names always exist.
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS request_pending_by_expiry
       ON request (expires_at) WHERE status = 'pending'`,
    );
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

    // POST /pairing/start — root-signed; binds the account root on first success.
    if (method === "POST" && path0 === "pairing" && path1 === "start") {
      return this.handlePairingStart(request, segments[0] ?? "");
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

    // POST /account-states — anyone may publish; only documents verified against the bound root
    // are stored.
    if (method === "POST" && path0 === "account-states" && !path1) {
      return this.handleAccountStatePublish(request, segments[0] ?? "");
    }

    // GET /account-states — unauthenticated: the documents are public and relay-verified.
    if (method === "GET" && path0 === "account-states" && !path1) {
      return this.handleAccountStateList();
    }

    // GET /devices
    if (method === "GET" && path0 === "devices" && !path1) {
      return this.handleDeviceList();
    }

    // POST /devices/{device_id}/revoke
    if (method === "POST" && path0 === "devices" && path1 !== "" && path2 === "revoke") {
      return this.handleDeviceRevoke(path1, request);
    }

    // PUT /devices/{device_id}/push-tokens — the device replaces its own push-token set.
    if (
      method === "PUT" &&
      path0 === "devices" &&
      path1 !== "" &&
      path2 === "push-tokens" &&
      (subSegments[3] ?? "") === ""
    ) {
      return this.handleDevicePushTokens(path1, request);
    }

    // GET /devices/{device_id}/inbox — authenticated device polls its pending envelopes.
    if (method === "GET" && path0 === "devices" && path1 !== "" && path2 === "inbox") {
      return this.handleDeviceInbox(path1, request);
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
      return this.handleIntegratorWait(path1, request);
    }

    // GET /requests/{request_id} — integrator polls request status / fetches the verdict.
    if (method === "GET" && path0 === "requests" && path1 !== "" && path2 === "") {
      return this.handleGetRequest(path1, request);
    }

    // POST /requests/{request_id}/retract — integrator cancels its own pending request (#195).
    if (method === "POST" && path0 === "requests" && path1 !== "" && path2 === "retract") {
      return this.handleRetract(path1, request);
    }

    // 405 only for a KNOWN route path reached with an unsupported method; any other (unknown)
    // sub-path is a 404 — e.g. `GET /devices/<id>` or `GET /pairing/unknown` are not routes.
    const isKnownRoutePath =
      (path0 === "pairing" && (path1 === "start" || path1 === "complete") && path2 === "") ||
      (path0 === "actors" && path1 === "") ||
      (path0 === "account-states" && path1 === "") ||
      (path0 === "devices" && path1 === "") ||
      (path0 === "devices" &&
        path1 !== "" &&
        path2 === "revoke" &&
        (subSegments[3] ?? "") === "") ||
      (path0 === "devices" && path1 !== "" && path2 === "inbox" && (subSegments[3] ?? "") === "") ||
      (path0 === "devices" &&
        path1 !== "" &&
        path2 === "push-tokens" &&
        (subSegments[3] ?? "") === "") ||
      (path0 === "devices" &&
        path1 !== "" &&
        path2 === "connect" &&
        (subSegments[3] ?? "") === "") ||
      (path0 === "requests" && path1 === "") ||
      (path0 === "requests" && path1 !== "" && path2 === "" && (subSegments[2] ?? "") === "") ||
      (path0 === "requests" && path1 !== "" && path2 === "wait" && (subSegments[3] ?? "") === "") ||
      (path0 === "requests" &&
        path1 !== "" &&
        path2 === "retract" &&
        (subSegments[3] ?? "") === "");
    if (isKnownRoutePath) {
      return json({ error: "method not allowed" }, 405);
    }

    return json({ error: "not found" }, 404);
  }

  // ---------------------------------------------------------------------------
  // Route handlers
  // ---------------------------------------------------------------------------

  private async authorizeStoredHash(
    request: Request,
    storedHash: string | null | undefined,
  ): Promise<Response | null> {
    // A missing hash is a legacy/migration row, not proof of authorization. Fail closed and require
    // re-pairing or re-submission so no endpoint silently falls back to unauthenticated access.
    if (storedHash === null || storedHash === undefined) return authError(401);
    const token = bearerToken(request);
    if (token === null) return authError(401);
    return (await tokenMatches(storedHash, token)) ? null : authError(403);
  }

  private async authorizedDeviceId(request: Request): Promise<string | Response> {
    const token = bearerToken(request);
    if (token === null) return authError(401);
    const tokenHash = await hashAuthToken(token);
    const rows = [
      ...this.sql.exec<DeviceRow>(
        `SELECT device_id, auth_token_hash FROM device WHERE auth_token_hash IS NOT NULL`,
      ),
    ];
    for (const row of rows) {
      if (row.auth_token_hash !== null && timingSafeEqual(row.auth_token_hash, tokenHash)) {
        return row.device_id;
      }
    }
    return authError(403);
  }

  /**
   * The account-root public key this Durable Object is bound to, or `null` before the first
   * verified root-signed pairing start. Root-authorized operations verify against this row.
   */
  private boundRootPubkey(): string | null {
    const rows = [
      ...this.sql.exec<AccountMetaRow>(`SELECT root_pubkey FROM account_meta WHERE id = 1`),
    ];
    return rows[0]?.root_pubkey ?? null;
  }

  /**
   * Whether this unbound account already holds rows that, under the pre-binding relay, anyone could
   * create for any account id: devices, pairing codes, or actors. Binding a root over them would
   * make them look root-authorized, so the first bind refuses (see the module doc). The legacy
   * unverified account-state tables are dropped at schema init instead (nothing in them is
   * trusted); `verified_account_state` can only be written once a root is bound, so it is checked
   * here as defense in depth.
   */
  private hasPreBindingState(): boolean {
    for (const table of ["device", "pairing", "actor", "verified_account_state"]) {
      if ([...this.sql.exec(`SELECT 1 FROM ${table} LIMIT 1`)].length > 0) return true;
    }
    return false;
  }

  /**
   * POST /pairing/start
   * Body: { root_pubkey: string (b64url Ed25519), authorization: string (allw-pairing-start+jws),
   *         label?: string }
   * Response: { code: string, expires_at: number, pairing_auth_token: string }
   *
   * Only the account root may start a pairing, because a pairing code enrolls a device that every
   * later request is encrypted to. The relay checks, fail-closed:
   * - 400: invalid JSON, `root_pubkey` malformed, or `{acct}` does not derive from `root_pubkey`
   * - 401: `authorization` missing
   * - 403: the core rejects `authorization` (bad signature, wrong `typ`, wrong `account_id`,
   *        expired / not-yet-valid / overlong window), its `jti` was already used, or the presented
   *        root differs from the root already bound to this account
   * - 409: no root is bound yet but the account already holds devices, pairing codes or actors
   *        from before root binding (refused, never purged — see the module doc)
   * - 500: the relay's core wasm failed to initialize (logged; nothing about the request is judged)
   *
   * On success the root is bound to the account (first time only) and a short pairing code plus its
   * pairing auth token are issued. See `docs/relay-api.md` §3 Pairing.
   */
  private async handlePairingStart(request: Request, accountId: string): Promise<Response> {
    try {
      ensureCore();
    } catch (err) {
      return coreUnavailable(err);
    }

    const body = await parseJsonBody(request);
    if (!body) return json({ error: "invalid JSON body" }, 400);

    const rootPubkey = requiredString(body, "root_pubkey");
    if (rootPubkey === null || !validatePubkey(rootPubkey)) {
      return json({ error: "'root_pubkey' must be a base64url-unpadded 32-byte public key" }, 400);
    }
    try {
      checkAccountIdForRoot(accountId, rootPubkey);
    } catch {
      return json(
        {
          error:
            "'root_pubkey' is not a valid Ed25519 key or the account id does not derive from it",
        },
        400,
      );
    }

    const authorization = requiredString(body, "authorization");
    if (authorization === null) return authError(401);
    const label = optionalString(body, "label");

    // Mint the pairing secret before the critical section so nothing below awaits: the verify,
    // replay check, root bind, and code insert run without interleaving another request.
    const code = generatePairingCode();
    const pairingAuthToken = generateAuthToken();
    const pairingAuthTokenHash = await hashAuthToken(pairingAuthToken);
    const now = Date.now();

    let jti: string;
    let jtiExpiresAt: number;
    try {
      const claims = verifyPairingStartAuthorization(authorization, accountId, rootPubkey, now);
      jti = claims.jti;
      jtiExpiresAt = claims.expires_at;
    } catch {
      return authError(403);
    }

    // Defense in depth: the id derives from the root, so a different bound root would need a
    // SHA-256 collision. Never let a second root act on an account regardless.
    const boundRoot = this.boundRootPubkey();
    if (boundRoot !== null && boundRoot !== rootPubkey) return authError(403);
    if (boundRoot === null && this.hasPreBindingState()) {
      return json(
        {
          error:
            "account has devices, pairing codes or actors from before root binding; " +
            "refusing to bind a root over them (use a new account root)",
        },
        409,
      );
    }

    this.sql.exec(
      `DELETE FROM pairing_start_jti WHERE expires_at + ? <= ?`,
      PAIRING_START_JTI_RETENTION_MARGIN_MS,
      now,
    );
    const replayed = [...this.sql.exec(`SELECT jti FROM pairing_start_jti WHERE jti = ?`, jti)]
      .length;
    if (replayed > 0) return authError(403);

    const expiresAt = now + PAIRING_TTL_MS;
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        `INSERT INTO pairing_start_jti (jti, expires_at) VALUES (?, ?)`,
        jti,
        jtiExpiresAt,
      );
      if (boundRoot === null) {
        this.sql.exec(
          `INSERT INTO account_meta (id, root_pubkey, bound_at) VALUES (1, ?, ?)`,
          rootPubkey,
          now,
        );
      }
      this.sql.exec(
        `INSERT INTO pairing (code, label, created_at, expires_at, used, auth_token_hash)
         VALUES (?, ?, ?, ?, 0, ?)`,
        code,
        label ?? null,
        now,
        expiresAt,
        pairingAuthTokenHash,
      );
    });

    return json({ code, expires_at: expiresAt, pairing_auth_token: pairingAuthToken }, 201);
  }

  /**
   * POST /pairing/complete
   * Body: { code: string, pubkey: string (b64url 32 bytes), label?: string,
   *         push_tokens?: Array<{ transport: "apns" | "fcm" | "webpush", token: string }> }
   * Response: { device_id: string }
   *
   * Validates the pairing code and enrolls the device's public key.
   * - 403: no account root is bound (a pairing code on an unbound account predates root binding,
   *        so it was never root-authorized), or the pairing auth token is wrong
   * - 404: code not found
   * - 409: code already used, or the account's push-token budget is full (code not consumed)
   * - 410: code expired
   * - 400: invalid pubkey (not base64url or not 32 bytes), or invalid / over-budget push_tokens
   */
  private async handlePairingComplete(request: Request): Promise<Response> {
    // Every pairing row this relay issues is created together with (or after) the root bind, so a
    // code on an unbound account is a pre-binding leftover: never let it enroll a device.
    if (this.boundRootPubkey() === null) {
      return json({ error: "account root not bound; start a root-signed pairing first" }, 403);
    }

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
        `SELECT code, label, created_at, expires_at, used, auth_token_hash FROM pairing WHERE code = ?`,
        code,
      ),
    ];
    const pairing = rows[0];
    if (!pairing) return json({ error: "pairing code not found" }, 404);
    const authFailure = await this.authorizeStoredHash(request, pairing.auth_token_hash);
    if (authFailure) return authFailure;
    if (pairing.used !== 0) return json({ error: "pairing code already used" }, 409);
    if (Date.now() > pairing.expires_at) {
      return json({ error: "pairing code expired" }, 410);
    }

    const deviceId = crypto.randomUUID();
    const deviceAuthToken = generateAuthToken();
    const deviceAuthTokenHash = await hashAuthToken(deviceAuthToken);
    const now = Date.now();
    // Checked after the last await so the count and the inserts below are one atomic step.
    const pushTokenBudget = this.pushTokenBudgetFailure(pushTokens.length);
    if (pushTokenBudget) return pushTokenBudget;

    // Mark the code as used and insert the device record atomically.
    // SECURITY: only the public key (pubkey) is stored — no private key ever touches this table.
    this.sql.exec(`UPDATE pairing SET used = 1 WHERE code = ?`, code);
    this.sql.exec(
      `INSERT INTO device (device_id, pubkey, label, created_at, auth_token_hash)
       VALUES (?, ?, ?, ?, ?)`,
      deviceId,
      pubkey,
      // Fall back to the label supplied at /pairing/start so that field stays meaningful when
      // /pairing/complete omits its own.
      label ?? pairing.label ?? null,
      now,
      deviceAuthTokenHash,
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

    return json({ device_id: deviceId, device_auth_token: deviceAuthToken }, 201);
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
    const authorizedDevice = await this.authorizedDeviceId(request);
    if (authorizedDevice instanceof Response) return authorizedDevice;

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

  /** The stored relay-verified account-state documents and their (shared) highest sequence. */
  private verifiedAccountStates(): { states: string[]; sequence: number | null } {
    const rows = [
      ...this.sql.exec<VerifiedAccountStateRow>(
        `SELECT state_jws, sequence FROM verified_account_state ORDER BY state_jws ASC`,
      ),
    ];
    let sequence: number | null = null;
    for (const row of rows)
      sequence = sequence === null ? row.sequence : Math.max(sequence, row.sequence);
    return { states: rows.map((row) => row.state_jws), sequence };
  }

  /**
   * POST /account-states
   * Body: { account_states: string[] (1–16 compact JWS), max_sequence?: number }
   * Response: { account_states: string[], max_sequence: number }
   *
   * No device token: authority comes from the account root's signature, which the core verifies
   * (`verify_account_state`) for every submitted document against the root bound to this account
   * and the path's account id. Fail-closed and all-or-nothing — any rejection leaves the stored
   * state unchanged:
   * - 400: malformed body, a string that is not a compact JWS, a non-integer `max_sequence`, an
   *        asserted `max_sequence` that differs from the highest verified sequence, or a verified
   *        sequence outside the exactly-representable range (> 2^53-1)
   * - 403: any document fails verification (other signer, wrong account id, wrong root, wrong
   *        `typ`, unsupported version, junk)
   * - 409: no root is bound yet (start a root-signed pairing first), or the highest verified
   *        sequence is not strictly above the stored one
   * - 500: the relay's core wasm failed to initialize (logged; no document is judged)
   *
   * On success the stored documents are replaced by the submitted documents at the highest verified
   * sequence. See `docs/relay-api.md` §3 Account state.
   */
  private async handleAccountStatePublish(request: Request, accountId: string): Promise<Response> {
    // A broken core must not surface as a 403 that blames the caller's documents.
    try {
      ensureCore();
    } catch (err) {
      return coreUnavailable(err);
    }

    const body = await parseJsonBody(request);
    if (!body) return json({ error: "invalid JSON body" }, 400);

    const accountStates = requiredAccountStates(body);
    if (accountStates === null || accountStates.length === 0) {
      return json(
        {
          error: `'account_states' must be an array of 1 to ${String(MAX_ACCOUNT_STATE_DOCS)} compact JWS strings`,
        },
        400,
      );
    }
    const assertedMaxSequence = optionalAccountStateMaxSequence(body);
    if (assertedMaxSequence === null) {
      return json({ error: "'max_sequence' must be a non-negative safe integer" }, 400);
    }

    const boundRoot = this.boundRootPubkey();
    if (boundRoot === null) {
      return json(
        { error: "account root not bound; start a root-signed pairing for this account first" },
        409,
      );
    }

    // Verify every document before touching storage; nothing below awaits.
    const verified: { stateJws: string; sequence: number }[] = [];
    for (const stateJws of accountStates) {
      let sequence: number;
      try {
        sequence = verifyAccountState(stateJws, accountId, boundRoot).sequence;
      } catch {
        return json(
          { error: "an account-state document did not verify against the account root" },
          403,
        );
      }
      if (!Number.isSafeInteger(sequence)) {
        return json({ error: "account-state sequence exceeds 2^53-1" }, 400);
      }
      verified.push({ stateJws, sequence });
    }
    const highest = Math.max(...verified.map((doc) => doc.sequence));
    if (assertedMaxSequence !== undefined && assertedMaxSequence !== highest) {
      return json(
        {
          error: `'max_sequence' ${String(assertedMaxSequence)} does not equal the highest verified sequence ${String(highest)}`,
        },
        400,
      );
    }

    const stored = this.verifiedAccountStates().sequence;
    if (stored !== null && highest <= stored) {
      return json(
        {
          error: `account-state sequence ${String(highest)} is not above the current ${String(stored)}`,
        },
        409,
      );
    }

    const now = Date.now();
    const current = verified.filter((doc) => doc.sequence === highest).map((doc) => doc.stateJws);
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(`DELETE FROM verified_account_state`);
      for (const stateJws of current) {
        this.sql.exec(
          `INSERT INTO verified_account_state (state_jws, sequence, verified_at) VALUES (?, ?, ?)`,
          stateJws,
          highest,
          now,
        );
      }
    });

    return json({ account_states: [...current].sort(), max_sequence: highest });
  }

  /**
   * GET /account-states
   * Response: { account_states: string[], max_sequence: number }
   *
   * Unauthenticated: the documents are public, root-signed, and only ever stored after the relay
   * verified them against the bound root (so integrators, which hold no device token, can read
   * them — #243). `max_sequence` is the highest verified sequence (0 when none is stored).
   * Consumers still verify the root signature themselves; the relay is not the trust anchor.
   */
  private handleAccountStateList(): Response {
    const { states, sequence } = this.verifiedAccountStates();
    return json({ account_states: states, max_sequence: sequence ?? 0 });
  }

  /**
   * POST /devices/{device_id}/revoke
   * Response: { revoked: true } | 404
   *
   * Removes the device record. Returns 404 if the device is not enrolled.
   */
  private async handleDeviceRevoke(deviceId: string, request: Request): Promise<Response> {
    const authorizedDevice = await this.authorizedDeviceId(request);
    if (authorizedDevice instanceof Response) return authorizedDevice;
    const existing = [
      ...this.sql.exec<DeviceRow>(`SELECT device_id FROM device WHERE device_id = ?`, deviceId),
    ];
    if (existing.length === 0) {
      return json({ error: "device not found" }, 404);
    }
    if (authorizedDevice !== deviceId) {
      return authError(403);
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

  /**
   * PUT /devices/{device_id}/push-tokens
   * Body: { push_tokens: Array<{ transport: "apns" | "fcm" | "webpush", token: string }> }
   * Response: 200 { push_tokens: [...] } — the device's stored set after the replace.
   *
   * Replaces the calling device's push-token set, so a paired device can add, rotate, or clear
   * (`[]`) its tokens, e.g. a browser that subscribes to Web Push only after pairing. Validation
   * is `optionalPushTokens`, shared with `/pairing/complete`, so the two cannot drift. Self only,
   * in the revoke handler's order:
   * - 401: no bearer; 403: the bearer is no device's token (including a revoked device's own)
   * - 404: `{device_id}` is not enrolled (or was revoked)
   * - 403: the bearer belongs to another device
   * - 400: invalid JSON, `push_tokens` missing, or invalid / over-budget per registration
   * - 409: a growing set would exceed the account push-token budget (the device's own rows don't
   *        count; a set that stays the same size or shrinks is never refused)
   *
   * The replace is a diff applied in one transaction: unchanged tokens keep their row (and
   * `created_at`), so repeating the same body is a no-op.
   */
  private async handleDevicePushTokens(deviceId: string, request: Request): Promise<Response> {
    const authorizedDevice = await this.authorizedDeviceId(request);
    if (authorizedDevice instanceof Response) return authorizedDevice;
    const body = await parseJsonBody(request);
    // Everything below is synchronous, so the device checks, budget, and writes are one atomic step.
    const enrolled = [
      ...this.sql.exec<DeviceRow>(`SELECT device_id FROM device WHERE device_id = ?`, deviceId),
    ];
    if (enrolled.length === 0) return json({ error: "device not found" }, 404);
    if (authorizedDevice !== deviceId) return authError(403);

    if (!body) return json({ error: "invalid JSON body" }, 400);
    if (body.push_tokens === undefined) {
      return json({ error: "'push_tokens' is required (array; [] clears)" }, 400);
    }
    const desired = optionalPushTokens(body);
    if (desired === null) {
      return json({ error: "'push_tokens' must contain supported transport/token pairs" }, 400);
    }

    const current = [
      ...this.sql.exec<DevicePushTokenRow>(
        `SELECT device_id, transport, token, created_at FROM device_push_token WHERE device_id = ?`,
        deviceId,
      ),
    ];
    // The budget gates growth only: a set that stays the same size or shrinks is always allowed,
    // so a device can clear or trim its tokens even on an account already over the budget (rows
    // registered before budgets existed).
    if (desired.length > current.length) {
      const otherDevicesRow = [
        ...this.sql.exec<{ n: number }>(
          `SELECT COUNT(*) AS n FROM device_push_token WHERE device_id != ?`,
          deviceId,
        ),
      ][0];
      if ((otherDevicesRow?.n ?? 0) + desired.length > MAX_PUSH_TOKENS_PER_ACCOUNT) {
        return json({ error: "account push-token limit reached" }, 409);
      }
    }
    const { remove, add } = diffPushTokenSet(current, desired);
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      for (const gone of remove) {
        this.sql.exec(
          `DELETE FROM device_push_token WHERE device_id = ? AND transport = ? AND token = ?`,
          deviceId,
          gone.transport,
          gone.token,
        );
      }
      for (const entry of add) {
        this.sql.exec(
          `INSERT INTO device_push_token (device_id, transport, token, created_at)
           VALUES (?, ?, ?, ?)`,
          deviceId,
          entry.transport,
          entry.token,
          now,
        );
      }
    });
    return json({
      push_tokens: desired.map(({ transport, token }) => ({ transport, token })),
    });
  }

  // ---------------------------------------------------------------------------
  // Ciphertext routing + verdict relay (issue #11)
  // ---------------------------------------------------------------------------

  /**
   * GET /devices/{device_id}/inbox
   *
   * HTTP polling counterpart to the WebSocket offline-queue flush. Returns the full relay-visible
   * envelope (routing/lifecycle + opaque `context_ciphertext`) for every pending, non-expired
   * request addressed to this account, so a web-surface approver can poll on a 1–5s interval
   * without holding a WebSocket connection (issue #147).
   *
   * The relay never sees plaintext (zero-knowledge invariant). The response is the same ciphertext
   * the device would receive via the WebSocket offline-queue flush; the web approver decrypts on
   * device. Fail-closed: only `pending` requests whose `expires_at > now` are returned — an
   * already-expired request is never included (it cannot be approved; contract §Invariants #6).
   *
   * Auth: device bearer token (same token as `…/connect`).
   * Returns 404 if the device is not enrolled, 401/403 on auth failure.
   */
  private async handleDeviceInbox(deviceId: string, request: Request): Promise<Response> {
    const enrolled = [
      ...this.sql.exec<DeviceRow>(
        `SELECT device_id, auth_token_hash FROM device WHERE device_id = ?`,
        deviceId,
      ),
    ];
    const device = enrolled[0];
    if (!device) {
      return json({ error: "device not enrolled" }, 404);
    }
    const authFailure = await this.authorizeStoredHash(request, device.auth_token_hash);
    if (authFailure) return authFailure;

    const now = Date.now();
    const pending = [
      ...this.sql.exec<RequestRow>(
        `SELECT request_id, envelope FROM request
         WHERE status = 'pending' AND expires_at > ? ORDER BY created_at ASC`,
        now,
      ),
    ];

    const envelopes = pending.map((p) => JSON.parse(p.envelope) as unknown);
    return json({ envelopes });
  }

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
  private async handleDeviceConnect(deviceId: string, request: Request): Promise<Response> {
    const enrolled = [
      ...this.sql.exec<DeviceRow>(
        `SELECT device_id, auth_token_hash FROM device WHERE device_id = ?`,
        deviceId,
      ),
    ];
    const device = enrolled[0];
    if (!device) {
      return json({ error: "device not enrolled" }, 404);
    }
    const authFailure = await this.authorizeStoredHash(request, device.auth_token_hash);
    if (authFailure) return authFailure;
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
    const requestAuthToken = generateAuthToken();
    const requestAuthTokenHash = await hashAuthToken(requestAuthToken);

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
        `INSERT INTO request
         (request_id, envelope, created_at, expires_at, status, terminal_at, auth_token_hash)
         VALUES (?, ?, ?, ?, 'pending', NULL, ?)`,
        id,
        JSON.stringify(envelope),
        now,
        expiresAt,
        requestAuthTokenHash,
      );
    } catch {
      // Primary-key conflict: a concurrent submit with this id won the race → consistently a 409.
      return json({ error: "request already submitted" }, 409);
    }
    await this.armExpiryAlarm();

    const delivered = this.sendRequestToOneSocketPerSurface(id, envelope);
    const { scheduled: pushWakeups, coalesced } = this.schedulePushWakeups(
      accountId,
      id,
      expiresAt,
    );
    if (coalesced > 0) await this.armTrailingWakeupAlarm();

    return this.requestSubmitResponse(id, delivered, pushWakeups, requestAuthToken);
  }

  private async authorizeRequestRead(
    requestId: string,
    request: Request,
  ): Promise<{ row: RequestRow; status: string } | Response> {
    const rows = [
      ...this.sql.exec<RequestRow>(
        `SELECT request_id, status, expires_at, auth_token_hash FROM request WHERE request_id = ?`,
        requestId,
      ),
    ];
    const req = rows[0];
    if (!req) return json({ error: "request not found" }, 404);
    const authFailure = await this.authorizeStoredHash(request, req.auth_token_hash);
    if (authFailure) return authFailure;
    return {
      row: req,
      status: this.expireIfDue(requestId, req.status, req.expires_at, Date.now()),
    };
  }

  private requestSubmitResponse(
    id: string,
    delivered: number,
    pushWakeups: number,
    requestAuthToken: string,
  ): Response {
    return json(
      {
        request_id: id,
        status: "pending",
        delivered_to: delivered,
        push_wakeups: pushWakeups,
        request_auth_token: requestAuthToken,
      },
      202,
    );
  }

  /**
   * Schedule push wakeups to registered device push tokens: at most a request id (Web Push sends no
   * payload at all). Only tokens whose transport is configured are scheduled, newest registrations
   * first, up to the account budget. Each wakeup carries the latest deadline among the account's
   * pending requests (see `PushWakeup.expiresAt`), never just this request's.
   *
   * Web Push coalescing: if a subscription has a wakeup in flight, or was woken within
   * `WEB_PUSH_COALESCE_MS`, it is skipped. Submit needs no caller auth, so this is what bounds push
   * volume per subscription. The check-and-claim runs synchronously here, before any `await`, so
   * concurrent submits cannot both claim.
   *
   * A skipped subscription is recorded in `webpush_trailing_wakeup` and woken once more when its
   * window ends (see {@link sendTrailingWakeups}). The earlier wakeup may already have been fetched
   * before this request was stored, so without that the request could get no push at all. A
   * subscription that is claimed here keeps any owed trailing row until the push service accepts
   * this wakeup. Only then is the row cleared, and only if every skipped submit came before this
   * claim (see {@link clearCoveredTrailingWakeups}). A failed push therefore leaves the owed wakeup
   * to retry once, when the new window ends.
   *
   * The fan-out runs **off the response path** under `waitUntil`, so a slow or hung push service can
   * never delay or fail the submit. Returns how many wakeups were scheduled and how many Web Push
   * subscriptions were coalesced. When the second is non-zero the caller arms the alarm with
   * {@link armTrailingWakeupAlarm}.
   */
  private schedulePushWakeups(
    accountId: string,
    requestId: string,
    expiresAt: number,
  ): { scheduled: number; coalesced: number } {
    const now = Date.now();
    const claimedWebPushKeys: string[] = [];
    let coalesced = 0;
    const tokens = schedulablePushTokens(
      [
        ...this.sql.exec<DevicePushTokenRow>(
          `SELECT device_id, transport, token, created_at FROM device_push_token
           ORDER BY created_at DESC LIMIT ?`,
          MAX_PUSH_TOKENS_PER_ACCOUNT,
        ),
      ],
      this.pushTransports,
    ).filter((token) => {
      if (token.transport !== "webpush") return true;
      const key = webPushCoalesceKey(token.device_id, token.token);
      if (!this.webPushCoalescer.tryClaim(key, now)) {
        coalesced++;
        // The first skip in a window fixes the due time; later skips only advance last_skipped_at.
        this.sql.exec(
          `INSERT INTO webpush_trailing_wakeup
             (account_id, device_id, token, due_at, last_skipped_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (device_id, token)
           DO UPDATE SET last_skipped_at = MAX(last_skipped_at, excluded.last_skipped_at)`,
          accountId,
          token.device_id,
          token.token,
          this.webPushCoalescer.nextClaimableAt(key, now),
          now,
        );
        return false;
      }
      // An owed trailing wakeup stays until this wakeup is accepted (see clearCoveredTrailingWakeups),
      // so a failed push still gets its retry. It cannot be due inside the new window.
      this.sql.exec(
        `UPDATE webpush_trailing_wakeup SET due_at = MAX(due_at, ?) WHERE device_id = ? AND token = ?`,
        this.webPushCoalescer.nextClaimableAt(key, now),
        token.device_id,
        token.token,
      );
      claimedWebPushKeys.push(key);
      return true;
    });
    // The just-stored request is pending, so the latest pending deadline is never before its own.
    const wakeupExpiresAt = Math.max(expiresAt, this.latestPendingRequest(now)?.expires_at ?? 0);
    this.startPushFanOut(tokens, claimedWebPushKeys, accountId, requestId, wakeupExpiresAt, now);
    return { scheduled: tokens.length, coalesced };
  }

  /**
   * Start one background fan-out under `waitUntil`, then release the coalescing claims it holds,
   * whatever the outcome. Does nothing for an empty token list.
   */
  private startPushFanOut(
    tokens: readonly StoredPushToken[],
    claimedWebPushKeys: readonly string[],
    accountId: string,
    requestId: string,
    expiresAt: number,
    claimedAt: number,
  ): void {
    if (tokens.length === 0) return;
    const fanOut = this.deliverPushWakeups(
      tokens,
      accountId,
      requestId,
      expiresAt,
      claimedAt,
    ).finally(() => {
      for (const key of claimedWebPushKeys) this.webPushCoalescer.release(key);
    });
    this.pushFanOut = Promise.all([this.pushFanOut, fanOut]).then(() => undefined);
    this.ctx.waitUntil(fanOut);
  }

  /**
   * The pending, unexpired request with the latest deadline, or `undefined` if none. Its deadline
   * is how long any wakeup stays useful: a wakeup leads to an inbox fetch that returns every pending
   * request.
   */
  private latestPendingRequest(
    now: number,
  ): { request_id: string; expires_at: number } | undefined {
    return [
      ...this.sql.exec<{ request_id: string; expires_at: number }>(
        `SELECT request_id, expires_at FROM request
         WHERE status = 'pending' AND expires_at > ?
         ORDER BY expires_at DESC LIMIT 1`,
        now,
      ),
    ][0];
  }

  /** Point the `webpush-trailing-wakeup` alarm purpose at the earliest owed trailing wakeup, if any. */
  private async armTrailingWakeupAlarm(): Promise<void> {
    const next = [
      ...this.sql.exec<{ next: number | null }>(
        `SELECT MIN(due_at) AS next FROM webpush_trailing_wakeup`,
      ),
    ][0]?.next;
    await this.alarms.schedule("webpush-trailing-wakeup", next ?? null);
  }

  /**
   * Alarm purpose `webpush-trailing-wakeup`: send each subscription whose trailing wakeup is due its
   * one owed wakeup.
   *
   * - The send goes through the coalescer like any other, so the per-window bound holds. Claims
   *   are stored, so this also holds after eviction.
   * - Claiming the send consumes the row, so a failed trailing wakeup is not owed again: the
   *   trailing send itself is never retried.
   * - A subscription still blocked (a wakeup in flight, or claimed again since) is retried at its
   *   next claimable time, at least {@link WEB_PUSH_TRAILING_RETRY_MS} away.
   * - Rows are dropped without sending when there is nothing left to fetch (no pending, unexpired
   *   request), when the subscription is no longer registered, or when Web Push is not configured.
   * - The wakeup's deadline is that of the longest-lived pending request, so it lasts as long as
   *   anything it covers.
   */
  private async sendTrailingWakeups(now: number): Promise<void> {
    if (this.pushTransports.webpush === undefined) {
      this.sql.exec(`DELETE FROM webpush_trailing_wakeup`);
      await this.armTrailingWakeupAlarm();
      return;
    }
    this.sql.exec(
      `DELETE FROM webpush_trailing_wakeup
       WHERE NOT EXISTS (
         SELECT 1 FROM device_push_token p
         WHERE p.device_id = webpush_trailing_wakeup.device_id
           AND p.transport = 'webpush'
           AND p.token = webpush_trailing_wakeup.token
       )`,
    );
    const latest = this.latestPendingRequest(now);
    if (latest === undefined) {
      this.sql.exec(`DELETE FROM webpush_trailing_wakeup WHERE due_at <= ?`, now);
      await this.armTrailingWakeupAlarm();
      return;
    }
    const due = [
      ...this.sql.exec<TrailingWakeupRow>(
        `SELECT account_id, device_id, token, due_at FROM webpush_trailing_wakeup
         WHERE due_at <= ? ORDER BY due_at ASC`,
        now,
      ),
    ];
    const tokens: StoredPushToken[] = [];
    const claimedKeys: string[] = [];
    let accountId = "";
    for (const row of due) {
      const key = webPushCoalesceKey(row.device_id, row.token);
      if (this.webPushCoalescer.tryClaim(key, now)) {
        this.sql.exec(
          `DELETE FROM webpush_trailing_wakeup WHERE device_id = ? AND token = ?`,
          row.device_id,
          row.token,
        );
        tokens.push({ device_id: row.device_id, transport: "webpush", token: row.token });
        claimedKeys.push(key);
        accountId = row.account_id;
      } else {
        const claimableAt = this.webPushCoalescer.nextClaimableAt(key, now);
        this.sql.exec(
          `UPDATE webpush_trailing_wakeup SET due_at = ? WHERE device_id = ? AND token = ?`,
          Math.max(claimableAt, now + WEB_PUSH_TRAILING_RETRY_MS),
          row.device_id,
          row.token,
        );
      }
    }
    this.startPushFanOut(tokens, claimedKeys, accountId, latest.request_id, latest.expires_at, now);
    await this.armTrailingWakeupAlarm();
  }

  /**
   * Run one fan-out, then prune the tokens a transport reported permanently undeliverable and clear
   * the trailing wakeups the accepted ones cover. Never rejects: push is best-effort, and devices
   * still receive requests via WebSocket or polling.
   */
  private async deliverPushWakeups(
    tokens: readonly StoredPushToken[],
    accountId: string,
    requestId: string,
    expiresAt: number,
    claimedAt: number,
  ): Promise<void> {
    try {
      const { deliveredTokens, undeliverableTokens } = await dispatchPushWakeups(tokens, {
        accountId,
        requestId,
        expiresAt,
        transports: this.pushTransports,
      });
      for (const gone of undeliverableTokens) {
        this.sql.exec(
          `DELETE FROM device_push_token WHERE device_id = ? AND transport = ? AND token = ?`,
          gone.device_id,
          gone.transport,
          gone.token,
        );
      }
      await this.clearCoveredTrailingWakeups(deliveredTokens, claimedAt);
    } catch (error) {
      console.warn("push fan-out bookkeeping failed", error);
    }
  }

  /**
   * A Web Push wakeup claimed at `claimedAt` was accepted by the push service, so the device will
   * fetch every request stored before that claim. Clear each such subscription's owed trailing
   * wakeup, unless a submit was skipped at or after the claim. That submit's request may postdate
   * the inbox fetch, so it still needs the trailing wakeup.
   */
  private async clearCoveredTrailingWakeups(
    deliveredTokens: readonly StoredPushToken[],
    claimedAt: number,
  ): Promise<void> {
    let cleared = false;
    for (const token of deliveredTokens) {
      if (token.transport !== "webpush") continue;
      const result = this.sql.exec(
        `DELETE FROM webpush_trailing_wakeup
         WHERE device_id = ? AND token = ? AND last_skipped_at < ?`,
        token.device_id,
        token.token,
        claimedAt,
      );
      if (result.rowsWritten > 0) cleared = true;
    }
    if (cleared) await this.armTrailingWakeupAlarm();
  }

  /**
   * Enforce the per-account push-token budget for registering `adding` more tokens: a 409 (the
   * account is full; nothing is stored) or `null` when they fit.
   */
  private pushTokenBudgetFailure(adding: number): Response | null {
    if (adding === 0) return null;
    const row = [...this.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM device_push_token`)][0];
    if ((row?.n ?? 0) + adding <= MAX_PUSH_TOKENS_PER_ACCOUNT) return null;
    return json({ error: "account push-token limit reached" }, 409);
  }

  /**
   * GET /requests/{request_id}
   * Response: `{ request_id, status }` where status is `pending`, terminal `expired` (fail-closed,
   *           past `expires_at`), or `resolved` (+ the signed `verdict`). 404 if unknown.
   *
   * The polling counterpart to `…/wait` — lets a disconnected integrator fetch a persisted verdict.
   * Lazy-expires a past-deadline request on read so it never reports a perpetual `pending`.
   */
  private async handleGetRequest(requestId: string, request: Request): Promise<Response> {
    const authorized = await this.authorizeRequestRead(requestId, request);
    if (authorized instanceof Response) return authorized;
    const status = authorized.status;
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
   * POST /requests/{request_id}/retract  (issue #195)
   *
   * Integrator-authenticated cancellation of a request it submitted. Bearer `request_auth_token`,
   * scoped by {@link authorizeRequestRead} to exactly the request that token was issued for — an
   * integrator can never retract a request it did not submit (401/403, same as polling/wait).
   *
   * A retract is **NOT a verdict**: it never touches the `verdict` table and can never appear in
   * the audit chain as a decision. It transitions a `pending` request straight to the terminal
   * `retracted` status — distinct from the fail-closed `expired` timeout (`docs/contract.md`
   * §Lifecycle) — and is refused (409) once a real decision (`resolved`) or a timeout (`expired`)
   * already landed, so a legitimate verdict or a fail-closed expiry can never be discarded by a
   * racing cancellation. Retracting an already-retracted request is idempotent (200).
   */
  private async handleRetract(requestId: string, request: Request): Promise<Response> {
    const authorized = await this.authorizeRequestRead(requestId, request);
    if (authorized instanceof Response) return authorized;
    const status = authorized.status;
    if (status === "resolved") {
      return json({ error: "request already resolved; cannot retract a recorded decision" }, 409);
    }
    if (status === "expired") {
      return json({ error: "request already expired" }, 409);
    }
    if (status === "retracted") {
      return json({ request_id: requestId, status: "retracted" });
    }

    const now = Date.now();
    this.sql.exec(
      `UPDATE request SET status = 'retracted', terminal_at = ?
       WHERE request_id = ? AND status = 'pending'`,
      now,
      requestId,
    );
    this.notifyRetractedRequest(requestId);
    await this.armExpiryAlarm();
    return json({ request_id: requestId, status: "retracted" });
  }

  /**
   * GET /requests/{request_id}/wait  (WebSocket upgrade)
   *
   * A live waiting integrator: the verdict is pushed the instant a device decides (or immediately
   * if it already has), then the socket is closed. A past-deadline request is lazy-expired and the
   * terminal status is pushed at once (fail-closed). Returns 404 for an unknown request (a request
   * without a WebSocket upgrade header is rejected earlier, at the router, with 426).
   *
   * Protocol (relay → integrator): `{ type: "verdict", request_id, verdict }`,
   * `{ type: "expired", request_id }`, or `{ type: "retracted", request_id }` (terminal, no verdict
   * will come for either of the latter two).
   */
  private async handleIntegratorWait(requestId: string, request: Request): Promise<Response> {
    const authorized = await this.authorizeRequestRead(requestId, request);
    if (authorized instanceof Response) return authorized;
    const status = authorized.status;

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
    } else if (status === "retracted") {
      // Cancelled by the submitting integrator (#195) — not a verdict; tell the waiter at once.
      trySendJson(server, { type: "retracted", request_id: requestId });
      try {
        server.close(1000, "retracted");
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
   * `{ type: "verdict", request_id, verdict }`. On a fresh verdict whose provenance verifies (#245)
   * the relay stores it, marks the request resolved, retracts it from the other devices, and pushes
   * it to any waiting integrator. A verdict for an already-resolved request is ignored (dedupe /
   * cross-device race).
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
   *
   * Only a verdict with valid provenance is recorded (#245): signed for this request by the
   * socket's own device, certified by the bound account root and not revoked. Any other verdict
   * gets an `error` frame and changes nothing, so the request stays answerable. Provenance is not a
   * decision: the integrator still verifies the verdict in full and decides what it means.
   */
  private onDeviceVerdict(ws: WebSocket, msg: Record<string, unknown>): void {
    // SECURITY: only a device presence socket may submit a verdict. An integrator `…/wait` socket
    // (or any other non-device client) carries no `device:<id>` tag — it must NEVER be able to
    // resolve a request by sending a forged verdict payload. The verdict body's provenance is checked
    // below; the integrator still verifies it in full.
    const deviceId = this.deviceIdForSocket(ws);
    if (deviceId === null) {
      trySendJson(ws, { type: "error", error: "verdicts are only accepted from device sockets" });
      return;
    }

    // SECURITY (fail-closed): re-confirm the device is still enrolled. The socket tag proves which
    // device opened the connection, but a revoke may have removed the enrollment while a hibernation
    // socket survived the best-effort close — a de-enrolled device must not be able to drive a
    // request to `resolved`. (The provenance check below also refuses a device revoked in the verified
    // account state; this covers a de-enrollment the account state does not yet record.)
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
    // Require a JSON-object verdict (the contract Verdict shape): a degenerate scalar (42, "x") can
    // never be a verdict, so it is refused before the provenance check.
    if (!isPlainObject(msg.verdict)) {
      trySendJson(ws, { type: "error", error: "'verdict' must be a JSON object" });
      return;
    }

    const reqRows = [
      ...this.sql.exec<RequestRow>(
        `SELECT request_id, envelope, status, expires_at FROM request WHERE request_id = ?`,
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

    // A retract is NOT a verdict and must not be overridden by a late-arriving one (#195) — the
    // integrator that cancelled has already stopped waiting for a decision.
    if (req.status === "retracted") {
      trySendJson(ws, { type: "ack", request_id: requestId, status: "retracted" });
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

    // The socket's device must be the device that answered: one device's token never carries
    // another device's verdict, even a genuine one. The outer `approver.device_id` is checked here,
    // before any crypto, so a mismatched verdict costs no signature work; the provenance check
    // next ties it to the signature (`kid`) and the signed claims.
    const approver = msg.verdict.approver;
    if (isPlainObject(approver) && approver.device_id !== deviceId) {
      trySendJson(ws, {
        type: "error",
        request_id: requestId,
        error: "verdict is signed by another device",
      });
      return;
    }

    // SECURITY (#245): only a verdict with valid provenance may become final. Any device could
    // otherwise resolve every request instantly with junk, retracting the prompt from the human's
    // other devices, so the relay, not the integrator, would decide which verdict counts. The core
    // checks, without the plaintext, that the verdict was signed for this request, at a time inside
    // the request's window, by a device the bound account root certified and has not revoked. A
    // failed check records nothing, retracts nothing, and leaves the request pending for another
    // device's verdict.
    const verdictJson = JSON.stringify(msg.verdict);
    const signer = this.verdictSigner(verdictJson, requestId, req);
    if (signer === null) {
      trySendJson(ws, {
        type: "error",
        request_id: requestId,
        error: "verdict failed provenance verification",
      });
      return;
    }
    // Defense in depth: the certified signer must be the socket's device too (the outer
    // `approver.device_id` was compared above; the core ties it to the signed `kid`).
    if (signer !== deviceId) {
      trySendJson(ws, {
        type: "error",
        request_id: requestId,
        error: "verdict is signed by another device",
      });
      return;
    }

    // The verdict is stored opaquely solely to route it back; its meaning is the integrator's call.
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
   * The device that signed `verdictJson` for `req`, or `null` when its provenance does not verify
   * against the request's window, the bound account root and the relay's verified account states
   * (#245). Fails closed: no bound root, an envelope without an integer `created_at`, a core that
   * cannot load, or any failed check is `null`.
   *
   * The window is the envelope's `created_at` and `expires_at`: the same values the integrator's
   * `verify_verdict` step 5 checks `decided_at` against. (The row's `created_at` column is the
   * relay's receive time, so it is not used here: a device clock slightly behind the relay's would
   * otherwise be refused for a verdict the integrator accepts.)
   */
  private verdictSigner(
    verdictJson: string,
    requestId: string,
    req: Pick<RequestRow, "envelope" | "expires_at">,
  ): string | null {
    const root = this.boundRootPubkey();
    if (root === null) return null;
    try {
      const envelope = JSON.parse(req.envelope) as unknown;
      if (!isPlainObject(envelope) || typeof envelope.created_at !== "number") return null;
      return verifyVerdictProvenance(
        verdictJson,
        requestId,
        envelope.created_at,
        req.expires_at,
        accountIdForRoot(root),
        root,
        this.verifiedAccountStates().states,
      ).device_id;
    } catch {
      return null;
    }
  }

  /**
   * Durable Object alarm: runs whichever purposes are due (see {@link RelayAlarmPurpose} and
   * `alarms.ts`). Expiry runs first, and on every firing: it recomputes everything from the request
   * table, so running it early is harmless, and an alarm left by an older deploy still expires and
   * sweeps.
   */
  async alarm(): Promise<void> {
    await this.alarms.run(
      Date.now(),
      {
        "request-expiry": (now) => this.expireDueRequests(now),
        "webpush-trailing-wakeup": (now) => this.sendTrailingWakeups(now),
      },
      { everyFiring: ["request-expiry"] },
    );
  }

  /**
   * Alarm purpose `request-expiry`: fail-close expired pending requests, retract them from
   * connected devices, wake live integrator waiters, sweep old terminal rows, and then schedule the
   * next pending expiry.
   */
  private async expireDueRequests(now: number): Promise<void> {
    const expired = this.expirePendingDue(now);
    for (const request of expired) {
      this.notifyExpiredRequest(request.request_id);
    }
    this.sweepTerminalRows(now);
    await this.armExpiryAlarm();
  }

  /** Point the `request-expiry` alarm purpose at the nearest pending expiry, or clear it when none remains. */
  private async armExpiryAlarm(): Promise<void> {
    const next = [
      ...this.sql.exec<{ expires_at: number }>(
        `SELECT expires_at FROM request WHERE status = 'pending' ORDER BY expires_at ASC LIMIT 1`,
      ),
    ][0];
    await this.alarms.schedule("request-expiry", next?.expires_at ?? null);
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

  /**
   * Fan out a cancellation (#195): clear it from device pending lists — reusing the SAME `retract`
   * message devices already understand for cross-device dedupe — and tell any live integrator
   * waiter it will never receive a verdict for this request.
   */
  private notifyRetractedRequest(requestId: string): void {
    for (const sock of this.ctx.getWebSockets(DEVICE_TAG)) {
      trySendJson(sock, { type: "retract", request_id: requestId });
    }
    for (const sock of this.ctx.getWebSockets(integratorTag(requestId))) {
      trySendJson(sock, { type: "retracted", request_id: requestId });
      try {
        sock.close(1000, "retracted");
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
       WHERE status IN ('expired', 'resolved', 'retracted') AND terminal_at IS NOT NULL AND terminal_at < ?`,
      cutoff,
    );
    this.sql.exec(`DELETE FROM verdict WHERE request_id NOT IN (SELECT request_id FROM request)`);
  }
}

/**
 * The push transports this deployment can deliver through: a kind is registered only when its
 * credentials are configured. Tokens for an unregistered kind stay stored (a later configuration
 * picks them up) but are neither sent nor counted in `push_wakeups`; devices then rely on WebSocket
 * presence and polling.
 */
function buildPushTransports(env: Env): PushTransportRegistry {
  const transports: PushTransportRegistry = {};
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
  const vapid = vapidConfigFromEnv(env);
  if (vapid) transports.webpush = new WebPushTransport({ vapid });
  return transports;
}
