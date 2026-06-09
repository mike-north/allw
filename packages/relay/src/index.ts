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
 * will be added alongside the enrollment mini-spec from `docs/contract.md §Open decisions`.
 */

export interface Env {
  readonly ACCOUNT: DurableObjectNamespace;
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
 * Pairing code TTL in milliseconds.
 * Exported so tests can seed deterministically-expired rows without waiting.
 */
export const PAIRING_TTL_MS = 10 * 60 * 1000; // 10 minutes

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

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
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
 * out of scope for this PR. It will be added with the enrollment mini-spec referenced in
 * `docs/contract.md §Open decisions: "Account / device enrollment, key rotation & revocation."
 */
export class AccountRelay implements DurableObject {
  private readonly sql: SqlStorage;

  constructor(ctx: DurableObjectState, _env: Env) {
    this.sql = ctx.storage.sql;
    this.initSchema();
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

    // 405 only for a KNOWN route path reached with an unsupported method; any other (unknown)
    // sub-path is a 404 — e.g. `GET /devices/<id>` or `GET /pairing/unknown` are not routes.
    const isKnownRoutePath =
      (path0 === "pairing" && (path1 === "start" || path1 === "complete") && path2 === "") ||
      (path0 === "actors" && path1 === "") ||
      (path0 === "devices" && path1 === "") ||
      (path0 === "devices" && path1 !== "" && path2 === "revoke" && (subSegments[3] ?? "") === "");
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
   * Body: { code: string, pubkey: string (b64url 32 bytes), label?: string }
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
    return json({ revoked: true });
  }
}
