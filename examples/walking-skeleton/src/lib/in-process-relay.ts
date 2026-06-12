/**
 * An in-process faithful stand-in for the zero-knowledge relay (`@allw/relay`'s `AccountRelay`),
 * used by the CI-runnable end-to-end test.
 *
 * # Why this exists (manual-test-design boundary — see the README "Decisions")
 * The real relay runs under **workerd** (Cloudflare Workers + a Durable Object) while the SDK and
 * the approver run under **node**. A single-process `node --test` cannot host both runtimes and dial
 * real WebSockets between them, so the genuinely-live workerd stack is exercised by the
 * locally-automatable `pnpm run demo:e2e` script (real `wrangler dev`) and by `@allw/relay`'s own
 * `workers-pool` test suite. For the deterministic CI round-trip we drive the **real** `@allw/sdk`
 * and the **real** `@allw/approver` core against this in-process relay, which mirrors the relay's
 * **observable contract** exactly (`docs/contract.md` §Transport → Relay routing API):
 *
 * - `GET  /:acct/devices`            → the enrolled device pubkey list (JWE recipients).
 * - `POST /:acct/requests`           → store the opaque envelope; reject any non-contract key
 *   (the zero-knowledge guard) and an already-expired `expires_at`; fan out to online devices;
 *   return the request-scoped bearer token used by the poll path.
 * - `GET  /:acct/requests/:id`       → poll status (`pending` / terminal `expired` / `resolved`
 *   + verdict) after bearer-token auth; lazy-expire a past-deadline request on read (fail-closed).
 * - device presence socket           → relay → device `{ type: "request", … }`; device → relay
 *   `{ type: "verdict", … }` answered with `{ type: "ack", status }`; **first verdict wins**; a
 *   verdict for an expired request is acked `expired` and never stored.
 *
 * # Zero-knowledge, enforced (not just asserted)
 * Like the real relay, this stand-in stores **only** the contract's envelope keys
 * ({@link ENVELOPE_KEYS}) wrapping the opaque `context_ciphertext`, plus the opaque signed verdict.
 * A submit carrying any extra (plaintext-looking) key is rejected with 400 — the same guard the
 * relay applies so an integrator can never persist `action`/`summary`/`actor`/… in the relay. The
 * test then reaches into {@link InProcessRelay.storedEnvelope} / {@link InProcessRelay.storedVerdict}
 * to prove no plaintext context field is present — mirroring `@allw/relay`'s zero-knowledge test.
 *
 * This module implements **no** cryptography and parses **no** ciphertext — it only routes opaque
 * strings, exactly as the contract requires of the relay.
 */

/**
 * The exact, exhaustive set of `ApprovalRequest` envelope keys the relay accepts
 * (`docs/contract.md` §Messages). Mirrors `ENVELOPE_KEYS` in `packages/relay/src/index.ts`; any
 * other key is rejected at submit time so plaintext context can never reach the relay.
 */
export const ENVELOPE_KEYS = [
  "v",
  "id",
  "created_at",
  "expires_at",
  "approver",
  "context_ciphertext",
] as const;

/** One enrolled approver device, as returned by `GET /:acct/devices`. */
export interface RelayDevice {
  readonly device_id: string;
  /** The device's X25519 public key (base64url-unpadded) — the JWE recipient key. */
  readonly pubkey: string;
  readonly label: string | null;
  readonly created_at: number;
}

/** A stored request row (the opaque envelope + lifecycle status). */
interface StoredRequest {
  readonly envelope: Record<string, unknown>;
  /** Relay-scoped capability token required to read this request's poll status. */
  readonly authToken: string;
  status: "pending" | "resolved" | "expired";
  readonly expiresAt: number;
}

/** The relay-visible status of a request on the poll/wait paths. */
type RequestStatus = "pending" | "resolved" | "expired";

/**
 * A device presence connection the relay can push to and receive a verdict from. The approver side
 * registers its handlers here; the relay invokes {@link onRequest} to deliver a pushed request and
 * the device calls {@link sendVerdict} to return a signed decision.
 */
export interface DeviceConnection {
  /** Relay → device: deliver a pushed (or queue-flushed) request envelope. */
  onRequest(handler: (requestId: string, envelope: Record<string, unknown>) => void): void;
  /** Relay → device: another surface resolved the request; clear any pending prompt. */
  onRetract(handler: (requestId: string) => void): void;
  /** Device → relay: submit a signed verdict; resolves to the relay's ack status. */
  sendVerdict(requestId: string, verdict: unknown): { status: string };
  /** Close the presence socket. */
  close(): void;
}

/** Options for {@link InProcessRelay}. */
export interface InProcessRelayOptions {
  /** The clock (ms). Injected so expiry is deterministic in tests (no wall-clock read). */
  readonly now: () => number;
}

/** Extract `Authorization` from the fetch-compatible header shapes Node/browser tests may pass. */
function authHeader(headers: HeadersInit | undefined): string | null {
  if (headers === undefined) return null;
  if (headers instanceof Headers) return headers.get("Authorization");
  if (Array.isArray(headers)) {
    for (const [key, value] of headers) {
      if (key.toLowerCase() === "authorization") return value;
    }
    return null;
  }
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === "authorization") return value;
  }
  return null;
}

/**
 * A faithful in-process relay for one account. Construct it, enroll a device pubkey, hand its
 * {@link fetchImpl} to the real `@allw/sdk` client, connect the approver via {@link connectDevice},
 * and the SDK's submit/poll round-trip flows through it exactly as it would through the real relay.
 */
export class InProcessRelay {
  private readonly now: () => number;
  private readonly devices: RelayDevice[] = [];
  private readonly requests = new Map<string, StoredRequest>();
  private readonly verdicts = new Map<string, unknown>();
  private readonly connections = new Set<InternalDeviceConnection>();

  constructor(options: InProcessRelayOptions) {
    this.now = options.now;
  }

  /** Enroll a device's X25519 pubkey (mirrors `POST /pairing/complete` registering one key). */
  enrollDevice(device: RelayDevice): void {
    this.devices.push(device);
  }

  /**
   * Open a device presence connection and immediately flush the offline queue — every still-live
   * pending request, oldest first (fail-closed: an expired queued request is skipped). Mirrors
   * `handleDeviceConnect`.
   */
  connectDevice(): DeviceConnection {
    const conn = new InternalDeviceConnection(() => {
      this.connections.delete(conn);
    });
    conn.setVerdictSink((requestId, verdict) => this.recordVerdict(requestId, verdict));
    this.connections.add(conn);

    // Flush still-pending, unexpired requests in insertion (creation) order.
    const now = this.now();
    for (const [requestId, req] of this.requests) {
      if (req.status === "pending" && req.expiresAt > now) {
        conn.deliver(requestId, req.envelope);
      }
    }
    return conn;
  }

  /**
   * A `fetch`-compatible implementation of the relay's integrator-facing HTTP surface. Hand this to
   * `createClient({ fetchImpl })`; the real SDK then drives the genuine submit + poll paths.
   */
  readonly fetchImpl: typeof fetch = (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = (init?.method ?? "GET").toUpperCase();

    if (url.endsWith("/devices") && method === "GET") {
      return Promise.resolve(this.json({ devices: this.devices }));
    }
    if (url.endsWith("/requests") && method === "POST") {
      return Promise.resolve(this.handleSubmit(init?.body));
    }
    const pollMatch = /\/requests\/([^/]+)$/.exec(url);
    if (pollMatch && method === "GET") {
      const requestId = decodeURIComponent(pollMatch[1] ?? "");
      return Promise.resolve(this.handlePoll(requestId, authHeader(init?.headers)));
    }
    return Promise.resolve(this.json({ error: "not found" }, 404));
  };

  /** The raw stored envelope for a request (zero-knowledge assertion target). */
  storedEnvelope(requestId: string): Record<string, unknown> | undefined {
    return this.requests.get(requestId)?.envelope;
  }

  /** The raw stored verdict for a request (zero-knowledge assertion target). */
  storedVerdict(requestId: string): unknown {
    return this.verdicts.get(requestId);
  }

  /** Every request id the relay has stored (so a test can find the SDK-minted id). */
  requestIds(): string[] {
    return [...this.requests.keys()];
  }

  // --- internals ---------------------------------------------------------------------------------

  /**
   * `POST /requests` — store the opaque envelope and fan it out to online devices.
   *
   * Mirrors the real relay's `handleSubmit` observable contract: the zero-knowledge guard (reject
   * any non-{@link ENVELOPE_KEYS} key), every required routing/lifecycle field (`v`, `id`,
   * `created_at`, `expires_at`, `approver`, `context_ciphertext`), the duplicate-id 409, and
   * fail-closed expiry (reject an already-past `expires_at`).
   */
  private handleSubmit(body: BodyInit | null | undefined): Response {
    let parsed: unknown;
    try {
      parsed = JSON.parse(typeof body === "string" ? body : "");
    } catch {
      return this.json({ error: "invalid JSON body" }, 400);
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return this.json({ error: "invalid JSON body" }, 400);
    }
    const envelope = parsed as Record<string, unknown>;

    // SECURITY (zero-knowledge): the envelope must be EXACTLY the contract's keys — reject any extra
    // (e.g. a stray `summary`) so plaintext context can never be persisted by the relay.
    const extraneous = Object.keys(envelope).filter(
      (k) => !(ENVELOPE_KEYS as readonly string[]).includes(k),
    );
    if (extraneous.length > 0) {
      return this.json({ error: `unexpected envelope field(s): ${extraneous.join(", ")}` }, 400);
    }

    // Required-field validation in the SAME order and with the same checks as the real relay's
    // `handleSubmit` (`packages/relay/src/index.ts`), so the double mirrors the observable submit
    // contract and catches the same SDK/approver regressions.
    const id = envelope.id;
    if (typeof id !== "string" || id.length === 0) {
      return this.json({ error: "'id' is required (string)" }, 400);
    }
    if (typeof envelope.v !== "number" || !Number.isFinite(envelope.v)) {
      return this.json({ error: "'v' is required (number)" }, 400);
    }
    if (typeof envelope.created_at !== "number" || !Number.isFinite(envelope.created_at)) {
      return this.json({ error: "'created_at' is required (i64 ms)" }, 400);
    }
    if (typeof envelope.approver !== "string" || envelope.approver.length === 0) {
      return this.json({ error: "'approver' is required (string)" }, 400);
    }
    // The ciphertext is opaque to the relay — present and a string is all we check.
    if (
      typeof envelope.context_ciphertext !== "string" ||
      envelope.context_ciphertext.length === 0
    ) {
      return this.json({ error: "'context_ciphertext' is required (opaque JWE string)" }, 400);
    }
    const expiresAt = envelope.expires_at;
    if (typeof expiresAt !== "number" || !Number.isFinite(expiresAt)) {
      return this.json({ error: "'expires_at' is required (i64 ms)" }, 400);
    }
    if (expiresAt <= this.now()) {
      return this.json({ error: "request already expired" }, 400);
    }
    if (this.requests.has(id)) {
      return this.json({ error: "request already submitted" }, 409);
    }

    // The real relay returns this opaque token once on submit; clients must present it when polling
    // request status. Deterministic derivation keeps the test double reproducible.
    const authToken = `request-token-${id}`;
    this.requests.set(id, { envelope, authToken, status: "pending", expiresAt });

    // Fan out to every online device.
    let delivered = 0;
    for (const conn of this.connections) {
      conn.deliver(id, envelope);
      delivered++;
    }
    return this.json(
      { request_id: id, status: "pending", delivered_to: delivered, request_auth_token: authToken },
      202,
    );
  }

  /**
   * `GET /requests/:id` — poll status, lazy-expiring a past-deadline pending request (fail-closed).
   * Returns the verdict only when `resolved`.
   */
  private handlePoll(requestId: string, authorization: string | null): Response {
    const req = this.requests.get(requestId);
    if (!req) return this.json({ error: "request not found" }, 404);
    if (authorization === null) return this.json({ error: "missing bearer token" }, 401);
    if (authorization !== `Bearer ${req.authToken}`) {
      return this.json({ error: "authorization denied" }, 403);
    }
    const status = this.expireIfDue(req);
    if (status !== "resolved") {
      return this.json({ request_id: requestId, status });
    }
    return this.json({
      request_id: requestId,
      status: "resolved",
      verdict: this.verdicts.get(requestId) ?? null,
    });
  }

  /** Fail-closed lazy expiry: a pending request past its deadline transitions to terminal `expired`. */
  private expireIfDue(req: StoredRequest): RequestStatus {
    if (req.status === "pending" && this.now() > req.expiresAt) {
      req.status = "expired";
    }
    return req.status;
  }

  /**
   * Process a device verdict (the device side calls this via {@link DeviceConnection.sendVerdict}).
   * First verdict wins; a verdict for an expired request is refused (acked `expired`, not stored);
   * on a fresh verdict it retracts the request from the other connected devices. Mirrors
   * `onDeviceVerdict`.
   */
  private recordVerdict(requestId: string, verdict: unknown): { status: string } {
    const req = this.requests.get(requestId);
    if (!req) return { status: "unknown_request" };
    if (req.status === "resolved") return { status: "already_resolved" };

    if (req.status === "expired" || this.now() > req.expiresAt) {
      req.status = "expired";
      return { status: "expired" };
    }

    this.verdicts.set(requestId, verdict);
    req.status = "resolved";

    // Retract from the other devices (cross-device coordination).
    for (const conn of this.connections) {
      conn.retract(requestId);
    }
    return { status: "resolved" };
  }

  private json(data: unknown, status = 200): Response {
    return new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }
}

/**
 * The concrete device connection; the relay holds these to fan out and retract.
 *
 * # Why deliveries are buffered until the handler attaches
 * A caller does `const conn = relay.connectDevice()` and only *then* `conn.onRequest(...)`. The
 * relay, meanwhile, flushes the offline queue synchronously **inside** `connectDevice()` and fans
 * out submits the instant they arrive — both before the caller has had a chance to register its
 * handler. The real relay never loses these because the WebSocket buffers server pushes until the
 * client reads them; this double mirrors that by queuing any `deliver`/`retract` that arrives before
 * the corresponding handler is set and flushing it on registration. Without this, an offline-queued
 * request (the reconnect path the docstring claims to mirror) would be silently dropped.
 */
class InternalDeviceConnection implements DeviceConnection {
  private requestHandler: ((requestId: string, envelope: Record<string, unknown>) => void) | null =
    null;
  private retractHandler: ((requestId: string) => void) | null = null;
  private verdictSink: ((requestId: string, verdict: unknown) => { status: string }) | null = null;
  private closed = false;
  /** Requests delivered before `onRequest` was attached (flushed on registration). */
  private readonly pendingRequests: { requestId: string; envelope: Record<string, unknown> }[] = [];
  /** Retracts delivered before `onRetract` was attached (flushed on registration). */
  private readonly pendingRetracts: string[] = [];

  constructor(private readonly onClose: () => void) {}

  onRequest(handler: (requestId: string, envelope: Record<string, unknown>) => void): void {
    this.requestHandler = handler;
    // Flush anything that arrived (offline-queue flush / fan-out) before this handler existed.
    const buffered = this.pendingRequests.splice(0, this.pendingRequests.length);
    for (const { requestId, envelope } of buffered) {
      if (!this.closed) handler(requestId, envelope);
    }
  }

  onRetract(handler: (requestId: string) => void): void {
    this.retractHandler = handler;
    const buffered = this.pendingRetracts.splice(0, this.pendingRetracts.length);
    for (const requestId of buffered) {
      if (!this.closed) handler(requestId);
    }
  }

  setVerdictSink(sink: (requestId: string, verdict: unknown) => { status: string }): void {
    this.verdictSink = sink;
  }

  sendVerdict(requestId: string, verdict: unknown): { status: string } {
    if (this.verdictSink === null) throw new Error("device connection not bound to a relay");
    return this.verdictSink(requestId, verdict);
  }

  /**
   * Relay-internal: deliver a request push to the device. If the device has not attached its
   * `onRequest` handler yet, buffer the push and flush it on registration (mirrors the WS buffering
   * the real relay relies on, so an offline-queued request is never dropped).
   */
  deliver(requestId: string, envelope: Record<string, unknown>): void {
    if (this.closed) return;
    if (this.requestHandler === null) {
      this.pendingRequests.push({ requestId, envelope });
      return;
    }
    this.requestHandler(requestId, envelope);
  }

  /** Relay-internal: deliver a retract to the device (buffered until `onRetract` is attached). */
  retract(requestId: string): void {
    if (this.closed) return;
    if (this.retractHandler === null) {
      this.pendingRetracts.push(requestId);
      return;
    }
    this.retractHandler(requestId);
  }

  close(): void {
    this.closed = true;
    this.onClose();
  }
}
