/**
 * Thin HTTP client for the relay's device-facing endpoints (`docs/contract.md` §Transport →
 * Relay routing API). Pairing only — the presence WebSocket is handled in `watch.ts`. The client
 * sends only public key material + routing metadata; it never sends a seed (zero-knowledge relay).
 */

/** Pairing HTTP requests are short; bound them so a hung relay can't stall the CLI indefinitely. */
export const PAIRING_TIMEOUT_MS = 15_000;

/**
 * A non-2xx relay response. The message is the human-facing error; `status` lets a caller name a
 * specific fix for a specific status without parsing the message.
 */
export class RelayHttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "RelayHttpError";
  }
}

/** Trim a trailing slash so `${base}/path` never doubles up. */
function normalizeBase(url: string): string {
  return url.replace(/\/+$/, "");
}

/**
 * POST JSON and parse the JSON response, surfacing non-2xx as a thrown error with the body.
 *
 * `timeoutMs` bounds a hung/unreachable relay (a relay that accepts the connection but never
 * responds would otherwise stall the CLI forever); it defaults to {@link PAIRING_TIMEOUT_MS} and is
 * parameterized so the fail-closed abort can be exercised in tests without a multi-second wait.
 */
async function postJson(
  url: string,
  body: unknown,
  timeoutMs: number = PAIRING_TIMEOUT_MS,
  headers: Record<string, string> = {},
): Promise<unknown> {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
    // Fail-closed on a hung/unreachable relay rather than blocking forever (aborts after timeout).
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await resp.text();
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  if (!resp.ok) {
    const detail =
      parsed && typeof parsed === "object" && "error" in parsed ? String(parsed.error) : text;
    throw new RelayHttpError(`relay ${url} → HTTP ${String(resp.status)}: ${detail}`, resp.status);
  }
  return parsed;
}

/**
 * GET JSON with the same bounded relay failure behavior as pairing POSTs. Callers pass any bearer
 * authorization the route needs, and decide whether an error aborts or downgrades their UI.
 */
async function getJson(
  url: string,
  timeoutMs: number = PAIRING_TIMEOUT_MS,
  headers: Record<string, string> = {},
): Promise<unknown> {
  const resp = await fetch(url, {
    method: "GET",
    headers,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await resp.text();
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  if (!resp.ok) {
    const detail =
      parsed && typeof parsed === "object" && "error" in parsed ? String(parsed.error) : text;
    throw new RelayHttpError(`relay ${url} → HTTP ${String(resp.status)}: ${detail}`, resp.status);
  }
  return parsed;
}

/** Result of `POST /:acct/pairing/start`. */
export interface PairingStartResult {
  readonly code: string;
  readonly expires_at: number;
  readonly pairing_auth_token: string;
}

export interface PairingCompleteResult {
  readonly device_id: string;
  readonly device_auth_token: string;
}

/** The account-root credentials that authorize `POST /:acct/pairing/start`. */
export interface PairingStartAuthorization {
  /** The account-root Ed25519 public key (base64url); `accountId` must derive from it. */
  readonly rootPubkey: string;
  /** A fresh root-signed `allw-pairing-start+jws` for `accountId`. */
  readonly authorization: string;
}

/**
 * Start a pairing: ask the relay for a short code. Only the account-root holder can: the request
 * carries the root public key and a root-signed authorization (`docs/relay-api.md` §3 Pairing).
 *
 * `timeoutMs` (default {@link PAIRING_TIMEOUT_MS}) bounds a hung relay; it is parameterized so the
 * fail-closed abort is testable without a multi-second wait.
 */
export async function pairingStart(
  relayUrl: string,
  accountId: string,
  auth: PairingStartAuthorization,
  label?: string,
  timeoutMs: number = PAIRING_TIMEOUT_MS,
): Promise<PairingStartResult> {
  const url = `${normalizeBase(relayUrl)}/${encodeURIComponent(accountId)}/pairing/start`;
  const body: Record<string, string> = {
    root_pubkey: auth.rootPubkey,
    authorization: auth.authorization,
  };
  if (label !== undefined) body.label = label;
  const result = await postJson(url, body, timeoutMs);
  if (
    typeof result !== "object" ||
    result === null ||
    typeof (result as { code: unknown }).code !== "string" ||
    typeof (result as { pairing_auth_token: unknown }).pairing_auth_token !== "string"
  ) {
    throw new Error(`relay pairing/start returned an unexpected shape: ${JSON.stringify(result)}`);
  }
  return result as unknown as PairingStartResult;
}

/**
 * Complete a pairing: redeem `code` and register the device public key, returning the relay-issued
 * `device_id` plus the relay bearer token for device-scoped endpoints.
 *
 * **Single-key relay surface.** `POST /pairing/complete` registers exactly one `pubkey` per
 * device row. The approver holds two device keys (X25519 for decryption, Ed25519 for verdict
 * signing); the relay only needs the **X25519** key to route ciphertext as a JWE recipient, and
 * the Ed25519 verifying key reaches verifiers via the account-root **device_cert** (not the relay
 * registry). So we register the X25519 key here and rely on the cert for the signing-key trust
 * chain. See the PR "Decisions" note.
 */
export async function pairingComplete(
  relayUrl: string,
  accountId: string,
  code: string,
  pairingAuthToken: string,
  encryptionPubkey: string,
  label?: string,
): Promise<PairingCompleteResult> {
  const url = `${normalizeBase(relayUrl)}/${encodeURIComponent(accountId)}/pairing/complete`;
  const body: Record<string, string> = { code, pubkey: encryptionPubkey };
  if (label !== undefined) body.label = label;
  const result = await postJson(url, body, PAIRING_TIMEOUT_MS, {
    Authorization: `Bearer ${pairingAuthToken}`,
  });
  if (
    typeof result !== "object" ||
    result === null ||
    typeof (result as { device_id: unknown }).device_id !== "string" ||
    typeof (result as { device_auth_token: unknown }).device_auth_token !== "string"
  ) {
    throw new Error(
      `relay pairing/complete returned an unexpected shape: ${JSON.stringify(result)}`,
    );
  }
  return result as unknown as PairingCompleteResult;
}

/**
 * The relay's account-state distribution set (`GET`/`POST /:acct/account-states`): compact
 * root-signed `allw-account-state+jws` documents plus the relay's `max_sequence` bookkeeping.
 *
 * The relay stores only documents it verified against the account's bound root, and
 * `maxSequence` is the highest *verified* sequence it holds (0 when none). Neither makes the relay
 * a trust anchor: the approver core still verifies every document against the configured account
 * root, and a `maxSequence` no verified document backs is treated as a misbehaving relay.
 */
export interface AccountStateFetchResult {
  readonly accountStates: readonly string[];
  readonly maxSequence: number;
}

function accountStatesUrl(relayUrl: string, accountId: string): string {
  return `${normalizeBase(relayUrl)}/${encodeURIComponent(accountId)}/account-states`;
}

/**
 * Validate an `{ account_states, max_sequence }` relay response body, fail-closed on any drift. The
 * relay always reports `max_sequence` (`docs/relay-api.md` §3 Account state) and the approver's
 * rollback defense compares against it, so a missing value is rejected, never defaulted.
 */
function parseAccountStateSet(result: unknown): AccountStateFetchResult {
  if (
    typeof result !== "object" ||
    result === null ||
    !Array.isArray((result as { account_states?: unknown }).account_states) ||
    !(result as { account_states: unknown[] }).account_states.every(
      (value) => typeof value === "string",
    )
  ) {
    throw new Error(`relay account-states returned an unexpected shape: ${JSON.stringify(result)}`);
  }
  const maxSequence = (result as { max_sequence?: unknown }).max_sequence;
  if (typeof maxSequence !== "number" || !Number.isSafeInteger(maxSequence) || maxSequence < 0) {
    throw new Error(`relay account-states returned an unexpected shape: ${JSON.stringify(result)}`);
  }
  return {
    accountStates: (result as { account_states: string[] }).account_states,
    maxSequence,
  };
}

/**
 * Fetch the account's relay-verified account-state documents (`GET /:acct/account-states`). The
 * route is unauthenticated — the documents are public and root-signed — so no device token is
 * sent.
 */
export async function fetchAccountStatesWithMetadata(
  relayUrl: string,
  accountId: string,
  timeoutMs: number = PAIRING_TIMEOUT_MS,
): Promise<AccountStateFetchResult> {
  let body: unknown;
  try {
    body = await getJson(accountStatesUrl(relayUrl, accountId), timeoutMs);
  } catch (err) {
    // The endpoint is unauthenticated on current relays, so a 401 means the relay predates it.
    if (err instanceof RelayHttpError && err.status === 401) {
      throw new RelayHttpError(
        `${err.message} — this relay requires authorization for GET /account-states, which ` +
          `current relays serve without it, so the relay is too old to publish account state; ` +
          `redeploy it from current allw main (docs/relay-deploy.md)`,
        err.status,
      );
    }
    throw err;
  }
  return parseAccountStateSet(body);
}

/** {@link fetchAccountStatesWithMetadata} without the relay's sequence bookkeeping. */
export async function fetchAccountStates(
  relayUrl: string,
  accountId: string,
  timeoutMs: number = PAIRING_TIMEOUT_MS,
): Promise<readonly string[]> {
  return (await fetchAccountStatesWithMetadata(relayUrl, accountId, timeoutMs)).accountStates;
}

/**
 * Publish root-signed account-state documents (`POST /:acct/account-states`) for distribution.
 *
 * Authority is the account root's signature, not a device token: the relay verifies every
 * document against the root bound to `accountId` (bound by a root-signed `pairing/start`) and
 * stores only the documents at the highest verified sequence. No `max_sequence` is asserted — the
 * relay derives it from the verified documents.
 *
 * Throws (fail-closed) on any relay rejection: 403 when a document does not verify, 409 when no
 * root is bound yet or the highest sequence is not above the one the relay already holds (an
 * idempotent republish of the current document is a 409 too), 400 for a malformed request.
 */
export async function publishAccountStates(
  relayUrl: string,
  accountId: string,
  accountStates: readonly string[],
  timeoutMs: number = PAIRING_TIMEOUT_MS,
): Promise<AccountStateFetchResult> {
  const result = await postJson(
    accountStatesUrl(relayUrl, accountId),
    { account_states: accountStates },
    timeoutMs,
  );
  return parseAccountStateSet(result);
}

/**
 * Build the device presence WebSocket URL (`GET /:acct/devices/:deviceId/connect`). `http(s)` is
 * upgraded to `ws(s)` so the same relay base works for both HTTP pairing and the WS presence link.
 */
export function deviceConnectWsUrl(
  relayUrl: string,
  accountId: string,
  deviceId: string,
  deviceAuthToken: string,
): string {
  const base = normalizeBase(relayUrl).replace(/^http/, "ws");
  return `${base}/${encodeURIComponent(accountId)}/devices/${encodeURIComponent(deviceId)}/connect?auth=${encodeURIComponent(deviceAuthToken)}`;
}

// The approver no longer resolves actor *keys* from the relay `/actors` registry: a relay-supplied
// key is not a trust anchor (a malicious relay could substitute its own). Actor keys are now
// root-anchored via root-signed account state (`docs/enrollment.md` §Account State), verified in
// the WASM core (`verify_actor_attestation`). The relay's `/actors` endpoint (#10) still exists as
// an enrollment/registry convenience, but it never drives a ✓ VERIFIED origin on the device.
