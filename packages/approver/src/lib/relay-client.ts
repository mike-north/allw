/**
 * Thin HTTP client for the relay's device-facing endpoints (`docs/contract.md` §Transport →
 * Relay routing API). Pairing only — the presence WebSocket is handled in `watch.ts`. The client
 * sends only public key material + routing metadata; it never sends a seed (zero-knowledge relay).
 */

/** Pairing HTTP requests are short; bound them so a hung relay can't stall the CLI indefinitely. */
export const PAIRING_TIMEOUT_MS = 15_000;

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
    throw new Error(`relay ${url} → HTTP ${String(resp.status)}: ${detail}`);
  }
  return parsed;
}

/**
 * GET JSON with the same bounded relay failure behavior as pairing POSTs. Device-facing reads use
 * bearer authorization; callers decide whether an error aborts or downgrades their UI.
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
    throw new Error(`relay ${url} → HTTP ${String(resp.status)}: ${detail}`);
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

/**
 * Start a pairing: ask the relay for a short code (the account owner runs this in production).
 *
 * `timeoutMs` (default {@link PAIRING_TIMEOUT_MS}) bounds a hung relay; it is parameterized so the
 * fail-closed abort is testable without a multi-second wait.
 */
export async function pairingStart(
  relayUrl: string,
  accountId: string,
  label?: string,
  timeoutMs: number = PAIRING_TIMEOUT_MS,
): Promise<PairingStartResult> {
  const url = `${normalizeBase(relayUrl)}/${encodeURIComponent(accountId)}/pairing/start`;
  const body = label === undefined ? {} : { label };
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
 * Fetch the latest root-signed account-state documents distributed by the relay. These are compact
 * JWS strings signed by the account root; the relay only caches and serves them, while the approver
 * core decides whether any document actually verifies and enrolls the actor key.
 */
export interface AccountStateFetchResult {
  readonly accountStates: readonly string[];
  readonly maxSequence: number;
}

export async function fetchAccountStatesWithMetadata(
  relayUrl: string,
  accountId: string,
  deviceAuthToken: string,
  timeoutMs: number = PAIRING_TIMEOUT_MS,
): Promise<AccountStateFetchResult> {
  const url = `${normalizeBase(relayUrl)}/${encodeURIComponent(accountId)}/account-states`;
  const result = await getJson(url, timeoutMs, { Authorization: `Bearer ${deviceAuthToken}` });
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
  if (
    maxSequence !== undefined &&
    (typeof maxSequence !== "number" || !Number.isSafeInteger(maxSequence) || maxSequence < 0)
  ) {
    throw new Error(`relay account-states returned an unexpected shape: ${JSON.stringify(result)}`);
  }
  return {
    accountStates: (result as { account_states: string[] }).account_states,
    maxSequence: maxSequence ?? 0,
  };
}

export async function fetchAccountStates(
  relayUrl: string,
  accountId: string,
  deviceAuthToken: string,
  timeoutMs: number = PAIRING_TIMEOUT_MS,
): Promise<readonly string[]> {
  return (await fetchAccountStatesWithMetadata(relayUrl, accountId, deviceAuthToken, timeoutMs))
    .accountStates;
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
