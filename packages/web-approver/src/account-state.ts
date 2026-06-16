/**
 * Relay-backed {@link AccountStateResolver} for the web approver.
 *
 * {@link createRelayAccountStateResolver} fetches root-signed account-state documents from
 * `GET /{accountId}/account-states` on the relay and returns them for the WASM core to verify.
 * The relay only *distributes* these documents — it cannot forge them because it cannot produce a
 * valid root signature. The WASM core (`verify_actor_attestation`) does the actual trust work;
 * this module only wires the HTTP fetch.
 *
 * # Fail-closed (`docs/contract.md` §Invariants #6)
 * Any failure in `resolve` (network error, non-2xx, malformed response shape) returns an **empty
 * array** — it never throws. The runtime maps an empty array to `unverified` origin display, which
 * is the correct deny-only default. The human still sees the action; the attestation badge simply
 * shows ⚠ UNVERIFIED rather than ✓ VERIFIED until the resolver can reach the relay.
 *
 * # Why relay-substitution cannot produce VERIFIED (#16, `docs/enrollment.md` §Account State)
 * A relay that substitutes its own actor key in the returned account-state documents cannot produce
 * a `verified` origin: the WASM core's `verify_actor_attestation` checks both the account-state
 * document's root signature (signed by the configured account root, not the relay) and the
 * per-request actor attestation JWS. A forged account-state document will fail the root-signature
 * check; a forged per-request attestation will fail the actor-pubkey check. Both paths require the
 * account-root private key the relay has never seen.
 *
 * @see ../../../docs/enrollment.md §Account State, §Actor-Key Enrollment
 * @see ../../../docs/contract.md §Invariants #5, #6
 * @see ./runtime.ts (resolveAttestation — the consumer of these documents)
 */

import type { FetchImpl } from "./relay-poll.js";
import type { AccountStateResolver } from "./runtime.js";

/**
 * HTTP fetch timeout for account-state requests (ms). Short enough that a hung relay downgrades
 * cleanly to unverified without perceptibly blocking approval rendering.
 */
export const ACCOUNT_STATE_FETCH_TIMEOUT_MS = 10_000;

/** Options for {@link createRelayAccountStateResolver}. */
export interface RelayAccountStateResolverOptions {
  /** The relay base URL, e.g. `https://relay.allw.app`. Trailing slashes are normalized. */
  readonly relayUrl: string;
  /** The account id whose account-state documents to fetch. */
  readonly accountId: string;
  /** Device bearer token authorizing `GET /{accountId}/account-states`. */
  readonly deviceAuthToken: string;
  /**
   * Request timeout in ms. Defaults to {@link ACCOUNT_STATE_FETCH_TIMEOUT_MS}. Parameterized so
   * tests can exercise the fail-closed timeout path without a multi-second wait.
   */
  readonly timeoutMs?: number;
  /** Injectable `fetch` for tests. Defaults to the global `fetch`. */
  readonly fetchImpl?: FetchImpl;
}

/**
 * Build the relay account-states URL:
 * `<relayUrl>/<accountId>/account-states`.
 */
function accountStatesUrl(relayUrl: string, accountId: string): string {
  const base = relayUrl.replace(/\/+$/, "");
  return `${base}/${encodeURIComponent(accountId)}/account-states`;
}

/**
 * Validate the raw response body from `GET /account-states`. Returns the typed array on success,
 * or `null` if the body is malformed. The relay is zero-knowledge and cannot forge root signatures,
 * but the shape must be validated before passing to the WASM core.
 */
function parseAccountStatesBody(body: unknown): readonly string[] | null {
  if (typeof body !== "object" || body === null) return null;
  const raw = (body as Record<string, unknown>).account_states;
  if (!Array.isArray(raw)) return null;
  if (!raw.every((item): item is string => typeof item === "string")) return null;
  return raw;
}

/**
 * Create an {@link AccountStateResolver} that fetches root-signed account-state documents from the
 * relay (`GET /{accountId}/account-states`) and returns them for the WASM core to verify.
 *
 * The returned resolver:
 * - fetches once per `resolve` call (caching/ETag is out of scope for v1);
 * - returns `[]` on any failure (network error, timeout, non-2xx, malformed body) so the runtime
 *   degrades cleanly to `unverified` without aborting the approval flow;
 * - passes the raw JWS strings to the runtime as-is — the WASM core validates root signatures;
 *   a relay that substitutes its own actor key cannot forge a valid root signature, so relay
 *   substitution can never produce `verified`.
 *
 * The `actorId` parameter mirrors the `AccountStateResolver` signature but is currently unused:
 * the relay returns all account-state documents for the account (not actor-scoped), and the WASM
 * core filters by actor key inside `verify_actor_attestation`. This is intentional — the relay
 * must not learn which actor a particular device is verifying (zero-knowledge routing).
 */
export function createRelayAccountStateResolver(
  options: RelayAccountStateResolverOptions,
): AccountStateResolver {
  const { relayUrl, accountId, deviceAuthToken } = options;
  const timeoutMs = options.timeoutMs ?? ACCOUNT_STATE_FETCH_TIMEOUT_MS;
  const fetchImpl: FetchImpl = options.fetchImpl ?? fetch;

  const url = accountStatesUrl(relayUrl, accountId);
  const headers = { Authorization: `Bearer ${deviceAuthToken}` };

  return async function resolve(_actorId: string): Promise<readonly string[]> {
    let body: unknown;
    try {
      const resp = await fetchImpl(url, {
        method: "GET",
        headers,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!resp.ok) {
        // Non-2xx: relay is degraded or token is invalid — downgrade to unverified (fail-closed).
        return [];
      }
      body = await resp.json();
    } catch {
      // Network error, timeout, or JSON parse error — all map to fail-closed unverified.
      return [];
    }

    const accountStates = parseAccountStatesBody(body);
    if (accountStates === null) {
      // Malformed response shape — downgrade to unverified rather than passing garbage to the core.
      return [];
    }
    return accountStates;
  };
}
