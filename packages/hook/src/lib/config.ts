/**
 * Hook configuration, sourced from the environment so the hook needs no config file of its own.
 *
 * The hook is wired into Claude Code's `.claude/settings.json`; the relay coordinates and the
 * approver trust anchor come from these env vars (documented in the package README):
 *
 * | Variable                 | Required | Meaning                                                      |
 * | ------------------------ | -------- | ------------------------------------------------------------ |
 * | `ALLW_RELAY_URL`         | yes      | Base URL of the zero-knowledge relay.                        |
 * | `ALLW_ACCOUNT_ID`        | yes      | The approver's relay account id (routes to their devices).   |
 * | `ALLW_APPROVER_ROOT_KEY` | yes      | The approver account-root Ed25519 public key (base64url).    |
 * | `ALLW_TIMEOUT_MS`        | no       | Fail-closed deadline in ms (default 300000 = 5 min).         |
 *
 * **Fail-closed:** any missing required var yields a parse error the caller turns into a `deny`
 * with an actionable reason (which var to set) — the hook never proceeds on partial config.
 */

/** The fully-resolved hook config. */
export interface HookConfig {
  readonly relayUrl: string;
  readonly accountId: string;
  readonly approverRootKey: string;
  /** Present only when `ALLW_TIMEOUT_MS` is set to a valid positive integer. */
  readonly timeoutMs?: number;
}

/** The result of reading config: a resolved config or a fail-closed reason naming the problem. */
export type ConfigResult =
  | { readonly ok: true; readonly config: HookConfig }
  | { readonly ok: false; readonly reason: string };

/** The default fail-closed deadline (5 minutes), used when `ALLW_TIMEOUT_MS` is absent. */
export const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

/** An environment map (injectable for tests; defaults to `process.env`). */
export type Env = Record<string, string | undefined>;

/** Read a required non-empty string env var, or `null` if absent/blank. */
function required(env: Env, key: string): string | null {
  const value = env[key];
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

/**
 * Read and validate the hook config from an environment map.
 *
 * Returns a fail-closed `{ ok: false, reason }` (naming the first missing var, or the bad timeout)
 * rather than throwing, so the caller maps it straight to a `deny`.
 */
export function readConfig(env: Env): ConfigResult {
  const relayUrl = required(env, "ALLW_RELAY_URL");
  if (relayUrl === null) {
    return { ok: false, reason: "allw: ALLW_RELAY_URL is not set (fail-closed deny)" };
  }
  const accountId = required(env, "ALLW_ACCOUNT_ID");
  if (accountId === null) {
    return { ok: false, reason: "allw: ALLW_ACCOUNT_ID is not set (fail-closed deny)" };
  }
  const approverRootKey = required(env, "ALLW_APPROVER_ROOT_KEY");
  if (approverRootKey === null) {
    return { ok: false, reason: "allw: ALLW_APPROVER_ROOT_KEY is not set (fail-closed deny)" };
  }

  const rawTimeout = env.ALLW_TIMEOUT_MS;
  let timeoutMs: number | undefined;
  if (rawTimeout !== undefined && rawTimeout.trim().length > 0) {
    const parsed = Number(rawTimeout);
    if (!Number.isInteger(parsed) || parsed <= 0) {
      return {
        ok: false,
        reason: `allw: ALLW_TIMEOUT_MS must be a positive integer number of milliseconds, got '${rawTimeout}' (fail-closed deny)`,
      };
    }
    timeoutMs = parsed;
  }

  return {
    ok: true,
    config: {
      relayUrl,
      accountId,
      approverRootKey,
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    },
  };
}
