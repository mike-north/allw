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
 * | `ALLW_TIMEOUT_MS`        | no       | Fail-closed deadline in ms (default 300000 = 5 min, capped). |
 *
 * **Fail-closed:** any missing required var yields a parse error the caller turns into a `deny`
 * with an actionable reason (which var to set) — the hook never proceeds on partial config.
 *
 * # Timeout-ordering invariant (issue #52)
 * The hook's safety must NOT depend on what Claude Code does when a hook fails to emit a decision.
 * Per the Claude Code hooks docs, a command hook's default `timeout` is **600s**, and a hook
 * **timeout** is a *non-blocking error* → Claude Code **proceeds** (fail-OPEN); its behavior on
 * timeout is otherwise undocumented and version-dependent. So the contract we control is: the hook
 * always exits 0 with an explicit `allow`/`deny`, **well before** any external timeout.
 *
 * To guarantee that, the documented `.claude/settings.json` install block pins the hook `timeout`
 * to {@link PINNED_HOOK_TIMEOUT_MS}, and `ALLW_TIMEOUT_MS` is **capped** at
 * {@link MAX_TIMEOUT_MS} — strictly below the pinned hook timeout, with margin for the SDK's
 * per-request relay-fetch timeouts to fire too. An oversized `ALLW_TIMEOUT_MS` is rejected at
 * config-read time (fail-closed `deny`) rather than silently accepted into a regime where Claude
 * Code could kill the hook before it decides.
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

/**
 * The Claude Code hook `timeout` (in ms) the README's install block pins. Chosen comfortably below
 * Claude Code's 600s command-hook default so the relationship is explicit and version-independent,
 * and comfortably above {@link DEFAULT_TIMEOUT_MS} so the common case has ample headroom. The hook
 * always emits an explicit `allow`/`deny` before this fires (issue #52).
 *
 * NOTE: Claude Code expresses `timeout` in **seconds** (`480`); this is the same value in **ms**
 * (`480000`) for comparison against `ALLW_TIMEOUT_MS`, which is in ms.
 */
export const PINNED_HOOK_TIMEOUT_MS = 480_000; // 480s — see README install block (`"timeout": 480`)

/**
 * The upper bound on `ALLW_TIMEOUT_MS` (ms). Strictly below {@link PINNED_HOOK_TIMEOUT_MS}, leaving
 * a margin (≥ the SDK's per-request relay-fetch timeout) so the SDK deadline AND a trailing relay
 * fetch both complete before Claude Code's pinned hook timeout could fire. A configured value at or
 * above this cap is rejected (fail-closed `deny`) at config-read time.
 */
export const MAX_TIMEOUT_MS = 420_000; // 420s; PINNED − MAX = 60s margin (> the 30s fetch timeout)

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
    if (parsed >= MAX_TIMEOUT_MS) {
      // An oversized deadline would let Claude Code's pinned hook timeout fire before the hook emits
      // its explicit deny — at which point the outcome rides on Claude Code's undocumented
      // timeout behavior (a non-blocking error → the tool PROCEEDS = fail-OPEN). Refuse it.
      return {
        ok: false,
        reason: `allw: ALLW_TIMEOUT_MS=${String(parsed)}ms is too large — it must be below ${String(
          MAX_TIMEOUT_MS,
        )}ms (the pinned Claude Code hook timeout of ${String(
          PINNED_HOOK_TIMEOUT_MS,
        )}ms minus margin for relay-fetch timeouts), so the hook always decides before Claude Code can kill it (fail-closed deny)`,
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
