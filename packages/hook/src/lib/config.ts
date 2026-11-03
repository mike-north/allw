/**
 * Hook configuration: the relay coordinates and approver trust anchor come from the shared
 * integrator config loader (`@allw/sdk` `loadClientConfig`, issue #230); the hook-only timeouts come
 * from the environment.
 *
 * The coordinates are read from **one non-secret config file**, `~/.allw/config.json` (moved with
 * `ALLW_CONFIG`), with per-field env-var overrides. Env wins over the file, field by field:
 *
 * | Variable                 | File key            | Meaning                                                      |
 * | ------------------------ | ------------------- | ------------------------------------------------------------ |
 * | `ALLW_CONFIG`            | —                   | Config-file path (absolute; default `~/.allw/config.json`).  |
 * | `ALLW_RELAY_URL`         | `relay_url`         | Base URL of the zero-knowledge relay.                        |
 * | `ALLW_ACCOUNT_ID`        | `account_id`        | The approver's self-certifying relay account id.             |
 * | `ALLW_APPROVER_ROOT_KEY` | `approver_root_key` | The approver account-root Ed25519 public key (base64url).    |
 * | `ALLW_TIMEOUT_MS`        | —                   | Fail-closed deadline in ms (default 300000 = 5 min, capped). |
 * | `ALLW_FETCH_TIMEOUT_MS`  | —                   | Per-relay-fetch timeout in ms (default/max 30000).           |
 *
 * **Fail-closed:** no file and no env, a relative `ALLW_CONFIG`, a file that is not a regular file,
 * is oversize, is not owned by the user or is group/world-writable, a
 * malformed/unknown-version/incomplete file, a malformed root
 * key, an account id that does not derive from the root key, or a bad timeout all yield a parse
 * error the caller turns into a `deny` with an actionable reason (naming the file path and the env
 * var to fix) — the hook never proceeds on partial config. There is one loader for every surface;
 * this module does not parse the file itself.
 *
 * # Timeout-ordering invariant (issue #52)
 * The hook's safety must NOT depend on what Claude Code does when a hook fails to emit a decision.
 * Per the Claude Code hooks docs, a command hook's default `timeout` is **600s**, and a hook
 * **timeout** is a *non-blocking error* → Claude Code **proceeds** (fail-OPEN); its behavior on
 * timeout is otherwise undocumented and version-dependent. So the contract we control is: the hook
 * always exits 0 with its decision (no output for an approval, a `deny` otherwise) **well before**
 * any external timeout.
 *
 * To guarantee that, the documented `.claude/settings.json` install block pins the hook `timeout`
 * to {@link PINNED_HOOK_TIMEOUT_MS}, and `ALLW_TIMEOUT_MS` is **capped** at
 * {@link MAX_TIMEOUT_MS} — strictly below the pinned hook timeout, with margin for the SDK's
 * per-request relay-fetch timeouts to fire too. An oversized `ALLW_TIMEOUT_MS` is rejected at
 * config-read time (fail-closed `deny`) rather than silently accepted into a regime where Claude
 * Code could kill the hook before it decides. `ALLW_FETCH_TIMEOUT_MS` may lower (but not raise)
 * the SDK's production per-fetch timeout, which lets UATs prove the hung-relay path quickly without
 * weakening the production timeout-ordering margin.
 */

import {
  ClientConfigError,
  escapeToPrintableAscii,
  loadClientConfig,
  type IntegratorConfig,
} from "@allw/sdk";

/** The fully-resolved hook config. */
export interface HookConfig {
  readonly relayUrl: string;
  readonly accountId: string;
  readonly approverRootKey: string;
  /** Present only when `ALLW_TIMEOUT_MS` is set to a valid positive integer. */
  readonly timeoutMs?: number;
  /** Present only when `ALLW_FETCH_TIMEOUT_MS` lowers the SDK's default per-fetch timeout. */
  readonly fetchTimeoutMs?: number;
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
 * always reaches its decision (no output for an approval, a `deny` otherwise) before this fires
 * (issue #52).
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

/**
 * The SDK's production per-relay-fetch timeout (ms), duplicated here as the hook's maximum accepted
 * `ALLW_FETCH_TIMEOUT_MS`. The env var is an escape hatch for faster end-to-end/UAT failures; it
 * can only make relay fetches fail sooner, never extend them beyond the timeout-ordering budget.
 */
export const MAX_FETCH_TIMEOUT_MS = 30_000;

/** An environment map (injectable for tests; defaults to `process.env`). */
export type Env = Record<string, string | undefined>;

/** Read an optional positive-integer millisecond env var. A rejected value is quoted escaped (#358). */
function optionalMs(
  env: Env,
  key: string,
): { ok: true; value?: number } | { ok: false; reason: string } {
  const raw = env[key];
  if (raw === undefined || raw.trim().length === 0) {
    return { ok: true };
  }
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return {
      ok: false,
      reason: `allw: ${key} must be a positive integer number of milliseconds, got '${escapeToPrintableAscii(raw)}' (fail-closed deny)`,
    };
  }
  return { ok: true, value: parsed };
}

/** Options for {@link readConfig} (tests). */
export interface ReadConfigOptions {
  /** Config-file path override; see `LoadClientConfigOptions.path`. */
  readonly path?: string;
}

/**
 * Read and validate the hook config: coordinates via `loadClientConfig` (config file + env
 * overrides), timeouts from the environment.
 *
 * Returns a fail-closed `{ ok: false, reason }` rather than throwing, so the caller maps it straight
 * to a `deny`.
 */
export function readConfig(env: Env, options: ReadConfigOptions = {}): ConfigResult {
  let coordinates: IntegratorConfig;
  try {
    coordinates = loadClientConfig({
      env,
      ...(options.path !== undefined ? { path: options.path } : {}),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      // The loader escapes the env-sourced text it quotes (#358); anything else it throws is escaped
      // here, since config loading runs before the WASM core's display escape is available.
      reason:
        err instanceof ClientConfigError
          ? message
          : `allw: ${escapeToPrintableAscii(message)} (fail-closed deny)`,
    };
  }
  const { relayUrl, accountId, approverRootKey } = coordinates;

  const timeout = optionalMs(env, "ALLW_TIMEOUT_MS");
  if (!timeout.ok) return timeout;
  const timeoutMs = timeout.value;
  if (timeoutMs !== undefined) {
    if (timeoutMs >= MAX_TIMEOUT_MS) {
      // An oversized deadline would let Claude Code's pinned hook timeout fire before the hook emits
      // its explicit deny — at which point the outcome rides on Claude Code's undocumented
      // timeout behavior (a non-blocking error → the tool PROCEEDS = fail-OPEN). Refuse it.
      return {
        ok: false,
        reason: `allw: ALLW_TIMEOUT_MS=${String(timeoutMs)}ms is too large — it must be below ${String(
          MAX_TIMEOUT_MS,
        )}ms (the pinned Claude Code hook timeout of ${String(
          PINNED_HOOK_TIMEOUT_MS,
        )}ms minus margin for relay-fetch timeouts), so the hook always decides before Claude Code can kill it (fail-closed deny)`,
      };
    }
  }

  const fetchTimeout = optionalMs(env, "ALLW_FETCH_TIMEOUT_MS");
  if (!fetchTimeout.ok) return fetchTimeout;
  const fetchTimeoutMs = fetchTimeout.value;
  if (fetchTimeoutMs !== undefined && fetchTimeoutMs > MAX_FETCH_TIMEOUT_MS) {
    return {
      ok: false,
      reason: `allw: ALLW_FETCH_TIMEOUT_MS=${String(
        fetchTimeoutMs,
      )}ms is too large — it must be at or below ${String(
        MAX_FETCH_TIMEOUT_MS,
      )}ms so relay fetches cannot outlive the hook timeout-ordering margin (fail-closed deny)`,
    };
  }

  return {
    ok: true,
    config: {
      relayUrl,
      accountId,
      approverRootKey,
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      ...(fetchTimeoutMs !== undefined ? { fetchTimeoutMs } : {}),
    },
  };
}
