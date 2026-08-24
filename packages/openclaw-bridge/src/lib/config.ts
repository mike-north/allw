/**
 * Bridge configuration and the startup-failure gate.
 *
 * Every value here is operator-supplied, and every rule below is a **startup failure**, not a
 * runtime warning: a bridge that cannot produce a valid actor id, or whose allw deadline would land
 * at or after OpenClaw's own, must not appear to be gating
 * (`docs/openclaw-integration.md` §7.1, §8).
 *
 * @see ../../../../docs/openclaw-integration.md §7.1 Actor identity, §8 Timeout budgeting
 * @see ../../../../docs/contract.md §Invariants (fail-closed)
 */

/** A configuration problem that must stop the process before it claims to gate anything. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(`allw-openclaw-bridge: ${message}`);
    this.name = "ConfigError";
  }
}

/**
 * Syntax for the operator-configured `<gateway-id>` (spec §7.1). Matched **after** lowercasing and
 * trimming. The protocol offers no stable gateway identity (`hello-ok.server.connId` is
 * per-connection), so this label is what keeps two gateways from colliding in one allw inbox.
 */
export const GATEWAY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,62}$/;

/**
 * Margin subtracted from OpenClaw's `expiresAtMs` to get allw's deadline (spec §8).
 *
 * Must exceed the SDK per-relay-fetch timeout so the final verdict fetch **and** the
 * `approval.resolve` round trip both complete inside it. 60 s is the same 2× headroom the Claude
 * Code hook uses (`480_000 − 420_000`).
 */
export const DEFAULT_DEADLINE_MARGIN_MS = 60_000;
/** Floor for the margin. Anything smaller cannot hold a 30 s fetch plus a resolve round trip. */
export const MIN_DEADLINE_MARGIN_MS = 60_000;
/** Below this there is no realistic chance of a human decision; deny immediately instead (spec §8). */
export const DEFAULT_MIN_TIMEOUT_MS = 15_000;
/** Operator-configurable cap; only ever *lowers* the derived budget (spec §8). */
export const DEFAULT_MAX_TIMEOUT_MS = 420_000;
/** The SDK's own per-relay-fetch default. A configured value may only lower this (spec §8). */
export const DEFAULT_FETCH_TIMEOUT_MS = 30_000;

/** Fully validated bridge configuration. */
export interface BridgeConfig {
  /** WebSocket URL of the OpenClaw gateway (`ws://` / `wss://`). */
  readonly gatewayUrl: string;
  /** Operator-configured gateway label; the `openclaw:<gateway-id>` actor identity (spec §7.1). */
  readonly gatewayId: string;
  /** Relay base URL for `@allw/sdk`. */
  readonly relayUrl: string;
  /** Approver relay account id. */
  readonly accountId: string;
  /** Account-root Ed25519 public key (base64url) — the verdict trust anchor. */
  readonly approverRootKey: string;
  /** Directory holding the bridge's device identity + device token (secrets at rest). */
  readonly stateDir: string;
  /** One-time bootstrap credential used only until a device token is paired (spec §4.2). */
  readonly bootstrapToken?: string;
  readonly deadlineMarginMs: number;
  readonly minTimeoutMs: number;
  readonly maxTimeoutMs: number;
  readonly fetchTimeoutMs: number;
}

/** The environment slice the bridge reads. */
export type BridgeEnv = Readonly<Record<string, string | undefined>>;

/**
 * Normalize an operator-supplied gateway label: trim, lowercase, then validate against
 * {@link GATEWAY_ID_PATTERN}. Returns `null` for missing, blank, or malformed values — the caller
 * turns that into a startup failure (`loadConfig`) or a `config-error` deny (per-request
 * re-validation, spec §7.1).
 */
export function normalizeGatewayId(raw: string | undefined): string | null {
  if (typeof raw !== "string") return null;
  const normalized = raw.trim().toLowerCase();
  if (!GATEWAY_ID_PATTERN.test(normalized)) return null;
  return normalized;
}

/** The `actor.id` for a validated gateway label (spec §7.1). */
export function actorIdForGateway(gatewayId: string): string {
  return `openclaw:${gatewayId}`;
}

function requireString(env: BridgeEnv, key: string): string {
  const value = env[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new ConfigError(`${key} is required`);
  }
  return value.trim();
}

function readPositiveInt(env: BridgeEnv, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new ConfigError(`${key} must be a positive integer number of milliseconds, got '${raw}'`);
  }
  return parsed;
}

function requireWebSocketUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ConfigError(`ALLW_OPENCLAW_GATEWAY_URL is not a valid URL: '${value}'`);
  }
  if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") {
    throw new ConfigError(
      `ALLW_OPENCLAW_GATEWAY_URL must be a ws:// or wss:// URL, got '${parsed.protocol}'`,
    );
  }
  return value;
}

/**
 * Load and validate configuration, or throw {@link ConfigError}.
 *
 * The timeout rules are the §8 nesting invariant expressed as startup checks:
 * - the margin must be at least {@link MIN_DEADLINE_MARGIN_MS} **and** strictly greater than the
 *   per-fetch timeout, so the verdict fetch and the `approval.resolve` both fit inside it;
 * - the fetch timeout may only *lower* the SDK default;
 * - the minimum budget must be below the maximum, or no request could ever be raised.
 */
export function loadConfig(env: BridgeEnv, homeDir: string): BridgeConfig {
  const gatewayId = normalizeGatewayId(env.ALLW_OPENCLAW_GATEWAY_ID);
  if (gatewayId === null) {
    throw new ConfigError(
      "ALLW_OPENCLAW_GATEWAY_ID is required and must match /^[a-z0-9][a-z0-9._-]{0,62}$/ after " +
        "trimming and lowercasing; a silently-defaulted actor id would let two gateways collide " +
        "in one inbox",
    );
  }

  const deadlineMarginMs = readPositiveInt(
    env,
    "ALLW_DEADLINE_MARGIN_MS",
    DEFAULT_DEADLINE_MARGIN_MS,
  );
  const fetchTimeoutMs = readPositiveInt(env, "ALLW_FETCH_TIMEOUT_MS", DEFAULT_FETCH_TIMEOUT_MS);
  const minTimeoutMs = readPositiveInt(env, "ALLW_OPENCLAW_MIN_TIMEOUT_MS", DEFAULT_MIN_TIMEOUT_MS);
  const maxTimeoutMs = readPositiveInt(env, "ALLW_OPENCLAW_MAX_TIMEOUT_MS", DEFAULT_MAX_TIMEOUT_MS);

  if (deadlineMarginMs < MIN_DEADLINE_MARGIN_MS) {
    throw new ConfigError(
      `ALLW_DEADLINE_MARGIN_MS must be at least ${String(MIN_DEADLINE_MARGIN_MS)}ms so the final ` +
        `verdict fetch and the approval.resolve round trip both land before OpenClaw's own ` +
        `deadline, got ${String(deadlineMarginMs)}ms`,
    );
  }
  if (fetchTimeoutMs > DEFAULT_FETCH_TIMEOUT_MS) {
    throw new ConfigError(
      `ALLW_FETCH_TIMEOUT_MS may only lower the SDK default of ` +
        `${String(DEFAULT_FETCH_TIMEOUT_MS)}ms, got ${String(fetchTimeoutMs)}ms`,
    );
  }
  if (fetchTimeoutMs >= deadlineMarginMs) {
    throw new ConfigError(
      `ALLW_FETCH_TIMEOUT_MS (${String(fetchTimeoutMs)}ms) must stay below ` +
        `ALLW_DEADLINE_MARGIN_MS (${String(deadlineMarginMs)}ms)`,
    );
  }
  if (minTimeoutMs >= maxTimeoutMs) {
    throw new ConfigError(
      `ALLW_OPENCLAW_MIN_TIMEOUT_MS (${String(minTimeoutMs)}ms) must be below ` +
        `ALLW_OPENCLAW_MAX_TIMEOUT_MS (${String(maxTimeoutMs)}ms)`,
    );
  }

  const bootstrapToken = env.ALLW_OPENCLAW_BOOTSTRAP_TOKEN?.trim();
  const stateDir = env.ALLW_OPENCLAW_STATE_DIR?.trim();

  return {
    gatewayUrl: requireWebSocketUrl(requireString(env, "ALLW_OPENCLAW_GATEWAY_URL")),
    gatewayId,
    relayUrl: requireString(env, "ALLW_RELAY_URL"),
    accountId: requireString(env, "ALLW_ACCOUNT_ID"),
    approverRootKey: requireString(env, "ALLW_APPROVER_ROOT_KEY"),
    stateDir: stateDir !== undefined && stateDir.length > 0 ? stateDir : `${homeDir}/.allw`,
    ...(bootstrapToken !== undefined && bootstrapToken.length > 0 ? { bootstrapToken } : {}),
    deadlineMarginMs,
    minTimeoutMs,
    maxTimeoutMs,
    fetchTimeoutMs,
  };
}
