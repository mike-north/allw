/**
 * Shared, **fixed** fixtures for the OpenClaw bridge tests.
 *
 * No `Date.now()` / `new Date()` anywhere: every timestamp is a constant so budget arithmetic and
 * deadline assertions are reproducible across runs and CI.
 *
 * @see ../../../../docs/openclaw-integration.md §5.1, §6.1, §8
 */

/** 2023-11-14T22:13:20.000Z — the gateway-clock reference for every fixture. */
export const CREATED_AT_MS = 1_700_000_000_000;
/** Default exec approval TTL upstream is 1 800 000 ms (`DEFAULT_EXEC_APPROVAL_TIMEOUT_MS`). */
export const EXEC_TTL_MS = 1_800_000;
export const EXPIRES_AT_MS = CREATED_AT_MS + EXEC_TTL_MS;

export const GATEWAY_ID = "home-mini";
export const APPROVAL_ID = "apr_01HZX0EXECAPPROVAL";
export const SESSION_KEY = "sess_01HZX0SESSION";
export const AGENT_ID = "agent-main";

/** A fully-populated exec config; individual tests override just what they exercise. */
export const CONFIG = {
  gatewayUrl: "ws://127.0.0.1:18789",
  gatewayId: GATEWAY_ID,
  relayUrl: "https://relay.allw.test",
  accountId: "acct-test",
  approverRootKey: "x".repeat(43),
  stateDir: "/nonexistent",
  deadlineMarginMs: 60_000,
  minTimeoutMs: 15_000,
  maxTimeoutMs: 420_000,
  fetchTimeoutMs: 30_000,
};

/** An `exec.approval.requested` payload carrying the canonical `systemRunPlan`. */
export function execEvent(overrides = {}) {
  const { request: requestOverrides, systemRunPlan: planOverrides, ...rest } = overrides;
  return {
    id: APPROVAL_ID,
    approvalKind: "exec",
    createdAtMs: CREATED_AT_MS,
    expiresAtMs: EXPIRES_AT_MS,
    request: {
      host: "node",
      nodeId: "node-7",
      agentId: AGENT_ID,
      sessionKey: SESSION_KEY,
      systemRunPlan: {
        argv: ["git", "push", "--force"],
        cwd: "/srv/app",
        commandText: "git push --force",
        agentId: AGENT_ID,
        sessionKey: SESSION_KEY,
        ...planOverrides,
      },
      ...requestOverrides,
    },
    ...rest,
  };
}

/** The pinned `approval.get` snapshot that agrees with {@link execEvent}. */
export function execSnapshot(overrides = {}) {
  const { presentation: presentationOverrides, ...rest } = overrides;
  return {
    id: APPROVAL_ID,
    createdAtMs: CREATED_AT_MS,
    expiresAtMs: EXPIRES_AT_MS,
    status: "pending",
    presentation: {
      kind: "exec",
      title: "Run a command",
      commandText: "git push --force",
      allowedDecisions: ["allow-once", "deny"],
      ...presentationOverrides,
    },
    ...rest,
  };
}
