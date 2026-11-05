/**
 * The SDK client a hook process uses for one gated tool call, shared by the Claude Code hook and
 * the Codex hook so both wire account state the same way.
 *
 * Recipients come from the root-signed account state the relay serves
 * (`GET /{account}/account-states`, verified in the core against the configured root key), never
 * from the relay's device list. A per-account sequence floor under `~/.allw/state` is raised before
 * each request is sent, so a relay that later serves an older state is refused across hook runs.
 * Loading, verification and floor failures throw inside `requestApproval`, which the hook denies.
 *
 * @see ../../../../docs/enrollment.md (§Model: recipient selection rule; sealing and the sequence floor)
 */

import {
  createClient,
  fileSequenceFloorStore,
  relayAccountStateSource,
  type Client,
  type ClientConfig,
} from "@allw/sdk";

import type { HookConfig } from "./config.js";

/** The SDK transport seams a hook test may inject (production passes none). */
export type HookClientOverrides = Partial<
  Pick<
    ClientConfig,
    | "fetchImpl"
    | "nowImpl"
    | "webSocketFactory"
    | "pollIntervalMs"
    | "fetchTimeoutMs"
    | "scheduleImpl"
  >
>;

/**
 * Build the hook's client. The account-state fetch shares the client's fetch, timeout and timer
 * seams, so a test's relay double and fake clock drive it too.
 *
 * @throws when the configuration cannot build a client (the caller denies).
 */
export function createHookClient(config: HookConfig, overrides: HookClientOverrides = {}): Client {
  const fetchTimeoutMs = overrides.fetchTimeoutMs ?? config.fetchTimeoutMs;
  return createClient({
    relayUrl: config.relayUrl,
    accountId: config.accountId,
    approverRootKey: config.approverRootKey,
    expectedAccountId: config.accountId,
    accountStates: relayAccountStateSource({
      relayUrl: config.relayUrl,
      accountId: config.accountId,
      floorStore: fileSequenceFloorStore({ accountId: config.accountId }),
      ...(overrides.fetchImpl ? { fetchImpl: overrides.fetchImpl } : {}),
      ...(fetchTimeoutMs !== undefined ? { fetchTimeoutMs } : {}),
      ...(overrides.scheduleImpl ? { scheduleImpl: overrides.scheduleImpl } : {}),
    }),
    ...(config.fetchTimeoutMs !== undefined ? { fetchTimeoutMs: config.fetchTimeoutMs } : {}),
    ...overrides,
  });
}
