/**
 * `@allw/example-walking-skeleton` — the v0 walking-skeleton demo + integration harness.
 *
 * This package composes the existing `allw` surfaces (`@allw/sdk`, `@allw/approver`, `@allw/hook`,
 * `@allw/relay`) end to end to prove the whole approval primitive coheres — it adds **no** crypto
 * or contract logic of its own (`docs/contract.md`, `docs/architecture.md`). See the package README
 * for the reproducible demo and the manual-test-design split (CI round-trip vs. live `wrangler dev`).
 */

export { InProcessRelay, ENVELOPE_KEYS } from "./lib/in-process-relay.js";
export type {
  DeviceConnection,
  InProcessRelayOptions,
  RelayDevice,
} from "./lib/in-process-relay.js";

export { attachAutoApprover } from "./lib/approver-harness.js";
export type { ApproverIdentity, AutoDecision, DecisionLogEntry } from "./lib/approver-harness.js";

export { buildPairedApprover } from "./lib/identity.js";
export type { PairingParams } from "./lib/identity.js";

export { autoPrompter, runLiveApprover } from "./lib/live-approver.js";
export type { LiveApproverOptions, LiveAutoDecision } from "./lib/live-approver.js";
