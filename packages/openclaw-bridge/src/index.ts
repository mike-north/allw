/**
 * `@allw/openclaw-bridge` — allw as a native OpenClaw approval client.
 *
 * A gateway **operator client** holding exactly `operator.approvals` that turns each pending
 * OpenClaw approval into a verified human decision from the allw inbox. It is a thin shell: every
 * `ActionRecord`, hash, and verdict verification happens in `crates/allw-core` behind the WASM
 * boundary, and the approval round-trip goes through `@allw/sdk` (itself fail-closed).
 *
 * The executable is `allw-openclaw-bridge` (`./cli.ts`).
 *
 * @see ../README.md (configuration + operator prerequisites)
 * @see ../../../docs/openclaw-integration.md (the governing spec)
 */

export { runBridge } from "./cli.js";

export {
  OpenClawBridge,
  type ApprovalOutcome,
  type BridgeDeps,
  type BridgeVerdict,
  type RequestApprovalFn,
} from "./lib/bridge.js";

export { deriveTimeout, type BudgetInput, type BudgetOutcome } from "./lib/budget.js";

export {
  ConfigError,
  DEFAULT_DEADLINE_MARGIN_MS,
  DEFAULT_FETCH_TIMEOUT_MS,
  DEFAULT_MAX_TIMEOUT_MS,
  DEFAULT_MIN_TIMEOUT_MS,
  GATEWAY_ID_PATTERN,
  MIN_DEADLINE_MARGIN_MS,
  actorIdForGateway,
  loadConfig,
  normalizeGatewayId,
  type BridgeConfig,
  type BridgeEnv,
} from "./lib/config.js";

export {
  openCredentialStore,
  type CredentialStore,
  type DeviceIdentity,
  type DeviceTokenRecord,
} from "./lib/credential-store.js";

export {
  BRIDGE_ROLE,
  createGatewayConnection,
  type ApprovalGateway,
  type GatewayConnection,
  type GatewayEvent,
  type GatewayLifecycle,
} from "./lib/gateway.js";

export {
  createLogger,
  silentLogger,
  stderrSink,
  type LogLevel,
  type LogRecord,
  type Logger,
} from "./lib/logging.js";

export {
  buildExecApprovalRequest,
  buildPluginApprovalRequest,
  execSummary,
  floorRisk,
  pluginSummary,
  reversibleForRisk,
  slugifyTitle,
  type BridgeApprovalRequest,
  type DenyReason,
  type ExecMappingInput,
  type MappingOutcome,
  type PluginMappingInput,
  type Risk,
} from "./lib/mapping.js";

export {
  APPROVAL_EVENTS,
  APPROVAL_GET_METHOD,
  APPROVAL_RESOLVE_METHOD,
  BRIDGE_CAPABILITIES,
  BRIDGE_SCOPES,
  EXEC_APPROVAL_LIST_METHOD,
  PINNED_PROTOCOL_VERSION,
  PLUGIN_APPROVAL_LIST_METHOD,
  isExecPresentation,
  isPluginPresentation,
  kindForEvent,
  readApprovalList,
  readApprovalResolveResult,
  readApprovalSnapshot,
  readExecApprovalRequestedEvent,
  readPluginApprovalRequestedEvent,
  type ApprovalDecision,
  type ApprovalKind,
  type ApprovalListEntry,
  type ApprovalPresentation,
  type ApprovalSnapshot,
  type ExecApprovalPresentation,
  type ExecApprovalRequestedEvent,
  type OtherApprovalPresentation,
  type PluginApprovalPresentation,
  type PluginApprovalRequest,
  type PluginApprovalRequestedEvent,
} from "./lib/protocol.js";

export { getVersion } from "./version.js";
