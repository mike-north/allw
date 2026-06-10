/**
 * `@allw/hook` — the Claude Code PreToolUse permission hook (Node + WASM).
 *
 * The first real `allw` integrator: a `node` hook that turns a pending sensitive tool call into a
 * phone approval and gates execution on the **verified** human decision, fail-closed throughout.
 * All `ActionRecord` construction goes through the audited Rust core via WASM, and the approval
 * round-trip goes through `@allw/sdk` (whose `requestApproval` is itself fail-closed).
 *
 * This module re-exports the programmatic surface (used by the CLI entrypoint and the tests). The
 * executable lives at `./cli.ts` (the `bin`).
 *
 * @see ./cli.ts (the `node` entrypoint / `bin`)
 * @see ../README.md (install + config: the .claude/settings.json matcher, env vars, rationale)
 * @see ../../../docs/architecture.md (WASM-local hard constraint)
 * @see ../../../docs/contract.md §Invariants #6 (fail-closed)
 */

export { runHook } from "./cli.js";

export {
  decide,
  type ApprovalVerdict,
  type DecideDeps,
  type HookApprovalRequest,
  type RequestApprovalFn,
} from "./lib/decide.js";

export {
  HOOK_EVENT_NAME,
  allowOutput,
  denyOutput,
  makeOutput,
  parseHookInput,
  type HookSpecificOutput,
  type ParseResult,
  type PermissionDecision,
  type PreToolUseInput,
  type PreToolUseOutput,
} from "./lib/hook-io.js";

export { gateToolCall, isGatedTool, parseMcpToolName, type GateOutcome } from "./lib/gating.js";

export {
  DEFAULT_TIMEOUT_MS,
  readConfig,
  type ConfigResult,
  type Env,
  type HookConfig,
} from "./lib/config.js";

export { loadWasm, type HookWasm } from "./lib/wasm.js";
