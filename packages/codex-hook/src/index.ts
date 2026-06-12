/**
 * Programmatic exports for the Codex PreToolUse approval hook.
 *
 * The executable entrypoint is `allw-codex-hook` (`./cli.ts`). Tests and advanced integrators can
 * import the parser, decision core, and runner from this package.
 */

export { runCodexHook, type RunCodexHookOverrides } from "./cli.js";

export {
  decide,
  type ApprovalVerdict,
  type CodexApprovalRequest,
  type DecideDeps,
  type RequestApprovalFn,
} from "./lib/decide.js";

export {
  HOOK_EVENT_NAME,
  allowOutput,
  denyOutput,
  makeOutput,
  parseCodexHookInput,
  type CodexHookSpecificOutput,
  type CodexPreToolUseInput,
  type CodexPreToolUseOutput,
  type ParseResult,
  type PermissionDecision,
} from "./lib/codex-io.js";
