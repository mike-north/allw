/**
 * The Claude Code **PreToolUse** hook wire contract (stdin in, stdout out), and the parsing +
 * shaping helpers around it. Field names and values here are the verified contract from the
 * official docs (see `@see` below), not a guess — they are load-bearing for Claude Code to act on
 * the decision.
 *
 * # stdin (the pending tool call)
 * Claude Code writes a JSON object to the hook's stdin:
 *
 * ```jsonc
 * {
 *   "session_id": "…",
 *   "transcript_path": "…",
 *   "cwd": "/abs/path",
 *   "permission_mode": "default",
 *   "hook_event_name": "PreToolUse",
 *   "tool_name": "Bash",            // or "Edit" / "Write" / "mcp__<server>__<tool>"
 *   "tool_input": { "command": "rm -rf build" }   // tool-specific
 * }
 * ```
 *
 * # stdout (the permission decision)
 * The hook prints a JSON object and exits 0; Claude Code reads the decision from it:
 *
 * ```jsonc
 * {
 *   "hookSpecificOutput": {
 *     "hookEventName": "PreToolUse",
 *     "permissionDecision": "allow" | "deny" | "ask",
 *     "permissionDecisionReason": "…"
 *   }
 * }
 * ```
 *
 * `allw` only ever emits `allow` (a verified human approval) or `deny` (everything else — the
 * fail-closed default). It never emits `ask`/`defer`: a gated action that reaches the human is
 * decided by the human, and a non-gated action is passed through as `allow`.
 *
 * @see https://code.claude.com/docs/en/hooks (PreToolUse JSON schema, decision values, exit codes)
 */

/** The hook event we implement. Claude Code stamps this on both the input and our output. */
export const HOOK_EVENT_NAME = "PreToolUse" as const;

/**
 * The decision values Claude Code understands on `permissionDecision`. `allw` only emits
 * `allow`/`deny`; `ask` is part of the contract vocabulary but never produced here (a gated action
 * is decided by the human, a non-gated one passes through).
 */
export type PermissionDecision = "allow" | "deny" | "ask";

/**
 * The validated PreToolUse hook input. Only the fields the hook reads are typed; Claude Code may
 * send more (the parser ignores unknown keys). `toolInput` stays `unknown` — its shape depends on
 * `toolName` and is narrowed by the per-surface gating logic.
 */
export interface PreToolUseInput {
  readonly hookEventName: typeof HOOK_EVENT_NAME;
  readonly toolName: string;
  readonly toolInput: unknown;
  /** The working directory of the session, threaded into the command `ActionRecord`. */
  readonly cwd?: string;
}

/** The `hookSpecificOutput` object Claude Code reads the decision from. */
export interface HookSpecificOutput {
  readonly hookEventName: typeof HOOK_EVENT_NAME;
  readonly permissionDecision: PermissionDecision;
  readonly permissionDecisionReason: string;
}

/** The full stdout payload: a single `hookSpecificOutput` envelope. */
export interface PreToolUseOutput {
  readonly hookSpecificOutput: HookSpecificOutput;
}

/** Build the stdout payload for a decision. */
export function makeOutput(decision: PermissionDecision, reason: string): PreToolUseOutput {
  return {
    hookSpecificOutput: {
      hookEventName: HOOK_EVENT_NAME,
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  };
}

/** A `deny` output — the fail-closed default for every error/ambiguity path. */
export function denyOutput(reason: string): PreToolUseOutput {
  return makeOutput("deny", reason);
}

/** An `allow` output — only ever produced for a verified approval or a non-gated pass-through. */
export function allowOutput(reason: string): PreToolUseOutput {
  return makeOutput("allow", reason);
}

/** The result of parsing stdin: either a validated input or a fail-closed reason to deny. */
export type ParseResult =
  | { readonly ok: true; readonly input: PreToolUseInput }
  | { readonly ok: false; readonly reason: string };

/** True for a plain (non-array, non-null) object. */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Parse and validate the PreToolUse hook input from a raw stdin string.
 *
 * **Fail-closed:** any malformed/unexpected input (not JSON, not an object, a missing/non-string
 * `tool_name`, wrong `hook_event_name`) yields `{ ok: false, reason }` so the caller denies. We do
 * not throw — the caller maps the reason straight into a `deny` decision.
 */
export function parseHookInput(raw: string): ParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, reason: "allw: hook input was not valid JSON (fail-closed deny)" };
  }
  if (!isObject(parsed)) {
    return { ok: false, reason: "allw: hook input was not a JSON object (fail-closed deny)" };
  }

  const eventName = parsed.hook_event_name;
  if (eventName !== HOOK_EVENT_NAME) {
    return {
      ok: false,
      reason: `allw: unexpected hook_event_name '${String(
        eventName,
      )}' (expected '${HOOK_EVENT_NAME}'; fail-closed deny)`,
    };
  }

  const toolName = parsed.tool_name;
  if (typeof toolName !== "string" || toolName.length === 0) {
    return {
      ok: false,
      reason: "allw: hook input missing a string 'tool_name' (fail-closed deny)",
    };
  }

  const cwd = parsed.cwd;
  const input: PreToolUseInput = {
    hookEventName: HOOK_EVENT_NAME,
    toolName,
    toolInput: parsed.tool_input,
    ...(typeof cwd === "string" ? { cwd } : {}),
  };
  return { ok: true, input };
}
