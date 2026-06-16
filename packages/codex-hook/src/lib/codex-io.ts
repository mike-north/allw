/**
 * Codex PreToolUse hook wire contract.
 *
 * Codex writes one JSON object to stdin. This module validates only the fields allw depends on and
 * shapes the JSON decision Codex reads from stdout. Every malformed input path returns a parse
 * error so the CLI can emit an explicit fail-closed `deny`.
 *
 * @see ../../../../docs/codex-integration.md
 * @see https://developers.openai.com/codex/hooks
 */

/** The Codex hook event this package implements. */
export const HOOK_EVENT_NAME = "PreToolUse" as const;

/** Codex currently supports `allow` and `deny` as useful PreToolUse permission decisions. */
export type PermissionDecision = "allow" | "deny";

/**
 * Machine-readable category for the deny reason, surfaced in `hookSpecificOutput.denyReason`.
 *
 * - `input-parse-error` — stdin was malformed or missing required fields.
 * - `config-error` — required allw env vars were absent or invalid.
 * - `build-error` — the WASM core could not construct a valid `ActionRecord`.
 * - `transport-error` — the approval relay request failed (network/SDK error).
 * - `no-approval` — the human explicitly denied the request (`decision === "denied"`).
 * - `timeout` — the approval request expired before the human responded (`decision === "expired"`).
 * - `aborted` — the approval request was aborted (`decision === "aborted"`).
 */
export type DenyReason =
  | "input-parse-error"
  | "config-error"
  | "build-error"
  | "transport-error"
  | "no-approval"
  | "timeout"
  | "aborted";

/**
 * The validated subset of Codex PreToolUse input. Unknown fields are ignored; `toolInput` stays
 * `unknown` because Bash, MCP, and future tools each have their own shape.
 */
export interface CodexPreToolUseInput {
  readonly hookEventName: typeof HOOK_EVENT_NAME;
  readonly toolName: string;
  readonly toolInput: unknown;
  readonly cwd?: string;
  readonly toolUseId?: string;
}

/**
 * The `hookSpecificOutput` object Codex reads as a PreToolUse decision.
 *
 * On deny decisions, `denyReason` carries a machine-readable category so operators can
 * distinguish no-approval from timeout from config errors without parsing the reason string.
 */
export interface CodexHookSpecificOutput {
  readonly hookEventName: typeof HOOK_EVENT_NAME;
  readonly permissionDecision: PermissionDecision;
  readonly permissionDecisionReason: string;
  /** Present only on `deny` decisions; absent on `allow`. */
  readonly denyReason?: DenyReason;
}

/** The full JSON stdout payload emitted by the hook. */
export interface CodexPreToolUseOutput {
  readonly hookSpecificOutput: CodexHookSpecificOutput;
}

/** Parse result: either a validated input or the fail-closed reason to deny with. */
export type ParseResult =
  | { readonly ok: true; readonly input: CodexPreToolUseInput }
  | { readonly ok: false; readonly reason: string; readonly denyReason: DenyReason };

/** True for JSON objects whose fields can be inspected safely. */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Build a Codex PreToolUse output payload. */
export function makeOutput(
  decision: PermissionDecision,
  reason: string,
  denyReason?: DenyReason,
): CodexPreToolUseOutput {
  return {
    hookSpecificOutput: {
      hookEventName: HOOK_EVENT_NAME,
      permissionDecision: decision,
      permissionDecisionReason: reason,
      ...(denyReason !== undefined ? { denyReason } : {}),
    },
  };
}

/** Build an `allow` output. Only verified approvals and non-gated pass-throughs use this. */
export function allowOutput(reason: string): CodexPreToolUseOutput {
  return makeOutput("allow", reason);
}

/**
 * Build a `deny` output. This is the default for every error or ambiguous gated path.
 *
 * The `denyReason` parameter is required to ensure every deny path carries a machine-readable
 * category that operators can use to distinguish the cause without parsing the reason string.
 */
export function denyOutput(reason: string, denyReason: DenyReason): CodexPreToolUseOutput {
  return makeOutput("deny", reason, denyReason);
}

/**
 * Parse and validate raw Codex hook stdin.
 *
 * The hook denies on malformed JSON, non-object payloads, wrong event names, and missing or empty
 * `tool_name`. `tool_input` is optional in Codex's schema and remains `unknown` here.
 */
export function parseCodexHookInput(raw: string): ParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {
      ok: false,
      reason: "allw: Codex hook input was not valid JSON (fail-closed deny)",
      denyReason: "input-parse-error",
    };
  }
  if (!isObject(parsed)) {
    return {
      ok: false,
      reason: "allw: Codex hook input was not a JSON object (fail-closed deny)",
      denyReason: "input-parse-error",
    };
  }

  const eventName = parsed.hook_event_name;
  if (eventName !== HOOK_EVENT_NAME) {
    return {
      ok: false,
      reason: `allw: unexpected Codex hook_event_name '${String(
        eventName,
      )}' (expected '${HOOK_EVENT_NAME}'; fail-closed deny)`,
      denyReason: "input-parse-error",
    };
  }

  const toolName = parsed.tool_name;
  if (typeof toolName !== "string" || toolName.length === 0) {
    return {
      ok: false,
      reason: "allw: Codex hook input missing a string 'tool_name' (fail-closed deny)",
      denyReason: "input-parse-error",
    };
  }

  const cwd = parsed.cwd;
  const toolUseId = parsed.tool_use_id;
  return {
    ok: true,
    input: {
      hookEventName: HOOK_EVENT_NAME,
      toolName,
      toolInput: parsed.tool_input,
      ...(typeof cwd === "string" ? { cwd } : {}),
      ...(typeof toolUseId === "string" ? { toolUseId } : {}),
    },
  };
}
