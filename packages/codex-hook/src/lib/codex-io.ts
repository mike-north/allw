/**
 * Codex PreToolUse hook wire contract.
 *
 * Codex writes one JSON object to stdin. This module validates only the fields allw depends on and
 * shapes the JSON decision Codex reads from stdout. Every malformed input path returns a parse
 * error so the CLI can emit an explicit fail-closed `deny`.
 *
 * Codex's `PreToolUse` `hookSpecificOutput` object is documented as accepting exactly
 * `hookEventName`, `permissionDecision`, `permissionDecisionReason`, `updatedInput`, and
 * `additionalContext` — nothing else — and its schema declares `additionalProperties: false` (the
 * open-source implementation deserializes it with `#[serde(deny_unknown_fields)]`:
 * `codex-rs/hooks/src/schema.rs`, `PreToolUseHookSpecificOutputWire`). This module therefore never
 * emits a field outside that set (see {@link CodexHookSpecificOutput}), and a bare
 * `permissionDecision: "allow"` (without `updatedInput`) is an unsupported decision on the current
 * release, so "allw does not block this call" is represented as `null` here and encoded by the CLI
 * as empty stdout + exit 0 — the documented clean-success path — never a wire `allow` (see
 * {@link CodexHookResult}). Fixed in #191; see docs/codex-integration.md, "Decision Mapping".
 *
 * @see ../../../../docs/codex-integration.md
 * @see https://learn.chatgpt.com/docs/hooks
 */

/** The Codex hook event this package implements. */
export const HOOK_EVENT_NAME = "PreToolUse" as const;

/**
 * Machine-readable category for a deny reason. Not a Codex wire field — Codex's PreToolUse
 * `hookSpecificOutput` schema has no room for one (`additionalProperties: false`). {@link
 * denyOutput} preserves the category by prefixing `permissionDecisionReason` with
 * `allw[<category>]: ` instead.
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
 * This package only ever emits `deny` here — see the module doc comment for why "allw did not
 * block" is never encoded as a wire `permissionDecision` value. `permissionDecisionReason` carries
 * the machine-readable {@link DenyReason} category as an `allw[<category>]: ` prefix; there is
 * deliberately no separate `denyReason` field, because Codex rejects any key on this object beyond
 * the documented set.
 */
export interface CodexHookSpecificOutput {
  readonly hookEventName: typeof HOOK_EVENT_NAME;
  readonly permissionDecision: "deny";
  readonly permissionDecisionReason: string;
}

/** The full JSON stdout payload emitted by the hook for a `deny` decision. */
export interface CodexPreToolUseOutput {
  readonly hookSpecificOutput: CodexHookSpecificOutput;
}

/**
 * The hook's full decision. `null` means "allw does not block this call" — approvals and
 * non-gated pass-throughs — and must be encoded as empty stdout + exit 0, never a wire
 * `permissionDecision: "allow"`. A non-null value is always an explicit, schema-conformant `deny`.
 */
export type CodexHookResult = CodexPreToolUseOutput | null;

/** Parse result: either a validated input or the fail-closed reason to deny with. */
export type ParseResult =
  | { readonly ok: true; readonly input: CodexPreToolUseInput }
  | { readonly ok: false; readonly reason: string; readonly denyReason: DenyReason };

/** True for JSON objects whose fields can be inspected safely. */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * "allw does not block this call." Approved verdicts and non-gated pass-throughs return this.
 * Named rather than a bare `null` at call sites so the intent — silence, not a wire `allow` — reads
 * at the call site. See the module doc comment for why.
 */
export function noBlockOutput(): CodexHookResult {
  return null;
}

/**
 * Build a `deny` output. This is the default for every error or ambiguous gated path, and the only
 * decision this package ever writes to stdout.
 *
 * The emitted object contains only the fields Codex's `PreToolUse` `hookSpecificOutput` schema
 * documents (`hookEventName`, `permissionDecision`, `permissionDecisionReason`) — never a
 * `denyReason` field. The `category` parameter is required so every deny path still carries a
 * machine-readable reason for operators; it is preserved by prefixing `permissionDecisionReason`
 * with `allw[<category>]: ` rather than by adding an undocumented field. Any leading `allw: ` on
 * `reason` (several call sites already write their own) is stripped first so the prefix never
 * doubles up.
 */
export function denyOutput(reason: string, category: DenyReason): CodexPreToolUseOutput {
  const detail = reason.replace(/^allw:\s*/, "");
  return {
    hookSpecificOutput: {
      hookEventName: HOOK_EVENT_NAME,
      permissionDecision: "deny",
      permissionDecisionReason: `allw[${category}]: ${detail}`,
    },
  };
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
