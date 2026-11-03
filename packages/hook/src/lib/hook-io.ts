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
 * # stdout (the permission decision) — deny only
 * Claude Code's vocabulary is `allow` | `deny` | `ask` | `defer`. allw uses exactly one of them. The
 * hook always exits 0 and either:
 *
 * - prints **nothing** (no decision): a non-gated tool, a pass-through, or a verified human approval.
 *   Claude Code then applies the user's own permission rules, exactly as without allw; or
 * - prints a **deny**, the fail-closed result for everything else:
 *
 * ```jsonc
 * {
 *   "hookSpecificOutput": {
 *     "hookEventName": "PreToolUse",
 *     "permissionDecision": "deny",
 *     "permissionDecisionReason": "…"
 *   }
 * }
 * ```
 *
 * allw never emits `allow`: in Claude Code an `allow` skips the permission prompt, so it would let an
 * allw approval, or a matcher widened to tools allw never asks about, grant access the user's own
 * rules would have prompted for. A verdict may only tighten access (`docs/contract.md` §Invariants).
 * This mirrors `@allw/codex-hook` (#191); the shared writer is `./decision-output.ts`.
 *
 * @see https://code.claude.com/docs/en/hooks (PreToolUse JSON schema, decision values, exit codes)
 */

import { MAX_ESCAPED_DIAGNOSTIC_CHARS, escapeToPrintableAscii } from "@allw/sdk";

/** The hook event we implement. Claude Code stamps this on both the input and our output. */
export const HOOK_EVENT_NAME = "PreToolUse" as const;

/**
 * The only `permissionDecision` allw writes. Claude Code also understands `allow`, `ask` and `defer`;
 * allw deliberately emits none of them (see the module doc comment).
 */
export type PermissionDecision = "deny";

/**
 * The validated PreToolUse hook input. Only the fields the hook reads are typed; Claude Code may
 * send more (the parser ignores unknown keys). `toolInput` stays `unknown` — its shape depends on
 * `toolName` and is narrowed by the per-surface gating logic.
 */
export interface PreToolUseInput {
  readonly hookEventName: typeof HOOK_EVENT_NAME;
  readonly toolName: string;
  readonly toolInput: unknown;
  /**
   * The working directory of the session, threaded into the command `ActionRecord`. Never blank:
   * Claude Code sends `""` when it does not know the directory, and the parser treats that as
   * absent, so the record is left unbound (#371).
   */
  readonly cwd?: string;
}

/** The `hookSpecificOutput` object Claude Code reads the decision from. */
export interface HookSpecificOutput {
  readonly hookEventName: typeof HOOK_EVENT_NAME;
  readonly permissionDecision: PermissionDecision;
  readonly permissionDecisionReason: string;
}

/** The full stdout payload for a deny: a single `hookSpecificOutput` envelope. */
export interface PreToolUseOutput {
  readonly hookSpecificOutput: HookSpecificOutput;
}

/**
 * The hook's full result. `null` is "no decision" — written as empty stdout + exit 0, so Claude Code
 * applies the user's own permission rules. A non-null value is always a `deny`.
 */
export type ClaudeHookResult = PreToolUseOutput | null;

/**
 * "allw has no objection": a non-gated tool, a pass-through, or a verified human approval. Named
 * rather than a bare `null` so the intent (no decision, never an `allow`) reads at the call site.
 */
export function noDecisionOutput(): ClaudeHookResult {
  return null;
}

/** A `deny` output — the fail-closed default for every error/ambiguity path, and the only output. */
export function denyOutput(reason: string): PreToolUseOutput {
  return {
    hookSpecificOutput: {
      hookEventName: HOOK_EVENT_NAME,
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
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
      // Stdin is untrusted and this runs before the WASM core loads: quote it escaped and bounded.
      reason: `allw: unexpected hook_event_name '${escapeToPrintableAscii(
        String(eventName),
        MAX_ESCAPED_DIAGNOSTIC_CHARS,
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

  // Claude Code builds `cwd` as `<directory> ?? ""`, so an unknown directory arrives as a blank
  // string. Treat blank (or whitespace-only) as absent: the record is then unbound and the human is
  // still asked, on every surface, rather than bound to a meaningless "" directory (#371).
  const cwd = parsed.cwd;
  const input: PreToolUseInput = {
    hookEventName: HOOK_EVENT_NAME,
    toolName,
    toolInput: parsed.tool_input,
    ...(typeof cwd === "string" && cwd.trim() !== "" ? { cwd } : {}),
  };
  return { ok: true, input };
}
